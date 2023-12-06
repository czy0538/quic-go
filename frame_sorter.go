package quic

import (
	"errors"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	list "github.com/quic-go/quic-go/internal/utils/linkedlist"
)

// byteInterval is an interval from one ByteCount to the other
// 记录了开始和结束的偏移量
type byteInterval struct {
	Start protocol.ByteCount
	End   protocol.ByteCount
}

var byteIntervalElementPool sync.Pool

func init() {
	byteIntervalElementPool = *list.NewPool[byteInterval]()
}

type frameSorterEntry struct {
	Data   []byte
	DoneCb func()
}

type frameSorter struct {
	queue   map[protocol.ByteCount]frameSorterEntry
	readPos protocol.ByteCount
	gaps    *list.List[byteInterval] // 双链表
}

var errDuplicateStreamData = errors.New("duplicate stream data")

// 初始化frameSorter
func newFrameSorter() *frameSorter {
	s := frameSorter{
		// 建立一个双链表，返回的是一个根节点。
		gaps:  list.NewWithPool[byteInterval](&byteIntervalElementPool),
		queue: make(map[protocol.ByteCount]frameSorterEntry),
	}
	// 插入头结点
	s.gaps.PushFront(byteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *frameSorter) Push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	err := s.push(data, offset, doneCb)
	// 如果是重复插入数据，仍旧正常返回。推测该情况为例如重传导致的重复。
	if err == errDuplicateStreamData {
		if doneCb != nil {
			doneCb()
		}
		return nil
	}
	return err
}

func (s *frameSorter) push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	if len(data) == 0 {
		return errDuplicateStreamData
	}

	// 计算要存入数据的开始和结束的位置
	start := offset
	end := offset + protocol.ByteCount(len(data))

	// 如果当前元素的结束位置，小于已有的上一个元素的开始位置，说明是重复插入数据
	// 在新建时候插入了一个[0,protocol.MaxByteCount]的节点，因此第一个push的时候
	// 肯定是成功的，不用处理nil的问题
	if end <= s.gaps.Front().Value.Start {
		return errDuplicateStreamData
	}

	startGap, startsInGap := s.findStartGap(start)
	endGap, endsInGap := s.findEndGap(startGap, end)

	// 判断偏移量是否在一个节点中
	startGapEqualsEndGap := startGap == endGap

	if (startGapEqualsEndGap && end <= startGap.Value.Start) ||
		(!startGapEqualsEndGap && startGap.Value.End >= endGap.Value.Start && end <= startGap.Value.Start) {
		return errDuplicateStreamData
	}

	startGapNext := startGap.Next()
	startGapEnd := startGap.Value.End // save it, in case startGap is modified
	endGapStart := endGap.Value.Start // save it, in case endGap is modified
	endGapEnd := endGap.Value.End     // save it, in case endGap is modified
	var adjustedStartGapEnd bool
	var wasCut bool

	pos := start
	var hasReplacedAtLeastOne bool
	for {
		// 根据开始位置，查找是否已经存在以该开始位置为开始的数据
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		if end-pos > oldEntryLen || (hasReplacedAtLeastOne && end-pos == oldEntryLen) {
			// The existing frame is shorter than the new frame. Replace it.
			delete(s.queue, pos)
			pos += oldEntryLen
			hasReplacedAtLeastOne = true
			if oldEntry.DoneCb != nil {
				oldEntry.DoneCb()
			}
		} else {
			if !hasReplacedAtLeastOne {
				return errDuplicateStreamData
			}
			// The existing frame is longer than the new frame.
			// Cut the new frame such that the end aligns with the start of the existing frame.
			data = data[:pos-start]
			end = pos
			wasCut = true
			break
		}
	}

	if !startsInGap && !hasReplacedAtLeastOne {
		// cut the frame, such that it starts at the start of the gap
		data = data[startGap.Value.Start-start:]
		start = startGap.Value.Start
		wasCut = true
	}
	if start <= startGap.Value.Start {
		if end >= startGap.Value.End {
			// The frame covers the whole startGap. Delete the gap.
			s.gaps.Remove(startGap)
		} else {
			startGap.Value.Start = end
		}
	} else if !hasReplacedAtLeastOne {
		startGap.Value.End = start
		adjustedStartGapEnd = true
	}

	if !startGapEqualsEndGap {
		s.deleteConsecutive(startGapEnd)
		var nextGap *list.Element[byteInterval]
		for gap := startGapNext; gap.Value.End < endGapStart; gap = nextGap {
			nextGap = gap.Next()
			s.deleteConsecutive(gap.Value.End)
			s.gaps.Remove(gap)
		}
	}

	if !endsInGap && start != endGapEnd && end > endGapEnd {
		// cut the frame, such that it ends at the end of the gap
		data = data[:endGapEnd-start]
		end = endGapEnd
		wasCut = true
	}
	if end == endGapEnd {
		if !startGapEqualsEndGap {
			// The frame covers the whole endGap. Delete the gap.
			s.gaps.Remove(endGap)
		}
	} else {
		if startGapEqualsEndGap && adjustedStartGapEnd {
			// The frame split the existing gap into two.
			s.gaps.InsertAfter(byteInterval{Start: end, End: startGapEnd}, startGap)
		} else if !startGapEqualsEndGap {
			endGap.Value.Start = end
		}
	}

	if wasCut && len(data) < protocol.MinStreamFrameBufferSize {
		newData := make([]byte, len(data))
		copy(newData, data)
		data = newData
		if doneCb != nil {
			doneCb()
			doneCb = nil
		}
	}

	if s.gaps.Len() > protocol.MaxStreamFrameSorterGaps {
		return errors.New("too many gaps in received data")
	}

	s.queue[start] = frameSorterEntry{Data: data, DoneCb: doneCb}
	return nil
}

func (s *frameSorter) findStartGap(offset protocol.ByteCount) (*list.Element[byteInterval], bool) {
	// 遍历链表
	for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
		// 如果offset在gap的范围内，返回gap
		// gap.Start|offset|gap.End
		// 第一次插入时候肯定是返回的头结点，后续就会修改的
		if offset >= gap.Value.Start && offset <= gap.Value.End {
			return gap, true
		}
		// 如果offset在当前节点之前，返回该节点。
		// offset|gap.Start
		if offset < gap.Value.Start {
			return gap, false
		}
	}
	panic("no gap found")
}

func (s *frameSorter) findEndGap(startGap *list.Element[byteInterval], offset protocol.ByteCount) (*list.Element[byteInterval], bool) {
	for gap := startGap; gap != nil; gap = gap.Next() {
		// gap.Value.Start|offset|gap.Value.End
		if offset >= gap.Value.Start && offset < gap.Value.End {
			return gap, true
		}
		if offset < gap.Value.Start {
			return gap.Prev(), false
		}
	}
	panic("no gap found")
}

// deleteConsecutive deletes consecutive frames from the queue, starting at pos
func (s *frameSorter) deleteConsecutive(pos protocol.ByteCount) {
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		delete(s.queue, pos)
		if oldEntry.DoneCb != nil {
			oldEntry.DoneCb()
		}
		pos += oldEntryLen
	}
}

func (s *frameSorter) Pop() (protocol.ByteCount, []byte, func()) {
	entry, ok := s.queue[s.readPos]
	if !ok {
		return s.readPos, nil, nil
	}
	delete(s.queue, s.readPos)
	offset := s.readPos
	s.readPos += protocol.ByteCount(len(entry.Data))
	if s.gaps.Front().Value.End <= s.readPos {
		panic("frame sorter BUG: read position higher than a gap")
	}
	return offset, entry.Data, entry.DoneCb
}

// HasMoreData says if there is any more data queued at *any* offset.
func (s *frameSorter) HasMoreData() bool {
	return len(s.queue) > 0
}
