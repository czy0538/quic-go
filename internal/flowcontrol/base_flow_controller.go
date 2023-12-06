package flowcontrol

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type baseFlowController struct {
	// for sending data
	bytesSent     protocol.ByteCount
	sendWindow    protocol.ByteCount
	lastBlockedAt protocol.ByteCount

	// for receiving data
	//nolint:structcheck // The mutex is used both by the stream and the connection flow controller
	mutex                sync.Mutex
	bytesRead            protocol.ByteCount // 已经被应用读取的数据的offset
	highestReceived      protocol.ByteCount // 收到数据的最大offset
	receiveWindow        protocol.ByteCount // 接收窗口的最大偏移量
	receiveWindowSize    protocol.ByteCount // 接受窗口的大小
	maxReceiveWindowSize protocol.ByteCount // 接收窗口的最大大小

	allowWindowIncrease func(size protocol.ByteCount) bool

	epochStartTime   time.Time
	epochStartOffset protocol.ByteCount
	rttStats         *utils.RTTStats

	logger utils.Logger
}

// IsNewlyBlocked says if it is newly blocked by flow control.
// For every offset, it only returns true once.
// If it is blocked, the offset is returned.
func (c *baseFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	if c.sendWindowSize() != 0 || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
}

func (c *baseFlowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

// UpdateSendWindow is called after receiving a MAX_{STREAM_}DATA frame.
func (c *baseFlowController) UpdateSendWindow(offset protocol.ByteCount) {
	if offset > c.sendWindow {
		c.sendWindow = offset
	}
}

func (c *baseFlowController) sendWindowSize() protocol.ByteCount {
	// this only happens during connection establishment, when data is sent before we receive the peer's transport parameters
	if c.bytesSent > c.sendWindow {
		return 0
	}
	return c.sendWindow - c.bytesSent
}

// needs to be called with locked mutex
func (c *baseFlowController) addBytesRead(n protocol.ByteCount) {
	// pretend we sent a WindowUpdate when reading the first byte
	// this way auto-tuning of the window size already works for the first WindowUpdate
	if c.bytesRead == 0 {
		c.startNewAutoTuningEpoch(time.Now())
	}
	c.bytesRead += n
}

func (c *baseFlowController) hasWindowUpdate() bool {
	// 计算接收窗口的剩余量
	bytesRemaining := c.receiveWindow - c.bytesRead
	// update the window when more than the threshold was consumed
	// 如果当前的接收窗口的剩余量，小于等于接收窗口总量的0.75，就需要更新接收窗口了
	// 即当使用超过75%的接收窗口时，更新接收窗口
	return bytesRemaining <= protocol.ByteCount(float64(c.receiveWindowSize)*(1-protocol.WindowUpdateThreshold))
}

// getWindowUpdate updates the receive window, if necessary
// it returns the new offset
func (c *baseFlowController) getWindowUpdate() protocol.ByteCount {
	// 判断是否使用了超过75%的接收窗口
	if !c.hasWindowUpdate() {
		return 0
	}

	// 计算是否需要调整窗口大小
	c.maybeAdjustWindowSize()
	// receiveWindow 前移
	c.receiveWindow = c.bytesRead + c.receiveWindowSize
	return c.receiveWindow
}

// maybeAdjustWindowSize increases the receiveWindowSize if we're sending updates too often.
// For details about auto-tuning, see https://docs.google.com/document/d/1SExkMmGiz8VYzV3s9E35JQlJ73vhzCekKkDi85F1qCE/edit?usp=sharing.
func (c *baseFlowController) maybeAdjustWindowSize() {
	// 计算发送方在一段时间内发送过来的连续的数据量
	// 或者说计算接收方在一段时间内消费的数据量
	bytesReadInEpoch := c.bytesRead - c.epochStartOffset
	// don't do anything if less than half the window has been consumed
	if bytesReadInEpoch <= c.receiveWindowSize/2 {
		return
	}
	// 获取RTT，如何计算未知
	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	fraction := float64(bytesReadInEpoch) / float64(c.receiveWindowSize)
	now := time.Now()
	if now.Sub(c.epochStartTime) < time.Duration(4*fraction*float64(rtt)) {
		// window is consumed too fast, try to increase the window size
		newSize := utils.Min(2*c.receiveWindowSize, c.maxReceiveWindowSize)
		if newSize > c.receiveWindowSize && (c.allowWindowIncrease == nil || c.allowWindowIncrease(newSize-c.receiveWindowSize)) {
			c.receiveWindowSize = newSize
		}
	}
	c.startNewAutoTuningEpoch(now)
}

func (c *baseFlowController) startNewAutoTuningEpoch(now time.Time) {
	c.epochStartTime = now
	c.epochStartOffset = c.bytesRead
}

func (c *baseFlowController) checkFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}
