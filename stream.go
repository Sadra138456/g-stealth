// stream.go - Stream multiplexing layer
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrStreamClosed    = errors.New("stream closed")
	ErrConnectionClosed = errors.New("connection closed")
	ErrWindowExceeded  = errors.New("send window exceeded")
)

// Stream represents a multiplexed stream
type Stream struct {
	id         uint32
	conn       *Connection
	
	// Send state
	sendSeq    atomic.Uint32
	sendWindow atomic.Uint32
	sendBuf    chan []byte
	
	// Receive state
	recvSeq    atomic.Uint32
	recvWindow atomic.Uint32
	recvBuf    chan []byte
	recvQueue  map[uint32][]byte  // out-of-order packets
	recvMu     sync.Mutex
	
	// Flow control
	localWindow  atomic.Uint32
	remoteWindow atomic.Uint32
	
	closed atomic.Bool
	ctx    context.Context
	cancel context.CancelFunc
}

func newStream(id uint32, conn *Connection) *Stream {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Stream{
		id:       id,
		conn:     conn,
		sendBuf:  make(chan []byte, 32),
		recvBuf:  make(chan []byte, 32),
		recvQueue: make(map[uint32][]byte),
		ctx:      ctx,
		cancel:   cancel,
	}
	s.sendWindow.Store(InitialWindow)
	s.recvWindow.Store(InitialWindow)
	s.localWindow.Store(InitialWindow)
	s.remoteWindow.Store(InitialWindow)
	return s
}

// Write sends data on the stream
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}
	
	// Fragment large writes
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPayloadSize {
			chunk = p[:MaxPayloadSize]
		}
		
		// Wait for send window
		for s.sendWindow.Load() == 0 {
			if s.closed.Load() {
				return total, ErrStreamClosed
			}
			time.Sleep(time.Millisecond)
		}
		
		// Send packet
		seq := s.sendSeq.Add(1) - 1
		header := &PacketHeader{
			Version:    ProtocolVersion,
			Type:       PacketTypeStreamData,
			StreamID:   s.id,
			Sequence:   seq,
			WindowSize: uint16(s.localWindow.Load()),
		}
		
		if err := s.conn.sendPacket(header, chunk); err != nil {
			return total, err
		}
		
		s.sendWindow.Add(^uint32(0)) // decrement
		total += len(chunk)
		p = p[len(chunk):]
	}
	
	return total, nil
}

// Read receives data from the stream
func (s *Stream) Read(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}
	
	select {
	case data := <-s.recvBuf:
		n := copy(p, data)
		
		// Send ACK and update window
		s.localWindow.Add(1)
		ackHeader := &PacketHeader{
			Version:    ProtocolVersion,
			Type:       PacketTypeStreamAck,
			StreamID:   s.id,
			Sequence:   s.recvSeq.Load(),
			WindowSize: uint16(s.localWindow.Load()),
		}
		s.conn.sendPacket(ackHeader, nil)
		
		return n, nil
		
	case <-s.ctx.Done():
		return 0, ErrStreamClosed
	}
}

// Close closes the stream
func (s *Stream) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	
	s.cancel()
	
	// Send close packet
	header := &PacketHeader{
		Version:  ProtocolVersion,
		Type:     PacketTypeStreamClose,
		StreamID: s.id,
	}
	s.conn.sendPacket(header, nil)
	
	return nil
}

// handlePacket processes incoming packet for this stream
func (s *Stream) handlePacket(header *PacketHeader, payload []byte) {
	switch header.Type {
	case PacketTypeStreamData:
		s.handleData(header, payload)
	case PacketTypeStreamAck:
		s.handleAck(header)
	case PacketTypeStreamClose:
		s.Close()
	}
}

func (s *Stream) handleData(header *PacketHeader, payload []byte) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	
	expectedSeq := s.recvSeq.Load()
	
	if header.Sequence == expectedSeq {
		// In-order packet
		s.recvSeq.Add(1)
		s.localWindow.Add(^uint32(0)) // decrement
		
		select {
		case s.recvBuf <- payload:
		case <-s.ctx.Done():
		}
		
		// Check queue for next packets
		for {
			nextSeq := s.recvSeq.Load()
			if data, ok := s.recvQueue[nextSeq]; ok {
				delete(s.recvQueue, nextSeq)
				s.recvSeq.Add(1)
				select {
				case s.recvBuf <- data:
				case <-s.ctx.Done():
					return
				}
			} else {
				break
			}
		}
	} else if header.Sequence > expectedSeq {
		// Out-of-order, queue it
		s.recvQueue[header.Sequence] = payload
	}
	// Ignore duplicates (seq < expected)
}

func (s *Stream) handleAck(header *PacketHeader) {
	// Update remote window
	s.remoteWindow.Store(uint32(header.WindowSize))
	s.sendWindow.Store(uint32(header.WindowSize))
}

// Connection manages multiple streams over SpaceShuttleConn
type Connection struct {
	transport *SpaceShuttleConn
	
	streams   map[uint32]*Stream
	streamsMu sync.RWMutex
	nextID    atomic.Uint32
	
	// Congestion control
	cc *CongestionControl
	
	closed atomic.Bool
	ctx    context.Context
	cancel context.CancelFunc
}

// NewConnection creates a new multiplexed connection
func NewConnection(transport *SpaceShuttleConn) *Connection {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Connection{
		transport: transport,
		streams:   make(map[uint32]*Stream),
		cc:        NewCongestionControl(),
		ctx:       ctx,
		cancel:    cancel,
	}
	
	// Start receiver
	go c.receiveLoop()
	
	return c
}

// OpenStream opens a new stream
func (c *Connection) OpenStream() (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnectionClosed
	}
	
	id := c.nextID.Add(1)
	stream := newStream(id, c)
	
	c.streamsMu.Lock()
	c.streams[id] = stream
	c.streamsMu.Unlock()
	
	// Send stream open packet
	header := &PacketHeader{
		Version:  ProtocolVersion,
		Type:     PacketTypeStreamOpen,
		StreamID: id,
	}
	if err := c.sendPacket(header, nil); err != nil {
		return nil, err
	}
	
	return stream, nil
}

// AcceptStream waits for incoming stream (server side)
func (c *Connection) AcceptStream() (*Stream, error) {
	// This would be implemented with a channel of incoming streams
	// For now, simplified
	return nil, errors.New("not implemented")
}

// sendPacket sends a packet with congestion control
func (c *Connection) sendPacket(header *PacketHeader, payload []byte) error {
	if c.closed.Load() {
		return ErrConnectionClosed
	}
	
	// Wait for congestion control
	for !c.cc.CanSend() {
		time.Sleep(time.Millisecond)
	}
	
	// Update window in header
	header.WindowSize = uint16(c.cc.GetWindow())
	
	// Send via transport
	err := c.transport.SendPacket(header, payload, nil)
	if err == nil {
		c.cc.OnPacketSent(len(payload))
	} else {
		c.cc.OnPacketLost()
	}
	
	return err
}

// receiveLoop processes incoming packets
func (c *Connection) receiveLoop() {
	for {
		if c.closed.Load() {
			return
		}
		
		header, payload, _, err := c.transport.RecvPacket()
		if err != nil {
			if c.closed.Load() {
				return
			}
			continue
		}
		
		c.cc.OnPacketReceived(len(payload))
		
		// Route to stream
		c.streamsMu.RLock()
		stream, ok := c.streams[header.StreamID]
		c.streamsMu.RUnlock()
		
		if ok {
			stream.handlePacket(header, payload)
		} else if header.Type == PacketTypeStreamOpen {
			// New incoming stream
			stream = newStream(header.StreamID, c)
			c.streamsMu.Lock()
			c.streams[header.StreamID] = stream
			c.streamsMu.Unlock()
		}
	}
}

// Close closes the connection
func (c *Connection) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	
	c.cancel()
	
	// Close all streams
	c.streamsMu.Lock()
	for _, s := range c.streams {
		s.Close()
	}
	c.streamsMu.Unlock()
	
	return c.transport.Close()
}

// CongestionControl implements BBR-style congestion control
type CongestionControl struct {
	// Current state
	cwnd          atomic.Uint32  // congestion window
	ssthresh      atomic.Uint32  // slow start threshold
	bytesInFlight atomic.Uint32
	
	// RTT estimation
	minRTT        atomic.Int64   // nanoseconds
	smoothedRTT   atomic.Int64
	rttVar        atomic.Int64
	
	// BBR state
	btlBw         atomic.Uint64  // bottleneck bandwidth (bytes/sec)
	rtProp        atomic.Int64   // round-trip propagation delay
	
	// Pacing
	pacingRate    atomic.Uint64  // bytes/sec
	lastSendTime  atomic.Int64   // nanoseconds
	
	mu sync.Mutex
}

func NewCongestionControl() *CongestionControl {
	cc := &CongestionControl{}
	cc.cwnd.Store(InitialWindow)
	cc.ssthresh.Store(MaxWindow)
	cc.minRTT.Store(int64(100 * time.Millisecond))
	cc.smoothedRTT.Store(int64(100 * time.Millisecond))
	cc.pacingRate.Store(1024 * 1024) // 1 MB/s initial
	return cc
}

func (cc *CongestionControl) CanSend() bool {
	return cc.bytesInFlight.Load() < cc.cwnd.Load()*MaxPayloadSize
}

func (cc *CongestionControl) GetWindow() uint32 {
	return cc.cwnd.Load()
}

func (cc *CongestionControl) OnPacketSent(size int) {
	cc.bytesInFlight.Add(uint32(size))
	cc.lastSendTime.Store(time.Now().UnixNano())
}

func (cc *CongestionControl) OnPacketReceived(size int) {
	cc.bytesInFlight.Add(^uint32(size - 1)) // subtract
	
	// Update RTT
	now := time.Now().UnixNano()
	lastSend := cc.lastSendTime.Load()
	if lastSend > 0 {
		rtt := now - lastSend
		
		// Update min RTT
		minRTT := cc.minRTT.Load()
		if rtt < minRTT {
			cc.minRTT.Store(rtt)
		}
		
		// Smoothed RTT (exponential moving average)
		smoothed := cc.smoothedRTT.Load()
		smoothed = (7*smoothed + rtt) / 8
		cc.smoothedRTT.Store(smoothed)
	}
	
	// Increase window (additive increase)
	cwnd := cc.cwnd.Load()
	ssthresh := cc.ssthresh.Load()
	
	if cwnd < ssthresh {
		// Slow start: exponential growth
		cc.cwnd.Store(min(cwnd+1, MaxWindow))
	} else {
		// Congestion avoidance: linear growth
		if cwnd < MaxWindow {
			cc.cwnd.Store(cwnd + 1)
		}
	}
}

func (cc *CongestionControl) OnPacketLost() {
	// Multiplicative decrease
	cwnd := cc.cwnd.Load()
	cc.ssthresh.Store(max(cwnd/2, MinWindow))
	cc.cwnd.Store(max(cwnd/2, MinWindow))
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
