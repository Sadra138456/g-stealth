package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrStreamClosed      = errors.New("stream closed")
	ErrConnectionClosed  = errors.New("connection closed")
	ErrWindowExceeded    = errors.New("send window exceeded")
)

type Stream struct {
	id         uint32
	conn       *Connection
	sendSeq    atomic.Uint32
	recvSeq    atomic.Uint32
	sendWindow atomic.Uint32
	recvWindow atomic.Uint32
	closed     atomic.Bool

	sendBuf chan []byte
	recvBuf chan []byte

	mu sync.Mutex
}

type Connection struct {
	transport *SpaceShuttleConn
	streams   map[uint32]*Stream
	nextID    atomic.Uint32
	closed    atomic.Bool

	mu sync.RWMutex

	congestion *CongestionControl
	incomingStreams chan *Stream
}

type CongestionControl struct {
	window     atomic.Uint32
	ssthresh   atomic.Uint32
	rtt        atomic.Int64
	rttVar     atomic.Int64
	inFlight   atomic.Uint32
	lastAck    atomic.Int64

	mu sync.Mutex
}

func newStream(id uint32, conn *Connection) *Stream {
	s := &Stream{
		id:      id,
		conn:    conn,
		sendBuf: make(chan []byte, 32),
		recvBuf: make(chan []byte, 32),
	}
	s.sendWindow.Store(InitialWindow)
	s.recvWindow.Store(InitialWindow)
	return s
}

func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}

	header := &PacketHeader{
		Version:    ProtocolVersion,
		Type:       PacketTypeStreamData,
		StreamID:   s.id,
		Sequence:   s.sendSeq.Add(1),
		Timestamp:  time.Now().UnixNano(),
		WindowSize: uint16(s.recvWindow.Load()),
	}

	if err := s.conn.sendPacket(header, p); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (s *Stream) Read(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}

	select {
	case data := <-s.recvBuf:
		n := copy(p, data)
		return n, nil
	case <-time.After(ConnectionTimeout):
		return 0, errors.New("read timeout")
	}
}

func (s *Stream) Close() error {
	if s.closed.Swap(true) {
		return nil
	}

	header := &PacketHeader{
		Version:   ProtocolVersion,
		Type:      PacketTypeStreamClose,
		StreamID:  s.id,
		Timestamp: time.Now().UnixNano(),
	}

	s.conn.sendPacket(header, nil)

	s.conn.mu.Lock()
	delete(s.conn.streams, s.id)
	s.conn.mu.Unlock()

	close(s.sendBuf)
	close(s.recvBuf)

	return nil
}

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
	expectedSeq := s.recvSeq.Load() + 1
	if header.Sequence != expectedSeq {
		return
	}

	s.recvSeq.Store(header.Sequence)

	if len(payload) > 0 {
		dataCopy := make([]byte, len(payload))
		copy(dataCopy, payload)

		select {
		case s.recvBuf <- dataCopy:
		default:
		}
	}

	ackHeader := &PacketHeader{
		Version:   ProtocolVersion,
		Type:      PacketTypeStreamAck,
		StreamID:  s.id,
		Sequence:  header.Sequence,
		Timestamp: time.Now().UnixNano(),
	}
	s.conn.sendPacket(ackHeader, nil)
}

func (s *Stream) handleAck(header *PacketHeader) {
	s.sendWindow.Add(1)
	s.conn.congestion.onAck(header.Sequence)
}

func NewConnection(transport *SpaceShuttleConn) *Connection {
	c := &Connection{
		transport:       transport,
		streams:         make(map[uint32]*Stream),
		congestion:      NewCongestionControl(),
		incomingStreams: make(chan *Stream, 16),
	}
	c.nextID.Store(1)

	go c.receiveLoop()

	return c
}

func (c *Connection) OpenStream() (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnectionClosed
	}

	id := c.nextID.Add(2)
	stream := newStream(id, c)

	c.mu.Lock()
	c.streams[id] = stream
	c.mu.Unlock()

	header := &PacketHeader{
		Version:   ProtocolVersion,
		Type:      PacketTypeStreamOpen,
		StreamID:  id,
		Timestamp: time.Now().UnixNano(),
	}

	if err := c.sendPacket(header, nil); err != nil {
		c.mu.Lock()
		delete(c.streams, id)
		c.mu.Unlock()
		return nil, err
	}

	return stream, nil
}

func (c *Connection) AcceptStream() (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnectionClosed
	}

	select {
	case stream := <-c.incomingStreams:
		return stream, nil
	case <-time.After(ConnectionTimeout):
		return nil, errors.New("accept timeout")
	}
}

func (c *Connection) sendPacket(header *PacketHeader, payload []byte) error {
	if c.closed.Load() {
		return ErrConnectionClosed
	}

	return c.transport.SendPacket(header, payload, nil)
}

func (c *Connection) receiveLoop() {
	for !c.closed.Load() {
		header, payload, _, err := c.transport.RecvPacket()
		if err != nil {
			if c.closed.Load() {
				return
			}
			continue
		}

		switch header.Type {
		case PacketTypeStreamOpen:
			c.mu.Lock()
			if _, exists := c.streams[header.StreamID]; !exists {
				stream := newStream(header.StreamID, c)
				c.streams[header.StreamID] = stream

				select {
				case c.incomingStreams <- stream:
				default:
				}
			}
			c.mu.Unlock()

		case PacketTypeStreamData, PacketTypeStreamAck, PacketTypeStreamClose:
			c.mu.RLock()
			stream, exists := c.streams[header.StreamID]
			c.mu.RUnlock()

			if exists {
				stream.handlePacket(header, payload)
			}

		case PacketTypePing:
			pongHeader := &PacketHeader{
				Version:   ProtocolVersion,
				Type:      PacketTypePong,
				Timestamp: time.Now().UnixNano(),
			}
			c.sendPacket(pongHeader, nil)
		}
	}
}

func (c *Connection) Close() error {
	if c.closed.Swap(true) {
		return nil
	}

	c.mu.Lock()
	for _, stream := range c.streams {
		stream.Close()
	}
	c.streams = nil
	c.mu.Unlock()

	close(c.incomingStreams)

	return c.transport.Close()
}

func NewCongestionControl() *CongestionControl {
	cc := &CongestionControl{}
	cc.window.Store(InitialWindow)
	cc.ssthresh.Store(MaxWindow / 2)
	cc.rtt.Store(int64(100 * time.Millisecond))
	cc.rttVar.Store(int64(50 * time.Millisecond))
	return cc
}

func (cc *CongestionControl) onAck(seq uint32) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.inFlight.Add(^uint32(0))

	window := cc.window.Load()
	ssthresh := cc.ssthresh.Load()

	if window < ssthresh {
		cc.window.Store(window + 1)
	} else {
		if window < MaxWindow {
			cc.window.Store(window + 1)
		}
	}

	cc.lastAck.Store(time.Now().UnixNano())
}

func (cc *CongestionControl) onLoss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	window := cc.window.Load()
	cc.ssthresh.Store(window / 2)
	cc.window.Store(MinWindow)
}

func (cc *CongestionControl) getWindow() uint32 {
	return cc.window.Load()
}
