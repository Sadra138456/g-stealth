// stream.go - بخش‌های اصلاح شده

package main

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrStreamClosed      = errors.New("stream closed")
	ErrConnectionClosed  = errors.New("connection closed")
	ErrWindowExceeded    = errors.New("send window exceeded")
	ErrInvalidSequence   = errors.New("invalid sequence number")
	ErrBufferFull        = errors.New("receive buffer full")
)

// Stream با قابلیت segmentation و reassembly
type Stream struct {
	id          uint32
	conn        *Connection
	sendSeq     uint32
	recvSeq     uint32
	sendWindow  uint32
	recvWindow  uint32
	recvBuf     chan []byte
	closed      atomic.Bool
	closeMu     sync.Mutex
	
	// برای reassembly
	pendingData map[uint32][]byte
	pendingMu   sync.Mutex
	
	// برای retransmission
	unackedPackets map[uint32]*unackedPacket
	unackedMu      sync.RWMutex
	
	congestion *CongestionControl
}

type unackedPacket struct {
	header      *PacketHeader
	payload     []byte
	sentTime    time.Time
	retries     int
}

func newStream(id uint32, conn *Connection) *Stream {
	s := &Stream{
		id:             id,
		conn:           conn,
		sendWindow:     InitialWindow,
		recvWindow:     InitialWindow,
		recvBuf:        make(chan []byte, 64),
		pendingData:    make(map[uint32][]byte),
		unackedPackets: make(map[uint32]*unackedPacket),
		congestion:     NewCongestionControl(),
	}
	
	go s.receiveLoop()
	go s.retransmitLoop()
	
	return s
}

// Write با segmentation برای payload های بزرگ
func (s *Stream) Write(data []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}
	
	totalWritten := 0
	offset := 0
	
	for offset < len(data) {
		// محاسبه chunk size
		chunkSize := min(MaxPayloadSize, len(data)-offset)
		chunk := data[offset : offset+chunkSize]
		
		// منتظر window space
		for {
			s.unackedMu.RLock()
			unacked := uint32(len(s.unackedPackets))
			s.unackedMu.RUnlock()
			
			if unacked < atomic.LoadUint32(&s.sendWindow) {
				break
			}
			
			// backpressure
			time.Sleep(10 * time.Millisecond)
			
			if s.closed.Load() {
				return totalWritten, ErrStreamClosed
			}
		}
		
		// ارسال chunk
		seq := atomic.AddUint32(&s.sendSeq, 1)
		
		header := &PacketHeader{
			Version:    ProtocolVersion,
			Type:       PacketTypeStreamData,
			StreamID:   s.id,
			Sequence:   seq,
			Timestamp:  time.Now().UnixNano(),
			WindowSize: uint16(atomic.LoadUint32(&s.recvWindow)),
			Flags:      0,
		}
		
		// ذخیره برای retransmission
		s.unackedMu.Lock()
		s.unackedPackets[seq] = &unackedPacket{
			header:   header,
			payload:  append([]byte(nil), chunk...),
			sentTime: time.Now(),
			retries:  0,
		}
		s.unackedMu.Unlock()
		
		// ارسال
		if err := s.conn.sendPacket(header, chunk); err != nil {
			return totalWritten, err
		}
		
		totalWritten += chunkSize
		offset += chunkSize
	}
	
	return totalWritten, nil
}

// Read با reassembly
func (s *Stream) Read(buf []byte) (int, error) {
	if s.closed.Load() && len(s.recvBuf) == 0 {
		return 0, io.EOF
	}
	
	select {
	case data := <-s.recvBuf:
		n := copy(buf, data)
		return n, nil
		
	case <-time.After(30 * time.Second):
		if s.closed.Load() {
			return 0, io.EOF
		}
		return 0, errors.New("read timeout")
	}
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

// handleData با out-of-order buffering
func (s *Stream) handleData(header *PacketHeader, payload []byte) {
	expectedSeq := atomic.LoadUint32(&s.recvSeq) + 1
	
	// ارسال ACK
	ackHeader := &PacketHeader{
		Version:    ProtocolVersion,
		Type:       PacketTypeStreamAck,
		StreamID:   s.id,
		Sequence:   header.Sequence,
		Timestamp:  time.Now().UnixNano(),
		WindowSize: uint16(atomic.LoadUint32(&s.recvWindow)),
	}
	s.conn.sendPacket(ackHeader, nil)
	
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	
	if header.Sequence < expectedSeq {
		// duplicate, ignore
		return
	}
	
	if header.Sequence == expectedSeq {
		// in-order packet
		atomic.StoreUint32(&s.recvSeq, header.Sequence)
		
		// ارسال به buffer با backpressure
		select {
		case s.recvBuf <- append([]byte(nil), payload...):
		default:
			// buffer full - این یک مشکل جدی است
			// در production باید log بشه
		}
		
		// چک کردن pending packets
		s.deliverPendingPackets()
		
	} else {
		// out-of-order packet - buffer کن
		if len(s.pendingData) < 100 { // محدودیت buffer
			s.pendingData[header.Sequence] = append([]byte(nil), payload...)
		}
	}
}

func (s *Stream) deliverPendingPackets() {
	for {
		nextSeq := atomic.LoadUint32(&s.recvSeq) + 1
		data, ok := s.pendingData[nextSeq]
		if !ok {
			break
		}
		
		delete(s.pendingData, nextSeq)
		atomic.StoreUint32(&s.recvSeq, nextSeq)
		
		select {
		case s.recvBuf <- data:
		default:
			// buffer full
			return
		}
	}
}

func (s *Stream) handleAck(header *PacketHeader) {
	s.unackedMu.Lock()
	delete(s.unackedPackets, header.Sequence)
	s.unackedMu.Unlock()
	
	// update window
	if header.WindowSize > 0 {
		atomic.StoreUint32(&s.sendWindow, uint32(header.WindowSize))
	}
	
	// update congestion control
	s.congestion.OnAck()
}

func (s *Stream) retransmitLoop() {
	ticker := time.NewTicker(RetransmitTimeout)
	defer ticker.Stop()
	
	for !s.closed.Load() {
		<-ticker.C
		
		now := time.Now()
		s.unackedMu.Lock()
		
		for seq, pkt := range s.unackedPackets {
			if now.Sub(pkt.sentTime) > RetransmitTimeout {
				if pkt.retries >= MaxRetransmits {
					// give up
					delete(s.unackedPackets, seq)
					continue
				}
				
				// retransmit
				pkt.sentTime = now
				pkt.retries++
				s.conn.sendPacket(pkt.header, pkt.payload)
			}
		}
		
		s.unackedMu.Unlock()
	}
}

func (s *Stream) receiveLoop() {
	// این loop توسط Connection.handleIncoming فراخوانی میشه
}

func (s *Stream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	
	header := &PacketHeader{
		Version:   ProtocolVersion,
		Type:      PacketTypeStreamClose,
		StreamID:  s.id,
		Timestamp: time.Now().UnixNano(),
	}
	
	s.conn.sendPacket(header, nil)
	close(s.recvBuf)
	
	return nil
}

// Connection
type Connection struct {
	transport       *SpaceShuttleConn
	streams         map[uint32]*Stream
	streamsMu       sync.RWMutex
	nextStreamID    uint32
	incomingStreams chan *Stream
	closed          atomic.Bool
}

func NewConnection(transport *SpaceShuttleConn) *Connection {
	c := &Connection{
		transport:       transport,
		streams:         make(map[uint32]*Stream),
		incomingStreams: make(chan *Stream, 16),
	}
	
	go c.handleIncoming()
	
	return c
}

func (c *Connection) sendPacket(header *PacketHeader, payload []byte) error {
	// FIX: حذف آرگومان سوم که اشتباه بود
	return c.transport.SendPacket(header, payload)
}

func (c *Connection) handleIncoming() {
	for !c.closed.Load() {
		header, payload, err := c.transport.RecvPacket()
		if err != nil {
			if c.closed.Load() {
				return
			}
			continue
		}
		
		// validation
		if header.Version != ProtocolVersion {
			continue
		}
		
		c.streamsMu.RLock()
		stream, exists := c.streams[header.StreamID]
		c.streamsMu.RUnlock()
		
		if !exists {
			if header.Type == PacketTypeStreamOpen {
				stream = newStream(header.StreamID, c)
				c.streamsMu.Lock()
				c.streams[header.StreamID] = stream
				c.streamsMu.Unlock()
				
				select {
				case c.incomingStreams <- stream:
				default:
					// incoming queue full
					stream.Close()
				}
			}
			continue
		}
		
		stream.handlePacket(header, payload)
	}
}

func (c *Connection) OpenStream() (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnectionClosed
	}
	
	streamID := atomic.AddUint32(&c.nextStreamID, 1)
	stream := newStream(streamID, c)
	
	c.streamsMu.Lock()
	c.streams[streamID] = stream
	c.streamsMu.Unlock()
	
	header := &PacketHeader{
		Version:   ProtocolVersion,
		Type:      PacketTypeStreamOpen,
		StreamID:  streamID,
		Timestamp: time.Now().UnixNano(),
	}
	
	if err := c.sendPacket(header, nil); err != nil {
		return nil, err
	}
	
	return stream, nil
}

func (c *Connection) AcceptStream() (*Stream, error) {
	select {
	case stream := <-c.incomingStreams:
		return stream, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("accept timeout")
	}
}

func (c *Connection) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	
	c.streamsMu.Lock()
	for _, stream := range c.streams {
		stream.Close()
	}
	c.streamsMu.Unlock()
	
	return c.transport.Close()
}

// CongestionControl
type CongestionControl struct {
	cwnd     uint32
	ssthresh uint32
	mu       sync.Mutex
}

func NewCongestionControl() *CongestionControl {
	return &CongestionControl{
		cwnd:     InitialWindow,
		ssthresh: MaxWindow / 2,
	}
}

func (cc *CongestionControl) OnAck() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	if cc.cwnd < cc.ssthresh {
		// slow start
		cc.cwnd++
	} else {
		// congestion avoidance
		cc.cwnd += 1 / cc.cwnd
	}
	
	if cc.cwnd > MaxWindow {
		cc.cwnd = MaxWindow
	}
}

func (cc *CongestionControl) OnLoss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	cc.ssthresh = cc.cwnd / 2
	cc.cwnd = MinWindow
}

func (cc *CongestionControl) Window() uint32 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.cwnd
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
