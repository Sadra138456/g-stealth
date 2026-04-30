package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// فرض بر این است که این مقادیر در protocol.go تعریف شده‌اند.
const (
	PacketTypeStreamData = 1
	PacketTypeAck        = 2
	PacketTypeClose      = 3
	ProtocolVersion      = 1
)

var (
	ErrStreamClosed   = errors.New("stream closed")
	ErrConnClosed     = errors.New("connection closed")
	ConnectionTimeout = 30 * time.Second
)

// =================================================================
// ساختارهای کنترل ارسال مجدد و ازدحام
// =================================================================

type unackedPacket struct {
	data    []byte
	sentAt  time.Time
	seq     uint32
	retries int
}

type CongestionControl struct {
	window   atomic.Uint32
	ssthresh atomic.Uint32
	rtt      atomic.Int64
	rttVar   atomic.Int64
	inFlight atomic.Uint32
	lastAck  atomic.Int64
	mu       sync.Mutex
}

// =================================================================
// مدیریت استریم (Stream)
// =================================================================

type Stream struct {
	id         uint32
	conn       *Connection
	sendSeq    atomic.Uint32
	recvSeq    atomic.Uint32 // شماره توالی بعدی که انتظار داریم بخوانیم
	sendWindow atomic.Uint32
	recvWindow atomic.Uint32
	closed     atomic.Bool

	sendBuf chan []byte
	recvBuf chan []byte // بافر دیتای مرتب شده برای خواندن توسط برنامه
	mu      sync.Mutex

	// مکانیزم مسدودسازی برای Flow Control
	windowCond *sync.Cond

	unacked   map[uint32]*unackedPacket
	unackedMu sync.Mutex

	// بافر مرتب‌سازی (Reordering Buffer)
	reorderBuf map[uint32][]byte
	reorderMu  sync.Mutex
}

func newStream(id uint32, conn *Connection) *Stream {
	s := &Stream{
		id:         id,
		conn:       conn,
		sendBuf:    make(chan []byte, 1024),
		recvBuf:    make(chan []byte, 1024),
		unacked:    make(map[uint32]*unackedPacket),
		reorderBuf: make(map[uint32][]byte),
	}
	s.windowCond = sync.NewCond(&s.mu)

	s.sendWindow.Store(1024)
	s.recvWindow.Store(1024)

	// اجرای حلقه مانیتورینگ برای ارسال مجدد بسته‌های تاییدنشده
	go s.retransmitLoop()

	return s
}

func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}

	s.mu.Lock()
	// تا زمانی که ظرفیت پنجره 0 است، تابع مسدود می‌شود
	for s.sendWindow.Load() == 0 {
		if s.closed.Load() {
			s.mu.Unlock()
			return 0, ErrStreamClosed
		}
		s.windowCond.Wait()
	}
	s.mu.Unlock()

	seq := s.sendSeq.Add(1)

	header := &PacketHeader{
		Version:    ProtocolVersion,
		Type:       PacketTypeStreamData,
		StreamID:   s.id,
		Sequence:   seq,
		Timestamp:  time.Now().UnixNano(),
		WindowSize: uint16(s.recvWindow.Load()),
	}

	dataCopy := make([]byte, len(p))
	copy(dataCopy, p)

	s.unackedMu.Lock()
	s.unacked[seq] = &unackedPacket{
		data:    dataCopy,
		sentAt:  time.Now(),
		seq:     seq,
		retries: 0,
	}
	s.unackedMu.Unlock()

	s.sendWindow.Add(^uint32(0)) // کاهش ظرفیت پنجره به اندازه ۱ واحد

	err := s.conn.sendPacket(header, dataCopy)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (s *Stream) Read(p []byte) (int, error) {
	if s.closed.Load() && len(s.recvBuf) == 0 {
		return 0, ErrStreamClosed
	}

	select {
	case data, ok := <-s.recvBuf:
		if !ok {
			return 0, ErrStreamClosed
		}

		n := copy(p, data)
		s.recvWindow.Add(1) // آزادسازی ظرفیت بافر دریافت
		return n, nil

	case <-time.After(ConnectionTimeout):
		return 0, errors.New("read timeout")
	}
}

func (s *Stream) Close() error {
	if s.closed.Swap(true) {
		return ErrStreamClosed
	}

	s.mu.Lock()
	close(s.sendBuf)
	close(s.recvBuf)
	// بیدار کردن Write در صورت مسدود بودن هنگام بستن
	s.windowCond.Broadcast()
	s.mu.Unlock()

	s.unackedMu.Lock()
	s.unacked = make(map[uint32]*unackedPacket)
	s.unackedMu.Unlock()

	// ارسال پکت بستن استریم به سمت مقابل
	header := &PacketHeader{
		Version:   ProtocolVersion,
		Type:      PacketTypeClose,
		StreamID:  s.id,
		Sequence:  s.sendSeq.Add(1),
		Timestamp: time.Now().UnixNano(),
	}
	s.conn.sendPacket(header, nil)

	return nil
}

func (s *Stream) HandleAck(ackSeq uint32, windowSize uint16) {
	s.unackedMu.Lock()
	if _, exists := s.unacked[ackSeq]; exists {
		delete(s.unacked, ackSeq)
		s.sendWindow.Add(1)
	}
	s.unackedMu.Unlock()

	s.sendWindow.Store(uint32(windowSize))

	// بیدار کردن تابع Write که به دلیل پر بودن پنجره متوقف شده بود
	s.windowCond.Broadcast()
}

func (s *Stream) HandleIncomingData(seq uint32, payload []byte) {
	s.reorderMu.Lock()
	defer s.reorderMu.Unlock()

	expectedSeq := s.recvSeq.Load() + 1

	// اگر بسته قدیمی است (احتمالاً تکراری است)، آن را نادیده می‌گیریم
	if seq < expectedSeq {
		return
	}

	// ذخیره بسته در بافر مرتب‌سازی
	s.reorderBuf[seq] = payload

	// انتقال بسته‌های مرتب‌شده متوالی به recvBuf
	for {
		data, ok := s.reorderBuf[expectedSeq]
		if !ok {
			break // بسته بعدی هنوز نرسیده است
		}

		// بررسی ظرفیت بافر دریافت
		if s.recvWindow.Load() > 0 {
			select {
			case s.recvBuf <- data:
				s.recvSeq.Store(expectedSeq)
				s.recvWindow.Add(^uint32(0)) // کاهش ظرفیت بافر دریافت
				delete(s.reorderBuf, expectedSeq)
				expectedSeq++
			default:
				// بافر چنل پر است
				return
			}
		} else {
			break // پنجره دریافت برنامه بسته است
		}
	}
}

func (s *Stream) retransmitLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeout := 400 * time.Millisecond

	for range ticker.C {
		if s.closed.Load() {
			return
		}

		now := time.Now()
		s.unackedMu.Lock()

		for seq, pkt := range s.unacked {
			if now.Sub(pkt.sentAt) > timeout {
				if pkt.retries >= 5 {
					// قطع استریم در صورت عدم دریافت ACK پس از ۵ تلاش
					s.unackedMu.Unlock()
					s.Close()
					return
				}

				pkt.retries++
				pkt.sentAt = now

				header := &PacketHeader{
					Version:    ProtocolVersion,
					Type:       PacketTypeStreamData,
					StreamID:   s.id,
					Sequence:   seq,
					Timestamp:  time.Now().UnixNano(),
					WindowSize: uint16(s.recvWindow.Load()),
				}

				go s.conn.sendPacket(header, pkt.data)
			}
		}
		s.unackedMu.Unlock()
	}
}

// =================================================================
// مدیریت اتصال (Connection و Demultiplexer)
// =================================================================

type Connection struct {
	transport       *SpaceShuttleConn
	streams         map[uint32]*Stream
	nextID          atomic.Uint32
	closed          atomic.Bool
	mu              sync.RWMutex
	congestion      *CongestionControl
	incomingStreams chan *Stream
}

func NewConnection(transport *SpaceShuttleConn) *Connection {
	c := &Connection{
		transport:       transport,
		streams:         make(map[uint32]*Stream),
		incomingStreams: make(chan *Stream, 128),
		congestion:      &CongestionControl{},
	}

	// شروع گوش دادن به پکت‌های ورودی از شبکه
	go c.readLoop()
	return c
}

func (c *Connection) sendPacket(header *PacketHeader, payload []byte) error {
	if c.closed.Load() {
		return ErrConnClosed
	}
	return c.transport.SendPacket(header, payload)
}

// readLoop پکت‌ها را می‌خواند و به استریم مناسب هدایت می‌کند (Demultiplexing)
func (c *Connection) readLoop() {
	for {
		if c.closed.Load() {
			return
		}

		header, payload, _, err := c.transport.RecvPacket()
		if err != nil {
			continue
		}

		c.mu.RLock()
		stream, exists := c.streams[header.StreamID]
		c.mu.RUnlock()

		switch header.Type {
		case PacketTypeStreamData:
			if !exists {
				// ایجاد استریم جدید
				stream = newStream(header.StreamID, c)
				c.mu.Lock()
				c.streams[header.StreamID] = stream
				c.mu.Unlock()

				select {
				case c.incomingStreams <- stream:
				default:
					continue
				}
			}

			// ارسال خودکار پکت ACK به فرستنده
			ackHeader := &PacketHeader{
				Version:    ProtocolVersion,
				Type:       PacketTypeAck,
				StreamID:   header.StreamID,
				Sequence:   header.Sequence,
				Timestamp:  time.Now().UnixNano(),
				WindowSize: uint16(stream.recvWindow.Load()),
			}
			c.sendPacket(ackHeader, nil)

			// ارسال دیتا به استریم جهت مرتب‌سازی و ذخیره
			if !stream.closed.Load() && len(payload) > 0 {
				stream.HandleIncomingData(header.Sequence, payload)
			}

		case PacketTypeAck:
			if exists {
				stream.HandleAck(header.Sequence, header.WindowSize)
			}

		case PacketTypeClose:
			if exists {
				stream.Close()
				c.mu.Lock()
				delete(c.streams, header.StreamID)
				c.mu.Unlock()
			}
		}
	}
}

func (c *Connection) AcceptStream() (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}
	stream, ok := <-c.incomingStreams
	if !ok {
		return nil, ErrConnClosed
	}
	return stream, nil
}

func (c *Connection) OpenStream() (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}
	id := c.nextID.Add(1)
	stream := newStream(id, c)

	c.mu.Lock()
	c.streams[id] = stream
	c.mu.Unlock()

	return stream, nil
}

func (c *Connection) Close() error {
	if c.closed.Swap(true) {
		return ErrConnClosed
	}

	c.mu.Lock()
	for _, s := range c.streams {
		s.Close()
	}
	c.streams = make(map[uint32]*Stream)
	c.mu.Unlock()

	close(c.incomingStreams)
	return nil
}
