package main // در صورتی که پکیج شما نام دیگری دارد، آن را تغییر دهید

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrStreamClosed   = errors.New("stream closed")
	ErrWindowFull     = errors.New("send window is full")
	ConnectionTimeout = 30 * time.Second
)

// ساختار برای نگهداری بسته‌هایی که هنوز ACK آن‌ها دریافت نشده است
type unackedPacket struct {
	header []byte
	data   []byte
	sentAt time.Time
	seq    uint32
	retries int
}

// -----------------------------------------------------------------
// ساختار استریم (Stream)
// -----------------------------------------------------------------
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
	mu      sync.Mutex

	// فیلدهای کنترل ارسال مجدد
	unacked   map[uint32]*unackedPacket
	unackedMu sync.Mutex
}

func newStream(id uint32, conn *Connection) *Stream {
	s := &Stream{
		id:      id,
		conn:    conn,
		sendBuf: make(chan []byte, 1024),
		recvBuf: make(chan []byte, 1024),
		unacked: make(map[uint32]*unackedPacket),
	}
	
	s.sendWindow.Store(1024) // ظرفیت اولیه پنجره ارسال
	s.recvWindow.Store(1024) // ظرفیت اولیه پنجره دریافت

	// شروع حلقه مانیتورینگ برای ارسال مجدد در پس‌زمینه
	go s.retransmitLoop()

	return s
}

// -----------------------------------------------------------------
// توابع اصلی استریم (Write, Read, Close)
// -----------------------------------------------------------------

func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}

	// کنترل جریان: اگر پنجره ارسال پر شده باشد، منتظر می‌مانیم یا خطا می‌دهیم
	// در یک پیاده‌سازی پیشرفته‌تر، اینجا باید از channel برای بلاک کردن استفاده شود
	if s.sendWindow.Load() == 0 {
		return 0, ErrWindowFull
	}

	seq := s.sendSeq.Add(1)

	// ساخت هدر (باید مطابق با ساختار protocol.go شما باشد)
	// فرض بر این است که PacketHeader در protocol.go تعریف شده است
	header := &PacketHeader{
		Version:    ProtocolVersion, 
		Type:       PacketTypeStreamData, 
		StreamID:   s.id,
		Sequence:   seq,
		Timestamp:  time.Now().UnixNano(),
		WindowSize: uint16(s.recvWindow.Load()),
	}

	// کپی کردن داده‌ها برای جلوگیری از تغییر ناخواسته توسط لایه‌های بالاتر
	dataCopy := make([]byte, len(p))
	copy(dataCopy, p)

	// ذخیره بسته در لیست بسته‌های در انتظار ACK
	s.unackedMu.Lock()
	s.unacked[seq] = &unackedPacket{
		header:  nil, // اگر متد header.Bytes() دارید اینجا قرار دهید
		data:    dataCopy,
		sentAt:  time.Now(),
		seq:     seq,
		retries: 0,
	}
	s.unackedMu.Unlock()

	// کاهش ظرفیت پنجره ارسال به اندازه 1
	s.sendWindow.Add(^uint32(0)) 

	// ارسال بسته به لایه Connection
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
		
		// کپی داده‌های دریافت شده به بافر کاربر
		n := copy(p, data)
		
		// باز کردن فضای پنجره دریافت پس از خواندن برنامه
		s.recvWindow.Add(1) 
		
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
	defer s.mu.Unlock()

	// بستن کانال‌ها به صورت امن
	close(s.sendBuf)
	close(s.recvBuf)

	// پاکسازی لیست Unacked
	s.unackedMu.Lock()
	s.unacked = make(map[uint32]*unackedPacket)
	s.unackedMu.Unlock()

	return nil
}

// -----------------------------------------------------------------
// توابع مدیریت قابلیت اطمینان (ACK و Retransmission)
// -----------------------------------------------------------------

// HandleAck توسط Connection فراخوانی می‌شود وقتی پکت ACK برای این استریم می‌رسد
func (s *Stream) HandleAck(ackSeq uint32, windowSize uint16) {
	s.unackedMu.Lock()
	defer s.unackedMu.Unlock()

	if _, exists := s.unacked[ackSeq]; exists {
		delete(s.unacked, ackSeq) // حذف بسته تایید شده
		s.sendWindow.Add(1)       // افزایش ظرفیت پنجره ارسال
	}

	// به‌روزرسانی پنجره ارسال با توجه به ظرفیت اعلام شده گیرنده
	s.sendWindow.Store(uint32(windowSize))
}

func (s *Stream) retransmitLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeout := 400 * time.Millisecond // زمان انتظار قبل از ارسال مجدد

	for range ticker.C {
		if s.closed.Load() {
			return
		}

		now := time.Now()
		s.unackedMu.Lock()
		
		for seq, pkt := range s.unacked {
			if now.Sub(pkt.sentAt) > timeout {
				if pkt.retries >= 5 {
					// اگر ۵ بار تلاش کردیم و جواب نیامد، استریم قطع می‌شود
					s.unackedMu.Unlock()
					s.Close()
					return
				}

				pkt.retries++
				pkt.sentAt = now
				
				// ساخت مجدد هدر برای ارسال مجدد (جهت آپدیت تایم‌استمپ)
				header := &PacketHeader{
					Version:    ProtocolVersion, 
					Type:       PacketTypeStreamData, 
					StreamID:   s.id,
					Sequence:   seq,
					Timestamp:  time.Now().UnixNano(),
					WindowSize: uint16(s.recvWindow.Load()),
				}

				// ارسال مجدد بدون بلاک کردن در صورت امکان
				go s.conn.sendPacket(header, pkt.data)
			}
		}
		s.unackedMu.Unlock()
	}
}

// -----------------------------------------------------------------
// ساختارهای اتصال و کنترل ازدحام
// -----------------------------------------------------------------

type Connection struct {
	transport       *SpaceShuttleConn // تعریف شده در protocol.go
	streams         map[uint32]*Stream
	nextID          atomic.Uint32
	closed          atomic.Bool
	mu              sync.RWMutex
	congestion      *CongestionControl
	incomingStreams chan *Stream
}

// متدهای مرتبط با Connection (مانند sendPacket) اینجا قرار می‌گیرند...
func (c *Connection) sendPacket(header *PacketHeader, payload []byte) error {
	// پیاده‌سازی اتصال به transport.SendPacket
	// ...
	return nil
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
