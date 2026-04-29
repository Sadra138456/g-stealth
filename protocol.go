package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Protocol constants
const (
	ProtocolVersion   = 1
	MaxPacketSize     = 1350
	MaxPayloadSize    = 1200
	MinPaddingSize    = 16
	MaxPaddingSize    = 128
	NonceSize         = 24 // XChaCha20-Poly1305 uses 24-byte nonces
	TagSize           = 16
	HeaderSize        = 22 // Version(1) + Type(1) + StreamID(4) + Sequence(4) + Timestamp(8) + WindowSize(2) + Flags(2)
	SendBufferSize    = 4 * 1024 * 1024
	RecvBufferSize    = 4 * 1024 * 1024
	MaxStreamsPerConn = 256
	StreamBufferSize  = 64 * 1024
	MaxPacketAge      = 5 * time.Second
	KeepAliveInterval = 10 * time.Second
	ConnectionTimeout = 30 * time.Second
	RetransmitTimeout = 200 * time.Millisecond
	MaxRetransmits    = 5
	InitialWindow     = 10
	MaxWindow         = 1000
	MinWindow         = 2
)

// Packet types
const (
	PacketTypeData byte = iota
	PacketTypeAck
	PacketTypePing
	PacketTypePong
	PacketTypeStreamOpen
	PacketTypeStreamClose
	PacketTypeStreamData
	PacketTypeStreamAck
	PacketTypeReset
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, MaxPacketSize)
		return &buf
	},
}

type PacketHeader struct {
	Version    uint8
	Type       uint8
	StreamID   uint32
	Sequence   uint32
	Timestamp  int64
	WindowSize uint16
	Flags      uint16
}

func (h *PacketHeader) Encode(buf []byte) {
	buf[0] = h.Version
	buf[1] = h.Type
	binary.BigEndian.PutUint32(buf[2:6], h.StreamID)
	binary.BigEndian.PutUint32(buf[6:10], h.Sequence)
	binary.BigEndian.PutUint64(buf[10:18], uint64(h.Timestamp))
	binary.BigEndian.PutUint16(buf[18:20], h.WindowSize)
	binary.BigEndian.PutUint16(buf[20:22], h.Flags)
}

func (h *PacketHeader) Decode(buf []byte) error {
	if len(buf) < HeaderSize {
		return errors.New("buffer too small for header")
	}
	h.Version = buf[0]
	h.Type = buf[1]
	h.StreamID = binary.BigEndian.Uint32(buf[2:6])
	h.Sequence = binary.BigEndian.Uint32(buf[6:10])
	h.Timestamp = int64(binary.BigEndian.Uint64(buf[10:18]))
	h.WindowSize = binary.BigEndian.Uint16(buf[18:20])
	h.Flags = binary.BigEndian.Uint16(buf[20:22])
	return nil
}

type SpaceShuttleConn struct {
	conn       *net.UDPConn
	cipher     cipher.AEAD // ✅ تغییر از *chacha20poly1305.XChaCha20Poly1305 به cipher.AEAD
	remoteAddr *net.UDPAddr

	// Statistics
	bytesSent     uint64
	bytesReceived uint64
	packetsSent   uint64
	packetsRecv   uint64
	packetsLost   uint64

	// Adaptive delay
	adaptiveDelay time.Duration
	delayMu       sync.RWMutex

	closed uint32
	mu     sync.RWMutex
}

func NewSpaceShuttleConn(localAddr string, remoteAddr string, key []byte) (*SpaceShuttleConn, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", chacha20poly1305.KeySize, len(key))
	}

	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local address: %w", err)
	}

	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve remote address: %w", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}

	if err := conn.SetReadBuffer(RecvBufferSize); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set read buffer: %w", err)
	}

	if err := conn.SetWriteBuffer(SendBufferSize); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set write buffer: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	sc := &SpaceShuttleConn{
		conn:          conn,
		cipher:        aead,
		remoteAddr:    raddr,
		adaptiveDelay: 0,
	}

	return sc, nil
}

func (sc *SpaceShuttleConn) SendPacket(header *PacketHeader, payload []byte) error {
	if atomic.LoadUint32(&sc.closed) == 1 {
		return errors.New("connection closed")
	}

	headerBuf := make([]byte, HeaderSize)
	header.Encode(headerBuf)

	padding := sc.calculatePadding(len(payload))
	plaintext := make([]byte, HeaderSize+len(payload)+padding+1)
	copy(plaintext[0:HeaderSize], headerBuf)
	copy(plaintext[HeaderSize:], payload)
	if padding > 0 {
		if _, err := rand.Read(plaintext[HeaderSize+len(payload) : HeaderSize+len(payload)+padding]); err != nil {
			return fmt.Errorf("failed to generate padding: %w", err)
		}
	}
	plaintext[len(plaintext)-1] = byte(padding)

	nonce := make([]byte, sc.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := sc.cipher.Seal(nonce, nonce, plaintext, nil)

	sc.delayMu.RLock()
	delay := sc.adaptiveDelay
	sc.delayMu.RUnlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	_, err := sc.conn.WriteToUDP(ciphertext, sc.remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	atomic.AddUint64(&sc.bytesSent, uint64(len(ciphertext)))
	atomic.AddUint64(&sc.packetsSent, 1)

	return nil
}

func (sc *SpaceShuttleConn) RecvPacket() (*PacketHeader, []byte, *net.UDPAddr, error) {
	if atomic.LoadUint32(&sc.closed) == 1 {
		return nil, nil, nil, errors.New("connection closed")
	}

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	n, addr, err := sc.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to receive packet: %w", err)
	}

	atomic.AddUint64(&sc.bytesReceived, uint64(n))
	atomic.AddUint64(&sc.packetsRecv, 1)

	if n < sc.cipher.NonceSize()+sc.cipher.Overhead() {
		return nil, nil, nil, errors.New("packet too small")
	}

	nonce := buf[:sc.cipher.NonceSize()]
	ciphertext := buf[sc.cipher.NonceSize():n]

	plaintext, err := sc.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt packet: %w", err)
	}

	if len(plaintext) < HeaderSize+1 {
		return nil, nil, nil, errors.New("plaintext too small")
	}

	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen > len(plaintext)-HeaderSize-1 {
		return nil, nil, nil, errors.New("invalid padding length")
	}

	payloadEnd := len(plaintext) - paddingLen - 1

	header := &PacketHeader{}
	if err := header.Decode(plaintext[:HeaderSize]); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	payload := make([]byte, payloadEnd-HeaderSize)
	copy(payload, plaintext[HeaderSize:payloadEnd])

	return header, payload, addr, nil
}

func (sc *SpaceShuttleConn) calculatePadding(payloadSize int) int {
	totalSize := HeaderSize + payloadSize
	if totalSize >= MaxPayloadSize {
		return 0
	}
	maxPad := min(MaxPaddingSize, MaxPayloadSize-totalSize)
	if maxPad < MinPaddingSize {
		return 0
	}
	padBuf := make([]byte, 1)
	rand.Read(padBuf)
	return MinPaddingSize + int(padBuf[0])%(maxPad-MinPaddingSize+1)
}

func (sc *SpaceShuttleConn) SetAdaptiveDelay(delay time.Duration) {
	sc.delayMu.Lock()
	sc.adaptiveDelay = delay
	sc.delayMu.Unlock()
}

func (sc *SpaceShuttleConn) GetStats() (sent, recv, pktSent, pktRecv, pktLost uint64) {
	return atomic.LoadUint64(&sc.bytesSent),
		atomic.LoadUint64(&sc.bytesReceived),
		atomic.LoadUint64(&sc.packetsSent),
		atomic.LoadUint64(&sc.packetsRecv),
		atomic.LoadUint64(&sc.packetsLost)
}

func (sc *SpaceShuttleConn) Close() error {
	if !atomic.CompareAndSwapUint32(&sc.closed, 0, 1) {
		return nil
	}
	return sc.conn.Close()
}

func (sc *SpaceShuttleConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

func (sc *SpaceShuttleConn) RemoteAddr() net.Addr {
	return sc.remoteAddr
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
