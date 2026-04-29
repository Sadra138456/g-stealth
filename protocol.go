package main

import (
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

const (
	ProtocolVersion = 1
	MaxPacketSize   = 1350
	MaxPayloadSize  = 1200
	MinPaddingSize  = 16
	MaxPaddingSize  = 128
	NonceSize       = 24 // XChaCha20 uses 24-byte nonce
	TagSize         = 16
	HeaderSize      = 22

	SendBufferSize   = 4 * 1024 * 1024
	RecvBufferSize   = 4 * 1024 * 1024
	MaxStreamsPerConn = 256
	StreamBufferSize  = 64 * 1024

	MaxPacketAge       = 5 * time.Second
	KeepAliveInterval  = 10 * time.Second
	ConnectionTimeout  = 30 * time.Second
	RetransmitTimeout  = 200 * time.Millisecond
	MaxRetransmits     = 5

	InitialWindow = 10
	MaxWindow     = 1000
	MinWindow     = 2
)

const (
	PacketTypeData uint8 = iota
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

type SpaceShuttleConn struct {
	conn       *net.UDPConn
	cipher     chacha20poly1305.AEAD
	remoteAddr *net.UDPAddr

	bytesSent   atomic.Uint64
	bytesRecv   atomic.Uint64
	packetsSent atomic.Uint64
	packetsRecv atomic.Uint64

	lastSendTime  atomic.Int64
	adaptiveDelay atomic.Int64
	closed        atomic.Bool

	mu sync.RWMutex
}

func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
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

func NewSpaceShuttleConn(localAddr string, remoteAddr string, key []byte) (*SpaceShuttleConn, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid local address: %w", err)
	}

	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid remote address: %w", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	if err := conn.SetReadBuffer(RecvBufferSize); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set read buffer: %w", err)
	}

	if err := conn.SetWriteBuffer(SendBufferSize); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set write buffer: %w", err)
	}

	sc := &SpaceShuttleConn{
		conn:       conn,
		cipher:     cipher,
		remoteAddr: raddr,
	}

	return sc, nil
}

func (sc *SpaceShuttleConn) SendPacket(header *PacketHeader, payload []byte, addr *net.UDPAddr) error {
	if sc.closed.Load() {
		return errors.New("connection closed")
	}

	if len(payload) > MaxPayloadSize {
		return errors.New("payload too large")
	}

	buf := getBuffer()
	defer putBuffer(buf)

	plaintext := (*buf)[:0]
	plaintext = append(plaintext, make([]byte, HeaderSize)...)
	header.Encode(plaintext[:HeaderSize])
	plaintext = append(plaintext, payload...)

	padding := sc.calculatePadding(len(payload))
	if padding > 0 {
		paddingBytes := make([]byte, padding)
		rand.Read(paddingBytes)
		plaintext = append(plaintext, paddingBytes...)
	}
	plaintext = append(plaintext, byte(padding))

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := sc.cipher.Seal(nil, nonce, plaintext, nil)

	packet := make([]byte, 0, NonceSize+len(ciphertext))
	packet = append(packet, nonce...)
	packet = append(packet, ciphertext...)

	if addr == nil {
		addr = sc.remoteAddr
	}

	n, err := sc.conn.WriteToUDP(packet, addr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	sc.packetsSent.Add(1)
	sc.bytesSent.Add(uint64(n))
	sc.lastSendTime.Store(time.Now().UnixNano())

	return nil
}

func (sc *SpaceShuttleConn) RecvPacket() (*PacketHeader, []byte, *net.UDPAddr, error) {
	if sc.closed.Load() {
		return nil, nil, nil, errors.New("connection closed")
	}

	buf := getBuffer()
	defer putBuffer(buf)

	n, addr, err := sc.conn.ReadFromUDP(*buf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to receive packet: %w", err)
	}

	if n < NonceSize+TagSize {
		return nil, nil, nil, errors.New("packet too small")
	}

	nonce := (*buf)[:NonceSize]
	ciphertext := (*buf)[NonceSize:n]

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

	now := time.Now().UnixNano()
	age := time.Duration(now - header.Timestamp)
	if age > MaxPacketAge || age < -MaxPacketAge {
		return nil, nil, nil, errors.New("packet timestamp out of range")
	}

	payload := make([]byte, payloadEnd-HeaderSize)
	copy(payload, plaintext[HeaderSize:payloadEnd])

	sc.packetsRecv.Add(1)
	sc.bytesRecv.Add(uint64(n))

	return header, payload, addr, nil
}

func (sc *SpaceShuttleConn) calculatePadding(payloadSize int) int {
	totalSize := HeaderSize + payloadSize
	if totalSize >= MaxPacketSize-MaxPaddingSize {
		return 0
	}

	maxPad := MaxPacketSize - totalSize - 1
	if maxPad > MaxPaddingSize {
		maxPad = MaxPaddingSize
	}
	if maxPad < MinPaddingSize {
		return 0
	}

	var randByte [1]byte
	rand.Read(randByte[:])
	padding := MinPaddingSize + int(randByte[0])%(maxPad-MinPaddingSize+1)

	return padding
}

func (sc *SpaceShuttleConn) SetAdaptiveDelay(delay time.Duration) {
	sc.adaptiveDelay.Store(int64(delay))
}

func (sc *SpaceShuttleConn) GetStats() (sent, recv uint64) {
	return sc.bytesSent.Load(), sc.bytesRecv.Load()
}

func (sc *SpaceShuttleConn) Close() error {
	if sc.closed.Swap(true) {
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
