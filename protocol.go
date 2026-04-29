// protocol.go - SpaceShuttle Core Protocol
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Protocol constants
	ProtocolVersion    = 1
	MaxPacketSize      = 1350
	MaxPayloadSize     = 1200
	MinPaddingSize     = 16
	MaxPaddingSize     = 128
	NonceSize          = 12
	TagSize            = 16
	HeaderSize         = 32
	
	// Performance tuning
	SendBufferSize     = 4 * 1024 * 1024  // 4MB
	RecvBufferSize     = 4 * 1024 * 1024  // 4MB
	MaxStreamsPerConn  = 256
	StreamBufferSize   = 64 * 1024        // 64KB per stream
	
	// Timing
	MaxPacketAge       = 5 * time.Second
	KeepAliveInterval  = 10 * time.Second
	ConnectionTimeout  = 30 * time.Second
	RetransmitTimeout  = 200 * time.Millisecond
	MaxRetransmits     = 5
	
	// Congestion control
	InitialWindow      = 10
	MaxWindow          = 1000
	MinWindow          = 2
)

// Packet types
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

// Buffer pool for zero-copy
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, MaxPacketSize)
		return &buf
	},
}

func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

// Packet header structure (encrypted)
type PacketHeader struct {
	Version    uint8
	Type       uint8
	StreamID   uint32
	Sequence   uint32
	Timestamp  int64
	WindowSize uint16
	Flags      uint16
}

// Encode header to bytes
func (h *PacketHeader) Encode(buf []byte) {
	buf[0] = h.Version
	buf[1] = h.Type
	binary.BigEndian.PutUint32(buf[2:6], h.StreamID)
	binary.BigEndian.PutUint32(buf[6:10], h.Sequence)
	binary.BigEndian.PutUint64(buf[10:18], uint64(h.Timestamp))
	binary.BigEndian.PutUint16(buf[18:20], h.WindowSize)
	binary.BigEndian.PutUint16(buf[20:22], h.Flags)
}

// Decode header from bytes
func (h *PacketHeader) Decode(buf []byte) error {
	if len(buf) < 22 {
		return errors.New("header too short")
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

// SpaceShuttleConn - encrypted UDP transport with obfuscation
type SpaceShuttleConn struct {
	conn       *net.UDPConn
	cipher     *chacha20poly1305.XChaCha20Poly1305
	remoteAddr *net.UDPAddr
	
	// Statistics for adaptive obfuscation
	bytesSent     atomic.Uint64
	bytesRecv     atomic.Uint64
	packetsSent   atomic.Uint64
	packetsRecv   atomic.Uint64
	
	// Timing jitter control
	lastSendTime  atomic.Int64
	adaptiveDelay atomic.Int64  // nanoseconds
	
	closed atomic.Bool
	mu     sync.RWMutex
}

// NewSpaceShuttleConn creates encrypted UDP connection
func NewSpaceShuttleConn(localAddr string, remoteAddr string, key []byte) (*SpaceShuttleConn, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	
	// Create XChaCha20-Poly1305 cipher (better than ChaCha20-Poly1305)
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("cipher init failed: %w", err)
	}
	
	// Resolve addresses
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve local addr: %w", err)
	}
	
	var raddr *net.UDPAddr
	if remoteAddr != "" {
		raddr, err = net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve remote addr: %w", err)
		}
	}
	
	// Create UDP socket
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	
	// Set socket buffers for high throughput
	if err := conn.SetReadBuffer(RecvBufferSize); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set read buffer: %w", err)
	}
	if err := conn.SetWriteBuffer(SendBufferSize); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set write buffer: %w", err)
	}
	
	sc := &SpaceShuttleConn{
		conn:       conn,
		cipher:     cipher,
		remoteAddr: raddr,
	}
	
	sc.adaptiveDelay.Store(int64(5 * time.Millisecond))
	
	return sc, nil
}

// SendPacket encrypts and sends a packet with obfuscation
func (sc *SpaceShuttleConn) SendPacket(header *PacketHeader, payload []byte, addr *net.UDPAddr) error {
	if sc.closed.Load() {
		return errors.New("connection closed")
	}
	
	// Use remote addr if not specified
	if addr == nil {
		addr = sc.remoteAddr
	}
	if addr == nil {
		return errors.New("no remote address")
	}
	
	// Adaptive timing jitter (only if needed)
	delay := time.Duration(sc.adaptiveDelay.Load())
	if delay > 0 {
		lastSend := time.Unix(0, sc.lastSendTime.Load())
		elapsed := time.Since(lastSend)
		if elapsed < delay {
			time.Sleep(delay - elapsed)
		}
	}
	sc.lastSendTime.Store(time.Now().UnixNano())
	
	// Get buffer from pool
	buf := getBuffer()
	defer putBuffer(buf)
	
	// Build plaintext: [header][payload][padding][padLen]
	header.Timestamp = time.Now().Unix()
	
	// Adaptive padding based on traffic pattern
	padLen := sc.calculatePadding(len(payload))
	
	plaintext := (*buf)[:22+len(payload)+padLen+1]
	header.Encode(plaintext[:22])
	copy(plaintext[22:], payload)
	
	// Random padding
	if padLen > 0 {
		rand.Read(plaintext[22+len(payload) : 22+len(payload)+padLen])
	}
	plaintext[len(plaintext)-1] = byte(padLen)
	
	// Generate nonce (24 bytes for XChaCha20)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation: %w", err)
	}
	
	// Encrypt: [nonce][ciphertext+tag]
	ciphertext := sc.cipher.Seal(nonce, nonce, plaintext, nil)
	
	// Send
	n, err := sc.conn.WriteToUDP(ciphertext, addr)
	if err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	
	// Update stats
	sc.packetsSent.Add(1)
	sc.bytesSent.Add(uint64(n))
	
	return nil
}

// RecvPacket receives and decrypts a packet
func (sc *SpaceShuttleConn) RecvPacket() (*PacketHeader, []byte, *net.UDPAddr, error) {
	if sc.closed.Load() {
		return nil, nil, nil, errors.New("connection closed")
	}
	
	buf := getBuffer()
	
	// Read from UDP
	n, addr, err := sc.conn.ReadFromUDP(*buf)
	if err != nil {
		putBuffer(buf)
		return nil, nil, nil, err
	}
	
	// Update stats
	sc.packetsRecv.Add(1)
	sc.bytesRecv.Add(uint64(n))
	
	data := (*buf)[:n]
	
	// Minimum size check
	if len(data) < chacha20poly1305.NonceSizeX+TagSize+22 {
		putBuffer(buf)
		return nil, nil, nil, errors.New("packet too short")
	}
	
	// Split nonce and ciphertext
	nonce := data[:chacha20poly1305.NonceSizeX]
	ciphertext := data[chacha20poly1305.NonceSizeX:]
	
	// Decrypt
	plaintext, err := sc.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		putBuffer(buf)
		return nil, nil, nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	// Parse header
	if len(plaintext) < 23 {
		putBuffer(buf)
		return nil, nil, nil, errors.New("plaintext too short")
	}
	
	header := &PacketHeader{}
	if err := header.Decode(plaintext[:22]); err != nil {
		putBuffer(buf)
		return nil, nil, nil, err
	}
	
	// Check timestamp (anti-replay)
	age := time.Since(time.Unix(header.Timestamp, 0))
	if age > MaxPacketAge || age < -MaxPacketAge {
		putBuffer(buf)
		return nil, nil, nil, errors.New("packet too old or future")
	}
	
	// Extract padding
	padLen := int(plaintext[len(plaintext)-1])
	if padLen > len(plaintext)-23 {
		putBuffer(buf)
		return nil, nil, nil, errors.New("invalid padding")
	}
	
	payloadLen := len(plaintext) - 22 - padLen - 1
	payload := make([]byte, payloadLen)
	copy(payload, plaintext[22:22+payloadLen])
	
	putBuffer(buf)
	
	return header, payload, addr, nil
}

// calculatePadding returns adaptive padding size
func (sc *SpaceShuttleConn) calculatePadding(payloadSize int) int {
	// Smart padding: less padding for large payloads
	if payloadSize > 800 {
		return MinPaddingSize + (int(sc.packetsSent.Load()) % 16)
	}
	if payloadSize > 400 {
		return MinPaddingSize + (int(sc.packetsSent.Load()) % 32)
	}
	// Small payloads get more padding for obfuscation
	return MinPaddingSize + (int(sc.packetsSent.Load()) % (MaxPaddingSize - MinPaddingSize))
}

// SetAdaptiveDelay adjusts timing jitter
func (sc *SpaceShuttleConn) SetAdaptiveDelay(delay time.Duration) {
	sc.adaptiveDelay.Store(int64(delay))
}

// GetStats returns connection statistics
func (sc *SpaceShuttleConn) GetStats() (sent, recv uint64) {
	return sc.bytesSent.Load(), sc.bytesRecv.Load()
}

// Close closes the connection
func (sc *SpaceShuttleConn) Close() error {
	if sc.closed.Swap(true) {
		return nil
	}
	return sc.conn.Close()
}

// LocalAddr returns local address
func (sc *SpaceShuttleConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (sc *SpaceShuttleConn) RemoteAddr() net.Addr {
	return sc.remoteAddr
}
