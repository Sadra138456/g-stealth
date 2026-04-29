package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

const (
	SecretKey     = "kE?G-p_S9t!vA*z2B[vR4x7Z9m#qN@5u"
	SpaceMaxAge   = 5 * time.Minute
	SpaceMinPad   = 64
	SpaceMaxPad   = 256
	ServerPort    = ":443"
	MaxPacketSize = 1350 // MTU-safe
)

// SpaceConn - Encrypted UDP wrapper with timing obfuscation
type SpaceConn struct {
	net.PacketConn
	gcm cipher.AEAD
}

func NewSpaceConn(port string) (*SpaceConn, error) {
	conn, err := net.ListenPacket("udp", port)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	block, err := aes.NewCipher([]byte(SecretKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &SpaceConn{
		PacketConn: conn,
		gcm:        gcm,
	}, nil
}

func (sc *SpaceConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, 65535)
	n, addr, err = sc.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	nonceSize := sc.gcm.NonceSize()
	if n < nonceSize+8 {
		return 0, nil, fmt.Errorf("packet too short")
	}

	nonce := buf[:nonceSize]
	ciphertext := buf[nonceSize:n]

	plaintext, err := sc.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed")
	}

	if len(plaintext) < 8 {
		return 0, nil, fmt.Errorf("plaintext too short")
	}

	// Validate timestamp (anti-replay)
	timestamp := int64(binary.BigEndian.Uint64(plaintext[:8]))
	if time.Since(time.Unix(timestamp, 0)) > SpaceMaxAge {
		return 0, nil, fmt.Errorf("packet too old")
	}

	// Remove padding (last byte = padding length)
	if len(plaintext) < 9 {
		return 0, nil, fmt.Errorf("no padding info")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen > len(plaintext)-9 {
		return 0, nil, fmt.Errorf("invalid padding")
	}

	dataLen := len(plaintext) - 8 - padLen - 1
	copy(p, plaintext[8:8+dataLen])
	return dataLen, addr, nil
}

func (sc *SpaceConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Timing obfuscation
	jitter := time.Duration(randInt(0, 30)) * time.Millisecond
	time.Sleep(jitter)

	timestamp := time.Now().Unix()
	
	// Random padding (mimic HTTP/2 frame sizes)
	padLen := randInt(SpaceMinPad, SpaceMaxPad)
	padding := make([]byte, padLen)
	rand.Read(padding)

	// Build: [timestamp(8)][data][padding][padLen(1)]
	plaintext := make([]byte, 8+len(p)+padLen+1)
	binary.BigEndian.PutUint64(plaintext[:8], uint64(timestamp))
	copy(plaintext[8:], p)
	copy(plaintext[8+len(p):], padding)
	plaintext[len(plaintext)-1] = byte(padLen)

	// Encrypt with AES-GCM
	nonce := make([]byte, sc.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}
	ciphertext := sc.gcm.Seal(nonce, nonce, plaintext, nil)

	// Ensure packet size mimics normal traffic
	if len(ciphertext) > MaxPacketSize {
		ciphertext = ciphertext[:MaxPacketSize]
	}

	_, err = sc.PacketConn.WriteTo(ciphertext, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// SpaceShuttleCC - Custom congestion control (mimics BBR)
type SpaceShuttleCC struct{}

func (cc *SpaceShuttleCC) TimeUntilSend(bytesInFlight uint64) time.Time {
	return time.Time{} // Send immediately
}

func (cc *SpaceShuttleCC) OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64, isRetransmittable bool) {
}

func (cc *SpaceShuttleCC) CanSend(bytesInFlight uint64) bool {
	return true
}

func (cc *SpaceShuttleCC) MaybeExitSlowStart() {
}

func (cc *SpaceShuttleCC) OnPacketAcked(number uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time) {
}

func (cc *SpaceShuttleCC) OnPacketLost(number uint64, lostBytes uint64, priorInFlight uint64) {
}

func (cc *SpaceShuttleCC) OnRetransmissionTimeout(packetsRetransmitted bool) {
}

func (cc *SpaceShuttleCC) SetMaxDatagramSize(size uint64) {
}

func (cc *SpaceShuttleCC) InSlowStart() bool {
	return false
}

func (cc *SpaceShuttleCC) InRecovery() bool {
	return false
}

func (cc *SpaceShuttleCC) GetCongestionWindow() uint64 {
	return 1000000 // 1MB window
}

// Generate self-signed certificate (mimics Let's Encrypt)
func generateTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Cloudflare Inc"},
			CommonName:   "*.cloudflare.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"*.cloudflare.com", "cloudflare.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalECKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "h2", "http/1.1"}, // Mimic browser
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func mustMarshalECKey(key *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return b
}

// RunServer - Main server loop
func RunServer(port string) error {
	spaceConn, err := NewSpaceConn(port)
	if err != nil {
		return fmt.Errorf("failed to create SpaceConn: %w", err)
	}
	defer spaceConn.Close()

	tlsConf, err := generateTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to generate TLS config: %w", err)
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		EnableDatagrams:                true,
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          1000,
		DisablePathMTUDiscovery:        false,
		Allow0RTT:                      true,
		Tracer: func(ctx context.Context, p logging.Perspective, ci quic.ConnectionID) *logging.ConnectionTracer {
			return qlog.DefaultConnectionTracer(ctx, p, ci)
		},
	}

	listener, err := quic.Listen(spaceConn, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}
	defer listener.Close()

	log.Printf("🚀 SpaceShuttle server listening on %s (stealth mode)", port)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream quic.Stream) {
	defer stream.Close()

	// Read destination from client (SOCKS5-like protocol)
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil || n < 4 {
		log.Printf("failed to read destination: %v", err)
		stream.Write([]byte{0x01}) // error
		return
	}

	// Parse: [type(1)][len(1)][host][port(2)]
	addrType := buf[0]
	var target string

	switch addrType {
	case 0x01: // IPv4
		if n < 7 {
			stream.Write([]byte{0x01})
			return
		}
		ip := net.IP(buf[1:5])
		port := binary.BigEndian.Uint16(buf[5:7])
		target = fmt.Sprintf("%s:%d", ip.String(), port)

	case 0x03: // Domain
		hostLen := int(buf[1])
		if n < 2+hostLen+2 {
			stream.Write([]byte{0x01})
			return
		}
		host := string(buf[2 : 2+hostLen])
		port := binary.BigEndian.Uint16(buf[2+hostLen : 4+hostLen])
		target = fmt.Sprintf("%s:%d", host, port)

	case 0x04: // IPv6
		if n < 19 {
			stream.Write([]byte{0x01})
			return
		}
		ip := net.IP(buf[1:17])
		port := binary.BigEndian.Uint16(buf[17:19])
		target = fmt.Sprintf("[%s]:%d", ip.String(), port)

	default:
		stream.Write([]byte{0x01})
		return
	}

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("failed to connect to %s: %v", target, err)
		stream.Write([]byte{0x01})
		return
	}
	defer targetConn.Close()

	// Success
	stream.Write([]byte{0x00})

	// Bidirectional copy
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, stream)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(stream, targetConn)
		errCh <- err
	}()

	<-errCh
}

func randInt(min, max int) int {
	b := make([]byte, 1)
	rand.Read(b)
	return min + int(b[0])%(max-min+1)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := RunServer(ServerPort); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
