package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	MaxPacketSize = 1350
	SpaceMinPad   = 64
	SpaceMaxPad   = 256
)

// Config structure
type Config struct {
	ServerAddr string `json:"server_addr"` // مثال: "1.2.3.4:443"
	SecretKey  string `json:"secret_key"`  // کلید 32 بایتی
	LocalSOCKS string `json:"local_socks"` // مثال: "127.0.0.1:1080"
	LocalHTTP  string `json:"local_http"`  // مثال: "127.0.0.1:8080"
	EnableSub  bool   `json:"enable_sub"`  // فعال‌سازی سرور اشتراک
	SubPort    string `json:"sub_port"`    // پورت سرور اشتراک: "8090"
}

// SpaceConn - Client-side encrypted UDP
type SpaceConn struct {
	net.PacketConn
	gcm        cipher.AEAD
	serverAddr net.Addr
}

func NewSpaceConn(serverAddr string, secretKey string) (*SpaceConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &SpaceConn{
		PacketConn: conn,
		gcm:        gcm,
		serverAddr: udpAddr,
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

	if len(plaintext) < 9 {
		return 0, nil, fmt.Errorf("plaintext too short")
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
	jitter := time.Duration(randInt(0, 30)) * time.Millisecond
	time.Sleep(jitter)

	timestamp := time.Now().Unix()
	padLen := randInt(SpaceMinPad, SpaceMaxPad)
	padding := make([]byte, padLen)
	rand.Read(padding)

	plaintext := make([]byte, 8+len(p)+padLen+1)
	binary.BigEndian.PutUint64(plaintext[:8], uint64(timestamp))
	copy(plaintext[8:], p)
	copy(plaintext[8+len(p):], padding)
	plaintext[len(plaintext)-1] = byte(padLen)

	nonce := make([]byte, sc.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}
	ciphertext := sc.gcm.Seal(nonce, nonce, plaintext, nil)

	if len(ciphertext) > MaxPacketSize {
		ciphertext = ciphertext[:MaxPacketSize]
	}

	_, err = sc.PacketConn.WriteTo(ciphertext, sc.serverAddr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// SOCKS5 Server
type ProxyServer struct {
	quicConn quic.Connection
	config   *Config
}

func NewProxyServer(quicConn quic.Connection, config *Config) *ProxyServer {
	return &ProxyServer{
		quicConn: quicConn,
		config:   config,
	}
}

func (s *ProxyServer) RunSOCKS5() error {
	listener, err := net.Listen("tcp", s.config.LocalSOCKS)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("🔌 SOCKS5 proxy listening on %s", s.config.LocalSOCKS)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleSOCKS5(conn)
	}
}

func (s *ProxyServer) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	conn.Write([]byte{0x05, 0x00})

	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}

	var destBytes []byte
	switch buf[3] {
	case 0x01: // IPv4
		destBytes = make([]byte, 7)
		destBytes[0] = 0x01
		copy(destBytes[1:5], buf[4:8])
		copy(destBytes[5:7], buf[8:10])

	case 0x03: // Domain
		hostLen := int(buf[4])
		destBytes = make([]byte, 2+hostLen+2)
		destBytes[0] = 0x03
		destBytes[1] = byte(hostLen)
		copy(destBytes[2:2+hostLen], buf[5:5+hostLen])
		copy(destBytes[2+hostLen:], buf[5+hostLen:7+hostLen])

	case 0x04: // IPv6
		destBytes = make([]byte, 19)
		destBytes[0] = 0x04
		copy(destBytes[1:17], buf[4:20])
		copy(destBytes[17:19], buf[20:22])

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	stream, err := s.quicConn.OpenStreamSync(context.Background())
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	stream.Write(destBytes)

	resp := make([]byte, 1)
	if _, err := io.ReadFull(stream, resp); err != nil || resp[0] != 0x00 {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, stream)
		errCh <- err
	}()

	<-errCh
}

// HTTP Proxy Server
func (s *ProxyServer) RunHTTP() error {
	listener, err := net.Listen("tcp", s.config.LocalHTTP)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("🌐 HTTP proxy listening on %s", s.config.LocalHTTP)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleHTTP(conn)
	}
}

func (s *ProxyServer) handleHTTP(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Parse HTTP request
	request := string(buf[:n])
	lines := strings.Split(request, "\r\n")
	if len(lines) < 1 {
		return
	}

	parts := strings.Split(lines[0], " ")
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	target := parts[1]

	var host string
	var port uint16 = 80

	if method == "CONNECT" {
		// HTTPS
		hostPort := strings.Split(target, ":")
		host = hostPort[0]
		if len(hostPort) > 1 {
			fmt.Sscanf(hostPort[1], "%d", &port)
		} else {
			port = 443
		}
	} else {
		// HTTP
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				host = strings.TrimSpace(line[5:])
				break
			}
		}
		if host == "" {
			return
		}
	}

	// Build destination
	destBytes := make([]byte, 2+len(host)+2)
	destBytes[0] = 0x03 // Domain
	destBytes[1] = byte(len(host))
	copy(destBytes[2:], []byte(host))
	binary.BigEndian.PutUint16(destBytes[2+len(host):], port)

	stream, err := s.quicConn.OpenStreamSync(context.Background())
	if err != nil {
		return
	}
	defer stream.Close()

	stream.Write(destBytes)

	resp := make([]byte, 1)
	if _, err := io.ReadFull(stream, resp); err != nil || resp[0] != 0x00 {
		return
	}

	if method == "CONNECT" {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		stream.Write(buf[:n])
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, stream)
		errCh <- err
	}()

	<-errCh
}

// Subscription Server (برای کلاینت‌های موبایل)
func (s *ProxyServer) RunSubscription() error {
	if !s.config.EnableSub {
		return nil
	}

	http.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		// Generate subscription link
		link := fmt.Sprintf("socks5://%s@%s#SpaceShuttle",
			base64.StdEncoding.EncodeToString([]byte(s.config.SecretKey)),
			s.config.LocalSOCKS)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Subscription-Userinfo", "upload=0; download=0; total=10737418240; expire=0")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(link))))
	})

	http.HandleFunc("/clash", func(w http.ResponseWriter, r *http.Request) {
		clash := fmt.Sprintf(`proxies:
  - name: "SpaceShuttle"
    type: socks5
    server: %s
    port: %s
    skip-cert-verify: true
`, strings.Split(s.config.LocalSOCKS, ":")[0],
			strings.Split(s.config.LocalSOCKS, ":")[1])

		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Write([]byte(clash))
	})

	log.Printf("📡 Subscription server on http://127.0.0.1:%s/sub", s.config.SubPort)
	return http.ListenAndServe(":"+s.config.SubPort, nil)
}

func randInt(min, max int) int {
	b := make([]byte, 1)
	rand.Read(b)
	return min + int(b[0])%(max-min+1)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Validate
	if len(config.SecretKey) != 32 {
		return nil, fmt.Errorf("secret_key must be 32 bytes")
	}

	return &config, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Load config
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	log.Printf("📋 Config loaded: %s", configPath)

	// Create encrypted connection
	spaceConn, err := NewSpaceConn(config.ServerAddr, config.SecretKey)
	if err != nil {
		log.Fatalf("❌ Failed to create connection: %v", err)
	}
	defer spaceConn.Close()

	// QUIC config
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		EnableDatagrams: true,
	}

	// Connect
	quicConn, err := quic.Dial(context.Background(), spaceConn, spaceConn.serverAddr, tlsConf, quicConf)
	if err != nil {
		log.Fatalf("❌ Failed to connect: %v", err)
	}
	defer quicConn.CloseWithError(0, "")

	log.Printf("✅ Connected to %s", config.ServerAddr)

	// Start proxy servers
	proxy := NewProxyServer(quicConn, config)

	go func() {
		if err := proxy.RunSOCKS5(); err != nil {
			log.Fatalf("SOCKS5 error: %v", err)
		}
	}()

	go func() {
		if err := proxy.RunHTTP(); err != nil {
			log.Fatalf("HTTP error: %v", err)
		}
	}()

	// Subscription server
	if config.EnableSub {
		go func() {
			if err := proxy.RunSubscription(); err != nil {
				log.Printf("Subscription server error: %v", err)
			}
		}()
	}

	log.Println("🚀 SpaceShuttle client running...")
	select {}
}
