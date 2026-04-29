package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// Config holds client configuration
type Config struct {
	ServerAddr string `json:"server_addr"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	LocalSOCKS string `json:"local_socks"`
	LocalHTTP  string `json:"local_http"`
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// ClientTransport wraps SpaceShuttle connection
type ClientTransport struct {
	spaceConn *SpaceShuttleConn
	conn      *Connection
	mu        sync.Mutex
}

// NewClientTransport creates a new client transport
func NewClientTransport(serverAddr string, serverPort int, password string) (*ClientTransport, error) {
	// Resolve server address
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverAddr, serverPort))
	if err != nil {
		return nil, fmt.Errorf("resolve server address: %w", err)
	}

	// Create UDP connection
	udpConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}

	// Create SpaceShuttle connection
	spaceConn, err := NewSpaceShuttleConn(udpConn, []byte(password), addr)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("create SpaceShuttle connection: %w", err)
	}

	// Create multiplexed connection
	conn := NewConnection(spaceConn, false)

	return &ClientTransport{
		spaceConn: spaceConn,
		conn:      conn,
	}, nil
}

// OpenStream opens a new stream
func (ct *ClientTransport) OpenStream(ctx context.Context) (*ClientStream, error) {
	stream, err := ct.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &ClientStream{stream: stream}, nil
}

// Close closes the transport
func (ct *ClientTransport) Close() error {
	ct.conn.Close()
	return ct.spaceConn.Close()
}

// ClientStream wraps a multiplexed stream
type ClientStream struct {
	stream *Stream
}

// Write writes data to stream
func (cs *ClientStream) Write(p []byte) (int, error) {
	return cs.stream.Write(p)
}

// Read reads data from stream
func (cs *ClientStream) Read(p []byte) (int, error) {
	return cs.stream.Read(p)
}

// Close closes the stream
func (cs *ClientStream) Close() error {
	return cs.stream.Close()
}

// ProxyServer handles SOCKS5 and HTTP proxy
type ProxyServer struct {
	transport *ClientTransport
	config    *Config
}

// NewProxyServer creates a new proxy server
func NewProxyServer(transport *ClientTransport, config *Config) *ProxyServer {
	return &ProxyServer{
		transport: transport,
		config:    config,
	}
}

// StartSOCKS5 starts SOCKS5 proxy server
func (s *ProxyServer) StartSOCKS5() error {
	listener, err := net.Listen("tcp", s.config.LocalSOCKS)
	if err != nil {
		return fmt.Errorf("listen SOCKS5: %w", err)
	}
	log.Printf("SOCKS5 proxy listening on %s", s.config.LocalSOCKS)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept SOCKS5 connection: %v", err)
				continue
			}
			go s.handleSOCKS5(conn)
		}
	}()

	return nil
}

// StartHTTP starts HTTP proxy server
func (s *ProxyServer) StartHTTP() error {
	listener, err := net.Listen("tcp", s.config.LocalHTTP)
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}
	log.Printf("HTTP proxy listening on %s", s.config.LocalHTTP)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept HTTP connection: %v", err)
				continue
			}
			go s.handleHTTP(conn)
		}
	}()

	return nil
}

// handleSOCKS5 handles a SOCKS5 connection
func (s *ProxyServer) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("SOCKS5 read handshake: %v", err)
		return
	}

	if n < 2 || buf[0] != 0x05 {
		log.Printf("Invalid SOCKS5 version")
		return
	}

	// No authentication
	conn.Write([]byte{0x05, 0x00})

	// Read request
	n, err = conn.Read(buf)
	if err != nil {
		log.Printf("SOCKS5 read request: %v", err)
		return
	}

	if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		log.Printf("Invalid SOCKS5 request")
		return
	}

	// Parse target address
	var target string
	addrType := buf[3]
	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			log.Printf("Invalid IPv4 address")
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			binary.BigEndian.Uint16(buf[8:10]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			log.Printf("Invalid domain address")
			return
		}
		target = fmt.Sprintf("%s:%d",
			string(buf[5:5+domainLen]),
			binary.BigEndian.Uint16(buf[5+domainLen:5+domainLen+2]))
	case 0x04: // IPv6
		if n < 22 {
			log.Printf("Invalid IPv6 address")
			return
		}
		target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			binary.BigEndian.Uint16(buf[4:6]),
			binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]),
			binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]),
			binary.BigEndian.Uint16(buf[14:16]),
			binary.BigEndian.Uint16(buf[16:18]),
			binary.BigEndian.Uint16(buf[18:20]),
			binary.BigEndian.Uint16(buf[20:22]))
	default:
		log.Printf("Unsupported address type: %d", addrType)
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Open stream to server
	stream, err := s.transport.OpenStream(context.Background())
	if err != nil {
		log.Printf("Open stream: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// Send target address to server
	targetBytes := []byte(target)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes)))
	if _, err := stream.Write(append(lenBuf, targetBytes...)); err != nil {
		log.Printf("Write target: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Relay data
	s.relay(conn, stream)
}

// handleHTTP handles an HTTP proxy connection
func (s *ProxyServer) handleHTTP(conn net.Conn) {
	defer conn.Close()

	// Read HTTP request
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("HTTP read request: %v", err)
		return
	}

	// Parse CONNECT method
	request := string(buf[:n])
	var target string
	if len(request) > 8 && request[:7] == "CONNECT" {
		// Extract target from CONNECT request
		lines := []byte(request)
		end := 0
		for i := 8; i < len(lines); i++ {
			if lines[i] == ' ' || lines[i] == '\r' || lines[i] == '\n' {
				end = i
				break
			}
		}
		if end > 8 {
			target = string(lines[8:end])
		}
	}

	if target == "" {
		log.Printf("Invalid HTTP CONNECT request")
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Open stream to server
	stream, err := s.transport.OpenStream(context.Background())
	if err != nil {
		log.Printf("Open stream: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer stream.Close()

	// Send target address to server
	targetBytes := []byte(target)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes)))
	if _, err := stream.Write(append(lenBuf, targetBytes...)); err != nil {
		log.Printf("Write target: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Send success response
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay data
	s.relay(conn, stream)
}

// relay relays data between local connection and stream
func (s *ProxyServer) relay(local net.Conn, stream *ClientStream) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Local -> Stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Local read: %v", err)
				}
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				log.Printf("Stream write: %v", err)
				return
			}
		}
	}()

	// Stream -> Local
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Stream read: %v", err)
				}
				return
			}
			if _, err := local.Write(buf[:n]); err != nil {
				log.Printf("Local write: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

func main() {
	// Load configuration
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Load config: %v", err)
	}

	// Create client transport
	transport, err := NewClientTransport(config.ServerAddr, config.ServerPort, config.Password)
	if err != nil {
		log.Fatalf("Create transport: %v", err)
	}
	defer transport.Close()

	log.Printf("Connected to server %s:%d", config.ServerAddr, config.ServerPort)

	// Create proxy server
	proxy := NewProxyServer(transport, config)

	// Start SOCKS5 proxy
	if config.LocalSOCKS != "" {
		if err := proxy.StartSOCKS5(); err != nil {
			log.Fatalf("Start SOCKS5: %v", err)
		}
	}

	// Start HTTP proxy
	if config.LocalHTTP != "" {
		if err := proxy.StartHTTP(); err != nil {
			log.Fatalf("Start HTTP: %v", err)
		}
	}

	log.Println("Client started successfully")

	// Keep running
	select {}
}
