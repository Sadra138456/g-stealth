package main

import (
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

type Config struct {
	ServerAddr  string `json:"server_addr"`
	ServerPort  int    `json:"server_port"`
	Password    string `json:"password"`
	LocalSOCKS  string `json:"local_socks,omitempty"`
	LocalHTTP   string `json:"local_http,omitempty"`
}

type ClientTransport struct {
	conn *Connection
	mu   sync.Mutex
}

type ClientStream struct {
	stream *Stream
}

type ProxyServer struct {
	transport *ClientTransport
}

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

func NewClientTransport(serverAddr string, serverPort int, password string) (*ClientTransport, error) {
	if len(password) != 64 {
		return nil, fmt.Errorf("password must be 64 hex characters (32 bytes)")
	}

	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		fmt.Sscanf(password[i*2:i*2+2], "%02x", &key[i])
	}

	remoteAddr := fmt.Sprintf("%s:%d", serverAddr, serverPort)

	spaceConn, err := NewSpaceShuttleConn(":0", remoteAddr, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create space shuttle connection: %w", err)
	}

	conn := NewConnection(spaceConn)

	return &ClientTransport{
		conn: conn,
	}, nil
}

func (ct *ClientTransport) OpenStream() (*ClientStream, error) {
	stream, err := ct.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	return &ClientStream{stream: stream}, nil
}

func (ct *ClientTransport) Close() error {
	return ct.conn.Close()
}

func (cs *ClientStream) Write(p []byte) (int, error) {
	return cs.stream.Write(p)
}

func (cs *ClientStream) Read(p []byte) (int, error) {
	return cs.stream.Read(p)
}

func (cs *ClientStream) Close() error {
	return cs.stream.Close()
}

func NewProxyServer(transport *ClientTransport) *ProxyServer {
	return &ProxyServer{
		transport: transport,
	}
}

func (s *ProxyServer) StartSOCKS5(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("SOCKS5 proxy listening on %s\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v\n", err)
			continue
		}

		go s.handleSOCKS5(conn)
	}
}

func (s *ProxyServer) StartHTTP(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("HTTP proxy listening on %s\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v\n", err)
			continue
		}

		go s.handleHTTP(conn)
	}
}

func (s *ProxyServer) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 256)

	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	if buf[0] != 5 {
		return
	}

	conn.Write([]byte{5, 0})

	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	if buf[1] != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetAddr string
	switch buf[3] {
	case 1:
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			binary.BigEndian.Uint16(buf[8:10]))
	
	domainLen]))
	case 4:
		targetAddr = fmt.Sprintf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%d",
			buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
			buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
			binary.BigEndian.Uint16(buf[20:22]))
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	stream, err := s.transport.OpenStream()
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	if _, err := stream.Write([]byte(targetAddr)); err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	s.relay(conn, stream)
}

func (s *ProxyServer) handleHTTP(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])
	var targetAddr string

	if len(request) > 8 && request[:7] == "CONNECT" {
		lines := splitLines(request)
		if len(lines) > 0 {
			parts := splitSpaces(lines[0])
			if len(parts) >= 2 {
				targetAddr = parts[1]
			}
		}

		stream, err := s.transport.OpenStream()
		if err != nil {
			conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer stream.Close()

		if _, err := stream.Write([]byte(targetAddr)); err != nil {
			conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}

		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		s.relay(conn, stream)
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *ProxyServer) relay(local net.Conn, remote *ClientStream) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				return
			}
			if _, err := remote.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			if _, err := local.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			end := i
			if end > 0 && s[end-1] == '\r' {
				end--
			}
			lines = append(lines, s[start:end])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitSpaces(s string) []string {
	var parts []string
	start := 0
	inWord := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if inWord {
				parts = append(parts, s[start:i])
				inWord = false
			}
		} else {
			if !inWord {
				start = i
				inWord = true
			}
		}
	}
	if inWord {
		parts = append(parts, s[start:])
	}
	return parts
}

func RunClient(configPath string) error {
	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	transport, err := NewClientTransport(config.ServerAddr, config.ServerPort, config.Password)
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}
	defer transport.Close()

	log.Printf("Connected to server %s:%d\n", config.ServerAddr, config.ServerPort)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			stream, err := transport.OpenStream()
			if err != nil {
				log.Printf("Keepalive failed: %v\n", err)
				continue
			}
			stream.Close()
		}
	}()

	proxy := NewProxyServer(transport)

	var wg sync.WaitGroup

	if config.LocalSOCKS != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.StartSOCKS5(config.LocalSOCKS); err != nil {
				log.Printf("SOCKS5 server error: %v\n", err)
			}
		}()
	}

	if config.LocalHTTP != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.StartHTTP(config.LocalHTTP); err != nil {
				log.Printf("HTTP server error: %v\n", err)
			}
		}()
	}

	wg.Wait()
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: client <config.json>")
		os.Exit(1)
	}

	if err := RunClient(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}
