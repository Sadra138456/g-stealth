package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
)

const (
	ServerPort = ":8443"
	SecretKey  = "CHANGE_THIS_TO_A_RANDOM_32_BYTE_KEY!"
)

type Server struct {
	conn    *SpaceShuttleConn
	clients map[string]*Connection
	mu      sync.RWMutex
}

func main() {
	key := []byte(SecretKey)

	if SecretKey == "CHANGE_THIS_TO_A_RANDOM_32_BYTE_KEY!" {
		log.Println("⚠️  WARNING: Using default secret key!")
		log.Println("Generating a random key for this session...")

		newKey := make([]byte, 32)
		if _, err := rand.Read(newKey); err != nil {
			log.Fatal("Failed to generate random key:", err)
		}
		key = newKey
		log.Printf("Generated key (save this): %s\n", hex.EncodeToString(key))
	}

	log.Fatal(RunServer(ServerPort, key))
}

func NewServer(conn *SpaceShuttleConn) *Server {
	return &Server{
		conn:    conn,
		clients: make(map[string]*Connection),
	}
}

func (s *Server) Run() error {
	log.Printf("Server listening on %s\n", s.conn.LocalAddr())

	for {
		header, payload, addr, err := s.conn.RecvPacket()
		if err != nil {
			log.Printf("Error receiving packet: %v\n", err)
			continue
		}

		clientKey := addr.String()

		s.mu.RLock()
		client, exists := s.clients[clientKey]
		s.mu.RUnlock()

		if !exists {
			log.Printf("New client connection from %s\n", addr)

			clientConn := &SpaceShuttleConn{
				conn:       s.conn.conn,
				cipher:     s.conn.cipher,
				remoteAddr: addr,
			}

			client = NewConnection(clientConn)

			s.mu.Lock()
			s.clients[clientKey] = client
			s.mu.Unlock()

			go s.handleClient(client)
		}

		if header.Type == PacketTypePing {
			s.handlePing(header, addr)
		}
	}
}

func (s *Server) handleClient(client *Connection) {
	for {
		stream, err := client.AcceptStream()
		if err != nil {
			log.Printf("Error accepting stream: %v\n", err)
			return
		}

		go s.handleNewStream(stream)
	}
}

func (s *Server) handleNewStream(stream *Stream) {
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("Error reading from stream: %v\n", err)
		return
	}

	log.Printf("Received %d bytes on stream %d\n", n, stream.id)

	targetAddr := string(buf[:n])
	log.Printf("Proxying to %s\n", targetAddr)

	s.proxyStream(stream, targetAddr)
}

func (s *Server) proxyStream(stream *Stream, targetAddr string) {
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v\n", targetAddr, err)
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := target.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}
			if _, err := target.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func (s *Server) handlePing(header *PacketHeader, addr *net.UDPAddr) {
	pong := &PacketHeader{
		Version:   ProtocolVersion,
		Type:      PacketTypePong,
		Timestamp: header.Timestamp,
	}

	if err := s.conn.SendPacket(pong, nil, addr); err != nil {
		log.Printf("Failed to send pong: %v\n", err)
	}
}

func RunServer(port string, key []byte) error {
	conn, err := NewSpaceShuttleConn(port, "", key)
	if err != nil {
		return fmt.Errorf("failed to create server connection: %w", err)
	}

	server := NewServer(conn)
	return server.Run()
}
