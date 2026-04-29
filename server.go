// server.go - SpaceShuttle server (no QUIC)
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

const (
	ServerPort = ":8443"
)

var SecretKey = []byte("your-32-byte-secret-key-here!!!!") // 32 bytes

type Server struct {
	transport *SpaceShuttleConn
	conns     map[string]*Connection
	connsMu   sync.RWMutex
}

func NewServer(port string, key []byte) (*Server, error) {
	transport, err := NewSpaceShuttleConn(port, "", key)
	if err != nil {
		return nil, fmt.Errorf("create transport: %w", err)
	}
	
	return &Server{
		transport: transport,
		conns:     make(map[string]*Connection),
	}, nil
}

func (s *Server) Run() error {
	log.Printf("SpaceShuttle server listening on %s", s.transport.LocalAddr())
	
	for {
		header, payload, addr, err := s.transport.RecvPacket()
		if err != nil {
			log.Printf("recv error: %v", err)
			continue
		}
		
		// Get or create connection for this client
		addrKey := addr.String()
		s.connsMu.RLock()
		conn, ok := s.conns[addrKey]
		s.connsMu.RUnlock()
		
		if !ok {
			// New client connection
			clientTransport, err := NewSpaceShuttleConn("", addr.String(), SecretKey)
			if err != nil {
				log.Printf("create client transport: %v", err)
				continue
			}
			
			conn = NewConnection(clientTransport)
			s.connsMu.Lock()
			s.conns[addrKey] = conn
			s.connsMu.Unlock()
			
			log.Printf("New client: %s", addr)
		}
		
		// Handle packet based on type
		switch header.Type {
		case PacketTypeStreamOpen:
			go s.handleNewStream(conn, header.StreamID)
		case PacketTypeStreamData:
			// Routed by connection's receiveLoop
		case PacketTypePing:
			s.handlePing(addr)
		}
	}
}

func (s *Server) handleNewStream(conn *Connection, streamID uint32) {
	// Create stream on server side
	stream := newStream(streamID, conn)
	
	conn.streamsMu.Lock()
	conn.streams[streamID] = stream
	conn.streamsMu.Unlock()
	
	// Handle stream (proxy to destination)
	go s.proxyStream(stream)
}

func (s *Server) proxyStream(stream *Stream) {
	defer stream.Close()
	
	// Read destination address from first packet
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("read dest addr: %v", err)
		return
	}
	
	destAddr := string(buf[:n])
	log.Printf("Stream %d -> %s", stream.id, destAddr)
	
	// Connect to destination
	dest, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("dial %s: %v", destAddr, err)
		return
	}
	defer dest.Close()
	
	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Client -> Destination
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}
			if _, err := dest.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	
	// Destination -> Client
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := dest.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	
	wg.Wait()
}

func (s *Server) handlePing(addr *net.UDPAddr) {
	header := &PacketHeader{
		Version: ProtocolVersion,
		Type:    PacketTypePong,
	}
	s.transport.SendPacket(header, nil, addr)
}

func RunServer(port string) error {
	server, err := NewServer(port, SecretKey)
	if err != nil {
		return err
	}
	return server.Run()
}

func main() {
	// Generate random key if needed
	if hex.EncodeToString(SecretKey) == hex.EncodeToString([]byte("your-32-byte-secret-key-here!!!!")) {
		log.Println("WARNING: Using default key. Generate a secure key:")
		key := make([]byte, 32)
		rand.Read(key)
		log.Printf("  SecretKey = []byte(\"%s\")", hex.EncodeToString(key))
	}
	
	log.Fatal(RunServer(ServerPort))
}
