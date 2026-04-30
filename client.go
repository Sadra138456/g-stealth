package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Client struct {
	serverAddr string
	proxyAddr  string
	password   string
	conn       *Connection
	streams    map[uint32]*Stream
	streamsMu  sync.RWMutex
	nextID     uint32
	idMu       sync.Mutex
}

func NewClient(serverAddr, proxyAddr, password string) *Client {
	return &Client{
		serverAddr: serverAddr,
		proxyAddr:  proxyAddr,
		password:   password,
		streams:    make(map[uint32]*Stream),
		nextID:     1,
	}
}

func (c *Client) Start() error {
	// Decode password to key
	if len(c.password) != 64 {
		return fmt.Errorf("password must be 64 hex characters (32 bytes)")
	}
	
	key := make([]byte, 32)
	_, err := hex.Decode(key, []byte(c.password))
	if err != nil {
		return fmt.Errorf("invalid hex password: %w", err)
	}

	// Connect to server
	udpAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return fmt.Errorf("resolve server address: %w", err)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}

	// Create encrypted connection
	transport, err := NewSpaceShuttleConn(udpConn, key)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("create transport: %w", err)
	}

	c.conn = NewConnection(transport, false)

	// Start SOCKS5 proxy
	go c.runProxy()

	log.Printf("Client started, connecting to %s, SOCKS5 proxy on %s", c.serverAddr, c.proxyAddr)
	return nil
}

func (c *Client) runProxy() {
	listener, err := net.Listen("tcp", c.proxyAddr)
	if err != nil {
		log.Fatalf("Failed to start SOCKS5 proxy: %v", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on %s", c.proxyAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go c.handleSOCKS5(conn)
	}
}

func (c *Client) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("SOCKS5 handshake read error: %v", err)
		return
	}

	if n < 2 || buf[0] != 5 {
		log.Printf("Invalid SOCKS5 version")
		return
	}

	// No authentication
	_, err = conn.Write([]byte{5, 0})
	if err != nil {
		log.Printf("SOCKS5 handshake write error: %v", err)
		return
	}

	// Read request
	n, err = conn.Read(buf)
	if err != nil {
		log.Printf("SOCKS5 request read error: %v", err)
		return
	}

	if n < 7 || buf[0] != 5 || buf[1] != 1 {
		log.Printf("Invalid SOCKS5 request")
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse target address
	var targetAddr string
	switch buf[3] {
	case 1: // IPv4
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			binary.BigEndian.Uint16(buf[8:10]))

	case 3: // Domain name
		domainLen := int(buf[4])
		targetAddr = fmt.Sprintf("%s:%d",
			string(buf[5:5+domainLen]),
			binary.BigEndian.Uint16(buf[5+domainLen:7+domainLen]))

	case 4: // IPv6
		targetAddr = fmt.Sprintf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%d",
			buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
			buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
			binary.BigEndian.Uint16(buf[20:22]))

	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	log.Printf("SOCKS5 request to %s", targetAddr)

	// Create stream through tunnel
	stream, err := c.createStream()
	if err != nil {
		log.Printf("Failed to create stream: %v", err)
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer c.closeStream(stream.id)

	// Send target address through stream
	_, err = stream.Write([]byte(targetAddr))
	if err != nil {
		log.Printf("Failed to send target address: %v", err)
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send success response
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Printf("SOCKS5 response write error: %v", err)
		return
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Client read error: %v", err)
				}
				return
			}
			_, err = stream.Write(buf[:n])
			if err != nil {
				log.Printf("Stream write error: %v", err)
				return
			}
		}
	}()

	// Stream -> Client
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Stream read error: %v", err)
				}
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				log.Printf("Client write error: %v", err)
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Connection to %s closed", targetAddr)
}

func (c *Client) createStream() (*Stream, error) {
	c.idMu.Lock()
	streamID := c.nextID
	c.nextID += 2 // Client uses odd IDs
	c.idMu.Unlock()

	stream := &Stream{
		id:              streamID,
		conn:            c.conn,
		sendSeq:         0,
		recvSeq:         0,
		sendWindow:      InitialWindow,
		recvWindow:      InitialWindow,
		recvBuf:         make(chan []byte, 256),
		pendingData:     make(map[uint32][]byte),
		unackedPackets:  make(map[uint32]*unackedPacket),
		lastActivity:    time.Now(),
		retransmitTimer: time.NewTimer(RetransmitTimeout),
	}

	c.streamsMu.Lock()
	c.streams[streamID] = stream
	c.streamsMu.Unlock()

	// Send SYN
	header := &PacketHeader{
		Version:    ProtocolVersion,
		Type:       PacketTypeStreamOpen,
		StreamID:   streamID,
		Sequence:   0,
		Timestamp:  uint32(time.Now().Unix()),
		WindowSize: InitialWindow,
		Flags:      0,
	}

	err := c.conn.sendPacket(header, nil)
	if err != nil {
		c.closeStream(streamID)
		return nil, fmt.Errorf("send SYN: %w", err)
	}

	// Start retransmit loop
	go stream.retransmitLoop()

	return stream, nil
}

func (c *Client) closeStream(streamID uint32) {
	c.streamsMu.Lock()
	stream, exists := c.streams[streamID]
	if exists {
		delete(c.streams, streamID)
	}
	c.streamsMu.Unlock()

	if exists {
		stream.Close()
	}
}

func (c *Client) Close() error {
	c.streamsMu.Lock()
	streams := make([]*Stream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	c.streams = make(map[uint32]*Stream)
	c.streamsMu.Unlock()

	for _, s := range streams {
		s.Close()
	}

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
