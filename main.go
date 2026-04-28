package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	StreamPoolSize = 10
	BufferSize     = 32 * 1024
)

type Peer struct {
	mode        string
	listenAddr  string
	remoteAddr  string
	targetAddr  string
	quicConn    quic.Connection
	streamPool  chan quic.Stream
	mu          sync.Mutex
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./stealth <server|client> <listen_addr> [remote_addr]")
		return
	}

	p := &Peer{
		mode:       os.Args[1],
		listenAddr: os.Args[2],
	}

	if p.mode == "client" {
		if len(os.Args) < 4 {
			log.Fatal("Client needs remote_addr")
		}
		p.remoteAddr = os.Args[3]
		p.streamPool = make(chan quic.Stream, StreamPoolSize)
		p.runClient()
	} else {
		p.runServer()
	}
}

func (p *Peer) runServer() {
	listener, err := quic.ListenAddr(p.listenAddr, generateTLSConfig(), &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Server listening on %s", p.listenAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept connection error: %v", err)
			continue
		}
		go func() {
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go handleStealthStream(stream)
			}
		}()
	}
}

func handleStealthStream(stream quic.Stream) {
	defer stream.Close()

	// Read target address length and port
	header := make([]byte, 4)
	if _, err := io.ReadFull(stream, header); err != nil {
		return
	}

	addrLen := binary.BigEndian.Uint16(header[:2])
	port := binary.BigEndian.Uint16(header[2:])

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		return
	}

	target := fmt.Sprintf("%s:%d", string(addrBuf), port)
	log.Printf("Forwarding to: %s", target)

	remoteConn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Printf("Dial target error: %v", err)
		return
	}
	defer remoteConn.Close()

	go shredderForward(remoteConn, stream)
	shredderForward(stream, remoteConn)
}

func shredderForward(dst io.Writer, src io.Reader) {
	buf := make([]byte, BufferSize)
	io.CopyBuffer(dst, src, buf)
}

func (p *Peer) runClient() {
	go p.maintainConnection()

	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 proxy listening on %s", p.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go p.handleSOCKS5(conn)
	}
}

func (p *Peer) maintainConnection() {
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"stealth-v1"}}
	for {
		conn, err := quic.DialAddr(context.Background(), p.remoteAddr, tlsConf, &quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
		})
		if err != nil {
			log.Printf("Dial server error: %v, retrying...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		p.quicConn = conn

		// Pre-fill stream pool
		for i := 0; i < StreamPoolSize; i++ {
			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				break
			}
			p.streamPool <- stream
		}

		<-conn.Context().Done()
		log.Println("Connection lost, reconnecting...")
	}
}

func (p *Peer) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()

	// Minimal SOCKS5 Handshake
	buf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, buf); err != nil || buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	io.ReadFull(clientConn, methods)
	clientConn.Write([]byte{0x05, 0x00}) // No auth

	// Request
	header := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, header); err != nil || header[1] != 0x01 {
		return
	}

	var targetAddr string
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		io.ReadFull(clientConn, addr)
		targetAddr = net.IP(addr).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		io.ReadFull(clientConn, lenBuf)
		addr := make([]byte, int(lenBuf[0]))
		io.ReadFull(clientConn, addr)
		targetAddr = string(addr)
	default:
		return
	}

	portBuf := make([]byte, 2)
	io.ReadFull(clientConn, portBuf)
	port := binary.BigEndian.Uint16(portBuf)

	// Get stream from pool or open new
	var stream quic.Stream
	select {
	case stream = <-p.streamPool:
		// Replenish pool in background
		go func() {
			if p.quicConn != nil {
				s, err := p.quicConn.OpenStreamSync(context.Background())
				if err == nil {
					p.streamPool <- s
				}
			}
		}()
	default:
		if p.quicConn == nil {
			return
		}
		var err error
		stream, err = p.quicConn.OpenStreamSync(context.Background())
		if err != nil {
			return
		}
	}
	defer stream.Close()

	// Send target info to server
	addrBytes := []byte(targetAddr)
	h := make([]byte, 4)
	binary.BigEndian.PutUint16(h[:2], uint16(len(addrBytes)))
	binary.BigEndian.PutUint16(h[2:], port)
	stream.Write(h)
	stream.Write(addrBytes)

	// Success response to SOCKS5 client
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go shredderForward(clientConn, stream)
	shredderForward(stream, clientConn)
}

func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"stealth-v1"},
	}
}
