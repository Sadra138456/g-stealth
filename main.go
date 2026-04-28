package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
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
	mode       string
	listenAddr string
	serverAddr string
	conn       quic.EarlyConnection
	streams    chan quic.Stream
	mu         sync.Mutex
}

func main() {
	mode := flag.String("mode", "server", "Mode: server or client")
	listenAddr := flag.String("listen", ":4433", "Listen address (server mode or SOCKS5)")
	serverAddr := flag.String("server", "", "Server address (client mode)")
	flag.Parse()

	peer := &Peer{
		mode:       *mode,
		listenAddr: *listenAddr,
		serverAddr: *serverAddr,
	}

	if peer.mode == "server" {
		peer.runServer()
	} else {
		peer.runClient()
	}
}

func (p *Peer) runServer() {
	tlsConfig := generateTLSConfig()
	listener, err := quic.ListenAddr(p.listenAddr, tlsConfig, &quic.Config{
		MaxIdleTimeout:  time.Minute * 5,
		KeepAlivePeriod: time.Second * 30,
	})
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("Server listening on %s", p.listenAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		log.Printf("New connection from %s", conn.RemoteAddr())

		go func(conn quic.EarlyConnection) {
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					log.Printf("Failed to accept stream: %v", err)
					return
				}
				go handleStealthStream(stream)
			}
		}(conn)
	}
}

func handleStealthStream(stream quic.Stream) {
	defer stream.Close()

	var header [4]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		log.Printf("Failed to read header: %v", err)
		return
	}

	addrLen := binary.BigEndian.Uint16(header[0:2])
	portNum := binary.BigEndian.Uint16(header[2:4])

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		log.Printf("Failed to read address: %v", err)
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", string(addrBuf), portNum)
	log.Printf("Connecting to %s", targetAddr)

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		shredderForward(targetConn, stream)
	}()

	go func() {
		defer wg.Done()
		shredderForward(stream, targetConn)
	}()

	wg.Wait()
}

func shredderForward(dst io.Writer, src io.Reader) {
	buf := make([]byte, BufferSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *Peer) runClient() {
	p.streams = make(chan quic.Stream, StreamPoolSize)

	go p.maintainConnection()

	socksListener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		log.Fatalf("Failed to start SOCKS5 listener: %v", err)
	}
	defer socksListener.Close()

	log.Printf("SOCKS5 proxy listening on %s", p.listenAddr)

	for {
		conn, err := socksListener.Accept()
		if err != nil {
			log.Printf("Failed to accept SOCKS5 connection: %v", err)
			continue
		}
		go p.handleSOCKS5(conn)
	}
}

func (p *Peer) maintainConnection() {
	for {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"stealth-quic"},
		}

		conn, err := quic.DialAddr(context.Background(), p.serverAddr, tlsConfig, &quic.Config{
			MaxIdleTimeout:  time.Minute * 5,
			KeepAlivePeriod: time.Second * 30,
		})
		if err != nil {
			log.Printf("Failed to connect to server: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("Connected to server %s", p.serverAddr)

		p.mu.Lock()
		p.conn = conn
		p.mu.Unlock()

		for i := 0; i < StreamPoolSize; i++ {
			stream, err := conn.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream: %v", err)
				break
			}
			p.streams <- stream
		}

		<-conn.Context().Done()
		log.Printf("Connection closed, reconnecting...")
		time.Sleep(2 * time.Second)
	}
}

func (p *Peer) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()

	buf := make([]byte, 256)

	n, err := clientConn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	clientConn.Write([]byte{0x05, 0x00})

	n, err = clientConn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	if buf[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetAddr string
	var targetPort uint16

	switch buf[3] {
	case 0x01:
		targetAddr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03:
		addrLen := int(buf[4])
		targetAddr = string(buf[5 : 5+addrLen])
		targetPort = binary.BigEndian.Uint16(buf[5+addrLen : 7+addrLen])
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	stream := <-p.streams

	defer func() {
		stream.Close()
		newStream, err := p.conn.OpenStream()
		if err == nil {
			p.streams <- newStream
		}
	}()

	addrBytes := []byte(targetAddr)
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(addrBytes)))
	binary.BigEndian.PutUint16(header[2:4], targetPort)

	if _, err := stream.Write(header); err != nil {
		return
	}
	if _, err := stream.Write(addrBytes); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		shredderForward(stream, clientConn)
	}()

	go func() {
		defer wg.Done()
		shredderForward(clientConn, stream)
	}()

	wg.Wait()
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"stealth-quic"},
	}
}
