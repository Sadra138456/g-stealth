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
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	AuthToken      = "ef92b778ba715867219a6"
	ProtocolALPN   = "h3"
	SNI            = "www.google.com"
	StreamPoolSize = 20
	MaxChunkSize   = 800
)

type Peer struct {
	remoteAddr string
	conn       quic.Connection
	streams    chan quic.Stream
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func main() {
	mode := flag.String("mode", "server", "server or client")
	remote := flag.String("remote", "127.0.0.1:4433", "QUIC server address")
	listen := flag.String("listen", "0.0.0.0:4433", "listen address")
	proxy := flag.String("proxy", "127.0.0.1:1080", "SOCKS5 proxy address")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	if *mode == "server" {
		runServer(ctx, *listen)
	} else {
		runClient(ctx, *remote, *proxy)
	}
}

func runServer(ctx context.Context, listenAddr string) {
	tlsConf := generateTLSConfig()
	quicConf := &quic.Config{
		MaxIdleTimeout:  time.Minute * 5,
		KeepAlivePeriod: time.Second * 30,
	}

	listener, err := quic.ListenAddr(listenAddr, tlsConf, quicConf)
	if err != nil {
		log.Fatalf("Server listen failed: %v", err)
	}
	defer listener.Close()

	log.Printf("Server listening on %s", listenAddr)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(ctx, conn)
	}
}

func handleConnection(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "done")
	log.Printf("New connection from %s", conn.RemoteAddr())

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Accept stream error: %v", err)
			return
		}

		go handleStream(stream)
	}
}

func handleStream(stream quic.Stream) {
	defer stream.Close()

	// Read auth token
	token := make([]byte, len(AuthToken))
	if _, err := io.ReadFull(stream, token); err != nil {
		log.Printf("Auth read failed: %v", err)
		return
	}
	if string(token) != AuthToken {
		log.Printf("Invalid auth token")
		return
	}

	// Read target address
	var addrLen uint16
	if err := binary.Read(stream, binary.BigEndian, &addrLen); err != nil {
		log.Printf("Address length read failed: %v", err)
		return
	}
	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBytes); err != nil {
		log.Printf("Address read failed: %v", err)
		return
	}
	targetAddr := string(addrBytes)

	// Connect to target
	tcpConn, err := net.DialTimeout("tcp", targetAddr, time.Second*10)
	if err != nil {
		log.Printf("Target dial failed %s: %v", targetAddr, err)
		return
	}
	defer tcpConn.Close()

	log.Printf("Proxying to %s", targetAddr)

	// Bidirectional relay
	done := make(chan struct{}, 2)
	go func() {
		shredderForward(tcpConn, stream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, tcpConn)
		done <- struct{}{}
	}()
	<-done
}

func runClient(ctx context.Context, remoteAddr, proxyAddr string) {
	peer := &Peer{
		remoteAddr: remoteAddr,
		streams:    make(chan quic.Stream, StreamPoolSize),
	}
	peer.ctx, peer.cancel = context.WithCancel(ctx)
	defer peer.cancel()

	// Maintain QUIC connection
	peer.wg.Add(1)
	go peer.maintainConnection()

	// Run SOCKS5 proxy
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("Proxy listen failed: %v", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on %s", proxyAddr)

	for {
		select {
		case <-peer.ctx.Done():
			peer.wg.Wait()
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if peer.ctx.Err() != nil {
				peer.wg.Wait()
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go peer.handleSOCKS5(conn)
	}
}

func (p *Peer) maintainConnection() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			if p.conn != nil {
				p.conn.CloseWithError(0, "shutdown")
			}
			return
		default:
		}

		if err := p.connect(); err != nil {
			log.Printf("Connection failed: %v, retrying...", err)
			time.Sleep(time.Second * 2)
			continue
		}

		// Connection established, maintain stream pool
		p.refillStreams()
	}
}

func (p *Peer) connect() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ProtocolALPN},
		ServerName:         SNI,
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:  time.Minute * 5,
		KeepAlivePeriod: time.Second * 30,
	}

	conn, err := quic.DialAddr(p.ctx, p.remoteAddr, tlsConf, quicConf)
	if err != nil {
		return err
	}

	p.conn = conn
	log.Printf("Connected to %s", p.remoteAddr)
	return nil
}

func (p *Peer) refillStreams() {
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		if len(p.streams) >= StreamPoolSize {
			time.Sleep(time.Millisecond * 100)
			continue
		}

		stream, err := p.conn.OpenStreamSync(p.ctx)
		if err != nil {
			log.Printf("Stream open failed: %v", err)
			if p.conn != nil {
				p.conn.CloseWithError(0, "error")
			}
			return
		}

		// Write auth token
		if _, err := stream.Write([]byte(AuthToken)); err != nil {
			stream.Close()
			continue
		}

		select {
		case p.streams <- stream:
		case <-p.ctx.Done():
			stream.Close()
			return
		}
	}
}

func (p *Peer) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 greeting
	buf := make([]byte, 257)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// No auth
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Read request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}

	var targetAddr string
	switch buf[3] {
	case 0x01: // IPv4
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			binary.BigEndian.Uint16(buf[8:10]))
	case 0x03: // Domain
		addrLen := int(buf[4])
		targetAddr = fmt.Sprintf("%s:%d",
			string(buf[5:5+addrLen]),
			binary.BigEndian.Uint16(buf[5+addrLen:7+addrLen]))
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Get stream from pool
	var stream quic.Stream
	select {
	case stream = <-p.streams:
	case <-time.After(time.Second * 5):
		log.Printf("Stream pool timeout")
		return
	case <-p.ctx.Done():
		return
	}
	defer stream.Close()

	// Send target address
	addrBytes := []byte(targetAddr)
	if err := binary.Write(stream, binary.BigEndian, uint16(len(addrBytes))); err != nil {
		return
	}
	if _, err := stream.Write(addrBytes); err != nil {
		return
	}

	// Bidirectional relay
	done := make(chan struct{}, 2)
	go func() {
		shredderForward(stream, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, stream)
		done <- struct{}{}
	}()
	<-done
}

func shredderForward(dst io.Writer, src io.Reader) {
	buf := make([]byte, MaxChunkSize)
	junk := make([]byte, 100)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Write header: payload size
			header := make([]byte, 2)
			binary.BigEndian.PutUint16(header, uint16(n))
			if _, err := dst.Write(header); err != nil {
				return
			}

			// Write payload
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}

			// Write junk
			junkSize := (n % 50) + 10
			rand.Read(junk[:junkSize])
			if _, err := dst.Write(junk[:junkSize]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{ProtocolALPN},
	}
}
