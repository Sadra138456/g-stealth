package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	StreamPoolSize = 20
	MaxChunkSize   = 800
	ProtocolALPN   = "h3"
	SNI            = "www.google.com"
	AuthToken      = "MySecretToken123"
)

// wrapper برای سازگاری با io.Reader/Writer
type streamWrapper struct {
	quic.Stream
}

func (s *streamWrapper) Read(p []byte) (int, error) {
	return s.Stream.Read(p)
}

func (s *streamWrapper) Write(p []byte) (int, error) {
	return s.Stream.Write(p)
}

type Peer struct {
	remoteAddr string
	conn       quic.Connection
	streams    chan quic.Stream
	mu         sync.Mutex
}

func main() {
	mode := flag.String("mode", "client", "server or client")
	remoteAddr := flag.String("remote", "185.208.172.162:443", "remote server address")
	listenAddr := flag.String("listen", "0.0.0.0:443", "listen address (server mode)")
	localProxy := flag.String("proxy", "127.0.0.1:1080", "local SOCKS5 proxy address (client mode)")

	flag.Parse()

	if *mode == "server" {
		log.Println("Starting server on", *listenAddr)
		runServer(*listenAddr)
	} else {
		log.Println("Starting client, connecting to", *remoteAddr)
		log.Println("SOCKS5 proxy listening on", *localProxy)
		runClient(*remoteAddr, *localProxy)
	}
}

// ========== SERVER ==========

func runServer(listenAddr string) {
	tlsConf := generateTLSConfig()
	listener, err := quic.ListenAddr(listenAddr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Println("QUIC server listening...")

	for {
		qConn, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go func(conn quic.Connection) {
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go handleStealthStream(stream)
			}
		}(qConn)
	}
}

func handleStealthStream(stream quic.Stream) {
	defer stream.Close()

	// بررسی AuthToken
	tokenBuf := make([]byte, len(AuthToken))
	n, err := stream.Read(tokenBuf)
	if err != nil || n != len(AuthToken) || string(tokenBuf) != AuthToken {
		return
	}

	// خواندن آدرس هدف
	addrLenBuf := make([]byte, 2)
	n, err = stream.Read(addrLenBuf)
	if err != nil || n != 2 {
		return
	}
	addrLen := binary.BigEndian.Uint16(addrLenBuf)

	addrBuf := make([]byte, addrLen)
	n, err = stream.Read(addrBuf)
	if err != nil || n != int(addrLen) {
		return
	}
	forwardAddr := string(addrBuf)

	// اتصال به هدف نهایی
	target, err := net.Dial("tcp", forwardAddr)
	if err != nil {
		return
	}
	defer target.Close()

	// رله دوطرفه
	done := make(chan struct{}, 2)

	// QUIC → TCP
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			header := make([]byte, 3)
			n, err := stream.Read(header)
			if err != nil || n != 3 {
				return
			}

			payloadLen := binary.BigEndian.Uint16(header[:2])
			junkLen := header[2]

			totalLen := int(payloadLen) + int(junkLen)
			buf := make([]byte, totalLen)
			n, err = stream.Read(buf)
			if err != nil || n != totalLen {
				return
			}

			target.Write(buf[:payloadLen])
		}
	}()

	// TCP → QUIC
	go func() {
		defer func() { done <- struct{}{} }()
		wrapped := &streamWrapper{stream}
		io.Copy(wrapped, target)
	}()

	<-done
}

// ========== CLIENT ==========

func runClient(remoteAddr, localProxy string) {
	p := &Peer{
		remoteAddr: remoteAddr,
		streams:    make(chan quic.Stream, StreamPoolSize),
	}

	go p.maintainConnection()

	listener, err := net.Listen("tcp", localProxy)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Println("SOCKS5 proxy ready on", localProxy)

	for {
		c, err := listener.Accept()
		if err != nil {
			continue
		}

		go func(conn net.Conn) {
			targetAddr, err := handleSOCKS5(conn)
			if err != nil {
				conn.Close()
				return
			}
			p.shredderForward(conn, targetAddr)
		}(c)
	}
}

func (p *Peer) maintainConnection() {
	for {
		p.mu.Lock()
		needReconnect := p.conn == nil || p.conn.Context().Err() != nil
		p.mu.Unlock()

		if needReconnect {
			tlsConf := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{ProtocolALPN},
				ServerName:         SNI,
			}

			conn, err := quic.DialAddr(context.Background(), p.remoteAddr, tlsConf, nil)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			p.mu.Lock()
			p.conn = conn
			p.mu.Unlock()

			log.Println("QUIC connection established")

			// پر کردن استریم‌ها
			for i := 0; i < StreamPoolSize; i++ {
				s, err := conn.OpenStream()
				if err != nil {
					break
				}
				s.Write([]byte(AuthToken))
				p.streams <- s
			}
		}

		time.Sleep(5 * time.Second)
	}
}

func handleSOCKS5(localConn net.Conn) (string, error) {
	buf := make([]byte, 512)

	// خواندن greeting
	n, err := localConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return "", fmt.Errorf("invalid SOCKS5 greeting")
	}

	// پاسخ: no auth
	localConn.Write([]byte{0x05, 0x00})

	// خواندن request
	n, err = localConn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		return "", fmt.Errorf("invalid SOCKS5 request")
	}

	// پارس آدرس
	var host string
	var port uint16

	switch buf[3] {
	case 0x01: // IPv4
		host = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // Domain
		domainLen := int(buf[4])
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
	case 0x04: // IPv6
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	default:
		return "", fmt.Errorf("unsupported address type")
	}

	// پاسخ موفقیت
	localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (p *Peer) shredderForward(localConn net.Conn, targetAddr string) {
	defer localConn.Close()

	stream := <-p.streams

	// پر کردن مجدد استریم
	go func() {
		p.mu.Lock()
		conn := p.conn
		p.mu.Unlock()

		if conn != nil {
			s, err := conn.OpenStream()
			if err == nil {
				s.Write([]byte(AuthToken))
				p.streams <- s
			}
		}
	}()

	defer stream.Close()

	// ارسال آدرس هدف
	addrBytes := []byte(targetAddr)
	addrHeader := make([]byte, 2)
	binary.BigEndian.PutUint16(addrHeader, uint16(len(addrBytes)))
	stream.Write(addrHeader)
	stream.Write(addrBytes)

	// رله دوطرفه
	done := make(chan struct{}, 2)

	// QUIC → TCP
	go func() {
		defer func() { done <- struct{}{} }()
		wrapped := &streamWrapper{stream}
		io.Copy(localConn, wrapped)
	}()

	// TCP → QUIC
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, MaxChunkSize)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}

			junkLen := byte(10 + (n % 50))
			junk := make([]byte, junkLen)
			rand.Read(junk)

			header := make([]byte, 3)
			binary.BigEndian.PutUint16(header[:2], uint16(n))
			header[2] = junkLen

			stream.Write(header)
			stream.Write(buf[:n])
			stream.Write(junk)
		}
	}()

	<-done
}

// ========== TLS ==========

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certDER},
				PrivateKey:  key,
			},
		},
		NextProtos: []string{ProtocolALPN},
	}
}
