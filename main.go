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
	"time"

	"github.com/quic-go/quic-go"
)

const (
	StreamPoolSize = 20
	MaxChunkSize   = 16384
	ProtocolALPN   = "h3"
	SNI            = "www.google.com"
	AuthToken      = "MySecretToken123"
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	listenAddr := flag.String("listen", ":443", "listen address")
	remoteAddr := flag.String("remote", "", "remote QUIC server address")
	forwardAddr := flag.String("forward", "127.0.0.1:80", "forward address (server mode)")
	localProxy := flag.String("local", "127.0.0.1:1080", "local SOCKS5 proxy address (client mode)")

	flag.Parse()

	if *mode == "server" {
		runServer(*listenAddr, *forwardAddr)
	} else {
		if *remoteAddr == "" {
			log.Fatal("remote address required in client mode")
		}
		runClient(*localProxy, *remoteAddr)
	}
}

func runServer(listenAddr, forwardAddr string) {
	tlsConf := generateTLSConfig()
	listener, err := quic.ListenAddr(listenAddr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("Server listening on %s, forwarding to %s", listenAddr, forwardAddr)

	for {
		qConn, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(qConn, forwardAddr)
	}
}

func handleConnection(qConn quic.Connection, forwardAddr string) {
	defer qConn.CloseWithError(0, "done")

	for {
		stream, err := qConn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleStream(stream, forwardAddr)
	}
}

func handleStream(stream quic.Stream, forwardAddr string) {
	defer stream.Close()

	authBuf := make([]byte, len(AuthToken))
	if _, err := io.ReadFull(stream, authBuf); err != nil {
		return
	}
	if string(authBuf) != AuthToken {
		return
	}

	tcpConn, err := net.DialTimeout("tcp", forwardAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer tcpConn.Close()

	go io.Copy(stream, tcpConn)
	
	for {
		header := make([]byte, 3)
		if _, err := io.ReadFull(stream, header); err != nil {
			return
		}

		payloadLen := binary.BigEndian.Uint16(header[:2])
		junkLen := header[2]
		totalLen := int(payloadLen) + int(junkLen)

		buf := make([]byte, totalLen)
		if _, err := io.ReadFull(stream, buf); err != nil {
			return
		}

		if _, err := tcpConn.Write(buf[:payloadLen]); err != nil {
			return
		}
	}
}

func runClient(localProxy, remoteAddr string) {
	listener, err := net.Listen("tcp", localProxy)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on %s, tunneling to %s", localProxy, remoteAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleSOCKS5(conn, remoteAddr)
	}
}

func handleSOCKS5(conn net.Conn, remoteAddr string) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// No authentication
	conn.Write([]byte{0x05, 0x00})

	// Read request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}

	// Parse target address
	var targetAddr string
	switch buf[3] {
	case 0x01: // IPv4
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			binary.BigEndian.Uint16(buf[8:10]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		targetAddr = fmt.Sprintf("%s:%d",
			string(buf[5:5+domainLen]),
			binary.BigEndian.Uint16(buf[5+domainLen:7+domainLen]))
	case 0x04: // IPv6
		return // Not implemented
	default:
		return
	}

	// Connect via QUIC tunnel
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ProtocolALPN},
		ServerName:         SNI,
	}

	qConn, err := quic.DialAddr(context.Background(), remoteAddr, tlsConf, nil)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer qConn.CloseWithError(0, "done")

	stream, err := qConn.OpenStream()
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// Send auth token
	stream.Write([]byte(AuthToken))

	// Send target address to server (new feature)
	targetBytes := []byte(targetAddr)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes)))
	stream.Write(lenBuf)
	stream.Write(targetBytes)

	// SOCKS5 success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Relay data
	go io.Copy(conn, stream)
	relayToQUIC(conn, stream)
}

func relayToQUIC(src net.Conn, dst quic.Stream) {
	buf := make([]byte, MaxChunkSize)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}

		junkLen := byte(rand.Intn(64))
		header := make([]byte, 3)
		binary.BigEndian.PutUint16(header[:2], uint16(n))
		header[2] = junkLen

		junk := make([]byte, junkLen)
		rand.Read(junk)

		dst.Write(header)
		dst.Write(buf[:n])
		dst.Write(junk)
	}
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{ProtocolALPN},
	}
}
