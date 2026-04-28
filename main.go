package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

// --- تنظیمات امنیتی ---
const (
	SharedSecret = "Ghost-Protocol-Key-2024" // حتما این را عوض کنید
	ALPN         = "h3"                     
	MaxSkew      = 30                       
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	addr := flag.String("addr", "0.0.0.0:443", "listen address")
	serverPtr := flag.String("server", "127.0.0.1:443", "remote server address")
	flag.Parse()

	if *mode == "server" {
		runServer(*addr)
	} else {
		runClient(*addr, *serverPtr)
	}
}

// ---------------------------
// لایه امنیتی Anti-Replay
// ---------------------------

func generateToken() []byte {
	ts := time.Now().Unix()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ts))
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write(buf)
	return append(buf, mac.Sum(nil)...)
}

func verifyToken(data []byte) bool {
	if len(data) < 40 {
		return false
	}
	receivedTs := int64(binary.BigEndian.Uint64(data[:8]))
	currentTs := time.Now().Unix()
	if currentTs-receivedTs > MaxSkew || receivedTs-currentTs > MaxSkew {
		return false
	}
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write(data[:8])
	return hmac.Equal(data[8:], mac.Sum(nil))
}

// ---------------------------
// بخش سرور (Server Mode)
// ---------------------------

func runServer(listenAddr string) {
	tlsConf := generateTLSConfig()
	config := &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		EnableDatagrams: true,
	}

	listener, err := quic.ListenAddr(listenAddr, tlsConf, config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("💀 Ghost Server active on UDP %s\n", listenAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

// اصلاح شده: استفاده از *quic.Connection
func handleConnection(conn *quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleStream(stream)
	}
}

// اصلاح شده: استفاده از *quic.Stream
func handleStream(stream *quic.Stream) {
	defer stream.Close()

	tokenBuf := make([]byte, 40)
	stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	// حالا stream چون اشاره‌گر است، متد Read را پیاده‌سازی می‌کند
	if _, err := io.ReadFull(stream, tokenBuf); err != nil || !verifyToken(tokenBuf) {
		stream.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return
	}
	stream.SetReadDeadline(time.Time{})

	lenBuf := make([]byte, 1)
	io.ReadFull(stream, lenBuf)
	addrBuf := make([]byte, int(lenBuf[0]))
	io.ReadFull(stream, addrBuf)
	targetAddr := string(addrBuf)

	fmt.Printf("🚀 Tunneling to: %s\n", targetAddr)
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	done := make(chan struct{})
	go func() { io.Copy(target, stream); done <- struct{}{} }()
	go func() { io.Copy(stream, target); done <- struct{}{} }()
	<-done
}

// ---------------------------
// بخش کلاینت (Client Mode)
// ---------------------------

func runClient(localAddr, serverAddr string) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ALPN},
		ServerName:         "www.google.com",
	}

	qConn, err := quic.DialAddr(context.Background(), serverAddr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}

	l, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("🛡️ Ghost Client: SOCKS5 on %s -> Server %s\n", localAddr, serverAddr)

	for {
		client, err := l.Accept()
		if err != nil {
			continue
		}
		go handleSocks(client, qConn)
	}
}

// اصلاح شده: استفاده از *quic.Connection
func handleSocks(client net.Conn, qConn *quic.Connection) {
	defer client.Close()

	buf := make([]byte, 256)
	client.Read(buf[:2]) 
	client.Write([]byte{0x05, 0x00})

	client.Read(buf[:4])
	var target string
	if buf[3] == 0x01 {
		io.ReadFull(client, buf[:4])
		ip := net.IP(buf[:4])
		io.ReadFull(client, buf[:2])
		port := binary.BigEndian.Uint16(buf[:2])
		target = fmt.Sprintf("%s:%d", ip, port)
	} else if buf[3] == 0x03 {
		io.ReadFull(client, buf[:1])
		length := int(buf[0])
		io.ReadFull(client, buf[:length])
		domain := string(buf[:length])
		io.ReadFull(client, buf[:2])
		port := binary.BigEndian.Uint16(buf[:2])
		target = fmt.Sprintf("%s:%d", domain, port)
	}
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	stream, err := qConn.OpenStreamSync(context.Background())
	if err != nil {
		return
	}
	defer stream.Close()

	stream.Write(generateToken())
	stream.Write([]byte{byte(len(target))})
	stream.Write([]byte(target))

	done := make(chan struct{})
	go func() { io.Copy(stream, client); done <- struct{}{} }()
	go func() { io.Copy(client, stream); done <- struct{}{} }()
	<-done
}

// ---------------------------
// ابزارهای کمکی
// ---------------------------

func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{ALPN},
	}
}
