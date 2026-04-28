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
	SharedSecret = "Ghost-Protocol-Key-2024" // کلید مشترک برای تولید توکن
	ALPN         = "h3"                     // جعل ترافیک HTTP/3
	MaxSkew      = 30                       // ۳۰ ثانیه اعتبار برای هر پکت (Anti-Replay)
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	addr := flag.String("addr", "0.0.0.0:443", "listen address (UDP for QUIC, TCP for SOCKS5)")
	serverPtr := flag.String("server", "127.0.0.1:443", "remote server address (for client mode)")
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

func handleConnection(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream quic.Stream) {
	defer stream.Close()

	// ۱. تایید هویت ضد بازپخش
	tokenBuf := make([]byte, 40)
	stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(stream, tokenBuf); err != nil || !verifyToken(tokenBuf) {
		// فریب: ارسال دیتای رندوم برای گیج کردن اسکنر
		stream.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return
	}
	stream.SetReadDeadline(time.Time{})

	// ۲. خواندن مقصد
	lenBuf := make([]byte, 1)
	io.ReadFull(stream, lenBuf)
	addrBuf := make([]byte, int(lenBuf[0]))
	io.ReadFull(stream, addrBuf)
	targetAddr := string(addrBuf)

	// ۳. اتصال به اینترنت آزاد
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
		ServerName:         "www.google.com", // جعل SNI
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

func handleSocks(client net.Conn, qConn quic.Connection) {
	defer client.Close()

	// هندشیک ساده SOCKS5
	buf := make([]byte, 256)
	io.ReadFull(client, buf[:2]) // روش‌های احراز هویت
	client.Write([]byte{0x05, 0x00})

	io.ReadFull(client, buf[:4]) // درخواست CMD
	var target string
	if buf[3] == 0x01 { // IPv4
		io.ReadFull(client, buf[:4])
		ip := net.IP(buf[:4])
		io.ReadFull(client, buf[:2])
		port := binary.BigEndian.Uint16(buf[:2])
		target = fmt.Sprintf("%s:%d", ip, port)
	} else if buf[3] == 0x03 { // Domain name
		io.ReadFull(client, buf[:1])
		len := int(buf[0])
		io.ReadFull(client, buf[:len])
		domain := string(buf[:len])
		io.ReadFull(client, buf[:2])
		port := binary.BigEndian.Uint16(buf[:2])
		target = fmt.Sprintf("%s:%d", domain, port)
	}
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// ایجاد استریم در تونل QUIC
	stream, err := qConn.OpenStreamSync(context.Background())
	if err != nil {
		return
	}
	defer stream.Close()

	// ارسال توکن امنیتی و آدرس مقصد
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
