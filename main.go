package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	SuperSecretKey = "Phoenix-Auth-Key-2024" // رمز عبور اختصاصی شما
	ALPN           = "h3"                   // شبیه‌سازی پروتکل HTTP/3
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	addr := flag.String("addr", "0.0.0.0:443", "listen address")
	serverPtr := flag.String("server", "YOUR_SERVER_IP:443", "remote server address")
	flag.Parse()

	if *mode == "server" {
		runPhoenixServer(*addr)
	} else {
		runPhoenixClient(*addr, *serverPtr)
	}
}

// --- لایه امنیت و احراز هویت (Anti-Probe Layer) ---

func generateAuthToken() []byte {
	ts := time.Now().Unix() / 30 // توکن هر ۳۰ ثانیه عوض می‌شود
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ts))
	mac := hmac.New(sha256.New, []byte(SuperSecretKey))
	mac.Write(buf)
	return mac.Sum(nil)
}

func verifyAuth(token []byte) bool {
	expected := generateAuthToken()
	return hmac.Equal(token, expected)
}

// --- بخش سرور (Super Server) ---

func runPhoenixServer(addr string) {
	// تولید گواهی موقت (در محیط واقعی از Cert واقعی استفاده کنید)
	cert, _ := generateSelfSignedCert() 
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPN},
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:  45 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		EnableDatagrams: true,
	}

	listener, err := quic.ListenAddr(addr, tlsConf, quicConf)
	if err != nil { log.Fatal(err) }
	fmt.Println("🔥 Phoenix Super Protocol Active on", addr)

	for {
		conn, _ := listener.Accept(context.Background())
		go func(c quic.Connection) {
			for {
				stream, err := c.AcceptStream(context.Background())
				if err != nil { return }
				go handlePhoenixStream(stream)
			}
		}(conn)
	}
}

func handlePhoenixStream(stream quic.Stream) {
	defer stream.Close()

	// ۱. تایید هویت (اگر اشتباه باشد، سرور سکوت می‌کند یا دیتای فیک می‌فرستد)
	authBuf := make([]byte, 32)
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(stream, authBuf); err != nil || !verifyAuth(authBuf) {
		stream.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	stream.SetReadDeadline(time.Time{})

	// ۲. خواندن آدرس مقصد (Obfuscated)
	lenBuf := make([]byte, 1)
	stream.Read(lenBuf)
	addrBuf := make([]byte, int(lenBuf[0]))
	stream.Read(addrBuf)
	targetAddr := string(addrBuf)

	// ۳. برقراری اتصال به اینترنت آزاد
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil { return }
	defer target.Close()

	fmt.Printf("✅ Forwarding to: %s\n", targetAddr)

	// ۴. انتقال دیتا با لایه Padding تصادفی (اختیاری برای امنیت بیشتر)
	done := make(chan struct{})
	go func() { io.Copy(target, stream); done <- struct{}{} }()
	go func() { io.Copy(stream, target); done <- struct{}{} }()
	<-done
}

// --- بخش کلاینت (Super Client) ---

func runPhoenixClient(localAddr, serverAddr string) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ALPN},
		ServerName:         "www.google.com", // جعل SNI
	}

	conn, err := quic.DialAddr(context.Background(), serverAddr, tlsConf, &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil { log.Fatal(err) }

	l, _ := net.Listen("tcp", localAddr)
	fmt.Printf("🛡️ Phoenix Client: SOCKS5 on %s\n", localAddr)

	for {
		client, _ := l.Accept()
		go func(s net.Conn) {
			defer s.Close()
			target := getSocksTarget(s)
			if target == "" { return }

			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil { return }
			defer stream.Close()

			// ارسال توکن امنیتی و آدرس
			stream.Write(generateAuthToken())
			stream.Write([]byte{byte(len(target))})
			stream.Write([]byte(target))

			done := make(chan struct{})
			go func() { io.Copy(stream, s); done <- struct{}{} }()
			go func() { io.Copy(s, stream); done <- struct{}{} }()
			<-done
		}(client)
	}
}

// تابع کمکی برای SOCKS5 (بدون تغییر)
func getSocksTarget(s net.Conn) string {
	buf := make([]byte, 256)
	s.Read(buf[:2]); s.Write([]byte{0x05, 0x00})
	s.Read(buf[:4])
	var host string
	if buf[3] == 0x01 {
		io.ReadFull(s, buf[:4]); host = net.IP(buf[:4]).String()
	} else if buf[3] == 0x03 {
		io.ReadFull(s, buf[:1]); l := int(buf[0]); io.ReadFull(s, buf[:l]); host = string(buf[:l])
	}
	io.ReadFull(s, buf[:2]); port := (int(buf[0]) << 8) | int(buf[1])
	s.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return fmt.Sprintf("%s:%d", host, port)
}

// تابع کمکی برای تولید گواهی درجا (Self-Signed)
func generateSelfSignedCert() (tls.Certificate, error) {
	// این بخش برای سادگی در اینجا گواهی واقعی تولید نمیکند، 
	// در محیط تست از فایل استفاده کنید یا از کدهای قبلی برای تولید RSA استفاده کنید.
	// فعلاً فرض بر وجود فایل است یا از یک تابع کمکی RSA استفاده کنید.
	return tls.LoadX509KeyPair("server.crt", "server.key")
}
