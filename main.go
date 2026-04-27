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
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	StreamPoolSize = 50
	MaxChunkSize   = 800 // سایز هر تکه برای مقابله با DPI
	ProtocolALPN   = "h3"
	SNI            = "www.google.com"
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	remoteAddr := flag.String("remote", "127.0.0.1:443", "Server address")
	listenAddr := flag.String("listen", "0.0.0.0:443", "Listen address")
	forwardAddr := flag.String("forward", "127.0.0.1:8080", "X-UI port")
	localProxy := flag.String("proxy", "127.0.0.1:10808", "Local SOCKS/Tunnel port")
	flag.Parse()

	if *mode == "server" {
		runServer(*listenAddr, *forwardAddr)
	} else {
		runClient(*remoteAddr, *localProxy)
	}
}

// --- بخش سرور ---
func runServer(listenAddr, forwardAddr string) {
	listener, err := quic.ListenAddr(listenAddr, generateTLSConfig(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[SERVER] G-Stealth Running... Forwarding to %s\n", forwardAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			continue
		}
		go func(qConn quic.Connection) {
			for {
				stream, err := qConn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go handleStealthStream(stream, forwardAddr)
			}
		}(conn)
	}
}

func handleStealthStream(stream quic.Stream, forwardAddr string) {
	defer stream.Close()
	target, err := net.Dial("tcp", forwardAddr)
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// از سرور به کلاینت
	go func() {
		io.Copy(stream, target)
		wg.Done()
	}()

	// از کلاینت به سرور (بازسازی دیتای خرد شده)
	go func() {
		for {
			header := make([]byte, 3) // [ChunkLen (2)] [JunkLen (1)]
			if _, err := io.ReadFull(stream, header); err != nil {
				break
			}
			chunkLen := binary.BigEndian.Uint16(header[:2])
			junkLen := uint8(header[2])

			fullBuf := make([]byte, int(chunkLen)+int(junkLen))
			if _, err := io.ReadFull(stream, fullBuf); err != nil {
				break
			}
			target.Write(fullBuf[:chunkLen]) // فقط دیتای اصلی را به X-UI می‌فرستیم
		}
		wg.Done()
	}()
	wg.Wait()
}

// --- بخش کلاینت ---
type Peer struct {
	conn    quic.Connection
	streams chan quic.Stream
}

func runClient(remoteAddr, localProxy string) {
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{ProtocolALPN}, ServerName: SNI}
	conn, err := quic.DialAddr(context.Background(), remoteAddr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}

	p := &Peer{
		conn:    conn,
		streams: make(chan quic.Stream, StreamPoolSize),
	}

	for i := 0; i < StreamPoolSize; i++ {
		s, _ := conn.OpenStreamSync(context.Background())
		p.streams <- s
	}

	l, _ := net.Listen("tcp", localProxy)
	fmt.Printf("[CLIENT] G-Stealth Tunnel Active on %s\n", localProxy)

	for {
		c, _ := l.Accept()
		go p.shredderForward(c)
	}
}

func (p *Peer) shredderForward(localConn net.Conn) {
	defer localConn.Close()
	stream := <-p.streams
	// شارژ مجدد استخر
	go func() { s, _ := p.conn.OpenStreamSync(context.Background()); p.streams <- s }()

	var wg sync.WaitGroup
	wg.Add(2)

	// دریافت مستقیم از سرور
	go func() { io.Copy(localConn, stream); wg.Done() }()

	// ارسال به سرور با مکانیزم Shredding
	go func() {
		buf := make([]byte, MaxChunkSize)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				break
			}

			// هدر: طول دیتا و طول Junk
			junkLen := uint8(time.Now().UnixNano() % 50) // مقدار تصادفی Junk
			header := make([]byte, 3)
			binary.BigEndian.PutUint16(header[:2], uint16(n))
			header[2] = junkLen

			// دیتای تصادفی
			junk := make([]byte, junkLen)
			rand.Read(junk)

			// ارسال پکت نهایی: [Header][Data][Junk]
			packet := append(header, buf[:n]...)
			packet = append(packet, junk...)
			stream.Write(packet)
		}
		wg.Done()
	}()
	wg.Wait()
}

func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour * 24 * 365)}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{Certificates: []tls.Config{tlsCert}, NextProtos: []string{ProtocolALPN}}
}
