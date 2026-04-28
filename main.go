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
	StreamPoolSize = 20
	MaxChunkSize   = 800
	ProtocolALPN   = "h3"
	SNI            = "www.google.com"
	AuthToken      = "MySecretToken123" // حتما این را تغییر دهید
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, MaxChunkSize+100)
	},
}

func main() {
	mode := flag.String("mode", "server", "server or client")
	remoteAddr := flag.String("remote", "127.0.0.1:443", "Server address")
	listenAddr := flag.String("listen", "0.0.0.0:443", "Listen address")
	forwardAddr := flag.String("forward", "127.0.0.1:8080", "X-UI/Upstream port")
	localProxy := flag.String("proxy", "127.0.0.1:10808", "Local port")
	flag.Parse()

	if *mode == "server" {
		runServer(*listenAddr, *forwardAddr)
	} else {
		runClient(*remoteAddr, *localProxy)
	}
}

// --- بخش سرور ---
func runServer(listenAddr, forwardAddr string) {
	tlsConf := generateTLSConfig()
	listener, err := quic.ListenAddr(listenAddr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[SERVER] Bridge Active. Forwarding to %s\n", forwardAddr)

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

	// 1. چک کردن Token (احراز هویت)
	authBuf := make([]byte, len(AuthToken))
	if _, err := io.ReadFull(stream, authBuf); err != nil || string(authBuf) != AuthToken {
		return
	}

	target, err := net.DialTimeout("tcp", forwardAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(stream, target)
		wg.Done()
	}()

	go func() {
		header := make([]byte, 3)
		for {
			if _, err := io.ReadFull(stream, header); err != nil {
				break
			}
			chunkLen := binary.BigEndian.Uint16(header[:2])
			junkLen := uint8(header[2])

			fullBuf := make([]byte, int(chunkLen)+int(junkLen))
			if _, err := io.ReadFull(stream, fullBuf); err != nil {
				break
			}
			target.Write(fullBuf[:chunkLen])
		}
		wg.Done()
	}()
	wg.Wait()
}

// --- بخش کلاینت ---
type Peer struct {
	remoteAddr string
	conn       quic.Connection
	streams    chan quic.Stream
	mu         sync.Mutex
}

func runClient(remoteAddr, localProxy string) {
	p := &Peer{
		remoteAddr: remoteAddr,
		streams:    make(chan quic.Stream, StreamPoolSize),
	}

	go p.maintainConnection()

	l, err := net.Listen("tcp", localProxy)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[CLIENT] Tunnel Active on %s -> %s\n", localProxy, remoteAddr)

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go p.shredderForward(c)
	}
}

// مدیریت اتصال و برقراری مجدد در صورت قطع شدن
func (p *Peer) maintainConnection() {
	for {
		if p.conn == nil || p.conn.Context().Err() != nil {
			tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{ProtocolALPN}, ServerName: SNI}
			conn, err := quic.DialAddr(context.Background(), p.remoteAddr, tlsConf, nil)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			p.conn = conn
			// پر کردن استخر استریم‌ها
			for i := 0; i < StreamPoolSize; i++ {
				s, _ := conn.OpenStream()
				if s != nil {
					s.Write([]byte(AuthToken)) // ارسال توکن بلافاصله بعد از باز شدن
					p.streams <- s
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (p *Peer) shredderForward(localConn net.Conn) {
	defer localConn.Close()

	var stream quic.Stream
	select {
	case stream = <-p.streams:
		// استریم را گرفتیم، یکی جدید جایگزین می‌کنیم
		go func() {
			if p.conn != nil {
				s, err := p.conn.OpenStream()
				if err == nil {
					s.Write([]byte(AuthToken))
					p.streams <- s
				}
			}
		}()
	case <-time.After(3 * time.Second):
		return
	}
	defer stream.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// سرور به کلاینت (دریافت مستقیم)
	go func() {
		io.Copy(localConn, stream)
		wg.Done()
	}()

	// کلاینت به سرور (Shredding)
	go func() {
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)

		for {
			n, err := localConn.Read(buf[:MaxChunkSize])
			if err != nil {
				break
			}

			junkLen := uint8(time.Now().UnixNano() % 64)
			header := make([]byte, 3)
			binary.BigEndian.PutUint16(header[:2], uint16(n))
			header[2] = junkLen

			junk := make([]byte, junkLen)
			rand.Read(junk)

			stream.Write(header)
			stream.Write(buf[:n])
			stream.Write(junk)
		}
		wg.Done()
	}()
	wg.Wait()
}

func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		BasicConstraintsValid: true,
		IsCA: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{ProtocolALPN}}
}
