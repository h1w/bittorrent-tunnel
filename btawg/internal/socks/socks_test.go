package socks

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func startEgress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := NewServer(
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		func(ctx context.Context) (net.PacketConn, error) {
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		},
	)
	go srv.Serve(ctx, ln)
	return ln.Addr().String()
}

func tcpEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteToUDP(buf[:n], from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr)
}

func TestConnectRoundTrip(t *testing.T) {
	remote := startEgress(t)
	echo := tcpEcho(t)
	cli := NewClient(remote)
	conn, err := cli.Dial(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatalf("chain Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := bufio.NewReader(conn).ReadString('g')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
}

func TestUDPAssociateRoundTrip(t *testing.T) {
	remote := startEgress(t)
	echo := udpEcho(t)
	cli := NewClient(remote)
	pc, err := cli.DialUDP(context.Background())
	if err != nil {
		t.Fatalf("chain DialUDP: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("hello"), echo); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 128)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("udp echo = %q, want hello", buf[:n])
	}
	if from.(*net.UDPAddr).Port != echo.Port {
		t.Fatalf("udp from %v, want echo %v", from, echo)
	}
}

func TestChainedConnectRoundTrip(t *testing.T) {
	// The product path: an app speaks SOCKS5 to the local server, whose
	// dialers chain to the remote egress, which dials the destination.
	egressAddr := startEgress(t)
	chain := NewClient(egressAddr)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	local := NewServer(chain.Dial, func(ctx context.Context) (net.PacketConn, error) {
		return chain.DialUDP(ctx)
	})
	go local.Serve(ctx, ln)
	echo := tcpEcho(t)
	app := NewClient(ln.Addr().String())
	conn, err := app.Dial(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatalf("app Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("chained")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len("chained"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "chained" {
		t.Fatalf("echo = %q, want chained", got)
	}
}

func TestNoAuthMethods(t *testing.T) {
	remote := startEgress(t)
	c, err := net.Dial("tcp", remote)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Offer only an unacceptable auth method.
	if _, err := c.Write([]byte{socksVersion, 1, 0x7F}); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != socksVersion || reply[1] != 0xFF {
		t.Fatalf("reply = %v, want [5 FF]", reply)
	}
}
