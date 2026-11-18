package carrier

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

var (
	testHash = [20]byte{0x42, 0x54, 0x41, 0x57, 0x47, 1}
	peerA    = [20]byte{1}
	peerB    = [20]byte{2}
)

// tcpPair returns a buffered loopback connection pair. net.Pipe is fully
// synchronous and deadlocks the carriers (both read loops write requests
// while nobody reads); kernel socket buffers match production transports.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- nil
			return
		}
		srvCh <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}
	srv := <-srvCh
	ln.Close()
	if srv == nil {
		cli.Close()
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli, srv
}

func TestHandshakeBytes(t *testing.T) {
	h := HandshakeBytes(testHash, peerA)
	if len(h) != 68 {
		t.Fatalf("len %d, want 68", len(h))
	}
	if h[0] != 19 {
		t.Fatalf("protocol name length %d, want 19", h[0])
	}
	if string(h[1:20]) != "BitTorrent protocol" {
		t.Fatalf("protocol name %q", h[1:20])
	}
	if !bytes.Equal(h[28:48], testHash[:]) {
		t.Fatal("infohash not at [28:48]")
	}
	if !bytes.Equal(h[48:68], peerA[:]) {
		t.Fatal("peer ID not at [48:68]")
	}
}

func TestHandshakeRejectsWrongInfoHash(t *testing.T) {
	a, b := tcpPair(t)
	errs := make(chan error, 2)
	go func() {
		_, err := Handshake(a, testHash, peerA)
		errs <- err
	}()
	go func() {
		other := testHash
		other[0] ^= 0xff
		_, err := Handshake(b, other, peerB)
		errs <- err
	}()
	for range 2 {
		select {
		case err := <-errs:
			if err == nil {
				t.Fatal("handshake with mismatched infohash succeeded")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("handshake deadlock")
		}
	}
}

type result struct {
	tr  Transport
	err error
}

func pair(t *testing.T, fa, fb func(net.Conn) (Transport, error)) (Transport, Transport) {
	t.Helper()
	a, b := tcpPair(t)
	ch := make(chan result, 1)
	go func() {
		tr, err := fa(a)
		ch <- result{tr, err}
	}()
	tb, err := fb(b)
	if err != nil {
		t.Fatalf("carrier b: %v", err)
	}
	t.Cleanup(tb.Wait)
	r := <-ch
	if r.err != nil {
		t.Fatalf("carrier a: %v", r.err)
	}
	t.Cleanup(r.tr.Wait)
	return r.tr, tb
}

func roundTrip(t *testing.T, ta, tb Transport) {
	t.Helper()
	payload := make([]byte, 256)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := ta.Send(payload); err != nil {
		t.Fatalf("send a->b: %v", err)
	}
	select {
	case got := <-tb.Recv():
		if !bytes.Equal(got, payload) {
			t.Fatalf("b received %d bytes, want the same payload", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery a->b")
	}
	if err := tb.Send(payload); err != nil {
		t.Fatalf("send b->a: %v", err)
	}
	select {
	case got := <-ta.Recv():
		if !bytes.Equal(got, payload) {
			t.Fatalf("a received %d bytes, want the same payload", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery b->a")
	}
}

func TestRequestPieceRoundTrip(t *testing.T) {
	ta, tb := pair(t,
		func(c net.Conn) (Transport, error) { return NewRequestPiece(c, testHash, peerA, false) },
		func(c net.Conn) (Transport, error) { return NewRequestPiece(c, testHash, peerB, true) },
	)
	roundTrip(t, ta, tb)
}

func TestExtendedRoundTrip(t *testing.T) {
	ta, tb := pair(t,
		func(c net.Conn) (Transport, error) { return NewExtended(c, testHash, peerA) },
		func(c net.Conn) (Transport, error) { return NewExtended(c, testHash, peerB) },
	)
	roundTrip(t, ta, tb)
}

func TestOversizedSendRejected(t *testing.T) {
	ta, tb := pair(t,
		func(c net.Conn) (Transport, error) { return NewExtended(c, testHash, peerA) },
		func(c net.Conn) (Transport, error) { return NewExtended(c, testHash, peerB) },
	)
	_ = tb
	if err := ta.Send(make([]byte, BlockSize)); err == nil {
		t.Fatal("extended Send accepted BlockSize payload, want error")
	}
	pa, pb := pair(t,
		func(c net.Conn) (Transport, error) { return NewRequestPiece(c, testHash, peerA, false) },
		func(c net.Conn) (Transport, error) { return NewRequestPiece(c, testHash, peerB, true) },
	)
	_ = pb
	if err := pa.Send(make([]byte, BlockSize)); err == nil {
		t.Fatal("request/piece Send accepted BlockSize payload, want error")
	}
}
