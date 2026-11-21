package nativepeer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/direct"
)

func loopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

func newSocket(t *testing.T) *Socket {
	t.Helper()
	s, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

type result struct {
	tr  carrier.Transport
	err error
}

func start(ctx context.Context, s *Socket, offer Offer) <-chan result {
	ch := make(chan result, 1)
	go func() { tr, err := s.Connect(ctx, offer); ch <- result{tr, err} }()
	return ch
}
func take(t *testing.T, ch <-chan result) carrier.Transport {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { r.tr.Close(); r.tr.Wait() })
		return r.tr
	case <-time.After(4 * time.Second):
		t.Fatal("connect stalled")
		return nil
	}
}
func receive(t *testing.T, tr carrier.Transport, want []byte) {
	t.Helper()
	select {
	case got := <-tr.Recv():
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("datagram not received")
	}
}

func TestCrossedProbesAndDatagrams(t *testing.T) {
	a, b := newSocket(t), newSocket(t)
	key := [32]byte{1, 2, 3}
	expires := time.Now().Add(3 * time.Second)
	ca := start(context.Background(), a, Offer{Secret: key, Initiator: true, Candidates: []netip.AddrPort{loopback(b.Port())}, Expires: expires})
	cb := start(context.Background(), b, Offer{Secret: key, Candidates: []netip.AddrPort{loopback(a.Port())}, Expires: expires})
	ta, tb := take(t, ca), take(t, cb)
	if err := ta.Send([]byte{0, 1, 2, 0xff}); err != nil {
		t.Fatal(err)
	}
	receive(t, tb, []byte{0, 1, 2, 0xff})
	if err := tb.Send([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	receive(t, ta, []byte("reply"))
}

func TestWrongKeyAndTimeout(t *testing.T) {
	a, b := newSocket(t), newSocket(t)
	expires := time.Now().Add(350 * time.Millisecond)
	ca := start(context.Background(), a, Offer{Secret: [32]byte{1}, Initiator: true, Candidates: []netip.AddrPort{loopback(b.Port())}, Expires: expires})
	cb := start(context.Background(), b, Offer{Secret: [32]byte{2}, Candidates: []netip.AddrPort{loopback(a.Port())}, Expires: expires})
	for _, ch := range []<-chan result{ca, cb} {
		select {
		case r := <-ch:
			if r.tr != nil || !errors.Is(r.err, context.DeadlineExceeded) {
				t.Fatalf("unexpected result: %+v", r)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout stalled")
		}
	}
}

func TestNativeWireBytes(t *testing.T) {
	a, b := newSocket(t), newSocket(t)
	// Two real UDP relays expose a distinct stable source at each peer.
	pa, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pa.Close()
	pb, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pb.Close()
	observed := make(chan []byte, 64)
	forward := func(src, dst *net.UDPConn, target netip.AddrPort) {
		buf := make([]byte, 65535)
		for {
			n, _, err := src.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p := append([]byte(nil), buf[:n]...)
			select {
			case observed <- p:
			default:
			}
			_, _ = dst.WriteToUDPAddrPort(p, target)
		}
	}
	go forward(pa, pb, loopback(b.Port()))
	go forward(pb, pa, loopback(a.Port()))
	key := [32]byte{9}
	exp := time.Now().Add(3 * time.Second)
	ca := start(context.Background(), a, Offer{Secret: key, Initiator: true, Candidates: []netip.AddrPort{pa.LocalAddr().(*net.UDPAddr).AddrPort()}, Expires: exp})
	cb := start(context.Background(), b, Offer{Secret: key, Candidates: []netip.AddrPort{pb.LocalAddr().(*net.UDPAddr).AddrPort()}, Expires: exp})
	ta, tb := take(t, ca), take(t, cb)
	payload := []byte{4, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0, 0xff}
	if err := ta.Send(payload); err != nil {
		t.Fatal(err)
	}
	receive(t, tb, payload)
	deadline := time.After(time.Second)
	for {
		select {
		case p := <-observed:
			if bytes.Equal(p, payload) {
				return
			}
		case <-deadline:
			t.Fatal("raw payload not observed on UDP wire")
		}
	}
}

func TestObserverAndShutdown(t *testing.T) {
	s := newSocket(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go direct.ServeObserver(ctx, pc)
	obctx, obcancel := context.WithTimeout(ctx, time.Second)
	defer obcancel()
	got, err := s.Observe(obctx, pc.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil || got != loopback(s.Port()) {
		t.Fatalf("observation %v: %v", got, err)
	}
	pending := start(context.Background(), s, Offer{Secret: [32]byte{1}, Initiator: true, Candidates: []netip.AddrPort{loopback(1)}, Expires: time.Now().Add(time.Minute)})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-pending:
		if !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("got %v", r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("close left connection pending")
	}
}
