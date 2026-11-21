package nativepeer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLivePathCannotBeReplaced(t *testing.T) {
	a, b := newSocket(t), newSocket(t)
	exp := time.Now().Add(3 * time.Second)
	first := [32]byte{1}
	ca := start(context.Background(), a, Offer{Secret: first, Initiator: true, Candidates: []netip.AddrPort{loopback(b.Port())}, Expires: exp})
	cb := start(context.Background(), b, Offer{Secret: first, Candidates: []netip.AddrPort{loopback(a.Port())}, Expires: exp})
	ta, tb := take(t, ca), take(t, cb)
	deadline := time.Now().Add(350 * time.Millisecond)
	second := [32]byte{2}
	ca = start(context.Background(), a, Offer{Secret: second, Initiator: true, Candidates: []netip.AddrPort{loopback(b.Port())}, Expires: deadline})
	cb = start(context.Background(), b, Offer{Secret: second, Candidates: []netip.AddrPort{loopback(a.Port())}, Expires: deadline})
	for _, ch := range []<-chan result{ca, cb} {
		select {
		case r := <-ch:
			if r.tr != nil || !errors.Is(r.err, context.DeadlineExceeded) {
				t.Fatalf("replacement returned %+v", r)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("replacement stalled")
		}
	}
	if err := ta.Send([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	receive(t, tb, []byte("still alive"))
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ta.Done():
	case <-time.After(time.Second):
		t.Fatal("socket close left transport open")
	}
	if err := ta.Send([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after close: %v", err)
	}
}

func TestIPv6Path(t *testing.T) {
	a, b := newSocket(t), newSocket(t)
	if a.v6 == nil || b.v6 == nil {
		t.Skip("IPv6 unavailable")
	}
	ip := netip.MustParseAddr("::1")
	exp := time.Now().Add(3 * time.Second)
	key := [32]byte{8}
	ca := start(context.Background(), a, Offer{Secret: key, Initiator: true, Candidates: []netip.AddrPort{netip.AddrPortFrom(ip, b.Port())}, Expires: exp})
	cb := start(context.Background(), b, Offer{Secret: key, Candidates: []netip.AddrPort{netip.AddrPortFrom(ip, a.Port())}, Expires: exp})
	ta, tb := take(t, ca), take(t, cb)
	if err := ta.Send([]byte("ipv6")); err != nil {
		t.Fatal(err)
	}
	receive(t, tb, []byte("ipv6"))
}
