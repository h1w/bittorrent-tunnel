package server

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/store"
)

// fakeAddr is a net.Addr backed by a string address.
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// closableConn wraps a net.Pipe connection and records whether Close was called.
type closableConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closableConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// fakeListener returns connections from a channel in order.
type fakeListener struct {
	conns     chan net.Conn
	addr      net.Addr
	closeOnce sync.Once
}

func newFakeListener(cap int) *fakeListener {
	return &fakeListener{
		conns: make(chan net.Conn, cap),
		addr:  fakeAddr("fake-listener"),
	}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, errors.New("listener closed")
	}
	return c, nil
}

func (l *fakeListener) Close() error {
	l.closeOnce.Do(func() { close(l.conns) })
	return nil
}
func (l *fakeListener) Addr() net.Addr { return l.addr }

func makePipeConn(remote netip.Addr) *closableConn {
	c, _ := net.Pipe()
	return &closableConn{Conn: &connWithAddr{Conn: c, remote: net.TCPAddrFromAddrPort(netip.AddrPortFrom(remote, 0))}}
}

// connWithAddr overrides the RemoteAddr of an underlying connection.
type connWithAddr struct {
	net.Conn
	remote net.Addr
}

func (c *connWithAddr) RemoteAddr() net.Addr { return c.remote }

func TestGatedListenerBlocksNoInternetAndUnknown(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/policy.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	serverIP := netip.MustParseAddr("10.77.0.1")
	aIP := netip.MustParseAddr("10.77.0.2")
	cIP := netip.MustParseAddr("10.77.0.4")
	unknownIP := netip.MustParseAddr("10.77.0.9")

	a := store.ClientRecord{
		ID:     "A",
		Name:   "client-a",
		IP:     aIP.String(),
		PeerID: "peer-a",
	}
	c := store.ClientRecord{
		ID:         "C",
		Name:       "client-c",
		IP:         cIP.String(),
		PeerID:     "peer-c",
		NoInternet: true,
	}
	for _, rec := range []store.ClientRecord{a, c} {
		if err := st.CreateClient(rec); err != nil {
			t.Fatalf("create client %s: %v", rec.ID, err)
		}
	}

	p := newPolicySnapshot()
	if err := p.reload(st, serverIP); err != nil {
		t.Fatalf("reload: %v", err)
	}

	inner := newFakeListener(4)
	gl := &gatedListener{inner: inner, policy: p}

	// First connection: C has NoInternet -> should be closed and retried.
	cConn := makePipeConn(cIP)
	inner.conns <- cConn
	// Second connection: A is allowed -> should be returned.
	aConn := makePipeConn(aIP)
	inner.conns <- aConn

	got, err := gl.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got != aConn {
		t.Fatalf("expected A's connection, got %v", got)
	}
	if !cConn.closed.Load() {
		t.Fatalf("C's connection should have been closed")
	}

	// Unknown IP -> closed.
	unkConn := makePipeConn(unknownIP)
	inner.conns <- unkConn
	serverConn := makePipeConn(serverIP)
	inner.conns <- serverConn

	got, err = gl.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got != serverConn {
		t.Fatalf("expected server connection, got %v", got)
	}
	if !unkConn.closed.Load() {
		t.Fatalf("unknown connection should have been closed")
	}

	_ = gl.Close()
}

func TestGatedListenerDelegatesCloseAndAddr(t *testing.T) {
	inner := newFakeListener(0)
	gl := &gatedListener{inner: inner, policy: newPolicySnapshot()}

	if gl.Addr() != inner.Addr() {
		t.Fatalf("Addr() did not delegate")
	}

	done := make(chan struct{})
	go func() {
		// Accept will block until the listener is closed.
		for {
			_, err := gl.Accept()
			if err != nil {
				close(done)
				return
			}
		}
	}()

	if err := gl.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Accept")
	}
}
