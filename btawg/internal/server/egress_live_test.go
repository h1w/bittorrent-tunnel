package server

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/store"
)

func TestPolicyFlipClosesEstablishedEgress(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/egress.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ip := netip.MustParseAddr("10.77.0.2")
	rec := store.ClientRecord{ID: "client", IP: ip.String(), PeerID: "peer"}
	if err = st.CreateClient(rec); err != nil {
		t.Fatal(err)
	}
	p := newPolicySnapshot()
	gw := netip.MustParseAddr("10.77.0.1")
	if err = p.reload(st, gw); err != nil {
		t.Fatal(err)
	}
	inner := newFakeListener(1)
	l := &gatedListener{inner: inner, policy: p, active: make(map[*egressSession]netip.Addr)}
	defer l.Close()
	a, b := net.Pipe()
	defer b.Close()
	if err = b.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	inner.conns <- &connWithAddr{Conn: a, remote: &net.TCPAddr{IP: net.IP(ip.AsSlice())}}
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec, err = st.GetClient(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	denied := false
	rec.Internet = &denied
	if err = st.SaveClient(rec); err != nil {
		t.Fatal(err)
	}
	if err = p.reload(st, gw); err != nil {
		t.Fatal(err)
	}
	l.closeDenied()
	_, err = b.Write([]byte("must not reach proxy"))
	if err == nil {
		t.Fatal("old egress connection still passes data")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatalf("old egress connection was not closed: %v", err)
	}
}
