package server

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"bittorrent-tunnel/btawg/internal/store"
)

// fakeTun records Write calls and otherwise satisfies tun.Device.
type fakeTun struct {
	writes [][][]byte
	offsets []int
}

func (f *fakeTun) File() *os.File                                 { return nil }
func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) { return 0, nil }
func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	f.writes = append(f.writes, bufs)
	f.offsets = append(f.offsets, offset)
	return len(bufs), nil
}
func (f *fakeTun) MTU() (int, error)        { return 1420, nil }
func (f *fakeTun) Name() (string, error)    { return "fake", nil }
func (f *fakeTun) Events() <-chan tun.Event { return nil }
func (f *fakeTun) Close() error             { return nil }
func (f *fakeTun) BatchSize() int           { return 1 }

// makeIPv4 returns a minimal IPv4 packet with the given src/dst addresses.
func makeIPv4(src, dst netip.Addr) []byte {
	p := make([]byte, 20)
	p[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	src4, dst4 := src.As4(), dst.As4()
	copy(p[12:16], src4[:])
	copy(p[16:20], dst4[:])
	return p
}

func TestFilterTunDropsDisallowed(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/filter.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	serverIP := netip.MustParseAddr("10.77.0.1")
	a := store.ClientRecord{
		ID:      "A",
		Name:    "client-a",
		IP:      "10.77.0.2",
		PeerID:  "peer-a",
		Created: time.Unix(1, 0),
		// nil VisiblePeers normalizes to ["*"] => sees all.
	}
	b := store.ClientRecord{
		ID:           "B",
		Name:         "client-b",
		IP:           "10.77.0.3",
		PeerID:       "peer-b",
		Created:      time.Unix(1, 0),
		VisiblePeers: []string{"A"},
	}
	c := store.ClientRecord{
		ID:           "C",
		Name:         "client-c",
		IP:           "10.77.0.4",
		PeerID:       "peer-c",
		Created:      time.Unix(1, 0),
		VisiblePeers: []string{},
	}
	for _, rec := range []store.ClientRecord{a, b, c} {
		if err := st.CreateClient(rec); err != nil {
			t.Fatalf("create client %s: %v", rec.ID, err)
		}
	}

	p := newPolicySnapshot()
	if err := p.reload(st, serverIP); err != nil {
		t.Fatalf("reload: %v", err)
	}

	aIP := netip.MustParseAddr("10.77.0.2")
	bIP := netip.MustParseAddr("10.77.0.3")
	cIP := netip.MustParseAddr("10.77.0.4")
	unknownIP := netip.MustParseAddr("10.77.0.9")

	inner := &fakeTun{}
	ft := &filterTun{inner: inner, policy: p}

	bufs := [][]byte{
		makeIPv4(aIP, bIP),      // allowed
		makeIPv4(cIP, bIP),      // disallowed
		makeIPv4(bIP, serverIP), // allowed (hub)
		makeIPv4(unknownIP, bIP), // disallowed
	}

	n, err := ft.Write(bufs, 0)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(bufs) {
		t.Fatalf("Write returned n=%d, want %d", n, len(bufs))
	}

	if len(inner.writes) != 1 {
		t.Fatalf("inner.Write called %d times, want 1", len(inner.writes))
	}
	got := inner.writes[0]
	if len(got) != 2 {
		t.Fatalf("inner.Write received %d bufs, want 2: got %v", len(got), got)
	}

	if src, _ := ipv4Src(got[0]); src != aIP {
		t.Errorf("first passed packet src = %v, want %v", src, aIP)
	}
	if dst, _ := ipv4Dst(got[0]); dst != bIP {
		t.Errorf("first passed packet dst = %v, want %v", dst, bIP)
	}
	if src, _ := ipv4Src(got[1]); src != bIP {
		t.Errorf("second passed packet src = %v, want %v", src, bIP)
	}
	if dst, _ := ipv4Dst(got[1]); dst != serverIP {
		t.Errorf("second passed packet dst = %v, want %v", dst, serverIP)
	}
}
