package bind

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type stubTransport struct {
	recv chan []byte
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	sent [][]byte
}

func newStub() *stubTransport {
	return &stubTransport{recv: make(chan []byte, 8), done: make(chan struct{})}
}

func (s *stubTransport) Send(p []byte) error {
	s.mu.Lock()
	s.sent = append(s.sent, append([]byte(nil), p...))
	s.mu.Unlock()
	return nil
}

func (s *stubTransport) Recv() <-chan []byte   { return s.recv }
func (s *stubTransport) Done() <-chan struct{} { return s.done }
func (s *stubTransport) Close()                { s.once.Do(func() { close(s.done) }) }
func (s *stubTransport) Wait()                { s.Close() }

func (s *stubTransport) sentBufs() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

func ep(ip string) endpointID {
	a := netip.MustParseAddr(ip)
	return endpointID{netip.AddrPortFrom(a, EndpointPort)}
}

func TestAttachSendRoute(t *testing.T) {
	b := New()
	ea, eb := ep("10.77.0.2"), ep("10.77.0.3")
	sa, sb := newStub(), newStub()
	b.Attach(ea, sa)
	b.Attach(eb, sb)

	if err := b.Send([][]byte{[]byte("for-a")}, ea); err != nil {
		t.Fatalf("Send to a: %v", err)
	}
	if err := b.Send([][]byte{[]byte("for-b")}, eb); err != nil {
		t.Fatalf("Send to b: %v", err)
	}
	got := sa.sentBufs()
	if len(got) != 1 || string(got[0]) != "for-a" {
		t.Fatalf("stub a got %q, want [for-a]", got)
	}
	got = sb.sentBufs()
	if len(got) != 1 || string(got[0]) != "for-b" {
		t.Fatalf("stub b got %q, want [for-b]", got)
	}
}

func TestSendUnknownEndpointErrors(t *testing.T) {
	b := New()
	if err := b.Send([][]byte{[]byte("x")}, ep("10.77.0.9")); err == nil {
		t.Fatal("Send to unknown endpoint succeeded, want error")
	}
}

func TestDetachClosesCarrier(t *testing.T) {
	b := New()
	ea := ep("10.77.0.2")
	sa := newStub()
	b.Attach(ea, sa)
	b.Detach(ea)
	select {
	case <-sa.Done():
	case <-time.After(time.Second):
		t.Fatal("detach did not close the carrier")
	}
	if err := b.Send([][]byte{[]byte("x")}, ea); err == nil {
		t.Fatal("Send after detach succeeded, want error")
	}
}

func TestParseEndpointRoundTrip(t *testing.T) {
	b := New()
	got, err := b.ParseEndpoint("10.77.0.2:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if got.DstToString() != "10.77.0.2:51820" {
		t.Fatalf("DstToString = %q, want 10.77.0.2:51820", got.DstToString())
	}
}

func TestOpenReceiveDelivers(t *testing.T) {
	b := New()
	ea := ep("10.77.0.2")
	sa := newStub()
	b.Attach(ea, sa)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(fns) != 1 {
		t.Fatalf("Open returned %d funcs, want 1", len(fns))
	}
	sa.recv <- []byte("hello")
	p := make([][]byte, 1)
	p[0] = make([]byte, 128)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[0](p, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 {
		t.Fatalf("receive returned %d, want 1", n)
	}
	if string(p[0][:sizes[0]]) != "hello" {
		t.Fatalf("received %q, want hello", p[0][:sizes[0]])
	}
	if eps[0].DstToString() != "10.77.0.2:51820" {
		t.Fatalf("endpoint = %q, want 10.77.0.2:51820", eps[0].DstToString())
	}
}
