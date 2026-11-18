// Package bind adapts BitTorrent carriers to the AmneziaWG engine's conn.Bind
// contract: one Bind multiplexes many clients, routing outbound AWG datagrams
// to the carrier registered under the destination endpoint and merging every
// carrier's inbound datagrams into a single receive stream. Endpoints are
// overlay addresses (clientIP:51820); the real transport is the carrier.
package bind

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"

	"bittorrent-tunnel/btawg/internal/carrier"
)

// EndpointPort is the fixed overlay port every peer's IpcSet endpoint uses.
const EndpointPort = 51820

type endpointID struct{ addr netip.AddrPort }

func (e endpointID) ClearSrc()                          {}
func (e endpointID) SrcToString() string                 { return "" }
func (e endpointID) DstToString() string                 { return e.addr.String() }
func (e endpointID) DstToBytes() []byte                  { a := e.addr.Addr().As4(); b := make([]byte, 6); copy(b, a[:]); binary.BigEndian.PutUint16(b[4:], e.addr.Port()); return b }
func (e endpointID) DstIP() netip.Addr                   { return e.addr.Addr() }
func (e endpointID) SrcIP() netip.Addr                   { return netip.Addr{} }

type tagged struct {
	ep   endpointID
	data []byte
}

// Bind maps overlay endpoints to carriers.
type Bind struct {
	mu       sync.Mutex
	carriers map[endpointID]carrier.Transport
	closed   chan struct{}
	once     sync.Once
	inbox    chan tagged
}

// New returns an empty Bind with no carriers attached.
func New() *Bind {
	return &Bind{
		carriers: make(map[endpointID]carrier.Transport),
		inbox:    make(chan tagged, 512),
	}
}

// Attach maps ep to t and starts forwarding t's inbound datagrams. Attaching
// over an existing endpoint replaces (and closes) the previous carrier.
func (b *Bind) Attach(ep conn.Endpoint, t carrier.Transport) {
	e, ok := ep.(endpointID)
	if !ok {
		return
	}
	b.mu.Lock()
	old := b.carriers[e]
	b.carriers[e] = t
	closed := b.closed
	b.mu.Unlock()
	if old != nil {
		old.Close()
	}
	go func() {
		for {
			select {
			case d := <-t.Recv():
				select {
				case b.inbox <- tagged{e, d}:
				case <-t.Done():
					return
				case <-closed:
					return
				}
			case <-t.Done():
				return
			case <-closed:
				return
			}
		}
	}()
}

// Detach removes the carrier for ep and closes it.
func (b *Bind) Detach(ep conn.Endpoint) {
	e, ok := ep.(endpointID)
	if !ok {
		return
	}
	b.mu.Lock()
	t := b.carriers[e]
	delete(b.carriers, e)
	b.mu.Unlock()
	if t != nil {
		t.Close()
	}
}

// Open returns the single receive function draining all carriers.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.closed = make(chan struct{})
	fn := func(p [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case m := <-b.inbox:
			if len(m.data) > len(p[0]) {
				return 0, net.ErrClosed
			}
			sizes[0] = copy(p[0], m.data)
			eps[0] = m.ep
			return 1, nil
		case <-b.closed:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{fn}, port, nil
}

// Close tears down every attached carrier and unblocks the receive function.
func (b *Bind) Close() error {
	b.mu.Lock()
	if b.closed == nil {
		b.mu.Unlock()
		return nil
	}
	carriers := make([]carrier.Transport, 0, len(b.carriers))
	for _, t := range b.carriers {
		carriers = append(carriers, t)
	}
	b.carriers = make(map[endpointID]carrier.Transport)
	b.mu.Unlock()
	b.once.Do(func() {
		close(b.closed)
	})
	for _, t := range carriers {
		t.Close()
	}
	return nil
}

func (b *Bind) SetMark(mark uint32) error { return nil }

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	return endpointID{a}, nil
}

// BatchSize is 1: carriers deliver one datagram per call.
func (b *Bind) BatchSize() int { return 1 }

// Send routes each buffer to the carrier registered under ep.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(endpointID)
	if !ok {
		return fmt.Errorf("bind: unsupported endpoint type %T", ep)
	}
	b.mu.Lock()
	t := b.carriers[e]
	b.mu.Unlock()
	if t == nil {
		return fmt.Errorf("bind: no carrier for %s", e.DstToString())
	}
	for _, p := range bufs {
		if err := t.Send(p); err != nil {
			return err
		}
	}
	return nil
}

// Endpoint builds the overlay endpoint for a client IP.
func Endpoint(ip netip.Addr) conn.Endpoint {
	return endpointID{netip.AddrPortFrom(ip, EndpointPort)}
}
