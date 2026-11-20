package bind

import (
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"

	"bittorrent-tunnel/btawg/internal/carrier"
)

// Hybrid combines the direct UDP and stream paths of one AWG device. Its
// endpoint type identifies the path; the AWG engine authenticates roaming.
type Hybrid struct {
	streams *Bind
	udp     conn.Bind
	next    atomic.Uint64
}

func NewHybrid() *Hybrid { return &Hybrid{streams: New(), udp: conn.NewDefaultBind()} }

func (h *Hybrid) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fs, p, err := h.udp.Open(port)
	if err != nil {
		return nil, 0, err
	}
	ss, _, err := h.streams.Open(0)
	if err != nil {
		_ = h.udp.Close()
		return nil, 0, err
	}
	return append(fs, ss...), p, nil
}

func (h *Hybrid) Close() error                                  { return errors.Join(h.streams.Close(), h.udp.Close()) }
func (h *Hybrid) SetMark(mark uint32) error                     { return h.udp.SetMark(mark) }
func (h *Hybrid) BatchSize() int                                { return max(h.udp.BatchSize(), h.streams.BatchSize()) }
func (h *Hybrid) ParseEndpoint(s string) (conn.Endpoint, error) { return h.udp.ParseEndpoint(s) }
func (h *Hybrid) Send(bufs [][]byte, ep conn.Endpoint) error {
	if _, ok := ep.(endpointID); ok {
		return h.streams.Send(bufs, ep)
	}
	return h.udp.Send(bufs, ep)
}

// AddCarrier returns an endpoint unique to the connection. Closing it cannot
// delete a replacement or change an authenticated peer's current route.
func (h *Hybrid) AddCarrier(ip netip.Addr, t carrier.Transport) func() {
	e := endpointID{addr: netip.AddrPortFrom(ip, EndpointPort), session: h.next.Add(1)}
	h.streams.Attach(e, t)
	return func() { h.streams.Detach(e) }
}

var _ conn.Bind = (*Hybrid)(nil)
