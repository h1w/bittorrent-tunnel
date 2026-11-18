package server

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"golang.org/x/net/ipv4"
)

// forwardingTun wraps the netstack TUN and re-injects packets addressed to
// other overlay clients into the device's outbound path, exactly as kernel
// WireGuard does with ip_forward: the device then re-encrypts them to the
// peer whose allowed_ip matches the destination. Packets addressed to the hub
// itself pass through to the netstack normally.
type forwardingTun struct {
	inner   tun.Device
	local   netip.Addr
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
}

func newForwardingTun(inner tun.Device, local netip.Addr) *forwardingTun {
	f := &forwardingTun{
		inner:   inner,
		local:   local,
		packets: make(chan []byte, 256),
		closed:  make(chan struct{}),
	}
	go f.pumpInner()
	return f
}

// pumpInner moves netstack-originated packets into the merged queue.
func (f *forwardingTun) pumpInner() {
	buf := make([]byte, 65536)
	bufs := [][]byte{buf}
	sizes := make([]int, 1)
	for {
		n, err := f.inner.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if n < 1 {
			continue
		}
		p := make([]byte, sizes[0])
		copy(p, buf[:sizes[0]])
		select {
		case f.packets <- p:
		case <-f.closed:
			return
		}
	}
}

// Read returns one packet: either a netstack-originated outbound packet or a
// re-injected forwarding packet. The device re-encrypts both to the peer
// whose allowed_ip matches the destination.
func (f *forwardingTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-f.packets:
		if len(p) > len(bufs[0])-offset {
			return 0, errShortBuffer
		}
		copy(bufs[0][offset:], p)
		sizes[0] = len(p)
		return 1, nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

// Write receives decrypted packets from the device: hub-destined traffic goes
// to the netstack, everything else is re-injected for peer-to-peer routing.
func (f *forwardingTun) Write(bufs [][]byte, offset int) (int, error) {
	var local [][]byte
	for _, b := range bufs {
		packet := b[offset:]
		if dst, ok := ipv4Dst(packet); ok && dst == f.local {
			local = append(local, b)
			continue
		}
		p := make([]byte, len(packet))
		copy(p, packet)
		select {
		case f.packets <- p:
		case <-f.closed:
			return 0, net.ErrClosed
		default:
			// Queue full: drop rather than block the device's receive loop.
		}
	}
	if len(local) == 0 {
		return len(bufs), nil
	}
	if _, err := f.inner.Write(local, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func (f *forwardingTun) MTU() (int, error)          { return f.inner.MTU() }
func (f *forwardingTun) Name() (string, error)     { return f.inner.Name() }
func (f *forwardingTun) Events() <-chan tun.Event   { return f.inner.Events() }
func (f *forwardingTun) File() *os.File             { return f.inner.File() }
func (f *forwardingTun) BatchSize() int            { return 1 }
func (f *forwardingTun) Close() error {
	f.once.Do(func() { close(f.closed) })
	return f.inner.Close()
}

// ipv4Dst extracts the destination of an IPv4 packet.
func ipv4Dst(p []byte) (netip.Addr, bool) {
	if len(p) < ipv4.HeaderLen {
		return netip.Addr{}, false
	}
	if p[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	copy(b[:], p[16:20])
	_ = binary.BigEndian.Uint16(p[2:4])
	return netip.AddrFrom4(b), true
}

type shortBufferError struct{}

func (shortBufferError) Error() string { return "short buffer" }

var errShortBuffer error = shortBufferError{}
