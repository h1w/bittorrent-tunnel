package server

import (
	"net"
	"net/netip"
)

// gatedListener wraps a net.Listener and enforces the hub routing policy on
// every accepted connection. Connections whose source address is not allowed
// internet egress are closed immediately and Accept retries. This is a
// fail-closed gate: if the source cannot be parsed or is unknown, the
// connection is dropped.
type gatedListener struct {
	inner  net.Listener
	policy *policySnapshot
}

// Accept returns the next connection whose source is allowed to use internet
// egress. Disallowed connections are closed and skipped.
func (g *gatedListener) Accept() (net.Conn, error) {
	for {
		c, err := g.inner.Accept()
		if err != nil {
			return nil, err
		}

		src, ok := addrIP(c.RemoteAddr())
		if !ok || !g.policy.internetFor(src) {
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// Close delegates to the inner listener.
func (g *gatedListener) Close() error {
	return g.inner.Close()
}

// Addr delegates to the inner listener.
func (g *gatedListener) Addr() net.Addr {
	return g.inner.Addr()
}

// addrIP extracts the IP address from a net.Addr. It understands the standard
// TCP and UDP address types used by netstack and the Go net package.
func addrIP(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap(), true
		}
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap(), true
		}
	case interface{ Addr() netip.Addr }:
		return v.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}
