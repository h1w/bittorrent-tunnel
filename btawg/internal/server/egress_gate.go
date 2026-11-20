package server

import (
	"net"
	"net/netip"
	"sync"
)

// gatedListener wraps a net.Listener and enforces the hub routing policy on
// every accepted connection. Connections whose source address is not allowed
// internet egress are closed immediately and Accept retries. This is a
// fail-closed gate: if the source cannot be parsed or is unknown, the
// connection is dropped.
type gatedListener struct {
	inner          net.Listener
	policy         *policySnapshot
	mu             sync.Mutex
	active         map[*egressSession]netip.Addr
	requireGateway bool
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
		if g.requireGateway {
			dst, bound := addrIP(c.LocalAddr())
			if !bound || !g.policy.isGateway(dst) {
				_ = c.Close()
				continue
			}
		}
		g.mu.Lock()
		if !ok || !g.policy.internetFor(src) {
			g.mu.Unlock()
			_ = c.Close()
			continue
		}
		if g.active == nil {
			g.mu.Unlock()
			return c, nil
		}
		s := &egressSession{Conn: c, gate: g}
		g.active[s] = src
		g.mu.Unlock()
		return s, nil
	}
}

type egressSession struct {
	net.Conn
	gate *gatedListener
}

func (c *egressSession) Close() error {
	c.gate.mu.Lock()
	delete(c.gate.active, c)
	c.gate.mu.Unlock()
	return c.Conn.Close()
}

func (g *gatedListener) closeDenied() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for c, src := range g.active {
		if !g.policy.internetFor(src) {
			delete(g.active, c)
			_ = c.Conn.Close()
		}
	}
}

// Close delegates to the inner listener.
func (g *gatedListener) Close() error {
	err := g.inner.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	for c := range g.active {
		delete(g.active, c)
		_ = c.Conn.Close()
	}
	return err
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
