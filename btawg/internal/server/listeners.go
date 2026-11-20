package server

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

// gatewayListeners joins the address-specific listeners of the userspace VPN.
// Real TUN uses one listener bound to the VPN interface instead.
type gatewayListeners struct {
	listeners []net.Listener
	results   chan acceptedConn
	closed    chan struct{}
	once      sync.Once
}

type acceptedConn struct {
	conn net.Conn
	err  error
}

func (s *Server) netstackEgress() (net.Listener, error) {
	m := &gatewayListeners{results: make(chan acceptedConn), closed: make(chan struct{})}
	for _, g := range s.gateways {
		ln, err := s.ns.ListenTCPAddrPort(netip.AddrPortFrom(g.Addr(), uint16(s.cfg.SocksPort)))
		if err != nil {
			_ = m.Close()
			return nil, err
		}
		m.listeners = append(m.listeners, ln)
	}
	for _, ln := range m.listeners {
		go m.accept(ln)
	}
	return m, nil
}

func (m *gatewayListeners) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		select {
		case m.results <- acceptedConn{c, err}:
		case <-m.closed:
			if c != nil {
				_ = c.Close()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func (m *gatewayListeners) Accept() (net.Conn, error) {
	select {
	case a := <-m.results:
		return a.conn, a.err
	case <-m.closed:
		return nil, net.ErrClosed
	}
}
func (m *gatewayListeners) Addr() net.Addr { return m.listeners[0].Addr() }
func (m *gatewayListeners) Close() error {
	var err error
	m.once.Do(func() {
		close(m.closed)
		for _, ln := range m.listeners {
			err = errors.Join(err, ln.Close())
		}
	})
	return err
}
