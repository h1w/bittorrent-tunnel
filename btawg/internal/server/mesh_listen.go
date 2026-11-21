package server

import (
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Userspace gateways are immutable for the lifetime of a hub. The kernel
// listener instead binds the TUN and follows gateway changes automatically.
func listenMeshGateways(ns *netstack.Net, gateways []netip.Addr, port uint16) (net.Listener, error) {
	var listeners []net.Listener
	for _, ip := range gateways {
		ln, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(ip, port))
		if err != nil {
			for _, prior := range listeners {
				prior.Close()
			}
			return nil, err
		}
		listeners = append(listeners, ln)
	}
	if len(listeners) == 0 {
		return nil, net.ErrClosed
	}
	if len(listeners) == 1 {
		return listeners[0], nil
	}
	m := &meshListeners{listeners: listeners, done: make(chan struct{}), accepted: make(chan net.Conn)}
	for _, ln := range listeners {
		m.wg.Go(func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					m.shutdown()
					return
				}
				select {
				case m.accepted <- c:
				case <-m.done:
					c.Close()
					return
				}
			}
		})
	}
	return m, nil
}

type meshListeners struct {
	listeners []net.Listener
	done      chan struct{}
	accepted  chan net.Conn
	once      sync.Once
	wg        sync.WaitGroup
}

func (m *meshListeners) Accept() (net.Conn, error) {
	select {
	case c := <-m.accepted:
		return c, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}
func (m *meshListeners) shutdown() {
	m.once.Do(func() {
		close(m.done)
		for _, l := range m.listeners {
			l.Close()
		}
	})
}
func (m *meshListeners) Close() error   { m.shutdown(); m.wg.Wait(); return nil }
func (m *meshListeners) Addr() net.Addr { return m.listeners[0].Addr() }
