package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/socks"
)

// Credentials is the common RFC 1929 credential pair.
type Credentials struct {
	Username string
	Password string
}

const ManagedPortBase = 1080

func (c Credentials) valid() bool {
	return len(c.Username) > 0 && len(c.Username) <= 255 && len(c.Password) > 0 && len(c.Password) <= 255
}

type managedSlot struct {
	ln     net.Listener
	proxy  *socks.Server
	ctx    context.Context
	cancel context.CancelFunc
}

// managed reserves every listener for its lifetime. A slot generation owns
// all sessions admitted under the same credentials and tunnel.
type managed struct {
	slots  []managedSlot
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func newManaged(ctx context.Context, listenIP netip.Addr, portBase int) (*managed, error) {
	m := &managed{}
	m.ctx, m.cancel = context.WithCancel(ctx)
	for i, mode := range config.ClientModes() {
		port := portBase + i
		if portBase == 0 {
			port = 0
		}
		ln, err := net.Listen("tcp4", netip.AddrPortFrom(listenIP, uint16(port)).String())
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("SOCKS5 %s port %d: %w", mode, port, err)
		}
		m.slots = append(m.slots, managedSlot{ln: ln})
	}
	for i := range m.slots {
		m.wg.Go(func() { m.acceptLoop(&m.slots[i]) })
	}
	return m, nil
}

func (m *managed) replace(i int, proxy *socks.Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &m.slots[i]
	if s.cancel != nil {
		s.cancel()
	}
	s.proxy = proxy
	if proxy != nil {
		s.ctx, s.cancel = context.WithCancel(m.ctx)
	} else {
		s.ctx, s.cancel = nil, nil
	}
}

func (m *managed) acceptLoop(s *managedSlot) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		proxy, ctx := s.proxy, s.ctx
		if m.closed || proxy == nil {
			m.mu.Unlock()
			c.Close()
			continue
		}
		m.wg.Go(func() { proxy.ServeConn(ctx, c) })
		m.mu.Unlock()
	}
}

func (m *managed) Close() {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	for i := range m.slots {
		m.slots[i].ln.Close()
	}
	m.mu.Unlock()
	m.wg.Wait()
}
