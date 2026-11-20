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

// Credentials is the single SOCKS5 username/password pair shared by every
// managed inbound. It is generated at install and rotated from the TUI.
type Credentials struct {
	Username string
	Password string
}

// ManagedPortBase is the first local SOCKS5 port. config.ClientModes() order
// maps to portBase+index, so 1080..1089 stay fixed across toggles and restarts.
const ManagedPortBase = 1080

// ManagedPorts returns the fixed SOCKS5 listen port for each ClientModes index.
func ManagedPorts() []int {
	modes := config.ClientModes()
	ports := make([]int, len(modes))
	for i := range ports {
		ports[i] = ManagedPortBase + i
	}
	return ports
}

// ModeProxy is one transport's upstream: TCP CONNECT and UDP datagrams,
// both routed through that mode's tunnel.
type ModeProxy struct {
	TCP func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	UDP func(ctx context.Context) (net.PacketConn, error)
}

// managedSlot owns one fixed-port SOCKS5 inbound. The listener stays bound
// whether or not the mode is enabled so the port is never reassigned; a
// disabled slot closes every accepted connection instead of proxying it.
type managedSlot struct {
	index int
	mode  string
	port  int
	ln    net.Listener

	mu       sync.Mutex
	enabled  bool
	sessions map[net.Conn]context.CancelFunc
}

// managed runs the client's SOCKS5 inbounds, one per connection mode, sharing
// a single credential pair and one overlay identity across all of them.
type managed struct {
	cfg     config.ClientConfig
	slots   []*managedSlot
	proxies map[string]ModeProxy

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	auth   Credentials
	closed bool
	wg     sync.WaitGroup
}

// newManaged binds every managed SOCKS5 port on listenIP at portBase..portBase+n-1
// and starts their accept loops. It creates no tunnel: attach each mode's
// dialer with SetDialer before that mode can carry traffic.
func newManaged(ctx context.Context, cfg config.ClientConfig, listenIP netip.Addr, portBase int) (*managed, error) {
	modes := config.ClientModes()
	mctx, cancel := context.WithCancel(ctx)
	m := &managed{
		cfg:     cfg,
		proxies: make(map[string]ModeProxy, len(modes)),
		ctx:     mctx,
		cancel:  cancel,
	}
	for i, mode := range modes {
		s := &managedSlot{
			index:    i,
			mode:     mode,
			port:     portBase + i,
			sessions: make(map[net.Conn]context.CancelFunc),
		}
		ln, err := net.Listen("tcp4", netip.AddrPortFrom(listenIP, uint16(s.port)).String())
		if err != nil {
			cancel()
			m.Close()
			return nil, fmt.Errorf("socks %s listen %d: %w", mode, s.port, err)
		}
		s.ln = ln
		m.slots = append(m.slots, s)
	}
	for _, s := range m.slots {
		m.wg.Add(1)
		go m.acceptLoop(s)
	}
	return m, nil
}

// SetProxy attaches the upstream tunnel proxy for one mode.
func (m *managed) SetProxy(mode string, p ModeProxy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxies[mode] = p
}

// Apply enables the listed modes and installs the shared credential pair. A
// credential change invalidates every live session; disabling a mode closes
// only that mode's sessions. Fixed listeners are never released.
func (m *managed) Apply(enabled []string, auth Credentials) error {
	on := make(map[string]bool, len(enabled))
	for _, mode := range enabled {
		mode = config.CanonicalMode(mode)
		if !config.ValidClientMode(mode) {
			return fmt.Errorf("unsupported mode %q", mode)
		}
		on[mode] = true
	}

	m.mu.Lock()
	rotate := m.auth != auth
	m.auth = auth
	m.mu.Unlock()

	for _, s := range m.slots {
		enable := on[s.mode]
		s.mu.Lock()
		was := s.enabled
		s.enabled = enable
		var stops []context.CancelFunc
		if rotate || (was && !enable) {
			for c, stop := range s.sessions {
				stops = append(stops, stop)
				delete(s.sessions, c)
			}
		}
		s.mu.Unlock()
		for _, stop := range stops {
			stop()
		}
	}
	return nil
}

// Credentials returns the current shared SOCKS5 credential pair.
func (m *managed) Credentials() Credentials {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.auth
}

// acceptLoop keeps the fixed listener bound for the daemon's lifetime and
// serves only enabled slots.
func (m *managed) acceptLoop(s *managedSlot) {
	defer m.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		enabled := s.enabled
		s.mu.Unlock()
		if !enabled {
			c.Close()
			continue
		}
		if !m.track(s, c) {
			c.Close()
			return
		}
	}
}

// track registers a session and spawns its handler. It reports false when the
// managed client is already closing, so no goroutine is started after Close
// begins waiting.
func (m *managed) track(s *managedSlot, c net.Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	sctx, cancel := context.WithCancel(m.ctx)
	s.mu.Lock()
	s.sessions[c] = cancel
	s.mu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.sessions, c)
			s.mu.Unlock()
		}()
		m.serve(sctx, s, c)
	}()
	return true
}

// serve runs one authenticated SOCKS5 session against the mode's tunnel.
func (m *managed) serve(ctx context.Context, s *managedSlot, c net.Conn) {
	m.mu.Lock()
	auth, proxy := m.auth, m.proxies[s.mode]
	m.mu.Unlock()
	if proxy.TCP == nil {
		c.Close()
		return
	}
	srv := socks.NewServer(func(ctx context.Context, _, addr string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		return proxy.TCP(ctx, ap)
	}, proxy.UDP).WithCredentials(auth.Username, auth.Password)
	srv.ServeConn(ctx, c)
}

// Close tears down every listener and session. It does not touch tunnel state
// owned by the wider client.
func (m *managed) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	m.cancel()
	for _, s := range m.slots {
		s.mu.Lock()
		s.enabled = false
		s.ln.Close()
		var stops []context.CancelFunc
		for c, stop := range s.sessions {
			stops = append(stops, stop)
			delete(s.sessions, c)
		}
		s.mu.Unlock()
		for _, stop := range stops {
			stop()
		}
	}
	m.wg.Wait()
	return nil
}
