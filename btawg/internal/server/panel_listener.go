package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"

	"bittorrent-tunnel/btawg/internal/store"

	"bittorrent-tunnel/btawg/internal/tunsetup"
)

// panelListeners is protected by Server.applyMu. The same HTTP server serves
// both sockets so a gateway change does not reset the panel's session state.
type panelListeners struct {
	ctx      context.Context
	web      *http.Server
	errs     chan error
	loopback net.Listener
	vpn      net.Listener
	addr     netip.AddrPort
}

// StartPanel serves the panel on loopback and the configured default-group
// gateway. The VPN socket follows group edits; it is never a wildcard bind.
func (s *Server) StartPanel(ctx context.Context, port int, web *http.Server) (<-chan error, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	select {
	case <-s.closed:
		return nil, net.ErrClosed
	default:
	}
	if s.panel != nil {
		return nil, errors.New("panel already started")
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid panel port %d", port)
	}
	group, err := s.st.GetGroup(store.DefaultGroupID)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{}
	loopback, err := lc.Listen(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("panel loopback: %w", err)
	}
	p := &panelListeners{ctx: ctx, web: web, errs: make(chan error, 1), loopback: loopback}
	s.panel = p
	if err := s.rebindPanel(netip.MustParseAddr(group.ServerIP)); err != nil {
		s.panel = nil
		loopback.Close()
		return nil, err
	}
	p.serve(loopback)
	return p.errs, nil
}

func (s *Server) rebindPanel(gateway netip.Addr) error {
	p := s.panel
	if p == nil {
		return nil
	}
	addr := netip.AddrPortFrom(gateway, p.loopback.Addr().(*net.TCPAddr).AddrPort().Port())
	if addr == p.addr {
		return nil
	}
	if err := p.ctx.Err(); err != nil {
		return err
	}
	var ln net.Listener
	var err error
	if s.ns != nil {
		ln, err = s.ns.ListenTCPAddrPort(addr)
	} else {
		lc := net.ListenConfig{Control: tunsetup.BindDevice(s.tunName)}
		ln, err = lc.Listen(p.ctx, "tcp4", addr.String())
	}
	if err != nil {
		return fmt.Errorf("panel gateway %s: %w", addr, err)
	}
	if p.vpn != nil {
		p.vpn.Close()
	}
	p.vpn, p.addr = ln, addr
	p.serve(ln)
	return nil
}

func (p *panelListeners) serve(ln net.Listener) {
	log.Printf("btawg-server: panel on http://%s", ln.Addr())
	go func() {
		if err := p.web.Serve(ln); !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			select {
			case p.errs <- err:
			default:
			}
		}
	}()
}

func (s *Server) closePanel() {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if p := s.panel; p != nil {
		p.loopback.Close()
		p.vpn.Close()
		s.panel = nil
	}
}
