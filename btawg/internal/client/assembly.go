package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

type managedTunnel struct {
	c    *Client
	stop context.CancelFunc
	done chan struct{}
}

// Managed runs independent data paths with fixed SOCKS ports and one VPN IP.
type Managed struct {
	inbound *managed
	cfg     config.ClientConfig
	shared  *sharedTUN
	route   *tunsetup.ProxyRoute
	mu      sync.Mutex
	tunnels []*managedTunnel
	auth    Credentials
	closed  bool
}

func NewManaged(ctx context.Context, cfg config.ClientConfig, enabled []string, listenIP netip.Addr, auth Credentials, realTUN bool, tunBase string) (*Managed, error) {
	return newManagedAt(ctx, cfg, enabled, listenIP, auth, realTUN, tunBase, ManagedPortBase)
}

func newManagedAt(ctx context.Context, cfg config.ClientConfig, enabled []string, listenIP netip.Addr, auth Credentials, realTUN bool, tunBase string, portBase int) (*Managed, error) {
	inbound, err := newManaged(ctx, listenIP, portBase)
	if err != nil {
		return nil, err
	}
	m := &Managed{inbound: inbound, cfg: cfg, tunnels: make([]*managedTunnel, len(inbound.slots))}
	if realTUN {
		dev, err := openClientTUN(cfg, tunBase)
		if err != nil {
			inbound.Close()
			return nil, err
		}
		m.route, err = tunsetup.NewProxyRoute(tunBase)
		if err != nil {
			dev.Close()
			inbound.Close()
			return nil, err
		}
		m.shared = newSharedTUN(dev, tunBase, config.DefaultMTU)
	}
	if err := m.Apply(enabled, auth); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func (m *Managed) Apply(enabled []string, auth Credentials) error {
	return m.apply(enabled, auth, nil)
}

// Prepare every requested path before persisting or changing live listeners.
// A failed start/write leaves existing sessions and config unchanged.
func (m *Managed) apply(enabled []string, auth Credentials, save func() error) error {
	if !auth.valid() {
		return fmt.Errorf("invalid SOCKS5 credentials")
	}
	modes := config.ClientModes()
	for _, mode := range enabled {
		if !slices.Contains(modes, mode) {
			return fmt.Errorf("unsupported transport %q", mode)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("managed client closed")
	}
	pending := make([]*Client, len(modes))
	defer func() {
		for _, c := range pending {
			if c != nil {
				c.Close()
			}
		}
	}()
	for i, mode := range modes {
		if m.tunnels[i] != nil || !slices.Contains(enabled, mode) {
			continue
		}
		cfg := m.cfg
		cfg.Transport = mode
		var c *Client
		var err error
		if m.shared != nil {
			path := m.shared.newPath()
			c = &Client{cfg: cfg, path: path}
			path.proxySockets(c, netip.MustParseAddr(cfg.ClientIP))
			err = c.start(path)
		} else {
			c, err = New(cfg)
		}
		if err != nil {
			return fmt.Errorf("start %s: %w", mode, err)
		}
		pending[i] = c
	}
	if save != nil {
		if err := save(); err != nil {
			return err
		}
	}
	if m.shared != nil {
		var primary *tunPath
		for i, mode := range modes {
			if slices.Contains(enabled, mode) {
				if c := pending[i]; c != nil {
					primary = c.path
				} else {
					primary = m.tunnels[i].c.path
				}
				break
			}
		}
		m.shared.primary.Store(primary)
	}
	rotated := m.auth != auth
	for i, mode := range modes {
		if !slices.Contains(enabled, mode) {
			if t := m.tunnels[i]; t != nil {
				m.inbound.replace(i, nil)
				t.close()
				m.tunnels[i] = nil
			}
			continue
		}
		if c := pending[i]; c != nil {
			pending[i] = nil
			m.tunnels[i] = startManagedTunnel(m.inbound.ctx, c, mode)
		} else if !rotated {
			continue
		}
		m.inbound.replace(i, m.tunnels[i].c.localProxy().WithCredentials(auth.Username, auth.Password))
	}
	m.auth = auth
	return nil
}

func startManagedTunnel(parent context.Context, c *Client, mode string) *managedTunnel {
	ctx, stop := context.WithCancel(parent)
	t := &managedTunnel{c: c, stop: stop, done: make(chan struct{})}
	go func() {
		defer close(t.done)
		for ctx.Err() == nil {
			err := c.runTunnel(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil || c.ip != nil && c.ip.life.Err() != nil {
				log.Printf("btawg-client: %s tunnel stopped: %v", mode, err)
				return
			}
			log.Printf("btawg-client: %s: %v", mode, err)
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return t
}

func (t *managedTunnel) close() { t.stop(); <-t.done; t.c.Close() }

func (m *Managed) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if m.shared != nil {
		m.shared.primary.Store(nil)
	}
	m.inbound.Close()
	for _, t := range m.tunnels {
		if t != nil {
			t.close()
		}
	}
	if m.shared != nil {
		return errors.Join(m.route.Close(), m.shared.close())
	}
	return nil
}
