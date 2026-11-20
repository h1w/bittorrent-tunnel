package client

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"sync"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

// managedTunnel is one mode's live transport: its Client engine plus the
// background loop keeping that carrier (or native UDP device) alive.
type managedTunnel struct {
	mode string
	c    *Client
	stop context.CancelFunc
	done chan struct{}
}

// Managed is the concurrent VPN client: one transport tunnel per enabled
// mode, each feeding its own fixed-port SOCKS5 inbound, all sharing a single
// overlay identity. Modes start and stop live as the operator toggles them.
type Managed struct {
	inbound *managed
	cfg     config.ClientConfig
	realTUN bool
	tunBase string

	mu      sync.Mutex
	tunnels map[string]*managedTunnel
	closed  bool
}

// NewManaged binds the fixed SOCKS5 slots at ManagedPortBase and brings up the
// enabled modes. realTUN selects a kernel TUN per mode (tunBase names them);
// otherwise each mode runs in userspace netstack.
func NewManaged(ctx context.Context, cfg config.ClientConfig, enabled []string, listenIP netip.Addr, auth Credentials, realTUN bool, tunBase string) (*Managed, error) {
	return newManagedAt(ctx, cfg, enabled, listenIP, auth, realTUN, tunBase, ManagedPortBase)
}

func newManagedAt(ctx context.Context, cfg config.ClientConfig, enabled []string, listenIP netip.Addr, auth Credentials, realTUN bool, tunBase string, portBase int) (*Managed, error) {
	inbound, err := newManaged(ctx, cfg, listenIP, portBase)
	if err != nil {
		return nil, err
	}
	m := &Managed{
		inbound: inbound,
		cfg:     cfg,
		realTUN: realTUN,
		tunBase: tunBase,
		tunnels: make(map[string]*managedTunnel, len(enabled)),
	}
	if err := m.Apply(enabled, auth); err != nil {
		inbound.Close()
		return nil, err
	}
	return m, nil
}

// slot returns the SOCKS inbound for ClientModes index i.
func (M *Managed) slot(i int) *managedSlot { return M.inbound.slots[i] }

// Apply reconciles live tunnels with the enabled set and pushes the shared
// credential pair to the slots. Enabling builds and starts that mode's tunnel;
// disabling tears it down. Slot port reservation and session invalidation are
// handled by the slot layer.
func (M *Managed) Apply(enabled []string, auth Credentials) error {
	on := make(map[string]bool, len(enabled))
	for _, mode := range enabled {
		mode = config.CanonicalMode(mode)
		if !config.ValidClientMode(mode) {
			return fmt.Errorf("unsupported mode %q", mode)
		}
		on[mode] = true
	}

	M.mu.Lock()
	if M.closed {
		M.mu.Unlock()
		return fmt.Errorf("managed client closed")
	}
	var drop []*managedTunnel
	for mode, mt := range M.tunnels {
		if !on[mode] {
			drop = append(drop, mt)
			delete(M.tunnels, mode)
		}
	}
	M.mu.Unlock()
	for _, mt := range drop {
		mt.stop()
		<-mt.done
		mt.c.Close()
	}

	for mode := range on {
		if M.hasTunnel(mode) {
			continue
		}
		mt, err := M.buildTunnel(mode)
		if err != nil {
			return fmt.Errorf("start %s: %w", mode, err)
		}
		if !M.trackTunnel(mt) {
			mt.stop()
			<-mt.done
			mt.c.Close()
			return fmt.Errorf("managed client closed")
		}
	}

	names := make([]string, 0, len(on))
	for mode := range on {
		names = append(names, mode)
	}
	return M.inbound.Apply(names, auth)
}

// Credentials returns the current shared SOCKS5 credential pair.
func (M *Managed) Credentials() Credentials { return M.inbound.Credentials() }

func (M *Managed) hasTunnel(mode string) bool {
	M.mu.Lock()
	defer M.mu.Unlock()
	return M.tunnels[mode] != nil
}

func (M *Managed) trackTunnel(mt *managedTunnel) bool {
	M.mu.Lock()
	defer M.mu.Unlock()
	if M.closed {
		return false
	}
	M.tunnels[mt.mode] = mt
	return true
}

// buildTunnel constructs one mode's engine and starts keeping its data path
// alive. Its SOCKS upstream is the tunnel's per-mode proxy, wired to the slot.
func (M *Managed) buildTunnel(mode string) (*managedTunnel, error) {
	cfg := M.cfg
	cfg.Transport = mode

	var (
		c   *Client
		err error
	)
	if M.realTUN {
		tunName := M.tunBase + "-" + strconv.Itoa(modeIndex(mode))
		addr := netip.PrefixFrom(netip.MustParseAddr(cfg.ClientIP), 32)
		if err := tunsetup.Setup(tunName, addr, nil, config.DefaultMTU, false); err != nil {
			return nil, err
		}
		c, err = NewRealTUN(cfg, tunName)
	} else {
		c, err = New(cfg)
	}
	if err != nil {
		return nil, err
	}

	mt := &managedTunnel{mode: mode, c: c, done: make(chan struct{})}
	tctx, cancel := context.WithCancel(M.inbound.ctx)
	mt.stop = cancel
	go func() {
		defer close(mt.done)
		_ = c.runTunnel(tctx)
	}()

	M.inbound.SetProxy(mode, ModeProxy{TCP: c.proxyTCP, UDP: c.proxyUDP})
	return mt, nil
}

// Close tears down every mode and slot.
func (M *Managed) Close() error {
	M.mu.Lock()
	if M.closed {
		M.mu.Unlock()
		return nil
	}
	M.closed = true
	tunnels := make([]*managedTunnel, 0, len(M.tunnels))
	for mode, mt := range M.tunnels {
		tunnels = append(tunnels, mt)
		delete(M.tunnels, mode)
	}
	M.mu.Unlock()
	for _, mt := range tunnels {
		mt.stop()
	}
	for _, mt := range tunnels {
		<-mt.done
		mt.c.Close()
	}
	return M.inbound.Close()
}

func modeIndex(mode string) int {
	for i, m := range config.ClientModes() {
		if m == mode {
			return i
		}
	}
	return -1
}
