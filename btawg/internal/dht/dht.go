// Package dht implements btawg's strictly-DHT discovery: the server announces
// its carrier address under a per-deployment infohash in the BitTorrent DHT
// (BEP 5), and clients bootstrap from well-known routers and get_peers the
// infohash to learn the server's current address. DHT is never a data relay.
package dht

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	anadht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/krpc"
	"github.com/anacrolix/torrent/metainfo"
)

// memPeerStore is a correct in-memory peer_store.Interface. The upstream
// peer_store.InMemory keys entries by raw IP bytes but reads them back with
// NodeAddr.UnmarshalBinary, which expects IP+port bytes: the stored peer
// 127.0.0.1:45001 comes back as a two-byte IP with port 1 and is then
// dropped by get_peers filtering. btawg cannot use it, because the
// announcer's own node is a legitimate discovery target in small
// deployments.
type memPeerStore struct {
	mu sync.Mutex
	m  map[metainfo.Hash]map[string]krpc.NodeAddr
}

func (s *memPeerStore) AddPeer(ih metainfo.Hash, na krpc.NodeAddr) {
	b, err := na.MarshalBinary()
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[metainfo.Hash]map[string]krpc.NodeAddr)
	}
	if s.m[ih] == nil {
		s.m[ih] = make(map[string]krpc.NodeAddr)
	}
	s.m[ih][string(b)] = na
}

func (s *memPeerStore) GetPeers(ih metainfo.Hash) []krpc.NodeAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []krpc.NodeAddr
	for _, na := range s.m[ih] {
		out = append(out, na)
	}
	return out
}

// DefaultBootstrap is the well-known public DHT bootstrap baked into the
// client. The config string may override it.
var DefaultBootstrap = []string{
	"router.bittorrent.com:6881",
	"router.utorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"dht.libtorrent.org:25401",
}

const (
	// announceInterval re-announces before DHT peer entries expire.
	announceInterval = 15 * time.Minute
	// discoverTimeout bounds Discover when the caller sets no deadline.
	discoverTimeout = 30 * time.Second
)

// Announcer runs a DHT node that announces the carrier port under infoHash.
// The announced IP is always the source address the DHT observes; a NAT'd
// server must forward its carrier port.
type Announcer struct {
	srv      *anadht.Server
	infoHash [20]byte
	port     int

	mu        sync.Mutex
	bootstrap []string
}

// NewAnnouncer creates the DHT node. bootstrap may be nil for the public
// default list; it can be replaced later with SetBootstrap.
func NewAnnouncer(infoHash [20]byte, announceAddr netip.AddrPort, bootstrap []string) (*Announcer, error) {
	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("dht listen: %w", err)
	}
	a := &Announcer{
		infoHash:  infoHash,
		port:      int(announceAddr.Port()),
		bootstrap: append([]string(nil), bootstrap...),
	}
	if len(a.bootstrap) == 0 {
		a.bootstrap = append([]string(nil), DefaultBootstrap...)
	}
	srv, err := anadht.NewServer(&anadht.ServerConfig{
		Conn:        pc,
		NoSecurity:  true,
		PeerStore:   &memPeerStore{},
		StartingNodes: a.startingNodes,
	})
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("dht server: %w", err)
	}
	a.srv = srv
	return a, nil
}

// Addr is the announcer's DHT socket address (its own bootstrap entry in
// single-node deployments; shown in the panel otherwise).
func (a *Announcer) Addr() netip.AddrPort {
	return addrPortOf(a.srv.Addr())
}

// SetBootstrap replaces the bootstrap node list; the next announce uses it.
func (a *Announcer) SetBootstrap(hosts []string) {
	a.mu.Lock()
	a.bootstrap = append([]string(nil), hosts...)
	a.mu.Unlock()
}

func (a *Announcer) startingNodes() ([]anadht.Addr, error) {
	a.mu.Lock()
	hosts := append([]string(nil), a.bootstrap...)
	a.mu.Unlock()
	var addrs []anadht.Addr
	for _, h := range hosts {
		ua, err := net.ResolveUDPAddr("udp4", h)
		if err != nil {
			continue
		}
		addrs = append(addrs, anadht.NewAddr(ua))
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no reachable bootstrap nodes")
	}
	return addrs, nil
}

// Run announces once immediately and then on every interval tick.
func (a *Announcer) Run(ctx context.Context) error {
	if err := a.AnnounceOnce(ctx); err != nil {
		return err
	}
	t := time.NewTicker(announceInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := a.AnnounceOnce(ctx); err != nil {
				return err
			}
		}
	}
}

// AnnounceOnce drives one announce traversal: get_peers toward the closest
// nodes, then announce_peer of the carrier port to each.
func (a *Announcer) AnnounceOnce(ctx context.Context) error {
	ann, err := a.srv.Announce(a.infoHash, a.port, false)
	if err != nil {
		return fmt.Errorf("dht announce: %w", err)
	}
	defer ann.Close()
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ann.Peers:
			if !ok {
				return nil
			}
		}
	}
}

// Close stops the DHT node.
func (a *Announcer) Close() { a.srv.Close() }

// Discover returns the peers announced for infoHash, or an explicit error if
// the bounded discovery finds nothing.
func Discover(ctx context.Context, infoHash [20]byte, bootstrap []string) ([]netip.AddrPort, error) {
	if len(bootstrap) == 0 {
		bootstrap = DefaultBootstrap
	}
	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("dht listen: %w", err)
	}
	defer pc.Close()
	srv, err := anadht.NewServer(&anadht.ServerConfig{
		Conn:         pc,
		NoSecurity:   true,
		StartingNodes: bootstrapGetter(bootstrap),
	})
	if err != nil {
		return nil, fmt.Errorf("dht server: %w", err)
	}
	defer srv.Close()
	if _, err := srv.BootstrapContext(ctx); err != nil {
		return nil, fmt.Errorf("dht bootstrap: %w", err)
	}
	ann, err := srv.AnnounceTraversal(infoHash)
	if err != nil {
		return nil, fmt.Errorf("dht traversal: %w", err)
	}
	defer ann.Close()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, discoverTimeout)
		defer cancel()
	}
	var out []netip.AddrPort
	seen := make(map[netip.AddrPort]bool)
	for {
		select {
		case <-ctx.Done():
			if len(out) > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("dht discovery timed out: no peers for infohash %x", infoHash)
		case pv, ok := <-ann.Peers:
			if !ok {
				if len(out) > 0 {
					return out, nil
				}
				return nil, fmt.Errorf("dht traversal finished: no peers for infohash %x", infoHash)
			}
			for _, p := range pv.Peers {
				if ap, ok := nodeAddrPort(p); ok && !seen[ap] {
					seen[ap] = true
					out = append(out, ap)
				}
			}
		}
	}
}

func bootstrapGetter(hosts []string) anadht.StartingNodesGetter {
	return func() ([]anadht.Addr, error) {
		var addrs []anadht.Addr
		for _, h := range hosts {
			ua, err := net.ResolveUDPAddr("udp4", h)
			if err != nil {
				continue
			}
			addrs = append(addrs, anadht.NewAddr(ua))
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no reachable bootstrap nodes")
		}
		return addrs, nil
	}
}

func nodeAddrPort(na krpc.NodeAddr) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(na.IP)
	if !ok || !ip.IsValid() || !ip.Is4() || na.Port <= 0 || na.Port > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(na.Port)), true
}

func addrPortOf(netAddr net.Addr) netip.AddrPort {
	ap, err := netip.ParseAddrPort(netAddr.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}

// NewMemStore returns a correct in-memory DHT peer store, for tests that
// stand up bare relay nodes.
func NewMemStore() *memPeerStore { return &memPeerStore{} }
