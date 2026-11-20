// Package server assembles the btawg hub: the AmneziaWG device over a
// netstack overlay with peer-to-peer forwarding, the BitTorrent carrier
// listener (µTP or TCP per transport), the egress SOCKS5 reachable only inside
// the tunnel, and the DHT announcer. The web panel (separate package) drives
// the same store this server loads.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	utp "github.com/anacrolix/go-utp"
	"golang.org/x/sys/unix"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/dht"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/store"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

// serverPeerID is the fixed BitTorrent peer ID this hub presents in every
// carrier handshake; clients identify the deployment by infohash, not peer ID.
var serverPeerID = [20]byte{'b', 't', 'a', 'w', 'g', '-', 's', 'e', 'r', 'v', 'e', 'r', '-', 'n', 'o', 'd', 'e', '0', '0', '1'}

// Server is the assembled btawg hub.
type Server struct {
	cfg      config.ServerConfig
	st       *store.Store
	infoHash [20]byte
	pubKey   string

	bd      *bind.Hybrid
	dev, wg *device.Device
	ns      *netstack.Net
	router  *packetRouter
	kernel  *tunsetup.Hub
	tunName string

	mu           sync.Mutex
	applyMu      sync.Mutex
	closeOnce    sync.Once
	closeErr     error
	trafficWG    sync.WaitGroup
	savedTraffic map[string]store.Traffic
	hashes       map[[20]byte]string
	peers        map[string]store.ClientRecord
	sessions     map[string]map[carrier.Transport]struct{}
	gateways     []netip.Prefix
	byPeerID     map[string]store.ClientRecord
	attached     map[string]int // client IP -> carrier count

	policy *policySnapshot

	udpPC      net.PacketConn
	sock       utp.Socket
	tcpLn      net.Listener
	anns       []*dht.Announcer
	egressLn   net.Listener
	egressGate *gatedListener
	closed     chan struct{}
}

// New loads (or generates at first boot) the server identity, builds the AWG
// hub with one peer per stored client, the carrier listener and the egress
// SOCKS5 in userspace netstack mode. Call Run to serve; call Announce to
// publish via DHT.
func New(cfg config.ServerConfig, st *store.Store) (*Server, error) {
	return newServer(cfg, st, "")
}

// NewRealTUN shares one kernel interface across all transports.
func NewRealTUN(cfg config.ServerConfig, st *store.Store, tunName string) (*Server, error) {
	return newServer(cfg, st, tunName)
}

func newServer(cfg config.ServerConfig, st *store.Store, tunName string) (*Server, error) {
	s, err := prepareServer(cfg, st)
	if err != nil {
		return nil, err
	}
	gateways, err := groupGateways(st)
	s.tunName = tunName
	if err != nil {
		return nil, err
	}
	s.gateways = gateways
	var td tun.Device
	if tunName == "" {
		addresses := make([]netip.Addr, len(gateways))
		for i, p := range gateways {
			addresses[i] = p.Addr()
		}
		td, s.ns, err = netstack.CreateNetTUN(addresses, nil, 1420)
	} else {
		td, err = tun.CreateTUN(tunName, 1420)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun %q: %w", tunName, err)
	}
	s.router = newPacketRouter(td, tunName != "", s.policy)
	if tunName != "" {
		// Set link state before installing scoped routes and NAT.
		if err = tunsetup.Setup(tunName, gateways[0], nil, 1420, false); err == nil {
			s.kernel, err = tunsetup.NewHub(tunName)
		}
		if err == nil {
			err = s.kernel.Apply(gateways)
		}
	}
	if err == nil {
		err = s.finish()
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	s.trafficWG.Go(s.refreshHandshakeRoutes)
	return s, nil
}

func groupGateways(st *store.Store) ([]netip.Prefix, error) {
	groups, err := st.ListGroups()
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no VPN groups")
	}
	out := make([]netip.Prefix, 0, len(groups))
	for _, g := range groups {
		out = append(out, netip.PrefixFrom(netip.MustParseAddr(g.ServerIP), netip.MustParsePrefix(g.Subnet).Bits()))
	}
	return out, nil
}

// prepareServer loads (or generates) the hub identity, policy snapshot, and
// peer configuration shared by New and NewRealTUN.
func prepareServer(cfg config.ServerConfig, st *store.Store) (*Server, error) {
	stored, err := st.LoadServerConfig()
	if err != nil {
		return nil, err
	}
	if cfg.LegacyTransport == "" {
		cfg.LegacyTransport = stored.LegacyTransport
		if cfg.LegacyTransport == "" {
			cfg.LegacyTransport = cfg.Transport
			if stored.InfoHash != "" {
				cfg.LegacyTransport = stored.Transport
			}
		}
	}
	cfg.Normalize()
	for _, p := range []int{cfg.CarrierPort, cfg.AWGPort, cfg.WGPort, cfg.SocksPort} {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %d", p)
		}
	}
	if cfg.WGPort == cfg.AWGPort || cfg.WGPort == cfg.CarrierPort || cfg.AWGPort == cfg.CarrierPort {
		return nil, fmt.Errorf("carrier, AWG and WG UDP ports must differ")
	}
	if cfg.ExternalIP == "" {
		if c, err := net.Dial("udp4", "1.1.1.1:53"); err == nil {
			cfg.ExternalIP = c.LocalAddr().(*net.UDPAddr).IP.String()
			_ = c.Close()
		}
	}
	if cfg.ExternalIP != "" {
		ip, err := netip.ParseAddr(cfg.ExternalIP)
		if err != nil || !ip.Is4() || ip.IsUnspecified() {
			return nil, fmt.Errorf("invalid external IPv4 address %q", cfg.ExternalIP)
		}
	}
	// The argument is the working configuration (main loads it from the
	// store, applying any CLI overrides). At first boot the deployment
	// identity is generated, persisted, and reused from then on.
	if cfg.InfoHash == "" || cfg.ServerPrivKey == "" {
		var ih [20]byte
		if _, err := rand.Read(ih[:]); err != nil {
			return nil, fmt.Errorf("generate infohash: %w", err)
		}
		cfg.InfoHash = hex.EncodeToString(ih[:])
		priv, _, err := awg.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate server key: %w", err)
		}
		cfg.ServerPrivKey = priv
		if err := st.SaveServerConfig(cfg); err != nil {
			return nil, fmt.Errorf("save first-boot identity: %w", err)
		}
	} else if stored.LegacyTransport == "" {
		stored.LegacyTransport = cfg.LegacyTransport
		if err := st.SaveServerConfig(stored); err != nil {
			return nil, err
		}
	}

	ih, err := hex.DecodeString(cfg.InfoHash)
	if err != nil || len(ih) != 20 {
		return nil, fmt.Errorf("bad infohash in store")
	}
	serverPub, err := awg.DerivePubKey(cfg.ServerPrivKey)
	if err != nil {
		return nil, fmt.Errorf("derive server public key: %w", err)
	}
	serverIP := netip.MustParseAddr(cfg.ServerIP)
	if g, err := st.GetGroup(store.DefaultGroupID); err == nil {
		cfg.ServerIP, cfg.Subnet = g.ServerIP, g.Subnet
		serverIP = netip.MustParseAddr(g.ServerIP)
	} else {
		return nil, err
	}

	s := &Server{
		cfg:      cfg,
		st:       st,
		infoHash: [20]byte(ih),
		pubKey:   serverPub,
		bd:       bind.NewHybrid(),
		peers:    make(map[string]store.ClientRecord),
		sessions: make(map[string]map[carrier.Transport]struct{}),
		byPeerID: make(map[string]store.ClientRecord),
		attached: make(map[string]int),
		closed:   make(chan struct{}),
	}

	s.policy = newPolicySnapshot()
	s.savedTraffic, err = st.LoadTraffic()
	if err != nil {
		return nil, fmt.Errorf("load traffic: %w", err)
	}
	for id, v := range s.savedTraffic {
		c := new(trafficCounter)
		c.up.Store(v.Up)
		c.down.Store(v.Down)
		c.lastSeen.Store(v.LastSeen)
		s.policy.traffic[id] = c
	}
	if err := s.policy.reload(st, serverIP); err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	return s, nil
}

func (s *Server) finish() error {
	s.dev = device.NewDevice(s.router.device(0), s.bd, device.NewLogger(device.LogLevelError, "btawg-awg: "))
	s.wg = device.NewDevice(s.router.device(1), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "btawg-wg: "))
	if err := s.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n%s", s.cfg.ServerPrivKey, s.cfg.AWGPort, s.cfg.AWGProfile.String())); err != nil {
		return err
	}
	if err := s.wg.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", s.cfg.ServerPrivKey, s.cfg.WGPort)); err != nil {
		return err
	}
	if err := s.reloadPeers(); err != nil {
		return err
	}
	if err := s.dev.Up(); err != nil {
		return fmt.Errorf("AWG: %w", err)
	}
	if err := s.wg.Up(); err != nil {
		return fmt.Errorf("WG: %w", err)
	}
	listen := net.ListenConfig{Control: carrier.TCPControl}
	var err error
	s.tcpLn, err = listen.Listen(context.Background(), "tcp4", fmt.Sprintf(":%d", s.cfg.CarrierPort))
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: s.cfg.CarrierPort})
	if err != nil {
		return err
	}
	s.udpPC = pc
	s.sock, err = carrier.NewUTPSocket(pc)
	if err != nil {
		return err
	}
	if s.ns != nil {
		s.egressLn, err = s.netstackEgress()
	} else {
		lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
			if err := tunsetup.OverlayTCP(network, address, c); err != nil {
				return err
			}
			var optErr error
			if err := c.Control(func(fd uintptr) { optErr = unix.BindToDevice(int(fd), s.tunName) }); err != nil {
				return err
			}
			return optErr
		}}
		s.egressLn, err = lc.Listen(context.Background(), "tcp4", fmt.Sprintf(":%d", s.cfg.SocksPort))
	}
	if err != nil {
		return err
	}
	s.egressGate = &gatedListener{inner: s.egressLn, policy: s.policy, active: make(map[*egressSession]netip.Addr)}
	s.hashes = make(map[[20]byte]string, 2)
	if s.ns == nil {
		s.egressGate.requireGateway = true
	}
	for _, framing := range []string{"ext", "req"} {
		hash, err := config.CarrierHash(s.InfoHash(), s.cfg.LegacyTransport, framing+"-tcp")
		if err != nil {
			return err
		}
		key, err := awg.InfoHashBytes(hash)
		if err != nil {
			return err
		}
		s.hashes[key] = framing
		ann, err := dht.NewAnnouncer(key, netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(s.cfg.CarrierPort)), nil)
		if err != nil {
			return err
		}
		s.anns = append(s.anns, ann)
	}
	return nil
}

// InfoHash returns the deployment's hex infohash (shown by the panel, carried
// in every client import string).
func (s *Server) InfoHash() string { return hex.EncodeToString(s.infoHash[:]) }

// PubKey returns the hub's AWG public key.
func (s *Server) PubKey() string { return s.pubKey }

// Config returns the active server configuration.
func (s *Server) Config() config.ServerConfig { return s.cfg }

// ReloadPolicy applies stored group addresses, peer addresses and access rules.
func (s *Server) ReloadPolicy() error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	gs, err := groupGateways(s.st)
	if err != nil {
		return err
	}
	if s.ns != nil {
		if len(gs) != len(s.gateways) {
			return fmt.Errorf("changing group networks in -no-tun mode requires a restart or a real TUN")
		}
		for i, g := range gs {
			if g != s.gateways[i] {
				return fmt.Errorf("changing group networks in -no-tun mode requires a restart or a real TUN")
			}
		}
	}
	if s.kernel != nil && !slices.Equal(gs, s.gateways) {
		if err = s.kernel.Apply(gs); err != nil {
			return err
		}
		s.gateways = gs
	}
	if err = s.reloadPeers(); err != nil {
		s.policy.disableClients()
		if s.egressGate != nil {
			s.egressGate.closeDenied()
		}
		return err
	}
	group, err := s.st.GetGroup(store.DefaultGroupID)
	if err != nil {
		return err
	}
	if err = s.policy.reload(s.st, netip.MustParseAddr(group.ServerIP)); err != nil {
		s.policy.disableClients()
		if s.egressGate != nil {
			s.egressGate.closeDenied()
		}
		return err
	}
	if s.egressGate != nil {
		s.egressGate.closeDenied()
	}
	s.gateways = gs
	return nil
}

// OverlayNet exposes the hub's userspace network stack for the panel and diagnostics.
func (s *Server) OverlayNet() *netstack.Net { return s.ns }

// Run serves the carrier listener and the egress SOCKS5 until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
		case <-s.closed:
		}
		cancel()
	}()

	prefix := egressDenied{policy: s.policy}
	egress := socks.NewServer(
		newEgressDialer(prefix, net.DefaultResolver),
		func(ctx context.Context) (net.PacketConn, error) {
			return newEgressUDP(prefix)
		},
	).WithRelayUDP(func(local, remote net.Addr) (net.PacketConn, error) {
		// The relay must live inside the overlay. In netstack mode that is a
		// netstack address; in real-TUN mode the kernel interface owns the
		// overlay prefix, so bind the relay to it on the host network.
		serverIP, ok := addrIP(local)
		if !ok {
			return nil, fmt.Errorf("invalid relay local address")
		}
		var relay net.PacketConn
		var err error
		if s.ns != nil {
			relay, err = s.ns.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 0))
		} else {
			relay, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(serverIP.String())})
		}
		if err != nil {
			return nil, err
		}
		remoteIP, ok := addrIP(remote)
		if !ok {
			relay.Close()
			return nil, fmt.Errorf("relay: cannot parse control remote address %v", remote)
		}
		return &sourceLockedRelay{PacketConn: relay, allow: remoteIP}, nil
	})
	go egress.Serve(runCtx, s.egressGate)

	errs := make(chan error, 2)
	for _, accept := range []func() (net.Conn, error){s.tcpLn.Accept, s.sock.Accept} {
		go func() {
			for {
				c, err := accept()
				if err != nil {
					errs <- err
					return
				}
				go s.acceptConn(runCtx, c)
			}
		}()
	}
	select {
	case <-runCtx.Done():
		return nil
	case err := <-errs:
		select {
		case <-s.closed:
			return nil
		default:
			return fmt.Errorf("carrier accept: %w", err)
		}
	}
}

// Announce publishes both framing hashes through DHT.
func (s *Server) Announce(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(s.anns))
	for _, a := range s.anns {
		go func() { errs <- a.Run(ctx) }()
	}
	select {
	case <-ctx.Done():
		return nil
	case <-s.closed:
		return nil
	case err := <-errs:
		return err
	}
}

func (s *Server) acceptConn(ctx context.Context, c net.Conn) {
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = c.Close()
		return
	}
	t, theirs, err := carrier.Accept(c, serverPeerID, s.hashes)
	if err != nil {
		_ = c.Close()
		return
	}
	if err = c.SetDeadline(time.Time{}); err != nil {
		t.Close()
		return
	}
	id := hex.EncodeToString(theirs[:])
	s.mu.Lock()
	rec, ok := s.byPeerID[id]
	if !ok {
		s.mu.Unlock()
		t.Close()
		return
	}
	select {
	case <-s.closed:
		s.mu.Unlock()
		t.Close()
		return
	default:
	}
	if s.sessions[id] == nil {
		s.sessions[id] = make(map[carrier.Transport]struct{})
	}
	s.sessions[id][t] = struct{}{}
	detach := s.bd.AddCarrier(netip.MustParseAddr(rec.IP), t)
	s.attached[rec.IP]++
	s.mu.Unlock()
	select {
	case <-t.Done():
	case <-ctx.Done():
	case <-s.closed:
	}
	detach()
	s.mu.Lock()
	delete(s.sessions[id], t)
	if len(s.sessions[id]) == 0 {
		delete(s.sessions, id)
	}
	if s.attached[rec.IP] > 1 {
		s.attached[rec.IP]--
	} else {
		delete(s.attached, rec.IP)
	}
	s.mu.Unlock()
}

func (s *Server) reloadPeers() error {
	recs, err := s.st.ListClients()
	if err != nil {
		return err
	}
	next := make(map[string]store.ClientRecord, len(recs))
	byPeerID := make(map[string]store.ClientRecord, len(recs))
	for _, r := range recs {
		if r.Revoked {
			continue
		}
		if _, err := netip.ParseAddr(r.IP); err != nil {
			return err
		}
		if _, err := awg.InfoHashBytes(r.PeerID); r.PeerID != "" && err != nil {
			return fmt.Errorf("invalid carrier identity for user %q", r.ID)
		}
		if decoded, err := hex.DecodeString(r.PubKey); err != nil || len(decoded) != 32 || r.PubKey == s.pubKey {
			return fmt.Errorf("invalid public key for user %q", r.ID)
		}
		if r.PeerID == "" {
			r.PeerID = awg.PeerID(r.PubKey)
		}
		next[r.ID] = r
		byPeerID[r.PeerID] = r
	}
	var closeList []carrier.Transport
	s.mu.Lock()
	s.byPeerID = byPeerID
	for id, old := range s.peers {
		if r, ok := next[id]; ok && r.IP == old.IP && r.PubKey == old.PubKey {
			continue
		}
		for t := range s.sessions[old.PeerID] {
			closeList = append(closeList, t)
		}
	}
	s.mu.Unlock()
	for _, t := range closeList {
		t.Close()
	}
	for id, old := range s.peers {
		if r, ok := next[id]; ok && r.IP == old.IP && r.PubKey == old.PubKey {
			continue
		}
		ip := netip.MustParseAddr(old.IP)
		s.policy.remove(ip)
		s.router.forget(ip)
		line := fmt.Sprintf("public_key=%s\nremove=true\n", old.PubKey)
		if err := s.dev.IpcSet(line); err != nil {
			return err
		}
		if err := s.wg.IpcSet(line); err != nil {
			return err
		}
	}
	for id, r := range next {
		if old, ok := s.peers[id]; ok && old.IP == r.IP && old.PubKey == r.PubKey {
			continue
		}
		line := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", r.PubKey, r.IP)
		if err := s.dev.IpcSet(line); err != nil {
			return err
		}
		if err := s.wg.IpcSet(line); err != nil {
			return err
		}
	}
	s.peers = next
	return nil
}

// RegisterClient applies an enrollment already persisted by the panel.
func (s *Server) RegisterClient(rec store.ClientRecord) error { return s.ReloadPolicy() }

// RevokeClient applies a revocation already persisted by the panel.
func (s *Server) RevokeClient(rec store.ClientRecord) error { return s.ReloadPolicy() }

// hostResolver is the minimal resolver surface the egress dialer needs.
type hostResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// overlayFilteredPacketConn wraps an upstream UDP socket and refuses writes
// to destinations inside the overlay subnet. SOCKS/egress is internet-only;
// client-to-client traffic must use the filtered OverlayDialTCP path.
type overlayFilteredPacketConn struct {
	net.PacketConn
	prefix interface{ Contains(netip.Addr) bool }
}

func (c *overlayFilteredPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if ip, ok := addrIP(addr); !ok || c.prefix.Contains(ip.Unmap()) {
		return 0, fmt.Errorf("egress refused: UDP destination %v is not allowed", addr)
	}
	return c.PacketConn.WriteTo(p, addr)
}

// sourceLockedRelay wraps the app-facing UDP relay socket of a single SOCKS5
// UDP ASSOCIATE. It only accepts datagrams from the overlay IP that opened
// the TCP control connection; datagrams from any other source are dropped
// before pumpUDP can forward them upstream. This prevents a malicious or
// NoInternet client from hijacking another client's UDP relay association.
type sourceLockedRelay struct {
	net.PacketConn
	allow netip.Addr
}

func (r *sourceLockedRelay) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, src, err := r.PacketConn.ReadFrom(p)
		if err != nil {
			return n, src, err
		}
		ip, ok := addrIP(src)
		if ok && ip == r.allow {
			return n, src, nil
		}
		// Datagram from an unauthorized source: drop and keep reading.
	}
}

// newEgressDialer returns a TCP dialer that refuses overlay destinations.
// For literal IPs the check is direct; for hostnames it resolves the name and
// refuses if any returned IP lies inside the overlay subnet. After the check
// succeeds, the dial uses the resolved address so the guard cannot be bypassed
// by a name that resolves differently at dial time.
func newEgressDialer(prefix interface{ Contains(netip.Addr) bool }, resolver hostResolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("egress: malformed destination %q: %w", addr, err)
		}
		dialHost := host

		if ip, err := netip.ParseAddr(host); err == nil {
			if prefix.Contains(ip.Unmap()) {
				return nil, fmt.Errorf("egress refused: destination %s is not allowed", addr)
			}
		} else {
			ips, err := resolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("egress: resolve %s: %w", host, err)
			}
			var addrs []string
			for _, ip := range ips {
				a, ok := netip.AddrFromSlice(ip)
				if !ok {
					continue
				}
				a = a.Unmap()
				if prefix.Contains(a) {
					return nil, fmt.Errorf("egress refused: hostname %s resolved to a prohibited IP %s", host, a)
				}
				addrs = append(addrs, net.JoinHostPort(a.String(), port))
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("egress: no usable IP for %s", host)
			}

			var d net.Dialer
			var firstErr error
			for _, addr := range addrs {
				conn, err := d.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				if firstErr == nil {
					firstErr = err
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				default:
				}
			}
			return nil, firstErr
		}

		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(dialHost, port))
	}
}

// newEgressUDP returns an upstream UDP socket that refuses overlay destinations.
func newEgressUDP(prefix interface{ Contains(netip.Addr) bool }) (net.PacketConn, error) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &overlayFilteredPacketConn{PacketConn: pc, prefix: prefix}, nil
}

// ConnectedCount reports how many carriers are attached per overlay IP.
func (s *Server) ConnectedCount() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.attached))
	for ip, n := range s.attached {
		out[ip] = n
	}
	return out
}

// Close tears the hub down.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.trafficWG.Wait()
		for _, a := range s.anns {
			a.Close()
		}
		if s.sock != nil {
			_ = s.sock.Close()
		}
		if s.tcpLn != nil {
			_ = s.tcpLn.Close()
		}
		if s.udpPC != nil {
			_ = s.udpPC.Close()
		}
		if s.egressGate != nil {
			_ = s.egressGate.Close()
		} else if s.egressLn != nil {
			_ = s.egressLn.Close()
		}
		if s.dev != nil {
			s.dev.Close()
		}
		if s.wg != nil {
			s.wg.Close()
		}
		if s.kernel != nil {
			s.closeErr = s.kernel.Close()
		}
		if s.router != nil {
			s.closeErr = errors.Join(s.closeErr, s.router.close(), s.flushTraffic())
		}
	})
	return s.closeErr
}

// SetDHTBootstrap updates discovery bootstrap for both framing hashes.
func (s *Server) SetDHTBootstrap(hosts []string) {
	for _, a := range s.anns {
		a.SetBootstrap(hosts)
	}
}
