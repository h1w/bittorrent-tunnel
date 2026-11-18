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
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	utp "github.com/anacrolix/go-utp"
	"github.com/anacrolix/go-utp/purego"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/dht"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/store"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

// The hub sends real-time tunnel traffic too: same µTP send policy as the
// client, set once before any goroutine exists.
func init() { purego.MatrixDisableNagle = true }

// serverPeerID is the fixed BitTorrent peer ID this hub presents in every
// carrier handshake; clients identify the deployment by infohash, not peer ID.
var serverPeerID = [20]byte{'b', 't', 'a', 'w', 'g', '-', 's', 'e', 'r', 'v', 'e', 'r', '-', 'n', 'o', 'd', 'e', '0', '0', '1'}

// Server is the assembled btawg hub.
type Server struct {
	cfg      config.ServerConfig
	st       *store.Store
	infoHash [20]byte
	pubKey   string

	bd  *bind.Bind
	dev *device.Device
	ns  *netstack.Net

	mu       sync.Mutex
	byPeerID map[string]store.ClientRecord
	attached map[string]int // client IP -> carrier count

	policy *policySnapshot

	udpPC    net.PacketConn
	sock     utp.Socket
	tcpLn    net.Listener
	ann      *dht.Announcer
	egressLn net.Listener
	closed   chan struct{}
}

// New loads (or generates at first boot) the server identity, builds the AWG
// hub with one peer per stored client, the carrier listener and the egress
// SOCKS5 in userspace netstack mode. Call Run to serve; call Announce to
// publish via DHT.
func New(cfg config.ServerConfig, st *store.Store) (*Server, error) {
	s, serverIP, peerConf, err := prepareServer(cfg, st)
	if err != nil {
		return nil, err
	}

	tunDev, ns, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		return nil, fmt.Errorf("create netstack: %w", err)
	}
	s.ns = ns
	fwd := newForwardingTun(tunDev, serverIP)
	filtered := &filterTun{inner: fwd, policy: s.policy}

	egressLn, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, uint16(cfg.SocksPort)))
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("egress listen: %w", err)
	}

	if err := s.finish(filtered, egressLn, peerConf); err != nil {
		s.closeAll()
		return nil, err
	}
	return s, nil
}

// NewRealTUN loads the server identity and builds the hub on a real kernel
// TUN interface, like the client in real-TUN mode. The kernel owns the
// overlay prefix and forwards allowed peer-to-peer traffic via ip_forward;
// no userspace forwardingTun is used.
func NewRealTUN(cfg config.ServerConfig, st *store.Store, tunName string) (*Server, error) {
	s, serverIP, peerConf, err := prepareServer(cfg, st)
	if err != nil {
		return nil, err
	}

	tunDev, err := tun.CreateTUN(tunName, 1420)
	if err != nil {
		return nil, fmt.Errorf("create tun %q: %w", tunName, err)
	}
	filtered := &filterTun{inner: tunDev, policy: s.policy}

	addr, err := serverIP.Prefix(24)
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("server ip prefix: %w", err)
	}
	if err := tunsetup.Setup(tunName, addr, nil, 1420, true); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("setup tun: %w", err)
	}

	egressLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(serverIP.String()), Port: cfg.SocksPort})
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("egress listen: %w", err)
	}

	if err := s.finish(filtered, egressLn, peerConf); err != nil {
		s.closeAll()
		return nil, err
	}
	return s, nil
}

// prepareServer loads (or generates) the hub identity, policy snapshot, and
// peer configuration shared by New and NewRealTUN.
func prepareServer(cfg config.ServerConfig, st *store.Store) (*Server, netip.Addr, string, error) {
	// The argument is the working configuration (main loads it from the
	// store, applying any CLI overrides). At first boot the deployment
	// identity is generated, persisted, and reused from then on.
	if cfg.InfoHash == "" || cfg.ServerPrivKey == "" {
		var ih [20]byte
		if _, err := rand.Read(ih[:]); err != nil {
			return nil, netip.Addr{}, "", fmt.Errorf("generate infohash: %w", err)
		}
		cfg.InfoHash = hex.EncodeToString(ih[:])
		priv, _, err := awg.GenerateKeyPair()
		if err != nil {
			return nil, netip.Addr{}, "", fmt.Errorf("generate server key: %w", err)
		}
		cfg.ServerPrivKey = priv
		if err := st.SaveServerConfig(cfg); err != nil {
			return nil, netip.Addr{}, "", fmt.Errorf("save first-boot identity: %w", err)
		}
	}

	ih, err := hex.DecodeString(cfg.InfoHash)
	if err != nil || len(ih) != 20 {
		return nil, netip.Addr{}, "", fmt.Errorf("bad infohash in store")
	}
	serverPub, err := awg.DerivePubKey(cfg.ServerPrivKey)
	if err != nil {
		return nil, netip.Addr{}, "", fmt.Errorf("derive server public key: %w", err)
	}
	serverIP := netip.MustParseAddr(cfg.ServerIP)

	s := &Server{
		cfg:      cfg,
		st:       st,
		infoHash: [20]byte(ih),
		pubKey:   serverPub,
		bd:       bind.New(),
		byPeerID: make(map[string]store.ClientRecord),
		attached: make(map[string]int),
		closed:   make(chan struct{}),
	}

	s.policy = newPolicySnapshot()
	if err := s.policy.reload(st, serverIP); err != nil {
		return nil, netip.Addr{}, "", fmt.Errorf("load policy: %w", err)
	}

	clients, err := st.ListClients()
	if err != nil {
		return nil, netip.Addr{}, "", fmt.Errorf("list clients: %w", err)
	}
	var peerConf string
	for _, rec := range clients {
		if rec.PeerID == "" {
			rec.PeerID = awg.PeerID(rec.PubKey)
		}
		if rec.Revoked {
			continue
		}
		s.byPeerID[rec.PeerID] = rec
		peerConf += awg.ServerPeerLine(rec.PubKey, rec.IP)
	}
	return s, serverIP, peerConf, nil
}

// finish assembles the AWG device, carrier listener, and DHT announcer once
// the TUN device and egress listener have been chosen by the caller.
func (s *Server) finish(tunDev tun.Device, egressLn net.Listener, peerConf string) error {
	s.dev = device.NewDevice(tunDev, s.bd, device.NewLogger(device.LogLevelError, "btawg-server: "))
	ipc := fmt.Sprintf("private_key=%s\n%s%s", s.cfg.ServerPrivKey, s.cfg.AWGProfile.String(), peerConf)
	if err := s.dev.IpcSet(ipc); err != nil {
		s.dev.Close()
		return fmt.Errorf("server IpcSet: %w", err)
	}
	if err := s.dev.Up(); err != nil {
		s.dev.Close()
		return fmt.Errorf("server up: %w", err)
	}

	s.egressLn = egressLn

	switch s.cfg.Transport {
	case "ext-utp", "req-utp":
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: s.cfg.CarrierPort})
		if err != nil {
			return fmt.Errorf("carrier listen: %w", err)
		}
		s.udpPC = pc
		sock, err := utp.NewSocketFromPacketConn(pc,
			utp.WithTargetDelay(5*time.Millisecond),
			utp.WithBufferSizes(65536, 65536))
		if err != nil {
			return fmt.Errorf("utp socket: %w", err)
		}
		s.sock = sock
	case "ext-tcp", "req-tcp":
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.CarrierPort))
		if err != nil {
			return fmt.Errorf("carrier listen: %w", err)
		}
		s.tcpLn = ln
	default:
		return fmt.Errorf("unknown transport %q", s.cfg.Transport)
	}

	announceIP, err := netip.ParseAddr(s.cfg.ExternalIP)
	if err != nil {
		announceIP = netip.IPv4Unspecified()
	}
	ann, err := dht.NewAnnouncer(s.infoHash, netip.AddrPortFrom(announceIP, uint16(s.cfg.CarrierPort)), nil)
	if err != nil {
		return fmt.Errorf("dht announcer: %w", err)
	}
	s.ann = ann
	return nil
}

// InfoHash returns the deployment's hex infohash (shown by the panel, carried
// in every client import string).
func (s *Server) InfoHash() string { return hex.EncodeToString(s.infoHash[:]) }

// PubKey returns the hub's AWG public key.
func (s *Server) PubKey() string { return s.pubKey }

// Config returns the active server configuration.
func (s *Server) Config() config.ServerConfig { return s.cfg }

// ReloadPolicy re-reads the current client records from the store into the
// in-memory policy snapshot.
func (s *Server) ReloadPolicy() error {
	return s.policy.reload(s.st, netip.MustParseAddr(s.cfg.ServerIP))
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

	prefix := overlayPrefix(s.cfg)
	egress := socks.NewServer(
		newEgressDialer(prefix, net.DefaultResolver),
		func(ctx context.Context) (net.PacketConn, error) {
			return newEgressUDP(prefix)
		},
	).WithRelayUDP(func(local, remote net.Addr) (net.PacketConn, error) {
		// The relay must live inside the overlay. In netstack mode that is a
		// netstack address; in real-TUN mode the kernel interface owns the
		// overlay prefix, so bind the relay to it on the host network.
		serverIP := netip.MustParseAddr(s.cfg.ServerIP)
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
	gated := &gatedListener{inner: s.egressLn, policy: s.policy}
	go egress.Serve(runCtx, gated)

	switch {
	case s.sock != nil:
		for {
			c, err := s.sock.Accept()
			if err != nil {
				if runCtx.Err() != nil {
					return nil
				}
				return fmt.Errorf("carrier accept: %w", err)
			}
			go s.acceptConn(runCtx, c)
		}
	case s.tcpLn != nil:
		for {
			c, err := s.tcpLn.Accept()
			if err != nil {
				if runCtx.Err() != nil {
					return nil
				}
				return fmt.Errorf("carrier accept: %w", err)
			}
			go s.acceptConn(runCtx, c)
		}
	}
	<-runCtx.Done()
	return nil
}

// Announce publishes the carrier address in the DHT until ctx is done.
func (s *Server) Announce(ctx context.Context) error { return s.ann.Run(ctx) }

// acceptConn performs the BitTorrent handshake inside the carrier
// constructor, identifies the client by the returned peer ID, and attaches
// the carrier to the AWG bind under the client's overlay endpoint.
func (s *Server) acceptConn(ctx context.Context, c net.Conn) {
	var t carrier.Transport
	var theirID [20]byte
	var err error
	switch s.cfg.Transport {
	case "ext-utp", "ext-tcp":
		t, theirID, err = carrier.NewExtended(c, s.infoHash, serverPeerID)
	case "req-utp", "req-tcp":
		t, theirID, err = carrier.NewRequestPiece(c, s.infoHash, serverPeerID, true)
	default:
		err = fmt.Errorf("unknown transport")
	}
	if err != nil {
		c.Close()
		return
	}
	s.mu.Lock()
	rec, ok := s.byPeerID[hex.EncodeToString(theirID[:])]
	s.mu.Unlock()
	if !ok {
		t.Close()
		return
	}
	ip := netip.MustParseAddr(rec.IP)
	ep := bind.Endpoint(ip)
	s.bd.Attach(ep, t)
	s.mu.Lock()
	s.attached[rec.IP]++
	s.mu.Unlock()
	go func() {
		select {
		case <-t.Done():
		case <-ctx.Done():
		case <-s.closed:
		}
		s.bd.Detach(ep)
		s.mu.Lock()
		s.attached[rec.IP]--
		s.mu.Unlock()
	}()
}

// RegisterClient adds a client at runtime (panel create): AWG peer entry,
// carrier routing by peer ID, and an in-memory policy snapshot update so the
// new client is immediately enforceable without a reload or restart.
func (s *Server) RegisterClient(rec store.ClientRecord) error {
	if rec.PeerID == "" {
		rec.PeerID = awg.PeerID(rec.PubKey)
	}
	store.NormalizeClientRecord(&rec)
	if err := s.dev.IpcSet(awg.ServerPeerLine(rec.PubKey, rec.IP)); err != nil {
		return fmt.Errorf("ipc add peer: %w", err)
	}
	s.mu.Lock()
	s.byPeerID[rec.PeerID] = rec
	s.mu.Unlock()
	s.policy.upsert(rec, netip.MustParseAddr(s.cfg.ServerIP))
	return nil
}

// RevokeClient removes a client at runtime (panel revoke): the AWG peer is
// dropped, its carrier detached, future handshakes from its peer ID are
// rejected, and the policy snapshot is updated to drop the revoked record.
func (s *Server) RevokeClient(rec store.ClientRecord) error {
	ipc := fmt.Sprintf("public_key=%s\nremove=true\n", rec.PubKey)
	if err := s.dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("ipc remove peer: %w", err)
	}
	ip := netip.MustParseAddr(rec.IP)
	s.bd.Detach(bind.Endpoint(ip))
	s.mu.Lock()
	delete(s.byPeerID, rec.PeerID)
	s.mu.Unlock()
	s.policy.remove(ip)
	return nil
}

// overlayPrefix returns the hub's overlay subnet (ServerIP/24).
func overlayPrefix(cfg config.ServerConfig) netip.Prefix {
	p, err := netip.MustParseAddr(cfg.ServerIP).Prefix(24)
	if err != nil {
		// A /24 is always valid for an IPv4 address; panic on programmer error.
		panic(fmt.Sprintf("overlay prefix: %v", err))
	}
	return p
}

// hostResolver is the minimal resolver surface the egress dialer needs.
type hostResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// overlayFilteredPacketConn wraps an upstream UDP socket and refuses writes
// to destinations inside the overlay subnet. SOCKS/egress is internet-only;
// client-to-client traffic must use the filtered OverlayDialTCP path.
type overlayFilteredPacketConn struct {
	net.PacketConn
	prefix netip.Prefix
}

func (c *overlayFilteredPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if ip, ok := addrIP(addr); ok && c.prefix.Contains(ip) {
		return 0, fmt.Errorf("egress refused: UDP destination %v is inside overlay subnet", addr)
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
func newEgressDialer(prefix netip.Prefix, resolver hostResolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("egress: malformed destination %q: %w", addr, err)
		}
		dialHost := host

		if ip, err := netip.ParseAddr(host); err == nil {
			if prefix.Contains(ip) {
				return nil, fmt.Errorf("egress refused: destination %s is inside overlay subnet", addr)
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
					return nil, fmt.Errorf("egress refused: hostname %s resolved to overlay IP %s", host, a)
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
func newEgressUDP(prefix netip.Prefix) (net.PacketConn, error) {
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
	select {
	case <-s.closed:
		return nil
	default:
	}
	close(s.closed)
	return s.closeAll()
}

func (s *Server) closeAll() error {
	if s.ann != nil {
		s.ann.Close()
	}
	if s.sock != nil {
		s.sock.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	if s.udpPC != nil {
		s.udpPC.Close()
	}
	if s.egressLn != nil {
		s.egressLn.Close()
	}
	if s.dev != nil {
		s.dev.Close()
	}
	return nil
}

// SetDHTBootstrap overrides the announcer's bootstrap node list; the next
// announce cycle uses it (tests point it at a local relay).
func (s *Server) SetDHTBootstrap(hosts []string) {
	s.ann.SetBootstrap(hosts)
}
