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
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	utp "github.com/anacrolix/go-utp"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/dht"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/store"
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

	bd  *bind.Bind
	dev *device.Device
	ns  *netstack.Net

	mu       sync.Mutex
	byPeerID map[string]store.ClientRecord
	attached map[string]int // client IP -> carrier count

	udpPC    net.PacketConn
	sock     utp.Socket
	tcpLn    net.Listener
	ann      *dht.Announcer
	egressLn net.Listener
	closed   chan struct{}
}

// New loads (or generates at first boot) the server identity, builds the AWG
// hub with one peer per stored client, the carrier listener and the egress
// SOCKS5. Call Run to serve; call Announce to publish via DHT.
func New(cfg config.ServerConfig, st *store.Store) (*Server, error) {
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

	clients, err := st.ListClients()
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
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

	tunDev, ns, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		return nil, fmt.Errorf("create netstack: %w", err)
	}
	s.ns = ns
	fwd := newForwardingTun(tunDev, serverIP)
	s.dev = device.NewDevice(fwd, s.bd, device.NewLogger(device.LogLevelError, "btawg-server: "))
	ipc := fmt.Sprintf("private_key=%s\n%s%s", cfg.ServerPrivKey, cfg.AWGProfile.String(), peerConf)
	if err := s.dev.IpcSet(ipc); err != nil {
		s.dev.Close()
		return nil, fmt.Errorf("server IpcSet: %w", err)
	}
	if err := s.dev.Up(); err != nil {
		s.dev.Close()
		return nil, fmt.Errorf("server up: %w", err)
	}

	// Egress SOCKS5 inside the overlay: reachable only through the tunnel.
	egressLn, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, uint16(cfg.SocksPort)))
	if err != nil {
		s.dev.Close()
		return nil, fmt.Errorf("egress listen: %w", err)
	}
	s.egressLn = egressLn

	switch cfg.Transport {
	case "ext-utp", "req-utp":
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.CarrierPort})
		if err != nil {
			s.dev.Close()
			return nil, fmt.Errorf("carrier listen: %w", err)
		}
		s.udpPC = pc
		sock, err := utp.NewSocketFromPacketConn(pc,
			utp.WithTargetDelay(5*time.Millisecond),
			utp.WithBufferSizes(65536, 65536))
		if err != nil {
			pc.Close()
			s.dev.Close()
			return nil, fmt.Errorf("utp socket: %w", err)
		}
		s.sock = sock
	case "ext-tcp", "req-tcp":
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.CarrierPort))
		if err != nil {
			s.dev.Close()
			return nil, fmt.Errorf("carrier listen: %w", err)
		}
		s.tcpLn = ln
	default:
		s.dev.Close()
		return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
	}

	announceIP, err := netip.ParseAddr(cfg.ExternalIP)
	if err != nil {
		announceIP = netip.IPv4Unspecified()
	}
	ann, err := dht.NewAnnouncer(s.infoHash, netip.AddrPortFrom(announceIP, uint16(cfg.CarrierPort)), nil)
	if err != nil {
		s.closeAll()
		return nil, fmt.Errorf("dht announcer: %w", err)
	}
	s.ann = ann
	return s, nil
}

// InfoHash returns the deployment's hex infohash (shown by the panel, carried
// in every client import string).
func (s *Server) InfoHash() string { return hex.EncodeToString(s.infoHash[:]) }

// PubKey returns the hub's AWG public key.
func (s *Server) PubKey() string { return s.pubKey }

// Config returns the active server configuration.
func (s *Server) Config() config.ServerConfig { return s.cfg }

// OverlayNet exposes the hub's userspace network stack for the panel and
// diagnostics.
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

	egress := socks.NewServer(
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		func(ctx context.Context) (net.PacketConn, error) {
			return net.ListenUDP("udp", nil)
		},
	).WithRelayUDP(func(net.Addr) (net.PacketConn, error) {
		// The relay must live inside the overlay: 10.77.0.1 is a netstack
		// address, not a host interface address.
		return s.ns.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(s.cfg.ServerIP), 0))
	})
	go egress.Serve(runCtx, s.egressLn)

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

// RegisterClient adds a client at runtime (panel create): AWG peer entry plus
// carrier routing by peer ID.
func (s *Server) RegisterClient(rec store.ClientRecord) error {
	if rec.PeerID == "" {
		rec.PeerID = awg.PeerID(rec.PubKey)
	}
	if err := s.dev.IpcSet(awg.ServerPeerLine(rec.PubKey, rec.IP)); err != nil {
		return fmt.Errorf("ipc add peer: %w", err)
	}
	s.mu.Lock()
	s.byPeerID[rec.PeerID] = rec
	s.mu.Unlock()
	return nil
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

