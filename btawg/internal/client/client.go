// Package client assembles the btawg client: DHT discovery of the hub (never
// a direct endpoint), the BitTorrent carrier to the discovered address, the
// AmneziaWG device holding the client's overlay address, and a no-auth SOCKS5
// server on loopback that chains every CONNECT and UDP ASSOCIATE to the hub's
// egress inside the tunnel. Netstack mode runs fully in userspace (tests);
// real-TUN mode exposes the overlay as an OS interface without a
// default-route takeover.
package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
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
)

// Real-time traffic must not wait on µTP's Nagle-like holdback: set the
// global send policy once, before any goroutine can race on it.
func init() { purego.MatrixDisableNagle = true }

// retryDelay spaces carrier reconnect attempts.
const retryDelay = 3 * time.Second

// Client is the assembled btawg client node.
type Client struct {
	cfg config.ClientConfig
	bd  *bind.Bind
	dev *device.Device
	ns  *netstack.Net // non-nil in netstack mode
	tun tun.Device    // non-nil in real-TUN mode

	chainTCP func(ctx context.Context, addr string) (net.Conn, error)
	chainUDP func(ctx context.Context) (net.PacketConn, error)

	disc func(ctx context.Context) ([]netip.AddrPort, error)

	socksAddr atomic.Value // string, set once the SOCKS5 listener is up
}

// New builds the client in userspace netstack mode: the overlay lives inside
// the process and the SOCKS5 chain dials through it.
func New(cfg config.ClientConfig) (*Client, error) {
	c := &Client{
		cfg: cfg,
		bd:  bind.New(),
	}
	clientIP := netip.MustParseAddr(cfg.ClientIP)
	tunDev, ns, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		return nil, fmt.Errorf("client netstack: %w", err)
	}
	c.ns = ns
	if err := c.start(tunDev); err != nil {
		return nil, err
	}
	c.chainTCP = func(ctx context.Context, addr string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("chain addr: %w", err)
		}
		return ns.DialContextTCPAddrPort(ctx, ap)
	}
	c.chainUDP = func(ctx context.Context) (net.PacketConn, error) {
		// Bind the client's overlay address: an unspecified-source socket
		// gets "no route to host" in the netstack on WriteTo.
		return ns.ListenUDPAddrPort(netip.AddrPortFrom(clientIP, 0))
	}
	return c, nil
}

// NewRealTUN builds the client on a real OS network interface (root). The
// overlay address and subnet route are configured by the caller (main);
// nothing here takes over the default route.
func NewRealTUN(cfg config.ClientConfig, tunName string) (*Client, error) {
	c := &Client{
		cfg: cfg,
		bd:  bind.New(),
	}
	tunDev, err := tun.CreateTUN(tunName, 1420)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	c.tun = tunDev
	if err := c.start(tunDev); err != nil {
		return nil, err
	}
	// Kernel defaults: the overlay route on the TUN carries chain traffic.
	return c, nil
}

func (c *Client) start(tunDev tun.Device) error {
	level := device.LogLevelError
	if os.Getenv("BTAWG_AWG_VERBOSE") != "" {
		// Field debugging: shows handshake initiation/response exchange on
		// the wire when the tunnel does not come up.
		level = device.LogLevelVerbose
	}
	c.dev = device.NewDevice(tunDev, c.bd, device.NewLogger(level, "btawg-client: "))
	if err := c.dev.IpcSet(awg.ClientConf(c.cfg)); err != nil {
		c.dev.Close()
		return fmt.Errorf("client IpcSet: %w", err)
	}
	infoHash, err := awg.InfoHashBytes(c.cfg.InfoHash)
	if err != nil {
		c.dev.Close()
		return fmt.Errorf("config infohash: %w", err)
	}
	c.disc = func(ctx context.Context) ([]netip.AddrPort, error) {
		return dht.Discover(ctx, infoHash, c.cfg.DHTBootstrap)
	}
	return nil
}

// SetDiscovery replaces the DHT discovery function (tests inject a relay or a
// direct address; production always uses DHT).
func (c *Client) SetDiscovery(fn func(ctx context.Context) ([]netip.AddrPort, error)) {
	if fn != nil {
		c.disc = fn
	}
}

// SocksAddr returns the local no-auth SOCKS5 address once it is listening.
func (c *Client) SocksAddr() string {
	s, _ := c.socksAddr.Load().(string)
	return s
}

// OverlayDialTCP dials a TCP address inside the overlay — another client's
// address or the hub. This is the client-to-client path: packets route
// through the tunnel and the hub forwards them between carriers; SOCKS5 and
// the egress are never involved.
func (c *Client) OverlayDialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if c.ns != nil {
		return c.ns.DialContextTCPAddrPort(ctx, addr)
	}
	// Real-TUN mode: the kernel routes overlay addresses via the interface.
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr.String())
}

// OverlayListenTCP starts a TCP listener inside the client's overlay
// netstack (netstack mode only): other clients reach it at ClientIP:port
// through the hub's forwarding — the "local network among clients".
func (c *Client) OverlayListenTCP(port uint16) (net.Listener, error) {
	if c.ns == nil {
		return nil, fmt.Errorf("overlay listener requires netstack mode")
	}
	return c.ns.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(c.cfg.ClientIP), port))
}

// Run serves the local SOCKS5 and keeps a carrier connection to the hub
// alive: discovery is always through DHT, and a dead carrier reconnects.
func (c *Client) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", c.cfg.SocksPort))
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}
	c.socksAddr.Store(ln.Addr().String())
	serverIP := netip.MustParseAddr(c.cfg.ServerIP)
	chain := socks.NewClient(netip.AddrPortFrom(serverIP, uint16(c.cfg.EgressPort)).String())
	chain.WithTransport(c.chainTCP, c.chainUDP)
	local := socks.NewServer(chain.Dial, func(ctx context.Context) (net.PacketConn, error) {
		return chain.DialUDP(ctx)
	})
	go local.Serve(ctx, ln)

	serverEp := bind.Endpoint(serverIP)
	for {
		// DHT announces may not have landed yet when we look: retry the
		// discovery for a bounded window, then fail explicitly.
		var addrs []netip.AddrPort
		var discErr error
		for range 15 {
			var a []netip.AddrPort
			a, discErr = c.disc(ctx)
			if discErr == nil && len(a) > 0 {
				addrs = a
				break
			}
			if discErr == nil {
				discErr = fmt.Errorf("no peers found")
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
		}
		if len(addrs) == 0 {
			return fmt.Errorf("dht discovery: %v (infohash %s)", discErr, c.cfg.InfoHash)
		}
		t, err := c.connectCarrier(ctx, addrs[0])
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Field debugging: silent retry loops made "no carrier"
			// errors undiagnosable (dial failures vs discovery gaps).
			fmt.Printf("btawg-client: carrier dial %s: %v; retrying\n", addrs[0], err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(retryDelay):
			}
			continue
		}
		fmt.Printf("btawg-client: carrier connected to %s\n", addrs[0])
		c.bd.Attach(serverEp, t)
		select {
		case <-t.Done():
			c.bd.Detach(serverEp)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(retryDelay):
			}
		case <-ctx.Done():
			c.bd.Detach(serverEp)
			return nil
		}
	}
}

// connectCarrier dials the hub's real carrier address (learned via DHT) over
// the host network and performs the BitTorrent handshake. This dial never
// goes through the tunnel: the carrier IS the tunnel's transport.
func (c *Client) connectCarrier(ctx context.Context, addr netip.AddrPort) (carrier.Transport, error) {
	infoHash, err := awg.InfoHashBytes(c.cfg.InfoHash)
	if err != nil {
		return nil, err
	}
	peerID, err := awg.PeerIDBytes(awg.PeerID(c.cfg.ClientPubKey))
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	switch c.cfg.Transport {
	case "ext-utp", "req-utp":
		pc, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, fmt.Errorf("carrier udp: %w", err)
		}
		// 100 ms target delay is the library default (what the rest of the
		// µTP network uses); buffers are 4 MiB so the window can cover the
		// bandwidth-delay product of fast WAN paths. The 64 KiB / 5 ms
		// tuning formerly here strangled throughput to ~400 KiB/s.
		sock, err := utp.NewSocketFromPacketConn(pc,
			utp.WithBufferSizes(4<<20, 4<<20))
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("carrier utp socket: %w", err)
		}
		conn, err = sock.DialTimeout(addr.String(), 10*time.Second)
		if err != nil {
			sock.Close()
			return nil, fmt.Errorf("carrier dial %s: %w", addr, err)
		}
	case "ext-tcp", "req-tcp":
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", addr.String())
		if err != nil {
			return nil, fmt.Errorf("carrier dial %s: %w", addr, err)
		}
	default:
		return nil, fmt.Errorf("unknown transport %q", c.cfg.Transport)
	}
	var t carrier.Transport
	switch c.cfg.Transport {
	case "ext-utp", "ext-tcp":
		t, _, err = carrier.NewExtended(conn, infoHash, peerID)
	case "req-utp", "req-tcp":
		t, _, err = carrier.NewRequestPiece(conn, infoHash, peerID, false)
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("carrier handshake: %w", err)
	}
	return t, nil
}

// Close tears the client down.
func (c *Client) Close() {
	c.bd.Close()
	c.dev.Close()
	if c.ns != nil {
		// The netstack TUN is owned by the device; nothing extra to close.
		c.ns = nil
	}
}
