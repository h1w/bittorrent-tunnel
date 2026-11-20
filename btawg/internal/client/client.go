// Package client assembles the btawg client: DHT discovery of the hub (never
// a direct endpoint), the BitTorrent carrier to the discovered address, the
// AmneziaWG device holding the client's overlay address, and a no-auth SOCKS5
// server that chains every CONNECT and UDP ASSOCIATE to the hub's egress
// inside the tunnel. Netstack mode runs fully in userspace (tests);
// real-TUN mode exposes the overlay as an OS interface without a
// default-route takeover.
package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"bittorrent-tunnel/btawg/internal/awg"
	carrierbind "bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/dht"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

// retryDelay spaces carrier reconnect attempts.
const retryDelay = 3 * time.Second

// Client is the assembled btawg client node.
type Client struct {
	cfg  config.ClientConfig
	bind conn.Bind
	dev  *device.Device
	ns   *netstack.Net // non-nil in netstack mode
	tun  tun.Device    // non-nil in real-TUN mode

	chainTCP func(ctx context.Context, addr string) (net.Conn, error)
	chainUDP func(ctx context.Context) (net.PacketConn, error)

	disc func(ctx context.Context) ([]netip.AddrPort, error)

	socksAddr atomic.Value // string, set once the SOCKS5 listener is up
}

// New builds the client in userspace netstack mode: the overlay lives inside
// the process and the SOCKS5 chain dials through it.
func New(cfg config.ClientConfig) (*Client, error) {
	c := &Client{cfg: cfg}
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
	c := &Client{cfg: cfg}
	tunDev, err := tun.CreateTUN(tunName, 1420)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	c.tun = tunDev
	if err := c.start(tunDev); err != nil {
		return nil, err
	}
	clientIP := netip.MustParseAddr(cfg.ClientIP)
	dialer := net.Dialer{Control: tunsetup.OverlayTCP}
	c.chainTCP = func(ctx context.Context, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", addr)
	}
	c.chainUDP = func(ctx context.Context) (net.PacketConn, error) {
		// Bind the overlay source address so the kernel selects the TUN
		// interface for traffic to the hub's SOCKS5 UDP relay.
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(clientIP.AsSlice())})
	}
	return c, nil
}

func (c *Client) start(tunDev tun.Device) error {
	level := device.LogLevelError
	if os.Getenv("BTAWG_AWG_VERBOSE") != "" {
		// Field debugging: shows handshake initiation/response exchange on
		// the wire when the tunnel does not come up.
		level = device.LogLevelVerbose
	}

	mode := c.cfg.Transport
	if config.IsNativeMode(mode) {
		c.bind = conn.NewDefaultBind()
	} else {
		c.bind = carrierbind.New()
	}

	c.dev = device.NewDevice(tunDev, c.bind, device.NewLogger(level, "btawg-client: "))

	var ipc string
	var err error
	if config.IsNativeMode(mode) {
		ipc, err = c.cfg.NativeDeviceConfig(mode)
	} else {
		ipc = awg.ClientConf(c.cfg)
	}
	if err != nil {
		c.dev.Close()
		return fmt.Errorf("client config (%s): %w", mode, err)
	}
	if err := c.dev.IpcSet(ipc); err != nil {
		c.dev.Close()
		return fmt.Errorf("client IpcSet: %w", err)
	}
	if err := c.dev.Up(); err != nil {
		c.dev.Close()
		return fmt.Errorf("client up: %w", err)
	}

	if config.IsCarrierMode(mode) {
		hash, err := c.carrierInfoHash()
		if err != nil {
			c.dev.Close()
			return fmt.Errorf("carrier infohash: %w", err)
		}
		infoHash, err := awg.InfoHashBytes(hash)
		if err != nil {
			c.dev.Close()
			return fmt.Errorf("config infohash: %w", err)
		}
		if c.cfg.CarrierEndpoint != "" {
			ap, err := netip.ParseAddrPort(c.cfg.CarrierEndpoint)
			if err != nil || !ap.Addr().Is4() || ap.Addr().IsUnspecified() || ap.Port() == 0 {
				c.dev.Close()
				return fmt.Errorf("invalid carrier endpoint %q", c.cfg.CarrierEndpoint)
			}
			c.disc = func(context.Context) ([]netip.AddrPort, error) { return []netip.AddrPort{ap}, nil }
			return nil
		}
		c.disc = func(ctx context.Context) ([]netip.AddrPort, error) {
			return dht.Discover(ctx, infoHash, c.cfg.DHTBootstrap)
		}
	}
	return nil
}

// carrierInfoHash returns the infohash to use for the selected carrier mode.
// It prefers an explicit entry in CarrierHashes and falls back to the legacy
// base InfoHash for backward compatibility.
func (c *Client) carrierInfoHash() (string, error) {
	mode := c.cfg.Transport
	if h := c.cfg.CarrierHashes[mode]; h != "" {
		if _, err := awg.InfoHashBytes(h); err != nil {
			return "", fmt.Errorf("invalid carrier hash for %s: %w", mode, err)
		}
		return h, nil
	}
	return c.cfg.InfoHash, nil
}

// SetDiscovery replaces endpoint selection for an integration test.
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

// Run serves the local SOCKS5 and keeps the data path alive. In carrier modes
// it discovers the hub via DHT and reconnects on failure; in native modes it
// relies on the direct UDP endpoint configured in the import string.
func (c *Client) Run(ctx context.Context) error {
	listenIP := c.cfg.SocksListenIP
	if !listenIP.IsValid() {
		listenIP = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(listenIP.String(), strconv.Itoa(c.cfg.SocksPort)))
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

	if config.IsNativeMode(c.cfg.Transport) {
		<-ctx.Done()
		return nil
	}

	serverEp := carrierbind.Endpoint(serverIP)
	hash, _ := c.carrierInfoHash()
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
			return fmt.Errorf("dht discovery: %v (infohash %s)", discErr, hash)
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
		c.bind.(*carrierbind.Bind).Attach(serverEp, t)
		var key device.NoisePublicKey
		if key.FromHex(c.cfg.ServerPubKey) == nil {
			if peer := c.dev.LookupPeer(key); peer != nil {
				peer.SendKeepalive()
			}
		}
		select {
		case <-t.Done():
			c.bind.(*carrierbind.Bind).Detach(serverEp)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(retryDelay):
			}
		case <-ctx.Done():
			c.bind.(*carrierbind.Bind).Detach(serverEp)
			return nil
		}
	}
}

// connectCarrier dials the hub's carrier address over
// the host network and performs the BitTorrent handshake. This dial never
// goes through the tunnel: the carrier IS the tunnel's transport.
func (c *Client) connectCarrier(ctx context.Context, addr netip.AddrPort) (carrier.Transport, error) {
	hash, err := c.carrierInfoHash()
	if err != nil {
		return nil, err
	}
	infoHash, err := awg.InfoHashBytes(hash)
	if err != nil {
		return nil, err
	}
	peerID, err := awg.PeerIDBytes(awg.PeerID(c.cfg.ClientPubKey))
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	var closeSocket func() error
	switch c.cfg.Transport {
	case config.ModeExtUTP, config.ModeReqUTP:
		pc, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, fmt.Errorf("carrier udp: %w", err)
		}
		sock, err := carrier.NewUTPSocket(pc)
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("carrier utp socket: %w", err)
		}
		conn, err = sock.DialTimeout(addr.String(), 10*time.Second)
		if err != nil {
			sock.Close()
			return nil, fmt.Errorf("carrier dial %s: %w", addr, err)
		}
		closeSocket = sock.Close
	case config.ModeExtTCP, config.ModeReqTCP:
		d := net.Dialer{Control: carrier.TCPControl}
		conn, err = d.DialContext(ctx, "tcp", addr.String())
		if err != nil {
			return nil, fmt.Errorf("carrier dial %s: %w", addr, err)
		}
	default:
		return nil, fmt.Errorf("unknown transport %q", c.cfg.Transport)
	}
	var t carrier.Transport
	switch c.cfg.Transport {
	case config.ModeExtUTP, config.ModeExtTCP:
		t, _, err = carrier.NewExtended(conn, infoHash, peerID)
	case config.ModeReqUTP, config.ModeReqTCP:
		t, _, err = carrier.NewRequestPiece(conn, infoHash, peerID, false)
	}
	if err != nil {
		conn.Close()
		if closeSocket != nil {
			closeSocket()
		}
		return nil, fmt.Errorf("carrier handshake: %w", err)
	}
	if closeSocket != nil {
		go func() {
			<-t.Done()
			closeSocket()
		}()
	}
	return t, nil
}

// Close tears the client down.
func (c *Client) Close() {
	c.bind.Close()
	c.dev.Close()
	if c.ns != nil {
		// The netstack TUN is owned by the device; nothing extra to close.
		c.ns = nil
	}
}
