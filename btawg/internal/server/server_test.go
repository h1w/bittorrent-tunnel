package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	utp "github.com/anacrolix/go-utp"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/store"
)

// TestServerClientEcho drives the hub end to end over an extended µTP
// carrier: one registered client AWG device connects through the carrier
// listener, completes the AWG handshake, and exchanges a UDP echo with a
// listener inside the server's overlay netstack.
func TestServerClientEcho(t *testing.T) {

	st, err := store.Open(t.TempDir() + "/hub.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	cfg.Transport = "ext-utp"
	cfg.CarrierPort = 17777

	clientPriv, clientPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	rec := store.ClientRecord{
		ID:      "c1",
		Name:    "smoke",
		PubKey:  clientPub,
		PrivKey: clientPriv,
		IP:      "10.77.0.2",
		PeerID:  awg.PeerID(clientPub),
		Created: time.Unix(1, 0),
	}
	if err := st.CreateClient(rec); err != nil {
		t.Fatalf("create client: %v", err)
	}

	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	if len(srv.InfoHash()) != 40 {
		t.Fatalf("infohash %q is not 20 bytes", srv.InfoHash())
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Run(ctx)

	// UDP echo inside the server's overlay.
	echoLn, err := srv.OverlayNet().ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:9000"))
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echoLn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := echoLn.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()

	// Client AWG device over its own netstack, routed through one carrier.
	clientIP := netip.MustParseAddr("10.77.0.2")
	serverIP := netip.MustParseAddr("10.77.0.1")
	cb := bind.New()
	ct, cn, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}
	cd := device.NewDevice(ct, cb, device.NewLogger(device.LogLevelError, "client: "))
	t.Cleanup(func() { cd.Close() })
	ccfg := config.ClientConfig{
		Version:       config.ClientVersion,
		InfoHash:      srv.InfoHash(),
		ServerPubKey:  srv.PubKey(),
		ClientPrivKey: clientPriv,
		ClientPubKey:  clientPub,
		ClientIP:      "10.77.0.2",
		Subnet:        "10.77.0.0/24",
		ServerIP:      "10.77.0.1",
		Transport:     "ext-utp",
		SocksPort:     1080,
		EgressPort:    1080,
		Profile:       config.DefaultProfile(),
	}
	if err := cd.IpcSet(awg.ClientConf(ccfg)); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := cd.Up(); err != nil {
		t.Fatalf("client up: %v", err)
	}

	// Dial the carrier: µTP over loopback to the hub's carrier port.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client udp: %v", err)
	}
	t.Cleanup(func() { udp.Close() })
	sock, err := utp.NewSocketFromPacketConn(udp,
		utp.WithTargetDelay(5*time.Millisecond),
		utp.WithBufferSizes(65536, 65536))
	if err != nil {
		t.Fatalf("client utp socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() })
	conn, err := sock.DialTimeout("127.0.0.1:17777", 5*time.Second)
	if err != nil {
		t.Fatalf("carrier dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	infoHash, err := awg.InfoHashBytes(srv.InfoHash())
	if err != nil {
		t.Fatalf("parse infohash: %v", err)
	}
	peerID, err := awg.PeerIDBytes(rec.PeerID)
	if err != nil {
		t.Fatalf("parse peer id: %v", err)
	}
	tcar, _, err := carrier.NewExtended(conn, infoHash, peerID)
	if err != nil {
		t.Fatalf("carrier handshake: %v", err)
	}
	cb.Attach(bind.Endpoint(serverIP), tcar)

	// Dial the echo socket and send a first ping: outgoing traffic is what
	// makes wireguard-go initiate the AWG handshake.
	cli, err := cn.DialUDPAddrPort(netip.AddrPortFrom(clientIP, 0), netip.MustParseAddrPort("10.77.0.1:9000"))
	if err != nil {
		t.Fatalf("client dial echo: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	if _, err := cli.WriteTo([]byte("ping"), nil); err != nil {
		t.Fatalf("echo write: %v", err)
	}

	// Wait for the authenticated AWG handshake on the client device.
	ok := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, err := cd.IpcGet()
		if err != nil {
			t.Fatalf("client IpcGet: %v", err)
		}
		var sec int64
		for _, line := range strings.Split(state, "\n") {
			if _, err := fmt.Sscanf(line, "last_handshake_time_sec=%d", &sec); err == nil && sec > 0 {
				ok = true
				break
			}
		}
		if ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Fatal("no authenticated AWG handshake within 10s")
	}
	if got := srv.ConnectedCount()["10.77.0.2"]; got < 1 {
		t.Fatalf("server reports %d carriers for the client, want >= 1", got)
	}

	// UDP echo through the tunnel (the session is up; this ping returns).
	if _, err := cli.WriteTo([]byte("ping"), nil); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("echo = %q, want ping", buf[:n])
	}
}

// TestRegisterClientUpdatesSnapshot proves that runtime registration (panel
// create) and revocation immediately update the in-memory policy snapshot
// without requiring a server restart or policy reload.
func TestRegisterClientUpdatesSnapshot(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/snapshot.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	cfg.ServerIP = "10.77.0.1"
	cfg.CarrierPort = 17779

	aPriv, aPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("A key: %v", err)
	}
	a := store.ClientRecord{
		ID:      "A",
		Name:    "client-a",
		IP:      "10.77.0.2",
		PubKey:  aPub,
		PrivKey: aPriv,
		PeerID:  awg.PeerID(aPub),
		Created: time.Unix(1, 0),
	}
	if err := st.CreateClient(a); err != nil {
		t.Fatalf("create A: %v", err)
	}

	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	aIP := netip.MustParseAddr("10.77.0.2")
	bIP := netip.MustParseAddr("10.77.0.3")
	if srv.policy.clientCanReach(aIP, bIP) {
		t.Fatalf("A -> B: want false before runtime registration")
	}

	bPriv, bPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("B key: %v", err)
	}
	b := store.ClientRecord{
		ID:      "B",
		Name:    "client-b",
		IP:      "10.77.0.3",
		PubKey:  bPub,
		PrivKey: bPriv,
		PeerID:  awg.PeerID(bPub),
		Created: time.Unix(1, 0),
	}
	if err := srv.RegisterClient(b); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if !srv.policy.clientCanReach(aIP, bIP) {
		t.Errorf("A -> B after register: want true, got false")
	}
	if !srv.policy.clientCanReach(bIP, aIP) {
		t.Errorf("B -> A after register: want true, got false")
	}
	if !srv.policy.internetFor(bIP) {
		t.Errorf("internetFor(B): want true, got false")
	}

	if err := srv.RevokeClient(b); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	if srv.policy.clientCanReach(aIP, bIP) {
		t.Errorf("A -> B after revoke: want false, got true")
	}
	if srv.policy.internetFor(bIP) {
		t.Errorf("internetFor(B) after revoke: want false, got true")
	}
}

// stubResolver is a hostResolver that returns a fixed set of IPs.
type stubResolver struct {
	ips []net.IP
	err error
}

func (s stubResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return s.ips, s.err
}

// TestEgressDialRejectsOverlay proves the real-TUN-shaped egress TCP dialer
// refuses to proxy connections back into the overlay subnet for both literal
// IPs and hostnames that resolve to overlay IPs.
func TestEgressDialRejectsOverlay(t *testing.T) {
	prefix := netip.MustParsePrefix("10.77.0.0/24")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Literal overlay IP.
	dial := newEgressDialer(prefix, stubResolver{})
	if _, err := dial(ctx, "tcp", "10.77.0.2:1234"); err == nil {
		t.Fatal("dial to overlay IP succeeded, want refusal")
	}

	// Hostname that resolves to an overlay IP.
	dial = newEgressDialer(prefix, stubResolver{ips: []net.IP{net.ParseIP("10.77.0.2")}})
	if _, err := dial(ctx, "tcp", "host.example:1234"); err == nil {
		t.Fatal("dial to hostname resolving to overlay IP succeeded, want refusal")
	}

	// Non-overlay destination still works (stub resolves to the listener IP).
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	dial = newEgressDialer(prefix, stubResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	conn, err := dial(ctx, "tcp", net.JoinHostPort("ok.example", port))
	if err != nil {
		t.Fatalf("dial to non-overlay host: %v", err)
	}
	conn.Close()
}

// TestEgressUDPRejectsOverlay proves the egress UDP upstream refuses to send
// datagrams back into the overlay subnet.
func TestEgressUDPRejectsOverlay(t *testing.T) {
	prefix := netip.MustParsePrefix("10.77.0.0/24")
	pc, err := newEgressUDP(prefix)
	if err != nil {
		t.Fatalf("newEgressUDP: %v", err)
	}
	defer pc.Close()

	overlayDst, err := net.ResolveUDPAddr("udp", "10.77.0.3:53")
	if err != nil {
		t.Fatalf("resolve overlay: %v", err)
	}
	n, err := pc.WriteTo([]byte("x"), overlayDst)
	if err == nil {
		t.Fatalf("WriteTo overlay IP succeeded, want refusal")
	}
	if n != 0 {
		t.Fatalf("WriteTo overlay IP wrote %d bytes, want 0", n)
	}

	// Non-overlay destinations are still accepted by the wrapper.
	localDst, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("resolve local: %v", err)
	}
	if _, err := pc.WriteTo([]byte("x"), localDst); err != nil {
		t.Fatalf("WriteTo localhost: %v", err)
	}
}

// TestNewRealTUNRequiresRoot guards the hub real-TUN constructor. Without root
// the kernel TUN creation fails; the error must name the requested interface.
// When running as root the live path is validated manually instead.
func TestNewRealTUNRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root: live TUN creation would succeed")
	}
	st, err := store.Open(t.TempDir() + "/hub.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	cfg.Transport = "ext-tcp" // avoid carrier UDP setup on this error path
	tunName := "btawgroot0"
	_, err = NewRealTUN(cfg, st, tunName)
	if err == nil {
		t.Fatal("expected NewRealTUN to fail without root")
	}
	if !strings.Contains(err.Error(), tunName) {
		t.Fatalf("error %q does not name the TUN interface %q", err, tunName)
	}
}

// recordedWrite is one upstream UDP write captured by recordingPacketConn.
type recordedWrite struct {
	data []byte
	to   net.Addr
}

// recordingPacketConn is a fake net.PacketConn that records WriteTo calls and
// blocks on ReadFrom until closed.
type recordingPacketConn struct {
	mu     sync.Mutex
	writes chan recordedWrite
	closed chan struct{}
	local  net.Addr
}

func newRecordingPacketConn() *recordingPacketConn {
	return &recordingPacketConn{
		writes: make(chan recordedWrite, 16),
		closed: make(chan struct{}),
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999},
	}
}

func (r *recordingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-r.closed
	return 0, nil, net.ErrClosed
}

func (r *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.closed:
		return 0, net.ErrClosed
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	r.writes <- recordedWrite{data: buf, to: addr}
	return len(p), nil
}

func (r *recordingPacketConn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func (r *recordingPacketConn) LocalAddr() net.Addr  { return r.local }
func (r *recordingPacketConn) SetDeadline(t time.Time) error      { return nil }
func (r *recordingPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *recordingPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// buildSOCKSUDPHeader builds a minimal SOCKS5 UDP header for an IPv4 destination.
func buildSOCKSUDPHeader(dst *net.UDPAddr) []byte {
	b := []byte{0, 0, 0, 1}
	b = append(b, dst.IP.To4()...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(dst.Port))
	return append(b, p[:]...)
}

// TestUDPRelaySourceLock proves that a SOCKS5 UDP ASSOCIATE relay created by
// the hub only forwards datagrams from the overlay IP that owns the control
// connection. A second source (simulating a NoInternet client spraying the
// relay port) is dropped with no upstream write and no reply.
func TestUDPRelaySourceLock(t *testing.T) {
	allowed := netip.MustParseAddr("127.0.0.1")

	upstream := newRecordingPacketConn()
	srv := socks.NewServer(
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("no TCP egress in this test")
		},
		func(ctx context.Context) (net.PacketConn, error) { return upstream, nil },
	).WithRelayUDP(func(local, remote net.Addr) (net.PacketConn, error) {
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			return nil, err
		}
		return &sourceLockedRelay{PacketConn: pc, allow: allowed}, nil
	})

	c1, c2 := net.Pipe()
	ln := newFakeListener(1)
	ln.conns <- &connWithAddr{
		Conn:   c2,
		remote: net.TCPAddrFromAddrPort(netip.AddrPortFrom(allowed, 12345)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	// SOCKS5 greeting (no-auth).
	if _, err := c1.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	var gr [2]byte
	if _, err := io.ReadFull(c1, gr[:]); err != nil {
		t.Fatalf("greeting read: %v", err)
	}
	if gr[0] != 0x05 || gr[1] != 0x00 {
		t.Fatalf("greeting rejected: %v", gr)
	}

	// UDP ASSOCIATE request.
	if _, err := c1.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		t.Fatalf("associate write: %v", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(c1, head[:]); err != nil {
		t.Fatalf("associate reply head: %v", err)
	}
	if head[0] != 0x05 || head[1] != 0x00 || head[3] != 0x01 {
		t.Fatalf("associate rejected: %v", head)
	}
	body := make([]byte, 6)
	if _, err := io.ReadFull(c1, body[:]); err != nil {
		t.Fatalf("associate reply body: %v", err)
	}
	relayAddr := &net.UDPAddr{
		IP:   net.IPv4(body[0], body[1], body[2], body[3]),
		Port: int(binary.BigEndian.Uint16(body[4:6])),
	}

	dst := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	// Allowed source: same IP as the control connection.
	allowedSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("allowed socket: %v", err)
	}
	defer allowedSock.Close()
	frame := append(buildSOCKSUDPHeader(dst), []byte("allowed")...)
	if _, err := allowedSock.WriteTo(frame, relayAddr); err != nil {
		t.Fatalf("allowed write: %v", err)
	}
	select {
	case w := <-upstream.writes:
		if string(w.data) != "allowed" {
			t.Fatalf("upstream data = %q, want allowed", string(w.data))
		}
		if w.to.String() != dst.String() {
			t.Fatalf("upstream destination = %v, want %v", w.to, dst)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("allowed packet was not forwarded upstream")
	}

	// Disallowed source: another overlay IP spraying the relay port.
	disallowedSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatalf("disallowed socket: %v", err)
	}
	defer disallowedSock.Close()
	frame2 := append(buildSOCKSUDPHeader(dst), []byte("disallowed")...)
	if _, err := disallowedSock.WriteTo(frame2, relayAddr); err != nil {
		t.Fatalf("disallowed write: %v", err)
	}
	select {
	case w := <-upstream.writes:
		t.Fatalf("disallowed packet was forwarded upstream: %q", string(w.data))
	case <-time.After(300 * time.Millisecond):
	}

	// Closing the control connection tears the relay down.
	c1.Close()
}
