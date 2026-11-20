package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	utp "github.com/anacrolix/go-utp"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/bind"
	"bittorrent-tunnel/btawg/internal/carrier"
	"bittorrent-tunnel/btawg/internal/config"
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
	cfg.AWGPort, cfg.WGPort = 17801, 17802

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
	cfg.AWGPort, cfg.WGPort = 17803, 17804

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
	if err := st.CreateClient(b); err != nil {
		t.Fatal(err)
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
	public := netip.MustParseAddr("1.1.1.1")
	if !srv.policy.upload(bIP, public, true, 40, time.Now()) {
		t.Errorf("new client B cannot send routed Internet traffic")
	}

	if err := st.RevokeClient(b.ID); err != nil {
		t.Fatal(err)
	}
	if err := srv.RevokeClient(b); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	if srv.policy.clientCanReach(aIP, bIP) {
		t.Errorf("A -> B after revoke: want false, got true")
	}
	if srv.policy.upload(bIP, public, true, 40, time.Now()) {
		t.Errorf("revoked client B can still send routed Internet traffic")
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

// TestNewRealTUNLive runs the hub real-TUN constructor with full privileges
// and asserts the overlay address actually lands on the interface with its
// host bits intact. Regression guard for the Addr.Prefix masking bug where
// iproute2 silently assigned the network number (10.77.0.0) and the egress
// bind then failed with EADDRNOTAVAIL. Skipped without root; runnable
// rootless via `unshare -Urn go test ...`.
func TestNewRealTUNLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (or a user namespace): live TUN creation")
	}
	st, err := store.Open(t.TempDir() + "/hub.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	cfg.Transport = "ext-tcp"
	tunName := "btawglive0"
	s, err := NewRealTUN(cfg, st, tunName)
	if err != nil {
		t.Fatalf("NewRealTUN: %v", err)
	}
	defer s.Close()

	out, err := exec.Command("ip", "addr", "show", "dev", tunName).CombinedOutput()
	if err != nil {
		t.Fatalf("ip addr show: %v: %s", err, out)
	}
	if !strings.Contains(string(out), cfg.ServerIP+"/24") {
		t.Fatalf("tun %s missing %q, has:\n%s", tunName, cfg.ServerIP+"/24", out)
	}
}

func testServerWithClient(t *testing.T) (*Server, *store.Store, store.ClientRecord) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/flow.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	cfg.CarrierPort = 18777
	cfg.AWGPort, cfg.WGPort = 18801, 18802

	clientPriv, clientPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	rec := store.ClientRecord{
		ID:      "c1",
		Name:    "flow-client",
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
	return srv, st, rec
}

// TestReverseFlowPinnedToIngressEngine proves that when a client sends a
// packet through one mode's engine, the reverse flow returns to that same
// engine even if the per-IP primary route points elsewhere.
func TestReverseFlowPinnedToIngressEngine(t *testing.T) {
	srv, _, rec := testServerWithClient(t)
	clientIP := netip.MustParseAddr(rec.IP)
	gatewayIP := netip.MustParseAddr(srv.cfg.ServerIP)

	extTCP := srv.router.engines[config.ModeExtTCP]
	extUTP := srv.router.engines[config.ModeExtUTP]
	if extTCP == nil || extUTP == nil {
		t.Fatal("missing per-mode engines")
	}

	// Make extUTP the primary route for the client IP.
	srv.router.remember(clientIP, extUTP, time.Now().UnixNano())

	// Client sends through extTCP. This should pin the reverse flow to extTCP.
	fwd := makeTCPPacket(clientIP.String(), gatewayIP.String(), 12345, 443)
	if _, err := extTCP.Write([][]byte{fwd}, 0); err != nil {
		t.Fatalf("extTCP Write: %v", err)
	}

	// Verify the flow table pinned the reverse to extTCP.
	fwdKey, _ := flowKeyFromPacket(fwd)
	revKey := fwdKey.reverse()
	if pinned, ok := srv.router.flows.lookup(revKey, time.Now()); !ok || pinned != extTCP {
		t.Fatalf("reverse flow not pinned to extTCP: %v %v", pinned, ok)
	}

	// Gateway replies. lookupDestinationEngine must return extTCP even though
	// the primary route is extUTP.
	rev := makeTCPPacket(gatewayIP.String(), clientIP.String(), 443, 12345)
	eng := srv.router.lookupDestinationEngine(gatewayIP, clientIP, rev, time.Now())
	if eng != extTCP {
		t.Fatalf("reverse flow routed to %v, want extTCP", eng)
	}

	// The queued packet must be accepted by extTCP.Read and rejected by extUTP.
	pktBuf := make([]byte, len(rev)+tunOffset)
	copy(pktBuf[tunOffset:], rev)
	if !extTCP.enqueue(pktBuf[:len(rev)+tunOffset]) {
		t.Fatal("extTCP enqueue failed")
	}
	out := make([][]byte, 1)
	out[0] = make([]byte, 2048)
	sizes := make([]int, 1)
	if _, err := extTCP.Read(out, sizes, 0); err != nil || sizes[0] != len(rev) || !bytes.Equal(out[0][:sizes[0]], rev) {
		t.Fatalf("extTCP.Read did not deliver reverse packet: err=%v sizes=%d", err, sizes[0])
	}

	// extUTP must reject the packet because it is not the flow owner.
	pktBuf2 := make([]byte, len(rev)+tunOffset)
	copy(pktBuf2[tunOffset:], rev)
	if !extUTP.enqueue(pktBuf2[:len(rev)+tunOffset]) {
		t.Fatal("extUTP enqueue failed")
	}
	out[0] = make([]byte, 2048)
	sizes[0] = 0
	done := make(chan struct{})
	go func() {
		extUTP.Read(out, sizes, 0)
		close(done)
	}()
	select {
	case <-done:
		if sizes[0] > 0 {
			t.Fatal("extUTP accepted a packet owned by extTCP")
		}
	case <-time.After(200 * time.Millisecond):
	}
}

// TestStaleModeClosureReleasesFlows verifies that closing a mode's engine
// invalidates its pinned flows, so traffic falls back to the current primary
// route instead of being black-holed on a dead engine.
func TestStaleModeClosureReleasesFlows(t *testing.T) {
	srv, _, rec := testServerWithClient(t)
	clientIP := netip.MustParseAddr(rec.IP)
	gatewayIP := netip.MustParseAddr(srv.cfg.ServerIP)

	extTCP := srv.router.engines[config.ModeExtTCP]
	extUTP := srv.router.engines[config.ModeExtUTP]

	// Establish a flow on extTCP.
	fwd := makeTCPPacket(clientIP.String(), gatewayIP.String(), 12345, 443)
	if _, err := extTCP.Write([][]byte{fwd}, 0); err != nil {
		t.Fatalf("extTCP Write: %v", err)
	}

	// Close extTCP and make extUTP the primary route.
	if err := extTCP.Close(); err != nil {
		t.Fatalf("extTCP Close: %v", err)
	}
	srv.router.remember(clientIP, extUTP, time.Now().UnixNano())

	// Gateway reply should fall back to extUTP now that extTCP is gone.
	rev := makeTCPPacket(gatewayIP.String(), clientIP.String(), 443, 12345)
	eng := srv.router.lookupDestinationEngine(gatewayIP, clientIP, rev, time.Now())
	if eng != extUTP {
		t.Fatalf("reverse flow routed to %v after extTCP close, want extUTP", eng)
	}
}

// TestUnauthenticatedSessionCannotSpoof proves that a TLS engine whose
// authSource is one client cannot pin flows using a different client's source
// address.
func TestUnauthenticatedSessionCannotSpoof(t *testing.T) {
	srv, st, rec := testServerWithClient(t)
	clientIP := netip.MustParseAddr(rec.IP)
	otherIP := netip.MustParseAddr("10.77.0.3")

	// Create a second client record.
	otherPriv, otherPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	other := store.ClientRecord{
		ID:      "c2",
		Name:    "other",
		PubKey:  otherPub,
		PrivKey: otherPriv,
		IP:      otherIP.String(),
		PeerID:  awg.PeerID(otherPub),
		Created: time.Unix(1, 0),
	}
	if err := st.CreateClient(other); err != nil {
		t.Fatalf("create other: %v", err)
	}
	if err := srv.RegisterClient(other); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	// A TLS engine authenticated as the first client.
	eng := srv.router.newEngine(clientIP)
	defer eng.Close()

	// Attempt to send a packet spoofing the second client.
	spoof := makeTCPPacket(otherIP.String(), clientIP.String(), 12345, 443)
	if _, err := eng.Write([][]byte{spoof}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// No flow should be pinned for the spoofed source.
	key, _ := flowKeyFromPacket(spoof)
	if _, ok := srv.router.flows.lookup(key.reverse(), time.Now()); ok {
		t.Fatal("unauthenticated engine pinned a spoofed flow")
	}
}
