package e2e

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	anadht "github.com/anacrolix/dht/v2"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/dht"
	"bittorrent-tunnel/btawg/internal/server"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/store"
)

// clientSpec describes a client to register in the hub store before the
// server boots. An explicit empty VisiblePeers slice means "isolated".
type clientSpec struct {
	id           string
	ip           string
	noInternet   bool
	visiblePeers []string
}

// newRelay starts a bare DHT node standing in for the public network.
func newRelay(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	srv, err := anadht.NewServer(&anadht.ServerConfig{
		Conn:       conn,
		NoSecurity: true,
		PeerStore:  dht.NewMemStore(),
		StartingNodes: func() ([]anadht.Addr, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("relay server: %v", err)
	}
	t.Cleanup(srv.Close)
	return conn.LocalAddr().String()
}

// hubWithClients builds the hub with a set of registered clients and returns
// the running server, the open store, and the generated records. Records are
// created in the store before server.New so the initial policy snapshot and
// AWG peer configuration include every client.
func hubWithClients(t *testing.T, ctx context.Context, relay string, specs []clientSpec, transport string) (*server.Server, *store.Store, []*store.ClientRecord) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/hub.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	recs := make([]*store.ClientRecord, len(specs))
	for i, spec := range specs {
		priv, pub, err := awg.GenerateKeyPair()
		if err != nil {
			t.Fatalf("client key for %s: %v", spec.id, err)
		}
		rec := &store.ClientRecord{
			ID:           spec.id,
			Name:         spec.id,
			PubKey:       pub,
			PrivKey:      priv,
			IP:           spec.ip,
			PeerID:       awg.PeerID(pub),
			Created:      time.Unix(1, 0),
			NoInternet:   spec.noInternet,
			VisiblePeers: spec.visiblePeers,
		}
		if err := st.CreateClient(*rec); err != nil {
			t.Fatalf("create client %s: %v", spec.id, err)
		}
		recs[i] = rec
	}

	hubCfg := config.DefaultServerConfig()
	hubCfg.Transport = transport
	hubCfg.CarrierPort = 17781
	hubCfg.AWGPort, hubCfg.WGPort = 17807, 17808
	hubCfg.ExternalIP = "127.0.0.1"

	srv, err := server.New(hubCfg, st)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	srv.SetDHTBootstrap([]string{relay})
	go srv.Run(ctx)
	go srv.Announce(ctx)
	return srv, st, recs
}

func clientConfigFor(srv *server.Server, rec *store.ClientRecord, relay, ip string) config.ClientConfig {
	return config.ClientConfig{
		Version:       config.ClientVersion,
		InfoHash:      srv.InfoHash(),
		ServerPubKey:  srv.PubKey(),
		ClientPrivKey: rec.PrivKey,
		ClientPubKey:  rec.PubKey,
		ClientIP:      ip,
		Subnet:        "10.77.0.0/24",
		ServerIP:      "10.77.0.1",
		Transport:     srv.Config().Transport,
		SocksPort:     0,
		EgressPort:    1080,
		Profile:       config.DefaultProfile(),
		DHTBootstrap:  []string{relay},
	}
}

// waitConnected blocks until the hub reports at least one carrier attached
// for the given overlay IP.
func waitConnected(t *testing.T, srv *server.Server, ip string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ConnectedCount()[ip] > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("client %s never attached a carrier", ip)
}

// waitSocksAddr blocks until the client's local SOCKS5 listener is up.
func waitSocksAddr(t *testing.T, c *client.Client) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if a := c.SocksAddr(); a != "" {
			return a
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("client SOCKS5 never came up")
	return ""
}

// TestEndToEndSocksAndLan drives two clients through the product path:
// internet egress via each client's SOCKS5 (TCP CONNECT and UDP ASSOCIATE)
// and client-to-client reachability through the hub's forwarding.
func TestEndToEndSocksAndLan(t *testing.T) {
	for _, mode := range []string{"ext-utp", "ext-tcp", "req-utp", "req-tcp"} {
		t.Run(mode, func(t *testing.T) { testEndToEndSocksAndLan(t, mode) })
	}
}

func testEndToEndSocksAndLan(t *testing.T, mode string) {
	relay := newRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	srv, _, recs := hubWithClients(t, ctx, relay, []clientSpec{
		{id: "e2e-a", ip: "10.77.0.2"},
		{id: "e2e-b", ip: "10.77.0.3"},
	}, mode)
	recA, recB := recs[0], recs[1]

	ca, err := client.New(clientConfigFor(srv, recA, relay, "10.77.0.2"))
	if err != nil {
		t.Fatalf("client a: %v", err)
	}
	t.Cleanup(ca.Close)
	go ca.Run(ctx)

	cb, err := client.New(clientConfigFor(srv, recB, relay, "10.77.0.3"))
	if err != nil {
		t.Fatalf("client b: %v", err)
	}
	t.Cleanup(cb.Close)
	go cb.Run(ctx)

	socksA := waitSocksAddr(t, ca)
	socksB := waitSocksAddr(t, cb)

	// Loopback TCP and UDP endpoints live on the hub, not on the Internet.
	// A connected client must not be able to use SOCKS to reach either.
	deadline := time.Now().Add(20 * time.Second)
	for _, ip := range []string{"10.77.0.2", "10.77.0.3"} {
		waitConnected(t, srv, ip)
	}
	for _, addr := range []string{tcpEcho(t), "localhost:1"} {
		dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		conn, e := socks.NewClient(socksA).Dial(dialCtx, "tcp", addr)
		stop()
		if e == nil {
			conn.Close()
			t.Fatalf("proxy accepted non-Internet target %s", addr)
		}
	}
	udp := udpEcho(t)
	pc, err := socks.NewClient(socksB).DialUDP(ctx)
	if err != nil {
		t.Fatalf("udp associate: %v", err)
	}
	defer pc.Close()
	if _, err = pc.WriteTo([]byte("must not reach hub loopback"), udp); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err = pc.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("UDP loopback echo leaked through proxy")
	}

	// --- Client-to-client: B dials A's overlay address directly (never
	// SOCKS5, never the egress); the hub forwards between the carriers.
	lanLn, err := ca.OverlayListenTCP(9001)
	if err != nil {
		t.Fatalf("lan listen: %v", err)
	}
	defer lanLn.Close()
	go func() {
		for {
			c, err := lanLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				c.Write([]byte("accepted:"))
				c.SetWriteDeadline(time.Time{})
				copyEcho(c)
			}()
		}
	}()
	var lanConn net.Conn
	for lanConn == nil {
		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
		lanConn, err = cb.OverlayDialTCP(dialCtx, netip.MustParseAddrPort("10.77.0.2:9001"))
		dialCancel()
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("lan dial never succeeded: %v", err)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	defer lanConn.Close()
	// First read the accept marker: this isolates the hub->A->hub->B data
	// return path from the echo itself.
	lanConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	marker := make([]byte, len("accepted:"))
	if _, err := readFull(lanConn, marker); err != nil {
		t.Fatalf("lan accept marker: %v", err)
	}
	if string(marker) != "accepted:" {
		t.Fatalf("lan marker = %q", marker)
	}
	if _, err := lanConn.Write([]byte("lan")); err != nil {
		t.Fatalf("lan write: %v", err)
	}
	lanConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	lbuf := make([]byte, len("lan"))
	if _, err := readFull(lanConn, lbuf); err != nil {
		t.Fatalf("lan read: %v", err)
	}
	if string(lbuf) != "lan" {
		t.Fatalf("lan echo = %q", lbuf)
	}
}

// TestRuntimeRegistration proves that a client registered after server.New
// (the panel create path) is immediately usable: its chained internet egress
// works and it can reach permitted overlay peers without any restart or
// explicit policy reload.
func TestRuntimeRegistration(t *testing.T) {
	relay := newRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	srv, st, recs := hubWithClients(t, ctx, relay, []clientSpec{
		{id: "e2e-a", ip: "10.77.0.2"},
	}, "ext-utp")
	recA := recs[0]

	// Bring client A online in the normal pre-registered path.
	ca, err := client.New(clientConfigFor(srv, recA, relay, "10.77.0.2"))
	if err != nil {
		t.Fatalf("client a: %v", err)
	}
	t.Cleanup(ca.Close)
	go ca.Run(ctx)
	_ = waitSocksAddr(t, ca)
	waitConnected(t, srv, "10.77.0.2")

	// Register client B at runtime, exactly like the panel does.
	bPriv, bPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("B key: %v", err)
	}
	recB := &store.ClientRecord{
		ID:      "e2e-b",
		Name:    "e2e-b",
		PubKey:  bPub,
		PrivKey: bPriv,
		IP:      "10.77.0.3",
		PeerID:  awg.PeerID(bPub),
		Created: time.Unix(1, 0),
	}
	if err := st.CreateClient(*recB); err != nil {
		t.Fatalf("create B in store: %v", err)
	}
	if err := srv.RegisterClient(*recB); err != nil {
		t.Fatalf("runtime register B: %v", err)
	}

	cb, err := client.New(clientConfigFor(srv, recB, relay, "10.77.0.3"))
	if err != nil {
		t.Fatalf("client b: %v", err)
	}
	t.Cleanup(cb.Close)
	go cb.Run(ctx)
	waitConnected(t, srv, "10.77.0.3")

	// B can reach A over the overlay (mutual visibility by default).
	// A needs one authenticated data packet to activate its return path.
	ready, err := ca.OverlayDialTCP(ctx, netip.MustParseAddrPort("10.77.0.1:1080"))
	if err != nil {
		t.Fatal(err)
	}
	ready.Close()
	lanALn, err := ca.OverlayListenTCP(9004)
	if err != nil {
		t.Fatalf("A lan listen: %v", err)
	}
	defer lanALn.Close()
	go func() {
		for {
			c, err := lanALn.Accept()
			if err != nil {
				return
			}
			go copyEcho(c)
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 20*time.Second)
	baConn, err := cb.OverlayDialTCP(dialCtx, netip.MustParseAddrPort("10.77.0.2:9004"))
	dialCancel()
	if err != nil {
		t.Fatalf("B dial A: %v", err)
	}
	defer baConn.Close()
	if _, err := baConn.Write([]byte("b-to-a")); err != nil {
		t.Fatalf("B write A: %v", err)
	}
	baConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	bbuf := make([]byte, len("b-to-a"))
	if _, err := readFull(baConn, bbuf); err != nil {
		t.Fatalf("B read A: %v", err)
	}
	if string(bbuf) != "b-to-a" {
		t.Fatalf("B<->A echo = %q", bbuf)
	}
}

// TestPolicyIsolationLive proves hub-enforced routing policy end-to-end:
func TestPolicyIsolationLive(t *testing.T) {
	relay := newRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	srv, st, recs := hubWithClients(t, ctx, relay, []clientSpec{
		{id: "e2e-a", ip: "10.77.0.2"},
		{id: "e2e-b", ip: "10.77.0.3", noInternet: true},
		{id: "e2e-c", ip: "10.77.0.4", visiblePeers: []string{}},
	}, "ext-utp")
	recA, recB, recC := recs[0], recs[1], recs[2]

	ca, err := client.New(clientConfigFor(srv, recA, relay, "10.77.0.2"))
	if err != nil {
		t.Fatalf("client a: %v", err)
	}
	t.Cleanup(ca.Close)
	go ca.Run(ctx)

	cb, err := client.New(clientConfigFor(srv, recB, relay, "10.77.0.3"))
	if err != nil {
		t.Fatalf("client b: %v", err)
	}
	t.Cleanup(cb.Close)
	go cb.Run(ctx)

	cc, err := client.New(clientConfigFor(srv, recC, relay, "10.77.0.4"))
	if err != nil {
		t.Fatalf("client c: %v", err)
	}
	t.Cleanup(cc.Close)
	go cc.Run(ctx)

	socksB := waitSocksAddr(t, cb)
	_ = waitSocksAddr(t, cc)

	echoAddr := tcpEcho(t)

	// --- A can reach B over the overlay (mutual visibility by default).
	lanBLn, err := cb.OverlayListenTCP(9002)
	if err != nil {
		t.Fatalf("b lan listen: %v", err)
	}
	defer lanBLn.Close()
	go func() {
		for {
			c, err := lanBLn.Accept()
			if err != nil {
				return
			}
			go copyEcho(c)
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 20*time.Second)
	abConn, err := ca.OverlayDialTCP(dialCtx, netip.MustParseAddrPort("10.77.0.3:9002"))
	dialCancel()
	if err != nil {
		t.Fatalf("A dial B: %v", err)
	}
	defer abConn.Close()
	if _, err := abConn.Write([]byte("a-to-b")); err != nil {
		t.Fatalf("A write B: %v", err)
	}
	abConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	abuf := make([]byte, len("a-to-b"))
	if _, err := readFull(abConn, abuf); err != nil {
		t.Fatalf("A read B: %v", err)
	}
	if string(abuf) != "a-to-b" {
		t.Fatalf("A<->B echo = %q", abuf)
	}

	// --- A cannot reach C: C's VisiblePeers is empty, so the filter silently
	// drops the packets. The dial must time out, not return a clean error.
	// No listener is started on C here; even a closed-port dial would normally
	// get RST, but the filter drop makes it time out instead.
	dialCtx, dialCancel = context.WithTimeout(ctx, 5*time.Second)
	start := time.Now()
	_, err = ca.OverlayDialTCP(dialCtx, netip.MustParseAddrPort("10.77.0.4:9003"))
	dialCancel()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("A dial C succeeded, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("A dial C error = %v (%T), want context.DeadlineExceeded", err, err)
	}
	if elapsed > 6*time.Second {
		t.Fatalf("A dial C took %v, expected bounded ~5s timeout", elapsed)
	}

	// --- B's chained internet egress is closed by the egress gate.
	appB := socks.NewClient(socksB)
	failStart := time.Now()
	dialCtx, dialCancel = context.WithTimeout(ctx, 5*time.Second)
	_, err = appB.Dial(dialCtx, "tcp", echoAddr)
	dialCancel()
	failElapsed := time.Since(failStart)
	if err == nil {
		t.Fatal("B chained egress succeeded, want failure")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("B chained egress timed out, want fast close: %v", err)
	}
	if failElapsed > 4*time.Second {
		t.Fatalf("B chained egress took %v, want fast close", failElapsed)
	}

	// --- B can still send packets to the hub itself (dst == serverIP passes
	// the filter). The TCP connect succeeds, but the egress gate closes it.
	serverEgress := netip.AddrPortFrom(netip.MustParseAddr(srv.Config().ServerIP), uint16(srv.Config().SocksPort))
	dialCtx, dialCancel = context.WithTimeout(ctx, 20*time.Second)
	hubConn, err := cb.OverlayDialTCP(dialCtx, serverEgress)
	dialCancel()
	if err != nil {
		t.Fatalf("B dial hub egress: %v", err)
	}
	defer hubConn.Close()
	hubConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := hubConn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("B hub read = %v, want io.EOF", err)
	}

	// --- Live flip: make C visible to everyone, reload policy, and verify
	// A reaches C without restarting the server.
	recC2, err := st.GetClient(recC.ID)
	if err != nil {
		t.Fatalf("get C for update: %v", err)
	}
	recC2.VisiblePeers = []string{"*"}
	if err := st.DeleteClient(recC.ID); err != nil {
		t.Fatalf("delete old C record: %v", err)
	}
	if err := st.CreateClient(recC2); err != nil {
		t.Fatalf("create updated C record: %v", err)
	}
	if err := srv.ReloadPolicy(); err != nil {
		t.Fatalf("reload policy: %v", err)
	}

	// Start C's listener only after the policy flip so the pre-flip isolation
	// test cannot leave a stale connection in the accept queue.
	lanCLn, err := cc.OverlayListenTCP(9003)
	if err != nil {
		t.Fatalf("c lan listen: %v", err)
	}
	defer lanCLn.Close()
	go func() {
		for {
			c, err := lanCLn.Accept()
			if err != nil {
				return
			}
			go copyEcho(c)
		}
	}()

	var acConn net.Conn
	flipDeadline := time.Now().Add(10 * time.Second)
	for acConn == nil {
		dialCtx, dialCancel = context.WithTimeout(ctx, 5*time.Second)
		acConn, err = ca.OverlayDialTCP(dialCtx, netip.MustParseAddrPort("10.77.0.4:9003"))
		dialCancel()
		if err != nil {
			if time.Now().After(flipDeadline) {
				t.Fatalf("A dial C after flip: %v", err)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	defer acConn.Close()
	if _, err := acConn.Write([]byte("a-to-c-live")); err != nil {
		t.Fatalf("A write C after flip: %v", err)
	}
	acConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	cbuf := make([]byte, len("a-to-c-live"))
	if _, err := readFull(acConn, cbuf); err != nil {
		t.Fatalf("A read C after flip: %v", err)
	}
	if string(cbuf) != "a-to-c-live" {
		t.Fatalf("A<->C echo after flip = %q", cbuf)
	}
}

// --- helpers ---

func tcpEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				copyEcho(c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func udpEcho(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteToUDP(buf[:n], from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr()
}

func copyEcho(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if _, err := c.Write(buf[:n]); err != nil {
			return
		}
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	return io.ReadFull(conn, buf)
}
