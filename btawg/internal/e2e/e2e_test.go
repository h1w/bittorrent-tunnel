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
func hubWithClients(t *testing.T, ctx context.Context, relay string, specs []clientSpec) (*server.Server, *store.Store, []*store.ClientRecord) {
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
	hubCfg.Transport = "ext-utp"
	hubCfg.CarrierPort = 17781
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
		Transport:     "ext-utp",
		SocksPort:     0,
		EgressPort:    1080,
		Profile:       config.DefaultProfile(),
		DHTBootstrap:  []string{relay},
	}
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
	relay := newRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	srv, _, recs := hubWithClients(t, ctx, relay, []clientSpec{
		{id: "e2e-a", ip: "10.77.0.2"},
		{id: "e2e-b", ip: "10.77.0.3"},
	})
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

	// --- Internet egress via client A's SOCKS5: TCP CONNECT through the chain.
	echoAddr := tcpEcho(t)
	app := socks.NewClient(socksA)
	var conn net.Conn
	deadline := time.Now().Add(20 * time.Second)
	for conn == nil {
		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err = app.Dial(dialCtx, "tcp", echoAddr)
		dialCancel()
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("egress dial never succeeded: %v", err)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if _, err := conn.Write([]byte("internet")); err != nil {
		t.Fatalf("egress write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len("internet"))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("egress read: %v", err)
	}
	if string(buf) != "internet" {
		t.Fatalf("egress echo = %q", buf)
	}
	conn.Close()

	// --- Domain egress: a CONNECT carrying a hostname must resolve at the
	// hub (DNS-at-hub), never on the client.
	_, echoPort, _ := net.SplitHostPort(echoAddr)
	dconn, err := app.Dial(ctx, "tcp", "localhost:"+echoPort)
	if err != nil {
		t.Fatalf("domain egress dial: %v", err)
	}
	defer dconn.Close()
	if _, err := dconn.Write([]byte("byname")); err != nil {
		t.Fatalf("domain egress write: %v", err)
	}
	dconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	dbuf := make([]byte, len("byname"))
	if _, err := readFull(dconn, dbuf); err != nil {
		t.Fatalf("domain egress read: %v", err)
	}
	if string(dbuf) != "byname" {
		t.Fatalf("domain egress echo = %q", dbuf)
	}

	// --- Internet egress via client B's SOCKS5: UDP ASSOCIATE through the chain.
	udp := udpEcho(t)
	pc, err := socks.NewClient(socksB).DialUDP(ctx)
	if err != nil {
		t.Fatalf("udp associate: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("udp-through-chain"), udp); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	ubuf := make([]byte, 128)
	n, _, err := pc.ReadFrom(ubuf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if string(ubuf[:n]) != "udp-through-chain" {
		t.Fatalf("udp echo = %q", ubuf[:n])
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

// TestPolicyIsolationLive proves hub-enforced routing policy end-to-end:
//   - visible-peer mutual isolation (A reaches B, A cannot reach C),
//   - internet gating (B cannot use the egress, A can),
//   - filter passthrough to the hub itself (B can reach 10.77.0.1, but the
//     egress gate closes the connection),
//   - live policy reload without restarting the server (C becomes visible).
func TestPolicyIsolationLive(t *testing.T) {
	relay := newRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	srv, st, recs := hubWithClients(t, ctx, relay, []clientSpec{
		{id: "e2e-a", ip: "10.77.0.2"},
		{id: "e2e-b", ip: "10.77.0.3", noInternet: true},
		{id: "e2e-c", ip: "10.77.0.4", visiblePeers: []string{}},
	})
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

	socksA := waitSocksAddr(t, ca)
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

	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	abConn, err := ca.OverlayDialTCP(dialCtx, netip.MustParseAddrPort("10.77.0.3:9002"))
	dialCancel()
	if err != nil {
		t.Fatalf("A dial B: %v", err)
	}
	defer abConn.Close()
	if _, err := abConn.Write([]byte("a-to-b")); err != nil {
		t.Fatalf("A write B: %v", err)
	}
	abConn.SetReadDeadline(time.Now().Add(5 * time.Second))
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

	// --- A's chained internet egress still works.
	appA := socks.NewClient(socksA)
	dialCtx, dialCancel = context.WithTimeout(ctx, 5*time.Second)
	aConn, err := appA.Dial(dialCtx, "tcp", echoAddr)
	dialCancel()
	if err != nil {
		t.Fatalf("A chained egress: %v", err)
	}
	defer aConn.Close()
	if _, err := aConn.Write([]byte("a-egress")); err != nil {
		t.Fatalf("A egress write: %v", err)
	}
	aConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ebuf := make([]byte, len("a-egress"))
	if _, err := readFull(aConn, ebuf); err != nil {
		t.Fatalf("A egress read: %v", err)
	}
	if string(ebuf) != "a-egress" {
		t.Fatalf("A egress echo = %q", ebuf)
	}

	// --- B can still send packets to the hub itself (dst == serverIP passes
	// the filter). The TCP connect succeeds, but the egress gate closes it.
	serverEgress := netip.AddrPortFrom(netip.MustParseAddr(srv.Config().ServerIP), uint16(srv.Config().SocksPort))
	dialCtx, dialCancel = context.WithTimeout(ctx, 5*time.Second)
	hubConn, err := cb.OverlayDialTCP(dialCtx, serverEgress)
	dialCancel()
	if err != nil {
		t.Fatalf("B dial hub egress: %v", err)
	}
	defer hubConn.Close()
	hubConn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
