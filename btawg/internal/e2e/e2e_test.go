package e2e

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	anadht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/go-utp/purego"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/dht"
	"bittorrent-tunnel/btawg/internal/server"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/store"
)

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

// hubWithClient builds the hub with one registered client and returns its
// bootstrap pieces plus the generated client record material.
func hubWithClient(t *testing.T, ctx context.Context, relay string) (*server.Server, *store.ClientRecord) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/hub.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	hubCfg := config.DefaultServerConfig()
	hubCfg.Transport = "ext-utp"
	hubCfg.CarrierPort = 17781
	hubCfg.ExternalIP = "127.0.0.1"

	priv, pub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	rec := &store.ClientRecord{
		ID:      "e2e-a",
		Name:    "e2e-a",
		PubKey:  pub,
		PrivKey: priv,
		IP:      "10.77.0.2",
		PeerID:  awg.PeerID(pub),
		Created: time.Unix(1, 0),
	}
	if err := st.CreateClient(*rec); err != nil {
		t.Fatalf("create client: %v", err)
	}
	srv, err := server.New(hubCfg, st)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	srv.SetDHTBootstrap([]string{relay})
	go srv.Run(ctx)
	go srv.Announce(ctx)
	return srv, rec
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

// TestEndToEndSocksAndLan drives two clients through the product path:
// internet egress via each client's SOCKS5 (TCP CONNECT and UDP ASSOCIATE)
// and client-to-client reachability through the hub's forwarding.
func TestEndToEndSocksAndLan(t *testing.T) {
	purego.MatrixDisableNagle = true
	relay := newRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	srv, recA := hubWithClient(t, ctx, relay)

	// Second client record, registered at runtime like the panel does.
	privB, pubB, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client b key: %v", err)
	}
	recB := &store.ClientRecord{
		ID:      "e2e-b",
		Name:    "e2e-b",
		PubKey:  pubB,
		PrivKey: privB,
		IP:      "10.77.0.3",
		PeerID:  awg.PeerID(pubB),
		Created: time.Unix(1, 0),
	}
	if err := srv.RegisterClient(*recB); err != nil {
		t.Fatalf("register b: %v", err)
	}

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

	waitSocks := func(c *client.Client) string {
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
	socksA := waitSocks(ca)
	socksB := waitSocks(cb)

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
