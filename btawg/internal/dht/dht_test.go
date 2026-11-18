package dht

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	anadht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/torrent/metainfo"
)

// newRelay starts a bare DHT node standing in for the public network: it
// stores announced peers (PeerStore) and serves them on get_peers, exactly
func newRelayAt(t *testing.T, addr *net.UDPAddr) *anadht.Server {
	t.Helper()
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	srv, err := anadht.NewServer(&anadht.ServerConfig{
		Conn:       conn,
		NoSecurity: true,
		PeerStore:  &memPeerStore{},
		StartingNodes: func() ([]anadht.Addr, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("relay server: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func newRelay(t *testing.T) (*anadht.Server, string) {
	t.Helper()
	srv := newRelayAt(t, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	return srv, srv.Addr().String()
}

func TestAnnounceDiscoverLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("loopback DHT is UDP best-effort; skip in -short")
	}
	var infoHash [20]byte
	infoHash[0], infoHash[1] = 0xb7, 0x77

	// The "carrier" port need not have a listener: DHT never connects to it.
	carrier := netip.MustParseAddrPort("127.0.0.1:45001")
	relaySrv, relay := newRelay(t)

	ann, err := NewAnnouncer(infoHash, carrier, []string{relay})
	if err != nil {
		t.Fatalf("NewAnnouncer: %v", err)
	}
	t.Cleanup(ann.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ann.AnnounceOnce(ctx); err != nil {
		t.Fatalf("AnnounceOnce: %v", err)
	}

	// The relay must have stored the announced peer, like a public node.
	stored := relaySrv.PeerStore().GetPeers(metainfo.Hash(infoHash))
	if len(stored) == 0 {
		t.Fatal("relay peer store empty after AnnounceOnce")
	}
	t.Logf("relay stored: %v", stored)

	found, err := Discover(ctx, infoHash, []string{relay})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("Discover returned no peers")
	}
	for _, p := range found {
		if p == carrier {
			return // announced carrier address learned strictly via DHT
		}
	}
	t.Fatalf("Discover = %v, want %v", found, carrier)
}

func TestDiscoverNoPeersIsExplicitError(t *testing.T) {
	if testing.Short() {
		t.Skip("loopback DHT is UDP best-effort; skip in -short")
	}
	// A relay exists but nobody announced this infohash: discovery must fail
	// loudly, not hang.
	_, relay := newRelay(t)
	var infoHash [20]byte
	infoHash[0] = 0x99

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := Discover(ctx, infoHash, []string{relay}); err == nil {
		t.Fatal("Discover for unannounced infohash succeeded, want explicit error")
	}
}

func TestAnnounceDeadBootstrapIsNoContact(t *testing.T) {
	if testing.Short() {
		t.Skip("loopback DHT is UDP best-effort; skip in -short")
	}
	// Bind a port and close it: the bootstrap address resolves but nobody
	// ever answers. AnnounceOnce must say so instead of reporting success.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := conn.LocalAddr().String()
	conn.Close()

	var infoHash [20]byte
	infoHash[0] = 0xee
	ann, err := NewAnnouncer(infoHash, netip.MustParseAddrPort("127.0.0.1:45002"), []string{dead})
	if err != nil {
		t.Fatalf("NewAnnouncer: %v", err)
	}
	t.Cleanup(ann.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = ann.AnnounceOnce(ctx)
	if !errors.Is(err, ErrNoContact) {
		t.Fatalf("AnnounceOnce with dead bootstrap = %v, want ErrNoContact", err)
	}
}

func TestRunRetriesAfterBootstrapComesUp(t *testing.T) {
	if testing.Short() {
		t.Skip("loopback DHT is UDP best-effort; skip in -short")
	}
	// The race the runtime check caught: the server announces at boot
	// before its bootstrap island is reachable. Run must retry shortly
	// and recover once the relay appears, not wait the full 15 minutes.
	var infoHash [20]byte
	infoHash[0], infoHash[1] = 0xb7, 0x77
	carrier := netip.MustParseAddrPort("127.0.0.1:45003")

	// Reserve the relay port so the announcer's first attempt lands on a
	// closed socket, then free it and start the real relay mid-run.
	hold, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("hold: %v", err)
	}
	relayAddr := hold.LocalAddr().String()

	ann, err := NewAnnouncer(infoHash, carrier, []string{relayAddr})
	if err != nil {
		t.Fatalf("NewAnnouncer: %v", err)
	}
	t.Cleanup(ann.Close)
	ann.retryInterval = 300 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() { ann.Run(ctx) }()

	// First announce attempts hit the held-but-silent socket, fail as
	// no-contact, and schedule a retry. Give that one round time, then
	// swap in the real relay.
	time.Sleep(2 * time.Second)
	hold.Close()
	_, portStr, _ := net.SplitHostPort(relayAddr)
	p, _ := strconv.Atoi(portStr)
	relaySrv := newRelayAt(t, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		stored := relaySrv.PeerStore().GetPeers(metainfo.Hash(infoHash))
		if len(stored) > 0 {
			return // recovered strictly via retry, no restart needed
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("Run never announced after the relay came up")
}

func TestListenUDPRangeFirstFreeThenEphemeral(t *testing.T) {
	// Tested on an uncommon port range to avoid cross-package parallel
	// collisions with the production 688x binds. Occupy the first three
	// ports of the range: the helper must land on the next free one, like a
	// torrent client whose usual port is busy.
	var holds []net.PacketConn
	for p := 38882; p <= 38884; p++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: p})
		if err != nil {
			t.Fatalf("hold %d: %v", p, err)
		}
		holds = append(holds, c)
	}
	defer func() {
		for _, c := range holds {
			c.Close()
		}
	}()

	pc, err := listenUDPRange(38882, 38889)
	if err != nil {
		t.Fatalf("listenUDPRange: %v", err)
	}
	defer pc.Close()
	if got := pc.LocalAddr().(*net.UDPAddr).Port; got != 38885 {
		t.Fatalf("listenUDPRange port = %d, want first free 38885", got)
	}

	// Whole range busy: fall back to an ephemeral port instead of failing.
	pc.Close()
	for p := 38885; p <= 38889; p++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: p})
		if err != nil {
			t.Fatalf("hold %d: %v", p, err)
		}
		holds = append(holds, c)
	}
	pc2, err := listenUDPRange(38882, 38889)
	if err != nil {
		t.Fatalf("listenUDPRange fallback: %v", err)
	}
	defer pc2.Close()
	if got := pc2.LocalAddr().(*net.UDPAddr).Port; got >= 38882 && got <= 38889 {
		t.Fatalf("listenUDPRange fallback port = %d inside busy range, want ephemeral", got)
	}
}
