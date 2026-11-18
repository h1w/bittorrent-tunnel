package dht

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	anadht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/torrent/metainfo"
)

// newRelay starts a bare DHT node standing in for the public network: it
// stores announced peers (PeerStore) and serves them on get_peers, exactly
// like a public BitTorrent DHT node would.
func newRelay(t *testing.T) (*anadht.Server, string) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
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
	return srv, conn.LocalAddr().String()
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
