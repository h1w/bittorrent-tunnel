package server

import (
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

func TestServerReloadPolicy(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/policy.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	cfg.ServerIP = "10.77.0.1"
	cfg.CarrierPort = 17778 // uncommon port; avoid fixed 6881 contention in parallel runs

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
		t.Fatalf("create client: %v", err)
	}

	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	aIP := netip.MustParseAddr("10.77.0.2")
	bIP := netip.MustParseAddr("10.77.0.3")
	if srv.policy.clientCanReach(aIP, bIP) {
		t.Fatalf("A -> B: want false before B exists")
	}

	bPriv, bPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("B key: %v", err)
	}
	b := store.ClientRecord{
		ID:           "B",
		Name:         "client-b",
		IP:           "10.77.0.3",
		PubKey:       bPub,
		PrivKey:      bPriv,
		PeerID:       awg.PeerID(bPub),
		Created:      time.Unix(1, 0),
		VisiblePeers: []string{"A"},
	}
	if err := st.CreateClient(b); err != nil {
		t.Fatalf("create B: %v", err)
	}
	if err := srv.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if !srv.policy.clientCanReach(aIP, bIP) {
		t.Errorf("A -> B after reload: want true, got false")
	}
}

func TestPolicySnapshotMatrix(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/policy.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	serverIP := netip.MustParseAddr("10.77.0.1")

	a := store.ClientRecord{
		ID:      "A",
		Name:    "client-a",
		IP:      "10.77.0.2",
		PeerID:  "peer-a",
		Created: time.Unix(1, 0),
		// nil VisiblePeers normalizes to ["*"] => sees all.
	}
	b := store.ClientRecord{
		ID:           "B",
		Name:         "client-b",
		IP:           "10.77.0.3",
		PeerID:       "peer-b",
		Created:      time.Unix(1, 0),
		VisiblePeers: []string{"A"},
	}
	c := store.ClientRecord{
		ID:           "C",
		Name:         "client-c",
		IP:           "10.77.0.4",
		PeerID:       "peer-c",
		Created:      time.Unix(1, 0),
		VisiblePeers: []string{},
		NoInternet:   true,
	}
	for _, rec := range []store.ClientRecord{a, b, c} {
		if err := st.CreateClient(rec); err != nil {
			t.Fatalf("create client %s: %v", rec.ID, err)
		}
	}

	p := newPolicySnapshot()
	if err := p.reload(st, serverIP); err != nil {
		t.Fatalf("reload: %v", err)
	}

	aIP := netip.MustParseAddr("10.77.0.2")
	bIP := netip.MustParseAddr("10.77.0.3")
	cIP := netip.MustParseAddr("10.77.0.4")
	unknownIP := netip.MustParseAddr("10.77.0.9")

	// Mutual visibility rules.
	if !p.clientCanReach(aIP, bIP) {
		t.Errorf("A -> B: want true, got false")
	}
	if !p.clientCanReach(bIP, aIP) {
		t.Errorf("B -> A: want true, got false")
	}
	if p.clientCanReach(cIP, bIP) {
		t.Errorf("C -> B: want false, got true")
	}
	if p.clientCanReach(bIP, cIP) {
		t.Errorf("B -> C: want false, got true")
	}
	if p.clientCanReach(unknownIP, aIP) {
		t.Errorf("unknown -> A: want false, got true")
	}
	if p.clientCanReach(unknownIP, unknownIP) {
		t.Errorf("unknown -> unknown: want false, got true")
	}
	if !p.clientCanReach(aIP, aIP) {
		t.Errorf("A -> A: want true (sees all), got false")
	}
	if p.clientCanReach(bIP, bIP) {
		t.Errorf("B -> B: want false (does not list itself), got true")
	}
	if p.clientCanReach(cIP, cIP) {
		t.Errorf("C -> C: want false (sees nobody), got true")
	}
	if !p.clientCanReach(aIP, serverIP) {
		t.Errorf("A -> serverIP: want true, got false")
	}
	if !p.clientCanReach(serverIP, cIP) {
		t.Errorf("serverIP -> C: want true, got false")
	}

	// Internet access rules.
	if !p.internetFor(aIP) {
		t.Errorf("internetFor(A): want true, got false")
	}
	if p.internetFor(cIP) {
		t.Errorf("internetFor(C): want false, got true")
	}
	if !p.internetFor(serverIP) {
		t.Errorf("internetFor(serverIP): want true, got false")
	}
	if p.internetFor(unknownIP) {
		t.Errorf("internetFor(unknown): want false, got true")
	}

	// Live reload: flip B and C so they mutually see each other, reload, C->B true.
	if err := st.DeleteClient(b.ID); err != nil {
		t.Fatalf("delete B: %v", err)
	}
	b.VisiblePeers = []string{"A", "C"}
	if err := st.CreateClient(b); err != nil {
		t.Fatalf("recreate B: %v", err)
	}
	if err := st.DeleteClient(c.ID); err != nil {
		t.Fatalf("delete C: %v", err)
	}
	c.VisiblePeers = []string{"B"}
	if err := st.CreateClient(c); err != nil {
		t.Fatalf("recreate C: %v", err)
	}
	if err := p.reload(st, serverIP); err != nil {
		t.Fatalf("reload after update: %v", err)
	}
	if !p.clientCanReach(cIP, bIP) {
		t.Errorf("after reload C -> B: want true, got false")
	}
	if !p.clientCanReach(bIP, cIP) {
		t.Errorf("after reload B -> C: want true, got false")
	}
}
