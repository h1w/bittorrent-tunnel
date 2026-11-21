package client

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
)

func TestPeerSettingsDefaultsAndExplicitEmpty(t *testing.T) {
	var p PeerSettings
	if !slices.Equal(p.IncomingModes(), []string{config.ModeExtUTP}) || !slices.Equal(p.OutgoingModes(), []string{config.ModeExtUTP}) || p.SelectedMode() != config.ModeExtUTP || p.Relay {
		t.Fatalf("incorrect defaults: %+v", p)
	}
	p = PeerSettings{Incoming: []string{}, Outgoing: "failover", Pools: map[string][]string{"failover": {}}}
	if p.IncomingModes() == nil || len(p.IncomingModes()) != 0 || p.OutgoingModes() == nil || len(p.OutgoingModes()) != 0 {
		t.Fatal("explicit empty lists must remain empty")
	}
	p.Outgoing = "adaptive"
	if !slices.Equal(p.OutgoingModes(), config.ClientModes()) {
		t.Fatal("missing pool must default to all modes")
	}
}

func TestPeerSettingsCanonicalAndOrdered(t *testing.T) {
	p := PeerSettings{Incoming: []string{"wg", "ext-utp"}, Outgoing: "failover", Pools: map[string][]string{"failover": {"wg", "ext-tcp"}}}
	if !slices.Equal(p.IncomingModes(), []string{config.ModeWG, config.ModeExtUTP}) || !slices.Equal(p.OutgoingModes(), []string{config.ModeWG, config.ModeExtTCP}) {
		t.Fatalf("canonical order lost: %+v", p)
	}
	p.Outgoing = "wg"
	if p.SelectedMode() != config.ModeWG || !slices.Equal(p.OutgoingModes(), []string{config.ModeWG}) {
		t.Fatal("single canonical mode not selected")
	}
}

func TestPeerSettingsValidationAndRoundTrip(t *testing.T) {
	tests := []struct {
		p     PeerSettings
		valid bool
	}{
		{PeerSettings{}, true},
		{PeerSettings{Incoming: []string{"wg", config.ModeWG}}, false},
		{PeerSettings{Incoming: []string{"invalid"}}, false},
		{PeerSettings{Outgoing: "invalid"}, false},
		{PeerSettings{Pools: map[string][]string{"invalid": {}}}, false},
		{PeerSettings{Pools: map[string][]string{"adaptive": {"wg", config.ModeWG}}}, false},
		{PeerSettings{Pools: map[string][]string{"adaptive": {"bad"}}}, false},
		{PeerSettings{Incoming: []string{}, Outgoing: "adaptive", Pools: map[string][]string{"adaptive": {}, "failover": {"wg", "ext-utp"}}, Relay: true}, true},
	}
	for _, tt := range tests {
		path := filepath.Join(t.TempDir(), "client.json")
		cfg := ManagedConfig{Peer: tt.p}
		err := cfg.Save(path)
		if (err == nil) != tt.valid {
			t.Fatalf("Save(%+v): %v", tt.p, err)
		}
		if err == nil {
			got, err := LoadManagedConfig(path)
			if err != nil || !reflect.DeepEqual(got.Peer, tt.p) {
				t.Fatalf("roundtrip: %+v, %v", got.Peer, err)
			}
		}
	}
	var old ManagedConfig
	if err := json.Unmarshal([]byte(`{"p2p":true}`), &old); err != nil || !slices.Equal(old.Peer.IncomingModes(), []string{config.ModeExtUTP}) {
		t.Fatalf("legacy config: %+v %v", old, err)
	}
}

func TestSetPeerValidatesWithoutMutatingOnError(t *testing.T) {
	cfg := ManagedConfig{Peer: PeerSettings{Relay: true}}
	invalid := PeerSettings{Outgoing: "bad"}
	if err := cfg.update(ControlRequest{Op: "set-peer", Peer: &invalid}, nil, false); err == nil || !cfg.Peer.Relay {
		t.Fatal("invalid update accepted or changed existing config")
	}
	if err := cfg.update(ControlRequest{Op: "set-peer"}, nil, false); err == nil {
		t.Fatal("missing settings accepted")
	}
	wanted := PeerSettings{Incoming: []string{}, Outgoing: "wg", Relay: true}
	if err := cfg.update(ControlRequest{Op: "set-peer", Peer: &wanted}, nil, false); err != nil || !reflect.DeepEqual(cfg.response("status").Peer, wanted) {
		t.Fatalf("update: %+v %v", cfg.Peer, err)
	}
}

func TestDaemonPeerUpdatePersistsBeforeApplying(t *testing.T) {
	base := managedCfg(t)
	raw, err := base.ImportString()
	if err != nil {
		t.Fatal(err)
	}
	cfg := ManagedConfig{Import: raw, ListenIP: "127.0.0.1", Credentials: Credentials{Username: "user", Password: "secret"}}
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "client.json")
	socket := filepath.Join(dir, "run", "control.sock")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runManagedAt(ctx, cfg, path, socket, false, "btawg", 0) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := request(socket, ControlRequest{Op: "status"})
		if err == nil {
			break
		}
		if !errors.Is(err, ErrNotRunning) || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	peer := PeerSettings{Incoming: []string{}, Outgoing: "adaptive", Pools: map[string][]string{"adaptive": {config.ModeWG, config.ModeAWG}}, Relay: true}
	got, err := request(socket, ControlRequest{Op: "set-peer", Peer: &peer})
	if err != nil || !reflect.DeepEqual(got.Peer, peer) {
		t.Fatalf("set-peer: %+v %v", got, err)
	}
	saved, err := LoadManagedConfig(path)
	if err != nil || !reflect.DeepEqual(saved.Peer, peer) {
		t.Fatalf("saved peer: %+v %v", saved.Peer, err)
	}
	if err := os.Rename(filepath.Dir(path), filepath.Join(dir, "backup")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(path), nil, 0600); err != nil {
		t.Fatal(err)
	}
	changed := PeerSettings{Outgoing: config.ModeWG}
	if _, err := request(socket, ControlRequest{Op: "set-peer", Peer: &changed}); err == nil {
		t.Fatal("peer update accepted without persistence")
	}
	got, err = request(socket, ControlRequest{Op: "status"})
	if err != nil || !reflect.DeepEqual(got.Peer, peer) {
		t.Fatalf("failed update changed peer: %+v %v", got.Peer, err)
	}
}
