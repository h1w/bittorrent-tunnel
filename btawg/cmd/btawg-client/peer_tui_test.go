package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
)

func TestPeerScreensPreserveLatestIndependentSettings(t *testing.T) {
	state := client.PeerSettings{Outgoing: "wg", Relay: true}
	request := func(req client.ControlRequest) (client.ControlResponse, bool, error) {
		if req.Op == "set-peer" {
			state = *req.Peer
		}
		return client.ControlResponse{OK: true, Peer: state, PeerRevision: "test"}, false, nil
	}
	screen, err := peerSettingsScreen(request)
	if err != nil {
		t.Fatal(err)
	}
	screen, err = screen.Choices[0].Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(screen.Choices) != 4 {
		t.Fatalf("peer menu choices = %d", len(screen.Choices))
	}
	incoming, err := screen.Choices[0].Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(incoming.Fields) != 10 || !incoming.Fields[0].Checked {
		t.Fatal("incoming defaults missing")
	}
	state.Outgoing = "adaptive"
	for i := range incoming.Fields {
		incoming.Fields[i].Checked = false
	}
	if _, err := incoming.Save(incoming.Fields); err != nil {
		t.Fatal(err)
	}
	if state.Incoming == nil || len(state.Incoming) != 0 || state.Outgoing != "adaptive" || !state.Relay {
		t.Fatalf("incoming save clobbered settings: %+v", state)
	}
	pools, err := screen.Choices[1].Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(pools.Choices) != 3 {
		t.Fatalf("pool choices = %d", len(pools.Choices))
	}
	pool, err := pools.Choices[0].Run()
	if err != nil {
		t.Fatal(err)
	}
	if !pool.Reorder || len(pool.Fields) != 10 {
		t.Fatal("failover pool must be reorderable and default to all")
	}
	for i := range pool.Fields {
		pool.Fields[i].Checked = false
	}
	pool.Fields[1].Checked = true
	state.Outgoing = "round-robin"
	if _, err := pool.Save(pool.Fields); err != nil {
		t.Fatal(err)
	}
	if state.Outgoing != "round-robin" || !state.Relay || !slices.Equal(state.Pools["failover"], []string{config.ModeExtTCP}) {
		t.Fatalf("pool save clobbered settings: %+v", state)
	}
	rr, err := pools.Choices[1].Run()
	if err != nil || rr.Reorder {
		t.Fatal("round robin should not reorder")
	}
	connect, err := screen.Choices[2].Run()
	if err != nil || len(connect.Choices) != 13 {
		t.Fatalf("connect options = %v, %v", connect, err)
	}
	if _, err := connect.Choices[0].Run(); err != nil || state.Outgoing != config.ModeExtUTP || !state.Relay {
		t.Fatalf("connect selection: %+v %v", state, err)
	}
	if _, err := screen.Choices[3].Run(); err != nil || state.Relay {
		t.Fatalf("relay toggle: %+v %v", state, err)
	}
}

func TestPeerOverrideScreensEditAndRestoreInheritance(t *testing.T) {
	ip := netip.MustParseAddr("10.77.0.5")
	state := client.PeerSettings{Outgoing: "wg", Relay: true, Pools: map[string][]string{"failover": {config.ModeWG}}}
	request := func(req client.ControlRequest) (client.ControlResponse, bool, error) {
		if req.Op == "set-peer" {
			state = *req.Peer
		}
		return client.ControlResponse{OK: true, Peer: state, PeerRevision: "test"}, false, nil
	}
	open := func(screen *service.Screen, prefix string) *service.Screen {
		t.Helper()
		for _, choice := range screen.Choices {
			if strings.HasPrefix(strings.TrimPrefix(strings.TrimPrefix(choice.Label, "[x] "), "[ ] "), prefix) {
				next, err := choice.Run()
				if err != nil {
					t.Fatal(err)
				}
				return next
			}
		}
		t.Fatalf("option %q not available in %q", prefix, screen.Title)
		return nil
	}
	list := func() *service.Screen {
		t.Helper()
		screen, err := peerSettingsScreen(request)
		if err != nil {
			t.Fatal(err)
		}
		return open(screen, "Per-peer overrides")
	}
	add := open(list(), "Add by VPN IP")
	add.Fields[0].Value = "10.77.0.0/24"
	if _, err := add.Save(add.Fields); err == nil {
		t.Fatal("accepted a subnet instead of a peer address")
	}
	add.Fields[0].Value = ip.String()
	if _, err := add.Save(add.Fields); err != nil {
		t.Fatal(err)
	}
	peer := func() *service.Screen { return open(list(), ip.String()) }
	open(open(peer(), "Connect using"), config.ModeTLSReqTCP)
	open(open(peer(), "Allow relay"), "Off")
	pool := func() *service.Screen { return open(open(peer(), "Outgoing pools"), "Failover") }
	owned := open(pool(), "Customize")
	for i := range owned.Fields {
		owned.Fields[i].Checked = false
	}
	if _, err := owned.Save(owned.Fields); err != nil {
		t.Fatal(err)
	}
	got := state.ForPeer(ip)
	if got.SelectedMode() != config.ModeTLSReqTCP || got.Relay || got.Pools["failover"] == nil || len(got.Pools["failover"]) != 0 {
		t.Fatalf("peer edits not applied independently: %+v", got)
	}
	other := state.ForPeer(netip.MustParseAddr("10.77.0.6"))
	if other.SelectedMode() != config.ModeWG || !other.Relay || !slices.Equal(other.Pools["failover"], []string{config.ModeWG}) {
		t.Fatalf("peer edits changed global defaults: %+v", other)
	}
	open(pool(), "Use global")
	state.Pools["failover"] = []string{config.ModeAWG}
	if !slices.Equal(state.ForPeer(ip).Pools["failover"], []string{config.ModeAWG}) {
		t.Fatal("reset pool did not follow changed globals")
	}
	open(open(peer(), "Remove override"), "Remove")
	if _, exists := state.Overrides[ip]; exists || !state.ForPeer(ip).Relay || state.ForPeer(ip).SelectedMode() != config.ModeWG {
		t.Fatal("removed peer did not revert to global defaults")
	}
}
