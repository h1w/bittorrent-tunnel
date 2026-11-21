package main

import (
	"slices"
	"testing"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
)

func TestPeerScreensPreserveLatestIndependentSettings(t *testing.T) {
	state := client.PeerSettings{Outgoing: "wg", Relay: true}
	request := func(req client.ControlRequest) (client.ControlResponse, bool, error) {
		if req.Op == "set-peer" {
			state = *req.Peer
		}
		return client.ControlResponse{OK: true, Peer: state}, false, nil
	}
	screen, err := peerSettingsScreen(request)
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
