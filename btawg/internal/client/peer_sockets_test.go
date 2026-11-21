package client

import (
	"net/netip"
	"slices"
	"testing"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/mesh"
)

func TestPeerCandidatesReserveNativeDirections(t *testing.T) {
	many := func() []mesh.Candidate {
		candidates := make([]mesh.Candidate, 70)
		for i := range candidates {
			candidates[i] = mesh.Candidate{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 0, byte(i + 1)}), 2000), Kind: "lan"}
		}
		return candidates
	}
	s := &peerSockets{all: []*peerSocket{
		{local: many},
		{local: many, mode: config.ModeAWG},
		{local: many, mode: config.ModeAWG, receive: true},
		{local: many, mode: config.ModeWG},
		{local: many, mode: config.ModeWG, receive: true},
	}}
	modes := []string{config.ModeAWG, config.ModeWG}
	candidates := s.candidates("", "", modes, modes)
	if len(candidates) > 64 {
		t.Fatalf("candidate registration exceeds hub limit: %d", len(candidates))
	}
	for _, receive := range []bool{false, true} {
		if !slices.ContainsFunc(candidates, func(c mesh.Candidate) bool { return c.Mode == config.ModeWG && c.Receive == receive }) {
			t.Fatalf("early candidates starved WG receive=%v", receive)
		}
	}
}
