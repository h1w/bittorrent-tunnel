package client

import (
	"net/netip"
	"slices"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/mesh"
)

type peerPolicy struct {
	mesh.PeerModes
	selection string
	relay     bool
}

type peerPolicies struct {
	defaults       peerPolicy
	peers          map[netip.Addr]peerPolicy
	meshOverrides  map[netip.Addr]mesh.PeerModes
	nativeIncoming []string
	nativeOutgoing []string
}

func compilePeerPolicies(p PeerSettings) *peerPolicies {
	compile := func(settings PeerSettings) peerPolicy {
		return peerPolicy{
			PeerModes: mesh.PeerModes{Incoming: settings.IncomingModes(), Outgoing: settings.OutgoingModes()},
			selection: settings.SelectedMode(), relay: settings.Relay,
		}
	}
	s := &peerPolicies{defaults: compile(p)}
	if len(p.Overrides) != 0 {
		s.peers = make(map[netip.Addr]peerPolicy, len(p.Overrides))
		for ip := range p.Overrides {
			policy := compile(p.ForPeer(ip))
			s.peers[ip] = policy
			if slices.Equal(policy.Incoming, s.defaults.Incoming) && slices.Equal(policy.Outgoing, s.defaults.Outgoing) {
				continue
			}
			if s.meshOverrides == nil {
				s.meshOverrides = make(map[netip.Addr]mesh.PeerModes)
			}
			s.meshOverrides[ip] = policy.PeerModes
		}
	}
	for _, mode := range [...]string{config.ModeAWG, config.ModeWG} {
		in, out := slices.Contains(s.defaults.Incoming, mode), slices.Contains(s.defaults.Outgoing, mode)
		for _, p := range s.meshOverrides {
			in = in || slices.Contains(p.Incoming, mode)
			out = out || slices.Contains(p.Outgoing, mode)
			if in && out {
				break
			}
		}
		if in {
			s.nativeIncoming = append(s.nativeIncoming, mode)
		}
		if out {
			s.nativeOutgoing = append(s.nativeOutgoing, mode)
		}
	}
	return s
}

func (s *peerPolicies) forPeer(ip netip.Addr) peerPolicy {
	if s != nil {
		if p, ok := s.peers[ip]; ok {
			return p
		}
		return s.defaults
	}
	return peerPolicy{}
}
