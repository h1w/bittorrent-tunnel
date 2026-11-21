package client

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
)

func peerTCP(src, dst netip.Addr, a, b uint16, flags byte) []byte {
	p := make([]byte, 40)
	p[0], p[9], p[32], p[33] = 0x45, 6, 0x50, flags
	binary.BigEndian.PutUint16(p[2:], 40)
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[20:], a)
	binary.BigEndian.PutUint16(p[22:], b)
	return p
}

func directFlowPath(t *testing.T, mode string, outgoing bool) *tunPath {
	t.Helper()
	until := new(atomic.Int64)
	until.Store(time.Now().Add(time.Minute).UnixNano())
	p := &tunPath{directLife: t.Context(), directUntil: until, peerOutbound: outgoing, peerMode: mode}
	p.peerHealth = &managedTunnel{c: &Client{path: p}}
	p.peerHealth.score.Store(int64(15 * time.Millisecond))
	return p
}

func TestPeerFlowUsesOnlyApprovedDirectionAndPinsReplies(t *testing.T) {
	cfg := config.ClientConfig{ClientIP: "10.77.0.2", ServerIP: "10.77.0.1", Subnet: "10.77.0.0/24"}
	a, b := netip.MustParseAddr(cfg.ClientIP), netip.MustParseAddr("10.77.0.3")
	s := &sharedTUN{}
	s.primary.Store(&tunPath{})
	s.enableDirect(cfg)
	s.configurePeer(PeerSettings{Incoming: []string{config.ModeTLSReqTCP}, Outgoing: roundRobinPolicy, Pools: map[string][]string{roundRobinPolicy: {config.ModeWG, config.ModeExtUTP}}})
	if p := s.packetPath(peerTCP(a, b, 100, 22, 2), 20); p != nil {
		t.Fatal("default leaked a SYN into the hub")
	}
	if p := s.packetPath(peerTCP(a, netip.MustParseAddr(cfg.ServerIP), 100, 1054, 2), 20); p != s.primary.Load() {
		t.Fatal("peer settings blocked the hub control plane")
	}
	wg, utp := directFlowPath(t, config.ModeWG, true), directFlowPath(t, config.ModeExtUTP, true)
	s.setDirect(b, wg)
	s.setDirect(b, utp)
	for i, want := range []*tunPath{wg, utp, wg} {
		port := uint16(100 + i)
		if p := s.packetPath(peerTCP(a, b, port, 22, 2), 20); p != want {
			t.Fatalf("flow %d used wrong link", i)
		}
		if p := s.packetPath(peerTCP(a, b, port, 22, 0x10), 20); p != want {
			t.Fatalf("flow %d moved mid-stream", i)
		}
		if !s.acceptPeerPacket(want, peerTCP(b, a, 22, port, 0x12), 20) {
			t.Fatalf("flow %d reply was blocked", i)
		}
	}
	if s.acceptPeerPacket(wg, peerTCP(b, a, 300, 22, 2), 20) {
		t.Fatal("outgoing WG link accepted an unsolicited incoming stream")
	}
	tls := directFlowPath(t, config.ModeTLSReqTCP, false)
	if !s.acceptPeerPacket(tls, peerTCP(b, a, 301, 22, 2), 20) || s.packetPath(peerTCP(a, b, 22, 301, 0x12), 20) != tls {
		t.Fatal("incoming TLS stream did not send its reply over the same link")
	}
	s.configurePeer(PeerSettings{Incoming: []string{}, Outgoing: config.ModeReqTCP, Relay: true})
	if s.acceptPeerPacket(tls, peerTCP(b, a, 302, 22, 2), 20) {
		t.Fatal("revoked inbound mode still accepts new connections")
	}
	if p := s.packetPath(peerTCP(a, b, 400, 22, 2), 20); p != s.primary.Load() {
		t.Fatal("explicit relay unavailable")
	}
	s.configurePeer(PeerSettings{Incoming: []string{}, Outgoing: config.ModeReqTCP})
	if p := s.packetPath(peerTCP(a, b, 400, 22, 2), 20); p != nil {
		t.Fatal("old relay pin survived turning relay off")
	}
}
