package server

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/store"
)

func testRouterWithClient(t *testing.T) (*packetRouter, netip.Addr, netip.Addr) {
	t.Helper()
	clientPub, _, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	clientIP := netip.MustParseAddr("10.77.0.2")
	gatewayIP := netip.MustParseAddr("10.77.0.1")

	inner, _, err := netstack.CreateNetTUN([]netip.Addr{gatewayIP}, nil, 1280)
	if err != nil {
		t.Fatalf("create netstack tun: %v", err)
	}

	policy := newPolicySnapshot()
	policy.serverIP = gatewayIP
	rec := store.ClientRecord{
		ID:      "c1",
		Name:    "router-flow",
		PubKey:  clientPub,
		IP:      clientIP.String(),
		GroupID: "g1",
	}
	policy.byIP = map[netip.Addr]store.ClientRecord{clientIP: rec}
	policy.byAddr = map[netip.Addr]*trafficCounter{clientIP: new(trafficCounter)}
	policy.groups = map[string]store.GroupRecord{
		"g1": {ID: "g1", ServerIP: gatewayIP.String(), Subnet: "10.77.0.0/24"},
	}
	policy.gateways = map[netip.Addr]string{gatewayIP: "g1"}
	policy.prefixes = []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}

	r := newPacketRouter(inner, false, policy)
	t.Cleanup(func() { _ = r.close() })
	return r, clientIP, gatewayIP
}

// TestRouterFlowPinningPrecedence verifies that a pinned reverse flow wins
// over the per-IP primary route when choosing the destination engine.
func TestRouterFlowPinningPrecedence(t *testing.T) {
	r, clientIP, gatewayIP := testRouterWithClient(t)

	engA := r.newEngine(netip.Addr{})
	engB := r.newEngine(netip.Addr{})

	// Primary route points to B.
	r.remember(clientIP, engB, time.Now().UnixNano())

	// A packet forwarded by A pins the reverse flow to A.
	fwd := makeTCPPacket(clientIP.String(), gatewayIP.String(), 12345, 443)
	if _, err := engA.Write([][]byte{fwd}, 0); err != nil {
		t.Fatalf("engA Write: %v", err)
	}

	// The reverse packet must resolve to A, not B.
	rev := makeTCPPacket(gatewayIP.String(), clientIP.String(), 443, 12345)
	if got := r.lookupDestinationEngine(gatewayIP, clientIP, rev, time.Now()); got != engA {
		t.Fatalf("lookup returned %v, want engA", got)
	}

	// Enqueue and read through A succeeds.
	buf := make([]byte, len(rev)+tunOffset)
	copy(buf[tunOffset:], rev)
	if !engA.enqueue(buf[:len(rev)+tunOffset]) {
		t.Fatal("engA enqueue failed")
	}
	out := make([][]byte, 1)
	out[0] = make([]byte, 2048)
	sizes := make([]int, 1)
	if _, err := engA.Read(out, sizes, 0); err != nil || sizes[0] != len(rev) || !bytes.Equal(out[0][:sizes[0]], rev) {
		t.Fatalf("engA.Read: err=%v size=%d", err, sizes[0])
	}

	// The same packet is rejected by B because B is not the flow owner.
	buf2 := make([]byte, len(rev)+tunOffset)
	copy(buf2[tunOffset:], rev)
	if !engB.enqueue(buf2[:len(rev)+tunOffset]) {
		t.Fatal("engB enqueue failed")
	}
	out[0] = make([]byte, 2048)
	sizes[0] = 0
	done := make(chan struct{})
	go func() {
		engB.Read(out, sizes, 0)
		close(done)
	}()
	select {
	case <-done:
		if sizes[0] != 0 {
			t.Fatal("engB accepted packet owned by engA")
		}
	case <-time.After(200 * time.Millisecond):
	}
}

// TestRouterStaleEngineFallback verifies that closing an engine removes its
// pinned flows and lets subsequent reverse traffic fall back to the primary
// route.
func TestRouterStaleEngineFallback(t *testing.T) {
	r, clientIP, gatewayIP := testRouterWithClient(t)

	engA := r.newEngine(netip.Addr{})
	engB := r.newEngine(netip.Addr{})

	fwd := makeTCPPacket(clientIP.String(), gatewayIP.String(), 12345, 443)
	if _, err := engA.Write([][]byte{fwd}, 0); err != nil {
		t.Fatalf("engA Write: %v", err)
	}

	if err := engA.Close(); err != nil {
		t.Fatalf("engA Close: %v", err)
	}

	r.remember(clientIP, engB, time.Now().UnixNano())

	rev := makeTCPPacket(gatewayIP.String(), clientIP.String(), 443, 12345)
	if got := r.lookupDestinationEngine(gatewayIP, clientIP, rev, time.Now()); got != engB {
		t.Fatalf("lookup returned %v after close, want engB", got)
	}
}

// TestRouterUnauthenticatedSourceCannotSpoof verifies that a TLS engine whose
// authSource is pinned to one client rejects packets with a different source
// address and does not create flow pins for the spoofed source.
func TestRouterUnauthenticatedSourceCannotSpoof(t *testing.T) {
	r, clientIP, gatewayIP := testRouterWithClient(t)
	otherIP := netip.MustParseAddr("10.77.0.3")

	// Add a second client to the policy so the spoofed source is a known IP.
	otherPub, _, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	r.policy.byIP[otherIP] = store.ClientRecord{
		ID:      "c2",
		Name:    "other",
		PubKey:  otherPub,
		IP:      otherIP.String(),
		GroupID: "g1",
	}
	r.policy.byAddr[otherIP] = new(trafficCounter)

	eng := r.newEngine(clientIP)
	defer eng.Close()

	spoof := makeTCPPacket(otherIP.String(), gatewayIP.String(), 12345, 443)
	if _, err := eng.Write([][]byte{spoof}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	key, _ := flowKeyFromPacket(spoof)
	if _, ok := r.flows.lookup(key.reverse(), time.Now()); ok {
		t.Fatal("unauthenticated engine pinned a spoofed flow")
	}
}

func TestTLSModesBothReturnTrafficForOneIP(t *testing.T) {
	r, clientIP, gatewayIP := testRouterWithClient(t)
	first, second := r.newEngine(clientIP), r.newEngine(clientIP)
	defer first.Close()
	defer second.Close()
	r.remember(clientIP, second, time.Now().UnixNano())
	for i, e := range []*engineTun{first, second} {
		port := uint16(32000 + i)
		if _, err := e.Write([][]byte{makeTCPPacket(clientIP.String(), gatewayIP.String(), port, 443)}, 0); err != nil {
			t.Fatal(err)
		}
		reply := makeTCPPacket(gatewayIP.String(), clientIP.String(), 443, port)
		if r.lookupDestinationEngine(gatewayIP, clientIP, reply, time.Now()) != e {
			t.Fatalf("reply to port %d left on the wrong TLS tunnel", port)
		}
	}
}
