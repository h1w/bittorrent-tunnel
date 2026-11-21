package server

import (
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/mesh"
	"bittorrent-tunnel/btawg/internal/store"
)

func TestPeerOffersRespectRecipientAndDirection(t *testing.T) {
	a, b := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
	one := store.ClientRecord{ID: "one", IP: a.String(), PubKey: "a", GroupID: "g"}
	two := store.ClientRecord{ID: "two", IP: b.String(), PubKey: "b", GroupID: "g"}
	now := time.Now()
	policy := newPolicySnapshot()
	policy.byIP[a], policy.byIP[b] = one, two
	policy.groups = map[string]store.GroupRecord{"g": {ID: "g"}}
	s := &Server{policy: policy, mesh: newMeshControl()}
	ra := meshRegistration{Registration: mesh.Registration{TransportPolicy: true, DirectKey: "direct-one", TLSPin: "tls-one", IncomingModes: []string{config.ModeTLSReqTCP}, OutgoingModes: []string{config.ModeWG, config.ModeExtUTP}, Want: []netip.Addr{b}}, ip: a, key: one.PubKey, until: now.Add(10 * time.Second)}
	rb := meshRegistration{Registration: mesh.Registration{TransportPolicy: true, DirectKey: "direct-two", TLSPin: "tls-two", IncomingModes: []string{config.ModeExtUTP}, OutgoingModes: []string{config.ModeTLSReqTCP}, Want: []netip.Addr{a}}, ip: b, key: two.PubKey, until: now.Add(9 * time.Second)}
	s.mesh.clients[one.ID], s.mesh.clients[two.ID] = ra, rb
	var first, second mesh.Reply
	s.appendPair(&first, one, ra, two.ID, now)
	s.appendPair(&second, two, rb, one.ID, now)
	if len(first.Pairs) != 2 || len(second.Pairs) != 2 {
		t.Fatalf("offers = %v / %v", first.Pairs, second.Pairs)
	}
	fromA, toA := first.Pairs[0], first.Pairs[1]
	if fromA.Mode != config.ModeExtUTP || !fromA.Initiator || fromA.Origin != a || fromA.Key != "direct-two" || fromA.Secret != second.Pairs[1].Secret {
		t.Fatal("wrong A -> B grant")
	}
	if toA.Mode != config.ModeTLSReqTCP || toA.Initiator || toA.Origin != b || toA.Key != "tls-two" || toA.Secret != second.Pairs[0].Secret || toA.Secret == fromA.Secret || !toA.Expires.Equal(rb.until) {
		t.Fatal("wrong B -> A grant")
	}
	two.VisiblePeers = []string{}
	policy.byIP[b] = two
	var denied mesh.Reply
	s.appendPair(&denied, one, ra, two.ID, now)
	if len(denied.Pairs) != 0 {
		t.Fatal("denied peer received direct grants")
	}
}
