package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"bittorrent-tunnel/btawg/internal/config"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/store.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func client(id, ip, peerID string) ClientRecord {
	return ClientRecord{ID: id, Name: "client-" + id, PubKey: id + "pub", PrivKey: id + "priv", IP: ip, PeerID: peerID, Created: time.Unix(1, 0), GroupID: DefaultGroupID, Internet: new(true), VisiblePeers: []string{"*"}}
}

// canon makes a record comparable after a store round-trip: a time.Time
// that went through JSON unmarshalling carries a nil location while
// time.Unix carries Local, and reflect.DeepEqual on that is TZ-dependent
// (fails under TZ=UTC). Normalizing both sides to UTC keeps the whole
// suite runnable in any timezone.
func canon(r ClientRecord) ClientRecord {
	r.Created = r.Created.UTC()
	return r
}

func TestServerConfigRoundTrip(t *testing.T) {
	s := testStore(t)
	def, err := s.LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig on empty store: %v", err)
	}
	if def != config.DefaultServerConfig() {
		t.Fatalf("empty store returned %+v, want defaults", def)
	}
	want := config.DefaultServerConfig()
	want.Transport = "ext-tcp"
	want.ExternalIP = "203.0.113.7"
	if err := s.SaveServerConfig(want); err != nil {
		t.Fatalf("SaveServerConfig: %v", err)
	}
	got, err := s.LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if got != want {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestClientCRUD(t *testing.T) {
	s := testStore(t)
	a := client("id-a", "10.77.0.2", "peerid-a")
	b := client("id-b", "10.77.0.3", "peerid-b")
	if err := s.CreateClient(a); err != nil {
		t.Fatalf("CreateClient a: %v", err)
	}
	if err := s.CreateClient(b); err != nil {
		t.Fatalf("CreateClient b: %v", err)
	}
	list, err := s.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(list) != 2 || !reflect.DeepEqual(canon(list[0]), canon(a)) || !reflect.DeepEqual(canon(list[1]), canon(b)) {
		t.Fatalf("ListClients = %+v, want [a b]", list)
	}
	got, err := s.GetClient("id-a")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !reflect.DeepEqual(canon(got), canon(a)) {
		t.Fatalf("GetClient = %+v, want %+v", got, a)
	}
	if err := s.RevokeClient("id-a"); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	got, err = s.GetClient("id-a")
	if err != nil {
		t.Fatalf("GetClient after revoke: %v", err)
	}
	if !got.Revoked {
		t.Fatal("revoke did not set Revoked")
	}
	if err := s.DeleteClient("id-a"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, err := s.GetClient("id-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetClient after delete = %v, want ErrNotFound", err)
	}
	list, err = s.ListClients()
	if err != nil {
		t.Fatalf("ListClients after delete: %v", err)
	}
	if len(list) != 1 || list[0].ID != "id-b" {
		t.Fatalf("ListClients after delete = %+v, want [b]", list)
	}
}

func TestCreateRejectsDuplicateIP(t *testing.T) {
	s := testStore(t)
	if err := s.CreateClient(client("id-a", "10.77.0.2", "peerid-a")); err != nil {
		t.Fatalf("CreateClient a: %v", err)
	}
	if err := s.CreateClient(client("id-b", "10.77.0.2", "peerid-b")); !errors.Is(err, ErrDuplicateIP) {
		t.Fatalf("duplicate IP create = %v, want ErrDuplicateIP", err)
	}
	if err := s.CreateClient(client("id-c", "10.77.0.4", "peerid-a")); !errors.Is(err, ErrDuplicatePeerID) {
		t.Fatalf("duplicate peer ID create = %v, want ErrDuplicatePeerID", err)
	}
	if _, err := s.GetClient("id-b"); !errors.Is(err, ErrNotFound) {
		t.Fatal("rejected client id-b was stored")
	}
}

func TestPolicyFieldsRoundTripAndLegacyDefaults(t *testing.T) {
	s := testStore(t)

	// Round-trip: policy fields survive CreateClient/GetClient.
	want := client("id-policy", "10.77.0.5", "peerid-policy")
	want.NoInternet = true
	want.Internet = new(false)
	want.VisiblePeers = []string{"c2"}
	if err := s.CreateClient(want); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, err := s.GetClient(want.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !reflect.DeepEqual(canon(got), canon(want)) {
		t.Fatalf("policy round trip mismatch:\n got %+v\nwant %+v", got, want)
	}

	// Round-trip: an explicit empty VisiblePeers slice means "no peers" and
	// must stay distinct from the nil/legacy "all peers" default.
	empty := client("id-empty", "10.77.0.6", "peerid-empty")
	empty.VisiblePeers = []string{}
	if err := s.CreateClient(empty); err != nil {
		t.Fatalf("CreateClient empty peers: %v", err)
	}
	gotEmpty, err := s.GetClient(empty.ID)
	if err != nil {
		t.Fatalf("GetClient empty peers: %v", err)
	}
	if gotEmpty.VisiblePeers == nil || len(gotEmpty.VisiblePeers) != 0 {
		t.Fatalf("empty VisiblePeers round trip = %v, want non-nil zero-length slice", gotEmpty.VisiblePeers)
	}

	// Legacy record written as raw JSON without the new fields.
	legacyID := "id-legacy"
	legacyRaw := []byte(`{"id":"id-legacy","name":"client-legacy","pubkey":"legacypub","privkey":"legacypriv","ip":"10.77.0.9","peer_id":"peerid-legacy","created":"1970-01-01T00:00:01Z","revoked":false}`)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).Put([]byte(legacyID), legacyRaw)
	}); err != nil {
		t.Fatalf("legacy raw write: %v", err)
	}

	got, err = s.GetClient(legacyID)
	if err != nil {
		t.Fatalf("GetClient legacy: %v", err)
	}
	if got.GroupID != DefaultGroupID {
		t.Errorf("legacy GroupID = %q, want %q", got.GroupID, DefaultGroupID)
	}
	if got.NoInternet {
		t.Errorf("legacy NoInternet = true, want false")
	}
	if got.Internet == nil || *got.Internet != true {
		t.Errorf("legacy Internet = %v, want true", got.Internet)
	}
	if !reflect.DeepEqual(got.VisiblePeers, []string{"*"}) {
		t.Errorf("legacy VisiblePeers = %v, want [\"*\"]", got.VisiblePeers)
	}

	list, err := s.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	var found bool
	for _, r := range list {
		if r.ID == legacyID {
			found = true
			if r.GroupID != DefaultGroupID {
				t.Errorf("ListClients legacy GroupID = %q, want %q", r.GroupID, DefaultGroupID)
			}
			if r.NoInternet {
				t.Errorf("ListClients legacy NoInternet = true, want false")
			}
			if r.Internet == nil || *r.Internet != true {
				t.Errorf("ListClients legacy Internet = %v, want true", r.Internet)
			}
			if !reflect.DeepEqual(r.VisiblePeers, []string{"*"}) {
				t.Errorf("ListClients legacy VisiblePeers = %v, want [\"*\"]", r.VisiblePeers)
			}
		}
	}
	if !found {
		t.Errorf("legacy client not found in ListClients")
	}
}

func TestSaveClientPreservesNilVisiblePeers(t *testing.T) {
	s := testStore(t)
	rec := client("id-save", "10.77.0.10", "peerid-save")
	if err := s.CreateClient(rec); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	rec.VisiblePeers = nil
	if err := s.SaveClient(rec); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	got, err := s.GetClient(rec.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.VisiblePeers != nil {
		t.Fatalf("VisiblePeers = %v, want nil (inherit)", got.VisiblePeers)
	}
	if err := s.SaveClient(ClientRecord{ID: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SaveClient missing = %v, want ErrNotFound", err)
	}
}

func group(id, subnet, serverIP string) GroupRecord {
	return GroupRecord{ID: id, Name: "group-" + id, Subnet: subnet, ServerIP: serverIP}
}

func TestDefaultGroupCreatedFromConfig(t *testing.T) {
	s := testStore(t)
	groups, err := s.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("len(groups) = %d, want 1", len(groups))
	}
	g := groups[0]
	if g.ID != DefaultGroupID {
		t.Errorf("default group ID = %q, want %q", g.ID, DefaultGroupID)
	}
	cfg, _ := s.LoadServerConfig()
	if g.Subnet != cfg.Subnet {
		t.Errorf("default subnet = %q, want %q", g.Subnet, cfg.Subnet)
	}
	if g.ServerIP != cfg.ServerIP {
		t.Errorf("default server IP = %q, want %q", g.ServerIP, cfg.ServerIP)
	}
	if g.VisibleGroups != nil {
		t.Errorf("default VisibleGroups = %v, want nil", g.VisibleGroups)
	}
}

func TestGroupCRUD(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	got, err := s.GetGroup(g.ID)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.Name != g.Name || got.Subnet != g.Subnet {
		t.Fatalf("GetGroup = %+v, want %+v", got, g)
	}
	groups, err := s.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}

	g.Name = "renamed"
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup update: %v", err)
	}
	got, _ = s.GetGroup(g.ID)
	if got.Name != "renamed" {
		t.Errorf("name = %q, want renamed", got.Name)
	}

	if err := s.DeleteGroup(g.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, err := s.GetGroup(g.ID); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("GetGroup after delete = %v, want ErrGroupNotFound", err)
	}
}

func TestGroupValidation(t *testing.T) {
	s := testStore(t)
	base := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(base); err != nil {
		t.Fatalf("SaveGroup base: %v", err)
	}

	cases := []struct {
		name string
		g    GroupRecord
	}{
		{"bad cidr", group("bad", "not-a-cidr", "10.78.1.1")},
		{"ipv6", group("bad", "2001:db8::/32", "2001:db8::1")},
		{"server outside", group("bad", "10.78.1.0/24", "10.78.2.1")},
		{"server network", group("bad", "10.78.1.0/24", "10.78.1.0")},
		{"server broadcast", group("bad", "10.78.1.0/24", "10.78.1.255")},
		{"overlap", group("bad", "10.78.0.128/25", "10.78.0.129")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.SaveGroup(tc.g); err == nil {
				t.Fatalf("SaveGroup %s: expected error", tc.name)
			}
		})
	}
}

func TestGroupVisibleGroupsSemantics(t *testing.T) {
	s := testStore(t)
	cases := []struct {
		name string
		vg   []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"star", []string{"*"}},
		{"ids", []string{"g1", "g2"}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := group(tc.name, fmt.Sprintf("10.78.%d.0/24", i), fmt.Sprintf("10.78.%d.1", i))
			g.VisibleGroups = tc.vg
			if err := s.SaveGroup(g); err != nil {
				t.Fatalf("SaveGroup: %v", err)
			}
			got, err := s.GetGroup(g.ID)
			if err != nil {
				t.Fatalf("GetGroup: %v", err)
			}
			if tc.vg == nil {
				if got.VisibleGroups != nil {
					t.Fatalf("VisibleGroups = %v, want nil", got.VisibleGroups)
				}
			} else if !reflect.DeepEqual(got.VisibleGroups, tc.vg) {
				t.Fatalf("VisibleGroups = %v, want %v", got.VisibleGroups, tc.vg)
			}
		})
	}
}

func TestAllocateClientAssignsIPInsideGroup(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	rec := ClientRecord{ID: "c1", Name: "client1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID}
	if err := s.AllocateClient(rec); err != nil {
		t.Fatalf("AllocateClient: %v", err)
	}
	got, err := s.GetClient(rec.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.GroupID != g.ID {
		t.Errorf("GroupID = %q, want %q", got.GroupID, g.ID)
	}
	if got.IP == "" {
		t.Fatal("expected allocated IP")
	}
	if !ipInPrefix(got.IP, g.Subnet) {
		t.Fatalf("IP %s not in %s", got.IP, g.Subnet)
	}
	if got.IP == g.ServerIP || got.IP == networkAddr(g.Subnet) || got.IP == broadcastAddr(g.Subnet) {
		t.Fatalf("IP %s is reserved", got.IP)
	}
}

func TestAllocateClientKeepsExplicitIP(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	rec := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID, IP: "10.78.0.5"}
	if err := s.AllocateClient(rec); err != nil {
		t.Fatalf("AllocateClient: %v", err)
	}
	got, _ := s.GetClient(rec.ID)
	if got.IP != "10.78.0.5" {
		t.Fatalf("IP = %q, want 10.78.0.5", got.IP)
	}
}

func TestAllocateClientRejectsInvalidIP(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	rec := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID, IP: "10.79.0.5"}
	if err := s.AllocateClient(rec); err == nil {
		t.Fatal("expected error for IP outside subnet")
	}
}

func TestAllocateClientRejectsReservedIP(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	for _, ip := range []string{"10.78.0.0", "10.78.0.255", "10.78.0.1"} {
		rec := ClientRecord{ID: ip, PubKey: "pk" + ip, PrivKey: "priv" + ip, PeerID: "peer" + ip, Created: time.Unix(1, 0), GroupID: g.ID, IP: ip}
		if err := s.AllocateClient(rec); err == nil {
			t.Fatalf("expected error for reserved IP %s", ip)
		}
	}
}

func TestAllocateClientRejectsDuplicatesAndExhaustion(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/30", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	c1 := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID, IP: "10.78.0.2"}
	if err := s.AllocateClient(c1); err != nil {
		t.Fatalf("AllocateClient c1: %v", err)
	}
	c2 := ClientRecord{ID: "c2", PubKey: "pk2", PrivKey: "priv2", PeerID: "peer2", Created: time.Unix(1, 0), GroupID: g.ID, IP: "10.78.0.2"}
	if err := s.AllocateClient(c2); !errors.Is(err, ErrDuplicateIP) {
		t.Fatalf("duplicate IP = %v, want ErrDuplicateIP", err)
	}
	c3 := ClientRecord{ID: "c3", PubKey: "pk3", PrivKey: "priv3", PeerID: "peer3", Created: time.Unix(1, 0), GroupID: g.ID}
	if err := s.AllocateClient(c3); !errors.Is(err, ErrSubnetExhausted) {
		t.Fatalf("exhausted = %v, want ErrSubnetExhausted", err)
	}
}

func TestAllocateClientRejectsDuplicatePeerID(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	c1 := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID, IP: "10.78.0.2"}
	if err := s.AllocateClient(c1); err != nil {
		t.Fatalf("AllocateClient c1: %v", err)
	}
	c2 := ClientRecord{ID: "c2", PubKey: "pk2", PrivKey: "priv2", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID, IP: "10.78.0.3"}
	if err := s.AllocateClient(c2); !errors.Is(err, ErrDuplicatePeerID) {
		t.Fatalf("duplicate peer ID = %v, want ErrDuplicatePeerID", err)
	}
}

func TestAllocateClientConcurrent(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := ClientRecord{
				ID: fmt.Sprintf("c%d", i), Name: fmt.Sprintf("c%d", i),
				PubKey: fmt.Sprintf("pk%d", i), PrivKey: fmt.Sprintf("priv%d", i),
				PeerID: fmt.Sprintf("peer%d", i), Created: time.Unix(1, 0),
				GroupID: g.ID,
			}
			if err := s.AllocateClient(rec); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("concurrent allocation errors: %v", errs)
	}
	clients, err := s.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	seen := make(map[string]bool)
	count := 0
	for _, c := range clients {
		if c.GroupID != g.ID {
			continue
		}
		count++
		if seen[c.IP] {
			t.Fatalf("duplicate IP %s", c.IP)
		}
		seen[c.IP] = true
	}
	if count != n {
		t.Fatalf("allocated %d clients, want %d", count, n)
	}
}

func TestMoveClient(t *testing.T) {
	s := testStore(t)
	g1 := group("g1", "10.78.0.0/24", "10.78.0.1")
	g2 := group("g2", "10.79.0.0/24", "10.79.0.1")
	if err := s.SaveGroup(g1); err != nil {
		t.Fatalf("SaveGroup g1: %v", err)
	}
	if err := s.SaveGroup(g2); err != nil {
		t.Fatalf("SaveGroup g2: %v", err)
	}
	rec := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g1.ID, IP: "10.78.0.5"}
	if err := s.AllocateClient(rec); err != nil {
		t.Fatalf("AllocateClient: %v", err)
	}

	if err := s.MoveClient(rec.ID, "missing"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("MoveClient missing = %v, want ErrGroupNotFound", err)
	}

	oldIP := rec.IP
	if err := s.MoveClient(rec.ID, g2.ID); err != nil {
		t.Fatalf("MoveClient: %v", err)
	}
	got, _ := s.GetClient(rec.ID)
	if got.GroupID != g2.ID {
		t.Errorf("GroupID = %q, want %q", got.GroupID, g2.ID)
	}
	if got.IP == oldIP {
		t.Errorf("IP unchanged after move: %s", got.IP)
	}
	if !ipInPrefix(got.IP, g2.Subnet) {
		t.Fatalf("IP %s not in %s", got.IP, g2.Subnet)
	}

	if err := s.MoveClient(rec.ID, g2.ID); err != nil {
		t.Fatalf("MoveClient same group: %v", err)
	}
}

func TestSaveGroupRenumberAtomically(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/28", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	for i := 0; i < 5; i++ {
		rec := ClientRecord{ID: fmt.Sprintf("c%d", i), PubKey: fmt.Sprintf("pk%d", i), PrivKey: fmt.Sprintf("priv%d", i), PeerID: fmt.Sprintf("peer%d", i), Created: time.Unix(1, 0), GroupID: g.ID}
		if err := s.AllocateClient(rec); err != nil {
			t.Fatalf("AllocateClient %d: %v", i, err)
		}
	}

	g.Subnet = "10.79.0.0/28"
	g.ServerIP = "10.79.0.1"
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup renumber: %v", err)
	}

	got, _ := s.GetGroup(g.ID)
	if got.Subnet != g.Subnet || got.ServerIP != g.ServerIP {
		t.Fatalf("group = %+v, want subnet %s serverIP %s", got, g.Subnet, g.ServerIP)
	}
	clients, _ := s.ListClients()
	seen := make(map[string]bool)
	for _, c := range clients {
		if c.GroupID != g.ID {
			continue
		}
		if !ipInPrefix(c.IP, g.Subnet) {
			t.Fatalf("client %s IP %s not in new subnet", c.ID, c.IP)
		}
		if seen[c.IP] {
			t.Fatalf("duplicate IP %s", c.IP)
		}
		seen[c.IP] = true
	}
	if len(seen) != 5 {
		t.Fatalf("renumbered %d clients, want 5", len(seen))
	}

	// Too-small new subnet must fail and leave everything unchanged.
	g.Subnet = "10.80.0.0/30"
	g.ServerIP = "10.80.0.1"
	if err := s.SaveGroup(g); !errors.Is(err, ErrSubnetExhausted) {
		t.Fatalf("too small subnet = %v, want ErrSubnetExhausted", err)
	}
	got, _ = s.GetGroup(g.ID)
	if got.Subnet != "10.79.0.0/28" {
		t.Fatalf("subnet changed after failed renumber: %s", got.Subnet)
	}
}

func TestDeleteGroupRejectsWithClients(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	rec := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID}
	if err := s.AllocateClient(rec); err != nil {
		t.Fatalf("AllocateClient: %v", err)
	}
	if err := s.DeleteGroup(g.ID); !errors.Is(err, ErrGroupNotEmpty) {
		t.Fatalf("DeleteGroup with clients = %v, want ErrGroupNotEmpty", err)
	}
	if err := s.DeleteClient(rec.ID); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if err := s.DeleteGroup(g.ID); err != nil {
		t.Fatalf("DeleteGroup empty: %v", err)
	}
}

func TestMigrationLegacyClients(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/store.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	legacyID := "id-legacy"
	legacyRaw := []byte(`{"id":"id-legacy","name":"client-legacy","pubkey":"legacypub","privkey":"legacypriv","ip":"10.77.0.9","peer_id":"peerid-legacy","created":"1970-01-01T00:00:01Z","revoked":false}`)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).Put([]byte(legacyID), legacyRaw)
	}); err != nil {
		t.Fatalf("legacy raw write: %v", err)
	}
	s.Close()

	s, err = Open(dir + "/store.db")
	if err != nil {
		t.Fatalf("Open second: %v", err)
	}
	defer s.Close()

	got, err := s.GetClient(legacyID)
	if err != nil {
		t.Fatalf("GetClient legacy: %v", err)
	}
	if got.GroupID != DefaultGroupID {
		t.Errorf("GroupID = %q, want %q", got.GroupID, DefaultGroupID)
	}
	if got.Internet == nil || *got.Internet != true {
		t.Errorf("Internet = %v, want true", got.Internet)
	}
	if !reflect.DeepEqual(got.VisiblePeers, []string{"*"}) {
		t.Errorf("VisiblePeers = %v, want [\"*\"]", got.VisiblePeers)
	}
	if got.IP != "10.77.0.9" {
		t.Errorf("IP = %q, want 10.77.0.9", got.IP)
	}

	list, _ := s.ListGroups()
	found := false
	for _, g := range list {
		if g.ID == DefaultGroupID {
			found = true
		}
	}
	if !found {
		t.Errorf("default group not created during migration")
	}
}

func TestClientPolicyInheritance(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	g.NoInternet = true
	g.VisibleGroups = []string{"g2"}
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	rec := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID}
	if err := s.AllocateClient(rec); err != nil {
		t.Fatalf("AllocateClient: %v", err)
	}
	got, _ := s.GetClient(rec.ID)
	if got.Internet != nil {
		t.Errorf("Internet = %v, want nil", got.Internet)
	}
	if got.VisiblePeers != nil {
		t.Errorf("VisiblePeers = %v, want nil", got.VisiblePeers)
	}

	explicit := false
	rec2 := ClientRecord{ID: "c2", PubKey: "pk2", PrivKey: "priv2", PeerID: "peer2", Created: time.Unix(1, 0), GroupID: g.ID, Internet: &explicit, VisiblePeers: []string{"*"}}
	if err := s.AllocateClient(rec2); err != nil {
		t.Fatalf("AllocateClient c2: %v", err)
	}
	got2, _ := s.GetClient(rec2.ID)
	if got2.Internet == nil || *got2.Internet != false {
		t.Errorf("Internet = %v, want false", got2.Internet)
	}
	if !reflect.DeepEqual(got2.VisiblePeers, []string{"*"}) {
		t.Errorf("VisiblePeers = %v, want [\"*\"]", got2.VisiblePeers)
	}
}

func ipInPrefix(ip, prefix string) bool {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return p.Contains(a)
}

func networkAddr(prefix string) string {
	p, _ := netip.ParsePrefix(prefix)
	return p.Masked().Addr().String()
}

func broadcastAddr(prefix string) string {
	p, _ := netip.ParsePrefix(prefix)
	b := p.Masked().Addr().As4()
	hostBits := 32 - p.Bits()
	if hostBits >= 32 {
		return netip.AddrFrom4(b).String()
	}
	inc := uint32(1) << hostBits
	u := binary.BigEndian.Uint32(b[:]) + inc - 1
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b).String()
}

func TestCreateClientLegacyGroupNormalizesExplicitACL(t *testing.T) {
	s := testStore(t)
	rec := ClientRecord{ID: "legacy", Name: "legacy", PubKey: "pk", PrivKey: "priv", IP: "10.77.0.20", PeerID: "peer", Created: time.Unix(1, 0)}
	if err := s.CreateClient(rec); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, _ := s.GetClient(rec.ID)
	if got.GroupID != DefaultGroupID {
		t.Errorf("GroupID = %q, want %q", got.GroupID, DefaultGroupID)
	}
	if got.Internet == nil || *got.Internet != true {
		t.Errorf("Internet = %v, want true", got.Internet)
	}
	if !reflect.DeepEqual(got.VisiblePeers, []string{"*"}) {
		t.Errorf("VisiblePeers = %v, want [\"*\"]", got.VisiblePeers)
	}

	rec2 := ClientRecord{ID: "legacy-denied", Name: "legacy-denied", PubKey: "pk2", PrivKey: "priv2", IP: "10.77.0.21", PeerID: "peer2", Created: time.Unix(1, 0), NoInternet: true}
	if err := s.CreateClient(rec2); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got2, _ := s.GetClient(rec2.ID)
	if got2.Internet == nil || *got2.Internet != false {
		t.Errorf("Internet = %v, want false", got2.Internet)
	}
}

func TestSaveClientVerifiesIPGroupConsistency(t *testing.T) {
	s := testStore(t)
	g := group("g1", "10.78.0.0/24", "10.78.0.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	rec := ClientRecord{ID: "c1", PubKey: "pk1", PrivKey: "priv1", PeerID: "peer1", Created: time.Unix(1, 0), GroupID: g.ID}
	if err := s.AllocateClient(rec); err != nil {
		t.Fatalf("AllocateClient: %v", err)
	}

	got, _ := s.GetClient(rec.ID)
	got.IP = "10.99.0.5"
	if err := s.SaveClient(got); !errors.Is(err, ErrInvalidSubnet) {
		t.Fatalf("SaveClient outside subnet = %v, want ErrInvalidSubnet", err)
	}

	got.IP = "10.78.0.0"
	if err := s.SaveClient(got); !errors.Is(err, ErrInvalidSubnet) {
		t.Fatalf("SaveClient network IP = %v, want ErrInvalidSubnet", err)
	}

	got.GroupID = "missing"
	if err := s.SaveClient(got); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("SaveClient missing group = %v, want ErrGroupNotFound", err)
	}
}
