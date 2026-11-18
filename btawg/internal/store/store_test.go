package store

import (
	"errors"
	"reflect"
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
	return ClientRecord{ID: id, Name: "client-" + id, PubKey: id + "pub", PrivKey: id + "priv", IP: ip, PeerID: peerID, Created: time.Unix(1, 0), VisiblePeers: []string{"*"}}
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
	if got.NoInternet {
		t.Errorf("legacy NoInternet = true, want false")
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
			if r.NoInternet {
				t.Errorf("ListClients legacy NoInternet = true, want false")
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

func TestSaveClientNormalizesNilVisiblePeers(t *testing.T) {
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
	if !reflect.DeepEqual(got.VisiblePeers, []string{"*"}) {
		t.Fatalf("VisiblePeers = %v, want [\"*\"]", got.VisiblePeers)
	}
	if err := s.SaveClient(ClientRecord{ID: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SaveClient missing = %v, want ErrNotFound", err)
	}
}
