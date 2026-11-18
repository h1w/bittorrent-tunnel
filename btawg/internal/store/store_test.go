package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

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
	return ClientRecord{ID: id, Name: "client-" + id, PubKey: id + "pub", PrivKey: id + "priv", IP: ip, PeerID: peerID, Created: time.Unix(1, 0)}
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
	if len(list) != 2 || !reflect.DeepEqual(list[0], a) || !reflect.DeepEqual(list[1], b) {
		t.Fatalf("ListClients = %+v, want [a b]", list)
	}
	got, err := s.GetClient("id-a")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !reflect.DeepEqual(got, a) {
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
