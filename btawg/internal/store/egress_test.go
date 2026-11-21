package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func egressFixture(t *testing.T, s *Store) {
	t.Helper()
	if err := s.SaveGroup(group("allowed", "10.77.8.0/24", "10.77.8.1")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []ClientRecord{
		{ID: "origin", PubKey: "origin-key", PeerID: "origin-peer", GroupID: DefaultGroupID, Internet: new(false)},
		{ID: "member", PubKey: "member-key", PeerID: "member-peer", GroupID: "allowed"},
		{ID: "outsider", PubKey: "outsider-key", PeerID: "outsider-peer", GroupID: DefaultGroupID, Internet: new(true)},
		{ID: "transit", PubKey: "transit-key", PeerID: "transit-peer", GroupID: "allowed"},
		{ID: "exit", PubKey: "exit-key", PeerID: "exit-peer", GroupID: DefaultGroupID},
	} {
		if err := s.AllocateClient(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetEgressRole("exit", EgressRole{Exit: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEgressRole("transit", EgressRole{Transit: true}); err != nil {
		t.Fatal(err)
	}
}

func assertEgressDenied(t *testing.T, s *Store, origin, id string) {
	t.Helper()
	if r, hops, err := s.ResolveEgressRoute(origin, id); !errors.Is(err, ErrEgressRouteUnavailable) || r.ID != "" || len(hops) != 0 {
		t.Fatalf("ResolveEgressRoute(%q, %q) = %+v, %v hops, %v; want denial", origin, id, r, len(hops), err)
	}
	routes, err := s.AuthorizedEgressRoutes(origin)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.ID == id {
			t.Fatalf("AuthorizedEgressRoutes(%q) exposed denied route %q", origin, id)
		}
	}
}

func TestEgressRoutesPersistCRUDAndAuthorization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s != nil {
			s.Close()
		}
	})
	egressFixture(t, s)
	cascade := EgressRoute{ID: "z", Name: "Cascade", Hops: []string{"transit", "exit"}, Clients: []string{"origin"}, Groups: []string{"allowed"}}
	for _, r := range []EgressRoute{cascade, {ID: "a", Name: "Nobody", Hops: []string{"exit"}}} {
		if err := s.SaveEgressRoute(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := s.ListEgressRoutes()
	if err != nil || len(routes) != 2 || routes[0].ID != "a" || !reflect.DeepEqual(routes[1], cascade) {
		t.Fatalf("persisted routes = %+v, %v; want sorted a, z", routes, err)
	}
	if role, err := s.EgressRole("transit"); err != nil || role != (EgressRole{Transit: true}) {
		t.Fatalf("persisted transit role = %+v, %v", role, err)
	}
	var authorization uint64
	for _, origin := range []string{"origin", "member"} {
		r, hops, err := s.ResolveEgressRoute(origin, "z")
		if r.Authorization == 0 {
			t.Fatal("missing authorization generation")
		}
		authorization = r.Authorization
		r.Authorization = 0
		if err != nil || !reflect.DeepEqual(r, cascade) || len(hops) != 2 || hops[0].ID != "transit" || hops[1].ID != "exit" {
			t.Fatalf("resolved %s = %+v, %d hops, %v; want ordered transit, exit", origin, r, len(hops), err)
		}
		grants, err := s.AuthorizedEgressRoutes(origin)
		if err != nil || len(grants) != 1 || grants[0].ID != "z" {
			t.Fatalf("authorized %s = %+v, %v; want only z", origin, grants, err)
		}
	}
	assertEgressDenied(t, s, "outsider", "z") // Hub Internet access does not grant named routes.
	assertEgressDenied(t, s, "outsider", "hub")
	assertEgressDenied(t, s, "origin", "a")  // Empty ACL grants nobody.
	assertEgressDenied(t, s, "transit", "z") // Even group members cannot relay to themselves.
	assertEgressDenied(t, s, "missing", "z")
	cascade.Name = "Renamed"
	if err := s.SaveEgressRoute(cascade); err != nil {
		t.Fatal(err)
	}
	if r, _, err := s.ResolveEgressRoute("origin", "z"); err != nil || r.Name != "Renamed" || r.Authorization != authorization {
		t.Fatalf("rename did not retain authorization: %+v, %v", r, err)
	}
	if err := s.SetEgressRole("exit", EgressRole{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEgressRole("exit", EgressRole{Exit: true}); err != nil {
		t.Fatal(err)
	}
	if r, _, err := s.ResolveEgressRoute("origin", "z"); err != nil || r.Authorization <= authorization {
		t.Fatalf("regrant retained generation %d: %+v, %v", authorization, r, err)
	}
	if err := s.DeleteEgressRoute("z"); err != nil {
		t.Fatal(err)
	}
	assertEgressDenied(t, s, "origin", "z")
	if routes, err := s.ListEgressRoutes(); err != nil || len(routes) != 1 || routes[0].ID != "a" {
		t.Fatalf("remaining routes = %+v, %v; want only a", routes, err)
	}
}

func TestSaveEgressRouteRejectsInvalidReferencesAndOrder(t *testing.T) {
	s := testStore(t)
	egressFixture(t, s)
	if err := s.SetEgressRole("exit", EgressRole{Exit: true, Transit: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeClient("outsider"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*EgressRoute)
	}{
		{"empty ID", func(r *EgressRoute) { r.ID = "" }},
		{"reserved ID", func(r *EgressRoute) { r.ID = "hub" }},
		{"blank name", func(r *EgressRoute) { r.Name = " \t" }},
		{"no exit", func(r *EgressRoute) { r.Hops = nil }},
		{"too many hops", func(r *EgressRoute) { r.Hops = []string{"origin", "transit", "exit"} }},
		{"wrong order", func(r *EgressRoute) { r.Hops = []string{"exit", "transit"} }},
		{"duplicate hop", func(r *EgressRoute) { r.Hops = []string{"exit", "exit"} }},
		{"missing hop", func(r *EgressRoute) { r.Hops = []string{"missing"} }},
		{"explicit origin is hop", func(r *EgressRoute) { r.Clients = []string{"exit"} }},
		{"missing audience client", func(r *EgressRoute) { r.Clients = []string{"missing"} }},
		{"revoked audience client", func(r *EgressRoute) { r.Clients = []string{"outsider"} }},
		{"missing audience group", func(r *EgressRoute) { r.Groups = []string{"missing"} }},
		{"wildcard audience", func(r *EgressRoute) { r.Groups = []string{"*"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := EgressRoute{ID: "route", Name: "Named", Hops: []string{"exit"}, Clients: []string{"origin"}}
			tc.edit(&r)
			if err := s.SaveEgressRoute(r); err == nil {
				t.Fatal("saved invalid route")
			}
		})
	}
	if err := s.SetEgressRole("outsider", EgressRole{Exit: true}); err == nil {
		t.Fatal("assigned a role to a revoked device")
	}
	if err := s.SetEgressRole("missing", EgressRole{Exit: true}); err == nil {
		t.Fatal("assigned a role to a missing device")
	}
	if routes, err := s.ListEgressRoutes(); err != nil || len(routes) != 0 {
		t.Fatalf("rejected saves persisted routes: %+v, %v", routes, err)
	}
}

func TestEgressAuthorizationTracksClientAndRoleChanges(t *testing.T) {
	for _, change := range []string{"role removed", "hop revoked", "hop IP reused", "hop identity replaced", "origin revoked", "origin ID reused", "group membership changed"} {
		t.Run(change, func(t *testing.T) {
			s := testStore(t)
			egressFixture(t, s)
			origin := "origin"
			if change == "group membership changed" {
				origin = "member"
			}
			r := EgressRoute{ID: "route", Name: "Named", Hops: []string{"transit", "exit"}, Clients: []string{"origin"}, Groups: []string{"allowed"}}
			if err := s.SaveEgressRoute(r); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.ResolveEgressRoute(origin, r.ID); err != nil {
				t.Fatalf("before %s: %v", change, err)
			}
			var err error
			switch change {
			case "role removed":
				err = s.SetEgressRole("transit", EgressRole{Exit: true})
			case "hop revoked":
				err = s.RevokeClient("exit")
			case "hop IP reused", "hop identity replaced", "origin ID reused":
				id := "exit"
				if change == "origin ID reused" {
					id = "origin"
				}
				c, err := s.GetClient(id)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.DeleteClient(id); err != nil {
					t.Fatal(err)
				}
				if change == "hop IP reused" {
					c.ID = "replacement"
				}
				c.PubKey, c.PeerID = "new-key", "new-peer"
				if err := s.AllocateClient(c); err != nil {
					t.Fatal(err)
				}
				if change != "origin ID reused" {
					if role, err := s.EgressRole(c.ID); err != nil || role.Exit {
						t.Fatalf("replacement inherited exit role: %+v, %v", role, err)
					}
					// Even explicitly setting the new device's role cannot transfer the old route.
					if err := s.SetEgressRole(c.ID, EgressRole{Exit: true}); err != nil {
						t.Fatal(err)
					}
				}
			case "origin revoked":
				err = s.RevokeClient("origin")
			case "group membership changed":
				err = s.MoveClient("member", DefaultGroupID)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertEgressDenied(t, s, origin, r.ID)
			if routes, err := s.ListEgressRoutes(); err != nil || len(routes) != 1 || routes[0].ID != r.ID {
				t.Fatalf("admin lost stale route: %+v, %v", routes, err)
			}
			if err := s.DeleteEgressRoute(r.ID); err != nil {
				t.Fatalf("admin cannot delete stale route: %v", err)
			}
		})
	}
}

func TestEgressRoutesRefuseADeviceUnderAnotherID(t *testing.T) {
	s := testStore(t)
	egressFixture(t, s)
	if err := s.AllocateClient(ClientRecord{ID: "alias", PubKey: "EXIT-KEY", PeerID: "alias-peer", GroupID: "allowed"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEgressRole("alias", EgressRole{Transit: true}); err != nil {
		t.Fatal(err)
	}
	route := EgressRoute{ID: "route", Name: "Named", Hops: []string{"alias", "exit"}, Clients: []string{"origin"}}
	if err := s.SaveEgressRoute(route); err == nil {
		t.Fatal("saved transit and exit with the same public key")
	}
	route.Hops = []string{"exit"}
	route.Groups = []string{"allowed"}
	if err := s.SaveEgressRoute(route); err != nil {
		t.Fatal(err)
	}
	assertEgressDenied(t, s, "alias", route.ID)
}

func TestResolveEgressRouteUsesSingleSnapshotDuringGroupRenumber(t *testing.T) {
	s := testStore(t)
	egressFixture(t, s)
	if err := s.MoveClient("exit", "allowed"); err != nil {
		t.Fatal(err)
	}
	route := EgressRoute{ID: "route", Name: "Named", Hops: []string{"transit", "exit"}, Clients: []string{"origin"}}
	if err := s.SaveEgressRoute(route); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	renumbered := make(chan error, 1)
	go func() {
		<-start
		for i := range 50 {
			prefix := fmt.Sprintf("10.77.%d.", 8+i%2)
			if err := s.SaveGroup(group("allowed", prefix+"0/24", prefix+"1")); err != nil {
				renumbered <- err
				return
			}
		}
		renumbered <- nil
	}()
	close(start)
	defer func() {
		if err := <-renumbered; err != nil {
			t.Error(err)
		}
	}()
	for range 50 {
		_, hops, err := s.ResolveEgressRoute("origin", route.ID)
		if err != nil || len(hops) != 2 {
			t.Fatalf("renumbering changed route grant: %d hops, %v", len(hops), err)
		}
		ip1, ip2 := hops[0].IP, hops[1].IP
		bothInOld := strings.HasPrefix(ip1, "10.77.8.") && strings.HasPrefix(ip2, "10.77.8.")
		bothInNew := strings.HasPrefix(ip1, "10.77.9.") && strings.HasPrefix(ip2, "10.77.9.")
		if !bothInOld && !bothInNew {
			t.Fatalf("mixed subnet snapshots: %s and %s", ip1, ip2)
		}
	}
}

func TestEgressRouteReusesNeitherDeletedIDsNorUnchangedStaleBindings(t *testing.T) {
	s := testStore(t)
	egressFixture(t, s)
	r := EgressRoute{ID: "route", Name: "Named", Hops: []string{"exit"}, Clients: []string{"origin"}, Groups: []string{"allowed"}}
	if err := s.SaveEgressRoute(r); err != nil {
		t.Fatal(err)
	}
	origin, err := s.GetClient("origin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteClient(origin.ID); err != nil {
		t.Fatal(err)
	}
	// An exact reenrollment is a new registration even if all fields match.
	if err := s.AllocateClient(origin); err != nil {
		t.Fatal(err)
	}
	assertEgressDenied(t, s, "origin", r.ID)
	r.Name = "Renamed"
	if err := s.SaveEgressRoute(r); !errors.Is(err, ErrInvalidEgressRoute) {
		t.Fatalf("rename repinned stale origin: %v", err)
	}
	r.Clients = nil
	if err := s.SaveEgressRoute(r); err != nil {
		t.Fatalf("remove stale grant: %v", err)
	}
	r.Clients = []string{"origin"}
	if err := s.SaveEgressRoute(r); err != nil {
		t.Fatalf("add new grant: %v", err)
	}
	if _, _, err := s.ResolveEgressRoute("origin", r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEgressRoute(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEgressRoute(r); !errors.Is(err, ErrInvalidEgressRoute) {
		t.Fatalf("reused deleted route ID: %v", err)
	}
}

func TestEgressRouteDoesNotGrantRecreatedGroup(t *testing.T) {
	s := testStore(t)
	egressFixture(t, s)
	g := group("old", "10.77.15.0/24", "10.77.15.1")
	if err := s.SaveGroup(g); err != nil {
		t.Fatal(err)
	}
	r := EgressRoute{ID: "route", Name: "Named", Hops: []string{"exit"}, Groups: []string{g.ID}}
	if err := s.SaveEgressRoute(r); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveGroup(g); err != nil {
		t.Fatal(err)
	}
	if err := s.MoveClient("origin", g.ID); err != nil {
		t.Fatal(err)
	}
	assertEgressDenied(t, s, "origin", r.ID)
	if err := s.SaveEgressRoute(r); !errors.Is(err, ErrInvalidEgressRoute) {
		t.Fatalf("repinned stale group: %v", err)
	}
}

func TestEgressRouteNameAndCatalogueLimits(t *testing.T) {
	s := testStore(t)
	egressFixture(t, s)
	r := EgressRoute{ID: "first", Name: strings.Repeat("é", 65), Hops: []string{"exit"}}
	if err := s.SaveEgressRoute(r); !errors.Is(err, ErrInvalidEgressRoute) {
		t.Fatalf("saved 130-byte name: %v", err)
	}
	r.Name = strings.Repeat("é", 64)
	if err := s.SaveEgressRoute(r); err != nil {
		t.Fatalf("rejected 128-byte name: %v", err)
	}
	for i := range 127 {
		r.ID = fmt.Sprintf("route-%d", i)
		if err := s.SaveEgressRoute(r); err != nil {
			t.Fatalf("save %s: %v", r.ID, err)
		}
	}
	r.ID = "overflow"
	if err := s.SaveEgressRoute(r); !errors.Is(err, ErrInvalidEgressRoute) {
		t.Fatalf("saved 129th route: %v", err)
	}
	r.ID = "first"
	r.Name = "Rename at capacity"
	if err := s.SaveEgressRoute(r); err != nil {
		t.Fatalf("cannot edit at limit: %v", err)
	}
	if err := s.DeleteEgressRoute(r.ID); err != nil {
		t.Fatal(err)
	}
	r.ID = "new"
	if err := s.SaveEgressRoute(r); err != nil {
		t.Fatalf("delete did not free capacity: %v", err)
	}
}
