package mesh

import (
	"testing"
	"time"
)

func TestRouteGrantBindsIdentityAndOrderedHops(t *testing.T) {
	var key [32]byte
	key[0] = 1
	origin := Node{ID: "origin", Key: "key-a", IP: "10.77.0.2"}
	transit := Node{ID: "transit", Key: "key-b", IP: "10.77.0.3"}
	exit := Node{ID: "exit", Key: "key-c", IP: "10.77.0.4"}
	now := time.Unix(100, 0)
	grant, err := SealGrant(key, "route", origin, []Node{transit, exit}, now, 41)
	if err != nil {
		t.Fatal(err)
	}
	g, err := OpenGrant(key, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	if g.Authorization != 41 {
		t.Fatalf("grant authorization = %d", g.Authorization)
	}
	if !g.Matches("route", origin, []Node{transit, exit}) {
		t.Fatal("authorized route was rejected")
	}
	if g.Matches("route", origin, []Node{exit, transit}) {
		t.Fatal("reordered hops authorized")
	}
	origin.Key = "replacement"
	if g.Matches("route", origin, []Node{transit, exit}) {
		t.Fatal("replacement key inherited grant")
	}
	if _, err := OpenGrant(key, grant+"x", now); err == nil {
		t.Fatal("modified grant accepted")
	}
	if _, err := OpenGrant(key, grant, now.Add(time.Hour)); err == nil {
		t.Fatal("expired grant accepted")
	}
}
