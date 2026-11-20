package e2e

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

func TestTLSSessionRetirement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	relay := newRelay(t)
	hub, st, recs := hubWithClients(t, ctx, relay, []clientSpec{{id: "tls-client", ip: "10.77.0.2"}}, config.ModeTLSExtTCP)
	rec := *recs[0]
	start := func(rec store.ClientRecord) {
		t.Helper()
		cc := clientConfigFor(hub, &rec, relay, rec.IP)
		cc.CarrierEndpoint = net.JoinHostPort("127.0.0.1", strconv.Itoa(hub.Config().CarrierPort))
		c, err := client.New(cc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		go c.Run(ctx)
	}
	wait := func(want int) {
		t.Helper()
		until := time.Now().Add(2 * time.Second)
		for {
			got := hub.ConnectedCount()[rec.IP]
			if got == want {
				return
			}
			if time.Now().After(until) {
				t.Fatalf("active sessions for %s = %d, want %d", rec.IP, got, want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	start(rec)
	wait(1)
	rotated := rec
	rotated.PrivKey = strings.Repeat("ed", 32)
	if err := st.SaveClient(rotated); err != nil {
		t.Fatal(err)
	}
	if err := hub.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	wait(0)
	start(rotated)
	wait(1)
	// An incompatible group update makes a netstack reload fail before
	// touching peers. A persisted revocation must still close this user.
	if err := st.SaveGroup(store.GroupRecord{ID: "extra", Name: "Extra", Subnet: "10.78.0.0/24", ServerIP: "10.78.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeClient(rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := hub.RevokeClient(rotated); err == nil {
		t.Fatal("expected netstack group reload to fail")
	}
	wait(0)
}
