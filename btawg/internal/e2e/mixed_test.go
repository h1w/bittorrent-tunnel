package e2e

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/server"
)

func TestMixedTransportStableAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	relay := newRelay(t)
	specs := []clientSpec{{id: "a", ip: "10.77.0.2"}, {id: "b", ip: "10.77.0.3"}, {id: "c", ip: "10.77.0.4"}, {id: "d", ip: "10.77.0.5"}, {id: "e", ip: "10.77.0.6"}, {id: "f", ip: "10.77.0.7"}}
	hub, st, recs := hubWithClients(t, ctx, relay, specs, "ext-utp")
	modes := []string{"ext-tcp", "req-tcp", "ext-utp", "req-utp", "awg", "wg"}
	cs := make([]*client.Client, len(modes))
	ls := make([]net.Listener, len(modes))
	cfg := hub.Config()
	start := func(i int, mode string) *client.Client {
		t.Helper()
		cc := clientConfigFor(hub, recs[i], relay, recs[i].IP)
		cc.Transport = mode
		h, err := config.CarrierHash(hub.InfoHash(), cfg.Transport, mode)
		if mode != "wg" && mode != "awg" {
			if err != nil {
				t.Fatal(err)
			}
			cc.InfoHash = h
		}
		cc.AWGEndpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(cfg.AWGPort)).String()
		cc.WGEndpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(cfg.WGPort)).String()
		cc.CarrierEndpoint = net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.CarrierPort))
		cc.DHTBootstrap = []string{"0.0.0.0:0"}
		c, err := client.New(cc)
		if err != nil {
			t.Fatal(err)
		}
		clientCtx, stop := context.WithCancel(ctx)
		t.Cleanup(c.Close)
		t.Cleanup(stop)
		go c.Run(clientCtx)
		// Give the client an authenticated path to the hub before other peers initiate traffic.
		until := time.Now().Add(18 * time.Second)
		for time.Now().Before(until) {
			dialctx, done := context.WithTimeout(ctx, 450*time.Millisecond)
			conn, e := c.OverlayDialTCP(dialctx, netip.MustParseAddrPort("10.77.0.1:1080"))
			done()
			if e == nil {
				conn.Close()
				return c
			}
		}
		t.Fatalf("%s could not reach hub", mode)
		return nil
	}
	for i, mode := range modes {
		cs[i] = start(i, mode)
		var err error
		ls[i], err = cs[i].OverlayListenTCP(5410)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ls[i].Close() })
		go func(l net.Listener) {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); _, _ = c.Write([]byte("mixed")) }()
			}
		}(ls[i])
	}
	probe := func(from, to int) {
		t.Helper()
		cctx, done := context.WithTimeout(ctx, 3*time.Second)
		defer done()
		addr := netip.AddrPortFrom(netip.MustParseAddr(recs[to].IP), 5410)
		c, e := cs[from].OverlayDialTCP(cctx, addr)
		if e != nil {
			t.Fatalf("%s → %s: %v", modes[from], modes[to], e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		var reply [5]byte
		if _, e = io.ReadFull(c, reply[:]); e != nil || string(reply[:]) != "mixed" {
			t.Fatalf("%s → %s: %q, %v", modes[from], modes[to], reply, e)
		}
	}
	for i := range modes {
		probe(i, (i+1)%len(modes))
	}
	before := hub.Traffic()[recs[5].ID]
	if before.Up == 0 || before.Down == 0 || before.LastSeen == 0 {
		t.Fatalf("WG traffic not accounted: %+v", before)
	}
	// A new stack using the same identity and address can leave WG for AWG.
	ls[5].Close()
	cs[5].Close()
	cs[5] = start(5, "awg")
	probe(5, 0)
	after := hub.Traffic()[recs[5].ID]
	if after.Up <= before.Up || after.Down <= before.Down {
		t.Fatalf("changing transport lost traffic: before %+v, after %+v", before, after)
	}
	if err := hub.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := server.New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	saved := restarted.Traffic()[recs[5].ID]
	if saved.Up < after.Up || saved.Down < after.Down || saved.LastSeen < after.LastSeen {
		t.Fatalf("traffic after restart: got %+v; want at least %+v", saved, after)
	}
}
