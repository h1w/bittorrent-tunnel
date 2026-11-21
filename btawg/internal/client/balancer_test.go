package client

import (
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestManagedBalancerPortsAuthenticateAndFailClosed(t *testing.T) {
	auth := Credentials{Username: "operator", Password: "secret"}
	m, err := newManagedAt(t.Context(), managedCfg(t), nil, netip.MustParseAddr("127.0.0.1"), auth, false, "btawg", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, slot := range []int{10, 11, 12} {
		if slot >= len(m.inbound.slots) {
			t.Fatalf("SOCKS5 inbound %d is missing", 1080+slot)
		}
		addr := m.inbound.slots[slot].ln.Addr().String()
		c, err := proxyAuth(t, addr, auth)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 80}); err != nil {
			t.Fatal(err)
		}
		var reply [10]byte
		_, err = io.ReadFull(c, reply[:])
		c.Close()
		if err != nil || reply[1] == 0 {
			t.Fatalf("empty pool did not return a SOCKS5 failure: %v, %v", reply, err)
		}
	}
}

func TestBalancerSelectionSkipsFailedPathsAndRecovers(t *testing.T) {
	var first, second, dead managedTunnel
	var firstHealth, secondHealth probeHealth
	first.score.Store(int64(firstHealth.observe(40 * time.Millisecond)))
	second.score.Store(int64(secondHealth.observe(10 * time.Millisecond)))
	paths := []*managedTunnel{&first, &dead, &second}

	failover := balancer{paths: paths}
	adaptive := balancer{paths: paths, policy: "adaptive"}
	roundRobin := balancer{paths: paths, policy: "round-robin"}
	assertPick := func(b *balancer, want *managedTunnel) {
		t.Helper()
		if got := b.pick(); got != want {
			t.Fatalf("%q picked %p, want %p", b.policy, got, want)
		}
	}
	assertPick(&failover, &first)
	assertPick(&adaptive, &second)
	for _, want := range []*managedTunnel{&first, &second, &first} {
		assertPick(&roundRobin, want)
	}
	first.score.Store(int64(firstHealth.observe(0)))
	assertPick(&failover, &second)
	first.score.Store(int64(firstHealth.observe(time.Millisecond)))
	assertPick(&failover, &second)
	first.score.Store(int64(firstHealth.observe(time.Millisecond)))
	assertPick(&failover, &first)
	assertPick(&adaptive, &second)
}

func TestAdaptiveRequiresTwoMeaningfullyBetterProbes(t *testing.T) {
	for _, tc := range []struct {
		name                string
		current, challenger time.Duration
		shouldSwitch        bool
	}{
		{"under five milliseconds", 20 * time.Millisecond, 16 * time.Millisecond, false},
		{"under fifteen percent", 100 * time.Millisecond, 86 * time.Millisecond, false},
		{"meets both thresholds", 40 * time.Millisecond, 34 * time.Millisecond, true},
		{"reaches absolute threshold", 20 * time.Millisecond, 15 * time.Millisecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var current, challenger managedTunnel
			current.score.Store(int64(tc.current))
			b := balancer{policy: adaptivePolicy, paths: []*managedTunnel{&current, &challenger}}
			if b.pick() != &current {
				t.Fatal("no initial route")
			}
			challenger.score.Store(int64(tc.challenger))
			b.probed(&challenger, nil)
			b.probed(&current, nil)
			for range 3 {
				if b.pick() != &current {
					t.Fatal("one challenger probe switched traffic")
				}
			}
			b.probed(&challenger, nil)
			if (b.pick() == &challenger) != tc.shouldSwitch {
				t.Fatal("wrong route after two challenger probes")
			}
		})
	}
}

func TestAdaptiveDisconnectInvalidatesCarrierScore(t *testing.T) {
	var stream, native managedTunnel
	stream.carrierMode = true
	done := make(chan struct{})
	old := &carrierHealth{done: done}
	old.score.Store(int64(10 * time.Millisecond))
	stream.carrier.Store(old)
	stream.score.Store(int64(10 * time.Millisecond))
	native.score.Store(int64(30 * time.Millisecond))
	b := balancer{policy: adaptivePolicy, paths: []*managedTunnel{&stream, &native}}
	if b.pick() != &stream {
		t.Fatal("connected carrier should be preferred")
	}
	close(done)
	if b.pick() != &native {
		t.Fatal("closed carrier remained eligible before the next probe")
	}
	failover := balancer{paths: b.paths}
	if failover.pick() != &stream {
		t.Fatal("Adaptive carrier state changed Failover's probe-only behavior")
	}
	stream.carrier.Store(&carrierHealth{done: make(chan struct{})})
	if b.pick() != &native {
		t.Fatal("replacement carrier inherited the previous connection's score")
	}
}
