package client

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"bittorrent-tunnel/btawg/internal/mesh"
	"bittorrent-tunnel/btawg/internal/socks"
	"bittorrent-tunnel/btawg/internal/tunneldns"
)

const (
	failoverPolicy   = "failover"
	roundRobinPolicy = "round-robin"
	adaptivePolicy   = "adaptive"
	probeInterval    = 5 * time.Second
	probeTimeout     = 3 * time.Second
	adaptiveMinGain  = 5 * time.Millisecond
)

var balancerPolicies = [...]string{failoverPolicy, roundRobinPolicy, adaptivePolicy}

// BalancerPorts lists the three managed SOCKS5 balancers in port order.
func BalancerPorts() [3]string { return balancerPolicies }

// carrierHealth belongs to one attached carrier, not to the tunnel mode.
// Done makes a closed carrier ineligible even before its teardown finishes.
type carrierHealth struct {
	done  <-chan struct{}
	score atomic.Int64
}

type adaptivePath struct {
	tunnel  *managedTunnel
	carrier *carrierHealth
}

func (t *managedTunnel) adaptiveScore() (adaptivePath, time.Duration) {
	if !t.carrierMode {
		return adaptivePath{tunnel: t}, time.Duration(t.score.Load())
	}
	c := t.carrier.Load()
	if c != nil {
		select {
		case <-c.done:
		default:
			return adaptivePath{tunnel: t, carrier: c}, time.Duration(c.score.Load())
		}
	}
	return adaptivePath{}, 0
}

type balancer struct {
	policy              string
	mu                  sync.Mutex
	paths               []*managedTunnel
	next                int
	current, challenger adaptivePath
}

func (b *balancer) replace(paths []*managedTunnel) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.policy == adaptivePolicy && !slices.Equal(b.paths, paths) {
		b.challenger = adaptivePath{}
		if !slices.Contains(paths, b.current.tunnel) {
			b.current = adaptivePath{}
		}
	}
	b.paths = paths
	if b.next >= len(paths) {
		b.next = 0
	}
}

func (b *balancer) pick() *managedTunnel {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.policy == adaptivePolicy {
		if b.current.tunnel != nil {
			if path, score := b.current.tunnel.adaptiveScore(); path == b.current && score > 0 {
				return path.tunnel
			}
		}
		b.current, _ = b.bestAdaptive()
		b.challenger = adaptivePath{}
		return b.current.tunnel
	}
	for i := range b.paths {
		idx := i
		if b.policy == roundRobinPolicy {
			idx = (b.next + i) % len(b.paths)
		}
		path := b.paths[idx]
		score := time.Duration(path.score.Load())
		if score <= 0 {
			continue
		}
		if b.policy == roundRobinPolicy {
			b.next = (idx + 1) % len(b.paths)
		}
		return path
	}
	return nil
}

func (b *balancer) bestAdaptive() (best adaptivePath, bestScore time.Duration) {
	for _, tunnel := range b.paths {
		if path, score := tunnel.adaptiveScore(); score > 0 && (best.tunnel == nil || score < bestScore) {
			best, bestScore = path, score
		}
	}
	return best, bestScore
}

// probed is called once per completed background check, never by a request.
func (b *balancer) probed(tunnel *managedTunnel, carrier *carrierHealth) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current.tunnel == nil || !slices.Contains(b.paths, tunnel) {
		return
	}
	current, currentScore := b.current.tunnel.adaptiveScore()
	if current != b.current || currentScore <= 0 {
		b.current, b.challenger = adaptivePath{}, adaptivePath{}
		return
	}
	best, score := b.bestAdaptive()
	gain := currentScore - score
	if best.tunnel == nil || gain < adaptiveMinGain || gain*100 < currentScore*15 {
		b.challenger = adaptivePath{}
		return
	}
	if b.challenger != best {
		b.challenger = adaptivePath{}
	}
	if best != (adaptivePath{tunnel: tunnel, carrier: carrier}) {
		return
	}
	if b.challenger == best {
		b.current, b.challenger = best, adaptivePath{}
	} else {
		b.challenger = best
	}
}

func (b *balancer) upstream() (*socks.Server, context.Context) {
	if path := b.pick(); path != nil {
		return path.proxy, path.life
	}
	return nil, nil
}

type probeHealth struct {
	latency, penalty time.Duration
	recovering       bool
	passed           bool
}

// A first success is usable immediately. After an outage, wait for two
// consecutive successes; recent failures decay rather than vanish on recovery.
func (h *probeHealth) observe(latency time.Duration) time.Duration {
	if latency <= 0 {
		h.penalty = (3*h.penalty + probeTimeout) / 4
		h.recovering, h.passed = true, false
		return 0
	}
	h.penalty = 3 * h.penalty / 4
	if h.latency == 0 {
		h.latency = latency
	} else {
		h.latency = (3*h.latency + latency) / 4
	}
	if h.recovering && !h.passed {
		h.passed = true
		return 0
	}
	h.recovering = false
	return max(time.Nanosecond, h.latency+h.penalty)
}

// watch is called with Managed.mu held. At most one probe per path runs,
// regardless of how many balancers use it.
func (t *managedTunnel) watch(enabled bool, adaptive *balancer) {
	if !enabled {
		if t.stopProbe != nil {
			t.stopProbe()
			<-t.probeDone
			t.stopProbe = nil
		}
		return
	}
	if t.stopProbe != nil {
		return
	}
	ctx, stop := context.WithCancel(t.life)
	done := make(chan struct{})
	t.stopProbe, t.probeDone = stop, done
	go func() {
		defer close(done)
		defer t.score.Store(0)
		defer func() {
			if c := t.carrier.Load(); c != nil {
				c.score.Store(0)
			}
		}()
		hub := netip.MustParseAddr(t.c.cfg.ServerIP)
		gateway := netip.AddrPortFrom(hub, mesh.ControlPort)
		legacy := netip.AddrPortFrom(hub, tunneldns.Port)
		tick := time.NewTicker(probeInterval)
		defer tick.Stop()
		var health probeHealth
		for ctx.Err() == nil {
			// Establish overlay TCP to the hub itself. Do not issue a DNS query
			// or confuse an unreachable public destination with a bad tunnel.
			carrier := t.carrier.Load()
			started := time.Now()
			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			conn, err := t.c.proxyTCP(probeCtx, gateway)
			if err != nil && probeCtx.Err() == nil {
				conn, err = t.c.proxyTCP(probeCtx, legacy)
			}
			cancel()
			var elapsed time.Duration
			if err == nil {
				elapsed = max(time.Nanosecond, time.Since(started))
				conn.Close()
			}
			score := int64(health.observe(elapsed))
			t.score.Store(score)
			if carrier != nil {
				// A reconnect during the dial must not stamp the replacement
				// carrier with a result from the previous one.
				carrier.score.Store(score)
			}
			adaptive.probed(t, carrier)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}
