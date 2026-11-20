package server

import (
	"sync/atomic"

	"bittorrent-tunnel/btawg/internal/store"
)

type trafficCounter struct {
	up, down atomic.Uint64
	lastSeen atomic.Int64
}

func (c *trafficCounter) observe(at int64) {
	for prev := c.lastSeen.Load(); at > prev; prev = c.lastSeen.Load() {
		if c.lastSeen.CompareAndSwap(prev, at) {
			return
		}
	}
}

func (c *trafficCounter) snapshot() store.Traffic {
	return store.Traffic{Up: c.up.Load(), Down: c.down.Load(), LastSeen: c.lastSeen.Load()}
}

// Traffic returns a snapshot keyed by stable client ID, including revoked peers.
func (s *Server) Traffic() map[string]store.Traffic {
	s.policy.mu.RLock()
	defer s.policy.mu.RUnlock()
	out := make(map[string]store.Traffic, len(s.policy.traffic))
	for id, c := range s.policy.traffic {
		out[id] = c.snapshot()
	}
	return out
}

// flushTraffic is called by the sampler, then on shutdown after the sampler
// and both device engines have stopped. Failed commits leave records dirty.
func (s *Server) flushTraffic() error {
	changed := s.Traffic()
	for id, v := range changed {
		if v == s.savedTraffic[id] {
			delete(changed, id)
		}
	}
	if err := s.st.SaveTraffic(changed); err != nil {
		return err
	}
	for id, v := range changed {
		s.savedTraffic[id] = v
	}
	return nil
}
