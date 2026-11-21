package client

import (
	"net/netip"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
)

func (s *sharedTUN) enableDirect(cfg config.ClientConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.direct = make(map[netip.Addr]*tunPath)
	s.directGateway = netip.MustParseAddr(cfg.ServerIP)
	s.directOwn = netip.MustParseAddr(cfg.ClientIP)
	s.directWanted = make(chan netip.Addr, 64)
	for _, raw := range cfg.Routes {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Bits() > 0 {
			s.directRanges = append(s.directRanges, p)
		}
	}
	if p, err := netip.ParsePrefix(cfg.Subnet); err == nil {
		s.directRanges = append(s.directRanges, p)
	}
}

func (s *sharedTUN) directPath(ip netip.Addr) *tunPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.direct[ip]
	if p == nil || !p.validDirect() {
		return nil
	}
	return p
}

func (s *sharedTUN) wantDirect(ip netip.Addr) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.directWanted == nil {
		return
	}
	select {
	case s.directWanted <- ip:
	default:
	}
}

func (s *sharedTUN) setDirect(ip netip.Addr, p *tunPath) {
	s.mu.Lock()
	s.direct[ip] = p
	s.mu.Unlock()
}

func (s *sharedTUN) removeDirect(ip netip.Addr, p *tunPath) {
	s.mu.Lock()
	if s.direct[ip] == p {
		delete(s.direct, ip)
	}
	s.mu.Unlock()
}

func (p *tunPath) validDirect() bool {
	return p.directLife == nil || (p.directLife.Err() == nil && time.Now().UnixNano() < p.directUntil.Load())
}
