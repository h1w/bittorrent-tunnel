package client

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	peerFlowLimit     = 16384
	peerFlowTTL       = 5 * time.Minute
	peerFragmentLimit = 4096
)

type peerTuple struct {
	src, dst      [4]byte
	proto         byte
	icmpReply     bool
	first, second uint16
}

func (k peerTuple) reverse() peerTuple {
	k.src, k.dst = k.dst, k.src
	if k.proto == 1 {
		k.icmpReply = !k.icmpReply
	} else {
		k.first, k.second = k.second, k.first
	}
	return k
}

func peerTupleFrom(p []byte, h int) (peerTuple, bool) {
	k := peerTuple{src: [4]byte(p[12:16]), dst: [4]byte(p[16:20]), proto: p[9]}
	switch k.proto {
	case 6, 17:
		if len(p) < h+4 {
			return k, false
		}
		k.first, k.second = binary.BigEndian.Uint16(p[h:]), binary.BigEndian.Uint16(p[h+2:])
	case 1:
		if len(p) < h+8 || (p[h] != 0 && p[h] != 8) || p[h+1] != 0 {
			return k, false
		}
		k.first = binary.BigEndian.Uint16(p[h+4:])
		k.second = binary.BigEndian.Uint16(p[h+6:])
		k.icmpReply = p[h] == 0
	}
	return k, true
}

func newPeerFlow(p []byte, h int, proto byte) bool {
	return proto != 6 || len(p) >= h+14 && p[h+13]&0x12 == 0x02
}

type peerFlow struct {
	path     *tunPath
	until    time.Time
	awaiting bool
}

type peerPathGroup struct {
	constSize [10]*tunPath
	policy    balancer
}

func (s *sharedTUN) shouldRoutePeerLocked(dst netip.Addr) bool {
	if s.directWanted == nil || dst == s.directOwn || s.directGateways[dst] {
		return false
	}
	for _, prefix := range s.directRanges {
		if prefix.Contains(dst) {
			return true
		}
	}
	for _, prefix := range s.peerNetwork {
		if prefix.Contains(dst) {
			return true
		}
	}
	return false
}

func (s *sharedTUN) sweepPeerLocked(now time.Time) {
	if now.Before(s.peerSweep) {
		return
	}
	s.peerSweep = now.Add(time.Second)
	for k, v := range s.peerFlows {
		if !now.Before(v.until) {
			delete(s.peerFlows, k)
		}
	}
	for k, v := range s.peerFragments {
		if !now.Before(v.before) {
			delete(s.peerFragments, k)
		}
	}
}

func (s *sharedTUN) choosePeerPacket(p []byte, h int, dst netip.Addr) (*tunPath, bool) {
	if !s.peerEnabled.Load() {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.shouldRoutePeerLocked(dst) {
		return nil, false
	}
	now := time.Now()
	s.sweepPeerLocked(now)
	key, ok := peerTupleFrom(p, h)
	if !ok {
		return nil, true
	}
	if flow, ok := s.peerFlows[key]; ok && now.Before(flow.until) {
		if s.peerPathAllowedLocked(flow.path) && !(flow.awaiting && s.readyPeerLocked(dst)) {
			if flow.path.directLife != nil && flow.path.peerOutbound {
				s.requestPeerLocked(dst, now)
			}
			flow.until = now.Add(peerFlowTTL)
			s.peerFlows[key] = flow
			return flow.path, true
		}
		if key.proto == 6 && !newPeerFlow(p, h, key.proto) {
			return nil, true
		}
		delete(s.peerFlows, key)
	}
	if key.proto == 6 && !newPeerFlow(p, h, key.proto) {
		return nil, true
	}
	s.requestPeerLocked(dst, now)
	path := s.pickPeerLocked(dst)
	if path != nil && len(s.peerFlows) < peerFlowLimit {
		s.peerFlows[key] = peerFlow{path: path, until: now.Add(peerFlowTTL)}
		return path, true
	}
	if !s.peerRelay || len(s.peerFlows) >= peerFlowLimit {
		return nil, true
	}
	path = s.primary.Load()
	if path != nil {
		s.peerFlows[key] = peerFlow{path: path, until: now.Add(peerFlowTTL), awaiting: key.proto == 1}
	}
	return path, true
}

func (s *sharedTUN) requestPeerLocked(dst netip.Addr, now time.Time) {
	if last := s.peerRequests[dst]; !last.IsZero() && now.Sub(last) < time.Second {
		return
	}
	if len(s.peerRequests) >= 256 && s.peerRequests[dst].IsZero() {
		clear(s.peerRequests)
	}
	select {
	case s.directWanted <- dst:
		s.peerRequests[dst] = now
	default:
	}
}

// acceptPeerPacket pins the reverse direction to the authenticated link. An
// outgoing link may reply to existing local flows but cannot initiate a
// new inbound flow, even though its encryption keys are bidirectional.
func (s *sharedTUN) acceptPeerPacket(path *tunPath, p []byte, h int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.peerPathAllowedLocked(path) {
		return false
	}
	now := time.Now()
	s.sweepPeerLocked(now)
	flags := binary.BigEndian.Uint16(p[6:8])
	id := fragmentID{src: [4]byte(p[12:16]), dst: [4]byte(p[16:20]), id: binary.BigEndian.Uint16(p[4:6]), proto: p[9]}
	if flags&0x1fff != 0 {
		f, ok := s.peerFragments[id]
		if ok && flags&0x2000 == 0 {
			delete(s.peerFragments, id)
		}
		return ok && f.path == path && now.Before(f.before)
	}
	k, ok := peerTupleFrom(p, h)
	if !ok {
		return false
	}
	k = k.reverse()
	if path.peerOutbound && k.proto == 6 {
		key := localPort{port: k.first, proto: k.proto, remote: netip.AddrPortFrom(netip.AddrFrom4(k.dst), k.second)}
		if owner := s.ports[key]; owner != nil && owner.path == path {
			if flags&0x2000 != 0 && len(s.peerFragments) < peerFragmentLimit {
				s.peerFragments[id] = fragmentPath{path, now.Add(30 * time.Second)}
			}
			return true
		}
	}
	flow, exists := s.peerFlows[k]
	if exists && now.Before(flow.until) && flow.path == path {
		flow.until = now.Add(peerFlowTTL)
		s.peerFlows[k] = flow
	} else {
		if path.peerOutbound || !newPeerFlow(p, h, k.proto) || (exists && now.Before(flow.until) && flow.path.validDirect()) || len(s.peerFlows) >= peerFlowLimit {
			return false
		}
		s.peerFlows[k] = peerFlow{path: path, until: now.Add(peerFlowTTL)}
	}
	if flags&0x2000 != 0 && len(s.peerFragments) < peerFragmentLimit {
		s.peerFragments[id] = fragmentPath{path, now.Add(30 * time.Second)}
	}
	return true
}

func (s *sharedTUN) acceptHubPacket(path *tunPath, p []byte) bool {
	h := int(p[0]&15) * 4
	if p[0]>>4 != 4 || h < 20 || h > len(p) {
		return false
	}
	src := netip.AddrFrom4([4]byte(p[12:16]))
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.shouldRoutePeerLocked(src) {
		return true
	}
	if !s.peerRelay {
		return false
	}
	now := time.Now()
	s.sweepPeerLocked(now)
	flags := binary.BigEndian.Uint16(p[6:8])
	id := fragmentID{src: [4]byte(p[12:16]), dst: [4]byte(p[16:20]), id: binary.BigEndian.Uint16(p[4:6]), proto: p[9]}
	if flags&0x1fff != 0 {
		f, ok := s.peerFragments[id]
		if ok && flags&0x2000 == 0 {
			delete(s.peerFragments, id)
		}
		return ok && f.path == path && now.Before(f.before)
	}
	k, ok := peerTupleFrom(p, h)
	if !ok {
		return false
	}
	k = k.reverse()
	old, exists := s.peerFlows[k]
	if exists && now.Before(old.until) && old.path != path && s.peerPathAllowedLocked(old.path) {
		return false
	}
	if !exists && len(s.peerFlows) >= peerFlowLimit {
		return false
	}
	s.peerFlows[k] = peerFlow{path: path, until: now.Add(peerFlowTTL)}
	if flags&0x2000 != 0 && len(s.peerFragments) < peerFragmentLimit {
		s.peerFragments[id] = fragmentPath{path, now.Add(30 * time.Second)}
	}
	return true
}
