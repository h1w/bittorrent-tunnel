package server

import (
	"net/netip"
	"sync"

	"bittorrent-tunnel/btawg/internal/store"
)

// policySnapshot is a hub-side, read-optimized view of the routing policy.
// It is keyed by client overlay IP and guarded by an RWMutex so per-packet
// lookups from the TUN path can run concurrently with policy reloads.
type policySnapshot struct {
	mu       sync.RWMutex
	serverIP netip.Addr
	byIP     map[netip.Addr]store.ClientRecord
}

// newPolicySnapshot creates an empty policy snapshot.
func newPolicySnapshot() *policySnapshot {
	return &policySnapshot{
		byIP: make(map[netip.Addr]store.ClientRecord),
	}
}

// reload rebuilds the snapshot from the current store contents.
func (p *policySnapshot) reload(st *store.Store, serverIP netip.Addr) error {
	clients, err := st.ListClients()
	if err != nil {
		return err
	}

	next := make(map[netip.Addr]store.ClientRecord, len(clients))
	for _, rec := range clients {
		if rec.Revoked {
			continue
		}
		addr, err := netip.ParseAddr(rec.IP)
		if err != nil {
			continue
		}
		next[addr] = rec
	}

	p.mu.Lock()
	p.serverIP = serverIP
	p.byIP = next
	p.mu.Unlock()
	return nil
}

// clientCanReach reports whether traffic between src and dst is allowed.
// The hub itself (serverIP) is always reachable, and reachability between
// clients is mutual: each client must list the other in VisiblePeers.
func (p *policySnapshot) clientCanReach(src, dst netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if src == p.serverIP || dst == p.serverIP {
		return true
	}

	srcRec, srcOK := p.byIP[src]
	dstRec, dstOK := p.byIP[dst]
	if !srcOK || !dstOK {
		return false
	}

	return peerSees(&srcRec, dstRec.ID) && peerSees(&dstRec, srcRec.ID)
}

// internetFor reports whether src is allowed to use the hub's internet egress.
func (p *policySnapshot) internetFor(src netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if src == p.serverIP {
		return true
	}

	rec, ok := p.byIP[src]
	if !ok {
		return false
	}
	return !rec.NoInternet
}

// peerSees reports whether rec's policy allows it to communicate with peerID.
func peerSees(rec *store.ClientRecord, peerID string) bool {
	for _, v := range rec.VisiblePeers {
		if v == "*" || v == peerID {
			return true
		}
	}
	return false
}
