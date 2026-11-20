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
	groups   map[string]store.GroupRecord
	gateways map[netip.Addr]string
	prefixes []netip.Prefix
	localIPs map[netip.Addr]struct{}
}

// newPolicySnapshot creates an empty policy snapshot.
func newPolicySnapshot() *policySnapshot {
	return &policySnapshot{
		byIP: make(map[netip.Addr]store.ClientRecord),
	}
}

// remove deletes a client record from the snapshot by overlay IP.
func (p *policySnapshot) remove(ip netip.Addr) {
	p.mu.Lock()
	delete(p.byIP, ip)
	p.mu.Unlock()
}

func (p *policySnapshot) disableClients() {
	p.mu.Lock()
	clear(p.byIP)
	p.mu.Unlock()
}

// reload rebuilds the snapshot from the current store contents.
func (p *policySnapshot) reload(st *store.Store, serverIP netip.Addr) error {
	clients, err := st.ListClients()
	if err != nil {
		return err
	}
	groups, err := st.ListGroups()
	if err != nil {
		return err
	}
	localIPs, err := localAddresses()
	if err != nil {
		return err
	}
	groupByID := make(map[string]store.GroupRecord, len(groups))
	gateways := make(map[netip.Addr]string, len(groups))
	prefixes := make([]netip.Prefix, 0, len(groups))
	for _, g := range groups {
		groupByID[g.ID] = g
		gateways[netip.MustParseAddr(g.ServerIP)] = g.ID
		prefixes = append(prefixes, netip.MustParsePrefix(g.Subnet))
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
	p.groups, p.gateways, p.prefixes = groupByID, gateways, prefixes
	p.localIPs = localIPs
	p.mu.Unlock()
	return nil
}

func (p *policySnapshot) isGateway(ip netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.gateway(ip)
}

func (p *policySnapshot) gateway(ip netip.Addr) bool {
	_, ok := p.gateways[ip]
	return ok || ip == p.serverIP
}

func (p *policySnapshot) isClient(ip netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.byIP[ip]
	return ok
}

func (p *policySnapshot) Contains(ip netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.overlay(ip)
}

func (p *policySnapshot) overlay(ip netip.Addr) bool {
	for _, prefix := range p.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// packetAllowed is used only with a source authenticated by an engine's /32.
func (p *policySnapshot) packetAllowed(src, dst netip.Addr, directInternet bool) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	a, ok := p.byIP[src]
	if !ok || !dst.Is4() || dst.IsMulticast() || dst.IsUnspecified() || dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	if p.gateway(dst) {
		return true
	}
	if b, ok := p.byIP[dst]; ok {
		return p.peerSees(a, b) && p.peerSees(b, a)
	}
	_, local := p.localIPs[dst]
	return directInternet && !local && publicDestination(dst) && !p.overlay(dst) && p.internet(a)
}

func (p *policySnapshot) clientCanReach(src, dst netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	a, srcOK := p.byIP[src]
	b, dstOK := p.byIP[dst]
	if p.gateway(src) {
		return dstOK || p.gateway(dst)
	}
	if p.gateway(dst) {
		return srcOK
	}
	return srcOK && dstOK && p.peerSees(a, b) && p.peerSees(b, a)
}

func (p *policySnapshot) internetFor(src netip.Addr) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.gateway(src) {
		return true
	}
	rec, ok := p.byIP[src]
	return ok && p.internet(rec)
}

func (p *policySnapshot) internet(rec store.ClientRecord) bool {
	if rec.Internet != nil {
		return *rec.Internet
	}
	if g, ok := p.groups[rec.GroupID]; ok {
		return !g.NoInternet
	}
	return rec.GroupID == "" && !rec.NoInternet
}

func (p *policySnapshot) peerSees(a, b store.ClientRecord) bool {
	if a.VisiblePeers != nil {
		for _, id := range a.VisiblePeers {
			if id == "*" || id == b.ID {
				return true
			}
		}
		return false
	}
	g, ok := p.groups[a.GroupID]
	if !ok {
		return false
	}
	if g.VisibleGroups == nil {
		return a.GroupID == b.GroupID
	}
	for _, id := range g.VisibleGroups {
		if id == "*" || id == b.GroupID {
			return true
		}
	}
	return false
}
