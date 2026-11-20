package server

import (
	"net"
	"net/netip"
)

var nonInternet = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicDestination(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonInternet {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func localAddresses() (map[netip.Addr]struct{}, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]struct{}, len(list))
	for _, a := range list {
		p, err := netip.ParsePrefix(a.String())
		if err == nil {
			out[p.Addr().Unmap()] = struct{}{}
		}
	}
	return out, nil
}

type egressDenied struct{ policy *policySnapshot }

func (b egressDenied) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !publicDestination(ip) {
		return true
	}
	b.policy.mu.RLock()
	defer b.policy.mu.RUnlock()
	_, local := b.policy.localIPs[ip]
	return local || b.policy.overlay(ip)
}
