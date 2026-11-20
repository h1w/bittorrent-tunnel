package server

import (
	"net"
	"net/netip"
)

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
