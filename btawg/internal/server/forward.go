package server

import (
	"golang.org/x/net/ipv4"
	"net/netip"
)

// ipv4Dst extracts the destination of an IPv4 packet.
func ipv4Dst(p []byte) (netip.Addr, bool) {
	if len(p) < ipv4.HeaderLen {
		return netip.Addr{}, false
	}
	if p[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	copy(b[:], p[16:20])
	return netip.AddrFrom4(b), true
}

// ipv4Src extracts the source of an IPv4 packet.
func ipv4Src(p []byte) (netip.Addr, bool) {
	if len(p) < ipv4.HeaderLen {
		return netip.Addr{}, false
	}
	if p[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	copy(b[:], p[12:16])
	return netip.AddrFrom4(b), true
}

type shortBufferError struct{}

func (shortBufferError) Error() string { return "short buffer" }

var errShortBuffer error = shortBufferError{}
