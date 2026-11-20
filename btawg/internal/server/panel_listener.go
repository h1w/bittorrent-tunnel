package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"bittorrent-tunnel/btawg/internal/tunsetup"
)

// ListenPanel binds the management panel on 127.0.0.1:port and on the
// default-group gateway address (the VPN IP, e.g. 10.77.0.1:port). In real-TUN
// mode the gateway listener is additionally scoped to the tunnel interface;
// in userspace (-no-tun) mode it uses the overlay netstack. It never binds the
// WAN address or 0.0.0.0.
func (s *Server) ListenPanel(ctx context.Context, port int) ([]net.Listener, error) {
	loopback, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("panel loopback: %w", err)
	}
	listeners := []net.Listener{loopback}

	if len(s.gateways) == 0 {
		return listeners, nil
	}
	gateway := s.gateways[0].Addr()
	addrPort := netip.AddrPortFrom(gateway, uint16(port))

	if s.ns != nil {
		ln, err := s.ns.ListenTCPAddrPort(addrPort)
		if err != nil {
			loopback.Close()
			return nil, fmt.Errorf("panel netstack %s: %w", addrPort, err)
		}
		listeners = append(listeners, ln)
	} else if s.tunName != "" {
		lc := net.ListenConfig{Control: tunsetup.BindDevice(s.tunName)}
		ln, err := lc.Listen(ctx, "tcp4", addrPort.String())
		if err != nil {
			loopback.Close()
			return nil, fmt.Errorf("panel tun %s: %w", addrPort, err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}
