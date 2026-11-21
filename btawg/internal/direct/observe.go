package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	observeRequest  = "\x00BTOBS1?"
	observeResponse = "\x00BTOBS1!"
	observeSize     = 8 + len(token{}) + 19 // IPv6 family, address, port; also used for IPv4.
)

var emptyEndpoint [19]byte

type observation struct {
	observer netip.AddrPort
	result   chan netip.AddrPort
}

// Observe asks an observer for the public endpoint of this socket's address
// family. It consumes only the reply from that observer to its fresh nonce.
func (s *Socket) Observe(ctx context.Context, observer netip.AddrPort) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}
	observer = normalize(observer)
	f := s.familyFor(observer.Addr())
	if f == nil || !usable(observer) {
		return netip.AddrPort{}, fmt.Errorf("unsupported direct observer endpoint %v", observer)
	}
	var nonce token
	random(nonce[:])
	ob := observation{observer, make(chan netip.AddrPort, 1)}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return netip.AddrPort{}, net.ErrClosed
	}
	s.observers[nonce] = ob
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.observers, nonce)
		s.mu.Unlock()
	}()

	var query [observeSize]byte
	copy(query[:8], observeRequest)
	copy(query[8:], nonce[:])
	destination := net.UDPAddrFromAddrPort(observer)
	retry := time.NewTicker(punchInterval)
	defer retry.Stop()
	for {
		if _, err := f.WriteTo(query[:], destination); err != nil {
			if s.ctx.Err() != nil {
				return netip.AddrPort{}, net.ErrClosed
			}
			return netip.AddrPort{}, err
		}
		select {
		case result := <-ob.result:
			if err := ctx.Err(); err != nil {
				return netip.AddrPort{}, err
			}
			if s.ctx.Err() != nil {
				return netip.AddrPort{}, net.ErrClosed
			}
			return result, nil
		case <-retry.C:
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case <-s.ctx.Done():
			return netip.AddrPort{}, net.ErrClosed
		}
	}
}

// ServeObserver echoes a nonce and the datagram's actual source endpoint to
// that same source. It never sends a larger response than the request. The
// caller retains pc and must not concurrently use its raw reads or deadlines.
// For a multiplexed µTP socket, its streams and Accept may continue in parallel.
func ServeObserver(ctx context.Context, pc net.PacketConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = pc.SetDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
			_ = pc.SetDeadline(time.Time{})
		}
	}()
	var packet [observeSize + 1]byte
	for ctx.Err() == nil {
		n, source, err := pc.ReadFrom(packet[:])
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n != observeSize || string(packet[:8]) != observeRequest || [19]byte(packet[24:43]) != emptyEndpoint {
			continue
		}
		addr := remoteAddr(source)
		if !usable(addr) {
			continue
		}
		copy(packet[:8], observeResponse)
		putEndpoint(packet[24:43], addr)
		// A failed reply is specific to that source and does not stop service.
		_, _ = pc.WriteTo(packet[:n], source)
	}
	return ctx.Err()
}

func (s *Socket) observationReply(b []byte, source netip.AddrPort) {
	if len(b) != observeSize || string(b[:8]) != observeResponse {
		return
	}
	s.mu.Lock()
	ob, ok := s.observers[token(b[8:24])]
	s.mu.Unlock()
	if !ok || ob.observer != source {
		return
	}
	addr := parseEndpoint(b[24:43])
	if !usable(addr) || addr.Addr().Is4() != source.Addr().Is4() {
		return
	}
	select {
	case ob.result <- addr:
	default:
	}
}

func putEndpoint(b []byte, addr netip.AddrPort) {
	ip := addr.Addr()
	if ip.Is4() {
		b[0] = 4
		v4 := ip.As4()
		copy(b[1:5], v4[:])
	} else {
		b[0] = 6
		v6 := ip.As16()
		copy(b[1:17], v6[:])
	}
	b[17], b[18] = byte(addr.Port()>>8), byte(addr.Port())
}

func parseEndpoint(b []byte) netip.AddrPort {
	var ip netip.Addr
	switch b[0] {
	case 4:
		ip = netip.AddrFrom4([4]byte(b[1:5]))
	case 6:
		ip = netip.AddrFrom16([16]byte(b[1:17]))
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(b[17])<<8|uint16(b[18]))
}
