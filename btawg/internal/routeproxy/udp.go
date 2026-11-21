package routeproxy

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	datagramTimeout = 5 * time.Second
	replyWindow     = 30 * time.Second
	maxPending      = 128 // outstanding remote IP/port pairs per association
	maxPeerCredits  = 32  // outstanding replies per IP/port pair
)

type udpStream struct {
	net.Conn
	allowReply func(netip.Addr) bool
}

func (u *udpStream) WritePacket(host string, port uint16, data []byte) error {
	if len(host) == 0 || len(host) > maxHost || port == 0 || len(data) > maxDatagram {
		return errInvalidFrame
	}
	if err := u.SetWriteDeadline(time.Now().Add(datagramTimeout)); err != nil {
		_ = u.Close()
		return err
	}
	if err := writeDatagram(u.Conn, host, port, data); err != nil {
		_ = u.Close()
		return err
	}
	return nil
}

func (u *udpStream) ReadPacket(b []byte) (int, netip.AddrPort, error) {
	n, src, err := readReply(u.Conn, b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if !u.allowReply(src.Addr()) {
		return 0, netip.AddrPort{}, errInvalidFrame
	}
	return n, src, nil
}

// pendingUDP counts sends, so even the second packet from an otherwise
// permitted IP/port requires an outstanding send. The lock serializes the
// actual send with admission of a reply, including immediate UDP responses.
type pendingUDP struct {
	mu    sync.Mutex
	peers map[netip.AddrPort]udpCredits
}

type udpCredits struct {
	n       int
	expires time.Time
}

func (p *pendingUDP) send(ctx context.Context, udp *net.UDPConn, dst netip.AddrPort, data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	now := time.Now()
	credit := p.peers[dst]
	if !credit.expires.After(now) {
		delete(p.peers, dst)
		credit = udpCredits{}
	}
	if credit.n == 0 && len(p.peers) >= maxPending {
		for key, value := range p.peers {
			if !value.expires.After(now) {
				delete(p.peers, key)
			}
		}
		if len(p.peers) >= maxPending {
			return
		}
	}
	if err := udp.SetWriteDeadline(now.Add(datagramTimeout)); err != nil {
		return
	}
	if _, err := udp.WriteToUDPAddrPort(data, dst); err == nil {
		if credit.n < maxPeerCredits {
			credit.n++
		}
		credit.expires = now.Add(replyWindow)
		p.peers[dst] = credit
	}
}

func (p *pendingUDP) take(src netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	credit, ok := p.peers[src]
	if !ok || !credit.expires.After(time.Now()) {
		if ok {
			delete(p.peers, src)
		}
		return false
	}
	if credit.n == 1 {
		delete(p.peers, src)
	} else {
		credit.n--
		p.peers[src] = credit
	}
	return true
}

func (p exitPolicy) pumpUDP(ctx context.Context, stream net.Conn, udp *net.UDPConn) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() {
		_ = udp.Close()
		_ = stream.Close()
	})
	defer stop()
	pending := pendingUDP{peers: make(map[netip.AddrPort]udpCredits)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		// The extra byte makes oversized/truncated WAN packets observable.
		buf := make([]byte, maxDatagram+1)
		for ctx.Err() == nil {
			n, src, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n > maxDatagram || !src.Addr().Is4() || src.Port() == 0 || !pending.take(src) {
				continue
			}
			if !p.destinationAllowed(src.Addr()) {
				continue
			}
			if err := stream.SetWriteDeadline(time.Now().Add(datagramTimeout)); err != nil {
				return
			}
			if err := writeReply(stream, src, buf[:n]); err != nil {
				return
			}
		}
	}()
	defer func() {
		cancel()
		<-done
	}()
	buf := make([]byte, maxHost+maxDatagram)
	for ctx.Err() == nil {
		dst, data, err := readDatagram(stream, buf)
		if err != nil {
			return
		}
		lookup, cancelLookup := context.WithTimeout(ctx, datagramTimeout)
		ips, err := p.resolve(lookup, dst.host)
		cancelLookup()
		if err != nil || p.check(ips) != nil {
			continue
		}
		ip := ips[0].Unmap()
		if p.destinationAllowed(ip) {
			pending.send(ctx, udp, netip.AddrPortFrom(ip, dst.port), data)
		}
	}
}
