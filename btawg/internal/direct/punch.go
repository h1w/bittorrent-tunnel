package direct

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"net/netip"
	"time"

	"github.com/anacrolix/go-utp/purego"
)

const (
	punchMagic     = "\x00BTP2P1:"
	punchSize      = 8 + 1 + 3*len(token{}) + sha256.Size
	punchInterval  = 150 * time.Millisecond
	maxCandidates  = 32
	maxPaths       = 2 * maxCandidates
	punchTagDomain = "btawg/direct/punch/1"
)

type token [16]byte

func random(p []byte) { _, _ = rand.Read(p) }

func mac(key [32]byte, domain string, message []byte) (sum [32]byte) {
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(message)
	h.Sum(sum[:0])
	return
}

type path struct {
	family   *purego.Socket
	remote   *net.UDPAddr
	local    token
	listed   bool
	peer     token
	proved   bool
	dialable bool
}

type attempt struct {
	ctx           context.Context
	key           [32]byte
	id            token
	initiator     bool
	framing       string
	tcp           bool
	tcpCandidates []netip.AddrPort
	tcpLocal      []netip.Addr
	conn          net.Conn
	dialer        bool

	// Guarded by the owning Socket's mutex.
	paths     map[netip.AddrPort]*path
	order     []*path
	committed bool

	wake   chan struct{}
	winner chan connectResult
}

func (s *Socket) addPath(a *attempt, address netip.AddrPort, f *purego.Socket) *path {
	// Once published, caller holds s.mu. Outbound destinations get their own
	// challenge too, so an echo heard on a different source cannot authorize it.
	p := &path{family: f, remote: net.UDPAddrFromAddrPort(address)}
	random(p.local[:])
	a.paths[address] = p
	a.order = append(a.order, p)
	return p
}

func (a *attempt) sendPunch(p *path, peer token, proved bool) {
	var packet [punchSize]byte
	copy(packet[:8], punchMagic)
	if a.initiator {
		packet[8] = 1
	}
	if proved {
		packet[8] |= 2
	}
	copy(packet[9:25], a.id[:])
	copy(packet[25:41], p.local[:])
	copy(packet[41:57], peer[:])
	tag := mac(a.key, punchTagDomain, packet[8:57])
	copy(packet[57:], tag[:])
	_, _ = p.family.WriteTo(packet[:], p.remote)
}

func (s *Socket) punch(a *attempt, done chan<- struct{}) {
	defer close(done)
	tick := time.NewTicker(punchInterval)
	defer tick.Stop()
	for a.ctx.Err() == nil {
		s.mu.Lock()
		paths := a.order // elements already published are never replaced
		s.mu.Unlock()
		for _, p := range paths {
			if a.ctx.Err() != nil {
				return
			}
			s.mu.Lock()
			peer, proved := p.peer, p.proved
			s.mu.Unlock()
			if p.listed || proved {
				a.sendPunch(p, peer, proved)
			}
		}
		select {
		case <-tick.C:
		case <-a.ctx.Done():
			return
		}
	}
}

func (s *Socket) readPackets(f *purego.Socket) {
	var b [punchSize + 1]byte
	for {
		n, addr, err := f.ReadFrom(b[:])
		if err != nil {
			return
		}
		source := remoteAddr(addr)
		if !usable(source) {
			continue
		}
		switch n {
		case punchSize:
			s.punched(f, b[:n], source)
		case observeSize:
			s.observationReply(b[:n], source)
		}
	}
}

func (s *Socket) punched(f *purego.Socket, b []byte, source netip.AddrPort) {
	if string(b[:8]) != punchMagic || b[8] > 3 {
		return
	}
	id, sender, echo := token(b[9:25]), token(b[25:41]), token(b[41:57])
	s.mu.Lock()
	a := s.attempts[id]
	s.mu.Unlock()
	if a == nil || a.tcp || a.initiator == (b[8]&1 != 0) || a.ctx.Err() != nil || sender == (token{}) {
		return
	}
	want := mac(a.key, punchTagDomain, b[8:57])
	if !hmac.Equal(b[57:], want[:]) {
		return
	}

	s.mu.Lock()
	if s.closed || s.attempts[id] != a || a.committed || a.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	p := a.paths[source]
	if p == nil {
		if len(a.order) >= maxPaths {
			s.mu.Unlock()
			return
		}
		p = s.addPath(a, source, f)
	}
	proved := echo == p.local
	firstProof := proved && (!p.proved || p.peer != sender)
	// Replaying an old initial message does not invalidate existing proof.
	// Require the responder to acknowledge this endpoint before dialing,
	// or its SYN filter may drop the first packet before punch processing.
	wasDialable := p.dialable
	shouldReply := p.peer != sender || firstProof
	if proved || !p.proved {
		p.peer = sender
		p.proved = proved
		p.dialable = proved && (b[8]&2 != 0 || wasDialable && !firstProof)
	}
	acknowledge := p.proved && p.peer == sender
	becameDialable := p.dialable && (!wasDialable || firstProof)
	s.mu.Unlock()
	if shouldReply {
		a.sendPunch(p, sender, acknowledge)
	}
	if becameDialable && a.initiator {
		select {
		case a.wake <- struct{}{}:
		default:
		}
	}
}

// µTP calls this under its own lock. No µTP calls may be made under s.mu.
func (s *Socket) rejectSYN(from net.Addr) bool {
	source := remoteAddr(from)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return true
	}
	for _, a := range s.attempts {
		if !a.tcp && !a.initiator && !a.committed && a.ctx.Err() == nil {
			if p := a.paths[source]; p != nil && p.proved {
				return false
			}
		}
	}
	return true
}
