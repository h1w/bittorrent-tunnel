package direct

import (
	"context"
	"crypto/hmac"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"bittorrent-tunnel/btawg/internal/carrier"

	"github.com/anacrolix/go-utp/purego"
)

const streamAttemptTimeout = 900 * time.Millisecond

type connectResult struct {
	transport carrier.Transport
	err       error
}

// Connect punches from both roles but only the nominated initiator opens a
// stream. It tries verified endpoints in turn and authenticates the stream on
// both ends before starting the extended carrier. The caller owns the result.
func (s *Socket) Connect(ctx context.Context, offer Offer) (carrier.Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !time.Now().Before(offer.Expires) {
		return nil, context.DeadlineExceeded
	}
	if offer.Secret == ([32]byte{}) {
		return nil, errors.New("empty direct offer secret")
	}
	ctx, cancel := context.WithDeadline(ctx, offer.Expires)
	stop := context.AfterFunc(s.ctx, cancel)
	defer cancel()
	defer stop()
	key := mac(offer.Secret, "btawg/direct/pair/1", nil)
	id := mac(key, "btawg/direct/selector/1", nil)
	a := &attempt{
		ctx:       ctx,
		key:       key,
		id:        token(id[:16]),
		initiator: offer.Initiator,
		paths:     make(map[netip.AddrPort]*path),
		wake:      make(chan struct{}, 1),
		winner:    make(chan connectResult),
	}
	for _, candidate := range offer.Candidates {
		addr := normalize(candidate.Addr)
		if len(a.order) >= maxCandidates {
			break
		}
		if f := s.familyFor(addr.Addr()); f != nil && usable(addr) && a.paths[addr] == nil {
			s.addPath(a, addr, f).listed = true
		}
	}

	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return nil, net.ErrClosed
	case s.attempts[a.id] != nil:
		s.mu.Unlock()
		return nil, errors.New("direct offer already in flight")
	}
	s.workers.Add(1)
	s.attempts[a.id] = a
	s.mu.Unlock()
	punchDone := make(chan struct{})
	go s.punch(a, punchDone)
	defer func() {
		s.mu.Lock()
		delete(s.attempts, a.id)
		s.mu.Unlock()
		cancel()
		<-punchDone
		s.workers.Done()
	}()

	var tr carrier.Transport
	var err error
	if a.initiator {
		tr, err = s.dial(a)
	} else {
		select {
		case result := <-a.winner:
			tr, err = result.transport, result.err
		case <-ctx.Done():
		}
	}
	if s.ctx.Err() != nil {
		err = net.ErrClosed
	} else if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil && tr != nil {
		tr.Wait()
		tr = nil
	}
	return tr, err
}

func (s *Socket) dial(a *attempt) (carrier.Transport, error) {
	var next int
	retry := time.NewTicker(punchInterval)
	defer retry.Stop()
	for a.ctx.Err() == nil {
		var p *path
		s.mu.Lock()
		for range len(a.order) {
			candidate := a.order[next%len(a.order)]
			next = (next + 1) % len(a.order)
			if candidate.dialable {
				p = candidate
				break
			}
		}
		s.mu.Unlock()
		if p != nil {
			tr, committed, err := s.dialPath(a, p)
			if committed {
				return tr, err
			}
		}
		select {
		case <-a.ctx.Done():
		case <-a.wake:
		case <-retry.C:
		}
	}
	return nil, a.ctx.Err()
}

func (s *Socket) dialPath(a *attempt, p *path) (carrier.Transport, bool, error) {
	dialCtx, cancel := context.WithTimeout(a.ctx, streamAttemptTimeout)
	defer cancel()
	c, err := p.family.DialAddrContext(dialCtx, p.remote)
	if err != nil {
		return nil, false, err
	}
	stop := context.AfterFunc(a.ctx, func() { _ = c.Close() })
	var tr carrier.Transport
	defer func() {
		stop()
		if tr == nil {
			_ = c.Close()
		}
	}()
	deadline, _ := dialCtx.Deadline()
	_ = c.SetDeadline(deadline)
	var hello [32]byte
	copy(hello[:16], a.id[:])
	random(hello[16:])
	if err := writeMessage(c, hello[:]); err != nil {
		return nil, false, err
	}
	var reply [48]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return nil, false, err
	}
	var transcript [32]byte
	copy(transcript[:16], hello[16:])
	copy(transcript[16:], reply[:16])
	want := mac(a.key, "btawg/direct/stream/responder/1", transcript[:])
	if !hmac.Equal(reply[16:], want[:]) {
		return nil, false, errors.New("invalid direct responder proof")
	}
	if err := a.ctx.Err(); err != nil {
		return nil, false, err
	}
	// Sending the authenticated initiator proof nominates this stream. Do
	// not try a different stream after it could have committed at the peer.
	s.mu.Lock()
	a.committed = true
	s.mu.Unlock()
	deadline, _ = a.ctx.Deadline()
	_ = c.SetDeadline(deadline)
	proof := mac(a.key, "btawg/direct/stream/initiator/1", transcript[:])
	if err := writeMessage(c, proof[:]); err != nil {
		return nil, true, err
	}
	streamKey := mac(a.key, "btawg/direct/stream/carrier/1", transcript[:])
	tr, err = s.extended(a.ctx, c, streamKey)
	if err == nil && !stop() {
		tr.Wait()
		tr, err = nil, a.ctx.Err()
	}
	return tr, true, err
}

func (s *Socket) accept(f *purego.Socket) {
	for {
		c, err := f.Accept()
		if err != nil {
			return
		}
		select {
		case s.accepting <- struct{}{}:
			s.workers.Go(func() {
				defer func() { <-s.accepting }()
				s.inbound(c)
			})
		default:
			_ = c.Close()
		}
	}
}

func (s *Socket) inbound(c net.Conn) {
	var tr carrier.Transport
	defer func() {
		if tr == nil {
			_ = c.Close()
		}
	}()
	deadline := time.Now().Add(streamAttemptTimeout)
	_ = c.SetDeadline(deadline)
	var hello [32]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil {
		return
	}
	id := token(hello[:16])
	source := remoteAddr(c.RemoteAddr())
	s.mu.Lock()
	a := s.attempts[id]
	allowed := !s.closed && a != nil && !a.initiator && !a.committed && a.ctx.Err() == nil
	if allowed {
		p := a.paths[source]
		allowed = p != nil && p.proved
	}
	s.mu.Unlock()
	if !allowed {
		return
	}
	stop := context.AfterFunc(a.ctx, func() { _ = c.Close() })
	defer stop()
	lease, _ := a.ctx.Deadline()
	if lease.Before(deadline) {
		_ = c.SetDeadline(lease)
	}
	var transcript [32]byte
	copy(transcript[:16], hello[16:])
	random(transcript[16:])
	var reply [48]byte
	copy(reply[:16], transcript[16:])
	proof := mac(a.key, "btawg/direct/stream/responder/1", transcript[:])
	copy(reply[16:], proof[:])
	if err := writeMessage(c, reply[:]); err != nil {
		return
	}
	var got [32]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		return
	}
	want := mac(a.key, "btawg/direct/stream/initiator/1", transcript[:])
	if !hmac.Equal(got[:], want[:]) {
		return
	}
	s.mu.Lock()
	if s.closed || s.attempts[id] != a || a.committed || a.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	a.committed = true
	s.mu.Unlock()
	_ = c.SetDeadline(lease)
	streamKey := mac(a.key, "btawg/direct/stream/carrier/1", transcript[:])
	var err error
	tr, err = s.extended(a.ctx, c, streamKey)
	if err != nil {
		deliver(a, connectResult{err: err})
		return
	}
	// Disconnect the negotiation cancellation before handing ownership to
	// Connect, which always cancels its private context before returning.
	if !stop() {
		tr.Wait()
		return
	}
	deliver(a, connectResult{transport: tr})
}

func deliver(a *attempt, result connectResult) {
	select {
	case a.winner <- result:
	case <-a.ctx.Done():
		if result.transport != nil {
			result.transport.Wait()
		}
	}
}

func writeMessage(c net.Conn, b []byte) error {
	for len(b) != 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
