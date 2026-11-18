package carrier

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Virtual-file geometry for the request/piece carrier: each endpoint
// advertises one half of a finite index space; the carrier fails loudly when
// the space is exhausted rather than silently wrapping.
const (
	requestWindow = 32
	totalPieces   = 65536
)

// Wire-format experiment, NOT a valid immutable-file torrent: AWG ciphertext
// replaces file blocks, so file hashes never validate.
type request struct{ Index, Offset, Length uint32 }

type requestPieceCarrier struct {
	c        net.Conn
	writeMu  sync.Mutex
	requests chan request
	received chan []byte
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	pending  map[uint32]bool
	next     uint32
	invalid  atomic.Int64
}

// NewRequestPiece wraps an established connection with BEP 3 request/piece
// framing (message ids: 1 unchoke, 2 interested, 5 bitfield, 6 request,
// 7 piece). ownOdd selects which half of the virtual file this endpoint
// advertises; the two ends of one connection must pass opposite values. The
// peer's handshake ID is returned for caller-side routing.
func NewRequestPiece(c net.Conn, infoHash, peerID [20]byte, ownOdd bool) (Transport, [20]byte, error) {
	theirs, err := Handshake(c, infoHash, peerID)
	if err != nil {
		return nil, theirs, err
	}
	x := &requestPieceCarrier{
		c:        c,
		requests: make(chan request, requestWindow),
		received: make(chan []byte, 256),
		done:     make(chan struct{}),
		pending:  make(map[uint32]bool),
	}
	x.start(ownOdd)
	return x, theirs, nil
}

func (x *requestPieceCarrier) start(ownOdd bool) {
	own := make([]byte, totalPieces/8)
	for i := range totalPieces {
		if (i%2 == 1) == ownOdd {
			own[i/8] |= 1 << uint(7-i%8)
		}
	}
	x.next = 0
	if !ownOdd {
		x.next = 1
	}
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		x.readLoop()
	}()
	if err := x.message(5, own); err != nil {
		x.Close()
		return
	}
	if err := x.message(2, nil); err != nil {
		x.Close()
		return
	}
	if err := x.message(1, nil); err != nil {
		x.Close()
		return
	}
}

func (x *requestPieceCarrier) message(id byte, p []byte) error {
	b := make([]byte, 5+len(p))
	binary.BigEndian.PutUint32(b, uint32(len(p)+1))
	b[4] = id
	copy(b[5:], p)
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	return fullWrite(x.c, b)
}

func (x *requestPieceCarrier) issue() error {
	if x.next >= totalPieces {
		return fmt.Errorf("virtual piece space exhausted")
	}
	idx := x.next
	x.next += 2
	x.pending[idx] = true
	var p [12]byte
	binary.BigEndian.PutUint32(p[:], idx)
	binary.BigEndian.PutUint32(p[8:], BlockSize)
	return x.message(6, p[:])
}

func (x *requestPieceCarrier) readLoop() {
	defer x.Close()
	bitfield, unchoked, primed := false, false, false
	for {
		var h [4]byte
		if _, err := io.ReadFull(x.c, h[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(h[:]))
		if n == 0 {
			continue // keepalive
		}
		if n > 16397 {
			x.invalid.Add(1)
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(x.c, b); err != nil {
			return
		}
		switch b[0] {
		case 5:
			if len(b) != 1+totalPieces/8 {
				x.invalid.Add(1)
				return
			}
			bitfield = true
		case 1:
			unchoked = true
		case 2:
			// interested: no state needed
		case 6:
			if len(b) != 13 {
				x.invalid.Add(1)
				return
			}
			r := request{binary.BigEndian.Uint32(b[1:]), binary.BigEndian.Uint32(b[5:]), binary.BigEndian.Uint32(b[9:])}
			// Opposite parity to our requested blocks is our advertised half.
			if r.Index >= totalPieces || r.Index%2 == x.next%2 || r.Offset != 0 || r.Length != BlockSize {
				x.invalid.Add(1)
				return
			}
			select {
			case x.requests <- r:
			case <-x.done:
				return
			}
		case 7:
			if len(b) != 1+8+BlockSize {
				x.invalid.Add(1)
				return
			}
			idx := binary.BigEndian.Uint32(b[1:])
			off := binary.BigEndian.Uint32(b[5:])
			if !x.pending[idx] || off != 0 {
				x.invalid.Add(1)
				return
			}
			delete(x.pending, idx)
			size := int(binary.BigEndian.Uint16(b[9:11]))
			if size == 0 || size > BlockSize-2 {
				x.invalid.Add(1)
				return
			}
			p := append([]byte(nil), b[11:11+size]...)
			select {
			case x.received <- p:
			case <-x.done:
				return
			}
			// Replenish request credit immediately; no per-packet request RTT.
			if err := x.issue(); err != nil {
				return
			}
		default:
			x.invalid.Add(1)
			return
		}
		if bitfield && unchoked && !primed {
			primed = true
			for range requestWindow {
				if err := x.issue(); err != nil {
					return
				}
			}
		}
	}
}

func (x *requestPieceCarrier) Send(p []byte) error {
	if len(p) > BlockSize-2 {
		return fmt.Errorf("AWG datagram too large: %d", len(p))
	}
	var r request
	select {
	case r = <-x.requests:
	case <-x.done:
		return net.ErrClosed
	}
	b := make([]byte, 8+BlockSize)
	binary.BigEndian.PutUint32(b, r.Index)
	binary.BigEndian.PutUint16(b[8:], uint16(len(p)))
	copy(b[10:], p)
	// Random tail so each piece reads as high-entropy content.
	if _, err := rand.Read(b[10+len(p):]); err != nil {
		return err
	}
	return x.message(7, b)
}

// Invalid reports how many malformed wire messages were rejected.
func (x *requestPieceCarrier) Invalid() int64 { return x.invalid.Load() }

func (x *requestPieceCarrier) Close() {
	x.once.Do(func() {
		close(x.done)
		x.c.Close()
	})
}

func (x *requestPieceCarrier) Wait() {
	x.Close()
	x.wg.Wait()
}

func (x *requestPieceCarrier) Recv() <-chan []byte   { return x.received }
func (x *requestPieceCarrier) Done() <-chan struct{} { return x.done }
