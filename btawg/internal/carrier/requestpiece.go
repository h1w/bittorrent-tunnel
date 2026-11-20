package carrier

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// Each endpoint advertises one half of the virtual index space. Indices cycle
// after the outstanding requests have drained past them.
const (
	legacyRequestWindow   = 32
	wideRequestFeature    = 1
	compactRequestFeature = 2
	compactBlockSize      = 1536
	pieceContinuation     = 1 << 15
	// One credit carries one datagram. 12,288 credits leave room for 500
	// Mbit/s of full-sized TCP payloads at 200 ms RTT.
	requestWindow = 12288
	totalPieces   = 65536
)

// Wire-format experiment, NOT a valid immutable-file torrent: AWG ciphertext
// replaces file blocks, so file hashes never validate.
type request uint32

type requestPieceCarrier struct {
	c            net.Conn
	writeMu      sync.Mutex
	sendMu       sync.Mutex // keep fragments of one datagram adjacent
	pieceFrame   [13 + BlockSize]byte
	pieceBatch   []byte
	requests     chan request
	replacements chan [17]byte
	received     chan []byte
	done         chan struct{}
	once         sync.Once
	wg           sync.WaitGroup
	pending      map[uint32]bool
	next         uint32
	window       int
	blockSize    int
	invalid      atomic.Int64
}

// NewRequestPiece wraps an established connection with BEP 3 request/piece
// framing (message ids: 1 unchoke, 2 interested, 5 bitfield, 6 request,
// 7 piece). ownOdd selects which half of the virtual file this endpoint
// advertises; the two ends of one connection must pass opposite values. The
// peer's handshake ID is returned for caller-side routing.
func NewRequestPiece(c net.Conn, infoHash, peerID [20]byte, ownOdd bool) (Transport, [20]byte, error) {
	theirs, features, err := handshake(c, infoHash, peerID, wideRequestFeature|compactRequestFeature)
	if err != nil {
		return nil, theirs, err
	}
	window := legacyRequestWindow
	if features&wideRequestFeature != 0 {
		window = requestWindow
	}
	blockSize := BlockSize
	if features&compactRequestFeature != 0 {
		blockSize = compactBlockSize
	}
	x := &requestPieceCarrier{
		c:            c,
		requests:     make(chan request, window),
		replacements: make(chan [17]byte, window),
		received:     make(chan []byte, receiveQueuePackets),
		done:         make(chan struct{}),
		pending:      make(map[uint32]bool, window),
		window:       window,
		blockSize:    blockSize,
	}
	x.start(ownOdd)
	return x, theirs, nil
}

// acceptRequestPiece finishes a server-side request/piece carrier after the
// initial BitTorrent handshake has already been consumed by Accept. The server
// advertises the odd half of the virtual index space to match the legacy
// server role; connecting clients must use the even half (ownOdd=false).
func acceptRequestPiece(c net.Conn, theirs [20]byte, peerFeatures byte) (Transport, error) {
	window := legacyRequestWindow
	if peerFeatures&wideRequestFeature != 0 {
		window = requestWindow
	}
	blockSize := BlockSize
	if peerFeatures&compactRequestFeature != 0 {
		blockSize = compactBlockSize
	}
	x := &requestPieceCarrier{
		c:            c,
		requests:     make(chan request, window),
		replacements: make(chan [17]byte, window),
		received:     make(chan []byte, receiveQueuePackets),
		done:         make(chan struct{}),
		pending:      make(map[uint32]bool, window),
		window:       window,
		blockSize:    blockSize,
	}
	x.start(true)
	return x, nil
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
	x.wg.Add(1)
	go x.writeReplacements()
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

func (x *requestPieceCarrier) nextRequest() [17]byte {
	idx := x.next
	for x.pending[idx] {
		idx = (idx + 2) % totalPieces
	}
	x.next = (idx + 2) % totalPieces
	x.pending[idx] = true
	var b [17]byte
	binary.BigEndian.PutUint32(b[:], 13)
	b[4] = 6
	binary.BigEndian.PutUint32(b[5:], idx)
	binary.BigEndian.PutUint32(b[13:], uint32(x.wireBlockSize()))
	return b
}

func (x *requestPieceCarrier) queueReplacement() bool {
	b := x.nextRequest()
	select {
	case x.replacements <- b:
		return true
	case <-x.done:
		return false
	default:
		// At most a receive window of issued requests can be replaced before
		// the peer sees any new credits. More means it sent unsolicited data.
		x.invalid.Add(1)
		return false
	}
}

func (x *requestPieceCarrier) writeReplacements() {
	defer x.wg.Done()
	// Drain credits already waiting without a timer. More room matters
	// when the writer has been blocked behind a data batch.
	const batch = 256
	var requests [17 * batch]byte
	for {
		select {
		case <-x.done:
			return
		case b := <-x.replacements:
			copy(requests[:], b[:])
		}
		n := 17
		x.writeMu.Lock()
		for n < len(requests) && len(x.replacements) != 0 {
			b := <-x.replacements
			copy(requests[n:], b[:])
			n += len(b)
		}
		err := fullWrite(x.c, requests[:n])
		x.writeMu.Unlock()
		if err != nil {
			x.Close()
			return
		}
	}
}

func (x *requestPieceCarrier) readLoop() {
	defer x.Close()
	reader := bufio.NewReaderSize(x.c, streamReadBuffer)
	blockSize := x.wireBlockSize()
	var partial []byte
	bitfield, unchoked, primed := false, false, false
	for {
		h, err := reader.Peek(4)
		if err != nil {
			return
		}
		length := binary.BigEndian.Uint32(h)
		reader.Discard(4)
		if length == 0 {
			continue // keepalive
		}
		if length > 1+totalPieces/8 {
			x.invalid.Add(1)
			return
		}
		n := int(length)
		b, err := reader.Peek(n)
		if err != nil {
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
			idx := binary.BigEndian.Uint32(b[1:])
			// Opposite parity to our requested blocks is our advertised half.
			if idx >= totalPieces || idx%2 == x.next%2 || binary.BigEndian.Uint32(b[5:]) != 0 || binary.BigEndian.Uint32(b[9:]) != uint32(blockSize) {
				x.invalid.Add(1)
				return
			}
			select {
			case x.requests <- request(idx):
			case <-x.done:
				return
			default:
				x.invalid.Add(1)
				return
			}
		case 7:
			if len(b) != 9+blockSize {
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
			length := binary.BigEndian.Uint16(b[9:11])
			continued := length&pieceContinuation != 0
			size := int(length &^ pieceContinuation)
			if size == 0 || size > blockSize-2 || (continued && (blockSize != compactBlockSize || size != blockSize-2 || partial != nil)) || len(partial)+size > BlockSize-2 {
				x.invalid.Add(1)
				return
			}
			p := b[11 : 11+size]
			if continued {
				partial = make([]byte, size, BlockSize-2)
				copy(partial, p)
			} else {
				p = append(partial, p...)
				partial = nil
				select {
				case x.received <- p:
				case <-x.done:
					return
				}
			}
			if !x.queueReplacement() {
				return
			}
		default:
			x.invalid.Add(1)
			return
		}
		reader.Discard(n)
		if bitfield && unchoked && !primed {
			primed = true
			for range x.window {
				if !x.queueReplacement() {
					return
				}
			}
		}
	}
}

func (x *requestPieceCarrier) wireBlockSize() int {
	if x.blockSize == 0 {
		return BlockSize
	}
	return x.blockSize
}

func (x *requestPieceCarrier) Send(p []byte) error {
	if len(p) == 0 || len(p) > BlockSize-2 {
		return fmt.Errorf("invalid AWG datagram size: %d", len(p))
	}
	x.sendMu.Lock()
	defer x.sendMu.Unlock()
	return x.sendDatagram(p)
}

func (x *requestPieceCarrier) sendDatagram(p []byte) error {
	block := x.wireBlockSize()
	for len(p) > 0 {
		var r request
		select {
		case r = <-x.requests:
		case <-x.done:
			return net.ErrClosed
		}
		n := min(len(p), block-2)
		x.writeMu.Lock()
		b := x.pieceFrame[:13+block]
		framePiece(b, r, p[:n], n < len(p))
		err := fullWrite(x.c, b)
		x.writeMu.Unlock()
		if err != nil {
			x.Close()
			return err
		}
		p = p[n:]
	}
	return nil
}

// SendBatch uses the credits already queued, flushing before waiting for more.
func (x *requestPieceCarrier) SendBatch(packets [][]byte) error {
	for _, p := range packets {
		if len(p) == 0 || len(p) > BlockSize-2 {
			return fmt.Errorf("invalid AWG datagram size: %d", len(p))
		}
	}
	x.sendMu.Lock()
	defer x.sendMu.Unlock()
	block := x.wireBlockSize()
	frameSize := 13 + block
	const chunk = 32
	for len(packets) > 0 {
		if len(packets[0]) > block-2 {
			if err := x.sendDatagram(packets[0]); err != nil {
				return err
			}
			packets = packets[1:]
			continue
		}
		var credits [chunk]request
		select {
		case credits[0] = <-x.requests:
		case <-x.done:
			return net.ErrClosed
		}
		n := 1
	collect:
		for n < min(len(packets), chunk) && len(packets[n]) <= block-2 {
			select {
			case credits[n] = <-x.requests:
				n++
			default:
				break collect
			}
		}
		x.writeMu.Lock()
		if x.pieceBatch == nil {
			x.pieceBatch = make([]byte, chunk*frameSize)
		}
		for i, p := range packets[:n] {
			framePiece(x.pieceBatch[i*frameSize:(i+1)*frameSize], credits[i], p, false)
		}
		err := fullWrite(x.c, x.pieceBatch[:n*frameSize])
		x.writeMu.Unlock()
		if err != nil {
			x.Close()
			return err
		}
		packets = packets[n:]
	}
	return nil
}

func framePiece(b []byte, r request, p []byte, continued bool) {
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	b[4] = 7
	binary.BigEndian.PutUint32(b[5:], uint32(r))
	length := uint16(len(p))
	if continued {
		length |= pieceContinuation
	}
	binary.BigEndian.PutUint16(b[13:], length)
	copy(b[15:], p)
	rand.Read(b[15+len(p):])
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
