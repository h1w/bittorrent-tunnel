package carrier

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// extDataID is the private extended-message id negotiated for btawg data in
// the BEP 10 extension handshake.
const extDataID = 1

// extHandshakeMsg renders the BEP 10 extension handshake: message id 20,
// extended id 0, bencoded {"m":{"btawg":1}} with no padding.
func extHandshakeMsg() []byte {
	p := []byte("d1:md5:btawgi1ee")
	b := make([]byte, 6+len(p))
	binary.BigEndian.PutUint32(b, uint32(2+len(p)))
	b[4] = 20
	b[5] = 0
	copy(b[6:], p)
	return b
}

const extFrameSize = 8 + BlockSize

type extCarrier struct {
	c          net.Conn
	writeMu    sync.Mutex
	writeFrame [extFrameSize]byte
	writeBatch []byte
	received   chan []byte
	done       chan struct{}
	once       sync.Once
	wg         sync.WaitGroup
	invalid    atomic.Int64
}

// NewExtended wraps an established connection with BEP 10 extended framing:
// BitTorrent handshake (the peer's ID is returned for caller-side routing),
// extension handshake, then private id-1 messages whose payloads are
// uint16-length-prefixed AWG datagrams with bounded padding.
func NewExtended(c net.Conn, infoHash, peerID [20]byte) (Transport, [20]byte, error) {
	theirs, err := Handshake(c, infoHash, peerID)
	if err != nil {
		return nil, theirs, err
	}
	sendErr := make(chan error, 1)
	go func() { sendErr <- fullWrite(c, extHandshakeMsg()) }()
	var lenBuf [4]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		c.Close()
		<-sendErr
		return nil, theirs, fmt.Errorf("read ext handshake: %w", err)
	}
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	if n == 0 || n > 4098 {
		c.Close()
		<-sendErr
		return nil, theirs, fmt.Errorf("bad ext handshake length")
	}
	h := make([]byte, n)
	if _, err := io.ReadFull(c, h); err != nil {
		c.Close()
		<-sendErr
		return nil, theirs, fmt.Errorf("read ext handshake body: %w", err)
	}
	if err := <-sendErr; err != nil {
		return nil, theirs, fmt.Errorf("write ext handshake: %w", err)
	}
	if n < 2 || h[0] != 20 || h[1] != 0 {
		return nil, theirs, fmt.Errorf("bad ext handshake")
	}
	x := &extCarrier{
		c:        c,
		received: make(chan []byte, receiveQueuePackets),
		done:     make(chan struct{}),
	}
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		x.readLoop()
	}()
	return x, theirs, nil
}

// acceptExtended finishes a server-side extended carrier after the initial
// BitTorrent handshake has already been consumed by Accept. It performs the
// BEP 10 extension handshake and starts the read loop.
func acceptExtended(c net.Conn, theirs [20]byte) (Transport, error) {
	sendErr := make(chan error, 1)
	go func() { sendErr <- fullWrite(c, extHandshakeMsg()) }()
	var lenBuf [4]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		c.Close()
		<-sendErr
		return nil, fmt.Errorf("read ext handshake: %w", err)
	}
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	if n == 0 || n > 4098 {
		c.Close()
		<-sendErr
		return nil, fmt.Errorf("bad ext handshake length")
	}
	h := make([]byte, n)
	if _, err := io.ReadFull(c, h); err != nil {
		c.Close()
		<-sendErr
		return nil, fmt.Errorf("read ext handshake body: %w", err)
	}
	if err := <-sendErr; err != nil {
		return nil, fmt.Errorf("write ext handshake: %w", err)
	}
	if n < 2 || h[0] != 20 || h[1] != 0 {
		return nil, fmt.Errorf("bad ext handshake")
	}
	x := &extCarrier{
		c:        c,
		received: make(chan []byte, receiveQueuePackets),
		done:     make(chan struct{}),
	}
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		x.readLoop()
	}()
	return x, nil
}

func (x *extCarrier) readLoop() {
	defer x.Close()
	reader := bufio.NewReaderSize(x.c, streamReadBuffer)
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
		if length > 4+BlockSize {
			x.invalid.Add(1)
			return
		}
		n := int(length)
		b, err := reader.Peek(n)
		if err != nil {
			return
		}
		if n < 2 || b[0] != 20 {
			x.invalid.Add(1)
			return
		}
		switch b[1] {
		case 0:
			reader.Discard(n)
			continue // re-handshake, ignored
		case extDataID:
			if n < 4 {
				x.invalid.Add(1)
				return
			}
			size := int(binary.BigEndian.Uint16(b[2:4]))
			if size == 0 || size > n-4 {
				x.invalid.Add(1)
				return
			}
			d := append([]byte(nil), b[4:4+size]...)
			select {
			case x.received <- d:
			case <-x.done:
				return
			}
		default:
			x.invalid.Add(1)
			return
		}
		reader.Discard(n)
	}
}

func (x *extCarrier) Send(p []byte) error {
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	b := x.writeFrame[:]
	n, err := frameExtended(b, p)
	if err != nil {
		return err
	}
	return fullWrite(x.c, b[:n])
}

// SendBatch sends packets already available together without a coalescing timer.
func (x *extCarrier) SendBatch(packets [][]byte) error {
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	const chunk = 32
	if x.writeBatch == nil {
		x.writeBatch = make([]byte, chunk*extFrameSize)
	}
	for len(packets) > 0 {
		n := min(len(packets), chunk)
		used := 0
		for _, p := range packets[:n] {
			size, err := frameExtended(x.writeBatch[used:], p)
			if err != nil {
				return err
			}
			used += size
		}
		if err := fullWrite(x.c, x.writeBatch[:used]); err != nil {
			return err
		}
		packets = packets[n:]
	}
	return nil
}

func frameExtended(b, p []byte) (int, error) {
	if len(p) == 0 || len(p) > BlockSize-2 {
		return 0, fmt.Errorf("invalid AWG datagram size: %d", len(p))
	}
	// Round up the data region, retaining at most 31 bytes of random padding.
	n := 6 + (len(p)+2+31)&^31
	binary.BigEndian.PutUint32(b, uint32(n-4))
	b[4], b[5] = 20, extDataID
	binary.BigEndian.PutUint16(b[6:], uint16(len(p)))
	copy(b[8:], p)
	_, err := rand.Read(b[8+len(p) : n])
	return n, err
}

// Invalid reports how many malformed wire messages were rejected.
func (x *extCarrier) Invalid() int64 { return x.invalid.Load() }

func (x *extCarrier) Close() {
	x.once.Do(func() {
		close(x.done)
		x.c.Close()
	})
}

func (x *extCarrier) Wait() {
	x.Close()
	x.wg.Wait()
}

func (x *extCarrier) Recv() <-chan []byte   { return x.received }
func (x *extCarrier) Done() <-chan struct{} { return x.done }
