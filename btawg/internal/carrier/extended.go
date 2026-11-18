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

// extMessage frames one extended message: uint16 length + AWG datagram +
// random padding to BlockSize, carried as a BEP 10 message with the given
// private extended id.
func extMessage(id byte, p []byte) ([]byte, error) {
	if len(p) > BlockSize-2 {
		return nil, fmt.Errorf("AWG datagram too large: %d", len(p))
	}
	d := make([]byte, 2+BlockSize)
	binary.BigEndian.PutUint16(d[:2], uint16(len(p)))
	copy(d[2:], p)
	if _, err := rand.Read(d[2+len(p):]); err != nil {
		return nil, err
	}
	b := make([]byte, 6+len(d))
	binary.BigEndian.PutUint32(b, uint32(2+len(d)))
	b[4] = 20
	b[5] = id
	copy(b[6:], d)
	return b, nil
}

type extCarrier struct {
	c        net.Conn
	writeMu  sync.Mutex
	received chan []byte
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	invalid  atomic.Int64
}

// NewExtended wraps an established connection with BEP 10 extended framing:
// BitTorrent handshake, extension handshake, then private id-1 messages whose
// payloads are uint16-length-prefixed AWG datagrams padded to BlockSize.
func NewExtended(c net.Conn, infoHash, peerID [20]byte) (Transport, error) {
	if _, err := Handshake(c, infoHash, peerID); err != nil {
		return nil, err
	}
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
		received: make(chan []byte, 256),
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
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(x.c, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(lenBuf[:]))
		if n == 0 {
			continue // keepalive
		}
		if n > 4+BlockSize {
			x.invalid.Add(1)
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(x.c, b); err != nil {
			return
		}
		if n < 2 || b[0] != 20 {
			x.invalid.Add(1)
			return
		}
		switch b[1] {
		case 0:
			continue // re-handshake, ignored
		case extDataID:
			if n < 4 {
				x.invalid.Add(1)
				return
			}
			size := int(binary.BigEndian.Uint16(b[2:4]))
			if size == 0 || 2+size > n {
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
	}
}

func (x *extCarrier) Send(p []byte) error {
	b, err := extMessage(extDataID, p)
	if err != nil {
		return err
	}
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	return fullWrite(x.c, b)
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
