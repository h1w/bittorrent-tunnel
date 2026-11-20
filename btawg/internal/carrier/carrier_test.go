package carrier

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

var (
	testHash = [20]byte{0x42, 0x54, 0x41, 0x57, 0x47, 1}
	peerA    = [20]byte{1}
	peerB    = [20]byte{2}
)

// tcpPair returns a buffered loopback connection pair. net.Pipe is fully
// synchronous and deadlocks the carriers (both read loops write requests
// while nobody reads); kernel socket buffers match production transports.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- nil
			return
		}
		srvCh <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}
	srv := <-srvCh
	ln.Close()
	if srv == nil {
		cli.Close()
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli, srv
}

func TestHandshakeBytes(t *testing.T) {
	h := HandshakeBytes(testHash, peerA)
	if len(h) != 68 {
		t.Fatalf("len %d, want 68", len(h))
	}
	if h[0] != 19 {
		t.Fatalf("protocol name length %d, want 19", h[0])
	}
	if string(h[1:20]) != "BitTorrent protocol" {
		t.Fatalf("protocol name %q", h[1:20])
	}
	if !bytes.Equal(h[28:48], testHash[:]) {
		t.Fatal("infohash not at [28:48]")
	}
	if !bytes.Equal(h[48:68], peerA[:]) {
		t.Fatal("peer ID not at [48:68]")
	}
}

func TestHandshakeRejectsWrongInfoHash(t *testing.T) {
	a, b := tcpPair(t)
	errs := make(chan error, 2)
	go func() {
		_, err := Handshake(a, testHash, peerA)
		errs <- err
	}()
	go func() {
		other := testHash
		other[0] ^= 0xff
		_, err := Handshake(b, other, peerB)
		errs <- err
	}()
	for range 2 {
		select {
		case err := <-errs:
			if err == nil {
				t.Fatal("handshake with mismatched infohash succeeded")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("handshake deadlock")
		}
	}
}

type result struct {
	tr  Transport
	pid [20]byte
	err error
}

type factory func(net.Conn) (Transport, [20]byte, error)

func pair(t *testing.T, fa, fb factory) (Transport, Transport) {
	t.Helper()
	a, b := tcpPair(t)
	ch := make(chan result, 1)
	go func() {
		tr, pid, err := fa(a)
		ch <- result{tr, pid, err}
	}()
	rb, _, err := fb(b)
	if err != nil {
		t.Fatalf("carrier b: %v", err)
	}
	t.Cleanup(rb.Wait)
	r := <-ch
	if r.err != nil {
		t.Fatalf("carrier a: %v", r.err)
	}
	t.Cleanup(r.tr.Wait)
	return r.tr, rb
}

func roundTrip(t *testing.T, ta, tb Transport) {
	t.Helper()
	payload := make([]byte, 256)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := ta.Send(payload); err != nil {
		t.Fatalf("send a->b: %v", err)
	}
	select {
	case got := <-tb.Recv():
		if !bytes.Equal(got, payload) {
			t.Fatalf("b received %d bytes, want the same payload", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery a->b")
	}
	if err := tb.Send(payload); err != nil {
		t.Fatalf("send b->a: %v", err)
	}
	select {
	case got := <-ta.Recv():
		if !bytes.Equal(got, payload) {
			t.Fatalf("a received %d bytes, want the same payload", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery b->a")
	}
}

func TestRequestPieceRoundTrip(t *testing.T) {
	ta, tb := pair(t,
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewRequestPiece(c, testHash, peerA, false)
		},
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewRequestPiece(c, testHash, peerB, true)
		},
	)
	roundTrip(t, ta, tb)
}

func TestRequestPieceNegotiatesCompactBlocks(t *testing.T) {
	const compactBody = 9 + 1536
	a, b := pair(t,
		func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerA, false) },
		func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerB, true) },
	)
	for _, size := range []int{1484, 2046, 1484, 1} {
		p := bytes.Repeat([]byte{byte(size)}, size)
		if err := a.Send(p); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-b.Recv():
			if !bytes.Equal(got, p) {
				t.Fatalf("datagram %d: got %d bytes with different content", size, len(got))
			}
		case <-b.Done():
			t.Fatalf("carrier closed delivering %d bytes", size)
		case <-time.After(5 * time.Second):
			t.Fatalf("carrier stalled delivering %d bytes", size)
		}
		body := binary.BigEndian.Uint32(a.(*requestPieceCarrier).pieceFrame[:4])
		if body != compactBody {
			t.Fatalf("datagram %d: piece body %d, want %d", size, body, compactBody)
		}
	}
}

type gatedPieceWriter struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (c *gatedPieceWriter) Write(p []byte) (int, error) {
	if len(p) >= 5 && p[4] == 7 {
		close(c.entered)
		<-c.release
	}
	return c.Conn.Write(p)
}

func TestRequestPieceReceivesWhileOutboundWriteBlocked(t *testing.T) {
	a, b := tcpPair(t)
	gate := &gatedPieceWriter{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
	const deadline = 2 * time.Second
	for _, c := range []net.Conn{a, b} {
		if err := c.SetDeadline(time.Now().Add(deadline)); err != nil {
			t.Fatal(err)
		}
	}
	ready := make(chan result, 1)
	go func() {
		tr, pid, err := NewRequestPiece(gate, testHash, peerA, false)
		ready <- result{tr: tr, pid: pid, err: err}
	}()
	remote, _, err := NewRequestPiece(b, testHash, peerB, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.Wait)
	local := <-ready
	if local.err != nil {
		t.Fatal(local.err)
	}
	t.Cleanup(local.tr.Wait)
	t.Cleanup(func() { close(gate.release) })
	// The async writer must publish two credits before it is blocked.
	credits := remote.(*requestPieceCarrier).requests
	var primed [2]request
	for i := range primed {
		select {
		case primed[i] = <-credits:
		case <-time.After(deadline):
			t.Fatal("peer did not receive initial requests")
		}
	}
	for _, r := range primed {
		credits <- r
	}
	go local.tr.Send([]byte("blocked"))
	select {
	case <-gate.entered:
	case <-time.After(deadline):
		t.Fatal("outbound writer never blocked")
	}
	for _, p := range []string{"first", "second"} {
		if err := remote.Send([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"first", "second"} {
		select {
		case got := <-local.tr.Recv():
			if string(got) != want {
				t.Fatalf("got %q; want %q", got, want)
			}
		case <-time.After(deadline):
			t.Fatalf("awaiting %q while outbound writer blocked", want)
		}
	}
}

func TestRequestPieceSustainedTransfer(t *testing.T) {
	a, b := pair(t,
		func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerA, false) },
		func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerB, true) },
	)
	// Exceed the original per-direction piece space in both directions.
	const count = 33000
	deadline := time.After(20 * time.Second)
	for _, direction := range [][2]Transport{{a, b}, {b, a}} {
		sender, receiver := direction[0], direction[1]
		sent := make(chan error, 1)
		go func() {
			var payload [2]byte
			for i := range count {
				payload = [2]byte{byte(i >> 8), byte(i)}
				if err := sender.Send(payload[:]); err != nil {
					sent <- err
					return
				}
			}
			sent <- nil
		}()
		for i := range count {
			select {
			case got := <-receiver.Recv():
				if !bytes.Equal(got, []byte{byte(i >> 8), byte(i)}) {
					t.Fatalf("datagram %d: got %x", i, got)
				}
			case <-receiver.Done():
				t.Fatalf("carrier closed at datagram %d of %d", i, count)
			case <-deadline:
				t.Fatalf("transfer stalled at datagram %d of %d", i, count)
			}
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
	}
}

func TestRequestPiecePipelinesBeforeReplies(t *testing.T) {
	a, b := pair(t,
		func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerA, false) },
		func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerB, true) },
	)
	// At 200 ms RTT, 500 Mbit/s needs 12.5 MB of payload in flight.
	// Use a conservative 1300 bytes of application data per datagram.
	requests := b.(*requestPieceCarrier).requests
	deadline := time.After(5 * time.Second)
	for i := range 9616 {
		select {
		case <-requests:
		case <-a.Done():
			t.Fatalf("carrier closed after %d credits", i)
		case <-deadline:
			t.Fatalf("carrier stalled after %d credits without replies", i)
		}
	}
}

func TestRequestPieceInvalidBatchKeepsCredits(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	if err := b.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	x := &requestPieceCarrier{c: a, requests: make(chan request, 2), done: make(chan struct{})}
	x.requests <- 2
	x.requests <- 4
	if err := x.SendBatch([][]byte{[]byte("valid"), make([]byte, 2048)}); err == nil {
		t.Fatal("oversized datagram accepted")
	}
	done := make(chan error, 1)
	go func() { done <- x.SendBatch([][]byte{[]byte("first"), []byte("second")}) }()
	defer x.Close()
	for _, want := range []uint32{2, 4} {
		var frame [2061]byte
		if _, err := io.ReadFull(b, frame[:]); err != nil {
			t.Fatal(err)
		}
		if frame[4] != 7 || binary.BigEndian.Uint32(frame[5:9]) != want {
			t.Fatalf("expected piece index %d in wire response", want)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRequestPieceWrapSkipsDelayedReply(t *testing.T) {
	a, b := tcpPair(t)
	if err := b.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	x := &requestPieceCarrier{c: a, next: 0, pending: map[uint32]bool{0: true}, replacements: make(chan [17]byte, 1), done: make(chan struct{})}
	if !x.queueReplacement() {
		t.Fatal("failed to queue a replacement for a retired index")
	}
	frame := <-x.replacements
	if frame[4] != 6 || binary.BigEndian.Uint32(frame[5:9]) != 2 {
		t.Fatal("reused the index of a piece still in flight")
	}
}

func TestRequestPieceLegacyReceiverReadsPayload(t *testing.T) {
	a, b := tcpPair(t)
	if err := b.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ready := make(chan result, 1)
	go func() {
		tr, pid, err := NewRequestPiece(a, testHash, peerA, false)
		ready <- result{tr: tr, pid: pid, err: err}
	}()
	if _, err := Handshake(b, testHash, peerB); err != nil {
		t.Fatal(err)
	}
	readFrame := func() []byte {
		var prefix [4]byte
		if _, err := io.ReadFull(b, prefix[:]); err != nil {
			t.Fatal(err)
		}
		body := make([]byte, binary.BigEndian.Uint32(prefix[:]))
		if _, err := io.ReadFull(b, body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, id := range []byte{5, 2, 1} {
		if got := readFrame()[0]; got != id {
			t.Fatalf("startup message ID %d, want %d", got, id)
		}
	}
	res := <-ready
	if res.err != nil {
		t.Fatal(res.err)
	}
	t.Cleanup(res.tr.Wait)
	// Send one legacy request before unchoking. The new peer must not place
	// over 32 credits ahead of its first piece on this connection.
	var reply [8219]byte
	binary.BigEndian.PutUint32(reply[:4], 8193)
	reply[4] = 5
	binary.BigEndian.PutUint32(reply[8197:8201], 13)
	reply[8201] = 6
	binary.BigEndian.PutUint32(reply[8210:8214], BlockSize)
	binary.BigEndian.PutUint32(reply[8214:8218], 1)
	reply[8218] = 1
	if err := fullWrite(b, reply[:]); err != nil {
		t.Fatal(err)
	}
	for range 32 {
		if got := readFrame()[0]; got != 6 {
			t.Fatalf("credit message ID %d, want 6", got)
		}
	}
	if err := res.tr.Send([]byte("first piece")); err != nil {
		t.Fatal(err)
	}
	if got := readFrame(); got[0] != 7 || !bytes.Equal(got[11:22], []byte("first piece")) {
		t.Fatalf("legacy receiver sees message %d instead of its requested piece after 32 credits", got[0])
	}
}

func TestExtendedRoundTrip(t *testing.T) {
	ta, tb := pair(t,
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewExtended(c, testHash, peerA)
		},
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewExtended(c, testHash, peerB)
		},
	)
	roundTrip(t, ta, tb)
}

func TestExtendedWireFrameUsesPayloadSize(t *testing.T) {
	for _, batch := range []bool{false, true} {
		a, b := tcpPair(t)
		if err := b.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		x := &extCarrier{c: a}
		packets := [][]byte{bytes.Repeat([]byte{0x58}, 1456)}
		if batch {
			packets = append(packets, bytes.Repeat([]byte{0x72}, 64))
		}
		if batch {
			if err := x.SendBatch(packets); err != nil {
				t.Fatal(err)
			}
		} else if err := x.Send(packets[0]); err != nil {
			t.Fatal(err)
		}
		for _, p := range packets {
			var prefix [4]byte
			if _, err := io.ReadFull(b, prefix[:]); err != nil {
				t.Fatal(err)
			}
			n := int(binary.BigEndian.Uint32(prefix[:]))
			if n < 4+len(p) || n >= 4+len(p)+32 {
				t.Fatalf("batch=%t: %d-byte payload encoded as %d-byte message body", batch, len(p), n)
			}
			body := make([]byte, n)
			if _, err := io.ReadFull(b, body); err != nil {
				t.Fatal(err)
			}
			if body[0] != 20 || body[1] != 1 || int(binary.BigEndian.Uint16(body[2:4])) != len(p) || !bytes.Equal(body[4:4+len(p)], p) {
				t.Fatal("extended frame changed message ID or payload")
			}
		}
	}
}

func TestBatchCarriesEachDatagram(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b factory
	}{
		{"extended",
			func(c net.Conn) (Transport, [20]byte, error) { return NewExtended(c, testHash, peerA) },
			func(c net.Conn) (Transport, [20]byte, error) { return NewExtended(c, testHash, peerB) }},
		{"request-piece",
			func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerA, false) },
			func(c net.Conn) (Transport, [20]byte, error) { return NewRequestPiece(c, testHash, peerB, true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := pair(t, tc.a, tc.b)
			const count = 67
			var packets [count][]byte
			for i := range packets {
				packets[i] = bytes.Repeat([]byte{byte(i)}, 17+i)
			}
			res := make(chan error, 1)
			go func() { res <- a.(interface{ SendBatch([][]byte) error }).SendBatch(packets[:]) }()
			deadline := time.After(5 * time.Second)
			for i, want := range packets {
				select {
				case got := <-b.Recv():
					if !bytes.Equal(got, want) {
						t.Fatalf("datagram %d: got %x, want %x", i, got, want)
					}
				case <-b.Done():
					t.Fatalf("carrier closed before datagram %d", i)
				case <-deadline:
					t.Fatalf("datagram %d not delivered", i)
				}
			}
			if err := <-res; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPeerIDIsReturned(t *testing.T) {
	a, b := tcpPair(t)
	ch := make(chan [20]byte, 1)
	go func() {
		_, pid, err := NewExtended(a, testHash, peerA)
		if err != nil {
			t.Errorf("carrier a: %v", err)
		}
		ch <- pid
	}()
	_, pid, err := NewExtended(b, testHash, peerB)
	if err != nil {
		t.Fatalf("carrier b: %v", err)
	}
	if pid != peerA {
		t.Fatalf("carrier b saw peer ID %v, want %v", pid, peerA)
	}
	select {
	case got := <-ch:
		if got != peerB {
			t.Fatalf("carrier a saw peer ID %v, want %v", got, peerB)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("carrier a did not finish")
	}
}

func TestOversizedSendRejected(t *testing.T) {
	ta, tb := pair(t,
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewExtended(c, testHash, peerA)
		},
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewExtended(c, testHash, peerB)
		},
	)
	_ = tb
	if err := ta.Send(make([]byte, BlockSize)); err == nil {
		t.Fatal("extended Send accepted BlockSize payload, want error")
	}
	pa, pb := pair(t,
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewRequestPiece(c, testHash, peerA, false)
		},
		func(c net.Conn) (Transport, [20]byte, error) {
			return NewRequestPiece(c, testHash, peerB, true)
		},
	)
	_ = pb
	if err := pa.Send(make([]byte, BlockSize)); err == nil {
		t.Fatal("request/piece Send accepted BlockSize payload, want error")
	}
}
