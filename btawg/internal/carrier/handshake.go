package carrier

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

// protocol is the BitTorrent protocol identifier sent in every handshake.
const protocol = "BitTorrent protocol"

// HandshakeBytes renders the 68-byte BitTorrent protocol handshake for
// infoHash and peerID: length-prefixed protocol name, 8 reserved zero bytes,
// the 20-byte infohash, the 20-byte peer ID.
func HandshakeBytes(infoHash, peerID [20]byte) []byte {
	h := make([]byte, 68)
	h[0] = 19
	copy(h[1:], protocol)
	copy(h[28:], infoHash[:])
	copy(h[48:], peerID[:])
	return h
}

// Handshake performs the BitTorrent protocol handshake on c: it writes its own
// handshake for infoHash/peerID concurrently with reading the peer's, and
// fails on a short exchange, wrong magic, or a mismatched infohash. The peer's
// handshake bytes are returned for caller-side peer identification.
func Handshake(c net.Conn, infoHash, peerID [20]byte) ([20]byte, error) {
	var theirs [20]byte
	sendErr := make(chan error, 1)
	go func() {
		_, err := c.Write(HandshakeBytes(infoHash, peerID))
		sendErr <- err
	}()
	var got [68]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		c.Close()
		<-sendErr
		return theirs, fmt.Errorf("read peer handshake: %w", err)
	}
	if err := <-sendErr; err != nil {
		return theirs, fmt.Errorf("write handshake: %w", err)
	}
	if got[0] != 19 || string(got[1:20]) != protocol {
		return theirs, fmt.Errorf("invalid BT handshake magic")
	}
	if !bytes.Equal(got[28:48], infoHash[:]) {
		return theirs, fmt.Errorf("infohash mismatch")
	}
	copy(theirs[:], got[48:68])
	return theirs, nil
}
