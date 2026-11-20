package carrier

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
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
// handshake bytes are returned for caller-side routing.
func Handshake(c net.Conn, infoHash, peerID [20]byte) ([20]byte, error) {
	theirs, _, err := handshake(c, infoHash, peerID, 0)
	return theirs, err
}

// Accept reads the first BitTorrent handshake once on a server connection,
// dispatches to the carrier framing selected by the infohash in hashes
// ("ext" or "req", optionally with a payload suffix), replies, and
// negotiates the existing request/piece feature bits. The caller is
// responsible for any deadline on c; Accept does not reset it. The returned
// peer ID and family identify the enrollment and payload protocol.
func Accept(c net.Conn, serverID [20]byte, hashes map[[20]byte]string) (Transport, [20]byte, string, error) {
	var zero [20]byte
	var got [68]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		c.Close()
		return nil, zero, "", fmt.Errorf("read peer handshake: %w", err)
	}
	if got[0] != 19 || string(got[1:20]) != protocol {
		c.Close()
		return nil, zero, "", fmt.Errorf("invalid BT handshake magic")
	}
	var infoHash [20]byte
	copy(infoHash[:], got[28:48])
	mode, ok := hashes[infoHash]
	if !ok {
		c.Close()
		return nil, zero, "", fmt.Errorf("unknown infohash")
	}
	var theirs [20]byte
	copy(theirs[:], got[48:68])
	peerFeatures := got[20]

	framing, _, _ := strings.Cut(mode, "-")
	switch framing {
	case "ext":
		if err := acceptSendHandshake(c, infoHash, serverID, 0); err != nil {
			c.Close()
			return nil, theirs, mode, fmt.Errorf("write handshake: %w", err)
		}
		tr, err := acceptExtended(c, theirs)
		return tr, theirs, mode, err
	case "req":
		if err := acceptSendHandshake(c, infoHash, serverID, wideRequestFeature|compactRequestFeature); err != nil {
			c.Close()
			return nil, theirs, mode, fmt.Errorf("write handshake: %w", err)
		}
		tr, err := acceptRequestPiece(c, theirs, peerFeatures)
		return tr, theirs, mode, err
	default:
		c.Close()
		return nil, theirs, mode, fmt.Errorf("unknown carrier mode %q", mode)
	}
}

func acceptSendHandshake(c net.Conn, infoHash, peerID [20]byte, features byte) error {
	h := HandshakeBytes(infoHash, peerID)
	h[20] = features
	return fullWrite(c, h)
}

func handshake(c net.Conn, infoHash, peerID [20]byte, features byte) ([20]byte, byte, error) {
	var theirs [20]byte
	sendErr := make(chan error, 1)
	go func() {
		h := HandshakeBytes(infoHash, peerID)
		h[20] = features
		sendErr <- fullWrite(c, h)
	}()
	var got [68]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		c.Close()
		<-sendErr
		return theirs, 0, fmt.Errorf("read peer handshake: %w", err)
	}
	if err := <-sendErr; err != nil {
		return theirs, 0, fmt.Errorf("write handshake: %w", err)
	}
	if got[0] != 19 || string(got[1:20]) != protocol {
		return theirs, 0, fmt.Errorf("invalid BT handshake magic")
	}
	if !bytes.Equal(got[28:48], infoHash[:]) {
		return theirs, 0, fmt.Errorf("infohash mismatch")
	}
	copy(theirs[:], got[48:68])
	return theirs, got[20], nil
}
