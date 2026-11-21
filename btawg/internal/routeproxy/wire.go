package routeproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
)

const (
	wireMagic      = "BRP\x01"
	modeTCP        = 1
	modeUDP        = 2
	statusOK       = 0
	statusBad      = 1
	statusReceived = 2
	statusProceed  = 3

	maxRouteID = 256
	maxGrant   = 8192
	maxHost    = 255
	// Leave room for the 10-byte SOCKS header within IPv4's UDP payload limit.
	maxDatagram = 65507 - 10
)

var errInvalidFrame = errors.New("invalid route proxy frame")

// Initial request: magic/version, mode, hop, route ID length, grant length,
// host length, port, then the route ID, grant and host bytes. UDP has no host
// or port until the association is ready. The receiver acknowledges the
// invocation, the sender confirms the transport, then the receiver returns
// the final readiness status. No exit work occurs before confirmation.
// After success TCP uses a raw byte stream; UDP uses the frames below.
type command struct {
	req  Request
	mode byte
	dst  destination
}

// ReadInvocation reads exactly the first command and returns its route
// authorization fields and unchanged wire bytes. It does not read stream
// data. A forwarding caller should verify Request before relaying the bytes
// and must independently bound the reader's time to deliver the command.
func ReadInvocation(r io.Reader) (Request, []byte, error) {
	var raw bytes.Buffer
	q, err := readCommand(io.TeeReader(r, &raw))
	if err != nil {
		return Request{}, nil, err
	}
	return q.req, raw.Bytes(), nil
}

type destination struct {
	host string
	port uint16
}

func validRequest(r Request) bool {
	return r.Hop >= 0 && r.Hop <= 1 && len(r.RouteID) > 0 && len(r.RouteID) <= maxRouteID &&
		len(r.Grant) > 0 && len(r.Grant) <= maxGrant
}

func (q command) valid() bool {
	if !validRequest(q.req) {
		return false
	}
	switch q.mode {
	case modeTCP:
		return len(q.dst.host) > 0 && len(q.dst.host) <= maxHost && q.dst.port != 0
	case modeUDP:
		return q.dst == (destination{})
	default:
		return false
	}
}

const commandHeaderLen = 13

func (q command) writeTo(w io.Writer) error {
	if !q.valid() {
		return errInvalidFrame
	}
	b := make([]byte, commandHeaderLen, commandHeaderLen+len(q.req.RouteID)+len(q.req.Grant)+len(q.dst.host))
	copy(b[:4], wireMagic)
	b[4], b[5] = q.mode, byte(q.req.Hop)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(q.req.RouteID)))
	binary.BigEndian.PutUint16(b[8:10], uint16(len(q.req.Grant)))
	b[10] = byte(len(q.dst.host))
	binary.BigEndian.PutUint16(b[11:13], q.dst.port)
	b = append(b, q.req.RouteID...)
	b = append(b, q.req.Grant...)
	b = append(b, q.dst.host...)
	return writeBytes(w, b)
}

func readCommand(r io.Reader) (command, error) {
	var hdr [commandHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return command{}, err
	}
	idLen := int(binary.BigEndian.Uint16(hdr[6:8]))
	grantLen := int(binary.BigEndian.Uint16(hdr[8:10]))
	hostLen := int(hdr[10])
	if string(hdr[:4]) != wireMagic || idLen == 0 || idLen > maxRouteID || grantLen == 0 || grantLen > maxGrant {
		return command{}, errInvalidFrame
	}
	b := make([]byte, idLen+grantLen+hostLen)
	if _, err := io.ReadFull(r, b); err != nil {
		return command{}, err
	}
	// These fields share immutable storage for the duration of the request.
	s := string(b)
	q := command{
		req:  Request{RouteID: s[:idLen], Grant: s[idLen : idLen+grantLen], Hop: int(hdr[5])},
		mode: hdr[4],
		dst:  destination{host: s[idLen+grantLen:], port: binary.BigEndian.Uint16(hdr[11:13])},
	}
	if !q.valid() {
		return command{}, errInvalidFrame
	}
	return q, nil
}

func writeBytes(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

// Datagram request: payload length, host length, port, host, payload.
func writeDatagram(w io.Writer, host string, port uint16, payload []byte) error {
	var hdr [5 + maxHost]byte
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(payload)))
	hdr[2] = byte(len(host))
	binary.BigEndian.PutUint16(hdr[3:5], port)
	copy(hdr[5:], host)
	return writeDatagramParts(w, hdr[:5+len(host)], payload)
}

func readDatagram(r io.Reader, buf []byte) (destination, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return destination{}, nil, err
	}
	size := int(binary.BigEndian.Uint16(hdr[:2]))
	hostLen := int(hdr[2])
	port := binary.BigEndian.Uint16(hdr[3:5])
	if hostLen == 0 || port == 0 || size > maxDatagram {
		return destination{}, nil, errInvalidFrame
	}
	if _, err := io.ReadFull(r, buf[:hostLen+size]); err != nil {
		return destination{}, nil, err
	}
	return destination{host: string(buf[:hostLen]), port: port}, buf[hostLen : hostLen+size], nil
}

// Datagram reply: payload length, literal IPv4, port, payload.
func writeReply(w io.Writer, src netip.AddrPort, payload []byte) error {
	var hdr [8]byte
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(payload)))
	addr := src.Addr().As4()
	copy(hdr[2:6], addr[:])
	binary.BigEndian.PutUint16(hdr[6:8], src.Port())
	return writeDatagramParts(w, hdr[:], payload)
}

func readReply(r io.Reader, buf []byte) (int, netip.AddrPort, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	size := int(binary.BigEndian.Uint16(hdr[:2]))
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(hdr[2:6])), binary.BigEndian.Uint16(hdr[6:8]))
	if size > maxDatagram || size > len(buf) || src.Addr().IsUnspecified() || src.Port() == 0 {
		return 0, netip.AddrPort{}, errInvalidFrame
	}
	n, err := io.ReadFull(r, buf[:size])
	return n, src, err
}

func writeDatagramParts(w io.Writer, header, payload []byte) error {
	parts := net.Buffers{header, payload}
	n, err := parts.WriteTo(w)
	if err == nil && n != int64(len(header)+len(payload)) {
		return io.ErrShortWrite
	}
	return err
}
