// Package socks implements the two SOCKS5 roles btawg needs: a no-auth
// server (RFC 1928, CONNECT + UDP ASSOCIATE) and a chaining client that
// forwards both commands to a remote SOCKS5 server. The client's local server
// chains to the server's egress over the overlay; the egress server dials the
// real internet. UDP datagrams are never coalesced and FRAG != 0 is rejected.
package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
)

// DialFunc dials one TCP connection to the destination.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialUDPFunc returns an upstream UDP socket through which the caller sends
// raw datagrams to arbitrary destinations and receives raw datagrams back.
type DialUDPFunc func(ctx context.Context) (net.PacketConn, error)

// Server is a no-auth SOCKS5 server.
type Server struct {
	dial     DialFunc
	dialUDP  DialUDPFunc
	relayUDP func(local, remote net.Addr) (net.PacketConn, error)
}

// NewServer builds a server whose egress is the given dialers. The
// app-facing UDP relay defaults to a kernel socket on the listener's host;
// WithRelayUDP replaces it (btawg's netstack egress binds the relay inside
// the overlay stack).
func NewServer(dial DialFunc, dialUDP DialUDPFunc) *Server {
	return &Server{
		dial:     dial,
		dialUDP:  dialUDP,
		relayUDP: func(local, remote net.Addr) (net.PacketConn, error) { return listenUDPFor(local) },
	}
}

// WithRelayUDP replaces the app-facing UDP relay socket factory. The factory
// receives both the TCP listener's local address and the control connection's
// remote address so per-association source filtering can be applied.
func (s *Server) WithRelayUDP(fn func(local, remote net.Addr) (net.PacketConn, error)) *Server {
	if fn != nil {
		s.relayUDP = fn
	}
	return s
}

// ListenAndServe accepts SOCKS5 connections on addr until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts SOCKS5 connections on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	if !serveGreeting(c) {
		return
	}
	cmd, dst, err := readRequest(c)
	if err != nil {
		writeReply(c, replyGeneralFailure)
		return
	}
	switch cmd {
	case cmdConnect:
		s.handleConnect(ctx, c, dst)
	case cmdUDPAssociate:
		s.handleUDPAssociate(ctx, c, dst)
	default:
		writeReply(c, replyCommandUnsupported)
	}
}

func (s *Server) handleConnect(ctx context.Context, c net.Conn, dst target) {
	upstream, err := s.dial(ctx, "tcp", dst.String())
	if err != nil {
		writeReply(c, replyHostUnreachable)
		return
	}
	defer upstream.Close()
	boundLoopbackBuffers(c)
	boundLoopbackBuffers(upstream)
	if err := writeReply(c, replySucceeded); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, c)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, upstream)
		done <- struct{}{}
	}()
	<-done
}

// Loopback has negligible bandwidth-delay product. Large autotuned buffers
// there compete for the same TCP memory as the actual WAN carrier.
func boundLoopbackBuffers(c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok || !tcp.LocalAddr().(*net.TCPAddr).IP.IsLoopback() || !tcp.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
		return
	}
	const loopbackBuffer = 192 << 10
	// These are performance hints; a socket stays usable without them.
	_ = tcp.SetReadBuffer(loopbackBuffer)
	_ = tcp.SetWriteBuffer(loopbackBuffer)
}

func (s *Server) handleUDPAssociate(ctx context.Context, c net.Conn, _ target) {
	relay, err := s.relayUDP(c.LocalAddr(), c.RemoteAddr())
	if err != nil {
		writeReply(c, replyGeneralFailure)
		return
	}
	defer relay.Close()
	upstream, err := s.dialUDP(ctx)
	if err != nil {
		writeReply(c, replyGeneralFailure)
		return
	}
	defer upstream.Close()
	if err := writeUDPReply(c, relay.LocalAddr()); err != nil {
		return
	}
	s.pumpUDP(relay, upstream, c)
}

// pumpUDP bridges the app-facing relay (SOCKS5-UDP framed) and the upstream
// (raw datagrams) until the TCP control connection closes. Both sides use
// the net.PacketConn interface so kernel and netstack sockets work alike.
func (s *Server) pumpUDP(relay net.PacketConn, upstream net.PacketConn, ctrl net.Conn) {
	var appAddr atomic.Value // net.Addr of the app's relay socket
	closed := make(chan struct{})
	var once sync.Once
	shutdown := func() { once.Do(func() { close(closed) }) }
	go func() {
		io.Copy(io.Discard, ctrl) // control conn closed by the client
		shutdown()
		relay.Close()
		upstream.Close()
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := upstream.ReadFrom(buf)
			if err != nil {
				shutdown()
				return
			}
			app := appAddr.Load()
			if app == nil {
				continue
			}
			m := append(buildUDPHeader(src), buf[:n]...)
			if _, err := relay.WriteTo(m, app.(net.Addr)); err != nil {
				shutdown()
				return
			}
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, app, err := relay.ReadFrom(buf)
		if err != nil {
			shutdown()
			return
		}
		if appAddr.Load() == nil {
			appAddr.Store(app)
		}
		dst, data, err := parseUDPHeader(buf[:n])
		if err != nil {
			continue // malformed header: drop the datagram
		}
		if _, err := upstream.WriteTo(data, dst); err != nil {
			shutdown()
			return
		}
	}
}

// serveGreeting reads the client's method list and accepts no-auth (0x00).
func serveGreeting(c net.Conn) bool {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return false
	}
	if hdr[0] != socksVersion {
		return false
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return false
	}
	for _, m := range methods {
		if m == 0x00 {
			_, err := c.Write([]byte{socksVersion, 0x00})
			return err == nil
		}
	}
	c.Write([]byte{socksVersion, 0xFF})
	return false
}

const (
	socksVersion            = 5
	cmdConnect              = 0x01
	cmdUDPAssociate         = 0x03
	replySucceeded          = 0x00
	replyGeneralFailure     = 0x01
	replyHostUnreachable    = 0x04
	replyCommandUnsupported = 0x07
	atypIPv4                = 0x01
	atypDomain              = 0x03
	atypIPv6                = 0x04
)

// request is one parsed SOCKS5 request.
type request struct {
	cmd byte
	dst target
}

// target is the parsed destination of a SOCKS5 request: an IP or a domain
// plus a port. String is the host:port form the dialer receives.
type target struct {
	host string
	port int
}

func (t target) String() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }
func readRequest(c net.Conn) (byte, target, error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return 0, target{}, err
	}
	if head[0] != socksVersion {
		return 0, target{}, fmt.Errorf("bad SOCKS version %d", head[0])
	}
	host, err := readAddr(c, head[3])
	if err != nil {
		return 0, target{}, err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return 0, target{}, err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	return head[1], target{host: host, port: int(port)}, nil
}

// readAddr reads a SOCKS5 address field following the given ATYP and returns
// it as a host string: IP text, or the domain itself.
func readAddr(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case atypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case atypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return "", err
		}
		name := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		return string(name), nil
	default:
		return "", fmt.Errorf("unsupported ATYP %d", atyp)
	}
}

func writeReply(c net.Conn, rep byte) error {
	// VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0
	_, err := c.Write([]byte{socksVersion, rep, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func writeUDPReply(c net.Conn, bind net.Addr) error {
	udp, ok := bind.(*net.UDPAddr)
	if !ok {
		return writeReply(c, replyGeneralFailure)
	}
	ip := udp.IP.To4()
	atyp := byte(atypIPv4)
	if ip == nil {
		ip = udp.IP.To16()
		atyp = atypIPv6
	}
	b := []byte{socksVersion, replySucceeded, 0, atyp}
	b = append(b, ip...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(udp.Port))
	b = append(b, p[:]...)
	_, err := c.Write(b)
	return err
}

// listenUDPFor binds a UDP relay socket on the same host as the TCP listener.
func listenUDPFor(local net.Addr) (*net.UDPConn, error) {
	host := "127.0.0.1"
	if tcp, ok := local.(*net.TCPAddr); ok && tcp.IP != nil && !tcp.IP.IsUnspecified() {
		host = tcp.IP.String()
	}
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
}

// buildUDPHeader renders the SOCKS5 UDP header for addr: RSV(2) FRAG ATYP
// DST.ADDR DST.PORT.
func buildUDPHeader(addr net.Addr) []byte {
	var ip net.IP
	var port int
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, port = a.IP, a.Port
	case *net.TCPAddr:
		ip, port = a.IP, a.Port
	default:
		ip, port = net.IPv4zero, 0
	}
	if v4 := ip.To4(); v4 != nil {
		b := []byte{0, 0, 0, atypIPv4}
		b = append(b, v4...)
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], uint16(port))
		return append(b, p[:]...)
	}
	v6 := ip.To16()
	b := []byte{0, 0, 0, atypIPv6}
	b = append(b, v6...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	return append(b, p[:]...)
}

// parseUDPHeader splits a SOCKS5-UDP datagram into destination and payload.
// Fragmented datagrams (FRAG != 0) are rejected: btawg never fragments.
func parseUDPHeader(b []byte) (net.Addr, []byte, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("short UDP header")
	}
	if b[2] != 0 {
		return nil, nil, fmt.Errorf("fragmented UDP datagram rejected")
	}
	var ip net.IP
	switch b[3] {
	case atypIPv4:
		if len(b) < 10 {
			return nil, nil, fmt.Errorf("short IPv4 UDP header")
		}
		ip = net.IP(append([]byte(nil), b[4:8]...))
		b = b[8:]
	case atypIPv6:
		if len(b) < 22 {
			return nil, nil, fmt.Errorf("short IPv6 UDP header")
		}
		ip = net.IP(append([]byte(nil), b[4:20]...))
		b = b[20:]
	default:
		return nil, nil, fmt.Errorf("unsupported ATYP %d in UDP header", b[3])
	}
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("missing UDP port")
	}
	port := int(binary.BigEndian.Uint16(b[:2]))
	return &net.UDPAddr{IP: ip, Port: port}, b[2:], nil
}
