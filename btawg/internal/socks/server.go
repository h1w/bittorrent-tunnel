// Package socks implements the client-side SOCKS5 proxy (CONNECT and UDP
// ASSOCIATE) and helpers for applications speaking to it.
package socks

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
)

// DialFunc dials one TCP connection to the destination.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialUDPFunc returns an upstream UDP socket through which the caller sends
// raw datagrams to arbitrary destinations and receives raw datagrams back.
type DialUDPFunc func(ctx context.Context) (net.PacketConn, error)

// Server is a SOCKS5 server with optional RFC 1929 authentication.
type Server struct {
	dial               DialFunc
	dialUDP            DialUDPFunc
	resolveUDP         func(context.Context, netip.Addr, string) (netip.Addr, error)
	selectUpstream     func() (*Server, context.Context)
	greetingMethod     byte
	username, password []byte
}

// NewServer builds a local SOCKS5 server with the given upstream dialers.
func NewServer(dial DialFunc, dialUDP DialUDPFunc) *Server {
	return &Server{dial: dial, dialUDP: dialUDP}
}

// NewBalancer admits SOCKS requests using its own credentials, then selects
// one upstream for the whole TCP connection or UDP association.
func NewBalancer(selectUpstream func() (*Server, context.Context)) *Server {
	return &Server{selectUpstream: selectUpstream}
}

// WithCredentials requires username/password authentication on this server.
// Configure it before accepting connections. Empty credentials fail closed.
func (s *Server) WithCredentials(username, password string) *Server {
	s.greetingMethod = 2
	s.username, s.password = []byte(username), []byte(password)
	return s
}

// WithUDPResolver handles both IP literals and domain targets for UDP.
func (s *Server) WithUDPResolver(resolve func(context.Context, netip.Addr, string) (netip.Addr, error)) *Server {
	s.resolveUDP = resolve
	return s
}

// ServeConn handles one accepted SOCKS5 session. It owns c until the
// session ends and closes it when ctx is canceled.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) {
	s.handle(ctx, c)
}

// Serve accepts SOCKS5 connections on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
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
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if !s.serveGreeting(c) {
		return
	}
	cmd, dst, err := readRequest(c)
	if err != nil {
		writeReply(c, replyGeneralFailure)
		return
	}
	if s.selectUpstream != nil && (cmd == cmdConnect || cmd == cmdUDPAssociate) {
		upstream, life := s.selectUpstream()
		if upstream == nil || life.Err() != nil {
			writeReply(c, replyHostUnreachable)
			return
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(life, cancel)
		defer stop()
		closeConn := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer closeConn()
		s = upstream
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
	if s.dialUDP == nil {
		writeReply(c, replyCommandUnsupported)
		return
	}
	peer, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		writeReply(c, replyGeneralFailure)
		return
	}
	relay, err := listenUDPFor(c.LocalAddr())
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
	s.pumpUDP(ctx, relay, upstream, c, peer.AddrPort().Addr().Unmap())
}

func (s *Server) pumpUDP(ctx context.Context, relay *net.UDPConn, upstream net.PacketConn, ctrl net.Conn, peer netip.Addr) {
	type association struct{ addr netip.AddrPort }
	var appAddr atomic.Pointer[association]
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() {
		_ = ctrl.Close()
		_ = relay.Close()
		_ = upstream.Close()
	})
	defer stop()
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		cancel()
	}()
	go func() {
		defer cancel()
		buf := make([]byte, 65536)
		for {
			n, src, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			app := appAddr.Load()
			if app == nil {
				continue
			}
			m := append(buildUDPHeader(src), buf[:n]...)
			if _, err := relay.WriteToUDPAddrPort(m, app.addr); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, app, err := relay.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		app = netip.AddrPortFrom(app.Addr().Unmap(), app.Port())
		if app.Addr() != peer {
			continue
		}
		if last := appAddr.Load(); last != nil && last.addr != app {
			continue
		}
		dst, data, err := parseUDPTarget(buf[:n])
		if err != nil || dst.port == 0 {
			continue
		}
		ip := dst.ip
		if s.resolveUDP != nil {
			ip, err = s.resolveUDP(ctx, ip, dst.host)
		}
		if err != nil || !ip.IsValid() {
			continue
		}
		if appAddr.Load() == nil {
			appAddr.Store(&association{app})
		}
		// A failed DNS lookup or unreachable destination is per datagram.
		_, _ = upstream.WriteTo(data, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, dst.port)))
	}
}

// serveGreeting selects only the configured method, even if a client offers
// both no authentication and RFC 1929 authentication.
func (s *Server) serveGreeting(c net.Conn) bool {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != socksVersion {
		return false
	}
	var methods [255]byte
	if _, err := io.ReadFull(c, methods[:hdr[1]]); err != nil {
		return false
	}
	for _, m := range methods[:hdr[1]] {
		if m == s.greetingMethod {
			_, err := c.Write([]byte{socksVersion, m})
			return err == nil && (m == 0 || s.authenticate(c))
		}
	}
	_, _ = c.Write([]byte{socksVersion, 0xff})
	return false
}

func (s *Server) authenticate(c net.Conn) bool {
	var hdr [2]byte
	var user, pass [255]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 1 || hdr[1] == 0 {
		return false
	}
	username := user[:hdr[1]]
	if _, err := io.ReadFull(c, username); err != nil {
		return false
	}
	if _, err := io.ReadFull(c, hdr[:1]); err != nil || hdr[0] == 0 {
		return false
	}
	password := pass[:hdr[0]]
	if _, err := io.ReadFull(c, password); err != nil {
		return false
	}
	match := subtle.ConstantTimeCompare(username, s.username) & subtle.ConstantTimeCompare(password, s.password)
	_, err := c.Write([]byte{1, byte(1 - match)})
	return err == nil && match == 1
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

type udpTarget struct {
	ip   netip.Addr
	host string
	port uint16
}

// parseUDPTarget splits the header from the payload. SOCKS fragmentation is
// not supported; domain targets remain names until the caller resolves them.
func parseUDPTarget(b []byte) (udpTarget, []byte, error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return udpTarget{}, nil, fmt.Errorf("invalid SOCKS UDP header")
	}
	atyp := b[3]
	b = b[4:]
	var dst udpTarget
	switch atyp {
	case atypIPv4:
		if len(b) < 4 {
			return udpTarget{}, nil, io.ErrUnexpectedEOF
		}
		dst.ip, b = netip.AddrFrom4([4]byte(b[:4])), b[4:]
	case atypIPv6:
		if len(b) < 16 {
			return udpTarget{}, nil, io.ErrUnexpectedEOF
		}
		dst.ip, b = netip.AddrFrom16([16]byte(b[:16])).Unmap(), b[16:]
	case atypDomain:
		if len(b) == 0 || b[0] == 0 || len(b) < 1+int(b[0]) {
			return udpTarget{}, nil, io.ErrUnexpectedEOF
		}
		end := 1 + int(b[0])
		dst.host, b = string(b[1:end]), b[end:]
	default:
		return udpTarget{}, nil, fmt.Errorf("unsupported UDP address type %d", atyp)
	}
	if len(b) < 2 {
		return udpTarget{}, nil, io.ErrUnexpectedEOF
	}
	dst.port = binary.BigEndian.Uint16(b[:2])
	return dst, b[2:], nil
}
