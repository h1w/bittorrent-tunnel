package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Client chains SOCKS5 commands to a remote no-auth SOCKS5 server. Dial
// satisfies DialFunc, so a local Server can use the Client as its egress.
type Client struct {
	remote    string
	dialTCP   func(ctx context.Context, addr string) (net.Conn, error)
	listenUDP func(ctx context.Context) (net.PacketConn, error)
}

// NewClient returns a chaining client for the remote server address
// (e.g. 10.77.0.1:1080) using the host's network stack.
func NewClient(remote string) *Client {
	return &Client{
		remote: remote,
		dialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		listenUDP: func(ctx context.Context) (net.PacketConn, error) {
			return net.ListenUDP("udp", nil)
		},
	}
}

// WithTransport replaces how the chain reaches the remote SOCKS5 server.
// btawg's netstack-mode client passes overlay dialers here; the real-TUN
// client keeps the kernel defaults (routes carry the overlay traffic).
func (c *Client) WithTransport(dialTCP func(ctx context.Context, addr string) (net.Conn, error), listenUDP func(ctx context.Context) (net.PacketConn, error)) *Client {
	if dialTCP != nil {
		c.dialTCP = dialTCP
	}
	if listenUDP != nil {
		c.listenUDP = listenUDP
	}
	return c
}

// Dial connects to the remote server, performs the SOCKS5 handshake and a
// CONNECT for addr, and returns the established stream.
func (c *Client) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := c.dialTCP(ctx, c.remote)
	if err != nil {
		return nil, fmt.Errorf("socks chain dial %s: %w", c.remote, err)
	}
	if err := handshake(conn, cmdConnect, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialUDP performs UDP ASSOCIATE on the remote server and returns a
// PacketConn whose WriteTo wraps datagrams in SOCKS5 UDP headers toward the
// remote relay and whose ReadFrom unwraps responses.
func (c *Client) DialUDP(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.dialTCP(ctx, c.remote)
	if err != nil {
		return nil, fmt.Errorf("socks chain dial %s: %w", c.remote, err)
	}
	relayAddr, err := udpAssociate(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	pc, err := c.listenUDP(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &udpChain{pc: pc, dst: relayAddr, ctrl: conn}, nil
}

// handshake performs the no-auth greeting and one command on conn.
func handshake(conn net.Conn, cmd byte, addr string) error {
	if _, err := conn.Write([]byte{socksVersion, 1, 0x00}); err != nil {
		return fmt.Errorf("socks greeting: %w", err)
	}
	var gr [2]byte
	if _, err := io.ReadFull(conn, gr[:]); err != nil {
		return fmt.Errorf("socks greeting reply: %w", err)
	}
	if gr[0] != socksVersion || gr[1] != 0x00 {
		return fmt.Errorf("socks server refused no-auth (method 0x%02x)", gr[1])
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socks addr: %w", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return fmt.Errorf("socks port: %w", err)
	}
	ip := net.ParseIP(host)
	req := []byte{socksVersion, cmd, 0}
	if v4 := ip.To4(); ip != nil && v4 != nil {
		req = append(req, atypIPv4)
		req = append(req, v4...)
	} else if ip != nil {
		req = append(req, atypIPv6)
		req = append(req, ip.To16()...)
	} else {
		return fmt.Errorf("socks chain requires IP destinations, got %q", host)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	req = append(req, p[:]...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks request: %w", err)
	}
	rep, err := readReply(conn)
	if err != nil {
		return err
	}
	if rep != replySucceeded {
		return fmt.Errorf("socks command failed: reply 0x%02x", rep)
	}
	return nil
}

// readReply consumes a SOCKS5 reply and returns its REP field.
func readReply(conn net.Conn) (byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return 0, fmt.Errorf("socks reply: %w", err)
	}
	if head[0] != socksVersion {
		return 0, fmt.Errorf("bad reply version %d", head[0])
	}
	ipLen := 4
	if head[3] == atypIPv6 {
		ipLen = 16
	}
	if _, err := io.ReadFull(conn, make([]byte, ipLen+2)); err != nil {
		return 0, fmt.Errorf("socks reply addr: %w", err)
	}
	return head[1], nil
}

// udpAssociate performs UDP ASSOCIATE and returns the remote relay address.
func udpAssociate(conn net.Conn) (*net.UDPAddr, error) {
	if _, err := conn.Write([]byte{socksVersion, 1, 0x00}); err != nil {
		return nil, fmt.Errorf("socks greeting: %w", err)
	}
	var gr [2]byte
	if _, err := io.ReadFull(conn, gr[:]); err != nil {
		return nil, fmt.Errorf("socks greeting reply: %w", err)
	}
	if gr[0] != socksVersion || gr[1] != 0x00 {
		return nil, fmt.Errorf("socks server refused no-auth")
	}
	if _, err := conn.Write([]byte{socksVersion, cmdUDPAssociate, 0, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("socks udp associate: %w", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, fmt.Errorf("socks udp reply: %w", err)
	}
	if head[0] != socksVersion || head[1] != replySucceeded {
		return nil, fmt.Errorf("socks udp associate rejected: 0x%02x", head[1])
	}
	ipLen := 4
	if head[3] == atypIPv6 {
		ipLen = 16
	}
	body := make([]byte, ipLen+2)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("socks udp reply addr: %w", err)
	}
	ip := net.IP(append([]byte(nil), body[:ipLen]...))
	port := int(binary.BigEndian.Uint16(body[ipLen:]))
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

// udpChain is the PacketConn a chained UDP ASSOCIATE returns: it wraps
// outbound datagrams in SOCKS5 UDP headers toward the remote relay and
// unwraps inbound datagrams. Closing it tears down the control connection.
type udpChain struct {
	pc   net.PacketConn
	dst  *net.UDPAddr
	ctrl net.Conn
}

func (u *udpChain) WriteTo(b []byte, addr net.Addr) (int, error) {
	m := append(buildUDPHeader(addr), b...)
	if _, err := u.pc.WriteTo(m, u.dst); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (u *udpChain) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65536)
	n, _, err := u.pc.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	src, data, err := parseUDPHeader(buf[:n])
	if err != nil {
		return 0, nil, err
	}
	copy(b, data)
	return len(data), src, nil
}

func (u *udpChain) LocalAddr() net.Addr { return u.pc.LocalAddr() }
func (u *udpChain) Close() error {
	u.pc.Close()
	return u.ctrl.Close()
}
func (u *udpChain) SetDeadline(t time.Time) error      { return u.pc.SetDeadline(t) }
func (u *udpChain) SetReadDeadline(t time.Time) error  { return u.pc.SetReadDeadline(t) }
func (u *udpChain) SetWriteDeadline(t time.Time) error { return u.pc.SetWriteDeadline(t) }
