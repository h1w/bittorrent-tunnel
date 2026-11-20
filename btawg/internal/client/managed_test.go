package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
)

// errNoTunnel stands in for a transport tunnel the lifecycle test never dials.
var errNoTunnel = errors.New("no tunnel in lifecycle test")

// testManaged binds ten managed SOCKS listeners on a free consecutive port
// block so the test never collides with real services.
func testManaged(t *testing.T, cfg config.ClientConfig) *managed {
	t.Helper()
	for base := 21000; base < 40000; base += 10 {
		m, err := newManaged(context.Background(), cfg, netip.MustParseAddr("127.0.0.1"), base)
		if err == nil {
			t.Cleanup(func() { m.Close() })
			return m
		}
	}
	t.Fatal("no free managed port block")
	return nil
}

func TestManagedReservesDisabledPortsAndRotatesAuth(t *testing.T) {
	cfg := config.ClientConfig{ClientIP: "10.77.0.2", ServerIP: "10.77.0.1", Subnet: "10.77.0.0/24"}
	m := testManaged(t, cfg)
	m.SetProxy(config.ModeWG, ModeProxy{TCP: func(context.Context, netip.AddrPort) (net.Conn, error) {
		return nil, errNoTunnel
	}})
	auth := Credentials{Username: "operator", Password: "before"}
	if err := m.Apply([]string{config.ModeWG}, auth); err != nil {
		t.Fatal(err)
	}

	main, unused := m.slots[5].ln.Addr().String(), m.slots[0].ln.Addr().String()
	if l, err := net.Listen("tcp4", unused); err == nil {
		l.Close()
		t.Fatal("a disabled managed port was not reserved")
	}
	if _, err := proxyAuth(t, unused, auth); err == nil {
		t.Fatal("a disabled managed port accepted authentication")
	}

	c, err := proxyAuth(t, main, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	after := Credentials{Username: "operator", Password: "after"}
	if err := m.Apply([]string{config.ModeWG}, after); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("credential rotation kept an old session open")
	}
	if _, err := proxyAuth(t, main, auth); err == nil {
		t.Fatal("old credentials were still accepted after rotation")
	}
	c2, err := proxyAuth(t, main, after)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()

	if err := m.Apply(nil, after); err != nil {
		t.Fatal(err)
	}
	if l, err := net.Listen("tcp4", main); err == nil {
		l.Close()
		t.Fatal("disabling a mode released its fixed port")
	}
}

// proxyAuth negotiates RFC 1929 authentication and returns the live
// connection parked before any SOCKS request.
func proxyAuth(t *testing.T, addr string, auth Credentials) (_ net.Conn, err error) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = c.Write([]byte{5, 1, 2}); err != nil {
		return nil, err
	}
	var r [2]byte
	if _, err = io.ReadFull(c, r[:]); err != nil {
		return nil, err
	}
	if r != [2]byte{5, 2} {
		return nil, io.ErrUnexpectedEOF
	}
	b := append([]byte{1, byte(len(auth.Username))}, auth.Username...)
	b = append(append(b, byte(len(auth.Password))), auth.Password...)
	if _, err = c.Write(b); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(c, r[:]); err != nil {
		return nil, err
	}
	if r != [2]byte{1, 0} {
		return nil, io.ErrUnexpectedEOF
	}
	return c, nil
}
