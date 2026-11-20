package client

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/socks"
)

func TestManagedReservesDisabledPortsAndRotatesAuth(t *testing.T) {
	m, err := newManaged(context.Background(), netip.MustParseAddr("127.0.0.1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	auth := Credentials{Username: "operator", Password: "before"}
	m.replace(5, socks.NewServer(nil, nil).WithCredentials(auth.Username, auth.Password))

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
	m.replace(5, socks.NewServer(nil, nil).WithCredentials(after.Username, after.Password))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("credential rotation kept an old session open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("credential rotation did not close the session")
	}
	if _, err := proxyAuth(t, main, auth); err == nil {
		t.Fatal("old credentials were still accepted after rotation")
	}
	c2, err := proxyAuth(t, main, after)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()

	m.replace(5, nil)
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
