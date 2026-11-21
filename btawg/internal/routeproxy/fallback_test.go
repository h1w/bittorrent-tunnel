package routeproxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/socks"
)

func testAttempt(t *testing.T, ln net.Listener, want Request, status []byte) {
	t.Helper()
	withinTest(t, func(ctx context.Context) error {
		stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
		defer stop()
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		got, _, err := ReadInvocation(c)
		if err == nil && got != want {
			t.Errorf("primary got route %+v, want %+v", got, want)
		}
		if err != nil || len(status) == 0 {
			return err
		}
		if status[0] == 255 {
			// The direct connection carries the invocation but no reply.
			// The shorter transport budget must close it before hub fallback.
			var b [1]byte
			if _, err := c.Read(b[:]); err != io.EOF {
				t.Errorf("unacknowledged attempt did not close: %v", err)
			}
			return nil
		}
		if status[0] == 2 {
			if _, err := c.Write(status[:1]); err != nil {
				return err
			}
			var confirm [1]byte
			if _, err := io.ReadFull(c, confirm[:]); err != nil {
				return err
			}
			if confirm[0] != 3 {
				t.Errorf("unexpected invocation confirmation: %v", confirm)
			}
			status = status[1:]
		}
		if len(status) == 0 {
			return nil
		}
		_, err = c.Write(status)
		return err
	})
}

func TestOriginRouteFallbackOnlyBeforeStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   []byte
		wantDial int32
		wantOK   bool
	}{
		{"unacknowledged", nil, 1, true},
		{"unacknowledged-stall", []byte{255}, 1, true},
		{"refused", []byte{1}, 0, false},
		{"acknowledged-closed", []byte{2}, 0, false},
		{"acknowledged-refused", []byte{2, 1}, 0, false},
		{"ready", []byte{2, 0}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			primary, backup, local := listenTCP(t), listenTCP(t), listenTCP(t)
			testAttempt(t, primary, route, tc.status)
			withinTest(t, func(ctx context.Context) error {
				return serve(ctx, backup, authorizeTest("127.0.0.3", 0, Decision{Life: ctx}), exitPolicy{
					allow: func(ip netip.Addr) bool { return ip == loop },
				})
			})
			var dials atomic.Int32
			withinTest(t, func(ctx context.Context) error {
				p := ProxyWithFallback(via(primary, "127.0.0.2"), func(ctx context.Context, req Request) (net.Conn, error) {
					dials.Add(1)
					if req != route {
						t.Errorf("fallback changed request: %+v", req)
					}
					return via(backup, "127.0.0.3")(ctx, req)
				}, route)
				return p.Serve(ctx, local)
			})
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(echoTCP(t))))
			c, err := socks.NewClient(local.Addr().String()).Dial(t.Context(), "tcp", addr)
			if (err == nil) != tc.wantOK {
				t.Fatalf("CONNECT: %v", err)
			}
			if c != nil {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var b [4]byte
				if tc.wantDial != 0 {
					if _, err := io.WriteString(c, "echo"); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(c, b[:]); err != nil || string(b[:]) != "echo" {
						t.Fatalf("fallback echo: %q (%v)", b[:], err)
					}
				} else if _, err := c.Read(b[:]); err == nil {
					t.Fatal("acknowledged attempt unexpectedly delivered data")
				}
			}
			if got := dials.Load(); got != tc.wantDial {
				t.Fatalf("fallback dials = %d, want %d", got, tc.wantDial)
			}
		})
	}
}

func TestTransitRouteFallbackKeepsHopAndGrant(t *testing.T) {
	transit, primary, backup, local := listenTCP(t), listenTCP(t), listenTCP(t), listenTCP(t)
	want := route
	want.Hop = 1
	testAttempt(t, primary, want, nil)
	withinTest(t, func(ctx context.Context) error {
		return Serve(ctx, backup, authorizeTest("127.0.0.3", 1, Decision{Life: ctx}))
	})
	withinTest(t, func(ctx context.Context) error {
		return Serve(ctx, transit, authorizeTest("127.0.0.2", 0, Decision{
			Next: via(primary, "127.0.0.3"), Fallback: via(backup, "127.0.0.3"), Life: ctx,
		}))
	})
	withinTest(t, func(ctx context.Context) error {
		return Proxy(via(transit, "127.0.0.2"), route).Serve(ctx, local)
	})
	u, err := socks.NewClient(local.Addr().String()).DialUDP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
}

func TestBoundConnectionClosesOnPathRetirement(t *testing.T) {
	ln := listenTCP(t)
	c, err := via(ln, "127.0.0.2")(t.Context(), route)
	if err != nil {
		t.Fatal(err)
	}
	life, retire := context.WithCancel(t.Context())
	defer retire()
	bound := BindConn(life, c)
	defer bound.Close()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(bound, "a"); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(peer, b[:]); err != nil || b[0] != 'a' {
		t.Fatalf("active path lost data: %q (%v)", b[:], err)
	}
	retire()
	if _, err := peer.Read(b[:]); err != io.EOF {
		t.Fatalf("retired path did not close the peer: %v", err)
	}
}
