package socks

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestPasswordAuth(t *testing.T) {
	for _, tc := range []struct {
		name, user, pass string
		methods          []byte
		want             byte
	}{
		{"no auth refused", "", "", []byte{0}, 0xff},
		{"password preferred", "operator", "a-secret", []byte{0, 2}, 0},
		{"wrong username", "other", "a-secret", []byte{2}, 1},
		{"wrong password", "operator", "not-it", []byte{2}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := NewServer(nil, nil).WithCredentials("operator", "a-secret")
			x, y := net.Pipe()
			defer y.Close()
			y.SetDeadline(time.Now().Add(time.Second))
			done := make(chan struct{})
			go func() { defer close(done); server.handle(context.Background(), x) }()
			defer func() { y.Close(); <-done }()
			write := func(b []byte) {
				if _, err := y.Write(b); err != nil {
					t.Fatal(err)
				}
			}
			read := func(a, b byte) {
				var r [2]byte
				if _, err := io.ReadFull(y, r[:]); err != nil || r != [2]byte{a, b} {
					t.Fatalf("reply %x, want %02x%02x: %v", r, a, b, err)
				}
			}
			write(append([]byte{5, byte(len(tc.methods))}, tc.methods...))
			if tc.want == 0xff {
				read(5, 0xff)
				return
			}
			read(5, 2)
			request := append([]byte{1, byte(len(tc.user))}, tc.user...)
			request = append(append(request, byte(len(tc.pass))), tc.pass...)
			write(request)
			read(1, tc.want)
			if tc.want != 0 {
				return
			}
			write([]byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80})
			var r [10]byte
			if _, err := io.ReadFull(y, r[:]); err != nil || r[1] != 7 {
				t.Fatalf("authenticated request reply %x: %v", r, err)
			}
		})
	}
}
