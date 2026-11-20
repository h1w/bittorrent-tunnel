package iptunnel

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPinnedMutualTLS(t *testing.T) {
	hub, err := NewIdentity(strings.Repeat("01", 32), Hub)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewIdentity(strings.Repeat("02", 32), Client)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewIdentity(strings.Repeat("03", 32), Client)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		pin       string
		enrolled  string
		clientErr bool
		serverErr bool
	}{
		{"matched", hub.Pin(), client.Pin(), false, false},
		{"wrong hub", other.Pin(), client.Pin(), true, true},
		{"wrong client", hub.Pin(), other.Pin(), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			a, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			cfg, err := client.TLS(tc.pin)
			if err != nil {
				t.Fatal(err)
			}
			srv, err := hub.TLS(tc.enrolled)
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			done := make(chan error, 1)
			go func() { done <- tls.Server(b, srv).HandshakeContext(ctx); b.Close() }()
			ce := tls.Client(a, cfg).HandshakeContext(ctx)
			if (ce != nil) != tc.clientErr && tc.name != "wrong client" {
				t.Errorf("client handshake: %v", ce)
			}
			se := <-done
			if (se != nil) != tc.serverErr || (tc.name == "wrong client" && se.Error() != "unexpected TLS peer key") {
				t.Errorf("server handshake: %v", se)
			}
		})
	}
}

func TestReadIPPacketPreservesBoundaries(t *testing.T) {
	first := []byte("\x45\x00\x00\x15" + strings.Repeat("\x00", 16) + "x")
	second := []byte("\x45\x00\x00\x16" + strings.Repeat("\x00", 16) + "yz")
	r := strings.NewReader(string(first) + string(second))
	var buf [MTU]byte
	for _, want := range [][]byte{first, second} {
		got, err := ReadPacket(r, buf[:])
		if err != nil || string(got) != string(want) {
			t.Fatalf("packet = %x, %v; want %x", got, err, want)
		}
	}
	if _, err := ReadPacket(strings.NewReader("\x45\x00\xff\xff"+strings.Repeat("\x00", 16)), buf[:]); err == nil {
		t.Fatal("oversized packet accepted")
	}
}
