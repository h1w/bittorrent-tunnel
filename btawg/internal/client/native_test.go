package client

import (
	"context"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
)

// TestNativeAWGNetstack builds an AWG native client in userspace mode and
// verifies the local SOCKS5 listener comes up. No hub is required: the
// device is brought Up with the direct endpoint configuration.
func TestNativeAWGNetstack(t *testing.T) {
	cfg := config.ClientConfig{
		Version:       config.ClientVersion,
		ServerPubKey:  "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		ClientPrivKey: "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00",
		ClientPubKey:  "44556677889900aabbccddeeff0011223344556677889900aabbccddeeff00",
		ClientIP:      "10.77.0.2",
		Subnet:        "10.77.0.0/24",
		ServerIP:      "10.77.0.1",
		Transport:     config.ModeAWG,
		SocksPort:     0,
		AWGEndpoint:   "127.0.0.1:51821",
		Profile:       config.DefaultProfile(),
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New(native awg): %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()

	addr := ""
	deadline := time.Now().Add(2 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		addr = c.SocksAddr()
		if addr == "" {
			select {
			case err := <-runErr:
				t.Fatalf("Run exited early: %v", err)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if addr == "" {
		t.Fatal("native AWG client SOCKS5 never came up")
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}

// TestNativeWGNetstack does the same for canonical WireGuard mode.
func TestNativeWGNetstack(t *testing.T) {
	cfg := config.ClientConfig{
		Version:       config.ClientVersion,
		ServerPubKey:  "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		ClientPrivKey: "11223344556677889900aabbccddeeff0011223344556677889900aabbccdd00",
		ClientPubKey:  "44556677889900aabbccddeeff0011223344556677889900aabbccddeeff00",
		ClientIP:      "10.77.0.2",
		Subnet:        "10.77.0.0/24",
		ServerIP:      "10.77.0.1",
		Transport:     config.ModeWG,
		SocksPort:     0,
		WGEndpoint:    "127.0.0.1:51820",
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New(native wg): %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()

	addr := ""
	deadline := time.Now().Add(2 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		addr = c.SocksAddr()
		if addr == "" {
			select {
			case err := <-runErr:
				t.Fatalf("Run exited early: %v", err)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if addr == "" {
		t.Fatal("native WG client SOCKS5 never came up")
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}
