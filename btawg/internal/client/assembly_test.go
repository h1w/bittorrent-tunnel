package client

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/config"
)

// freePort returns a free UDP port for a native tunnel endpoint.
func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// freeBase finds ten free consecutive TCP ports and returns the first.
func freeBase(t *testing.T) int {
	t.Helper()
	for base := 23000; base < 40000; base += 10 {
		var ls []net.Listener
		ok := true
		for i := 0; i < 10; i++ {
			l, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(base+i)))
			if err != nil {
				ok = false
				break
			}
			ls = append(ls, l)
		}
		for _, l := range ls {
			l.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free managed port block")
	return 0
}

// managedCfg returns a config with real keys and loopback native endpoints so
// a netstack tunnel can be built without a hub.
func managedCfg(t *testing.T) config.ClientConfig {
	t.Helper()
	priv, pub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, serverPub, err := awg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.ClientConfig{
		Version:       config.ClientVersion,
		InfoHash:      "00112233445566778899aabbccddeeff00112233",
		ServerPubKey:  serverPub,
		ClientPrivKey: priv,
		ClientPubKey:  pub,
		ClientIP:      "10.77.0.2",
		Subnet:        "10.77.0.0/24",
		ServerIP:      "10.77.0.1",
		WGEndpoint:    net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))),
		AWGEndpoint:   net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))),
		Profile:       config.DefaultProfile(),
	}
	return cfg
}

func TestManagedTunnelsFollowEnabledSet(t *testing.T) {
	cfg := managedCfg(t)
	base := freeBase(t)
	m, err := newManagedAt(context.Background(), cfg,
		[]string{config.ModeWG, config.ModeAWG}, netip.MustParseAddr("127.0.0.1"),
		Credentials{Username: "op", Password: "pw"}, false, "btawg", base)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if got := len(m.tunnels); got != 2 {
		t.Fatalf("built %d tunnels, want 2", got)
	}
	if l, err := net.Listen("tcp4", m.slot(5).ln.Addr().String()); err == nil {
		l.Close()
		t.Fatal("WG slot listener was not reserved")
	}

	// Disable AWG: its tunnel goes away but its fixed port stays reserved.
	if err := m.Apply([]string{config.ModeWG}, Credentials{Username: "op", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	if m.hasTunnel(config.ModeAWG) {
		t.Fatal("AWG tunnel still live after disable")
	}
	if !m.hasTunnel(config.ModeWG) {
		t.Fatal("WG tunnel missing after sibling disabled")
	}
	if l, err := net.Listen("tcp4", m.slot(4).ln.Addr().String()); err == nil {
		l.Close()
		t.Fatal("disabled AWG port was released")
	}

	// Re-enable AWG: tunnel returns.
	if err := m.Apply([]string{config.ModeWG, config.ModeAWG}, Credentials{Username: "op", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	if !m.hasTunnel(config.ModeAWG) {
		t.Fatal("AWG tunnel did not return after re-enable")
	}
}
