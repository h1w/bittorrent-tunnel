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
	m, err := newManagedAt(context.Background(), cfg,
		[]string{config.ModeWG, config.ModeAWG}, netip.MustParseAddr("127.0.0.1"),
		Credentials{Username: "op", Password: "pw"}, false, "btawg", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	addr := m.inbound.slots[4].ln.Addr().String()
	creds := Credentials{Username: "op", Password: "pw"}
	if c, err := proxyAuth(t, addr, creds); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}

	// Disable AWG: its tunnel goes away but its fixed port stays reserved.
	if err := m.Apply([]string{config.ModeWG}, Credentials{Username: "op", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	if c, err := proxyAuth(t, addr, creds); err == nil {
		c.Close()
		t.Fatal("disabled AWG still accepting SOCKS authentication")
	}
	if c, err := proxyAuth(t, m.inbound.slots[5].ln.Addr().String(), creds); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
	if l, err := net.Listen("tcp4", addr); err == nil {
		l.Close()
		t.Fatal("disabled AWG port was released")
	}

	// Re-enable AWG: tunnel returns.
	if err := m.Apply([]string{config.ModeWG, config.ModeAWG}, Credentials{Username: "op", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	if c, err := proxyAuth(t, addr, creds); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
}
