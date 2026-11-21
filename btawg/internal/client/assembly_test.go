package client

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
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
		Credentials{Username: "op", Password: "pw"}, false, "btawg", 0, nil)
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

func TestManagedSingleTUN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires network administration; run with unshare -Urn")
	}
	const name = "btawg-single"
	for _, args := range [][]string{
		{"tuntap", "add", "dev", name, "mode", "tun", "vnet_hdr"},
		{"addr", "add", "10.77.0.2/24", "dev", name},
		{"link", "set", "dev", name, "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("setup legacy device: %v: %s", err, out)
		}
	}
	t.Cleanup(func() { _ = exec.Command("ip", "tuntap", "del", "dev", name, "mode", "tun").Run() })
	legacy, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	modes := []string{config.ModeAWG, config.ModeWG}
	auth := Credentials{Username: "op", Password: "pw"}
	m, err := newManagedAt(context.Background(), managedCfg(t), modes, netip.MustParseAddr("127.0.0.1"), auth, true, name, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	check := func(want *net.Interface) *net.Interface {
		t.Helper()
		ifaces, err := net.Interfaces()
		if err != nil {
			t.Fatal(err)
		}
		for _, iface := range ifaces {
			if strings.HasPrefix(iface.Name, name+"-") {
				t.Errorf("unexpected per-transport interface %s", iface.Name)
			}
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if iface.Flags&net.FlagRunning == 0 {
			t.Fatalf("%s has no carrier", name)
		}
		if want != nil && iface.Index != want.Index {
			t.Fatalf("toggle recreated %s: index %d, want %d", name, iface.Index, want.Index)
		}
		addrs, err := iface.Addrs()
		if err != nil || !slices.ContainsFunc(addrs, func(a net.Addr) bool { return a.String() == "10.77.0.2/24" }) {
			t.Fatalf("%s addresses = %v (%v), want 10.77.0.2/24", name, addrs, err)
		}
		if out, err := exec.Command("ip", "-4", "route", "get", "10.77.0.1", "oif", name).CombinedOutput(); err != nil {
			t.Fatalf("route to gateway: %v: %s", err, out)
		}
		return iface
	}
	iface := check(legacy)
	for _, enabled := range [][]string{{config.ModeWG}, nil, modes} {
		if err := m.Apply(enabled, auth); err != nil {
			t.Fatal(err)
		}
		check(iface)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("%s still exists after daemon stopped", name)
	}
}

func TestManagedRejectsForeignTUNState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires network administration; run with unshare -Urn")
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"extra IPv4", []string{"addr", "add", "10.77.0.3/24", "dev", "btawg-foreign"}},
		{"foreign route", []string{"route", "add", "192.0.2.0/24", "dev", "btawg-foreign"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const name = "btawg-foreign"
			for _, args := range [][]string{
				{"tuntap", "add", "dev", name, "mode", "tun", "vnet_hdr"},
				{"addr", "add", "10.77.0.2/24", "dev", name},
				{"link", "set", "dev", name, "up"}, tc.args,
			} {
				if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
					t.Fatalf("setup existing TUN: %v: %s", err, out)
				}
			}
			t.Cleanup(func() { _ = exec.Command("ip", "tuntap", "del", "dev", name, "mode", "tun").Run() })
			m, err := newManagedAt(context.Background(), managedCfg(t), []string{config.ModeWG}, netip.MustParseAddr("127.0.0.1"), Credentials{Username: "op", Password: "pw"}, true, name, 0, nil)
			if err == nil {
				m.Close()
				t.Fatal("took ownership of an interface with foreign state")
			}
			if _, err := net.InterfaceByName(name); err != nil {
				t.Fatal("failed startup removed the existing TUN:", err)
			}
		})
	}
}
