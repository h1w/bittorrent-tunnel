package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

// freeTCPPort and freeUDPPort return ephemeral ports so the hub's fixed
// service ports do not collide with other packages running in parallel.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func TestListenPanelBindsLoopbackAndGateway(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/panel.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SaveGroup(store.GroupRecord{ID: "aaa", Name: "Another group", Subnet: "10.78.0.0/24", ServerIP: "10.78.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveGroup(store.GroupRecord{ID: store.DefaultGroupID, Name: "Default", Subnet: "10.90.0.0/24", ServerIP: "10.90.0.7"}); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultServerConfig()
	cfg.CarrierPort = freeTCPPort(t)
	cfg.AWGPort = freeUDPPort(t)
	cfg.WGPort = freeUDPPort(t)
	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })}
	defer web.Close()
	if _, err := srv.StartPanel(context.Background(), 0, web); err != nil {
		t.Fatal(err)
	}

	// Verify loopback is reachable.
	loopAddr := srv.panel.loopback.Addr().String()
	resp, err := http.Get("http://" + loopAddr)
	if err != nil {
		t.Fatalf("loopback request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("loopback body = %q", body)
	}

	// Verify gateway listener is on the VPN address, not 0.0.0.0.
	gatewayAddr := srv.panel.vpn.Addr()
	ap := gatewayAddr.(*net.TCPAddr).AddrPort()
	if ap.Addr() != netip.MustParseAddr("10.90.0.7") {
		t.Fatalf("gateway addr = %s, want 10.90.0.7", ap.Addr())
	}

	// Reach the gateway listener from inside the overlay netstack.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := srv.OverlayNet().DialContextTCPAddrPort(ctx, ap)
	if err != nil {
		t.Fatalf("gateway dial: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", gatewayAddr.String()); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	body, err = io.ReadAll(conn)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("gateway body = %q", body)
	}
}

func TestPanelFollowsDefaultGroupGatewayOnReload(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/panel.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	group := store.GroupRecord{ID: store.DefaultGroupID, Name: "Default", Subnet: "127.8.0.0/24", ServerIP: "127.8.0.7"}
	if err := st.SaveGroup(group); err != nil {
		t.Fatal(err)
	}
	// Linux already routes 127/8 through lo; use real HTTP sockets without
	// changing host routes or requiring the TUN/NAT setup.
	srv := &Server{st: st, tunName: "lo", policy: newPolicySnapshot(), closed: make(chan struct{})}
	defer srv.Close()
	web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "panel") })}
	defer web.Close()
	if _, err := srv.StartPanel(context.Background(), 0, web); err != nil {
		t.Fatal(err)
	}
	port := srv.panel.loopback.Addr().(*net.TCPAddr).Port
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
	get := func(host string) error {
		r, err := client.Get("http://" + net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return err
		}
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		if string(body) != "panel" {
			return fmt.Errorf("unexpected response %q", body)
		}
		return nil
	}
	for _, host := range []string{"127.0.0.1", group.ServerIP} {
		if err := get(host); err != nil {
			t.Fatalf("initial panel on %s: %v", host, err)
		}
	}
	old := group.ServerIP
	group.ServerIP = "127.8.0.9"
	if err := st.SaveGroup(group); err != nil {
		t.Fatal(err)
	}
	if err := srv.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	if err := get(group.ServerIP); err != nil {
		t.Fatalf("panel on new gateway: %v", err)
	}
	if err := get("127.0.0.1"); err != nil {
		t.Fatalf("panel on loopback after reload: %v", err)
	}
	if err := get(old); err == nil {
		t.Fatal("panel still accepts connections on the old gateway")
	}
}
