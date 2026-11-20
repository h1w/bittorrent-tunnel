package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

func TestListenPanelBindsLoopbackAndGateway(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/panel.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.DefaultServerConfig()
	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	listeners, err := srv.ListenPanel(context.Background(), 18080)
	if err != nil {
		t.Fatalf("ListenPanel: %v", err)
	}
	if len(listeners) != 2 {
		t.Fatalf("listeners = %d, want 2", len(listeners))
	}
	for _, ln := range listeners {
		defer ln.Close()
	}

	// Serve a simple handler on both listeners.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	for _, ln := range listeners {
		go func(l net.Listener) {
			_ = http.Serve(l, handler)
		}(ln)
	}

	// Verify loopback is reachable.
	loopAddr := listeners[0].Addr().String()
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
	gatewayAddr := listeners[1].Addr()
	ap := gatewayAddr.(*net.TCPAddr).AddrPort()
	if ap.Addr() != netip.MustParseAddr("10.77.0.1") {
		t.Fatalf("gateway addr = %s, want 10.77.0.1", ap.Addr())
	}

	// Reach the gateway listener from inside the overlay netstack.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err = client.Get("http://" + gatewayAddr.String())
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("gateway body = %q", body)
	}
}
