package client

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
)

func dialControlRetry(t *testing.T, path string) *Control {
	t.Helper()
	for range 150 {
		c, err := DialControl(path)
		if err == nil {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("control socket never appeared")
	return nil
}

func TestDaemonControlToggleRotatePersist(t *testing.T) {
	base := managedCfg(t)
	importStr, err := base.ImportString()
	if err != nil {
		t.Fatal(err)
	}
	cfg := ManagedConfig{
		Import:      importStr,
		Enabled:     []string{config.ModeWG},
		ListenIP:    "127.0.0.1",
		Credentials: Credentials{Username: "first", Password: "secret"},
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.json")
	sockPath := filepath.Join(dir, "control.sock")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runManagedAt(ctx, cfg, cfgPath, sockPath, false, "btawg") }()

	ctl := dialControlRetry(t, sockPath)
	defer ctl.Close()

	// Initial state: WG enabled on its fixed port.
	r, err := ctl.Do(ControlRequest{Op: "status"})
	if err != nil || !r.OK {
		t.Fatalf("status: %+v %v", r, err)
	}
	if !enabledHas(r.Enabled, config.ModeWG) || len(r.Modes) != len(config.ClientModes()) {
		t.Fatalf("status state = %+v", r)
	}
	if got := r.Modes[5].Port; got != ManagedPortBase+5 {
		t.Fatalf("WG port = %d, want %d", got, ManagedPortBase+5)
	}

	// Live toggle: switch to AWG. It persists and reflects immediately.
	r, err = ctl.Do(ControlRequest{Op: "apply", Enabled: []string{config.ModeAWG}})
	if err != nil || !r.OK {
		t.Fatalf("apply: %+v %v", r, err)
	}
	if enabledHas(r.Enabled, config.ModeWG) || !enabledHas(r.Enabled, config.ModeAWG) {
		t.Fatalf("apply state = %+v", r.Enabled)
	}
	saved := loadSaved(t, cfgPath)
	if !enabledHas(saved.Enabled, config.ModeAWG) || enabledHas(saved.Enabled, config.ModeWG) {
		t.Fatalf("persisted enabled = %v", saved.Enabled)
	}

	// Rotation: new pair replaces the old and is persisted.
	r, err = ctl.Do(ControlRequest{Op: "rotate"})
	if err != nil || !r.OK || r.Credentials == nil {
		t.Fatalf("rotate: %+v %v", r, err)
	}
	if *r.Credentials == (Credentials{Username: "first", Password: "secret"}) {
		t.Fatal("rotate returned the old credentials")
	}
	if got := loadSaved(t, cfgPath).Credentials; got != *r.Credentials {
		t.Fatalf("persisted creds = %+v, want %+v", got, *r.Credentials)
	}

	// Show returns the current pair.
	r, err = ctl.Do(ControlRequest{Op: "show"})
	if err != nil || r.Credentials == nil {
		t.Fatalf("show: %+v %v", r, err)
	}
	if *r.Credentials != loadSaved(t, cfgPath).Credentials {
		t.Fatalf("show creds = %+v", *r.Credentials)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("daemon exit: %v", err)
	}
}

func enabledHas(list []string, mode string) bool {
	for _, m := range list {
		if m == mode {
			return true
		}
	}
	return false
}

func loadSaved(t *testing.T, path string) ManagedConfig {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c ManagedConfig
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
