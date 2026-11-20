package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
)

func TestDaemonControlToggleRotatePersist(t *testing.T) {
	base := managedCfg(t)
	raw, err := base.ImportString()
	if err != nil {
		t.Fatal(err)
	}
	cfg := ManagedConfig{Import: raw, Enabled: []string{config.ModeWG}, ListenIP: "127.0.0.1", Credentials: Credentials{Username: "first", Password: "secret"}}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "state", "client.json")
	socket := filepath.Join(dir, "run", "ctl.sock")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runManagedAt(ctx, cfg, cfgPath, socket, false, "btawg", 0) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	send := func(r ControlRequest) ControlResponse {
		t.Helper()
		res, err := request(socket, r)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		r, err := request(socket, ControlRequest{Op: "status"})
		if err == nil {
			if !slices.Equal(r.Enabled, []string{config.ModeWG}) || r.Credentials != nil {
				t.Fatalf("unexpected status: %+v", r)
			}
			break
		}
		if !errors.Is(err, ErrNotRunning) || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	send(ControlRequest{Op: "apply", Enabled: []string{config.ModeAWG}})
	if err := os.Rename(filepath.Dir(cfgPath), filepath.Join(dir, "backup")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(cfgPath), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := request(socket, ControlRequest{Op: "apply", Enabled: []string{config.ModeWG}}); err == nil {
		t.Fatal("update accepted without persistence")
	}
	if r := send(ControlRequest{Op: "status"}); !slices.Equal(r.Enabled, []string{config.ModeAWG}) {
		t.Fatal(r.Enabled)
	}
	if err := os.Remove(filepath.Dir(cfgPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "backup"), filepath.Dir(cfgPath)); err != nil {
		t.Fatal(err)
	}
	r := send(ControlRequest{Op: "rotate"})
	if r.Credentials == nil || *r.Credentials == cfg.Credentials {
		t.Fatal("credentials were not rotated")
	}
	loaded, err := LoadManagedConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Credentials != *r.Credentials || !slices.Equal(loaded.Enabled, []string{config.ModeAWG}) {
		t.Fatal("rotation or toggle was not persisted")
	}
	shown := send(ControlRequest{Op: "show"}).Credentials
	if shown == nil || *shown != loaded.Credentials {
		t.Fatal("show did not return current credentials")
	}
}
