package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
	"bittorrent-tunnel/btawg/internal/store"
)

func TestInstallCmdCopiesBinaryAndPrintsPassword(t *testing.T) {
	setInstallRequiresRoot(false)
	t.Cleanup(func() { setInstallRequiresRoot(true) })
	setPendingPassPath(filepath.Join(t.TempDir(), ".admin-password"))
	t.Cleanup(func() { setPendingPassPath("/etc/btawg/.admin-password") })

	oldUnitDir, oldBinDir := service.UnitDirs()
	tmpUnit := t.TempDir()
	tmpBin := t.TempDir()
	service.SetUnitDirs(tmpUnit, tmpBin)
	t.Cleanup(func() { service.SetUnitDirs(oldUnitDir, oldBinDir) })

	oldRunner := service.SystemctlRunner()
	var calls []string
	service.SetSystemctlRunner(func(ctx context.Context, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		return "", nil
	})
	t.Cleanup(func() { service.SetSystemctlRunner(oldRunner) })

	db := filepath.Join(t.TempDir(), "server.db")

	// First install: new DB, password generated.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	err = installCmd([]string{"-store", db})
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("installCmd: %v", err)
	}
	var out bytes.Buffer
	out.ReadFrom(r)

	if _, err := os.Stat(filepath.Join(tmpBin, "btawg-server")); err != nil {
		t.Fatalf("binary not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpUnit, "btawg-server.service")); err != nil {
		t.Fatalf("unit not written: %v", err)
	}
	want := []string{"daemon-reload", "enable btawg-server.service", "start btawg-server.service"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("call %d = %q, want %q", i, calls[i], want[i])
		}
	}

	outStr := out.String()
	if !strings.Contains(outStr, "panel login admin /") {
		t.Fatalf("password not printed: %q", outStr)
	}
	if _, err := os.Stat(pendingPassPath); err == nil {
		t.Fatal("pending password file should be removed after successful install")
	}

	// Second install: same DB, no new password printed.
	calls = nil
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	err = installCmd([]string{"-store", db})
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("second installCmd: %v", err)
	}
	out.Reset()
	out.ReadFrom(r)
	if strings.Contains(out.String(), "panel login admin /") {
		t.Fatalf("password should not be printed again: %q", out.String())
	}
}

func TestRunCmdStartsManagedNoTun(t *testing.T) {
	db := filepath.Join(t.TempDir(), "server.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	cfg := config.DefaultServerConfig()
	cfg.PanelPort = 28080 // avoid conflicts with a real panel on 8080
	if err := st.SaveServerConfig(cfg); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	st.Close()

	// Run with -managed -no-tun. Start it, give it a moment to serve, then
	// cancel and wait so no daemon goroutine outlives the test (a leaked
	// daemon races with cleanup under -race).
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runCmd(ctx, []string{"-managed", "-no-tun", "-store", db})
	}()

	select {
	case err := <-done:
		t.Logf("runCmd returned during startup: %v", err)
		return
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		t.Logf("runCmd stopped on cancel: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not stop on cancel; daemon leaked past the test")
	}
}
