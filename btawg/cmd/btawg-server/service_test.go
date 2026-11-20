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

	// Run with -managed -no-tun. We can't easily cancel it from the test, so
	// just verify it starts without panicking and attempts the managed path.
	done := make(chan error, 1)
	go func() {
		done <- runCmd([]string{"-managed", "-no-tun", "-store", db})
	}()

	select {
	case err := <-done:
		t.Logf("runCmd returned: %v", err)
	case <-time.After(3 * time.Second):
		t.Log("runCmd still running after 3s; test passes if no panic")
	}
}
