package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bittorrent-tunnel/btawg/internal/service"
	"bittorrent-tunnel/btawg/internal/store"
)

func TestInstallCmdCopiesBinaryAndPrintsPassword(t *testing.T) {
	setInstallRequiresRoot(false)
	t.Cleanup(func() { setInstallRequiresRoot(true) })
	oldLaunch := managedLaunchPath
	managedLaunchPath = filepath.Join(t.TempDir(), "server.json")
	t.Cleanup(func() { managedLaunchPath = oldLaunch })

	oldUnitDir, oldBinDir := service.UnitDirs()
	tmpUnit := t.TempDir()
	tmpBin := t.TempDir()
	service.SetUnitDirs(tmpUnit, tmpBin)
	t.Cleanup(func() { service.SetUnitDirs(oldUnitDir, oldBinDir) })

	db := filepath.Join(t.TempDir(), "server.db")
	oldRunner := service.SystemctlRunner()
	var calls []string
	service.SetSystemctlRunner(func(ctx context.Context, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "show" {
			return "LoadState=not-found\nActiveState=inactive\nUnitFileState=\n", nil
		}
		if len(args) > 0 && args[0] == "restart" {
			st, err := store.Open(db)
			if err != nil {
				return "", err
			}
			return "", st.Close()
		}
		return "", nil
	})
	t.Cleanup(func() { service.SetSystemctlRunner(oldRunner) })

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
	want := []string{
		"show --property=LoadState,ActiveState,UnitFileState btawg-server.service",
		"daemon-reload", "enable btawg-server.service", "restart btawg-server.service",
	}
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
	if _, err := os.Stat(db + ".pending-admin"); err == nil {
		t.Fatal("pending password file should be removed after successful install")
	}

	// Second install: same DB, no new password printed.
	calls = nil
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	err = installCmd(nil)
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
