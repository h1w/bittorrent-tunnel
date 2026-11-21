package service

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// systemctlRunner abstracts systemctl calls for tests.
var systemctlRunner = func(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// SystemctlRunner returns the current systemctl runner. Exposed for cmd tests.
func SystemctlRunner() func(context.Context, ...string) (string, error) {
	return systemctlRunner
}

// SetSystemctlRunner replaces the systemctl runner. Exposed for cmd tests.
func SetSystemctlRunner(f func(context.Context, ...string) (string, error)) {
	systemctlRunner = f
}

func daemonReload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := systemctlRunner(ctx, "daemon-reload")
	if err != nil {
		return fmt.Errorf("daemon-reload: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

func unitAction(unit, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	out, err := systemctlRunner(ctx, action, unit)
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", action, unit, err, strings.TrimSpace(out))
	}
	return nil
}

func unitStatus(unit string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := systemctlRunner(ctx, "show", "--property=LoadState,ActiveState,UnitFileState", unit)
	if err != nil {
		return "", false, fmt.Errorf("status %s: %w: %s", unit, err, strings.TrimSpace(out))
	}
	var load, active, file string
	for line := range strings.SplitSeq(out, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "LoadState":
			load = value
		case "ActiveState":
			active = value
		case "UnitFileState":
			file = value
		}
	}
	if load == "not-found" {
		return NotInstalled, false, nil
	}
	if load != "loaded" || active == "" {
		return "", false, fmt.Errorf("status %s: unexpected unit state %q (%q)", unit, load, active)
	}
	return active, file == "enabled" || file == "enabled-runtime", nil
}
