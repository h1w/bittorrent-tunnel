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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := systemctlRunner(ctx, action, unit)
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", action, unit, err, strings.TrimSpace(out))
	}
	return nil
}

func unitIsEnabled(unit string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := systemctlRunner(ctx, "is-enabled", unit)
	state := strings.TrimSpace(out)
	switch state {
	case "enabled":
		return true, nil
	case "disabled", "masked":
		return false, nil
	default:
		if err != nil {
			return false, fmt.Errorf("is-enabled %s: %w: %s", unit, err, state)
		}
		return false, nil
	}
}

func unitStatus(unit string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := systemctlRunner(ctx, "show", "--property=ActiveState", "--value", unit)
	state := strings.TrimSpace(out)
	if err != nil && state == "" {
		return "", fmt.Errorf("status %s: %w", unit, err)
	}
	return state, nil
}
