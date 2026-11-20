package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Unit is a managed btawg systemd role.
type Unit string

const (
	// Server is the btawg hub role.
	Server Unit = "server"
	// Client is the btawg VPN client role.
	Client Unit = "client"
)

// installPaths are overridable in tests.
var (
	unitDir = "/etc/systemd/system"
	binDir  = "/usr/local/bin"
)

func (u Unit) binaryName() string { return "btawg-" + string(u) }
func (u Unit) unitName() string   { return u.binaryName() + ".service" }
func (u Unit) binaryPath() string { return filepath.Join(binDir, u.binaryName()) }
func (u Unit) unitPath() string   { return filepath.Join(unitDir, u.unitName()) }

// Install copies the running binary into /usr/local/bin and installs,
// enables and starts the systemd unit. Any extra args are appended to the
// unit's ExecStart command after the implicit `run -managed`. The import
// secret is never placed in unit arguments; callers must persist it to
// /etc/btawg/client.json before installing the client unit.
func (u Unit) Install(extraArgs ...string) error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if err := copyFile(src, u.binaryPath(), 0o755); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	unit := u.renderUnit(extraArgs)
	if err := WriteFile(u.unitPath(), []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if err := daemonReload(); err != nil {
		return err
	}
	if err := unitAction(u.unitName(), "enable"); err != nil {
		return err
	}
	if err := unitAction(u.unitName(), "start"); err != nil {
		return err
	}
	return nil
}

// Control executes a systemd action for the unit. Supported actions are the
// same as systemctl: start, stop, restart, enable, disable, status.
func (u Unit) Control(action string) error {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
		return unitAction(u.unitName(), action)
	case "status":
		_, _, err := u.State()
		return err
	default:
		return fmt.Errorf("unsupported action %q", action)
	}
}

// State returns the unit's ActiveState and whether it is enabled.
func (u Unit) State() (string, bool, error) {
	state, err := unitStatus(u.unitName())
	if err != nil {
		return "", false, err
	}
	enabled, err := unitIsEnabled(u.unitName())
	if err != nil {
		return state, false, err
	}
	return state, enabled, nil
}

func (u Unit) renderUnit(extraArgs []string) string {
	exec := fmt.Sprintf("%s run -managed", u.binaryPath())
	if len(extraArgs) > 0 {
		exec += " " + strings.Join(extraArgs, " ")
	}
	var extra string
	switch u {
	case Server:
		extra = "StateDirectory=btawg\n"
	case Client:
		extra = "RuntimeDirectory=btawg-client\n"
	}
	return fmt.Sprintf(`[Unit]
Description=btawg VPN %s
After=network.target

[Service]
Type=notify
ExecStart=%s
Restart=on-failure
RestartSec=5
%s
[Install]
WantedBy=multi-user.target
`, u, exec, extra)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if closeErr := out.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}
