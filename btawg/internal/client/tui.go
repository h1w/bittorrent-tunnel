package client

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
)

func RunTUI() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("client TUI needs root; run sudo btawg-client")
	}
	return service.TUI(service.Client, tuiLines, tuiAction)
}

func tuiRequest(req ControlRequest) (r ControlResponse, running bool, err error) {
	r, err = request(ControlSocketPath, req)
	if !errors.Is(err, ErrNotRunning) {
		return r, true, err
	}
	if req.Op == "toggle" || req.Op == "rotate" {
		state, _, err := service.Client.State()
		if err != nil {
			return r, false, err
		}
		if state != "inactive" && state != "failed" {
			return r, false, fmt.Errorf("service is %s; control socket is not ready", state)
		}
	}
	cfg, err := LoadManagedConfig(ManagedConfigPath)
	if err != nil {
		return r, false, err
	}
	if err := cfg.update(req); err != nil {
		return r, false, err
	}
	if req.Op == "toggle" || req.Op == "rotate" {
		if err := cfg.Save(ManagedConfigPath); err != nil {
			return r, false, err
		}
	}
	return cfg.response(req.Op), false, nil
}

func tuiLines() ([]string, error) {
	r, running, err := tuiRequest(ControlRequest{Op: "status"})
	if err != nil {
		return nil, err
	}
	modes := config.ClientModes()
	rows := make([]string, 0, len(modes))
	for i, mode := range modes {
		box, status := "[ ]", "off"
		if running {
			status = "reserved"
		}
		if slices.Contains(r.Enabled, mode) {
			box, status = "[x]", "enabled"
			if !running {
				status = "on next start"
			}
		}
		rows = append(rows, fmt.Sprintf("%s %d  %-22s %s", box, ManagedPortBase+i, mode, status))
	}
	return rows, nil
}

func tuiAction(key byte, i int) (string, error) {
	var req ControlRequest
	switch key {
	case ' ':
		modes := config.ClientModes()
		if i < 0 || i >= len(modes) {
			return "", nil
		}
		req = ControlRequest{Op: "toggle", Mode: modes[i]}
	case 'v':
		req.Op = "show"
	case 'g':
		req.Op = "rotate"
	default:
		return "", nil
	}
	r, _, err := tuiRequest(req)
	if err != nil {
		return "", err
	}
	if r.Credentials != nil {
		return fmt.Sprintf("SOCKS5 login: %s / %s", r.Credentials.Username, r.Credentials.Password), nil
	}
	return "", nil
}
