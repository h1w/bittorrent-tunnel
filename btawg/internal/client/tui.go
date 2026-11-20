package client

import (
	"errors"
	"fmt"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
)

// RunTUI runs the client's terminal UI. It drives a live daemon over the
// control socket when the service is up, and edits the saved configuration
// directly when it is not, so toggles and credential rotation always persist.
func RunTUI() error {
	h := &tuiHandler{}
	defer h.close()
	return service.TUI(service.Client, h.lines, h.extra)
}

type tuiHandler struct {
	ctl  *Control
	cfg  ManagedConfig
	load bool
}

func (h *tuiHandler) close() {
	if h.ctl != nil {
		h.ctl.Close()
	}
}

// conn returns the daemon control connection, dialing on first use.
func (h *tuiHandler) conn() *Control {
	if h.ctl != nil {
		return h.ctl
	}
	c, err := DialControl(ControlSocketPath)
	if err != nil {
		return nil
	}
	h.ctl = c
	return c
}

// state returns the current modes and enabled set from the daemon if running,
// otherwise from the saved configuration.
func (h *tuiHandler) state() (ControlResponse, error) {
	if c := h.conn(); c != nil {
		return c.Do(ControlRequest{Op: "status"})
	}
	if !h.load {
		cfg, err := LoadManagedConfig(ManagedConfigPath)
		if err != nil {
			return ControlResponse{}, fmt.Errorf("no running service and no config: %w", err)
		}
		h.cfg = cfg
		h.load = true
	}
	ports := ManagedPorts()
	enabled := map[string]bool{}
	for _, m := range h.cfg.Enabled {
		enabled[m] = true
	}
	resp := ControlResponse{OK: true, Enabled: append([]string(nil), h.cfg.Enabled...)}
	for i, mode := range config.ClientModes() {
		resp.Modes = append(resp.Modes, ModeState{Mode: mode, Port: ports[i], Enabled: enabled[mode]})
	}
	return resp, nil
}

func (h *tuiHandler) lines() ([]string, error) {
	resp, err := h.state()
	if err != nil {
		return nil, err
	}
	return RenderModeLines(resp.Modes), nil
}

func (h *tuiHandler) extra(key byte, selected int) (string, error) {
	switch key {
	case ' ':
		return h.toggle(selected)
	case 'v':
		return h.show()
	case 'g':
		return h.rotate()
	}
	return "", nil
}

func (h *tuiHandler) toggle(selected int) (string, error) {
	resp, err := h.state()
	if err != nil {
		return "", err
	}
	if selected < 0 || selected >= len(resp.Modes) {
		return "", nil
	}
	mode := resp.Modes[selected].Mode
	enabled := map[string]bool{}
	for _, m := range resp.Enabled {
		enabled[m] = true
	}
	if enabled[mode] {
		delete(enabled, mode)
	} else {
		enabled[mode] = true
	}
	next := make([]string, 0, len(enabled))
	for _, m := range config.ClientModes() {
		if enabled[m] {
			next = append(next, m)
		}
	}
	if c := h.conn(); c != nil {
		r, err := c.Do(ControlRequest{Op: "apply", Enabled: next})
		if err != nil {
			return "", err
		}
		if !r.OK {
			return "", errors.New(r.Error)
		}
	} else {
		h.cfg.Enabled = next
		if err := h.cfg.Save(ManagedConfigPath); err != nil {
			return "", err
		}
	}
	action := "enabled"
	if !enabled[mode] {
		action = "disabled"
	}
	return fmt.Sprintf("%s %s", mode, action), nil
}

func (h *tuiHandler) show() (string, error) {
	creds, err := h.credentials("show")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("SOCKS5 %s / %s", creds.Username, creds.Password), nil
}

func (h *tuiHandler) rotate() (string, error) {
	creds, err := h.credentials("rotate")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rotated → %s / %s", creds.Username, creds.Password), nil
}

func (h *tuiHandler) credentials(op string) (Credentials, error) {
	if c := h.conn(); c != nil {
		r, err := c.Do(ControlRequest{Op: op})
		if err != nil {
			return Credentials{}, err
		}
		if !r.OK {
			return Credentials{}, errors.New(r.Error)
		}
		if r.Credentials == nil {
			return Credentials{}, errors.New("no credentials returned")
		}
		return *r.Credentials, nil
	}
	if !h.load {
		cfg, err := LoadManagedConfig(ManagedConfigPath)
		if err != nil {
			return Credentials{}, err
		}
		h.cfg = cfg
		h.load = true
	}
	creds := h.cfg.Credentials
	if op == "rotate" {
		nc, err := GenerateCredentials()
		if err != nil {
			return Credentials{}, err
		}
		h.cfg.Credentials = nc
		if err := h.cfg.Save(ManagedConfigPath); err != nil {
			return Credentials{}, err
		}
		creds = nc
	}
	return creds, nil
}

// RenderModeLines is a helper for tests: format the mode list the TUI shows.
func RenderModeLines(modes []ModeState) []string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		box, status := "[ ]", "reserved"
		if m.Enabled {
			box, status = "[x]", "active"
		}
		out = append(out, fmt.Sprintf("%s %4d %-22s %s", box, m.Port, m.Mode, status))
	}
	return out
}
