package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
)

func runTUI() error {
	return service.TUI(service.Menu{
		Unit: service.Client, Subtitle: "VPN client",
		Setup: func() (*service.Screen, error) { return clientSetup(false) },
		Install: func() (*service.Screen, error) {
			_, err := client.LoadManagedConfig(client.ManagedConfigPath)
			if errors.Is(err, os.ErrNotExist) {
				return clientSetup(true)
			}
			if err != nil {
				return nil, err
			}
			return nil, service.Client.Install()
		},
		Actions: clientActions,
	})
}

func clientSetup(install bool) (*service.Screen, error) {
	cfg, err := client.LoadManagedConfig(client.ManagedConfigPath)
	var previous *client.ManagedConfig
	switch {
	case errors.Is(err, os.ErrNotExist):
		cfg.ListenIP, cfg.TUNName = "127.0.0.1", "btawg0"
	case err != nil:
		return nil, err
	default:
		previous = &cfg
	}
	help := "Paste the btawg:// string from the server panel. The import is hidden."
	if previous != nil {
		help = "Leave the import blank to keep it. Settings take effect on next start."
	}
	submit := "Save settings"
	if install {
		submit = "Save and install"
	}
	return &service.Screen{
		Title: "Client settings", Text: help, Submit: submit,
		Fields: []service.Field{
			{Label: "VPN import", Secret: true},
			{Label: "SOCKS5 listen IPv4", Value: cfg.ListenIP},
			{Label: "TUN name prefix", Value: cfg.TUNName},
			{Label: "Userspace only (no TUN)", Toggle: true, Checked: cfg.NoTUN},
		},
		Save: func(fields []service.Field) (*service.Screen, error) {
			state, _, err := service.Client.State()
			if err != nil {
				return nil, err
			}
			if state != service.NotInstalled && state != "inactive" && state != "failed" {
				return nil, fmt.Errorf("stop the service before changing launch settings (currently %s)", state)
			}
			latest, err := client.LoadManagedConfig(client.ManagedConfigPath)
			if err == nil {
				previous = &latest
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			if err := saveClientSettings(previous, fields[0].Value, fields[1].Value, fields[3].Checked, fields[2].Value); err != nil {
				return nil, err
			}
			if install {
				return nil, service.Client.Install()
			}
			return nil, nil
		},
	}, nil
}

func saveClientSettings(previous *client.ManagedConfig, raw, listen string, noTUN bool, tun string) error {
	raw, listen, tun = strings.TrimSpace(raw), strings.TrimSpace(listen), strings.TrimSpace(tun)
	ip, err := netip.ParseAddr(listen)
	if err != nil || !ip.Is4() {
		return errors.New("SOCKS5 listen address must be IPv4")
	}
	if !noTUN {
		if err := service.ValidateInterface(tun, 13); err != nil {
			return err
		}
	}
	var next client.ManagedConfig
	if previous != nil {
		next = *previous
	}
	if raw != "" || previous == nil {
		parsed, err := config.ParseImportString(raw)
		if err != nil {
			return errors.New("invalid VPN import: paste the complete btawg:// string from the server panel")
		}
		mode := config.CanonicalMode(parsed.Transport)
		if !config.ValidClientMode(mode) {
			return errors.New("VPN import uses an unsupported transport")
		}
		if next.Import != raw {
			next.Import, next.Enabled = raw, []string{mode}
		}
	}
	if previous == nil {
		next.Credentials, err = client.GenerateCredentials()
		if err != nil {
			return err
		}
	}
	next.ListenIP, next.TUNName, next.NoTUN = ip.String(), tun, noTUN
	return next.Save(client.ManagedConfigPath)
}

func clientActions(_ string) ([]service.Action, error) {
	status, running, err := client.RequestControl(client.ControlRequest{Op: "status"})
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	modes := config.ClientModes()
	actions := make([]service.Action, 0, len(modes)+2)
	for i, mode := range modes {
		checked, state := "[ ]", "off"
		if running {
			state = "reserved"
		}
		if slices.Contains(status.Enabled, mode) {
			checked, state = "[x]", "enabled on start"
			if running {
				state = "enabled"
			}
		}
		actions = append(actions, service.Action{
			Label: fmt.Sprintf("%s %d  %-22s %s", checked, client.ManagedPortBase+i, mode, state),
			Run: func() (*service.Screen, error) {
				_, _, err := client.RequestControl(client.ControlRequest{Op: "toggle", Mode: mode})
				return nil, err
			},
		})
	}
	return append(actions,
		service.Action{Label: "Show SOCKS5 credentials", Run: func() (*service.Screen, error) { return socksCredentials("show") }},
		service.Action{Label: "Rotate SOCKS5 credentials", Confirm: "Replace the login and password for all ports? Existing SOCKS5 sessions will close.", Run: func() (*service.Screen, error) { return socksCredentials("rotate") }},
	), nil
}

func socksCredentials(op string) (*service.Screen, error) {
	r, _, err := client.RequestControl(client.ControlRequest{Op: op})
	if err != nil {
		return nil, err
	}
	if r.Credentials == nil {
		return nil, errors.New("SOCKS5 credentials not available")
	}
	title := "SOCKS5 credentials"
	if op == "rotate" {
		title = "New SOCKS5 credentials"
	}
	return &service.Screen{Title: title, Text: fmt.Sprintf("Username: %s\nPassword: %s", r.Credentials.Username, r.Credentials.Password)}, nil
}
