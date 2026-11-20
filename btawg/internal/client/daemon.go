package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
)

// ControlRequest is one live TUI command sent to the daemon's control socket.
type ControlRequest struct {
	Op      string   `json:"op"` // status | show | apply | rotate
	Enabled []string `json:"enabled,omitempty"`
}

// ModeState reports one connection mode's fixed port and whether it is live.
type ModeState struct {
	Mode    string `json:"mode"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
}

// ControlResponse is the daemon's answer to a ControlRequest.
type ControlResponse struct {
	OK          bool          `json:"ok"`
	Enabled     []string      `json:"enabled"`
	Modes       []ModeState   `json:"modes,omitempty"`
	Credentials *Credentials  `json:"credentials,omitempty"`
	Error       string        `json:"error,omitempty"`
}

// Daemon owns a running Managed client and serves live control requests over
// a root-only Unix socket. Enabled modes and credentials change in place and
// are persisted so they survive a restart.
type Daemon struct {
	m       *Managed
	path    string
	cfgPath string

	mu sync.Mutex
	cfg ManagedConfig
}

// RunManaged builds the managed client from cfg, serves live control on the
// socket, and reports readiness to systemd. It returns when ctx is done or the
// client fails irrecoverably.
func RunManaged(ctx context.Context, cfg ManagedConfig, realTUN bool, tunName string) error {
	return runManagedAt(ctx, cfg, ManagedConfigPath, ControlSocketPath, realTUN, tunName)
}

func runManagedAt(ctx context.Context, cfg ManagedConfig, cfgPath, socketPath string, realTUN bool, tunName string) error {
	importCfg, err := config.ParseImportString(cfg.Import)
	if err != nil {
		return fmt.Errorf("parse import: %w", err)
	}
	listenIP := netip.MustParseAddr(cfg.ListenIP)
	if !listenIP.IsValid() {
		listenIP = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	m, err := NewManaged(ctx, importCfg, cfg.Enabled, listenIP, cfg.Credentials, realTUN, tunName)
	if err != nil {
		return err
	}
	defer m.Close()

	d := &Daemon{m: m, path: socketPath, cfgPath: cfgPath, cfg: cfg}
	ln, err := d.listen()
	if err != nil {
		return err
	}
	defer func() {
		ln.Close()
		os.Remove(d.path)
	}()

	if err := service.NotifyReady(); err != nil {
		return fmt.Errorf("systemd ready: %w", err)
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-sctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if sctx.Err() != nil {
				return nil
			}
			return err
		}
		go d.serveConn(c)
	}
}

func (d *Daemon) listen() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(d.path), 0o700); err != nil {
		return nil, err
	}
	os.Remove(d.path)
	ln, err := net.Listen("unix", d.path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(d.path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (d *Daemon) serveConn(c net.Conn) {
	defer c.Close()
	dec := json.NewDecoder(c)
	enc := json.NewEncoder(c)
	for {
		var req ControlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		enc.Encode(d.handle(req))
	}
}

func (d *Daemon) handle(req ControlRequest) ControlResponse {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch req.Op {
	case "status", "show":
		resp := d.snapshotLocked()
		if req.Op == "show" {
			creds := d.cfg.Credentials
			resp.Credentials = &creds
		}
		return resp
	case "apply":
		if err := d.m.Apply(req.Enabled, d.cfg.Credentials); err != nil {
			return ControlResponse{OK: false, Error: err.Error()}
		}
		d.cfg.Enabled = canonicalModes(req.Enabled)
		if err := d.cfg.Save(d.cfgPath); err != nil {
			return ControlResponse{OK: false, Error: err.Error()}
		}
		return d.snapshotLocked()
	case "rotate":
		creds, err := GenerateCredentials()
		if err != nil {
			return ControlResponse{OK: false, Error: err.Error()}
		}
		if err := d.m.Apply(d.cfg.Enabled, creds); err != nil {
			return ControlResponse{OK: false, Error: err.Error()}
		}
		d.cfg.Credentials = creds
		if err := d.cfg.Save(d.cfgPath); err != nil {
			return ControlResponse{OK: false, Error: err.Error()}
		}
		resp := d.snapshotLocked()
		resp.Credentials = &creds
		return resp
	default:
		return ControlResponse{OK: false, Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

func (d *Daemon) snapshotLocked() ControlResponse {
	ports := ManagedPorts()
	modes := config.ClientModes()
	enabled := map[string]bool{}
	for _, m := range d.cfg.Enabled {
		enabled[m] = true
	}
	resp := ControlResponse{OK: true, Enabled: append([]string(nil), d.cfg.Enabled...)}
	for i, mode := range modes {
		resp.Modes = append(resp.Modes, ModeState{Mode: mode, Port: ports[i], Enabled: enabled[mode]})
	}
	return resp
}

func canonicalModes(list []string) []string {
	out := make([]string, 0, len(list))
	for _, m := range list {
		if cm := config.CanonicalMode(m); config.ValidClientMode(cm) {
			out = append(out, cm)
		}
	}
	return out
}

// Control is the TUI's client for the daemon socket. When the daemon is not
// running, commands return ErrNotRunning and the TUI falls back to editing the
// saved configuration.
var ErrNotRunning = errors.New("btawg-client service is not running")

// DialControl connects to the daemon's control socket.
func DialControl(path string) (*Control, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, ErrNotRunning
	}
	return &Control{conn: c}, nil
}

// Control is a live control connection to the daemon.
type Control struct {
	conn net.Conn
}

// Do sends one request and returns the daemon's response.
func (c *Control) Do(req ControlRequest) (ControlResponse, error) {
	var resp ControlResponse
	if err := json.NewEncoder(c.conn).Encode(req); err != nil {
		return resp, err
	}
	if err := json.NewDecoder(c.conn).Decode(&resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// Close releases the control connection.
func (c *Control) Close() error { return c.conn.Close() }
