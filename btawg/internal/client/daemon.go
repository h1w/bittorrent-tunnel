package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
)

type ControlRequest struct {
	Op      string   `json:"op"`
	Mode    string   `json:"mode,omitempty"`
	Enabled []string `json:"enabled,omitempty"`
}

type ControlResponse struct {
	OK          bool         `json:"ok"`
	Enabled     []string     `json:"enabled"`
	Credentials *Credentials `json:"credentials,omitempty"`
	Error       string       `json:"error,omitempty"`
}

type clientControl struct {
	m    *Managed
	path string
	mu   sync.Mutex
	cfg  ManagedConfig
}

func RunManaged(ctx context.Context, cfg ManagedConfig, realTUN bool, tunName string) error {
	return runManagedAt(ctx, cfg, ManagedConfigPath, ControlSocketPath, realTUN, tunName, ManagedPortBase)
}

func runManagedAt(ctx context.Context, cfg ManagedConfig, cfgPath, socketPath string, realTUN bool, tunName string, portBase int) error {
	importCfg, err := config.ParseImportString(cfg.Import)
	if err != nil {
		return err
	}
	listenIP, err := netip.ParseAddr(cfg.ListenIP)
	if err != nil || !listenIP.Is4() {
		return fmt.Errorf("invalid SOCKS5 listen IPv4 address")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(socketPath), 0700); err != nil {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	m, err := newManagedAt(ctx, importCfg, cfg.Enabled, listenIP, cfg.Credentials, realTUN, tunName, portBase)
	if err != nil {
		return err
	}
	defer m.Close()
	d := &clientControl{m: m, path: cfgPath, cfg: cfg}
	if err := service.NotifyReady(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		workers.Go(func() { d.serve(ctx, c) })
	}
}

func (d *clientControl) serve(ctx context.Context, c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var req ControlRequest
	if json.NewDecoder(io.LimitReader(c, 4096)).Decode(&req) != nil {
		return
	}
	_ = json.NewEncoder(c).Encode(d.handle(req))
}

func (d *clientControl) handle(req ControlRequest) ControlResponse {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := d.cfg
	if err := next.update(req); err != nil {
		return ControlResponse{Error: err.Error()}
	}
	if req.Op == "apply" || req.Op == "toggle" || req.Op == "rotate" {
		if err := d.m.apply(next.Enabled, next.Credentials, func() error { return next.Save(d.path) }); err != nil {
			return ControlResponse{Error: err.Error()}
		}
		d.cfg = next
	}
	return next.response(req.Op)
}

func (c *ManagedConfig) update(req ControlRequest) error {
	switch req.Op {
	case "status", "show":
	case "apply":
		for _, m := range req.Enabled {
			if !slices.Contains(config.ClientModes(), m) {
				return fmt.Errorf("unsupported transport %q", m)
			}
		}
		c.Enabled = req.Enabled
	case "toggle":
		if !slices.Contains(config.ClientModes(), req.Mode) {
			return fmt.Errorf("unsupported transport %q", req.Mode)
		}
		modes := slices.Clone(c.Enabled)
		if i := slices.Index(modes, req.Mode); i >= 0 {
			modes = slices.Delete(modes, i, i+1)
		} else {
			modes = append(modes, req.Mode)
		}
		c.Enabled = modes
	case "rotate":
		creds, err := GenerateCredentials()
		if err != nil {
			return err
		}
		c.Credentials = creds
	default:
		return fmt.Errorf("unknown operation %q", req.Op)
	}
	return nil
}

func (c ManagedConfig) response(op string) ControlResponse {
	r := ControlResponse{OK: true, Enabled: c.Enabled}
	if op == "show" || op == "rotate" {
		r.Credentials = &c.Credentials
	}
	return r
}

var ErrNotRunning = errors.New("btawg-client control socket is not listening")

func request(path string, req ControlRequest) (ControlResponse, error) {
	var r ControlResponse
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return r, ErrNotRunning
		}
		return r, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return r, err
	}
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		return r, err
	}
	if !r.OK {
		return r, errors.New(r.Error)
	}
	return r, nil
}
