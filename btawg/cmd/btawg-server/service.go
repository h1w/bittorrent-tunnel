package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/panel"
	"bittorrent-tunnel/btawg/internal/server"
	"bittorrent-tunnel/btawg/internal/service"
	"bittorrent-tunnel/btawg/internal/store"
)

const (
	managedStorePath = "/var/lib/btawg/server.db"
)

var managedLaunchPath = "/etc/btawg/server.json"

type serverLaunch struct {
	Store string `json:"store"`
	NoTUN bool   `json:"no_tun,omitempty"`
}

func installCmd(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	storePath := fs.String("store", managedStorePath, "path to existing bbolt database to use")
	noTun := fs.Bool("no-tun", false, "run overlay-only without kernel TUN or NAT")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if installRequiresRoot && os.Geteuid() != 0 {
		return errors.New("install must run as root")
	}

	launch := serverLaunch{Store: managedStorePath}
	if data, err := os.ReadFile(managedLaunchPath); err == nil {
		if err := json.Unmarshal(data, &launch); err != nil {
			return fmt.Errorf("read server launch settings: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "store":
			launch.Store = *storePath
		case "no-tun":
			launch.NoTUN = *noTun
		}
	})
	if launch.Store == "" {
		return errors.New("server store path must not be empty")
	}
	path, err := filepath.Abs(launch.Store)
	if err != nil {
		return err
	}
	launch.Store = path
	pendingPath := launch.Store + ".pending-admin"
	if launch.Store == managedStorePath {
		pendingPath = "/etc/btawg/.admin-password"
	}
	if err != nil {
		return err
	}
	defer st.Close()

	// Persist a root-only plaintext copy so the password survives a failed
	// enable/start and can still be printed on the next attempt.
	if generated {
		if err := service.WriteFile(pendingPassPath, []byte(pw), 0o600); err != nil {
			return fmt.Errorf("save pending password: %w", err)
		}
	}
	data, err := json.MarshalIndent(launch, "", "  ")
	if err != nil {
		return err
	}
	if err := service.WriteFile(managedLaunchPath, data, 0600); err != nil {
		return err
	}
	if err := service.Server.Install(); err != nil {
		return fmt.Errorf("install unit: %w", err)
	}
	pending, err := os.ReadFile(pendingPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := fmt.Printf("btawg-server: panel login admin / %s (shown once)\n", pending); err != nil {
		return err
	}
	return os.Remove(pendingPath)
}

func runCmd(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	managed := fs.Bool("managed", false, "run as a managed systemd service with fixed ports and durable paths")
	storePath := fs.String("store", "", "path to the bbolt database (managed default: /var/lib/btawg/server.db)")
	transport := fs.String("transport", "", "preferred connection chain for new imports ("+strings.Join(config.ClientModes(), "|")+")")
	carrierPort := fs.Int("carrier-port", 0, "override carrier listen port")
	externalIP := fs.String("external-ip", "", "public IPv4 for native imports (default: outbound interface address)")
	dhtBootstrap := fs.String("dht-bootstrap", "", "override DHT bootstrap nodes, comma-separated host:port (default: public)")
	noTun := fs.Bool("no-tun", false, "userspace overlay only: no OS interface or Internet forwarding")
	tunName := fs.String("tun", "btawg0", "TUN interface name in real-TUN mode")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *managed {
		var launch serverLaunch
		if data, err := os.ReadFile(managedLaunchPath); err == nil {
			if err := json.Unmarshal(data, &launch); err != nil {
				return fmt.Errorf("read server launch settings: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if *storePath == "" {
			*storePath = launch.Store
			if *storePath == "" {
				*storePath = managedStorePath
			}
		}
		*noTun = *noTun || launch.NoTUN
	}
	if *storePath == "" {
		*storePath = "btawg.db"
	}

	pendingPath := ""
	if *managed {
		pendingPath = *storePath + ".pending-admin"
		if *storePath == managedStorePath {
			pendingPath = "/etc/btawg/.admin-password"
		}
	}
	st, _, pw, err := openOrCreateServerStore(*storePath, pendingPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if pw != "" && !*managed {
		fmt.Printf("btawg-server: panel login admin / %s (shown once)\n", pw)
	}

	cfg, err := st.LoadServerConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if *transport != "" {
		cfg.Transport = *transport
	}
	if *managed {
		cfg.CarrierPort = config.DefaultServerConfig().CarrierPort
		cfg.AWGPort = config.DefaultServerConfig().AWGPort
		cfg.WGPort = config.DefaultServerConfig().WGPort
	} else if *carrierPort != 0 {
		cfg.CarrierPort = *carrierPort
	}
	if *externalIP != "" {
		cfg.ExternalIP = *externalIP
	}

	var srv *server.Server
	if *noTun {
		srv, err = server.New(cfg, st)
	} else {
		srv, err = server.NewRealTUN(cfg, st, *tunName)
	}
	if err != nil {
		return err
	}
	if *managed {
		srv.SetManaged(true)
	}
	defer func() {
		_ = srv.Close()
	}()

	if *dhtBootstrap != "" {
		srv.SetDHTBootstrap(strings.Split(*dhtBootstrap, ","))
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err = st.LoadServerConfig()
	if err != nil {
		return fmt.Errorf("reload config: %w", err)
	}
	if *transport != "" {
		cfg.Transport = *transport
	}
	if *managed {
		cfg.CarrierPort = config.DefaultServerConfig().CarrierPort
		cfg.AWGPort = config.DefaultServerConfig().AWGPort
		cfg.WGPort = config.DefaultServerConfig().WGPort
	} else if *carrierPort != 0 {
		cfg.CarrierPort = *carrierPort
	}
	if *externalIP != "" {
		cfg.ExternalIP = *externalIP
	}

	listeners, err := srv.ListenPanel(ctx, cfg.PanelPort)
	if err != nil {
		return fmt.Errorf("panel listeners: %w", err)
	}
	p := panel.New(st, srv, "admin", cfg.AdminPassHash)
	handler := p.Handler()
	web := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	defer web.Close()
	webErrors := make(chan error, len(listeners))
	for _, ln := range listeners {
		defer ln.Close()
		go func(l net.Listener) { webErrors <- web.Serve(l) }(ln)
	}
	for _, addr := range listenerAddrs(listeners) {
		fmt.Printf("btawg-server: panel on http://%s\n", addr)
	}

	if *managed {
		if err := service.NotifyReady(); err != nil {
			return fmt.Errorf("systemd readiness: %w", err)
		}
	}

	errCh := make(chan error, 2)
	go func() { errCh <- srv.Run(ctx) }()
	go func() { errCh <- srv.Announce(ctx) }()

	active := srv.Config()
	fmt.Printf("btawg-server: modes=%s carrier=:%d awg=:%d/udp wg=:%d/udp infohash=%s\n",
		strings.Join(config.ClientModes(), ","), active.CarrierPort, active.AWGPort, active.WGPort, srv.InfoHash())
	fmt.Println("btawg-server: optional DHT discovery announce loop started")

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return web.Shutdown(shutdown)
	case err := <-errCh:
		return err
	case err := <-webErrors:
		return err
	}
}

func tui() error {
	return service.TUI(service.Server, nil, nil)
}

// openOrCreateServerStore opens the database, generating server identity and
// an admin password when the store is new. It returns the store, whether a
// password was generated, and the generated plaintext password.
func openOrCreateServerStore(path string, pendingPath ...string) (*store.Store, bool, string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, "", fmt.Errorf("create db dir: %w", err)
	}
	st, err := store.Open(path)
	if err != nil {
		return nil, false, "", fmt.Errorf("open store: %w", err)
	}
	cfg, err := st.LoadServerConfig()
	if err != nil {
		st.Close()
		return nil, false, "", fmt.Errorf("load config: %w", err)
	}
	if cfg.AdminPassHash != "" {
		return st, false, "", nil
	}
	pw := randomPassword()
	if len(pendingPath) > 0 && pendingPath[0] != "" {
		if err := service.WriteFile(pendingPath[0], []byte(pw), 0600); err != nil {
			st.Close()
			return nil, false, "", err
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		st.Close()
		return nil, false, "", fmt.Errorf("hash password: %w", err)
	}
	cfg.AdminPassHash = string(hash)
	if err := st.SaveServerConfig(cfg); err != nil {
		st.Close()
		return nil, false, "", fmt.Errorf("save admin hash: %w", err)
	}
	return st, true, pw, nil
}

func listenerAddrs(listeners []net.Listener) []string {
	out := make([]string, len(listeners))
	for i, ln := range listeners {
		out[i] = ln.Addr().String()
	}
	return out
}

var installRequiresRoot = true

// setInstallRequiresRoot is used by tests to bypass the root check.
func setInstallRequiresRoot(v bool) { installRequiresRoot = v }

// randomPassword returns a 16-char alphanumeric password.
func randomPassword() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
