package main

import (
	"context"
	"crypto/rand"
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
	pendingPassPath  = "/etc/btawg/.admin-password"
)

func installCmd(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	storePath := fs.String("store", managedStorePath, "path to existing bbolt database to use")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
	}

	st, generated, pw, err := openOrCreateServerStore(*storePath)
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

	if err := service.Server.Install(); err != nil {
		return fmt.Errorf("install unit: %w", err)
	}

	if generated {
		pending, err := os.ReadFile(pendingPassPath)
		if err == nil && len(pending) > 0 {
			cfg, _ := st.LoadServerConfig()
			fmt.Printf("btawg-server: panel login admin / %s (shown once, loopback :%d)\n", string(pending), cfg.PanelPort)
			_ = os.Remove(pendingPassPath)
		}
	}
	return nil
}

func runCmd(args []string) error {
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
		if *storePath == "" {
			*storePath = managedStorePath
		}
	}
	if *storePath == "" {
		*storePath = "btawg.db"
	}

	st, _, _, err := openOrCreateServerStore(*storePath)
	if err != nil {
		return err
	}
	defer st.Close()

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
	defer func() {
		_ = srv.Close()
	}()

	if *dhtBootstrap != "" {
		srv.SetDHTBootstrap(strings.Split(*dhtBootstrap, ","))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	for _, ln := range listeners {
		go func(l net.Listener) {
			_ = http.Serve(l, handler)
		}(ln)
	}
	for _, addr := range listenerAddrs(listeners) {
		fmt.Printf("btawg-server: panel on http://%s\n", addr)
	}

	if *managed {
		if err := service.NotifyReady(); err != nil {
			fmt.Fprintf(os.Stderr, "btawg-server: sdnotify: %v\n", err)
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
		fmt.Println("btawg-server: shutting down")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}
	return nil
}

func tui() error {
	return service.TUI(service.Server, nil, nil)
}

// openOrCreateServerStore opens the database, generating server identity and
// an admin password when the store is new. It returns the store, whether a
// password was generated, and the generated plaintext password.
func openOrCreateServerStore(path string) (*store.Store, bool, string, error) {
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
