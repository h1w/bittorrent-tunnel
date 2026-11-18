// btawg-server runs the btawg hub: AmneziaWG inside a BitTorrent carrier,
// an egress SOCKS5 reachable only inside the overlay, and a DHT announcer
// publishing the carrier address. The web panel (3x-ui style) is served on
// loopback by the panel package.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"

	"bittorrent-tunnel/btawg/internal/panel"
	"bittorrent-tunnel/btawg/internal/server"
	"bittorrent-tunnel/btawg/internal/store"
)

func main() {
	storePath := flag.String("store", "btawg.db", "path to the bbolt database")
	transport := flag.String("transport", "", "override carrier transport (ext-utp|ext-tcp|req-utp|req-tcp)")
	carrierPort := flag.Int("carrier-port", 0, "override carrier listen port")
	externalIP := flag.String("external-ip", "", "override announced IP (autodetect if empty)")
	dhtBootstrap := flag.String("dht-bootstrap", "", "override DHT bootstrap nodes, comma-separated host:port (default: public)")
	noTun := flag.Bool("no-tun", false, "userspace netstack mode: no OS interface is created")
	tunName := flag.String("tun", "btawg0", "TUN interface name in real-TUN mode")
	flag.Parse()
	st, err := store.Open(*storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "btawg-server: open store: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	cfg, err := st.LoadServerConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "btawg-server: load config: %v\n", err)
		os.Exit(1)
	}
	if *transport != "" {
		cfg.Transport = *transport
	}
	if *carrierPort != 0 {
		cfg.CarrierPort = *carrierPort
	}
	if *externalIP != "" {
		cfg.ExternalIP = *externalIP
	}

	var srv *server.Server
	if *noTun {
		srv, err = server.New(cfg, st)
		if err != nil {
			fmt.Fprintf(os.Stderr, "btawg-server: %v\n", err)
			os.Exit(1)
		}
	} else {
		srv, err = server.NewRealTUN(cfg, st, *tunName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "btawg-server: tun setup (root required): %v\n", err)
			os.Exit(1)
		}
	}
	defer srv.Close()
	if *dhtBootstrap != "" {
		srv.SetDHTBootstrap(strings.Split(*dhtBootstrap, ","))
	}
	// New generates and persists the first-boot identity into the store;
	// reload so the save below (admin password) carries the identity too,
	// then re-apply the per-run CLI overrides.
	cfg, err = st.LoadServerConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "btawg-server: reload config: %v\n", err)
		os.Exit(1)
	}
	if *transport != "" {
		cfg.Transport = *transport
	}
	if *carrierPort != 0 {
		cfg.CarrierPort = *carrierPort
	}
	if *externalIP != "" {
		cfg.ExternalIP = *externalIP
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Panel identity: generate the admin password at first boot.
	if cfg.AdminPassHash == "" {
		pw := randomPassword()
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err == nil {
			cfg.AdminPassHash = string(hash)
			if err := st.SaveServerConfig(cfg); err == nil {
				fmt.Printf("btawg-server: panel login admin / %s (shown once, loopback :%d)\n", pw, cfg.PanelPort)
			}
		}
	}
	go func() {
		p := panel.New(st, srv, "admin", cfg.AdminPassHash)
		addr := fmt.Sprintf("127.0.0.1:%d", cfg.PanelPort)
		fmt.Printf("btawg-server: panel on http://%s (SSH port-forward to reach it)\n", addr)
		if err := http.ListenAndServe(addr, p.Handler()); err != nil {
			fmt.Fprintf(os.Stderr, "btawg-server: panel: %v\n", err)
		}
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- srv.Run(ctx) }()
	go func() { errCh <- srv.Announce(ctx) }()

	fmt.Printf("btawg-server: transport=%s carrier=:%d socks=%d infohash=%s\n",
		cfg.Transport, cfg.CarrierPort, cfg.SocksPort, srv.InfoHash())
	fmt.Println("btawg-server: DHT announce loop started (strictly-DHT discovery)")

	select {
	case <-ctx.Done():
		fmt.Println("btawg-server: shutting down")
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "btawg-server: %v\n", err)
			os.Exit(1)
		}
	}
}

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
