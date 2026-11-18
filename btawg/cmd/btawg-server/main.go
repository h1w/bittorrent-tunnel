// btawg-server runs the btawg hub: AmneziaWG inside a BitTorrent carrier,
// an egress SOCKS5 reachable only inside the overlay, and a DHT announcer
// publishing the carrier address. The web panel (3x-ui style) is served on
// loopback by the panel package.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"bittorrent-tunnel/btawg/internal/server"
	"bittorrent-tunnel/btawg/internal/store"
)

func main() {
	storePath := flag.String("store", "btawg.db", "path to the bbolt database")
	transport := flag.String("transport", "", "override carrier transport (ext-utp|ext-tcp|req-utp|req-tcp)")
	carrierPort := flag.Int("carrier-port", 0, "override carrier listen port")
	externalIP := flag.String("external-ip", "", "override announced IP (autodetect if empty)")
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

	srv, err := server.New(cfg, st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "btawg-server: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
