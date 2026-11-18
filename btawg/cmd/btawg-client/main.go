// btawg-client runs a btawg node from a btawg:// import string: it discovers
// the hub strictly through DHT, carries AmneziaWG inside a BitTorrent
// carrier, and exposes a no-auth SOCKS5 on loopback. Real-TUN mode (default
// with root) additionally creates the btawg0 interface with the overlay
// address; it never installs a default route.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

func main() {
	importFile := flag.String("config", "", "path to a file containing the btawg:// import string")
	noTun := flag.Bool("no-tun", false, "userspace netstack mode: no OS interface is created")
	tunName := flag.String("tun", "btawg0", "TUN interface name in real-TUN mode")
	flag.Parse()

	raw := strings.TrimSpace(flag.Arg(0))
	if raw == "" && *importFile != "" {
		b, err := os.ReadFile(*importFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "btawg-client: read config: %v\n", err)
			os.Exit(1)
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		fmt.Fprintln(os.Stderr, "btawg-client: pass the btawg:// import string as the argument or -config FILE")
		os.Exit(1)
	}
	cfg, err := config.ParseImportString(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "btawg-client: %v\n", err)
		os.Exit(1)
	}

	var c *client.Client
	if *noTun {
		c, err = client.New(cfg)
	} else {
		subnet, err := netip.ParsePrefix(cfg.Subnet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "btawg-client: parse subnet: %v\n", err)
			os.Exit(1)
		}
		addr := netip.PrefixFrom(netip.MustParseAddr(cfg.ClientIP), subnet.Bits())
		if err := tunsetup.Setup(*tunName, addr, &subnet, 1420, false); err != nil {
			fmt.Fprintf(os.Stderr, "btawg-client: tun setup (root required): %v\n", err)
			os.Exit(1)
		}
		c, err = client.NewRealTUN(cfg, *tunName)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "btawg-client: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		fmt.Printf("btawg-client: connecting via DHT (infohash %s)...\n", cfg.InfoHash)
	}()
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx) }()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("btawg-client: shutting down")
			return
		case err := <-errCh:
			if err != nil {
				fmt.Fprintf(os.Stderr, "btawg-client: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
}
