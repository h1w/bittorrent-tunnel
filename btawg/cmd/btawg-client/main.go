// btawg-client runs a btawg node from a btawg:// import string: it discovers
// the hub strictly through DHT, carries AmneziaWG inside a BitTorrent
// carrier, and exposes a no-auth SOCKS5 on loopback. Real-TUN mode (default
// with root) additionally creates the btawg0 interface with the overlay
// address; it never installs a default route. Native AWG/WG modes connect
// directly to the published UDP endpoint instead of using the carrier.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

func main() {
	importFile := flag.String("config", "", "path to a file containing the btawg:// import string")
	transport := flag.String("transport", "", "transport mode (ext-utp|ext-tcp|req-utp|req-tcp|awg|wg)")
	dhtOnly := flag.Bool("dht", false, "discover the carrier through DHT instead of using the import endpoint")
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
	if *transport != "" {
		cfg.Transport = *transport
	}
	if !config.ValidClientMode(cfg.Transport) {
		fmt.Fprintf(os.Stderr, "btawg-client: unsupported transport %q (want ext-utp|ext-tcp|req-utp|req-tcp|awg|wg)\n", cfg.Transport)
		os.Exit(1)
	}
	if *dhtOnly {
		if !config.IsCarrierMode(cfg.Transport) {
			fmt.Fprintln(os.Stderr, "btawg-client: -dht is only available for carrier modes")
			os.Exit(1)
		}
		cfg.CarrierEndpoint = ""
	}

	var c *client.Client
	if *noTun {
		c, err = client.New(cfg)
	} else {
		subnet, perr := netip.ParsePrefix(cfg.Subnet)
		if perr != nil || !subnet.Addr().Is4() || subnet.Bits() == 0 {
			fmt.Fprintf(os.Stderr, "btawg-client: invalid IPv4 subnet %q\n", cfg.Subnet)
			os.Exit(1)
		}
		addr := netip.PrefixFrom(netip.MustParseAddr(cfg.ClientIP), subnet.Bits())
		if serr := tunsetup.Setup(*tunName, addr, &subnet, 1420, false); serr != nil {
			fmt.Fprintf(os.Stderr, "btawg-client: tun setup (root required): %v\n", serr)
			os.Exit(1)
		}
		if err := addRoutes(*tunName, cfg.Routes, subnet); err != nil {
			fmt.Fprintf(os.Stderr, "btawg-client: add routes: %v\n", err)
			os.Exit(1)
		}
		// Deliberately assigns the outer err: the failure of NewRealTUN
		// must reach the check below, not a shadowed copy.
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
		if config.IsNativeMode(cfg.Transport) {
			fmt.Printf("btawg-client: native %s mode\n", cfg.Transport)
			return
		}
		if cfg.CarrierEndpoint != "" {
			fmt.Printf("btawg-client: connecting directly to %s (%s)\n", cfg.CarrierEndpoint, cfg.Transport)
			return
		}
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

// addRoutes installs explicit managed CIDRs on the TUN interface. It skips
// the subnet itself (already installed by tunsetup.Setup) and the default
// route, and ignores "file exists" errors so repeated runs are idempotent.
func addRoutes(tunName string, routes []string, subnet netip.Prefix) error {
	for _, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return fmt.Errorf("parse route %q: %w", r, err)
		}
		if !p.Addr().Is4() {
			return fmt.Errorf("IPv6 route %q not supported", r)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("default route %q not allowed", r)
		}
		if p.Masked() == subnet.Masked() {
			continue
		}
		cmd := exec.Command("ip", "route", "add", p.Masked().String(), "dev", tunName)
		if out, err := cmd.CombinedOutput(); err != nil {
			msg := string(out)
			if strings.Contains(msg, "File exists") {
				continue
			}
			return fmt.Errorf("ip route add %s: %w: %s", p.String(), err, msg)
		}
	}
	return nil
}
