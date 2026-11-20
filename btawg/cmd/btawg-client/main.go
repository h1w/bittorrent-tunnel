// btawg-client is the VPN client binary. It installs and manages its systemd
// service, runs the managed multi-mode daemon, or opens a TUI to toggle
// connection modes and view/rotate the shared SOCKS5 credentials. A bare
// import string still runs a single foreground connection for compatibility.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/service"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "install":
			if err := installMain(os.Args[2:]); err != nil {
				fatal(err)
			}
			return
		case "run":
			if err := runMain(os.Args[2:]); err != nil {
				fatal(err)
			}
			return
		}
	}
	if err := legacyOrTUI(os.Args[1:]); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "btawg-client: %v\n", err)
	os.Exit(1)
}

// installMain persists the client configuration and installs the systemd
// service. The import secret is read from a file or a hidden prompt and is
// never placed in unit arguments.
func installMain(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	importFile := fs.String("import-file", "", "file containing the btawg:// import string (secret)")
	socksListen := fs.String("socks-listen", "127.0.0.1", "SOCKS5 listen IPv4 address")
	noTun := fs.Bool("no-tun", false, "userspace netstack mode: no OS interface")
	tunName := fs.String("tun", "btawg0", "TUN interface name prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("install must run as root")
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("use -import-file or the hidden terminal prompt")
	}
	mc, err := client.LoadManagedConfig(client.ManagedConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		raw, err := readImport(*importFile)
		if err != nil {
			return err
		}
		cfg, err := config.ParseImportString(raw)
		if err != nil {
			return err
		}
		mode := config.CanonicalMode(cfg.Transport)
		if !config.ValidClientMode(mode) {
			return fmt.Errorf("unsupported import mode %q", mode)
		}
		ip, err := netip.ParseAddr(*socksListen)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("-socks-listen requires an IPv4 address")
		}
		creds, err := client.GenerateCredentials()
		if err != nil {
			return err
		}
		mc = client.ManagedConfig{Import: raw, Enabled: []string{mode}, ListenIP: ip.String(), Credentials: creds, NoTUN: *noTun, TUNName: *tunName}
		if err := mc.Save(client.ManagedConfigPath); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if fs.NFlag() != 0 {
		return fmt.Errorf("client already configured; run install without flags to upgrade")
	}
	if err := service.Client.Install(); err != nil {
		return err
	}
	fmt.Println("btawg-client: installed and started; use sudo btawg-client to view SOCKS5 credentials")
	return nil
}

// readImport reads the import secret from a file or a hidden terminal prompt.
func readImport(path string) (string, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("pass -import-file FILE or run in a terminal to type the import")
	}
	fmt.Fprint(os.Stderr, "btawg-client: paste btawg:// import string: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// runMain runs either the managed daemon (`run -managed`, started by systemd)
// or a single foreground connection (`run <import>`).
func runMain(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	managed := fs.Bool("managed", false, "run as the managed multi-mode daemon")
	noTun := fs.Bool("no-tun", false, "userspace netstack mode")
	tunName := fs.String("tun", "btawg0", "TUN interface name prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *managed {
		return runManaged(*noTun, *tunName)
	}
	raw := strings.TrimSpace(fs.Arg(0))
	if raw == "" {
		return fmt.Errorf("run: pass the btawg:// import string or -managed")
	}
	return runSingle(raw, *noTun, *tunName)
}

func runManaged(noTun bool, tunName string) error {
	mc, err := client.LoadManagedConfig(client.ManagedConfigPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", client.ManagedConfigPath, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if mc.TUNName != "" {
		tunName = mc.TUNName
	}
	return client.RunManaged(ctx, mc, !noTun && !mc.NoTUN, tunName)
}

// legacyOrTUI runs a bare import string (single foreground connection) or the
// TUI when no import is given.
func legacyOrTUI(args []string) error {
	fs := flag.NewFlagSet("btawg-client", flag.ExitOnError)
	importFile := fs.String("config", "", "file containing the btawg:// import string")
	transport := fs.String("transport", "", "connection chain")
	dhtOnly := fs.Bool("dht", false, "discover the carrier through DHT")
	noTun := fs.Bool("no-tun", false, "userspace netstack mode")
	socksListen := fs.String("socks-listen", "127.0.0.1", "SOCKS5 listen IPv4 address")
	tunName := fs.String("tun", "btawg0", "TUN interface name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw := strings.TrimSpace(fs.Arg(0))
	if raw == "" && *importFile != "" {
		b, err := os.ReadFile(*importFile)
		if err != nil {
			return err
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return client.RunTUI()
	}
	if *transport != "" || *dhtOnly || *socksListen != "127.0.0.1" {
		return runSingleOpts(raw, *transport, *dhtOnly, *socksListen, *noTun, *tunName)
	}
	return runSingle(raw, *noTun, *tunName)
}

func runSingle(raw string, noTun bool, tunName string) error {
	return runSingleOpts(raw, "", false, "127.0.0.1", noTun, tunName)
}

// runSingleOpts keeps the original single-connection foreground behavior.
func runSingleOpts(raw, transport string, dhtOnly bool, socksListen string, noTun bool, tunName string) error {
	cfg, err := config.ParseImportString(raw)
	if err != nil {
		return err
	}
	listenIP, err := netip.ParseAddr(socksListen)
	if err != nil || !listenIP.Is4() {
		return fmt.Errorf("-socks-listen requires an IPv4 address")
	}
	cfg.SocksListenIP = listenIP
	if transport != "" {
		cfg.Transport = transport
	}
	cfg.Transport = config.CanonicalMode(cfg.Transport)
	if !config.ValidClientMode(cfg.Transport) {
		return fmt.Errorf("unsupported transport %q (want %s)", cfg.Transport, strings.Join(config.ClientModes(), "|"))
	}
	if dhtOnly {
		if !config.IsCarrierMode(cfg.Transport) {
			return fmt.Errorf("-dht is only available for carrier modes")
		}
		cfg.CarrierEndpoint = ""
	}

	var c *client.Client
	if noTun {
		c, err = client.New(cfg)
	} else {
		subnet, perr := netip.ParsePrefix(cfg.Subnet)
		if perr != nil || !subnet.Addr().Is4() || subnet.Bits() == 0 {
			return fmt.Errorf("invalid IPv4 subnet %q", cfg.Subnet)
		}
		addr := netip.PrefixFrom(netip.MustParseAddr(cfg.ClientIP), subnet.Bits())
		if serr := tunsetup.Setup(tunName, addr, &subnet, config.DefaultMTU, false); serr != nil {
			return fmt.Errorf("tun setup (root required): %w", serr)
		}
		if err := addRoutes(tunName, cfg.Routes, subnet); err != nil {
			return fmt.Errorf("add routes: %w", err)
		}
		c, err = client.NewRealTUN(cfg, tunName)
	}
	if err != nil {
		return err
	}
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.Run(ctx); err != nil {
		return err
	}
	return nil
}

// addRoutes installs explicit managed CIDRs on the TUN interface. It skips the
// subnet itself and any default route, and ignores duplicate additions.
func addRoutes(tunName string, routes []string, subnet netip.Prefix) error {
	for _, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return fmt.Errorf("parse route %q: %w", r, err)
		}
		if !p.Addr().Is4() || p.Bits() == 0 {
			continue
		}
		if p.Masked() == subnet.Masked() {
			continue
		}
		cmd := exec.Command("ip", "route", "add", p.Masked().String(), "dev", tunName)
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "File exists") {
				continue
			}
			return fmt.Errorf("ip route add %s: %w: %s", p.Masked().String(), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
