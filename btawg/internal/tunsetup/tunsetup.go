// Package tunsetup configures a kernel TUN interface for btawg nodes. It is
// shared between the client (address + subnet route, no ip_forward) and the
// hub (address only, ip_forward enabled so the kernel forwards peer traffic).
package tunsetup

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// Setup brings up the named TUN interface with the overlay address, optional
// subnet route, link MTU, and (for the hub) IPv4 forwarding. The address is
// given as a prefix so the interface mask is set correctly; route is nil for
// the hub because it owns the prefix directly.
func Setup(name string, addr netip.Prefix, route *netip.Prefix, mtu int, ipForward bool) error {
	if run("ip", "addr", "add", addr.String(), "dev", name) != nil {
		// Interface does not exist yet; create a persistent TUN and retry.
		if err := run("ip", "tuntap", "add", "dev", name, "mode", "tun"); err != nil {
			return err
		}
		if err := run("ip", "addr", "add", addr.String(), "dev", name); err != nil {
			return err
		}
	}
	if err := run("ip", "link", "set", "dev", name, "up"); err != nil {
		return err
	}
	if err := run("ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu)); err != nil {
		return err
	}
	if route != nil {
		if err := run("ip", "route", "add", route.String(), "dev", name); err != nil {
			return err
		}
	}
	if ipForward {
		if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return err
		}
	}
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stdout = os.Stderr
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
