package tunsetup

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

// OpenClientTUN creates a non-persistent TUN, adopting only a matching,
// detached persistent TUN left by the old foreground client.
func OpenClientTUN(name string, addr netip.Prefix, routes []string, mtu int) (tun.Device, error) {
	prefixes := make(map[netip.Prefix]bool, len(routes))
	for _, raw := range routes {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() || p.Bits() == 0 {
			return nil, fmt.Errorf("invalid overlay route %q", raw)
		}
		if p = p.Masked(); p != addr.Masked() {
			prefixes[p] = true
		}
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_TUN_EXCL)
	old, err := net.InterfaceByName(name)
	if err == nil {
		if old.Flags&net.FlagRunning != 0 {
			return nil, fmt.Errorf("interface %s is already in use", name)
		}
		if err := inspectLegacyTUN(old, addr, prefixes); err != nil {
			return nil, err
		}
		flags &^= unix.IFF_TUN_EXCL
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(flags)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err == nil {
		err = unix.SetNonblock(fd, true)
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if old != nil {
		current, err := net.InterfaceByName(name)
		if err != nil || old.Index != current.Index {
			unix.Close(fd)
			return nil, fmt.Errorf("interface %s changed while opening it", name)
		}
		if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil || ifr.Uint16()&unix.IFF_PERSIST == 0 || ifr.Uint16()&unix.IFF_MULTI_QUEUE != 0 {
			unix.Close(fd)
			return nil, fmt.Errorf("interface %s is not a persistent single-queue client TUN", name)
		}
		if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	dev, err := tun.CreateTUNFromFile(f, mtu)
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := configureClientTUN(name, addr, prefixes, mtu); err != nil {
		dev.Close()
		return nil, err
	}
	return dev, nil
}

// Only the configured address and its legacy main-table routes are ours to
// adopt. Refuse foreign state rather than removing someone else's interface.
func inspectLegacyTUN(iface *net.Interface, addr netip.Prefix, prefixes map[netip.Prefix]bool) error {
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	var ipv4 []netip.Prefix
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
			ipv4 = append(ipv4, p)
		}
	}
	if len(ipv4) != 1 || ipv4[0] != addr {
		return fmt.Errorf("interface %s must own only %s before adoption (found %v)", iface.Name, addr, ipv4)
	}
	out, err := exec.Command("ip", "-4", "-j", "route", "show", "table", "all", "dev", iface.Name).Output()
	if err != nil {
		return fmt.Errorf("inspect routes on %s: %w", iface.Name, err)
	}
	var entries []struct {
		Dst, Table, Protocol, Scope string
		Gateway                     string
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return fmt.Errorf("inspect routes on %s: %w", iface.Name, err)
	}
	for _, r := range entries {
		if r.Table == "local" && r.Protocol == "kernel" {
			continue
		}
		p, err := netip.ParsePrefix(r.Dst)
		if host, hostErr := netip.ParseAddr(r.Dst); hostErr == nil {
			p, err = netip.PrefixFrom(host, 32), nil
		}
		_, configured := prefixes[p]
		if err != nil || (r.Table != "" && r.Table != "main") || r.Scope != "link" || r.Gateway != "" || (p != addr.Masked() && !configured) {
			return fmt.Errorf("interface %s has an unexpected IPv4 route to %s", iface.Name, r.Dst)
		}
		// This configured route already exists on the interface.
		if p != addr.Masked() {
			prefixes[p] = false
		}
	}
	return nil
}

func configureClientTUN(name string, addr netip.Prefix, prefixes map[netip.Prefix]bool, mtu int) error {
	if err := setupLink(name, addr, mtu); err != nil {
		return err
	}
	// Public SOCKS replies arrive over TUN while the host's unbound default
	// route still points at the WAN. Relax reverse-path checking only here.
	rp := "/proc/sys/net/ipv4/conf/" + name + "/rp_filter"
	b, err := os.ReadFile(rp)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != "2" {
		if err := os.WriteFile(rp, []byte("2\n"), 0644); err != nil {
			return err
		}
	}
	for p, missing := range prefixes {
		if !missing {
			continue
		}
		if err := run("ip", "-4", "route", "add", p.String(), "dev", name, "metric", "4200", "proto", "242"); err != nil {
			return err
		}
	}
	return nil
}
