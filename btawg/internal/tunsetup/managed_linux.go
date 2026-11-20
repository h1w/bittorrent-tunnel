package tunsetup

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

// CreateExclusiveTUN never attaches to a pre-existing interface.
func CreateExclusiveTUN(name string, mtu int) (tun.Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_TUN_EXCL)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err == nil {
		err = unix.SetNonblock(fd, true)
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	dev, err := tun.CreateTUNFromFile(f, mtu)
	if err != nil {
		f.Close()
	}
	return dev, err
}

// MarkedRoute gives each proxy a private routing table. Unmarked overlay
// traffic takes the lowest-index available path; host default is untouched.
type MarkedRoute struct {
	mark        int
	rule, guard []string
}

func NewMarkedRoute(name string, index, mtu int, addr netip.Addr, prefixes []netip.Prefix) (*MarkedRoute, error) {
	if err := Setup(name, netip.PrefixFrom(addr, 32), nil, mtu, false); err != nil {
		return nil, err
	}
	rp := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", name)
	b, err := os.ReadFile(rp)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(b)) != "2" {
		if err := os.WriteFile(rp, []byte("2\n"), 0644); err != nil {
			return nil, err
		}
	}
	for _, p := range prefixes {
		if err := run("ip", "-4", "route", "add", p.String(), "dev", name, "src", addr.String(), "metric", strconv.Itoa(4200+index), "proto", "242"); err != nil {
			return nil, err
		}
	}
	type entry struct {
		Table    string `json:"table"`
		Priority int    `json:"priority"`
		Mark     string `json:"fwmark"`
	}
	tables := map[string]bool{}
	priorities := map[int]bool{}
	marks := map[uint64]bool{}
	for _, args := range [][]string{{"rule", "show"}, {"route", "show", "table", "all"}} {
		b, err := exec.Command("ip", append([]string{"-4", "-j", "-N"}, args...)...).Output()
		if err != nil {
			return nil, err
		}
		var entries []entry
		if err := json.Unmarshal(b, &entries); err != nil {
			return nil, err
		}
		for _, e := range entries {
			tables[e.Table] = true
			if args[0] == "rule" {
				priorities[e.Priority] = true
				m, _ := strconv.ParseUint(e.Mark, 0, 32)
				marks[m] = true
			}
		}
	}
	for slot := 0; slot < 1000; slot++ {
		table := strconv.Itoa(10000 + slot)
		priority := 1000 + 2*slot
		mark := 0x42540000 + slot
		if tables[table] || priorities[priority] || priorities[priority+1] || marks[uint64(mark)] {
			continue
		}
		if err := run("ip", "-4", "route", "add", "default", "dev", name, "src", addr.String(), "table", table, "proto", "242"); err != nil {
			return nil, err
		}
		guard := []string{"pref", strconv.Itoa(priority + 1), "fwmark", strconv.Itoa(mark), "unreachable", "protocol", "242"}
		rule := []string{"pref", strconv.Itoa(priority), "fwmark", strconv.Itoa(mark), "lookup", table, "protocol", "242"}
		if err := ipRule("add", guard); err != nil {
			return nil, err
		}
		if err := ipRule("add", rule); err != nil {
			_ = ipRule("del", guard)
			return nil, err
		}
		return &MarkedRoute{mark: mark, rule: rule, guard: guard}, nil
	}
	return nil, fmt.Errorf("no free btawg policy routing table")
}

func ipRule(op string, args []string) error {
	return run("ip", append([]string{"-4", "rule", op}, args...)...)
}

func (r *MarkedRoute) Close() error {
	return errors.Join(ipRule("del", r.rule), ipRule("del", r.guard))
}

func (r *MarkedRoute) Control(_, _ string, c syscall.RawConn) error {
	var err error
	if e := c.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, r.mark) }); e != nil {
		return e
	}
	return err
}
