package tunsetup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// ProxyRoute provides an IPv4 default only for sockets bound to the TUN.
// The main routing table and unbound sockets are unaffected.
type ProxyRoute struct {
	name, table, priority string
	bind                  func(string, string, syscall.RawConn) error
	once                  sync.Once
	closeErr              error
}

// NewProxyRoute installs a per-interface policy rule and a private table.
func NewProxyRoute(name string) (*ProxyRoute, error) {
	type item struct {
		Table    string `json:"table"`
		Priority int    `json:"priority"`
	}
	usedTables := make(map[string]bool)
	usedPriorities := make(map[int]bool)
	for _, args := range [][]string{{"rule", "show"}, {"route", "show", "table", "all"}} {
		cmd := exec.Command("ip", append([]string{"-4", "-j", "-N"}, args...)...)
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("inspect IPv4 %s: %w", args[0], err)
		}
		var items []item
		if err := json.Unmarshal(out, &items); err != nil {
			return nil, fmt.Errorf("parse IPv4 %s: %w", args[0], err)
		}
		for _, i := range items {
			usedTables[i.Table] = true
			if args[0] == "rule" {
				usedPriorities[i.Priority] = true
			}
		}
	}
	r := &ProxyRoute{name: name, bind: BindDevice(name)}
	for i := 10000; i < 11000; i++ {
		if table := strconv.Itoa(i); !usedTables[table] {
			r.table = table
			break
		}
	}
	for i := 1; i < 9000; i++ {
		if !usedPriorities[i] {
			r.priority = strconv.Itoa(i)
			break
		}
	}
	if r.table == "" || r.priority == "" {
		return nil, errors.New("no free routing table or priority for SOCKS TUN")
	}
	if err := r.route("add"); err != nil {
		return nil, err
	}
	if err := r.rule("add"); err != nil {
		return nil, errors.Join(err, r.route("del"))
	}
	return r, nil
}

func (r *ProxyRoute) route(op string) error {
	return run("ip", "-4", "route", op, "default", "dev", r.name, "table", r.table, "proto", "242")
}

func (r *ProxyRoute) rule(op string) error {
	return run("ip", "-4", "rule", op, "pref", r.priority, "oif", r.name, "lookup", r.table, "protocol", "242")
}

// Close removes only the rule and route installed by this instance.
func (r *ProxyRoute) Close() error {
	r.once.Do(func() {
		for _, err := range []error{r.rule("del"), r.route("del")} {
			if err != nil && !notExists(err) && !strings.Contains(err.Error(), "No such process") {
				r.closeErr = errors.Join(r.closeErr, err)
			}
		}
	})
	return r.closeErr
}

// Control pins a socket to the TUN even if its policy route disappears.
func (r *ProxyRoute) Control(network, address string, conn syscall.RawConn) error {
	return r.bind(network, address, conn)
}
