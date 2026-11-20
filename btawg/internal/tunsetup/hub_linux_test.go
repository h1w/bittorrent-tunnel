package tunsetup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"net/netip"
)

func TestHubNonRootFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root test: root would succeed")
	}
	hub, err := NewHub("btawghubroot0")
	if err != nil {
		t.Fatalf("NewHub failed: %v", err)
	}
	gateways := []netip.Prefix{netip.MustParsePrefix("10.199.0.1/24")}
	err = hub.Apply(gateways)
	if err == nil {
		t.Fatal("expected Apply to fail without root")
	}
	if !strings.Contains(err.Error(), "btawghubroot0") {
		t.Fatalf("error %q does not name the interface", err)
	}
}

func TestHubNFTRender(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}

	hub, err := NewHub("btawgrender0")
	if err != nil {
		t.Fatalf("NewHub failed: %v", err)
	}
	gateways := []netip.Prefix{
		netip.MustParsePrefix("10.200.0.1/24"),
		netip.MustParsePrefix("10.201.0.1/24"),
	}
	script := hub.nftScript(gateways, "eth999", false)

	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") {
			t.Skip("nft syntax check requires privileges")
		}
		t.Fatalf("nft syntax check failed: %v\nscript:\n%s\nnft output:\n%s", err, script, out)
	}
}

func TestHubRequiresRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for live hub setup")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}

	name := "btawghubtest0"
	table := "btawg_" + name
	gateways := []netip.Prefix{
		netip.MustParsePrefix("10.200.0.1/24"),
		netip.MustParsePrefix("10.201.0.1/24"),
	}

	// Create and bring up a throw-away TUN, as the production caller would.
	_ = exec.Command("ip", "tuntap", "del", "dev", name, "mode", "tun").Run()
	if err := exec.Command("ip", "tuntap", "add", "dev", name, "mode", "tun").Run(); err != nil {
		t.Fatalf("create TUN: %v", err)
	}
	defer func() {
		_ = exec.Command("ip", "tuntap", "del", "dev", name, "mode", "tun").Run()
	}()
	if err := exec.Command("ip", "link", "set", "dev", name, "up", "mtu", "1420", "txqueuelen", "8192").Run(); err != nil {
		t.Fatalf("bring up TUN: %v", err)
	}

	ipFwdPath := "/proc/sys/net/ipv4/ip_forward"
	oldFwd, _ := os.ReadFile(ipFwdPath)
	defer func() {
		if oldFwd != nil {
			_ = os.WriteFile(ipFwdPath, oldFwd, 0o644)
		}
	}()

	hub, err := NewHub(name)
	if err != nil {
		t.Fatalf("NewHub failed: %v", err)
	}
	defer hub.Close()

	if err := hub.Apply(gateways); err != nil {
		if strings.Contains(err.Error(), "detect WAN interface") {
			t.Skipf("no usable default WAN route: %v", err)
		}
		t.Fatalf("Apply failed: %v", err)
	}

	// Addresses were assigned.
	out, err := exec.Command("ip", "addr", "show", "dev", name).Output()
	if err != nil {
		t.Fatalf("ip addr show: %v", err)
	}
	for _, g := range gateways {
		if !strings.Contains(string(out), g.String()) {
			t.Fatalf("address %s missing from interface output:\n%s", g, out)
		}
	}

	// IPv4 forwarding is enabled.
	fwd, err := os.ReadFile(ipFwdPath)
	if err != nil {
		t.Fatalf("read ip_forward: %v", err)
	}
	if v, _ := strconv.Atoi(strings.TrimSpace(string(fwd))); v != 1 {
		t.Fatalf("ip_forward = %s, want 1", fwd)
	}

	// Scoped nftables table contains the expected rules.
	nftout, err := exec.Command("nft", "list", "table", "ip", table).Output()
	if err != nil {
		t.Fatalf("nft list table: %v", err)
	}
	s := string(nftout)
	if !strings.Contains(s, "established,related") {
		t.Fatalf("missing established/related rule:\n%s", s)
	}
	if !strings.Contains(s, "masquerade") {
		t.Fatalf("missing masquerade rule:\n%s", s)
	}
	for _, g := range gateways {
		if !strings.Contains(s, g.String()) {
			t.Fatalf("missing gateway %s in nft rules:\n%s", g, s)
		}
	}
	if !strings.Contains(s, "counter drop") {
		t.Fatalf("missing default drop rules:\n%s", s)
	}
	if !strings.Contains(s, "__btawg_marker") {
		t.Fatalf("missing management marker:\n%s", s)
	}
	if !strings.Contains(s, "oifname \""+name+"\"") {
		t.Fatalf("missing overlay/return forward target to the TUN itself:\n%s", s)
	}

	// Re-Apply with a different gateway set: the obsolete address is removed
	// and the new one is added.
	newGateways := []netip.Prefix{netip.MustParsePrefix("10.202.0.1/24")}
	if err := hub.Apply(newGateways); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	out, err = exec.Command("ip", "addr", "show", "dev", name).Output()
	if err != nil {
		t.Fatalf("ip addr show after re-apply: %v", err)
	}
	for _, g := range gateways {
		if strings.Contains(string(out), g.String()) {
			t.Fatalf("obsolete address %s still present after re-apply", g)
		}
	}
	if !strings.Contains(string(out), newGateways[0].String()) {
		t.Fatalf("new address %s missing after re-apply:\n%s", newGateways[0], out)
	}
	nftout, err = exec.Command("nft", "list", "table", "ip", table).Output()
	if err != nil {
		t.Fatalf("nft list table after re-apply: %v", err)
	}
	if strings.Contains(string(nftout), gateways[0].String()) {
		t.Fatalf("obsolete gateway still present in nft rules after re-apply")
	}
	if !strings.Contains(string(nftout), newGateways[0].String()) {
		t.Fatalf("new gateway missing in nft rules after re-apply")
	}

	// Close removes the scoped table and addresses.
	if err := hub.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := exec.Command("nft", "list", "table", "ip", table).Run(); err == nil {
		t.Fatal("scoped nftables table still exists after Close")
	}
	out, _ = exec.Command("ip", "addr", "show", "dev", name).Output()
	for _, g := range newGateways {
		if strings.Contains(string(out), g.String()) {
			t.Fatalf("address %s still present after Close", g)
		}
	}
}

func TestHubDoesNotClobberUnrelatedTable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for live nftables test")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}

	name := "btawghubunrel0"
	table := "btawg_" + name

	// Pre-create an unrelated table with the same name.
	script := fmt.Sprintf("delete table ip %s\ntable ip %s { set unrelated { type ipv4_addr; } }\n", table, table)
	dir := t.TempDir()
	f := filepath.Join(dir, "unrelated.nft")
	if err := os.WriteFile(f, []byte(script), 0o644); err != nil {
		t.Fatalf("write unrelated ruleset: %v", err)
	}
	defer func() { _ = exec.Command("nft", "delete", "table", "ip", table).Run() }()
	if err := exec.Command("nft", "-f", f).Run(); err != nil {
		t.Fatalf("create unrelated table: %v", err)
	}

	hub, err := NewHub(name)
	if err != nil {
		t.Fatalf("NewHub failed: %v", err)
	}
	defer hub.Close()

	err = hub.Apply([]netip.Prefix{netip.MustParsePrefix("10.202.0.1/24")})
	if err == nil {
		t.Fatal("expected Apply to fail when an unrelated table with the same name exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error does not mention existing table: %v", err)
	}

	// The unrelated table must still be present.
	if err := exec.Command("nft", "list", "table", "ip", table).Run(); err != nil {
		t.Fatalf("unrelated table was clobbered: %v", err)
	}
}
