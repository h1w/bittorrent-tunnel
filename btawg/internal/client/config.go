package client

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/mesh"
	"bittorrent-tunnel/btawg/internal/service"
)

// ManagedConfigPath is the root-owned client configuration file.
const ManagedConfigPath = "/etc/btawg/client.json"

// ControlSocketPath is the root-only Unix socket the daemon serves for live
// TUI control.
const ControlSocketPath = "/run/btawg-client/control.sock"

// HubRouteID names the server egress and is the default for unconfigured ports.
const HubRouteID = mesh.HubRoute

// RouteOption is one egress route currently permitted by the hub.
type RouteOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ManagedConfig is the root-owned client configuration and persists across
// upgrades and restarts.
type ManagedConfig struct {
	Import      string      `json:"import"`
	Enabled     []string    `json:"enabled"`
	ListenIP    string      `json:"listen_ip"`
	Credentials Credentials `json:"credentials"`
	NoTUN       bool        `json:"no_tun,omitempty"`
	TUNName     string      `json:"tun_name,omitempty"`
	// A missing balancer pool follows Enabled; an empty list routes nothing.
	Balancers map[string][]string `json:"balancers,omitempty"`
	// Missing entries use the hub; explicit choices survive catalogue changes.
	Routes       map[int]string `json:"routes,omitempty"`
	P2P          bool           `json:"p2p,omitempty"`
	AutoMap      bool           `json:"auto_map,omitempty"`
	ServeEgress  bool           `json:"serve_egress,omitempty"`
	PeerPort     uint16         `json:"peer_port,omitempty"` // zero lets the OS allocate a port
	PeerEndpoint string         `json:"peer_endpoint,omitempty"`
}

func selectedRouteID(routes map[int]string, port int) string {
	if id := routes[port]; id != "" {
		return id
	}
	return HubRouteID
}

var globalIPv6 = netip.MustParsePrefix("2000::/3")

func (c ManagedConfig) validatePeerSettings(realTUN bool) error {
	if c.P2P && (!realTUN || c.NoTUN) {
		return fmt.Errorf("direct peer connections require a TUN interface")
	}
	if c.AutoMap && !c.P2P {
		return fmt.Errorf("automatic peer port mapping requires P2P")
	}
	if c.PeerEndpoint != "" {
		endpoint, err := netip.ParseAddrPort(c.PeerEndpoint)
		ip := endpoint.Addr()
		if err != nil || endpoint.Port() == 0 || ip.Zone() != "" || ip.Is4In6() ||
			!config.PublicIPv4(ip) && !globalIPv6.Contains(ip) {
			return fmt.Errorf("public P2P UDP address must be a public IPv4 or global IPv6 address with a nonzero port")
		}
	}
	return nil
}

// LoadManagedConfig reads the client configuration from path.
func LoadManagedConfig(path string) (ManagedConfig, error) {
	var c ManagedConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, nil
}

// Save writes the configuration atomically with root-only permissions.
func (c ManagedConfig) Save(path string) error {
	if err := c.validatePeerSettings(!c.NoTUN); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return service.WriteFile(path, b, 0o600)
}

// GenerateCredentials returns a fresh random SOCKS5 username/password pair.
func GenerateCredentials() (Credentials, error) {
	user, err := randomToken(6)
	if err != nil {
		return Credentials{}, err
	}
	pass, err := randomToken(18)
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{Username: "btawg-" + user, Password: pass}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
