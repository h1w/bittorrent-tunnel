package client

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"bittorrent-tunnel/btawg/internal/service"
)

// ManagedConfigPath is the root-owned client configuration file.
const ManagedConfigPath = "/etc/btawg/client.json"

// ControlSocketPath is the root-only Unix socket the daemon serves for live
// TUI control.
const ControlSocketPath = "/run/btawg-client/control.sock"

// ManagedConfig is the durable client state: the import secret, the enabled
// connection modes, the SOCKS5 bind address, and the shared credentials. It
// lives under /etc/btawg and survives upgrades and restarts.
type ManagedConfig struct {
	Import      string      `json:"import"`
	Enabled     []string    `json:"enabled"`
	ListenIP    string      `json:"listen_ip"`
	Credentials Credentials `json:"credentials"`
	NoTUN       bool        `json:"no_tun,omitempty"`
	TUNName     string      `json:"tun_name,omitempty"`
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
