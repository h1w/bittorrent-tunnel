// Package config defines the btawg configuration formats: the AWG obfuscation
// profile, the versioned client import string (btawg:// + base64url JSON), and
// the server-side hub configuration. The import string is a secret: it carries
// the client's private key. It never contains the server's public endpoint;
// clients learn the server address strictly through DHT discovery.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ImportPrefix identifies a btawg client import string.
const ImportPrefix = "btawg://"

// ClientVersion is the only import-string format version accepted by
// ParseImportString.
const ClientVersion = 1

// AWGProfile holds the AmneziaWG obfuscation parameters shared by the server
// hub and every client.
type AWGProfile struct {
	JC   int `json:"jc"`
	JMin int `json:"jmin"`
	JMax int `json:"jmax"`
	S1   int `json:"s1"`
	S2   int `json:"s2"`
	S3   int `json:"s3"`
	S4   int `json:"s4"`
	H1   int `json:"h1"`
	H2   int `json:"h2"`
	H3   int `json:"h3"`
	H4   int `json:"h4"`
}

// DefaultProfile returns the validated transport profile: extended (BEP 10)
// over µTP no-Nagle was benchmarked at +0.07 ms p95 versus bare AWG with this
// exact AmneziaWG parameter set.
func DefaultProfile() AWGProfile {
	return AWGProfile{JC: 4, JMin: 40, JMax: 100, S1: 32, S2: 32, S3: 32, S4: 32, H1: 101, H2: 102, H3: 103, H4: 104}
}

// String renders the profile in the line-oriented name=value form consumed by
// the AmneziaWG engine's IpcSet.
func (p AWGProfile) String() string {
	return fmt.Sprintf("jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n",
		p.JC, p.JMin, p.JMax, p.S1, p.S2, p.S3, p.S4, p.H1, p.H2, p.H3, p.H4)
}

// ClientConfig is the full client bootstrap state carried in the import string
// issued by the server panel. ServerIP is the overlay hub address, not a
// reachable endpoint: it exists only inside the tunnel.
type ClientConfig struct {
	Version       int        `json:"version"`
	InfoHash      string     `json:"infohash"`      // 20-byte hex
	ServerPubKey string     `json:"server_pubkey"` // hex
	ClientPrivKey string     `json:"client_privkey"` // hex (secret)
	ClientPubKey  string     `json:"client_pubkey"` // hex
	ClientIP      string     `json:"client_ip"`     // overlay, e.g. 10.77.0.2
	Subnet        string     `json:"subnet"`        // overlay, e.g. 10.77.0.0/24
	ServerIP      string     `json:"server_ip"`     // overlay hub, e.g. 10.77.0.1
	Transport     string     `json:"transport"`     // ext-utp|ext-tcp|req-utp|req-tcp
	SocksPort     int        `json:"socks_port"`    // client's local no-auth SOCKS5
	EgressPort    int        `json:"egress_port"`   // hub's overlay SOCKS5 the chain targets
	Profile       AWGProfile `json:"awg_profile"`
	DHTBootstrap  []string   `json:"dht_bootstrap,omitempty"`
}

// ImportString encodes the config as btawg:// + base64url(JSON).
func (c ClientConfig) ImportString() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal client config: %w", err)
	}
	return ImportPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseImportString decodes and validates a btawg:// import string.
func ParseImportString(s string) (ClientConfig, error) {
	var c ClientConfig
	if !strings.HasPrefix(s, ImportPrefix) {
		return c, fmt.Errorf("import string must start with %q", ImportPrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, ImportPrefix))
	if err != nil {
		return c, fmt.Errorf("decode import string: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse import string: %w", err)
	}
	if c.Version != ClientVersion {
		return c, fmt.Errorf("unsupported import string version %d (want %d)", c.Version, ClientVersion)
	}
	return c, nil
}

// ServerConfig is the persistent hub configuration edited through the web
// panel. ExternalIP is the announced carrier address; empty means autodetect
// from the default-route interface.
type ServerConfig struct {
	AWGProfile    AWGProfile `json:"awg_profile"`
	Subnet        string     `json:"subnet"`
	ServerIP      string     `json:"server_ip"`
	Transport     string     `json:"transport"`
	CarrierPort   int        `json:"carrier_port"`
	SocksPort     int        `json:"socks_port"`
	PanelPort     int        `json:"panel_port"`
	ExternalIP    string     `json:"external_ip"`
	InfoHash      string     `json:"infohash"`       // 20-byte hex, generated at first boot
	ServerPrivKey string     `json:"server_privkey"` // hex (secret), generated at first boot
	AdminPassHash string     `json:"admin_pass_hash"` // bcrypt hash of the panel password
}

// DefaultServerConfig returns the shipped defaults used when the store has no
// saved configuration yet.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		AWGProfile:  DefaultProfile(),
		Subnet:     "10.77.0.0/24",
		ServerIP:   "10.77.0.1",
		Transport:  "ext-utp",
		CarrierPort: 7777,
		SocksPort:  1080,
		PanelPort:  8080,
	}
}
