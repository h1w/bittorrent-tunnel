// Package mesh defines the hub control messages for managed clients.
package mesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"
)

const (
	ControlPort   = 1054
	EgressPort    = 1055
	RelayPort     = 1056
	PeerProbePort = 1057
	HubRoute      = "hub"
	Lease         = 15 * time.Second
	Poll          = 2 * time.Second
	MaxRequest    = 32 << 10
	MaxReply      = 512 << 10
	MaxPeers      = 32
	MaxPeerOffers = MaxPeers * 10 * 2
	Path          = "/v1/mesh"
)

const MaxPeerOverrides = 32

// Node identifies one enrollment independently of its current overlay address.
type Node struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	IP  string `json:"ip"`
}

type Candidate struct {
	Addr     netip.AddrPort `json:"addr"`
	Kind     string         `json:"kind"`
	Protocol string         `json:"protocol,omitempty"` // empty is UDP
	Mode     string         `json:"mode,omitempty"`     // native UDP candidates are mode-specific
	Receive  bool           `json:"receive,omitempty"`  // native socket accepts new flows
}

// PeerModes carries effective directional lists for one counterpart. Empty
// lists deny that direction; an absent map entry uses the global lists.
type PeerModes struct {
	Incoming []string `json:"incoming_modes,omitempty"`
	Outgoing []string `json:"outgoing_modes,omitempty"`
}

func ValidPeerOverrideIP(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsUnspecified() && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

type Registration struct {
	DirectKey       string                   `json:"key,omitempty"`
	Candidates      []Candidate              `json:"candidates,omitempty"`
	Want            []netip.Addr             `json:"want,omitempty"`
	Egress          bool                     `json:"egress,omitempty"`
	TransportPolicy bool                     `json:"transport_policy,omitempty"`
	IncomingModes   []string                 `json:"incoming_modes,omitempty"`
	OutgoingModes   []string                 `json:"outgoing_modes,omitempty"`
	TLSPin          string                   `json:"tls_pin,omitempty"`
	PeerOverrides   map[netip.Addr]PeerModes `json:"peer_overrides,omitempty"`
}

func (r Registration) ModesForPeer(ip netip.Addr) PeerModes {
	if modes, ok := r.PeerOverrides[ip]; ok {
		return modes
	}
	return PeerModes{Incoming: r.IncomingModes, Outgoing: r.OutgoingModes}
}

type Pair struct {
	IP         netip.Addr  `json:"ip"`
	Key        string      `json:"key"`
	Secret     [32]byte    `json:"secret"`
	Initiator  bool        `json:"initiator"`
	Candidates []Candidate `json:"candidates"`
	Expires    time.Time   `json:"expires"`
	Mode       string      `json:"mode,omitempty"`
	Origin     netip.Addr  `json:"origin,omitempty"` // initiator of flows, not just the physical connection
}

type Route struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	First netip.Addr `json:"first,omitempty"`
	Grant string     `json:"grant,omitempty"`
}

type Check struct {
	ID       string     `json:"id"`
	Grant    string     `json:"grant"`
	Previous netip.Addr `json:"previous"`
	Hop      int        `json:"hop"`
	Renew    bool       `json:"renew,omitempty"`
	Session  string     `json:"session,omitempty"`
}

type Request struct {
	Registration *Registration `json:"registration,omitempty"`
	Check        *Check        `json:"check,omitempty"`
}

type Reply struct {
	Routes       []Route        `json:"routes,omitempty"`
	Pairs        []Pair         `json:"pairs,omitempty"`
	Next         netip.Addr     `json:"next,omitempty"`
	Gateways     []netip.Addr   `json:"gateways,omitempty"`
	Prefixes     []netip.Prefix `json:"prefixes,omitempty"`
	PeerPrefixes []netip.Prefix `json:"peer_prefixes,omitempty"`
	Session      string         `json:"session,omitempty"`
}

type Grant struct {
	RouteID       string `json:"route_id"`
	Origin        Node   `json:"origin"`
	Hops          []Node `json:"hops"`
	Expires       int64  `json:"expires"`
	Authorization uint64 `json:"authorization"`
}

func (g Grant) Matches(id string, origin Node, hops []Node) bool {
	return id == g.RouteID && origin == g.Origin && slices.Equal(hops, g.Hops)
}
func SealGrant(key [32]byte, id string, origin Node, hops []Node, now time.Time, authorization uint64) (string, error) {
	if len(hops) < 1 || len(hops) > 2 {
		return "", errors.New("invalid route size")
	}
	b, err := json.Marshal(Grant{id, origin, hops, now.Add(Lease).UnixMilli(), authorization})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(append(b, sign(key, b)...)), nil
}

func OpenGrant(key [32]byte, token string, now time.Time) (Grant, error) {
	return openGrant(key, token, now, false)
}

// RenewGrant verifies a token for a session already admitted at a route node.
// It is never used for a new stream, which requires OpenGrant.
func RenewGrant(key [32]byte, token string) (Grant, error) {
	return openGrant(key, token, time.Time{}, true)
}

func openGrant(key [32]byte, token string, now time.Time, renew bool) (Grant, error) {
	var g Grant
	if len(token) > 2048 {
		return g, errors.New("grant too large")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(b) <= sha256.Size {
		return g, errors.New("invalid route grant")
	}
	body, mac := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	if !hmac.Equal(mac, sign(key, body)) || json.Unmarshal(body, &g) != nil || len(g.Hops) < 1 || len(g.Hops) > 2 || !renew && g.Expires <= now.UnixMilli() {
		return Grant{}, errors.New("invalid or expired route grant")
	}
	return g, nil
}

func sign(key [32]byte, body []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("btawg/egress-grant/v1\x00"))
	mac.Write(body)
	return mac.Sum(nil)
}
