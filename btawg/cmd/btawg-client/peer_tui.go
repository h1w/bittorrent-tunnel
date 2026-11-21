package main

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"bittorrent-tunnel/btawg/internal/client"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/mesh"
	"bittorrent-tunnel/btawg/internal/service"
)

type peerRequester func(client.ControlRequest) (client.ControlResponse, bool, error)

type peerEditor struct {
	request peerRequester
	ip      netip.Addr // invalid means global defaults
}

func (e peerEditor) load() (client.PeerSettings, error) {
	status, err := e.status()
	return status.Peer, err
}

func (e peerEditor) status() (client.ControlResponse, error) {
	status, _, err := e.request(client.ControlRequest{Op: "status"})
	if err != nil {
		return client.ControlResponse{}, err
	}
	if _, ok := status.Peer.Overrides[e.ip]; e.ip.IsValid() && !ok {
		return client.ControlResponse{}, fmt.Errorf("no override for %s", e.ip)
	}
	return status, nil
}

func savePeer(request peerRequester, settings client.PeerSettings, revision string) error {
	_, _, err := request(client.ControlRequest{Op: "set-peer", Peer: &settings, PeerRevision: revision})
	return err
}

// Reread defaults before changing a field so older screens do not reset other settings.
func (e peerEditor) update(change func(*client.PeerOverride)) (*service.Screen, error) {
	status, err := e.status()
	if err != nil {
		return nil, err
	}
	settings := status.Peer
	if e.ip.IsValid() {
		entry := settings.Overrides[e.ip]
		change(&entry)
		settings.Overrides = maps.Clone(settings.Overrides)
		settings.Overrides[e.ip] = entry
	} else {
		entry := client.PeerOverride{Incoming: settings.Incoming, Outgoing: settings.Outgoing, Pools: settings.Pools, Relay: &settings.Relay}
		change(&entry)
		settings.Incoming, settings.Outgoing, settings.Pools, settings.Relay = entry.Incoming, entry.Outgoing, entry.Pools, *entry.Relay
	}
	return nil, savePeer(e.request, settings, status.PeerRevision)
}

func peerSettingsScreen(request peerRequester) (*service.Screen, error) {
	global := peerEditor{request: request}
	return &service.Screen{Title: "Peer connections", Choices: []service.Action{
		{Label: "Global defaults", Run: global.settings},
		{Label: "Per-peer overrides", Run: func() (*service.Screen, error) { return peerOverridesScreen(request) }},
	}}, nil
}

func peerOverridesScreen(request peerRequester) (*service.Screen, error) {
	status, err := (peerEditor{request: request}).status()
	if err != nil {
		return nil, err
	}
	if status.PeerRevision == "" {
		return nil, fmt.Errorf("update the client service before editing per-peer overrides")
	}
	screen := &service.Screen{Title: "Per-peer overrides", Text: "Each VPN IPv4 address inherits any setting you do not override."}
	var refresh func(map[netip.Addr]client.PeerOverride)
	refresh = func(overrides map[netip.Addr]client.PeerOverride) {
		ips := slices.SortedFunc(maps.Keys(overrides), netip.Addr.Compare)
		choices := make([]service.Action, 0, len(ips)+1)
		choices = append(choices, service.Action{Label: "Add by VPN IP", Run: func() (*service.Screen, error) {
			return addPeerScreen(request, refresh), nil
		}})
		for _, ip := range ips {
			editor := peerEditor{request: request, ip: ip}
			choices = append(choices, service.Action{Label: ip.String(), Run: editor.settings})
		}
		screen.Choices = choices
	}
	refresh(status.Peer.Overrides)
	return screen, nil
}

func addPeerScreen(request peerRequester, refresh func(map[netip.Addr]client.PeerOverride)) *service.Screen {
	return &service.Screen{Title: "Add peer override", Text: "Enter a single VPN IPv4 address, for example 10.77.0.5.", Fields: []service.Field{{Label: "VPN IPv4 address"}}, Submit: "Add peer", Save: func(fields []service.Field) (*service.Screen, error) {
		ip, err := netip.ParseAddr(strings.TrimSpace(fields[0].Value))
		if err != nil || !mesh.ValidPeerOverrideIP(ip) {
			return nil, fmt.Errorf("enter a valid VPN IPv4 address")
		}
		status, err := (peerEditor{request: request}).status()
		if err != nil {
			return nil, err
		}
		settings := status.Peer
		if _, exists := settings.Overrides[ip]; exists {
			return nil, fmt.Errorf("an override for %s already exists", ip)
		}
		overrides := make(map[netip.Addr]client.PeerOverride, len(settings.Overrides)+1)
		maps.Copy(overrides, settings.Overrides)
		overrides[ip] = client.PeerOverride{}
		settings.Overrides = overrides
		if err := savePeer(request, settings, status.PeerRevision); err != nil {
			return nil, err
		}
		refresh(overrides)
		return (peerEditor{request: request, ip: ip}).settingsScreen(settings), nil
	}}
}

func (e peerEditor) settings() (*service.Screen, error) {
	settings, err := e.load()
	if err != nil {
		return nil, err
	}
	return e.settingsScreen(settings), nil
}

func (e peerEditor) settingsScreen(settings client.PeerSettings) *service.Screen {
	title := "Global defaults"
	if e.ip.IsValid() {
		title = "Peer " + e.ip.String()
	}
	entry := settings.Overrides[e.ip]
	effective := settings.ForPeer(e.ip)
	incoming := e.listEditor("Accept incoming", "An empty selection accepts no peer connections.", "", func(p *client.PeerOverride, modes []string) { p.Incoming = modes })
	choices := []service.Action{
		{Label: "Accept incoming" + e.inheritance(entry.Incoming == nil), Run: incoming},
		{Label: "Outgoing pools", Run: e.pools},
		{Label: "Connect using: " + effective.SelectedMode() + e.inheritance(entry.Outgoing == ""), Run: e.connect},
	}
	relay := service.Action{Label: "Allow relay via central server: " + relayState(effective.Relay) + e.inheritance(entry.Relay == nil), Run: e.relay}
	if !e.ip.IsValid() {
		relay.Run = func() (*service.Screen, error) {
			return e.update(func(p *client.PeerOverride) { *p.Relay = !*p.Relay })
		}
	}
	choices = append(choices, relay)
	if e.ip.IsValid() {
		choices = append(choices, service.Action{Label: "Remove override", Run: e.remove})
	}
	return &service.Screen{Title: title, Choices: choices}
}

func (e peerEditor) inheritance(inherited bool) string {
	if e.ip.IsValid() && inherited {
		return " (global)"
	}
	return ""
}

func (e peerEditor) pools() (*service.Screen, error) {
	settings, err := e.load()
	if err != nil {
		return nil, err
	}
	choices := make([]service.Action, 0, 3)
	for _, pool := range [...]struct{ label, policy string }{{"Failover", "failover"}, {"Round Robin", "round-robin"}, {"Adaptive", "adaptive"}} {
		_, custom := settings.Overrides[e.ip].Pools[pool.policy]
		choices = append(choices, service.Action{
			Label: pool.label + e.inheritance(!custom),
			Run: e.listEditor(pool.label, "An empty pool selects no direct transport.", pool.policy, func(p *client.PeerOverride, modes []string) {
				pools := make(map[string][]string, len(p.Pools)+1)
				maps.Copy(pools, p.Pools)
				if modes == nil {
					delete(pools, pool.policy)
				} else {
					pools[pool.policy] = modes
				}
				p.Pools = pools
			}),
		})
	}
	return &service.Screen{Title: "Outgoing pools", Choices: choices}, nil
}

func (e peerEditor) listEditor(title, text, policy string, set func(*client.PeerOverride, []string)) func() (*service.Screen, error) {
	return func() (*service.Screen, error) {
		settings, err := e.load()
		if err != nil {
			return nil, err
		}
		entry := settings.Overrides[e.ip]
		effective := settings.ForPeer(e.ip)
		var selected []string
		var inherited bool
		if policy == "" {
			selected, inherited = effective.IncomingModes(), entry.Incoming == nil
		} else {
			effective.Outgoing = policy
			selected = effective.OutgoingModes()
			_, custom := entry.Pools[policy]
			inherited = !custom
		}
		reorder := policy == "failover" || policy == "adaptive"
		form := func() (*service.Screen, error) {
			modes := config.ClientModes()
			fields := make([]service.Field, 0, len(modes))
			if reorder {
				for _, mode := range selected {
					fields = append(fields, service.Field{Label: mode, Toggle: true, Checked: true})
				}
			}
			for _, mode := range modes {
				checked := slices.Contains(selected, mode)
				if !reorder || !checked {
					fields = append(fields, service.Field{Label: mode, Toggle: true, Checked: checked})
				}
			}
			help := text
			if reorder {
				help += " Use - to move up, + or = to move down."
			}
			return &service.Screen{Title: title, Text: help, Fields: fields, Reorder: reorder, Submit: "Save", Save: func(fields []service.Field) (*service.Screen, error) {
				modes := make([]string, 0, len(fields))
				for _, field := range fields {
					if field.Checked {
						modes = append(modes, field.Label)
					}
				}
				return e.update(func(p *client.PeerOverride) { set(p, modes) })
			}}, nil
		}
		if !e.ip.IsValid() {
			return form()
		}
		return &service.Screen{Title: title, Choices: []service.Action{
			{Label: "Customize", Run: form},
			{Label: peerChoice(inherited, "Use global"), Run: func() (*service.Screen, error) {
				return e.update(func(p *client.PeerOverride) { set(p, nil) })
			}},
		}}, nil
	}
}

func (e peerEditor) connect() (*service.Screen, error) {
	settings, err := e.load()
	if err != nil {
		return nil, err
	}
	selected := settings.SelectedMode()
	modes := append(config.ClientModes(), "failover", "round-robin", "adaptive")
	choices := make([]service.Action, 0, len(modes)+1)
	if e.ip.IsValid() {
		selected = settings.Overrides[e.ip].Outgoing
		if selected != "" {
			selected = config.CanonicalMode(selected)
		}
		choices = append(choices, service.Action{Label: peerChoice(selected == "", "Use global ("+settings.SelectedMode()+")"), Run: func() (*service.Screen, error) {
			return e.update(func(p *client.PeerOverride) { p.Outgoing = "" })
		}})
	}
	for _, mode := range modes {
		choices = append(choices, service.Action{Label: peerChoice(selected == mode, mode), Run: func() (*service.Screen, error) {
			return e.update(func(p *client.PeerOverride) { p.Outgoing = mode })
		}})
	}
	return &service.Screen{Title: "Connect using", Choices: choices}, nil
}

func (e peerEditor) relay() (*service.Screen, error) {
	settings, err := e.load()
	if err != nil {
		return nil, err
	}
	override := settings.Overrides[e.ip].Relay
	set := func(relay *bool) func() (*service.Screen, error) {
		return func() (*service.Screen, error) {
			return e.update(func(p *client.PeerOverride) { p.Relay = relay })
		}
	}
	on, off := true, false
	return &service.Screen{Title: "Allow relay via central server", Choices: []service.Action{
		{Label: peerChoice(override == nil, "Use global ("+relayState(settings.Relay)+")"), Run: set(nil)},
		{Label: peerChoice(override != nil && *override, "On"), Run: set(&on)},
		{Label: peerChoice(override != nil && !*override, "Off"), Run: set(&off)},
	}}, nil
}

func (e peerEditor) remove() (*service.Screen, error) {
	return &service.Screen{Title: "Remove override for " + e.ip.String() + "?", Text: "This peer will use all global defaults. Esc cancels.", Choices: []service.Action{
		{Label: "Remove", Run: func() (*service.Screen, error) {
			status, err := e.status()
			if err != nil {
				return nil, err
			}
			settings := status.Peer
			settings.Overrides = maps.Clone(settings.Overrides)
			delete(settings.Overrides, e.ip)
			return nil, savePeer(e.request, settings, status.PeerRevision)
		}},
	}}, nil
}

func peerChoice(selected bool, label string) string {
	if selected {
		return "[x] " + label
	}
	return "[ ] " + label
}

func relayState(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
