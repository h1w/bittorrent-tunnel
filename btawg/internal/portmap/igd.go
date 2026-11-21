package portmap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const soapEnvelope = "http://schemas.xmlsoap.org/soap/envelope/"

type igdAction struct {
	XMLName     xml.Name
	External    string  `xml:"NewExternalIPAddress"`
	Client      string  `xml:"NewInternalClient"`
	Port        uint16  `xml:"NewInternalPort"`
	Description string  `xml:"NewPortMappingDescription"`
	Seconds     *uint32 `xml:"NewLeaseDuration"`
	Enabled     string  `xml:"NewEnabled"`
}

type igdReply struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    struct {
		Fault struct {
			XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`
			Code    uint16   `xml:"detail>UPnPError>errorCode"`
		}
		Action igdAction `xml:",any"`
	} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
}

func (s igdService) call(ctx context.Context, action, args string) (igdAction, error) {
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="` + soapEnvelope + `" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + s.kind + `">` + args + `</u:` + action + `></s:Body></s:Envelope>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.control, strings.NewReader(body))
	if err != nil {
		return igdAction{}, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+s.kind+`#`+action+`"`)
	resp, err := s.client.Do(req)
	if err != nil {
		return igdAction{}, err
	}
	defer resp.Body.Close()
	var reply igdReply
	if err := boundedXML(resp.Body, &reply); err != nil {
		return igdAction{}, err
	}
	if resp.StatusCode == http.StatusInternalServerError && reply.Body.Fault.Code != 0 {
		return igdAction{}, routerResult{"UPnP IGD", reply.Body.Fault.Code}
	}
	if resp.StatusCode != http.StatusOK || reply.Body.Fault.XMLName.Local != "" || reply.Body.Action.XMLName != (xml.Name{Space: s.kind, Local: action + "Response"}) {
		return igdAction{}, fmt.Errorf("invalid IGD %s reply (HTTP %d)", action, resp.StatusCode)
	}
	return reply.Body.Action, nil
}

func igdErrorCode(err error, code uint16) bool {
	var result routerResult
	return errors.As(err, &result) && result.code == code
}

func (s igdService) externalIP(ctx context.Context) (netip.Addr, error) {
	reply, err := s.call(ctx, "GetExternalIPAddress", "")
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(reply.External))
	if err != nil || !usableEndpoint(netip.AddrPortFrom(ip, 1)) {
		return netip.Addr{}, errors.New("IGD did not report a usable external IPv4 address")
	}
	return ip, nil
}

func igdScope(port uint16) string {
	return `<NewRemoteHost></NewRemoteHost><NewExternalPort>` + strconv.Itoa(int(port)) + `</NewExternalPort><NewProtocol>UDP</NewProtocol>`
}

type igdMapping struct {
	source         netip.Addr
	port           uint16
	description    string
	services       []igdService
	selected       int // index of the service which accepted an Add request
	allowPermanent bool
}

func (r router) probeIGD(ctx context.Context, port uint16) (mapping, error) {
	services, err := r.discoverIGD(ctx)
	if err != nil {
		return nil, err
	}
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	return &igdMapping{source: r.source, port: port, description: "btawg-" + hex.EncodeToString(token[:]), services: services, allowPermanent: r.allowPermanentUPnP}, nil
}

func (m *igdMapping) owns(entry igdAction) bool {
	return strings.TrimSpace(entry.Client) == m.source.String() && entry.Port == m.port && entry.Description == m.description
}

func (m *igdMapping) add(ctx context.Context, s igdService, endpoint netip.AddrPort, seconds uint32) (lease, error) {
	scope := igdScope(endpoint.Port())
	args := scope + `<NewInternalPort>` + strconv.Itoa(int(m.port)) + `</NewInternalPort><NewInternalClient>` + m.source.String() + `</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>` + m.description + `</NewPortMappingDescription><NewLeaseDuration>` + strconv.FormatUint(uint64(seconds), 10) + `</NewLeaseDuration>`
	started := time.Now()
	if _, err := s.call(ctx, "AddPortMapping", args); err != nil {
		if seconds != 0 && m.allowPermanent && igdErrorCode(err, 725) {
			// Recheck before retrying: the first write was explicitly rejected,
			// but another client could have claimed the port since our lookup.
			entry, err := s.call(ctx, "GetSpecificPortMappingEntry", scope)
			if igdErrorCode(err, 714) || err == nil && m.owns(entry) {
				return m.add(ctx, s, endpoint, 0)
			}
			return lease{}, errLeaseLost
		}
		if seconds != 0 {
			return uncertainWrite(started, err), err
		}
		var result routerResult
		if errors.As(err, &result) {
			return lease{}, err
		}
		// A permanent write can outlive an HTTP timeout. Read back the
		// exact entry before publishing or attempting ownership-checked cleanup.
	}

	// The action's success reply has no arguments. Confirm the entry's
	// enabled flag, lease length and ownership before publishing it.
	lookup := time.Now()
	current := acknowledgedLease(endpoint, seconds, started, true)
	if seconds == 0 {
		current = lease{endpoint: endpoint, started: started, owned: true, permanent: true}
	}
	entry, err := s.call(ctx, "GetSpecificPortMappingEntry", scope)
	if err != nil {
		if igdErrorCode(err, 714) {
			return lease{}, errLeaseLost
		}
		return current, errors.Join(err, errLeaseLost)
	}
	if !m.owns(entry) {
		return lease{}, errLeaseLost
	}
	if entry.Seconds != nil && *entry.Seconds == 0 {
		current.permanent = true
		current.expires = time.Time{}
	}
	if !entry.enabled() || entry.Seconds == nil || (*entry.Seconds == 0) != (seconds == 0) {
		// Don't publish an unexpected permanent or disabled entry.
		return current, errLeaseLost
	}
	current.started = lookup
	if !current.permanent {
		current.expires = lookup.Add(time.Duration(min(*entry.Seconds, seconds)) * time.Second)
	}
	return current, nil
}

func (e igdAction) enabled() bool {
	return e.Enabled == "1" || strings.EqualFold(e.Enabled, "true")
}

func (m *igdMapping) refresh(ctx context.Context, old lease) (lease, error) {
	if old.endpoint.IsValid() {
		s := m.services[m.selected]
		external, err := s.externalIP(ctx)
		if err != nil {
			return lease{}, err
		}
		entry, err := s.call(ctx, "GetSpecificPortMappingEntry", igdScope(old.endpoint.Port()))
		if err != nil {
			if igdErrorCode(err, 714) {
				return lease{}, errLeaseLost
			}
			return lease{}, err
		}
		if !m.owns(entry) {
			return lease{}, errLeaseLost
		}
		endpoint := netip.AddrPortFrom(external, old.endpoint.Port())
		if old.permanent {
			// Permanent entries don't need rewriting. Confirm that the router
			// still has the enabled entry we created before advertising it again.
			if !entry.enabled() || entry.Seconds == nil || *entry.Seconds != 0 {
				return old, errLeaseLost
			}
			old.endpoint, old.started = endpoint, time.Now()
			return old, nil
		}
		return m.add(ctx, s, endpoint, requestedSeconds)
	}

	for i, s := range m.services {
		external, err := s.externalIP(ctx)
		if err != nil {
			continue
		}
		for attempt := 0; attempt < 3 && ctx.Err() == nil; attempt++ {
			port := m.port
			if attempt != 0 {
				// Try a high port when the well-known suggestion is occupied.
				// GetSpecific makes this safe even when the existing mapping
				// belongs to the same IP (which Add would otherwise replace).
				var random [2]byte
				if _, err := rand.Read(random[:]); err != nil {
					return lease{}, err
				}
				port = 49152 + (uint16(random[0]&0x3f)<<8 | uint16(random[1]))
			}
			_, err := s.call(ctx, "GetSpecificPortMappingEntry", igdScope(port))
			if err == nil { // occupied by someone else
				continue
			}
			if !igdErrorCode(err, 714) { // not confirmed free; don't overwrite
				break
			}
			current, err := m.add(ctx, s, netip.AddrPortFrom(external, port), requestedSeconds)
			if err == nil || current.validAt(time.Now()) {
				m.selected = i
				return current, err
			}
			if igdErrorCode(err, 718) { // port became occupied after lookup
				continue
			}
			break
		}
	}
	return lease{}, errors.New("no IGD service accepted the UDP port mapping")
}

func (m *igdMapping) remove(ctx context.Context, current lease) error {
	s := m.services[m.selected]
	args := igdScope(current.endpoint.Port())
	entry, err := s.call(ctx, "GetSpecificPortMappingEntry", args)
	if igdErrorCode(err, 714) {
		return nil
	}
	if err != nil {
		return err
	}
	if !m.owns(entry) {
		return errLeaseLost
	}
	_, err = s.call(ctx, "DeletePortMapping", args)
	return err
}
