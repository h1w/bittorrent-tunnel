package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/mesh"
	"bittorrent-tunnel/btawg/internal/store"
	"bittorrent-tunnel/btawg/internal/tunsetup"
)

type meshRegistration struct {
	mesh.Registration
	ip    netip.Addr
	key   string
	until time.Time
}

type meshAdmission struct {
	caller mesh.Node
	check  mesh.Check
	until  time.Time
}

type meshControl struct {
	key        [32]byte
	clients    map[string]meshRegistration // protected by Server.applyMu
	admissions map[string]meshAdmission
}

func newMeshControl() *meshControl {
	c := &meshControl{clients: make(map[string]meshRegistration), admissions: make(map[string]meshAdmission)}
	rand.Read(c.key[:])
	return c
}

func (s *Server) meshListen(ctx context.Context, port int) (net.Listener, error) {
	if s.ns != nil {
		// gonet treats a four-byte 0.0.0.0 as a specific address rather
		// than the empty IPv4 bind address. Bind each actual VPN gateway.
		s.applyMu.Lock()
		addresses := make([]netip.Addr, len(s.gateways))
		for i, gateway := range s.gateways {
			addresses[i] = gateway.Addr()
		}
		s.applyMu.Unlock()
		return listenMeshGateways(s.ns, addresses, uint16(port))
	}
	lc := net.ListenConfig{Control: tunsetup.BindDevice(s.tunName)}
	return lc.Listen(ctx, "tcp4", ":"+strconv.Itoa(port))
}

func (s *Server) serveMesh(ctx context.Context) error {
	ln, err := s.meshListen(ctx, mesh.ControlPort)
	if err != nil {
		return fmt.Errorf("mesh control: %w", err)
	}
	web := &http.Server{
		Handler:           http.HandlerFunc(s.meshRequest),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second, WriteTimeout: 6 * time.Second,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096,
	}
	defer web.Close()
	stop := context.AfterFunc(ctx, func() { web.Close(); ln.Close() })
	defer stop()
	err = web.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) meshRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != mesh.Path || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	from, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid source", http.StatusForbidden)
		return
	}
	var req mesh.Request
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, mesh.MaxRequest))
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || (req.Check == nil) == (req.Registration == nil) {
		http.Error(w, "invalid mesh request", http.StatusBadRequest)
		return
	}
	s.applyMu.Lock()
	var reply mesh.Reply
	rec, ok := s.meshClient(from.Addr().Unmap())
	if !ok {
		err = store.ErrNotFound
	} else if req.Registration != nil {
		reply, err = s.meshRegister(rec, from.Addr().Unmap(), *req.Registration, time.Now())
	} else {
		reply, err = s.admitEgress(rec, *req.Check, time.Now())
	}
	s.applyMu.Unlock()
	if err != nil {
		http.Error(w, "mesh authorization denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(reply)
}

func (s *Server) meshClient(ip netip.Addr) (store.ClientRecord, bool) {
	s.policy.mu.RLock()
	r, ok := s.policy.byIP[ip]
	s.policy.mu.RUnlock()
	return r, ok
}

func meshNode(rec store.ClientRecord) mesh.Node {
	return mesh.Node{ID: rec.ID, Key: rec.PubKey, IP: rec.IP}
}

func (s *Server) meshRegister(rec store.ClientRecord, ip netip.Addr, req mesh.Registration, now time.Time) (mesh.Reply, error) {
	var reply mesh.Reply
	if len(req.Want) > mesh.MaxPeers || len(req.Candidates) > 32 {
		return reply, errors.New("too many candidates")
	}
	if req.DirectKey != "" {
		key, err := hex.DecodeString(req.DirectKey)
		if err != nil || len(key) != 32 || req.DirectKey == rec.PubKey {
			return reply, errors.New("invalid direct key")
		}
	} else if len(req.Candidates) != 0 || len(req.Want) != 0 {
		return reply, errors.New("missing direct key")
	}
	req.Candidates = slices.DeleteFunc(req.Candidates, func(c mesh.Candidate) bool {
		a := c.Addr.Addr()
		if !a.IsValid() || !a.IsGlobalUnicast() || c.Addr.Port() == 0 || a.Zone() != "" || a.Is4In6() {
			return true
		}
		if s.policy.Contains(a) {
			return true
		}
		switch c.Kind {
		case "lan":
			return !a.Is4() || !a.IsPrivate()
		case "ipv6":
			return !a.Is6() || a.IsPrivate()
		case "public", "mapped", "observed":
			return !config.PublicIPv4(a)
		default:
			return true
		}
	})
	for id, registration := range s.mesh.clients {
		if !now.Before(registration.until) {
			delete(s.mesh.clients, id)
		}
	}
	self := meshRegistration{req, ip, rec.PubKey, now.Add(mesh.Lease)}
	s.mesh.clients[rec.ID] = self
	for _, gateway := range s.gateways {
		reply.Gateways = append(reply.Gateways, gateway.Addr())
	}
	if s.kernel != nil {
		s.policy.mu.RLock()
		allowed := s.policy.internet(rec)
		s.policy.mu.RUnlock()
		if allowed {
			reply.Routes = append(reply.Routes, mesh.Route{ID: mesh.HubRoute, Name: "Central server"})
		}
	}
	routes, err := s.st.AuthorizedEgressRoutes(rec.ID)
	if err != nil {
		return reply, err
	}
	for _, route := range routes {
		current, hops, err := s.st.ResolveEgressRoute(rec.ID, route.ID)
		if err != nil {
			continue
		}
		option := mesh.Route{ID: current.ID, Name: current.Name, First: netip.MustParseAddr(hops[0].IP)}
		if !s.meshHopsAvailable(hops, now) {
			reply.Routes = append(reply.Routes, option)
			continue
		}
		nodes := make([]mesh.Node, len(hops))
		for i := range hops {
			nodes[i] = meshNode(hops[i])
		}
		grant, err := mesh.SealGrant(s.mesh.key, current.ID, meshNode(rec), nodes, now, current.Authorization)
		if err != nil {
			return reply, err
		}
		option.Grant = grant
		reply.Routes = append(reply.Routes, option)
	}
	if self.DirectKey != "" {
		// Put our explicitly wanted peers first; cap unsolicited handshakes.
		for _, want := range self.Want {
			if peer, ok := s.meshClient(want); ok {
				s.appendPair(&reply, rec, self, peer.ID, now)
			}
		}
		for id, peer := range s.mesh.clients {
			if len(reply.Pairs) >= mesh.MaxPeers {
				break
			}
			if slices.Contains(peer.Want, self.ip) {
				s.appendPair(&reply, rec, self, id, now)
			}
		}
	}
	return reply, nil
}

func (s *Server) appendPair(reply *mesh.Reply, rec store.ClientRecord, self meshRegistration, id string, now time.Time) {
	peer, ok := s.mesh.clients[id]
	if !ok || id == rec.ID || peer.DirectKey == "" || peer.DirectKey == self.DirectKey || len(reply.Pairs) >= mesh.MaxPeers {
		return
	}
	for _, pair := range reply.Pairs {
		if pair.IP == peer.ip {
			return
		}
	}
	current, ok := s.meshClient(peer.ip)
	if !ok || current.ID != id || current.PubKey != peer.key || !s.policy.clientCanReach(self.ip, peer.ip) {
		return
	}
	a, b := self, peer
	aID, bID := rec.ID, id
	init := aID < bID
	if !init {
		a, b = b, a
		aID, bID = bID, aID
	}
	mac := hmac.New(sha256.New, s.mesh.key[:])
	for _, x := range []string{"btawg/mesh-pair/v1", aID, a.ip.String(), a.key, a.DirectKey, bID, b.ip.String(), b.key, b.DirectKey} {
		mac.Write([]byte(x))
		mac.Write([]byte{0})
	}
	var secret [32]byte
	copy(secret[:], mac.Sum(nil))
	if !now.Before(peer.until) {
		return
	}
	until := self.until
	if peer.until.Before(until) {
		until = peer.until
	}
	reply.Pairs = append(reply.Pairs, mesh.Pair{IP: peer.ip, Key: peer.DirectKey, Secret: secret, Initiator: init, Candidates: peer.Candidates, Expires: until})
}

func (s *Server) meshHopsAvailable(hops []store.ClientRecord, now time.Time) bool {
	if len(hops) == 0 {
		return false
	}
	for _, hop := range hops {
		r, ok := s.mesh.clients[hop.ID]
		if !ok || !r.Egress || r.ip.String() != hop.IP || r.key != hop.PubKey || !now.Before(r.until) {
			return false
		}
		if _, ok := s.meshClient(r.ip); !ok {
			return false
		}
	}
	return true
}

func (s *Server) admitEgress(caller store.ClientRecord, check mesh.Check, now time.Time) (mesh.Reply, error) {
	var reply mesh.Reply
	for token, session := range s.mesh.admissions {
		if !now.Before(session.until) {
			delete(s.mesh.admissions, token)
		}
	}
	key := check.Session
	check.Session = ""
	if check.Renew {
		stored, ok := s.mesh.admissions[key]
		check.Renew = false
		if !ok || stored.caller != meshNode(caller) || stored.check != check {
			return reply, errors.New("route session expired")
		}
		check.Renew = true
	} else {
		if key != "" || len(s.mesh.admissions) >= 8192 {
			return reply, errors.New("route session limit")
		}
		var nonce [16]byte
		rand.Read(nonce[:])
		key = hex.EncodeToString(nonce[:])
	}
	next, err := s.checkEgress(caller, check, now, false)
	if err != nil {
		delete(s.mesh.admissions, key)
		return reply, err
	}
	check.Renew = false
	s.mesh.admissions[key] = meshAdmission{meshNode(caller), check, now.Add(mesh.Lease)}
	reply.Session, reply.Next = key, next
	for _, gateway := range s.gateways {
		reply.Prefixes = append(reply.Prefixes, gateway.Masked())
	}
	return reply, nil
}

// checkEgress validates the actual client's identity at either the receiving
// node (for authorization) or the previous hop (for the hub relay).
func (s *Server) checkEgress(caller store.ClientRecord, req mesh.Check, now time.Time, relay bool) (netip.Addr, error) {
	deny := errors.New("route not authorized")
	if req.ID == "" || req.ID == mesh.HubRoute || req.Hop < 0 || req.Hop > 1 {
		return netip.Addr{}, deny
	}
	// Expiry limits admission. The live check for an admitted connection
	// reiterates the exact route authorization with the same signed token.
	grant, err := mesh.OpenGrant(s.mesh.key, req.Grant, now)
	if req.Renew && !relay {
		grant, err = mesh.RenewGrant(s.mesh.key, req.Grant)
	}
	if err != nil {
		return netip.Addr{}, deny
	}
	current, hops, err := s.st.ResolveEgressRoute(grant.Origin.ID, req.ID)
	if err != nil || req.Hop >= len(hops) || !s.meshHopsAvailable(hops, now) {
		return netip.Addr{}, deny
	}
	originIP, err := netip.ParseAddr(grant.Origin.IP)
	if err != nil {
		return netip.Addr{}, deny
	}
	origin, ok := s.meshClient(originIP)
	if !ok {
		return netip.Addr{}, deny
	}
	nodes := make([]mesh.Node, len(hops))
	for i := range hops {
		nodes[i] = meshNode(hops[i])
	}
	if grant.Authorization != current.Authorization || !grant.Matches(req.ID, meshNode(origin), nodes) {
		return netip.Addr{}, deny
	}
	previous := origin
	if req.Hop > 0 {
		previous = hops[req.Hop-1]
	}
	if relay {
		if meshNode(caller) != meshNode(previous) {
			return netip.Addr{}, deny
		}
		return netip.MustParseAddr(hops[req.Hop].IP), nil
	}
	if meshNode(caller) != nodes[req.Hop] || (req.Previous.String() != previous.IP && !s.policy.isGateway(req.Previous)) {
		return netip.Addr{}, deny
	}
	if req.Hop+1 < len(hops) {
		return netip.MustParseAddr(hops[req.Hop+1].IP), nil
	}
	return netip.Addr{}, nil
}
