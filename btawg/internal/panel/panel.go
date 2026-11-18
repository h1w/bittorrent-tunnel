// Package panel is the btawg web interface (3x-ui style): single-admin login
// with CSRF and login rate limiting, the hub configuration form, and client
// management whose create action yields the btawg:// import string. The panel
// binds loopback in production; SSH port-forwarding reaches it.
package panel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"bittorrent-tunnel/btawg/internal/awg"
	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

// Registry is what the panel drives; the assembled hub implements it.
type Registry interface {
	RegisterClient(store.ClientRecord) error
	RevokeClient(store.ClientRecord) error
	ReloadPolicy() error
	ConnectedCount() map[string]int
	InfoHash() string
	PubKey() string
}

const (
	sessionTTL    = 24 * time.Hour
	loginWindow   = 15 * time.Minute
	maxLoginFails = 5
)

type session struct {
	csrf    string
	expires time.Time
}

type failState struct {
	count int
	until time.Time
}

// Panel is the web interface.
type Panel struct {
	st   *store.Store
	reg  Registry
	user string
	pass []byte // bcrypt hash

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*failState
}

// New builds the panel for the given store, hub registry and admin
// credentials (pass is a bcrypt hash).
func New(st *store.Store, reg Registry, user, passHash string) *Panel {
	return &Panel{
		st:       st,
		reg:      reg,
		user:     user,
		pass:     []byte(passHash),
		sessions: make(map[string]*session),
		fails:    make(map[string]*failState),
	}
}

// Handler returns the routed panel.
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", p.loginPage)
	mux.HandleFunc("POST /login", p.loginSubmit)
	mux.HandleFunc("POST /logout", p.auth(p.logout))
	mux.HandleFunc("GET /{$}", p.auth(p.dashboard))
	mux.HandleFunc("GET /server", p.auth(p.serverPage))
	mux.HandleFunc("POST /server", p.auth(p.serverSubmit))
	mux.HandleFunc("GET /clients", p.auth(p.clientsPage))
	mux.HandleFunc("POST /clients/create", p.auth(p.clientCreate))
	mux.HandleFunc("POST /clients/revoke", p.auth(p.clientRevoke))
	mux.HandleFunc("POST /clients/policy", p.auth(p.clientPolicy))
	mux.HandleFunc("GET /clients/import", p.auth(p.clientImport))
	return mux
}

// ---- auth plumbing ----

func (p *Panel) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("btawg_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		p.mu.Lock()
		s := p.sessions[c.Value]
		if s != nil && time.Now().After(s.expires) {
			delete(p.sessions, c.Value)
			s = nil
		}
		p.mu.Unlock()
		if s == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil || r.PostFormValue("csrf") != s.csrf {
				http.Error(w, "bad csrf", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func (p *Panel) newSession(w http.ResponseWriter) {
	tok := randHex(24)
	p.mu.Lock()
	p.sessions[tok] = &session{csrf: randHex(16), expires: time.Now().Add(sessionTTL)}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "btawg_session",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (p *Panel) session(r *http.Request) *session {
	c, err := r.Cookie("btawg_session")
	if err != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sessions[c.Value]
}

func (p *Panel) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("btawg_session"); err == nil {
		p.mu.Lock()
		delete(p.sessions, c.Value)
		p.mu.Unlock()
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ---- login ----

func (p *Panel) loginPage(w http.ResponseWriter, r *http.Request) {
	p.render(w, "login", map[string]any{"Error": ""})
}

func (p *Panel) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	p.mu.Lock()
	f := p.fails[ip]
	if f == nil {
		f = &failState{}
		p.fails[ip] = f
	}
	locked := time.Now().Before(f.until)
	p.mu.Unlock()
	if locked {
		p.render(w, "login", map[string]any{"Error": "too many attempts, wait 15 minutes"})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := r.PostFormValue("username")
	pass := r.PostFormValue("password")
	if user != p.user || bcrypt.CompareHashAndPassword(p.pass, []byte(pass)) != nil {
		p.mu.Lock()
		f.count++
		if f.count >= maxLoginFails {
			f.until = time.Now().Add(loginWindow)
			f.count = 0
		}
		p.mu.Unlock()
		p.render(w, "login", map[string]any{"Error": "wrong username or password"})
		return
	}
	p.mu.Lock()
	f.count = 0
	p.mu.Unlock()
	p.newSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- dashboard ----

func (p *Panel) dashboard(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.st.LoadServerConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	clients, _ := p.st.ListClients()
	data := map[string]any{
		"CSRF":      p.session(r).csrf,
		"Cfg":       cfg,
		"InfoHash":  p.reg.InfoHash(),
		"PubKey":    p.reg.PubKey(),
		"Clients":   clients,
		"Connected": p.reg.ConnectedCount(),
		"Active":    "dashboard",
	}
	p.render(w, "dashboard", data)
}

// ---- server settings ----

func (p *Panel) serverPage(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.st.LoadServerConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.render(w, "server", map[string]any{"CSRF": p.session(r).csrf, "Cfg": cfg, "Saved": r.URL.Query().Get("saved") == "1", "Active": "server"})
}

func (p *Panel) serverSubmit(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.st.LoadServerConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	get := func(name string) int {
		var v int
		fmt.Sscanf(r.PostFormValue(name), "%d", &v)
		return v
	}
	cfg.AWGProfile = config.AWGProfile{
		JC: get("jc"), JMin: get("jmin"), JMax: get("jmax"),
		S1: get("s1"), S2: get("s2"), S3: get("s3"), S4: get("s4"),
		H1: get("h1"), H2: get("h2"), H3: get("h3"), H4: get("h4"),
	}
	cfg.Transport = r.PostFormValue("transport")
	switch cfg.Transport {
	case "ext-utp", "ext-tcp", "req-utp", "req-tcp":
	default:
		http.Error(w, "bad transport", http.StatusBadRequest)
		return
	}
	cfg.CarrierPort = get("carrier_port")
	cfg.SocksPort = get("socks_port")
	cfg.PanelPort = get("panel_port")
	cfg.ExternalIP = strings.TrimSpace(r.PostFormValue("external_ip"))
	if cfg.CarrierPort <= 0 || cfg.CarrierPort > 65535 ||
		cfg.SocksPort <= 0 || cfg.SocksPort > 65535 ||
		cfg.PanelPort <= 0 || cfg.PanelPort > 65535 {
		http.Error(w, "bad port", http.StatusBadRequest)
		return
	}
	if cfg.ExternalIP != "" {
		if _, err := netip.ParseAddr(cfg.ExternalIP); err != nil {
			http.Error(w, "bad external ip", http.StatusBadRequest)
			return
		}
	}
	if err := p.st.SaveServerConfig(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/server?saved=1", http.StatusFound)
}

// ---- clients ----

func (p *Panel) clientsPage(w http.ResponseWriter, r *http.Request) {
	clients, err := p.st.ListClients()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.render(w, "clients", map[string]any{"CSRF": p.session(r).csrf, "Clients": clients, "Connected": p.reg.ConnectedCount(), "Active": "clients"})
}

func (p *Panel) clientCreate(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.st.LoadServerConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	priv, pub, err := awg.GenerateKeyPair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	clients, err := p.st.ListClients()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ip, err := nextFreeIP(cfg.Subnet, clients)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rec := store.ClientRecord{
		ID:      randHex(8),
		Name:    name,
		PubKey:  pub,
		PrivKey: priv,
		IP:      ip,
		PeerID:  awg.PeerID(pub),
		Created: time.Now(),
	}
	if err := p.st.CreateClient(rec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := p.reg.RegisterClient(rec); err != nil {
		_ = p.st.DeleteClient(rec.ID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/clients/import?id="+rec.ID, http.StatusFound)
}

func (p *Panel) clientRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	rec, err := p.st.GetClient(id)
	if err != nil {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}
	if err := p.st.RevokeClient(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := p.reg.RevokeClient(rec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusFound)
}

func (p *Panel) clientPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	rec, err := p.st.GetClient(id)
	if err != nil {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}

	rec.NoInternet = r.PostFormValue("internet") != "on"
	peers := r.PostForm["peers"]
	if len(peers) == 0 || (len(peers) == 1 && peers[0] == "*") {
		rec.VisiblePeers = []string{"*"}
	} else {
		rec.VisiblePeers = peers
	}

	if err := p.st.SaveClient(rec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := p.reg.ReloadPolicy(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (p *Panel) clientImport(w http.ResponseWriter, r *http.Request) {
	rec, err := p.st.GetClient(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}
	cfg, err := p.st.LoadServerConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ccfg := config.ClientConfig{
		Version:       config.ClientVersion,
		InfoHash:      p.reg.InfoHash(),
		ServerPubKey:  p.reg.PubKey(),
		ClientPrivKey: rec.PrivKey,
		ClientPubKey:  rec.PubKey,
		ClientIP:      rec.IP,
		Subnet:        cfg.Subnet,
		ServerIP:      cfg.ServerIP,
		Transport:     cfg.Transport,
		SocksPort:     1080,
		EgressPort:    cfg.SocksPort,
		Profile:       cfg.AWGProfile,
	}
	s, err := ccfg.ImportString()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.render(w, "import", map[string]any{"CSRF": p.session(r).csrf, "Client": rec, "Import": s, "Active": "clients"})
}

// ---- helpers ----

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// nextFreeIP picks the first free host address in the /24 overlay.
func nextFreeIP(subnet string, clients []store.ClientRecord) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("bad subnet: %w", err)
	}
	if !prefix.Addr().Is4() || prefix.Bits() < 24 {
		return "", fmt.Errorf("only IPv4 /24+ overlays are supported")
	}
	b := prefix.Masked().Addr().As4()
	used := make(map[string]bool)
	for _, c := range clients {
		used[c.IP] = true
	}
	for i := 2; i < 255; i++ {
		candidate := netip.AddrFrom4([4]byte{b[0], b[1], b[2], byte(i)}).String()
		if !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("overlay subnet exhausted")
}
