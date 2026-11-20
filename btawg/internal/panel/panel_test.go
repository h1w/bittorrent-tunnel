package panel

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

type fakeRegistry struct {
	registered   []store.ClientRecord
	revoked      []store.ClientRecord
	reloadCalls  int
	reloadErr    error
	activeConfig config.ServerConfig
}

func (f *fakeRegistry) RegisterClient(rec store.ClientRecord) error {
	f.registered = append(f.registered, rec)
	return nil
}

func (f *fakeRegistry) RevokeClient(rec store.ClientRecord) error {
	f.revoked = append(f.revoked, rec)
	return nil
}

func (f *fakeRegistry) ReloadPolicy() error {
	f.reloadCalls++
	return f.reloadErr
}

func (f *fakeRegistry) Config() config.ServerConfig {
	if f.activeConfig.Transport != "" {
		return f.activeConfig
	}
	return config.DefaultServerConfig()
}

func (f *fakeRegistry) ConnectedCount() map[string]int { return nil }
func (f *fakeRegistry) InfoHash() string               { return "aabbccddeeff00112233445566778899aabbccdd" }
func (f *fakeRegistry) PubKey() string                 { return "11223344556677889900aabbccddeeff00112233" }

func importParse(raw string) (config.ClientConfig, error) {
	return config.ParseImportString(raw)
}

func newTestPanel(t *testing.T) (*httptest.Server, *store.Store, *fakeRegistry) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/panel.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SaveServerConfig(config.DefaultServerConfig()); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	reg := &fakeRegistry{}
	p := New(st, reg, "admin", string(hash))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv, st, reg
}

// login returns a client with a session cookie.
func login(t *testing.T, base string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	c := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // observe redirects instead of following
	}}
	resp, err := c.PostForm(base+"/login", map[string][]string{"username": {"admin"}, "password": {"secret"}})
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	return c
}

func csrfOf(t *testing.T, c *http.Client, base, path string) string {
	t.Helper()
	resp, err := c.Get(base + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	body := make([]byte, 1<<16)
	n, _ := resp.Body.Read(body)
	page := string(body[:n])
	i := strings.Index(page, `name="csrf" value="`)
	if i < 0 {
		t.Fatalf("no csrf token in %s", path)
	}
	rest := page[i+len(`name="csrf" value="`):]
	return rest[:strings.Index(rest, `"`)]
}

func TestLoginRequired(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	resp, err := (&http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}).Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated GET / = %d, want 302 to /login", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("redirect = %q, want /login", loc)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	resp, err := http.PostForm(srv.URL+"/login", map[string][]string{"username": {"admin"}, "password": {"wrong"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bad login status = %d, want 200 (form re-render)", resp.StatusCode)
	}
}

func TestServerConfigFormRoundTrip(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	c := login(t, srv.URL)
	csrf := csrfOf(t, c, srv.URL, "/server")
	form := map[string][]string{
		"csrf": {csrf},
		"jc":   {"4"}, "jmin": {"40"}, "jmax": {"100"},
		"s1": {"32"}, "s2": {"32"}, "s3": {"32"}, "s4": {"32"},
		"h1": {"101"}, "h2": {"102"}, "h3": {"103"}, "h4": {"104"},
		"transport":    {"ext-tcp"},
		"carrier_port": {"17777"}, "awg_port": {"51821"}, "wg_port": {"51820"},
		"socks_port": {"1080"}, "panel_port": {"8080"},
		"external_ip": {"203.0.113.7"},
	}
	resp, err := c.PostForm(srv.URL+"/server", form)
	if err != nil {
		t.Fatalf("post server: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post server = %d, want 302", resp.StatusCode)
	}
	cfg, err := st.LoadServerConfig()
	if err != nil {
		t.Fatalf("load cfg: %v", err)
	}
	if cfg.Transport != "ext-tcp" || cfg.CarrierPort != 17777 || cfg.ExternalIP != "203.0.113.7" {
		t.Fatalf("cfg not saved: %+v", cfg)
	}
	if cfg.InfoHash != "" {
		// The loaded config preserves identity fields only if they were set;
		// the fake store never set them. Nothing to assert here.
		_ = cfg.InfoHash
	}
}

func TestCreateClientProducesImportString(t *testing.T) {
	srv, st, reg := newTestPanel(t)
	c := login(t, srv.URL)
	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/create", map[string][]string{"csrf": {csrf}, "name": {"laptop"}})
	if err != nil {
		t.Fatalf("post create: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("create = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/clients/import?id=") {
		t.Fatalf("redirect = %q, want import page", loc)
	}
	if len(reg.registered) != 1 {
		t.Fatalf("registry saw %d registrations, want 1", len(reg.registered))
	}

	// Fetch the import page and extract the btawg:// string.
	resp, err = c.Get(srv.URL + loc)
	if err != nil {
		t.Fatalf("get import: %v", err)
	}
	defer resp.Body.Close()
	pageBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read import page: %v", err)
	}
	page := string(pageBytes)
	i := -1
	for from := 0; ; {
		j := strings.Index(page[from:], "btawg://")
		if j < 0 {
			break
		}
		j += from
		if j+len("btawg://") < len(page) && isB64Byte(page[j+len("btawg://")]) {
			i = j
			break
		}
		from = j + 1
	}
	if i < 0 {
		t.Fatal("no btawg:// import string on the import page")
	}
	// The template HTML-escapes quotes; cut at the first byte outside the
	// base64url alphabet.
	end := i + len("btawg://")
	for end < len(page) && isB64Byte(page[end]) {
		end++
	}
	raw := page[i:end]
	cfg, err := parseImportForTest(t, st, raw)
	_ = cfg
	if err != nil {
		t.Fatalf("import string invalid: %v", err)
	}
}

func parseImportForTest(t *testing.T, st *store.Store, raw string) (any, error) {
	t.Helper()
	cfg, err := importParse(raw)
	if err != nil {
		return nil, err
	}
	clients, err := st.ListClients()
	if err != nil {
		return nil, err
	}
	if len(clients) != 1 {
		t.Fatalf("store has %d clients, want 1", len(clients))
	}
	hub, err := st.LoadServerConfig()
	if err != nil {
		return nil, err
	}
	if cfg.ClientIP != clients[0].IP {
		t.Fatalf("import IP %q != store IP %q", cfg.ClientIP, clients[0].IP)
	}
	if cfg.EgressPort != hub.SocksPort {
		t.Fatalf("import EgressPort = %d, want hub socks port %d", cfg.EgressPort, hub.SocksPort)
	}
	if cfg.InfoHash != fakeInfoHash || cfg.ServerPubKey != fakePubKey {
		t.Fatal("import does not carry the hub identity")
	}
	if cfg.Version != 1 {
		t.Fatal("import version")
	}
	return cfg, nil
}

func isB64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}

const (
	fakeInfoHash = "aabbccddeeff00112233445566778899aabbccdd"
	fakePubKey   = "11223344556677889900aabbccddeeff00112233"
)

func TestRevokeClient(t *testing.T) {
	srv, st, reg := newTestPanel(t)
	c := login(t, srv.URL)
	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/create", map[string][]string{"csrf": {csrf}, "name": {"revoke-me"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	resp.Body.Close()
	clients, err := st.ListClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("clients after create: %v %d", err, len(clients))
	}
	id := clients[0].ID

	csrf = csrfOf(t, c, srv.URL, "/clients")
	resp, err = c.PostForm(srv.URL+"/clients/revoke", map[string][]string{"csrf": {csrf}, "id": {id}})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("revoke = %d, want 302", resp.StatusCode)
	}
	got, err := st.GetClient(id)
	if err != nil {
		t.Fatalf("get revoked: %v", err)
	}
	if !got.Revoked {
		t.Fatal("store did not mark the client revoked")
	}
	if len(reg.revoked) != 1 {
		t.Fatalf("registry saw %d revocations, want 1", len(reg.revoked))
	}
}

func TestCSRFRequired(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	c := login(t, srv.URL)
	resp, err := c.PostForm(srv.URL+"/clients/create", map[string][]string{"name": {"no-csrf"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("post without csrf = %d, want 403", resp.StatusCode)
	}
}

func createClientForTest(t *testing.T, c *http.Client, base, name string) string {
	t.Helper()
	csrf := csrfOf(t, c, base, "/clients")
	resp, err := c.PostForm(base+"/clients/create", map[string][]string{"csrf": {csrf}, "name": {name}})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("create %s = %d, want 302", name, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	const prefix = "/clients/import?id="
	if !strings.HasPrefix(loc, prefix) {
		t.Fatalf("create %s redirect = %q, want import page", name, loc)
	}
	return loc[len(prefix):]
}

func TestUpdateClientPolicy(t *testing.T) {
	srv, st, reg := newTestPanel(t)
	c := login(t, srv.URL)
	idA := createClientForTest(t, c, srv.URL, "A")
	idB := createClientForTest(t, c, srv.URL, "B")

	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf":     {csrf},
		"id":       {idA},
		"internet": {"off"},
		"peers":    {idB},
	})
	if err != nil {
		t.Fatalf("post policy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post policy = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("redirect = %q, want /", loc)
	}

	rec, err := st.GetClient(idA)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if rec.Internet == nil || *rec.Internet {
		t.Fatalf("Internet = %v, want explicit false", rec.Internet)
	}
	if len(rec.VisiblePeers) != 1 || rec.VisiblePeers[0] != idB {
		t.Fatalf("VisiblePeers = %v, want [%s]", rec.VisiblePeers, idB)
	}
	if reg.reloadCalls != 1 {
		t.Fatalf("ReloadPolicy calls = %d, want 1", reg.reloadCalls)
	}
}

func TestUpdateClientPolicyInternetPresence(t *testing.T) {
	srv, st, reg := newTestPanel(t)
	c := login(t, srv.URL)
	id := createClientForTest(t, c, srv.URL, "A")

	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf":     {csrf},
		"id":       {id},
		"internet": {"on"},
		"peers":    {"*"},
	})
	if err != nil {
		t.Fatalf("post policy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post policy = %d, want 302", resp.StatusCode)
	}

	rec, err := st.GetClient(id)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if rec.Internet == nil || !*rec.Internet {
		t.Fatalf("Internet = %v, want explicit true when internet field is on", rec.Internet)
	}
	if reg.reloadCalls != 1 {
		t.Fatalf("ReloadPolicy calls = %d, want 1", reg.reloadCalls)
	}
}

func TestUpdateClientPolicyEmptyPeersIsNobody(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	c := login(t, srv.URL)
	id := createClientForTest(t, c, srv.URL, "A")

	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf": {csrf},
		"id":   {id},
		// peers intentionally omitted -> [] (nobody)
	})
	if err != nil {
		t.Fatalf("post policy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post policy = %d, want 302", resp.StatusCode)
	}

	rec, err := st.GetClient(id)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if len(rec.VisiblePeers) != 0 {
		t.Fatalf("VisiblePeers = %v, want []", rec.VisiblePeers)
	}

	// Saving the same record again with no peer selection must preserve isolation.
	csrf = csrfOf(t, c, srv.URL, "/clients")
	resp, err = c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf": {csrf},
		"id":   {id},
	})
	if err != nil {
		t.Fatalf("post policy again: %v", err)
	}
	resp.Body.Close()
	rec, err = st.GetClient(id)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if len(rec.VisiblePeers) != 0 {
		t.Fatalf("VisiblePeers after re-save = %v, want []", rec.VisiblePeers)
	}
}

func TestUpdateClientPolicyAllOptionIsAll(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	c := login(t, srv.URL)
	id := createClientForTest(t, c, srv.URL, "A")

	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf":  {csrf},
		"id":    {id},
		"peers": {"*"},
	})
	if err != nil {
		t.Fatalf("post policy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post policy = %d, want 302", resp.StatusCode)
	}

	rec, err := st.GetClient(id)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if len(rec.VisiblePeers) != 1 || rec.VisiblePeers[0] != "*" {
		t.Fatalf("VisiblePeers = %v, want [*]", rec.VisiblePeers)
	}
}

func TestUpdateClientPolicyEditInternetKeepsIsolation(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	c := login(t, srv.URL)
	id := createClientForTest(t, c, srv.URL, "A")

	// First isolate the client.
	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf": {csrf},
		"id":   {id},
	})
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	resp.Body.Close()

	// Now edit only the internet checkbox; peers stays unselected.
	csrf = csrfOf(t, c, srv.URL, "/clients")
	resp, err = c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf":     {csrf},
		"id":       {id},
		"internet": {"on"},
	})
	if err != nil {
		t.Fatalf("enable internet: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post policy = %d, want 302", resp.StatusCode)
	}

	rec, err := st.GetClient(id)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if rec.Internet == nil || !*rec.Internet {
		t.Fatalf("Internet = %v, want explicit true", rec.Internet)
	}
	if len(rec.VisiblePeers) != 0 {
		t.Fatalf("VisiblePeers = %v, want []", rec.VisiblePeers)
	}
}

func TestUpdateClientPolicyUnknownID(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	c := login(t, srv.URL)
	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/policy", map[string][]string{
		"csrf":  {csrf},
		"id":    {"no-such-client"},
		"peers": {"*"},
	})
	if err != nil {
		t.Fatalf("post policy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("post policy unknown id = %d, want 404", resp.StatusCode)
	}
}

func TestServerPageShowsApplyBanner(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	c := login(t, srv.URL)
	resp, err := c.Get(srv.URL + "/server")
	if err != nil {
		t.Fatalf("get server: %v", err)
	}
	defer resp.Body.Close()
	pageBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read server page: %v", err)
	}
	page := string(pageBytes)
	if !strings.Contains(page, "restart") {
		t.Fatalf("server page missing 'restart'; page:\n%s", page)
	}
	if !strings.Contains(page, "re-import") {
		t.Fatalf("server page missing 're-import'; page:\n%s", page)
	}
}

func TestCreateClientInGroup(t *testing.T) {
	srv, st, reg := newTestPanel(t)
	c := login(t, srv.URL)

	// Create a custom group first.
	csrf := csrfOf(t, c, srv.URL, "/groups")
	resp, err := c.PostForm(srv.URL+"/groups/save", map[string][]string{
		"csrf":         {csrf},
		"name":         {"work"},
		"subnet":       {"10.77.5.0/24"},
		"server_ip":    {"10.77.5.1"},
		"internet":     {"on"},
		"visible_mode": {"same"},
	})
	if err != nil {
		t.Fatalf("save group: %v", err)
	}
	resp.Body.Close()
	groups, _ := st.ListGroups()
	var groupID string
	for _, g := range groups {
		if g.Name == "work" {
			groupID = g.ID
		}
	}
	if groupID == "" {
		t.Fatalf("work group not found in %d groups", len(groups))
	}

	// Create a client assigned to that group.
	csrf = csrfOf(t, c, srv.URL, "/clients")
	resp, err = c.PostForm(srv.URL+"/clients/create", map[string][]string{
		"csrf":     {csrf},
		"name":     {"laptop"},
		"group_id": {groupID},
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	resp.Body.Close()
	if len(reg.registered) != 1 {
		t.Fatalf("registered = %d, want 1", len(reg.registered))
	}
	rec := reg.registered[0]
	if rec.GroupID != groupID {
		t.Fatalf("GroupID = %q, want %q", rec.GroupID, groupID)
	}
	if !strings.HasPrefix(rec.IP, "10.77.5.") {
		t.Fatalf("IP %q not in group subnet", rec.IP)
	}
}

func TestMoveClientChangesGroup(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	c := login(t, srv.URL)
	id := createClientForTest(t, c, srv.URL, "A")

	csrf := csrfOf(t, c, srv.URL, "/groups")
	resp, err := c.PostForm(srv.URL+"/groups/save", map[string][]string{
		"csrf":         {csrf},
		"name":         {"work"},
		"subnet":       {"10.77.5.0/24"},
		"server_ip":    {"10.77.5.1"},
		"internet":     {"on"},
		"visible_mode": {"same"},
	})
	if err != nil {
		t.Fatalf("save group: %v", err)
	}
	resp.Body.Close()
	groups, _ := st.ListGroups()
	var groupID string
	for _, g := range groups {
		if g.Name == "work" {
			groupID = g.ID
		}
	}
	if groupID == "" {
		t.Fatalf("work group not found")
	}

	before, _ := st.GetClient(id)
	csrf = csrfOf(t, c, srv.URL, "/clients")
	resp, err = c.PostForm(srv.URL+"/clients/move", map[string][]string{
		"csrf":     {csrf},
		"id":       {id},
		"group_id": {groupID},
	})
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("move = %d, want 302", resp.StatusCode)
	}

	after, _ := st.GetClient(id)
	if after.GroupID != groupID {
		t.Fatalf("GroupID = %q, want %q", after.GroupID, groupID)
	}
	if after.IP == before.IP {
		t.Fatalf("IP unchanged after move: %s", after.IP)
	}
	if !strings.HasPrefix(after.IP, "10.77.5.") {
		t.Fatalf("IP %q not in new group subnet", after.IP)
	}
}

func TestGroupCRUD(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	c := login(t, srv.URL)

	csrf := csrfOf(t, c, srv.URL, "/groups")
	resp, err := c.PostForm(srv.URL+"/groups/save", map[string][]string{
		"csrf":         {csrf},
		"name":         {"work"},
		"subnet":       {"10.77.5.0/24"},
		"server_ip":    {"10.77.5.1"},
		"internet":     {"on"},
		"visible_mode": {"all"},
	})
	if err != nil {
		t.Fatalf("save group: %v", err)
	}
	resp.Body.Close()

	groups, _ := st.ListGroups()
	var g store.GroupRecord
	for _, gr := range groups {
		if gr.Name == "work" {
			g = gr
		}
	}
	if g.ID == "" {
		t.Fatalf("work group not found after save in %d groups", len(groups))
	}
	if g.Name != "work" || len(g.VisibleGroups) != 1 || g.VisibleGroups[0] != "*" {
		t.Fatalf("group = %+v", g)
	}

	// Edit to listed visibility.
	csrf = csrfOf(t, c, srv.URL, "/groups")
	resp, err = c.PostForm(srv.URL+"/groups/save", map[string][]string{
		"csrf":           {csrf},
		"id":             {g.ID},
		"name":           {"work"},
		"subnet":         {"10.77.5.0/24"},
		"server_ip":      {"10.77.5.1"},
		"internet":       {"on"},
		"visible_mode":   {"list"},
		"visible_groups": {"other"},
	})
	if err != nil {
		t.Fatalf("edit group: %v", err)
	}
	resp.Body.Close()
	g, _ = st.GetGroup(g.ID)
	if len(g.VisibleGroups) != 1 || g.VisibleGroups[0] != "other" {
		t.Fatalf("VisibleGroups after edit = %v", g.VisibleGroups)
	}

	// Delete.
	csrf = csrfOf(t, c, srv.URL, "/groups")
	resp, err = c.PostForm(srv.URL+"/groups/delete", map[string][]string{
		"csrf": {csrf},
		"id":   {g.ID},
	})
	if err != nil {
		t.Fatalf("delete group: %v", err)
	}
	resp.Body.Close()
	groups, _ = st.ListGroups()
	for _, gr := range groups {
		if gr.Name == "work" {
			t.Fatalf("work group still present after delete")
		}
	}
}

func TestNativeExportRequiresExternalIP(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	c := login(t, srv.URL)
	id := createClientForTest(t, c, srv.URL, "A")

	resp, err := c.Get(srv.URL + "/clients/native?id=" + id + "&mode=awg")
	if err != nil {
		t.Fatalf("get native: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("native without ExternalIP = %d, want 412", resp.StatusCode)
	}
}

func TestRevokedClientRefusedExport(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	c := login(t, srv.URL)
	id := createClientForTest(t, c, srv.URL, "A")

	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/revoke", map[string][]string{
		"csrf": {csrf},
		"id":   {id},
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()

	resp, err = c.Get(srv.URL + "/clients/import?id=" + id)
	if err != nil {
		t.Fatalf("get import: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("import revoked = %d, want 403", resp.StatusCode)
	}

	resp, err = c.Get(srv.URL + "/clients/native?id=" + id + "&mode=awg")
	if err != nil {
		t.Fatalf("get native: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("native revoked = %d, want 403", resp.StatusCode)
	}
}

func TestGroupSaveReloadRevert(t *testing.T) {
	srv, st, reg := newTestPanel(t)
	reg.reloadErr = fmt.Errorf("runtime reload failed")
	c := login(t, srv.URL)

	csrf := csrfOf(t, c, srv.URL, "/groups")
	resp, err := c.PostForm(srv.URL+"/groups/save", map[string][]string{
		"csrf":         {csrf},
		"name":         {"work"},
		"subnet":       {"10.77.5.0/24"},
		"server_ip":    {"10.77.5.1"},
		"internet":     {"on"},
		"visible_mode": {"same"},
	})
	if err != nil {
		t.Fatalf("save group: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("save group with failed reload = %d, want 500", resp.StatusCode)
	}
	groups, _ := st.ListGroups()
	for _, gr := range groups {
		if gr.Name == "work" {
			t.Fatalf("work group was not reverted")
		}
	}
}
