package panel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"bittorrent-tunnel/btawg/internal/config"
	"bittorrent-tunnel/btawg/internal/store"
)

func newManagedTestPanel(t *testing.T) (*httptest.Server, *store.Store, *fakeRegistry) {
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
	reg := &fakeRegistry{managed: true}
	p := New(st, reg, "admin", string(hash))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv, st, reg
}

func TestManagedServerPageShowsFixedPorts(t *testing.T) {
	srv, _, _ := newManagedTestPanel(t)
	c := login(t, srv.URL)
	resp, err := c.Get(srv.URL + "/server")
	if err != nil {
		t.Fatalf("get server: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(body)
	if !strings.Contains(page, "Managed service") {
		t.Fatalf("missing managed note: %s", page)
	}
	if strings.Contains(page, `name="awg_port"`) {
		t.Fatalf("awg_port input should be read-only in managed mode")
	}
	if strings.Contains(page, `name="wg_port"`) {
		t.Fatalf("wg_port input should be read-only in managed mode")
	}
	if !strings.Contains(page, `name="panel_port"`) {
		t.Fatalf("panel_port input must remain editable in managed mode")
	}
}

func TestManagedServerSubmitForcesFixedPorts(t *testing.T) {
	srv, st, _ := newManagedTestPanel(t)
	c := login(t, srv.URL)
	csrf := csrfOf(t, c, srv.URL, "/server")
	form := map[string][]string{
		"csrf": {csrf},
		"jc":   {"4"}, "jmin": {"40"}, "jmax": {"100"},
		"s1": {"32"}, "s2": {"32"}, "s3": {"32"}, "s4": {"32"},
		"h1": {"101"}, "h2": {"102"}, "h3": {"103"}, "h4": {"104"},
		"transport":    {"ext-tcp"},
		"carrier_port": {"17777"}, "awg_port": {"17778"}, "wg_port": {"17779"},
		"panel_port":  {"18080"},
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
	if cfg.CarrierPort != 6881 || cfg.AWGPort != 51821 || cfg.WGPort != 51820 {
		t.Fatalf("managed ports not forced: %+v", cfg)
	}
	if cfg.PanelPort != 18080 {
		t.Fatalf("panel port should remain editable: got %d", cfg.PanelPort)
	}
	if cfg.Transport != config.ModeExtTCP || cfg.ExternalIP != "203.0.113.7" {
		t.Fatalf("transport/ip not saved: %+v", cfg)
	}
}

func TestPanelCopiesRawClientImport(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	c := login(t, srv.URL)
	csrf := csrfOf(t, c, srv.URL, "/clients")
	resp, err := c.PostForm(srv.URL+"/clients/create", map[string][]string{"csrf": {csrf}, "name": {"laptop"}})
	if err != nil {
		t.Fatalf("post create: %v", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	resp, err = c.Get(srv.URL + loc)
	if err != nil {
		t.Fatalf("get import: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_, content, ok := strings.Cut(string(body), `<pre class="mono" id="import-string">`)
	if !ok {
		t.Fatal("missing raw import field")
	}
	raw, _, _ := strings.Cut(content, "</pre>")
	cfg, err := config.ParseImportString(raw)
	if err != nil || cfg.ClientIP == "" {
		t.Fatal("raw import field does not contain a usable client configuration")
	}
}
