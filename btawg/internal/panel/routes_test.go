package panel

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"bittorrent-tunnel/btawg/internal/store"
)

func routePanelGet(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, %v: %s", url, resp.StatusCode, err, body)
	}
	return string(body)
}

func routePanelPost(t *testing.T, c *http.Client, url string, form url.Values, want int, wantLocation string) {
	t.Helper()
	resp, err := c.PostForm(url, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want || resp.Header.Get("Location") != wantLocation {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s = %d redirect %q, want %d redirect %q: %s", url, resp.StatusCode, resp.Header.Get("Location"), want, wantLocation, body)
	}
}

func routePanelRevision(t *testing.T, page string) string {
	t.Helper()
	_, tail, found := strings.Cut(page, `name="revision" value="`)
	if !found {
		t.Fatal("route form omitted revision")
	}
	return strings.SplitN(tail, `"`, 2)[0]
}

func TestRoutesPanelRequiresSessionAndCSRF(t *testing.T) {
	srv, _, _ := newTestPanel(t)
	guest := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for _, path := range []string{"/routes", "/routes/edit"} {
		resp, err := guest.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
			t.Fatalf("guest GET %s = %d redirect %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	admin := login(t, srv.URL)
	for _, path := range []string{"/routes/role", "/routes/save", "/routes/delete"} {
		routePanelPost(t, guest, srv.URL+path, nil, http.StatusFound, "/login")
		routePanelPost(t, admin, srv.URL+path, nil, http.StatusForbidden, "")
	}
}

func TestRoutesPanelManagesRolesAndRepairsStaleRoutes(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	admin := login(t, srv.URL)
	if err := st.SaveGroup(store.GroupRecord{ID: "team", Name: "Branch team", Subnet: "10.77.9.0/24", ServerIP: "10.77.9.1"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ id, name, group string }{
		{"laptop", "Laptop", "team"},
		{"relay", "Relay node", store.DefaultGroupID},
		{"wan", "Exit node", store.DefaultGroupID},
	} {
		if err := st.AllocateClient(store.ClientRecord{ID: c.id, Name: c.name, PeerID: c.id, PubKey: c.id + "-key", GroupID: c.group}); err != nil {
			t.Fatal(err)
		}
	}

	csrf := csrfOf(t, admin, srv.URL, "/routes")
	post := func(path string, form url.Values, want int, redirect string) {
		t.Helper()
		form.Set("csrf", csrf)
		if !form.Has("revision") {
			form.Set("revision", routePanelRevision(t, routePanelGet(t, admin, srv.URL+"/routes")))
		}
		routePanelPost(t, admin, srv.URL+path, form, want, redirect)
	}
	post("/routes/role", url.Values{"client_id": {"relay"}, "transit": {"on"}}, http.StatusFound, "/routes")
	post("/routes/role", url.Values{"client_id": {"wan"}, "exit": {"on"}}, http.StatusFound, "/routes")
	edit := routePanelGet(t, admin, srv.URL+"/routes/edit")
	for _, item := range []string{`action="/routes/save"`, `name="transit_id"`, `name="exit_id"`, "Relay node", "Exit node", "Laptop", "Branch team"} {
		if !strings.Contains(edit, item) {
			t.Errorf("new route form missing %q", item)
		}
	}
	form := url.Values{"name": {"Two hops"}, "transit_id": {"relay"}, "exit_id": {"wan"}, "clients": {"laptop"}, "groups": {"team"}}
	post("/routes/save", form, http.StatusFound, "/routes")
	routes, err := st.ListEgressRoutes()
	if err != nil || len(routes) != 1 || routes[0].ID == "" || routes[0].Name != "Two hops" ||
		!reflect.DeepEqual(routes[0].Hops, []string{"relay", "wan"}) ||
		!reflect.DeepEqual(routes[0].Clients, []string{"laptop"}) ||
		!reflect.DeepEqual(routes[0].Groups, []string{"team"}) {
		t.Fatalf("posted route = %+v, %v", routes, err)
	}
	id := routes[0].ID
	list := routePanelGet(t, admin, srv.URL+"/routes")
	if !strings.Contains(list, "Two hops") || !strings.Contains(list, "Transit: Relay node") || !strings.Contains(list, "Exit: Exit node") {
		t.Fatalf("route page does not show name and hop positions: %s", list)
	}
	swapped := url.Values{"id": {id}, "name": {"Wrong order"}, "transit_id": {"wan"}, "exit_id": {"relay"}}
	post("/routes/save", swapped, http.StatusBadRequest, "")
	if r, _, err := st.ResolveEgressRoute("laptop", id); err != nil || r.Name != "Two hops" {
		t.Fatalf("bad edit altered stored route: %+v, %v", r, err)
	}

	post("/routes/role", url.Values{"client_id": {"relay"}}, http.StatusFound, "/routes")
	if _, _, err := st.ResolveEgressRoute("laptop", id); err == nil {
		t.Fatal("role removal left route authorized")
	}
	edit = routePanelGet(t, admin, srv.URL+"/routes/edit?id="+url.QueryEscape(id))
	form.Set("revision", routePanelRevision(t, edit))
	if !strings.Contains(edit, `value="relay" selected`) || !strings.Contains(edit, "unavailable") {
		t.Fatalf("edit form did not keep stale transit visibly selected: %s", edit)
	}
	form.Set("id", id)
	form.Set("name", "One hop")
	post("/routes/save", form, http.StatusBadRequest, "") // Must explicitly remove the stale hop.
	form.Del("transit_id")
	post("/routes/save", form, http.StatusFound, "/routes")
	if r, h, err := st.ResolveEgressRoute("laptop", id); err != nil || r.Name != "One hop" || len(h) != 1 || h[0].ID != "wan" {
		t.Fatalf("repair = %+v, %d hops, %v", r, len(h), err)
	}
	if err := st.RevokeClient("wan"); err != nil {
		t.Fatal(err)
	}
	post("/routes/delete", url.Values{"id": {id}}, http.StatusFound, "/routes")
	if routes, err := st.ListEgressRoutes(); err != nil || len(routes) != 0 {
		t.Fatalf("revoked route was not deleted: %+v, %v", routes, err)
	}
}

func TestRoutesPanelRejectsStaleSaveDeleteAndRoleForms(t *testing.T) {
	srv, st, _ := newTestPanel(t)
	admin := login(t, srv.URL)
	for _, id := range []string{"origin", "exit"} {
		if err := st.AllocateClient(store.ClientRecord{ID: id, PeerID: id, PubKey: id + "-key", GroupID: store.DefaultGroupID}); err != nil {
			t.Fatal(err)
		}
	}
	role := store.EgressRole{Exit: true}
	if err := st.SetEgressRole("exit", role); err != nil {
		t.Fatal(err)
	}
	r := store.EgressRoute{ID: "route", Name: "Named route", Hops: []string{"exit"}, Clients: []string{"origin"}}
	if err := st.SaveEgressRoute(r); err != nil {
		t.Fatal(err)
	}
	csrf := csrfOf(t, admin, srv.URL, "/routes")
	staleList := routePanelRevision(t, routePanelGet(t, admin, srv.URL+"/routes"))
	staleEdit := routePanelRevision(t, routePanelGet(t, admin, srv.URL+"/routes/edit?id=route"))
	// An independent admin removes the ACL and changes the role policy.
	r.Clients = nil
	if err := st.SaveEgressRoute(r); err != nil {
		t.Fatal(err)
	}
	role.Transit = true
	if err := st.SetEgressRole("exit", role); err != nil {
		t.Fatal(err)
	}
	routePanelPost(t, admin, srv.URL+"/routes/save", url.Values{
		"csrf": {csrf}, "revision": {staleEdit}, "id": {r.ID}, "name": {r.Name}, "exit_id": {"exit"}, "clients": {"origin"},
	}, http.StatusConflict, "")
	routePanelPost(t, admin, srv.URL+"/routes/delete", url.Values{
		"csrf": {csrf}, "revision": {staleList}, "id": {r.ID},
	}, http.StatusConflict, "")
	routePanelPost(t, admin, srv.URL+"/routes/role", url.Values{
		"csrf": {csrf}, "revision": {staleList}, "client_id": {"exit"}, "exit": {"on"},
	}, http.StatusConflict, "")
	routePanelPost(t, admin, srv.URL+"/routes/role", url.Values{
		"csrf": {csrf}, "client_id": {"exit"}, "exit": {"on"},
	}, http.StatusBadRequest, "")
	if routes, err := st.ListEgressRoutes(); err != nil || len(routes) != 1 || len(routes[0].Clients) != 0 {
		t.Fatalf("stale submit changed current route: %+v, %v", routes, err)
	}
	if got, err := st.EgressRole("exit"); err != nil || got != role {
		t.Fatalf("stale submit changed current roles: %+v, %v", got, err)
	}
}
