package panel

import (
	"errors"
	"net/http"
	"slices"
	"strconv"

	"bittorrent-tunnel/btawg/internal/store"
)

type routeDevice struct {
	ID, Name, IP string
	Revoked      bool
	Role         store.EgressRole
}

type routeOption struct {
	ID, Label   string
	Selected    bool
	Unavailable bool
}

func (p *Panel) routeDevices() ([]routeDevice, error) {
	clients, err := p.st.ListClients()
	if err != nil {
		return nil, err
	}
	devices := make([]routeDevice, 0, len(clients))
	for _, c := range clients {
		role, err := p.st.EgressRole(c.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue // Deleted after listing; mutations validate again in the store.
		}
		if err != nil {
			return nil, err
		}
		name := c.Name
		if name == "" {
			name = c.ID
		}
		devices = append(devices, routeDevice{ID: c.ID, Name: name, IP: c.IP, Revoked: c.Revoked, Role: role})
	}
	return devices, nil
}

func (p *Panel) routesPage(w http.ResponseWriter, r *http.Request) {
	sess := p.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	revision, err := p.st.EgressRevision()
	if err != nil {
		writeRouteError(w, err)
		return
	}
	routes, err := p.st.ListEgressRoutes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	devices, err := p.routeDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, err := p.st.ListGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	deviceNames := make(map[string]string, len(devices))
	for _, d := range devices {
		deviceNames[d.ID] = d.Name
	}
	p.render(w, "routes", map[string]any{
		"Active":      "routes",
		"CSRF":        sess.csrf,
		"Revision":   revision,
		"Routes":      routes,
		"Devices":     devices,
		"DeviceNames": deviceNames,
		"GroupNames":  groupNames(groups),
	})
}

func (p *Panel) routeByID(id string) (store.EgressRoute, error) {
	routes, err := p.st.ListEgressRoutes()
	if err != nil {
		return store.EgressRoute{}, err
	}
	for _, r := range routes {
		if r.ID == id {
			return r, nil
		}
	}
	return store.EgressRoute{}, store.ErrEgressRouteNotFound
}

func addUnavailableRouteOptions(options []routeOption, selected []string) []routeOption {
	for _, id := range selected {
		if !slices.ContainsFunc(options, func(o routeOption) bool { return o.ID == id }) {
			options = append(options, routeOption{ID: id, Label: id, Selected: true, Unavailable: true})
		}
	}
	return options
}

func (p *Panel) routeEdit(w http.ResponseWriter, r *http.Request) {
	sess := p.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	revision, err := p.st.EgressRevision()
	if err != nil {
		writeRouteError(w, err)
		return
	}
	var route store.EgressRoute
	if id := r.URL.Query().Get("id"); id != "" {
		route, err = p.routeByID(id)
		if err != nil {
			writeRouteError(w, err)
			return
		}
	}
	devices, err := p.routeDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, err := p.st.ListGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var transitID, exitID string
	if len(route.Hops) == 2 {
		transitID = route.Hops[0]
	}
	if len(route.Hops) != 0 {
		exitID = route.Hops[len(route.Hops)-1]
	}
	var transits, exits, audience []routeOption
	for _, d := range devices {
		label := d.Name + " (" + d.IP + ")"
		if selected := d.ID == transitID; selected || (d.Role.Transit && !d.Revoked) {
			transits = append(transits, routeOption{ID: d.ID, Label: label, Selected: selected, Unavailable: !d.Role.Transit || d.Revoked})
		}
		if selected := d.ID == exitID; selected || (d.Role.Exit && !d.Revoked) {
			exits = append(exits, routeOption{ID: d.ID, Label: label, Selected: selected, Unavailable: !d.Role.Exit || d.Revoked})
		}
		if selected := slices.Contains(route.Clients, d.ID); selected || !d.Revoked {
			audience = append(audience, routeOption{ID: d.ID, Label: label, Selected: selected, Unavailable: d.Revoked})
		}
	}
	if transitID != "" {
		transits = addUnavailableRouteOptions(transits, []string{transitID})
	}
	if exitID != "" {
		exits = addUnavailableRouteOptions(exits, []string{exitID})
	}
	groupOptions := make([]routeOption, 0, len(groups))
	for _, g := range groups {
		name := g.Name
		if name == "" {
			name = g.ID
		}
		groupOptions = append(groupOptions, routeOption{ID: g.ID, Label: name + " (" + g.Subnet + ")", Selected: slices.Contains(route.Groups, g.ID)})
	}
	p.render(w, "route-edit", map[string]any{
		"Active":   "routes",
		"CSRF":     sess.csrf,
		"Revision": revision,
		"Route":    route,
		"Transit":  transits,
		"Exit":     exits,
		"Clients":  addUnavailableRouteOptions(audience, route.Clients),
		"Groups":   addUnavailableRouteOptions(groupOptions, route.Groups),
	})
}

func readRouteRevision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	revision, err := strconv.ParseUint(r.PostFormValue("revision"), 10, 64)
	if err != nil {
		http.Error(w, "missing or invalid route settings revision", http.StatusBadRequest)
		return 0, false
	}
	return revision, true
}

func (p *Panel) routeSave(w http.ResponseWriter, r *http.Request) {
	revision, ok := readRouteRevision(w, r)
	if !ok {
		return
	}
	id := r.PostFormValue("id")
	create := id == ""
	if create {
		id = randHex(16)
	}
	exit := r.PostFormValue("exit_id")
	hops := []string{exit}
	if transit := r.PostFormValue("transit_id"); transit != "" {
		hops = []string{transit, exit}
	}
	route := store.EgressRoute{
		ID:      id,
		Name:    r.PostFormValue("name"),
		Hops:    hops,
		Clients: r.PostForm["clients"],
		Groups:  r.PostForm["groups"],
	}
	var err error
	if create {
		err = p.st.CreateEgressRouteAtRevision(route, revision)
	} else {
		err = p.st.SaveEgressRouteAtRevision(route, revision)
	}
	if err != nil {
		writeRouteError(w, err)
		return
	}
	http.Redirect(w, r, "/routes", http.StatusFound)
}

func (p *Panel) routeDelete(w http.ResponseWriter, r *http.Request) {
	revision, ok := readRouteRevision(w, r)
	if !ok {
		return
	}
	if err := p.st.DeleteEgressRouteAtRevision(r.PostFormValue("id"), revision); err != nil {
		writeRouteError(w, err)
		return
	}
	http.Redirect(w, r, "/routes", http.StatusFound)
}

func (p *Panel) routeRole(w http.ResponseWriter, r *http.Request) {
	revision, ok := readRouteRevision(w, r)
	if !ok {
		return
	}
	role := store.EgressRole{Exit: r.PostForm.Has("exit"), Transit: r.PostForm.Has("transit")}
	if err := p.st.SetEgressRoleAtRevision(r.PostFormValue("client_id"), role, revision); err != nil {
		writeRouteError(w, err)
		return
	}
	http.Redirect(w, r, "/routes", http.StatusFound)
}

func writeRouteError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, store.ErrEgressRouteNotFound), errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, store.ErrEgressConflict):
		status = http.StatusConflict
	case errors.Is(err, store.ErrInvalidEgressRoute), errors.Is(err, store.ErrEgressRouteUnavailable):
		status = http.StatusBadRequest
	}
	http.Error(w, err.Error(), status)
}

const routesTmpl = `{{define "content"}}
<h1>Routes</h1>
<p class="intro">Manage named exits for client SOCKS5 ports. The server Internet policy controls hub egress separately. Devices must also enable their roles locally.</p>
<p><a class="button" href="/routes/edit">Add route</a></p>
<div class="card"><h2>Named routes</h2>
{{if .Routes}}
<table><tr><th>Name</th><th>Hop order</th><th>Allowed origins</th><th>Actions</th></tr>
{{range .Routes}}
<tr><td><a href="/routes/edit?id={{.ID}}">{{.Name}}</a></td>
<td><ol>{{$hops := .Hops}}{{range $i, $id := $hops}}<li>{{if and (eq (len $hops) 2) (eq $i 0)}}Transit{{else}}Exit{{end}}: {{or (index $.DeviceNames $id) $id}}</li>{{end}}</ol></td>
<td>{{if or .Clients .Groups}}
{{range .Clients}}<div>Client: {{or (index $.DeviceNames .) .}}</div>{{end}}
{{range .Groups}}<div>Group: {{or (index $.GroupNames .) .}}</div>{{end}}
{{else}}Nobody{{end}}</td>
<td><form method="post" action="/routes/delete" onsubmit="return confirm('Delete this route?')">
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
<input type="hidden" name="revision" value="{{$.Revision}}">
<button class="warn">Delete</button></form></td></tr>
{{end}}
</table>
{{else}}<p>No named routes configured.</p>{{end}}
</div>
<div class="card"><h2>Device roles</h2>
{{range .Devices}}
{{if .Revoked}}<p>{{.Name}} ({{.IP}}) — revoked</p>
{{else}}<form method="post" action="/routes/role" class="row">
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="client_id" value="{{.ID}}">
<input type="hidden" name="revision" value="{{$.Revision}}">
<div><strong>{{.Name}}</strong> ({{.IP}})</div>
<div><label><input type="checkbox" name="transit" value="on" {{if .Role.Transit}}checked{{end}}> Transit</label></div>
<div><label><input type="checkbox" name="exit" value="on" {{if .Role.Exit}}checked{{end}}> Exit</label></div>
<div><button>Save roles</button></div>
</form>{{end}}
{{else}}<p>No clients configured.</p>{{end}}
</div>
{{end}}`

const routeEditTmpl = `{{define "content"}}
<h1>{{if .Route.ID}}Edit{{else}}Create{{end}} route</h1>
<form method="post" action="/routes/save">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="revision" value="{{.Revision}}">
{{if .Route.ID}}<input type="hidden" name="id" value="{{.Route.ID}}">{{end}}
<div class="card">
<label>Name<input name="name" value="{{.Route.Name}}" maxlength="128" required></label>
<h2>Hop order</h2>
<label>First: transit (optional)
<select name="transit_id"><option value="">No transit</option>
{{range .Transit}}<option value="{{.ID}}" {{if .Selected}}selected{{end}}>{{.Label}}{{if .Unavailable}} — unavailable{{end}}</option>{{end}}
</select></label>
<label>Final: exit (required)
<select name="exit_id" required><option value="">Choose an exit</option>
{{range .Exit}}<option value="{{.ID}}" {{if .Selected}}selected{{end}}>{{.Label}}{{if .Unavailable}} — unavailable{{end}}</option>{{end}}
</select></label>
</div>
<div class="card"><h2>Allowed origins</h2>
<p>Allow individual clients, members of selected groups, or both. With nothing selected, nobody can use this route.</p>
<fieldset><legend>Clients</legend>
{{range .Clients}}<label><input type="checkbox" name="clients" value="{{.ID}}" {{if .Selected}}checked{{end}}> {{.Label}}{{if .Unavailable}} — unavailable{{end}}</label>
{{else}}<p>No clients available.</p>{{end}}
</fieldset>
<fieldset><legend>Groups</legend>
{{range .Groups}}<label><input type="checkbox" name="groups" value="{{.ID}}" {{if .Selected}}checked{{end}}> {{.Label}}{{if .Unavailable}} — unavailable{{end}}</label>
{{else}}<p>No groups available.</p>{{end}}
</fieldset>
</div>
<button>Save route</button> <a href="/routes">Cancel</a>
</form>
{{end}}`
