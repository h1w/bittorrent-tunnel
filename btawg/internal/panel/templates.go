package panel

import (
	"html/template"
	"net/http"
)

// layout is the 3x-ui-inspired shell: dark top bar, sidebar, content pane.
const layout = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>btawg</title>
<style>
:root{--bg:#12151c;--panel:#1a1f2a;--line:#2a3140;--fg:#e6e9f0;--muted:#8b94a7;--accent:#4f8cff;--ok:#3ecf8e;--warn:#e5b455}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
a{color:var(--accent);text-decoration:none}
header{display:flex;align-items:center;gap:16px;padding:12px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
header .brand{font-weight:700;font-size:16px}
header form{margin-left:auto}
.container{display:flex;min-height:calc(100vh - 53px)}
nav{width:190px;background:var(--panel);border-right:1px solid var(--line);padding:14px 0}
nav a{display:block;padding:10px 20px;color:var(--muted)}
nav a.active,nav a:hover{color:var(--fg);background:var(--line)}
main{flex:1;padding:24px;max-width:860px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:18px}
h1{font-size:18px;margin:0 0 14px}
h2{font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:0 0 10px}
table{width:100%;border-collapse:collapse}
td,th{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left}
th{color:var(--muted);font-weight:500}
input,select{background:var(--bg);border:1px solid var(--line);border-radius:5px;color:var(--fg);padding:7px 9px;width:100%}
input:focus,select:focus{outline:1px solid var(--accent)}
button{background:var(--accent);border:0;border-radius:5px;color:#fff;padding:8px 16px;cursor:pointer;font-weight:600}
button.warn{background:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px}
.grid label{font-size:12px;color:var(--muted)}
.row{display:flex;gap:10px;align-items:flex-end}
.row>div{flex:1}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px}
.tag.ok{background:rgba(62,207,142,.15);color:var(--ok)}
.tag.off{background:rgba(139,148,167,.15);color:var(--muted)}
.mono{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all;background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:10px}
.note{color:var(--warn);font-size:12px}
.err{color:#ff6b6b;margin-bottom:10px}
</style>
</head>
<body>
<header><span class="brand">⚡ btawg</span>
{{if .Active}}<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Logout</button></form>{{end}}
</header>
<div class="container">
{{if .Active}}
<nav>
<a href="/" {{if eq .Active "dashboard"}}class="active"{{end}}>Dashboard</a>
<a href="/server" {{if eq .Active "server"}}class="active"{{end}}>Server settings</a>
<a href="/groups" {{if eq .Active "groups"}}class="active"{{end}}>Groups</a>
<a href="/clients" {{if eq .Active "clients"}}class="active"{{end}}>Clients</a>
</nav>
{{end}}
<main>{{template "content" .}}</main>
</div>
</body></html>`

const loginTmpl = `{{define "content"}}
<div class="card" style="max-width:360px;margin:80px auto">
<h1>Sign in to btawg</h1>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/login">
<label>Username<br><input name="username" autocomplete="username"></label><br><br>
<label>Password<br><input type="password" name="password" autocomplete="current-password"></label><br><br>
<button style="width:100%">Login</button>
</form>
</div>
{{end}}`

const dashboardTmpl = `{{define "content"}}
<h1>Dashboard</h1>
<div class="card"><h2>Hub</h2>
<table>
<tr><th>Infohash</th><td class="mono">{{.InfoHash}}</td></tr>
<tr><th>Public key</th><td class="mono">{{.PubKey}}</td></tr>
<tr><th>Transport</th><td>{{.Cfg.Transport}}</td></tr>
<tr><th>Carrier port</th><td>{{.Cfg.CarrierPort}}</td></tr>
<tr><th>Native ports</th><td>AWG {{.Cfg.AWGPort}}, WG {{.Cfg.WGPort}}</td></tr>
<tr><th>Clients</th><td>{{len .Clients}}</td></tr>
<tr><th>Groups</th><td>{{len .Groups}}</td></tr>
</table>
</div>
<div class="card"><h2>Connected carriers</h2>
{{if .Connected}}
<table><tr><th>Overlay IP</th><th>Carriers</th></tr>
{{range $ip, $n := .Connected}}<tr><td>{{$ip}}</td><td>{{$n}}</td></tr>{{end}}
</table>
{{else}}<div class="tag off">no clients connected</div>{{end}}
</div>
{{end}}`

const serverTmpl = `{{define "content"}}
<h1>Server settings</h1>
{{if .Saved}}<div class="tag ok">saved — restart required for transport/port/IP changes; re-import required for AWG profile changes</div>{{end}}
<div class="note">Pending settings are shown in the form. The running hub uses the active settings on the right. Transport, carrier/native ports and ExternalIP need a restart; AWG profile changes need clients to re-import.</div>
<form method="post" action="/server">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="card"><h2>AWG profile (BitTorrent + native AWG)</h2>
<div class="grid">
<label>jc<input name="jc" value="{{.Cfg.AWGProfile.JC}}"></label>
<label>jmin<input name="jmin" value="{{.Cfg.AWGProfile.JMin}}"></label>
<label>jmax<input name="jmax" value="{{.Cfg.AWGProfile.JMax}}"></label>
<label>s1<input name="s1" value="{{.Cfg.AWGProfile.S1}}"></label>
<label>s2<input name="s2" value="{{.Cfg.AWGProfile.S2}}"></label>
<label>s3<input name="s3" value="{{.Cfg.AWGProfile.S3}}"></label>
<label>s4<input name="s4" value="{{.Cfg.AWGProfile.S4}}"></label>
<label>h1<input name="h1" value="{{.Cfg.AWGProfile.H1}}"></label>
<label>h2<input name="h2" value="{{.Cfg.AWGProfile.H2}}"></label>
<label>h3<input name="h3" value="{{.Cfg.AWGProfile.H3}}"></label>
<label>h4<input name="h4" value="{{.Cfg.AWGProfile.H4}}"></label>
</div>
{{if ne .Cfg.AWGProfile.String .ActiveCfg.AWGProfile.String}}<div class="note">Profile differs from active config — clients must re-import.</div>{{end}}
</div>
<div class="card"><h2>Preferred mode &amp; transport</h2>
<div class="row">
<div><label>Mode
<select name="transport">
{{$t := .Cfg.Transport}}
<option value="ext-utp" {{if eq $t "ext-utp"}}selected{{end}}>extended (BEP 10) over µTP no-Nagle</option>
<option value="ext-tcp" {{if eq $t "ext-tcp"}}selected{{end}}>extended (BEP 10) over TCP</option>
<option value="req-utp" {{if eq $t "req-utp"}}selected{{end}}>request/piece over µTP no-Nagle</option>
<option value="req-tcp" {{if eq $t "req-tcp"}}selected{{end}}>request/piece over TCP</option>
<option value="awg" {{if eq $t "awg"}}selected{{end}}>native AmneziaWG UDP</option>
<option value="wg" {{if eq $t "wg"}}selected{{end}}>native WireGuard UDP</option>
</select></label></div>
<div><label>Carrier port<input name="carrier_port" value="{{.Cfg.CarrierPort}}"></label></div>
<div><label>External IP (announce &amp; native)<input name="external_ip" value="{{.Cfg.ExternalIP}}" placeholder="autodetect"></label></div>
</div>
<div class="note">Carrier modes use the BitTorrent framing. Native modes require ExternalIP to be set.</div>
{{if ne .Cfg.Transport .ActiveCfg.Transport}}<div class="note">Transport differs from active config — restart required.</div>{{end}}
</div>
<div class="card"><h2>Ports</h2>
<div class="row">
<div><label>Native AWG UDP<input name="awg_port" value="{{.Cfg.AWGPort}}"></label></div>
<div><label>Native WG UDP<input name="wg_port" value="{{.Cfg.WGPort}}"></label></div>
<div><label>Egress SOCKS5 (overlay)<input name="socks_port" value="{{.Cfg.SocksPort}}"></label></div>
<div><label>Panel (loopback)<input name="panel_port" value="{{.Cfg.PanelPort}}"></label></div>
</div>
{{if or (ne .Cfg.CarrierPort .ActiveCfg.CarrierPort) (ne .Cfg.AWGPort .ActiveCfg.AWGPort) (ne .Cfg.WGPort .ActiveCfg.WGPort) (ne .Cfg.SocksPort .ActiveCfg.SocksPort) (ne .Cfg.PanelPort .ActiveCfg.PanelPort)}}<div class="note">Port changes differ from active config — restart required.</div>{{end}}
</div>
<button>Save settings</button>
</form>
{{end}}`

const clientsTmpl = `{{define "content"}}
<h1>Clients</h1>
<div class="card"><h2>Create client</h2>
<form method="post" action="/clients/create">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="row"><div><label>Name (optional)<input name="name" placeholder="laptop"></label></div>
<div><label>Group
<select name="group_id">
<option value="{{.DefaultID}}">Default</option>
{{range .Groups}}<option value="{{.ID}}">{{.Name}}</option>{{end}}
</select></label></div>
<div style="flex:0"><button>Create → import string</button></div></div>
</form>
</div>
<div class="card"><h2>Deployed</h2>
{{if .Clients}}
<table><tr><th>Name</th><th>Group</th><th>Overlay IP</th><th>Status</th><th>Policy</th><th></th><th></th><th></th></tr>
{{$cs := .Connected}}{{$groups := .Groups}}{{$def := .DefaultID}}
{{range .Clients}}
<tr><td>{{.Name}}</td><td>{{if eq .GroupID $def}}Default{{else}}{{.GroupID}}{{end}}</td><td>{{.IP}}</td>
<td>{{if index $cs .IP}}<span class="tag ok">connected</span>{{else if .Revoked}}<span class="tag off">revoked</span>{{else}}<span class="tag off">offline</span>{{end}}</td>
<td>{{if not .Revoked}}
<form method="post" action="/clients/policy" style="display:flex;gap:8px;align-items:center">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="id" value="{{.ID}}">
<select name="internet" style="min-width:90px">
<option value="inherit" {{if not .Internet}}selected{{end}}>inherit</option>
<option value="on" {{if and .Internet (deref .Internet)}}selected{{end}}>internet on</option>
<option value="off" {{if and .Internet (not (deref .Internet))}}selected{{end}}>internet off</option>
</select>
<select name="peers" multiple size="3" style="min-width:120px">
<option value="inherit" {{if unset .VisiblePeers}}selected{{end}}>inherit (group)</option>
<option value="none" {{if and (not (unset .VisiblePeers)) (not .VisiblePeers)}}selected{{end}}>Nobody</option>
<option value="*" {{if contains .VisiblePeers "*"}}selected{{end}}>All</option>
{{$self := .ID}}{{$vp := .VisiblePeers}}
{{range $.Clients}}{{if ne .ID $self}}<option value="{{.ID}}" {{if contains $vp .ID}}selected{{end}}>{{.Name}}</option>{{end}}{{end}}
</select>
<button>Save</button>
</form>
{{end}}</td>
<td><a href="/clients/import?id={{.ID}}">import</a></td>
<td>{{if not .Revoked}}<form method="post" action="/clients/move" style="display:flex;gap:4px">
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
<select name="group_id"><option value="{{$def}}">Default</option>{{range $groups}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select>
<button>Move</button></form>{{end}}</td>
<td>{{if not .Revoked}}<form method="post" action="/clients/revoke" onsubmit="return confirm('Revoke this client?')">
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
<button class="warn">Revoke</button></form>{{end}}</td>
</tr>
{{end}}
</table>
{{else}}<div class="tag off">no clients yet</div>{{end}}
</div>
{{end}}`

const importTmpl = `{{define "content"}}
<h1>Import string — {{.Client.Name}}</h1>
<div class="card"><h2>btawg:// client bootstrap</h2>
<p>This string is a <b>secret</b>: it carries the client's private key. Run on any PC:</p>
<pre class="mono">btawg-client '{{.Import}}'</pre>
<p class="note">Copy it over a trusted channel. New imports connect directly. Select a carrier with <code>-transport</code> and use <code>-dht</code> when you want carrier discovery instead.</p>
</div>
<div class="card"><h2>Native config export</h2>
<p>For standard WireGuard/AmneziaWG apps (requires ExternalIP):</p>
<p>
<a href="/clients/native?id={{.Client.ID}}&mode=awg"><button>AWG config</button></a>
<a href="/clients/native?id={{.Client.ID}}&mode=wg"><button>WG config</button></a>
</p>
</div>
<p><a href="/clients">← back to clients</a></p>
{{end}}`

const nativeTmpl = `{{define "content"}}
<h1>Native {{.Mode}} config — {{.Client.Name}}</h1>
<div class="card"><h2>WireGuard/AmneziaWG import text</h2>
<p>Paste into the native app. The text contains keys and endpoint only; routes are managed.</p>
<pre class="mono">{{.Config}}</pre>
<p class="note">Do not share the private_key value.</p>
<p><a href="/clients/import?id={{.Client.ID}}">← back to import</a></p>
</div>
{{end}}`

const groupsTmpl = `{{define "content"}}
<h1>Groups</h1>
<div class="card"><a href="/groups/edit"><button>Create group</button></a></div>
<div class="card"><h2>Groups</h2>
{{if .Groups}}
<table><tr><th>Name</th><th>Subnet</th><th>Gateway</th><th>Internet</th><th>Visible groups</th><th></th></tr>
{{range .Groups}}
<tr>
<td><a href="/groups/edit?id={{.ID}}">{{.Name}}</a></td>
<td>{{.Subnet}}</td>
<td>{{.ServerIP}}</td>
<td>{{if .NoInternet}}off{{else}}on{{end}}</td>
<td>{{if unset .VisibleGroups}}same group{{else if not .VisibleGroups}}none{{else if contains .VisibleGroups "*"}}all{{else}}{{range .VisibleGroups}}{{.}} {{end}}{{end}}</td>
<td>{{if ne .ID "default"}}<form method="post" action="/groups/delete" onsubmit="return confirm('Delete this empty group?')">
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
<button class="warn">Delete</button></form>{{end}}</td>
</tr>
{{end}}
</table>
{{else}}<div class="tag off">no custom groups; all clients use the default group</div>{{end}}
</div>
{{end}}`

const groupEditTmpl = `{{define "content"}}
<h1>{{if .Group.ID}}Edit{{else}}Create{{end}} group</h1>
<form method="post" action="/groups/save">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Group.ID}}<input type="hidden" name="id" value="{{.Group.ID}}">{{end}}
<div class="card">
<div class="row">
<div><label>Name<input name="name" value="{{.Group.Name}}" placeholder="work-net"></label></div>
<div><label>Subnet<input name="subnet" value="{{.Group.Subnet}}" placeholder="10.77.1.0/24"></label></div>
<div><label>Gateway<input name="server_ip" value="{{.Group.ServerIP}}" placeholder="10.77.1.1"></label></div>
</div>
<div class="row" style="margin-top:10px">
<div><label style="white-space:nowrap"><input type="checkbox" name="internet" value="on" {{if and .Group.ID (not .Group.NoInternet)}}checked{{end}}> internet access</label></div>
</div>
<div class="row">
<div><label>Visible groups
<select name="visible_mode">
<option value="same" {{if unset .Group.VisibleGroups}}selected{{end}}>same group only</option>
<option value="none" {{if and (not (unset .Group.VisibleGroups)) (not .Group.VisibleGroups)}}selected{{end}}>none</option>
<option value="all" {{if contains .Group.VisibleGroups "*"}}selected{{end}}>all groups</option>
<option value="list" {{if and .Group.VisibleGroups (not (contains .Group.VisibleGroups "*"))}}selected{{end}}>listed groups</option>
</select></label></div>
<div><label>Listed group IDs (comma-separated)<input name="visible_groups" value="{{if and .Group.VisibleGroups (not (contains .Group.VisibleGroups "*"))}}{{range .Group.VisibleGroups}}{{.}},{{end}}{{end}}" placeholder="group-a, group-b"></label></div>
</div>
</div>
<button>Save group</button>
</form>
{{end}}`

var layoutTmpl = template.Must(template.New("layout").Parse(layout))

var pages = map[string]*template.Template{}

func init() {
	funcs := template.FuncMap{
		"contains": func(haystack []string, needle string) bool {
			for _, s := range haystack {
				if s == needle {
					return true
				}
			}
			return false
		},
		"deref": func(b *bool) bool {
			return b != nil && *b
		},
		"unset": func(v []string) bool { return v == nil },
	}
	for name, body := range map[string]string{
		"login":      loginTmpl,
		"dashboard":  dashboardTmpl,
		"server":     serverTmpl,
		"clients":    clientsTmpl,
		"import":     importTmpl,
		"native":     nativeTmpl,
		"groups":     groupsTmpl,
		"group-edit": groupEditTmpl,
	} {
		clone, err := layoutTmpl.Clone()
		if err != nil {
			panic(err)
		}
		clone.Funcs(funcs)
		pages[name] = template.Must(clone.Parse(body))
	}
}

func (p *Panel) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages[name].ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
