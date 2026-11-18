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
<tr><th>Clients</th><td>{{len .Clients}}</td></tr>
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
{{if .Saved}}<div class="tag ok">saved — carrier/transport/port changes apply after restart</div>{{end}}
<div class="note">Settings apply after a server restart; a changed AWG profile requires clients to re-import (import page regenerates strings with the current profile).</div>
<form method="post" action="/server">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="card"><h2>AWG profile (inside BitTorrent)</h2>
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
</div>
<div class="card"><h2>BitTorrent camouflage</h2>
<div class="row">
<div><label>Method &amp; transport
<select name="transport">
{{$t := .Cfg.Transport}}
<option value="ext-utp" {{if eq $t "ext-utp"}}selected{{end}}>extended (BEP 10) over µTP no-Nagle</option>
<option value="ext-tcp" {{if eq $t "ext-tcp"}}selected{{end}}>extended (BEP 10) over TCP</option>
<option value="req-utp" {{if eq $t "req-utp"}}selected{{end}}>request/piece over µTP no-Nagle</option>
<option value="req-tcp" {{if eq $t "req-tcp"}}selected{{end}}>request/piece over TCP</option>
</select></label></div>
<div><label>Carrier port<input name="carrier_port" value="{{.Cfg.CarrierPort}}"></label></div>
<div><label>External IP (announce)<input name="external_ip" value="{{.Cfg.ExternalIP}}" placeholder="autodetect"></label></div>
</div>
<div class="note">All four options classify as BitTorrent under nDPI 6.1.0 (see FINDINGS.md); webseed was discarded.</div>
</div>
<div class="card"><h2>Ports</h2>
<div class="row">
<div><label>Egress SOCKS5 (overlay)<input name="socks_port" value="{{.Cfg.SocksPort}}"></label></div>
<div><label>Panel (loopback)<input name="panel_port" value="{{.Cfg.PanelPort}}"></label></div>
</div>
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
<div style="flex:0"><button>Create → import string</button></div></div>
</form>
</div>
<div class="card"><h2>Deployed</h2>
{{if .Clients}}
<table><tr><th>Name</th><th>Overlay IP</th><th>Status</th><th>Policy</th><th></th><th></th></tr>
{{$cs := .Connected}}
{{range .Clients}}
<tr><td>{{.Name}}</td><td>{{.IP}}</td>
<td>{{if index $cs .IP}}<span class="tag ok">connected</span>{{else if .Revoked}}<span class="tag off">revoked</span>{{else}}<span class="tag off">offline</span>{{end}}</td>
<td>{{if not .Revoked}}
<form method="post" action="/clients/policy" style="display:flex;gap:8px;align-items:center">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="id" value="{{.ID}}">
<label style="white-space:nowrap;font-size:12px;color:var(--muted)"><input type="checkbox" name="internet" value="on" {{if not .NoInternet}}checked{{end}}> internet</label>
<select name="peers" multiple size="2" style="min-width:120px">
<option value="*" {{if contains .VisiblePeers "*"}}selected{{end}}>All</option>
{{$self := .ID}}{{$vp := .VisiblePeers}}
{{range $.Clients}}{{if ne .ID $self}}<option value="{{.ID}}" {{if contains $vp .ID}}selected{{end}}>{{.Name}}</option>{{end}}{{end}}
</select>
<button>Save</button>
</form>
{{end}}</td>
<td><a href="/clients/import?id={{.ID}}">import string</a></td>
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
<p class="note">Copy it over a trusted channel. The client needs no server address: it finds the hub strictly through DHT.</p>
<p><a href="/clients">← back to clients</a></p>
</div>
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
	}
	for name, body := range map[string]string{
		"login":     loginTmpl,
		"dashboard": dashboardTmpl,
		"server":    serverTmpl,
		"clients":   clientsTmpl,
		"import":    importTmpl,
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
