# btawg — routed IPv4 and SOCKS5 over BitTorrent

Two Linux binaries: `btawg-server` (VPS hub) and `btawg-client` (device node).
Use AmneziaWG or mutual TLS 1.3 inside BitTorrent, or native AmneziaWG
and WireGuard over UDP. Clients use an imported hub endpoint by default;
BitTorrent modes also support DHT discovery. The hub's web panel manages
VPN addresses, groups and `btawg://` imports.

Built on the validated transport: extended (BEP 10) over µTP no-Nagle —
**+0.07 ms p95 vs bare AWG**, classified as `BitTorrent` by nDPI 6.1.0 with
no risk flags (`../experiments/awg-bittorrent/FINDINGS.md`).

## Build

```sh
cd btawg
CGO_ENABLED=0 go build -o bin/btawg-server ./cmd/btawg-server
CGO_ENABLED=0 go build -o bin/btawg-client ./cmd/btawg-client
go test ./...
```

`third_party/go-utp` is a vendored copy of anacrolix/go-utp with one patch:
`purego.MatrixDisableNagle` bypasses the µTP Nagle hold (the validated
latency win; see the benchmark for why this matters).

## Quickstart (VPS + one client, from zero)

### 1. Hub on a public-IP VPS

```sh
sudo ./btawg-server install
```

One command copies the binary to `/usr/local/bin`, writes and enables the
`btawg-server` systemd unit, and starts it. State lives under `/var/lib/btawg`
and `/etc/btawg`, surviving upgrades and restarts. Re-running `install` upgrades
the binary without touching the database, client imports, or the admin password.

The first install prints, once:

```
btawg-server: panel login admin / <password> (shown once)
```

**Save that password now** — it is never shown again. If lost, delete the db
and re-import clients (or look into the store with the panel still logged in).

Manage the service and see its status from the TUI:

```sh
btawg-server            # TUI: status, start/stop/restart, autostart
```

Open **6881/TCP**, **6881/UDP**, **51821/UDP** (AWG), and **51820/UDP**
(WG) on the hub, or the configured equivalents. DHT also needs outbound
UDP. Real-TUN mode requires `ip`, `sysctl`, and `nft` (with kernel IPv4 NAT
support). If the host firewall drops traffic, allow **1053/TCP only on the hub
TUN** for DNS and allow forwarding from the TUN to the WAN plus established
return traffic. btawg configures routing, overlay addresses, and scoped NAT
automatically, but it **does not open host firewall ports** — add those
yourself.

### 2. Panel → first client

The panel listens on **localhost** and the **hub's VPN address** (e.g.
`http://10.77.0.1:8080`) — never the public IP. Before any client exists,
reach it via SSH port-forward; once a client is connected, open it directly
over the VPN.

```sh
ssh -L 8080:127.0.0.1:8080 vps      # or open http://10.77.0.1:8080 over the VPN
```

Open `http://127.0.0.1:8080`, log in (`admin` + printed password), then
**Clients → Add client → Create & get config**. Copy the `btawg://…` string
or the full client command. The import contains the client's private key;
share it as you would a WireGuard config.

### 3. Client machine

```sh
sudo ./btawg-client install -import-file client.txt   # or run without -import-file to paste it
```

One command stores the import and generated credentials in `/etc/btawg`, then
installs, enables, and starts the `btawg-client` systemd service. The mode from
the import is enabled at first; the rest start reserved-but-off. Re-running
`install` upgrades the binary without losing config or credentials.

Run `btawg-client` with no arguments for the TUI:

```text
btawg-client  active / enabled
[x] 1080  socks5-awg-ext-utp   active
[ ] 1081  socks5-awg-ext-tcp   reserved
...
Space: toggle   v: show SOCKS5 login   g: regenerate
s:start  t:stop  r:restart  b:autostart  q:quit
```

Each connection mode has a **fixed** local SOCKS5 port (1080 = first mode,
1081 = second, …). Toggling a mode off closes its sessions but keeps its port
reserved so nothing else can take it; the other ports keep working. The port
mapping is permanent across toggles and restarts:

| Port | Mode | Port | Mode |
|---:|---|---:|---|
| 1080 | AWG · ext-utp | 1085 | WG · udp |
| 1081 | AWG · ext-tcp | 1086 | TLS · ext-utp |
| 1082 | AWG · req-utp | 1087 | TLS · ext-tcp |
| 1083 | AWG · req-tcp | 1088 | TLS · req-utp |
| 1084 | AWG · udp | 1089 | TLS · req-tcp |

All inbounds share **one SOCKS5 username/password** (RFC 1929). The TUI shows
the pair (`v`) and regenerates it (`g`); rotation is immediate across every
port and closes existing sessions. No-auth is refused. The SOCKS5 protocol
does not encrypt these credentials — expose the ports only to a trusted LAN.

For a single foreground connection (no service), the old form still works:

```sh
sudo ./btawg-client 'btawg://…'      # one mode, btawg0 interface
./btawg-client -no-tun 'btawg://…'   # no interface, SOCKS5-only mode
```

### 4. Verify

```sh
curl -4 -s --socks5-hostname 127.0.0.1:1080 https://example.com   # 200
ip a show btawg0                                                  # 10.77.0.x present
```

Point any app's SOCKS5 at `127.0.0.1:1080` (DNS resolves at the hub — no
client-side leak). To route specific traffic via the interface instead,
add your own routes into `10.77.0.0/24` — btawg never touches your
default route.

### 5. Policy (panel, live)

In **Groups**, create an IPv4 subnet and set its peer visibility and
Internet policy. In **Clients**, choose a group when creating a user, or
move an existing user. Users inherit both group rules unless explicitly
overridden. The hub gives the user the same address in all ten modes.

Permission changes apply live, including closing disallowed active SOCKS
sessions. A move to another subnet or a changed group CIDR needs a new
import. Denied peer traffic is silently dropped.

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Client: `dht traversal finished: no peers` | Hub not announced yet — wait for its first announce, or the network blocks DHT → use `-dht-bootstrap` + `dht_bootstrap` in the import string |
| Client exits after ~45 s of retries | Hub unreachable (down / carrier port filtered) — check `6881/udp` and `-external-ip` |
| `curl` fails with IPv6 target | Hub host has no IPv6 — use `curl -4` (documented limit) |
| `tun setup (root required)` | Run with sudo or `-no-tun` |
| Password lost | Delete the db and recreate clients (keys live in the import strings) |


## Run the server (VPS)

```sh
./btawg-server -store /var/lib/btawg/btawg.db
```

First boot generates and prints (once) the panel password and the deployment
infohash; the panel listens on `127.0.0.1:8080` **and** the hub's VPN address
(e.g. `10.77.0.1:8080`) — not the public IP. Reach it over the VPN, or via SSH
port-forward (`ssh -L 8080:127.0.0.1:8080 vps`) before a client exists. Flags:
`-transport` sets the preferred client mode, not which listeners are
enabled. `-carrier-port` and `-dht-bootstrap host:port[,host:port…]` apply
to the eight BitTorrent modes. `-external-ip` is the public IPv4 written into
imports; set it explicitly if the outbound interface address is not public.

All eight BitTorrent modes support a direct endpoint and DHT discovery. Native
AWG/WG use their explicit UDP endpoints. No mode silently falls back to
another. The panel exposes one `btawg://` import and native config
downloads for the same registered user.

Ports: the carrier listens on **6881** (the canonical BitTorrent port,
override with `-carrier-port`), and every DHT socket in the system — hub
announcer and client discovery — binds the first free port of the standard
torrent client range **6881–6889**, falling back to an ephemeral port only if
the whole range is busy. A server + client on one machine coexist in the
range, exactly like two torrent clients would.

Upgrade hub and client together for the faster `req-tcp` and `req-utp` paths.
New peers negotiate a larger request window and 1536-byte blocks, fragmenting
only datagrams that do not fit. Old peers keep the 2048-byte block and 32-request
window and still stop at the original index limit. The import string and TUN
routes do not change if the selected transport stays the same.

For a lossy WAN, set `BTAWG_UTP_PACE_MBPS` independently on each host to
cap that process's outgoing µTP bulk data (50–10000 Mbit/s; unset or `0`
disables it). Measure direct UDP goodput and packet loss in each direction
before tuning. The cap is not a promised application throughput; all µTP
peers on the hub share its pacing budget. TCP modes ignore this setting.

## Run a client (any PC)

```sh
./btawg-client -transport socks5-awg-ext-tcp 'btawg://…'
./btawg-client -transport socks5-req-tcp -dht 'btawg://…'
```

or `./btawg-client -config file.txt`. The client then:

- for a BitTorrent mode, connects to the imported endpoint or discovers it
  through DHT when requested; for the two native modes, connects directly over UDP
  to the selected native endpoint;
- serves **SOCKS5 on 127.0.0.1:1080**. Traffic
  goes directly into the tunnel as IPv4 packets; the hub routes and NATs
  them. The client resolves SOCKS domain targets via the hub's overlay-only
  DNS service, without asking the client's system DNS resolver. This single
  foreground form is an unauthenticated debug path; the managed service
  (`btawg-client install`) provides the authenticated per-mode inbounds;
- with real TUN, creates `btawg0` with the assigned VPN address and the
  managed IPv4 subnet routes from the import. Only sockets bound to that
  interface use its private egress routing table; the host default route
  stays unchanged. The hub still decides which traffic to forward.

The hub and client use a default tunnel MTU of 1280 bytes, including in
`-no-tun` mode and in exported standalone VPN configurations.

| AWG inside BitTorrent | TLS 1.3 inside BitTorrent (no AWG) | Outer transport |
|---|---|---|
| `socks5-awg-ext-tcp` | `socks5-ext-tcp` | Extended messages over TCP |
| `socks5-awg-req-tcp` | `socks5-req-tcp` | Request/piece over TCP |
| `socks5-awg-ext-utp` | `socks5-ext-utp` | Extended messages over µTP (UDP) |
| `socks5-awg-req-utp` | `socks5-req-utp` | Request/piece over µTP (UDP) |

`socks5-awg-udp` and `socks5-wg-udp` are native AWG and WG without BitTorrent.
SOCKS5 supports TCP and UDP in all modes; direct VPN IP traffic uses the same
tunnel without SOCKS5. The four TLS modes use the same IPv4 addresses and
hub ACLs as AWG/WG. Upgrade both binaries and re-export the import to get the
TLS server pin and discovery hashes. Existing imports and short names remain
usable in the original modes; there is no TLS-to-AWG fallback.

### Client-to-client

Clients form a local network on the overlay: dial another client's
`10.77.0.x` address directly (the hub re-encrypts packets between carriers,
like kernel WireGuard's ip_forward). In netstack mode use
`Client.OverlayDialTCP`; on a real TUN the kernel routes overlay addresses
through `btawg0`. Use direct VPN IP traffic for LAN services; the client
SOCKS5 proxy is for public IPv4 destinations only.

## Routing policy and groups

Each group owns a non-overlapping IPv4 CIDR and a hub address. New groups
allow communication within the group and deny internet by default. Group
visibility and user exceptions are mutual: both endpoints must allow the
other. Different transports do not create separate IP networks. These are
routed IPv4 networks, not shared Ethernet segments.

The hub enforces the policy after VPN authentication, on both overlay
routing and internet egress. Internet can only use the central server.
A real-TUN hub routes IPv4 through scoped NAT. Clients can use SOCKS5 with
either a kernel TUN or `-no-tun`; a hub started with `-no-tun` is overlay-only
and does not provide Internet egress or DNS. The client never installs a
system-wide default route. Standalone WG/AWG users must add the desired
public prefixes to `AllowedIPs` and the OS routes for Internet access.

Back up the database before upgrading. Existing IPs and settings move to
the default group; existing per-user permissions become explicit. Policy
edits are live. Changing the hub listener ports or AWG profile requires a
restart and a fresh import. In `-no-tun` mode the group gateway addresses
are fixed at startup; use real TUN to change group networks live.

Upgrade both binaries together for client SOCKS5 Internet access. Existing
imports still work with the updated client; the old hub SOCKS port is ignored.
An old client cannot proxy Internet traffic through an updated hub.

## Live activity and traffic

**Overview** shows recent activity, live upload and download speeds, and
cumulative VPN traffic. Search by client name, group or VPN IP. **Clients**
has the same live table plus access, group and revocation controls. The
visible page refreshes traffic every two seconds without refreshing forms.

**Active** means a verified handshake or an accepted upload in the last
three minutes. It does not prove that an idle WireGuard peer is still
online. The arrows show direction from the client's perspective. Counters
count inner IP bytes, not the BitTorrent/WG overhead on the public link;
client-to-client traffic counts at both ends. Traffic to the hub and
Internet traffic also count. Moving a user or switching transports does not
reset that user's totals.

The hub checkpoints totals to its existing database every 15 seconds and
on clean shutdown. Tracking starts on upgrade; pre-upgrade traffic cannot
be recovered. An unclean shutdown may lose traffic since the last checkpoint.

## Import string

`btawg://` + base64url(JSON) carries overlay addressing, connection chain,
endpoints and discovery hashes, the hub's public keys, and the client's
private key. Treat it as a secret and share it only over a trusted channel.
The BitTorrent handshake and DHT hash do not authenticate a peer: AWG or
the pinned mutual TLS keys authenticate each encrypted connection.

## Verification performed

- Carrier framing, SOCKS5 (CONNECT + UDP ASSOCIATE), bbolt store, DHT
  announce/discover (loopback relay), panel handlers: unit tests.
- Full suite `go test ./...` green incl. `-race` on the networking paths.
- End-to-end in all eight BitTorrent modes: DHT discovery through a local
  relay, local SOCKS5 destination filtering and client-to-client IPv4 traffic.
  The mixed-mode test also routes between both native modes and the carriers.

On a single Linux host, separate network namespaces connected by a kernel
`netkit` link (RTT approximately 0.06 ms) transferred and verified 1 GiB per
mode and direction through real TUN interfaces, AWG, and SOCKS5. The
benchmark supplies the discovered peer address locally; it measures bulk
transfer after connect, not DHT or session setup. The speeds below are
application goodput, not link rate.

| Carrier | 1 stream down | 1 stream up | 4 streams down | 4 streams up |
|---|---:|---:|---:|---:|
| `ext-tcp` | 1.846 | 2.288 | 2.306 | 2.372 |
| `ext-utp` | 1.484 | 1.514 | 1.445 | 1.443 |
| `req-tcp` | 2.236 | 2.256 | 2.222 | 2.204 |
| `req-utp` | 1.349 | 1.375 | 1.308 | 1.303 |

All values are in Gbit/s. The Linux IPv4 µTP path batches UDP I/O and uses
UDP segmentation when available, without changing individual wire datagrams.
These numbers do not describe a physical 1 GbE link or public WAN path.

### Two-VPS WAN measurement

One external carrier per client. Each run transferred and verified 512 MiB
through real TUN, AWG and SOCKS5: four application flows for TCP, two for
µTP. The table reports medians and ranges of three runs per direction at
fixed settings, in Mbit/s. Download is hub to client.

| Carrier | Download median (range) | Upload median (range) | Median vs. direct, down / up |
|---|---:|---:|---:|
| `ext-tcp` | 821.3 (694.8–852.7) | 795.4 (778.0–873.9) | 93.4% / 80.2% |
| `req-tcp` | 738.4 (718.4–760.8) | 823.8 (789.5–832.1) | 84.0% / 83.0% |
| `ext-utp` | 181.3 (177.8–181.9) | 279.6 (253.7–281.4) | 76.2% / 74.0% |
| `req-utp` | 175.6 (172.7–182.9) | 294.5 (253.1–295.2) | 73.8% / 78.0% |

TCP percentages use the original four-stream direct control of 879/992
Mbit/s. A fresh direct TCP run on the same path measured 944.2/639.1.
Direct UDP delivered 237.9/377.7 Mbit/s with 1382-byte datagrams over six
seconds, offered at 250/390 Mbit/s (4.6%/2.9% packet loss).

Set `BTAWG_UTP_PACE_MBPS` to 275 on the hub and 410 on the client for
the measured `ext-utp` profile, or 355 and 455 respectively for `req-utp`.
These are pacing ceilings for this route, not throughput guarantees.
Both µTP upload medians exceeded 70% of direct UDP; each mode also had
one run below that threshold.

## Honest limits

- BitTorrent framing substitutes encrypted traffic for file blocks. Piece
  hashes never validate; no metadata is served. Existing nDPI 6.1.0 results
  cover the historical AWG carrier, not the new TLS modes. Active probing is out
  of scope. No claim of universal undetectability.
- Native AWG adds the profile's `S4` bytes on top of the normal tunnel
  overhead. If large transfers fail with `message too long`, check the
  outer path MTU. This overhead does not apply to the BitTorrent modes.
- DHT discovery depends on bootstrap reachability; if a network blocks the
  public DHT, point both sides at a private bootstrap island with
  `-dht-bootstrap` (hub) and the import string's `dht_bootstrap` field.
- The announced IP is the source address the DHT observes; a hub behind NAT
  must forward 6881/udp. Clients work behind any NAT with no setup — their
  traffic is purely outbound.
- The hub needs a public IP (or that forward): client-to-client traffic
  always routes through the hub, so there is no direct client↔client NAT
  traversal in this MVP.
- A local latency benchmark is not a WAN throughput guarantee. Measure raw
  TCP to the same hub in both directions and compare it with completed SOCKS
  transfers of the same size. A speed test to a different host is not a
  baseline for the VPN path. `ext-*` rounds the datagram plus its length field
  up to 32 bytes rather than padding every frame to 2 KiB. `req-*` uses
  1536-byte blocks between new peers and 2048-byte blocks with old peers.
  For a long-distance benchmark, apply 100 ms one-way delay in each
  direction (200 ms RTT total) to the carrier only. Place `netem` on an
  intermediate router's egress toward each endpoint, not on the TCP
  sender's egress, where TCP Small Queues can distort the result.
  Keep the SOCKS endpoint and test source local to their respective hosts,
  verify the complete payload at the receiver, and report upload and
  download separately.
  In an isolated Linux run at 201 ms RTT, all four modes delivered 512 MiB
  through real TUN and SOCKS5 in four parallel TCP streams per direction.
  Download/upload goodput was 559/564 Mbit/s (`ext-tcp`), 535/533 (`req-tcp`),
  547/542 (`ext-utp`), and 516/514 (`req-utp`). Direct TCP reached 719/719
  Mbit/s on the same lab path. The run used an already-established AWG
  session and injected the discovery result; it does not measure startup,
  single-stream speed, or a public WAN. Earlier `req-utp` tuning trials
  also fell below 500 Mbit/s, so the result is not a sustained minimum.
  Real-TUN mode uses Reno and a bounded send buffer on the inner SOCKS TCP
  sockets and a larger transmit queue on the overlay TUN. The outer TCP
  carrier uses BBR where available; other TCP sockets keep the host default.
  Loopback SOCKS CONNECT legs use bounded buffers. No host-wide TCP setting
  or WAN qdisc is changed.
- No IPv6 overlay, rate limits, LAN-behind-client routing, or kill switch.
  Revocation removes the peer from both engines and closes its carriers.
- Hub real-TUN mode requires `CAP_NET_ADMIN`. Run it on the VPS with
  `sudo ./btawg-server` or use the systemd unit above.
- Disallowed client↔client dials are silently dropped by design, so they time
  out rather than returning a clean error or RST.
