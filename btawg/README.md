# btawg — AmneziaWG inside BitTorrent

Two Linux binaries: `btawg-server` (VPS hub) and `btawg-client` (device node).
AmneziaWG datagrams travel inside BitTorrent wire messages; the server is
found **strictly through DHT** — no server address ships in any config. A
3x-ui-style web panel manages the hub; each client is one `btawg://` import
string.

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
mkdir -p /var/lib/btawg
./btawg-server -store /var/lib/btawg/btawg.db
```

First boot prints, once:

```
btawg-server: panel login admin / <password> (shown once, loopback :8080)
btawg-server: modes=ext-tcp,req-tcp,ext-utp,req-utp,awg,wg carrier=:6881 awg=:51821/udp wg=:51820/udp …
```

**Save that password now** — it is never shown again. If lost, delete the db
and re-import clients (or look into the store with the panel still logged in).
Production runs need root (real-TUN mode). systemd unit:

```ini
[Unit]
Description=btawg hub
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/btawg-server -store /var/lib/btawg/btawg.db
Restart=on-failure
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

Open **6881/TCP**, **6881/UDP**, **51821/UDP** (AWG), and **51820/UDP**
(WG) on the hub, or the configured equivalents. DHT also needs outbound
UDP. The admin panel stays on loopback. Real-TUN mode requires `ip`,
`sysctl`, and `nft` (with kernel IPv4 NAT support). If the host firewall
drops overlay traffic, allow the overlay SOCKS port on `btawg0`, and allow
the intended forwarding paths; btawg does not override the host firewall.

### 2. Panel → first client

```sh
ssh -L 8080:127.0.0.1:8080 vps      # panel is loopback-only by design
```

Open `http://127.0.0.1:8080`, log in (`admin` + printed password), then
**Clients → Add client → Create & get config**. Copy the `btawg://…` string
or the full client command. The import contains the client's private key;
share it as you would a WireGuard config.

### 3. Client machine

```sh
sudo ./btawg-client 'btawg://…'      # root = btawg0 interface; without: sudo -E …
./btawg-client -no-tun 'btawg://…'   # no interface, SOCKS5-only mode
```

New imports contain the public hub endpoint and connect directly by default.
For a BitTorrent carrier, `-dht` chooses discovery instead; earlier imports
without an endpoint continue to use DHT. SOCKS5 listens on `127.0.0.1:1080`.

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
overridden. The hub gives the user the same address in all six modes.

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
infohash; the panel listens on `127.0.0.1:8080` — reach it via SSH
port-forward (`ssh -L 8080:127.0.0.1:8080 vps`). Flags:
`-transport` sets the preferred client mode, not which listeners are
enabled. `-carrier-port` and `-dht-bootstrap host:port[,host:port…]` apply
to the four carrier modes. `-external-ip` is the public IPv4 written into
imports; set it explicitly if the outbound interface address is not public.

The four carriers support both a direct endpoint and DHT discovery. Native
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
./btawg-client -transport ext-tcp 'btawg://…'  # pick any listed mode
./btawg-client -transport ext-tcp -dht 'btawg://…' # explicitly use DHT
```

or `./btawg-client -config file.txt`. The client then:

- for a BitTorrent mode, connects to the imported endpoint or discovers it
  through DHT when requested; for `awg` or `wg`, connects directly over UDP
  to the selected native endpoint;
- serves **no-auth SOCKS5 on 127.0.0.1:1080**: point any app there; traffic
  is chained through the tunnel to the hub's egress, which dials the real
  internet (DNS resolves at the hub — no client-side leak);
- with real TUN, creates `btawg0` with the assigned VPN address and the
  managed IPv4 subnet routes from the import. It never installs a default
  route. To send selected public prefixes through the VPN, add explicit
  client routes; the hub still decides whether to forward them.

### Client-to-client

Clients form a local network on the overlay: dial another client's
`10.77.0.x` address directly (the hub re-encrypts packets between carriers,
like kernel WireGuard's ip_forward). In netstack mode use
`Client.OverlayDialTCP`; on a real TUN the kernel routes overlay addresses
through `btawg0`. **Do not** route LAN traffic through SOCKS5 — the egress
dials destinations on the hub's host, which is for the internet only.

## Routing policy and groups

Each group owns a non-overlapping IPv4 CIDR and a hub address. New groups
allow communication within the group and deny internet by default. Group
visibility and user exceptions are mutual: both endpoints must allow the
other. Different transports do not create separate IP networks. These are
routed IPv4 networks, not shared Ethernet segments.

The hub enforces the policy after VPN authentication, on both overlay
routing and internet egress. Internet can only use the central server.
Real-TUN mode supports explicitly routed IPv4 packets via scoped NAT;
SOCKS5 is available in real-TUN and `-no-tun` modes. The client never
installs a system-wide default route. To use internet egress with standalone
WG/AWG, add the selected public prefixes to `AllowedIPs` and the OS routes.

Back up the database before upgrading. Existing IPs and settings move to
the default group; existing per-user permissions become explicit. Policy
edits are live. Changing the hub listener ports or AWG profile requires a
restart and a fresh import. In `-no-tun` mode the group gateway addresses
are fixed at startup; use real TUN to change group networks live.

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

`btawg://` + base64url(JSON): version, infohash, hub public key, client
private/public key, overlay IP/subnet, transport, SOCKS/egress ports, AWG
profile. It carries **no server endpoint** and it is a **secret** — it
contains the client's private key. Anyone with the infohash can learn the
hub's IP via DHT, but without AWG keys the channel stays opaque.

## Verification performed

- Carrier framing, SOCKS5 (CONNECT + UDP ASSOCIATE), bbolt store, DHT
  announce/discover (loopback relay), panel handlers: unit tests.
- Full suite `go test ./...` green incl. `-race` on the networking paths.
- End-to-end in all four carrier modes: DHT discovery through a local relay,
  AWG handshake, SOCKS5 TCP and UDP egress, and client-to-client traffic
  through the hub (`internal/e2e/e2e_test.go`). These are functional checks,
  not throughput benchmarks.

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

- Camouflage is **wire-format only, not hash-correct**: AWG ciphertext
  substitutes for file blocks; piece hashes never validate; no metadata is
  served. Verified against **nDPI 6.1.0 only** (offline pcaps with
  synthesized L3/L4 headers around real outer bytes). Active probing is out
  of scope. No claim of universal undetectability.
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
