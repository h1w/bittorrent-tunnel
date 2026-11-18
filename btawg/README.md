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
btawg-server: transport=ext-utp carrier=:6881 socks=1080 infohash=<…>
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

Firewall: allow **6881/udp** inbound (carrier). Nothing else needs to be
open — DHT, AWG and panel traffic all ride that socket or stay on loopback.

### 2. Panel → first client

```sh
ssh -L 8080:127.0.0.1:8080 vps      # panel is loopback-only by design
```

Open `http://127.0.0.1:8080`, log in (`admin` + printed password), then
**Clients → Create** → open the import page → copy the `btawg://…` string.
It is a secret (contains the client's private key); hand it over the same
way you would a WireGuard config.

### 3. Client machine

```sh
sudo ./btawg-client 'btawg://…'      # root = btawg0 interface; without: sudo -E …
./btawg-client -no-tun 'btawg://…'   # no interface, SOCKS5-only mode
```

The client needs no server address anywhere: it finds the hub strictly
through the DHT (give it up to ~30 s), then serves no-auth SOCKS5 on
`127.0.0.1:1080`.

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

On the dashboard each client has **Internet** (egress toggle) and
**Visible peers** (who it may talk to; mutual). Example presets:

| Scenario | Internet | Visible peers |
|---|---|---|
| Full VPN (обход ограничений) | on, all clients | All |
| Рабочая сеть без интернета | off, all clients | All |
| Пары: 1↔2 и 5↔6, остальные изолированы | as needed | only each other |

Saves apply immediately — no restart, no re-import. A denied peer dial
just times out (silent drop, like a router). To isolate a client
completely, select no peers at all.

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
`-transport ext-utp|ext-tcp|req-utp|req-tcp`, `-carrier-port`,
`-external-ip`, `-dht-bootstrap host:port[,host:port…]` (private bootstrap
island for DHT-hostile networks; the default is the public bootstrap list).

In the panel: **Server settings** (AWG profile inside BitTorrent, camouflage
method & transport, ports), **Clients → Create** → copy the import string.

The hub announces its carrier address in the public BitTorrent DHT under the
deployment infohash; clients learn the current server address from the DHT
alone. Public bootstrap nodes are baked into the client binary.

Ports: the carrier listens on **6881** (the canonical BitTorrent port,
override with `-carrier-port`), and every DHT socket in the system — hub
announcer and client discovery — binds the first free port of the standard
torrent client range **6881–6889**, falling back to an ephemeral port only if
the whole range is busy. A server + client on one machine coexist in the
range, exactly like two torrent clients would.

## Run a client (any PC)

```sh
./btawg-client 'btawg://…'        # paste the import string (a secret)
```

or `./btawg-client -config file.txt`. The client then:

- joins the DHT via public bootstrap nodes and `get_peers` the infohash —
  no server address is configured anywhere;
- dials the discovered address, performs the real BitTorrent handshake
  (same infohash) and carries all AWG traffic inside it — no bare-AWG
  fallback exists;
- serves **no-auth SOCKS5 on 127.0.0.1:1080**: point any app there; traffic
  is chained through the tunnel to the hub's egress, which dials the real
  internet (DNS resolves at the hub — no client-side leak);
- with root (`-no-tun` skips this) creates the `btawg0` interface with the
  client's overlay address (default `10.77.0.x`) and a route for the overlay
  subnet **only** — never a default route, so the system's own traffic is
  untouched.

### Client-to-client

Clients form a local network on the overlay: dial another client's
`10.77.0.x` address directly (the hub re-encrypts packets between carriers,
like kernel WireGuard's ip_forward). In netstack mode use
`Client.OverlayDialTCP`; on a real TUN the kernel routes overlay addresses
through `btawg0`. **Do not** route LAN traffic through SOCKS5 — the egress
dials destinations on the hub's host, which is for the internet only.

## Routing policy

Policy is enforced on the hub and configured only in the panel. Each client
has two independent controls:

- **Internet** checkbox — gates the chained SOCKS5 egress to the real internet.
  The hub host itself (`10.77.0.1`) stays reachable regardless; turning this
  off produces a pure work-net client.
- **Visible peers** multi-select — the list of other clients this client may
  exchange overlay packets with. Visibility is mutual: A can talk to B only
  when A lists B **and** B lists A.

Examples (in the owner's spirit):

- Mutual pairs: client 1 sees only client 2, and client 2 sees only client 1;
  client 5 ↔ client 6 the same way. Everyone else is isolated from them.
- Full VPN: every client has **Internet** on and **Visible peers** = All.
- Work net without internet: every client has **Internet** off and **Visible
  peers** = All, so they can reach each other and the hub but nothing else.

Changes are saved to the store and reloaded into the hub snapshot live via
`POST /clients/policy`. **No server restart and no re-import of clients are
required** for policy changes; only AWG-profile / transport / port changes
require the restart + re-import banner shown on the server-settings page.

### Hub TUN mode and the no-route-takeover invariant

`btawg-server` defaults to real TUN mode and creates `btawg0` with the hub
overlay address (`10.77.0.1/24` by default). Flags:

```sh
./btawg-server -tun btawg0        # default real-TUN mode (root required)
./btawg-server -no-tun            # userspace netstack mode (tests, dev)
```

The hub adds **no routes** — not even a subnet route. Clients add only the
overlay subnet route into their own `btawg0`; they never install a default
route. No node in the system takes over the system's routing table.

### Egress gate semantics

The hub's egress SOCKS5 is the only path from a client to the public
internet. If a client's **Internet** toggle is off, the gate closes that
client's egress connections immediately (fail-closed). The hub itself and
overlay peer-to-peer traffic still flow through the AWG device; only the
SOCKS5 egress is gated.

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
- End-to-end: hub announces in DHT → client discovers strictly via DHT →
  µTP carrier → AWG handshake → SOCKS5 internet egress (TCP and UDP) →
  client-to-client overlay dial through hub forwarding
  (`internal/e2e/e2e_test.go`).

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
- Real WAN, loss, and a production VPS were not exercised; the latency claim
  comes from the emulated 20 ms one-way channel benchmark.
- No ACL groups, rate limits, LAN-behind-client routing, kill switch, or
  IPv6 in this MVP; revocation removes the AWG peer and detaches the carrier.
- Hub real-TUN mode requires root and is verified only by the root-gated unit
  tests and design review, not on this non-root dev host. Run it on the VPS
  with `sudo ./btawg-server`.
- Disallowed client↔client dials are silently dropped by design, so they time
  out rather than returning a clean error or RST.
