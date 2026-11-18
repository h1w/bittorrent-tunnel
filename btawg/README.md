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

## Run the server (VPS)

```sh
./btawg-server -store /var/lib/btawg/btawg.db
```

First boot generates and prints (once) the panel password and the deployment
infohash; the panel listens on `127.0.0.1:8080` — reach it via SSH
port-forward (`ssh -L 8080:127.0.0.1:8080 vps`). Flags:
`-transport ext-utp|ext-tcp|req-utp|req-tcp`, `-carrier-port`, `-external-ip`.

In the panel: **Server settings** (AWG profile inside BitTorrent, camouflage
method & transport, ports), **Clients → Create** → copy the import string.

The hub announces its carrier address in the public BitTorrent DHT under the
deployment infohash; clients learn the current server address from the DHT
alone. Public bootstrap nodes are baked into the client binary.

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
- DHT discovery depends on public bootstrap reachability; if a network
  blocks the DHT, the client fails loudly after a bounded retry (a private
  bootstrap island is the documented fallback, not built here).
- The announced IP is the source address the DHT observes; a NAT'd hub must
  forward its carrier port.
- Real WAN, loss, and a production VPS were not exercised; the latency claim
  comes from the emulated 20 ms one-way channel benchmark.
- No ACL groups, rate limits, LAN-behind-client routing, kill switch, or
  IPv6 in this MVP; revocation removes the AWG peer and detaches the carrier.
