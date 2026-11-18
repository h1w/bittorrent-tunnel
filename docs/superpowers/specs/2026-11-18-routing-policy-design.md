# btawg: routing policy, TUN on both sides, camouflage apply — design

> Status: implemented and verified in branch `btawg-routing-policy`
> (commits `998d368`..`ecf8840` plus Task 8 docs/live run). The live runtime
> verification on the non-root dev host uses `-no-tun`; hub real-TUN mode is
> covered by the root-gated `internal/tunsetup` unit tests and design review.

## Intent

Owner requirements (conversation, 2026-11-18):

1. Server and clients are equal routing nodes; each gets a VPN IP on a TUN
   interface (`btawg0`). No default-route takeover anywhere — the interface
   provides an address, the node's owner routes what they want into it (the
   SOCKS5 inbound on clients stays the primary entry).
2. Panel-configurable routing policy: which clients see each other
   (symmetric pairs, e.g. 1↔2 and 5↔6, or all↔all), and per-client internet
   egress (full VPN vs. pure work-VPN without any internet forwarding).
3. Panel-configurable camouflage (AWG junk-packet profile, transport, ports,
   external IP) with explicit apply semantics.
4. SOCKS5 inbound exists only on clients; the hub's egress SOCKS5 stays
   overlay-internal (already true).

## Current state (verified in code)

- Hub runs AWG over a userspace netstack only (no OS interface). Peer↔peer
  packets are re-injected by `forwardingTun` with no policy check.
- The egress SOCKS5 binds `10.77.0.1:socks_port` inside the netstack — not
  host-exposed — and accepts every overlay source.
- Clients already have real-TUN mode (default, root) and netstack (`-no-tun`);
  the TUN setup never installs routes.
- The panel already edits and stores AWG profile (jc/jmin/jmax/s1–s4/h1–h4),
  transport, ports, external IP (`panel.serverSubmit`); it applies only after
  a server restart and says nothing about that.
- `ClientRecord` has no policy fields.

## Design

### Policy model (store + enforcement)

`ClientRecord` gains two fields:

```go
Internet      bool     `json:"internet"`       // default true
VisiblePeers  []string `json:"visible_peers"`  // client IDs; ["*"] = all
```

Records predating the fields (missing/empty list) read as `internet: true`,
`visible_peers: ["*"]` — existing deployments keep today's behavior.

Rules, evaluated on the hub:

- **Client A→client B** allowed iff A can see B (A.list is `*` or contains B)
  **and** B can see A (mutual, matching "клиент 1 к клиенту 2 и обратно").
- **Client A→internet** allowed iff `A.internet`.
- **Client→hub host (10.77.0.1)** always allowed: the hub is the router and a
Enforcement lives entirely on the hub (all client traffic physically transits
it; AWG crypto means clients cannot bypass):

1. **Device-path filter — layering.** `filterTun` is the *outermost* wrapper
   handed to the AWG device. In netstack mode the device binds
   `filterTun(forwardingTun)`: the device's `Write` (decrypted packets from
   peers) calls `filterTun.Write`, which checks (src, dst), **drops** (returns
   len, no error) disallowed pairs, and passes allowed packets to
   `forwardingTun`, which then netstacks hub-destined traffic and re-injects
   peer↔peer. In real-TUN mode the inner is the kernel tun: same check, then
   the kernel forwards. Filtering must never sit *inside* `forwardingTun` —
   the re-injection path would bypass it.
2. **Egress gate.** The egress SOCKS5 maps `RemoteAddr` (overlay source IP,
   identical in both modes) to a client and closes immediately when that
   client's `internet` is false. Source `10.77.0.1` (the hub host itself) is
   exempt; unknown source IPs are denied (fail closed).
3. **Live reload wiring.** The panel's `Registry` interface gains
   `ReloadPolicy()`; `Server.ReloadPolicy()` re-reads the store into the
   snapshot. `POST /clients/policy` saves the record and calls it — no
   restart. (This is the only new cross-package contract.)

Failure semantics: a disallowed client↔client dial is a **silent drop — the
connection times out, no RST** — exactly like a router dropping packets.
Tests assert timeout, not a clean error.

Real-TUN server construction sequence: `tun.CreateTUN(name, 1420)` →
`ip addr add 10.77.0.1/24` → `ip link set up` → `sysctl
net.ipv4.ip_forward=1`. The server, owning the prefix, adds **no** subnet
route (unlike clients, whose `setupTUN` routes the /24 into their `btawg0`).
The shared `setupTUN` package parameterizes address-vs-route so both use one
implementation. Restart creates a fresh TUN device as the client mode
already does.

The hub holds a mutex-guarded policy snapshot (`IP → record`); legacy records
missing the new fields normalize to `internet: true`,
`visible_peers: ["*"]` at load. Import strings never change — policy is not
in client keys.

### Server TUN mode

`server.New` keeps today's netstack path (tests, `-no-tun`). New
`server.NewRealTUN(cfg, tunName)`: kernel TUN wrapped in the same
`filterTun`, kernel forwarding allowed peer↔peer packets (replacing
`forwardingTun`'s re-injection); egress SOCKS5 binds `10.77.0.1:socks_port`
on the host (reachable only via `btawg0`); carrier, DHT, panel unchanged.


`cmd/btawg-server` mirrors the client's flags: default real-TUN (production
VPS, root), `-no-tun` for userspace. The client's `setupTUN` helper moves to
a shared package so both binaries use one implementation. No routes are added
by anyone, ever.

### Panel

- Client list gains per-client controls: an "internet" checkbox and a
  "visible peers" multi-select including an "all" choice. `POST
  /clients/policy` → store save → live snapshot reload.
- Server settings page gains a banner: changes apply after a server restart,
  and a changed AWG profile means clients must re-import (the import page
  already regenerates strings with the current profile).

## Non-goals

- Direct client↔client data path bypassing the hub (AWG is hub-and-spoke;
  "equal nodes" is a policy statement, not a new data path).
- Hot application of AWG profile / transport (stale import strings would
  break silently — restart + banner is the honest MVP).
- Client-side visibility display, IPv6, rate limits, group ACLs.

## Tests

- Unit: policy pair symmetry, defaults, legacy-record migration; filterTun
  drop/allow over a fake tun; egress gate refusal.
- e2e (netstack server path): three clients A, B, C — A↔B allowed, C
  isolated: overlay dial A→B connects, A→C and B→C fail; internet off for A
  → egress connection refused, internet on for B → roundtrip works.
- Real-TUN server mode requires root: covered by the shared-setupTUN unit
  tests and a live manual check in verification (documented).

## Verification

Full suite + `-race`, then a live run: hub on `btawg0` (root) with two
clients, panel policy flips applied live (visibility pair and internet
toggle observable immediately in dials), camouflage change + restart with
re-imported strings.
