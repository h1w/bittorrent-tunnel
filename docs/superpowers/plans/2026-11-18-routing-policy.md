# Routing Policy, Hub TUN, Camouflage Apply — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hub-enforced, panel-live routing policy (mutual client visibility + per-client internet egress), a real TUN interface on the hub (server and clients are equal nodes with VPN IPs, no route takeover anywhere), and explicit apply semantics for panel-edited camouflage.

**Architecture:** All client traffic physically transits the AWG hub, so enforcement lives there: a `filterTun` wrapper as the *outermost* device wrapper drops disallowed client↔client packets, and a gated egress listener drops clients without internet. Policy is a store-backed snapshot reloaded live via a new `Registry.ReloadPolicy()` contract; import strings never change. `server.New` keeps the netstack path; new `server.NewRealTUN` binds the device to a kernel TUN.

**Tech Stack:** Go 1.x, bbolt, amneziawg-go/v3 (device + netstack + tun), existing `internal/{store,server,panel,socks,e2e}`.

**Spec:** `docs/superpowers/specs/2026-11-18-routing-policy-design.md`

## Global Constraints

- Never install any route except the overlay subnet on *clients*; the hub adds **no** routes. No default-route takeover, ever.
- Import string fields are frozen — policy and camouflage apply without re-issuing keys (policy) or require explicit re-import (AWG profile only).
- Disallowed client↔client dials are **silent drops** (timeout, no RST); tests assert timeout, not a clean error.
- Legacy store records (no policy fields) behave as today: all peers visible, internet allowed.
- Ports stay in the standard range (6881–6889; carrier default 6881).
- Suite must stay green with `-race`; TDD red-green for every behavior.

## Review Focus

1. **Peer↔peer bypass:** filter placed *inside* `forwardingTun` only filters hub-destined traffic — e2e isolation (Task 5) is the proof it wraps outside.
2. **Fail-closed egress:** unknown overlay source denied at the egress gate; hub IP exempt — unit (Task 4).
3. **Legacy records:** a db written by the pre-policy binary must keep all-see-all + internet — store normalization test (Task 1).
4. **Live reload:** policy flip must take effect without server restart — e2e flip (Task 5).
5. **NoInternet ≠ isolated from hub:** a client with internet off still sends packets to the hub itself (filter passes dst==serverIP); only the SOCKS5 egress refuses it — e2e (Task 5).

---

### Task 1: Policy fields in the store, legacy normalization

**Files:**
- Modify: `btawg/internal/store/store.go` (ClientRecord + a normalize step on read)
- Test: `btawg/internal/store/store_test.go`

**Interfaces:**
- Produces: `store.ClientRecord{ NoInternet bool; VisiblePeers []string }` (JSON `no_internet`, `visible_peers`), read back with: nil or `["*"]` VisiblePeers = all peers; `[]` = none. `NoInternet` false = internet allowed (zero value is the legacy default).

- [ ] **Step 1: Write the failing test** — `TestPolicyFieldsRoundTripAndLegacyDefaults`: save a record with `NoInternet: true, VisiblePeers: []string{"c2"}`; read back equal. Then simulate a legacy record by writing raw JSON `{"id":"x","ip":"10.77.0.9",...}` **without** the new fields (raw bolt bucket write, mirroring how the store serializes records today); read back: `NoInternet == false`, `VisiblePeers` normalized to `["*"]`.
- [ ] **Step 2: Run** `go test ./internal/store/ -run TestPolicyFields -v` — FAIL (fields missing).
- [ ] **Step 3: Implement** — add the two fields; in the read path (wherever records are unmarshalled) normalize `VisiblePeers == nil → ["*"]`. Keep `[]` distinct from nil.
- [ ] **Step 4: Run** — PASS; full `go test ./internal/store/`.
- [ ] **Step 5: Commit** `btawg: client policy fields with legacy defaults`.

### Task 2: Policy snapshot + evaluation on the hub

**Files:**
- Create: `btawg/internal/server/policy.go`
- Modify: `btawg/internal/server/server.go` (Server field `policy`, init in New, `ReloadPolicy`)
- Test: `btawg/internal/server/policy_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.ClientRecord` (Task 1).
- Produces:
  - `type policySnapshot struct{ ... }`, `func newPolicySnapshot() *policySnapshot`
  - `func (p *policySnapshot) reload(st *store.Store, serverIP netip.Addr) error`
  - `func (p *policySnapshot) clientCanReach(src, dst netip.Addr) bool` — src or dst == serverIP → true; otherwise mutual: (A sees B) && (B sees A); unknown IP → false.
  - `func (p *policySnapshot) internetFor(src netip.Addr) bool` — serverIP → true; unknown → false.
  - `func (s *Server) ReloadPolicy() error`

- [ ] **Step 1: Write the failing test** — store with clients A(10.77.0.2, sees all), B(10.77.0.3, sees ["A"]), C(10.77.0.4, sees [], NoInternet), serverIP 10.77.0.1. Assert matrix: A→B true (A all, B lists A); C→B false; B→C false; X(unknown 10.77.0.9)→any false; any→10.77.0.1 true; internetFor: A true, C false, serverIP true, unknown false. Then flip B's record in the store, `reload`, assert C→B now true (live reload).
- [ ] **Step 2: Run** `go test ./internal/server/ -run Policy -v` — FAIL.
- [ ] **Step 3: Implement** `policy.go` with an RWMutex-guarded `map[netip.Addr]store.ClientRecord`; `New` builds and reloads it; `ReloadPolicy` re-reads.
- [ ] **Step 4: Run** — PASS; `go vet ./internal/server/`.
- [ ] **Step 5: Commit** `btawg: hub policy snapshot with live reload`.

### Task 3: filterTun — outermost device wrapper

**Files:**
- Create: `btawg/internal/server/filter.go`
- Modify: `btawg/internal/server/server.go` (device binds `filterTun{forwardingTun}` — filter OUTSIDE forwarding)
- Test: `btawg/internal/server/filter_test.go`

**Interfaces:**
- Consumes: `policySnapshot.clientCanReach`, `tun.Device`, `ipv4Dst` (forward.go; add `ipv4Src` alongside).
- Produces: `type filterTun struct{ inner tun.Device; policy *policySnapshot; }` implementing `tun.Device`; delegating everything but `Write`.

- [ ] **Step 1: Write the failing test** — fake inner tun.Device records `Write` calls; snapshot from Task 2's builder. Feed Write with bufs: (A→B allowed) passed through; (C→B disallowed) NOT passed; (B→10.77.0.1) passed; (unknown→B) dropped. Assert inner saw exactly the allowed ones.
- [ ] **Step 2: Run** — FAIL (filterTun undefined).
- [ ] **Step 3: Implement** — `Write`: parse IPv4 src/dst per packet; `clientCanReach` false → drop that buf silently (still return len(bufs), no error); pass the rest to inner. In `New`, hand the device `&filterTun{newForwardingTun(...), s.policy}`.
- [ ] **Step 4: Run** — PASS; full `go test ./internal/server/`.
- [ ] **Step 5: Commit** `btawg: filterTun enforces pair visibility in the device path`.

### Task 4: Egress gate (fail-closed)

**Files:**
- Create: `btawg/internal/server/egress_gate.go`
- Modify: `btawg/internal/server/server.go` (wrap `s.egressLn` with the gate before `egress.Serve`)
- Test: `btawg/internal/server/egress_gate_test.go`

**Interfaces:**
- Consumes: `policySnapshot.internetFor`.
- Produces: `type gatedListener struct{ inner net.Listener; policy *policySnapshot }` implementing `net.Listener`; `Accept` closes and retries when `internetFor(remoteIP)` is false.

- [ ] **Step 1: Write the failing test** — net.Pipe-style fake listener whose conns carry a configurable RemoteAddr; policy with C NoInternet. Accept from C's IP → conn closed, next accept proceeds; from A → conn returned alive; from unknown IP → closed; from serverIP → alive.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** `gatedListener`; wrap in `Run` before `go egress.Serve(runCtx, gated)`.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `btawg: fail-closed egress gate by source client`.

### Task 5: e2e — isolated pair, internet toggle, live flip

**Files:**
- Modify: `btawg/internal/e2e/e2e_test.go`

**Interfaces:**
- Consumes: `server.New` with wired policy (Tasks 2–4), existing e2e harness (`hubWithClient`, `SetDiscovery`, `OverlayDialTCP`).
- Produces: a third registered client in the harness (extend the registration part of the setup).

- [ ] **Step 1: Write the failing test** — `TestPolicyIsolationLive`: hub + clients A, B, C. Store C with `VisiblePeers: []` and B with `NoInternet: true`, reload policy. Assert: A overlay-dials B → connects (existing echo leg); A dials C → times out (bounded 5 s context, no RST); B's chained egress dial → refused/closed; A's chained egress → roundtrip works; B's packets to hub IP still pass the filter (B dials the hub's egress port directly → TCP connects at filter level but the gate closes it — proves filter passes, gate refuses). Then flip: give C `VisiblePeers: ["*"]` in the store, `srv.ReloadPolicy()`, A dials C → connects. No restart anywhere.
- [ ] **Step 2: Run** `go test ./internal/e2e/ -v` — FAIL (policy not wired yet is fine; this task runs after 2–4, so expect FAIL on the new assertions only if wiring gaps remain).
- [ ] **Step 3: Fix wiring until green** — minimal; the pieces exist by now.
- [ ] **Step 4: Run full suite + `-race`** — all PASS.
- [ ] **Step 5: Commit** `btawg: e2e proves live policy isolation and egress gating`.

### Task 6: Panel — policy UI, live reload contract, apply banner

**Files:**
- Modify: `btawg/internal/panel/panel.go` (Registry += `ReloadPolicy() error`; `POST /clients/policy`)
- Modify: `btawg/internal/panel/templates.go` (client-list policy form; server-settings banner)
- Modify: `btawg/internal/server/server.go` (Server satisfies the extended Registry)
- Test: `btawg/internal/panel/panel_test.go`

**Interfaces:**
- Consumes: Task 1 fields, Task 2 `ReloadPolicy`.
- Produces: `Registry` now four methods; route `POST /clients/policy` with form `id`, `internet` (`on`/absent), `peers` (multi-value; `*` = all).

- [ ] **Step 1: Write the failing test** — logged-in POST `/clients/policy` with `id=<rec.ID>`, `internet=` absent, `peers=B` → fake registry records the ReloadPolicy call, record saved with `NoInternet: true, VisiblePeers: ["B"]`; redirect back to `/`. Missing/unknown id → 404. Banner test: GET `/server` contains "restart" and "re-import" wording (assert on the exact string the template carries).
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** handler + template form (per client row: internet checkbox, peers multi-select incl. "all", save button) + banner text: «Settings apply after a server restart; a changed AWG profile requires clients to re-import (import page regenerates strings with the current profile).»
- [ ] **Step 4: Run** — PASS; `go vet ./internal/panel/`.
- [ ] **Step 5: Commit** `btawg: panel policy controls with live reload; apply banner`.

### Task 7: Hub real-TUN mode + shared TUN setup

**Files:**
- Create: `btawg/internal/tunsetup/tunsetup.go` (+ `_test.go` skipped without root, mirroring client TUN tests)
- Modify: `btawg/cmd/btawg-client/main.go` (setupTUN moves to tunsetup; call sites)
- Modify: `btawg/internal/server/server.go` (`NewRealTUN`)
- Modify: `btawg/cmd/btawg-server/main.go` (flags `-tun` default `btawg0`, `-no-tun`)
- Test: `btawg/internal/server/server_test.go` (mode-selection unit only; TUN creation is root-only)

**Interfaces:**
- Consumes: `filterTun` (Task 3), device assembly from `New`.
- Produces:
  - `tunsetup.Setup(name string, addr netip.Prefix, route *netip.Prefix, mtu int, ipForward bool) error` — client: route = &subnet, ipForward false; hub: route = nil, ipForward true.
  - `server.NewRealTUN(cfg config.ServerConfig, st *store.Store, tunName string) (*Server, error)` — kernel tun (MTU 1420, matching netstack today) wrapped in the SAME `filterTun` (inner = raw kernel tun), egress listener on the host at `cfg.ServerIP:cfg.SocksPort`; peers/carrier/DHT identical to `New`.

- [ ] **Step 1: Write the failing test** — `TestNewRealTUNRequiresRoot` guards: non-root run must fail with the documented error (tun creation denied), root run is covered by live verification instead. Assert also the flag-mode selection helper if main.go gains one (`realTUN := !*noTun` logic stays trivial in main).
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** — extract `New`'s device/peer/egress assembly so both constructors share it; `NewRealTUN` swaps tun + egress bind + calls `tunsetup.Setup` (addr, nil route, ipForward). `cmd/btawg-server`: default real-TUN, `-no-tun` keeps userspace; mirror the client's error message.
- [ ] **Step 4: Run full suite + `-race`** — PASS.
- [ ] **Step 5: Commit** `btawg: hub TUN mode (equal nodes), shared tun setup`.

### Task 8: Docs + full verification + live run

**Files:**
- Modify: `btawg/README.md`, `docs/specification.md` pointer
- Modify: `docs/superpowers/specs/2026-11-18-routing-policy-design.md` (status note only if reality diverged)

- [ ] **Step 1: Update README** — policy model + examples (1↔2 / 5↔6 / all-internet / work-net), hub TUN flags, "no route takeover" invariant, egress gate, banner semantics.
- [ ] **Step 2: Full verification** — `go vet ./...`, `go test ./... -count=1`, `-race`, fresh `CGO_ENABLED=0` builds of both binaries.
- [ ] **Step 3: Live run** — relay + hub + two clients; through the panel: create clients, set C invisible to others and B internet-off; assert live effect (dial from C times out; B's egress refused; A fine); flip via panel → immediate effect; camouflage change + restart + re-import sanity. If root available (`sudo -n`), run hub in real-TUN mode and confirm `ip addr show btawg0` and client→hub- host reachability; otherwise document the root-only leg as verified by unit + design.
- [ ] **Step 4: Commit** `btawg: routing policy docs and live verification`.
