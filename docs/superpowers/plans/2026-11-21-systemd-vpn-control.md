# btawg Systemd and Concurrent VPN Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operate the hub and client through systemd/TUI and expose ten switchable authenticated SOCKS5 endpoints without splitting a user's overlay IP.

**Architecture:** Add reusable systemd/config/TUI plumbing, then wire it to the existing hub and client. Each managed proxy owns one transport; mark-based Linux socket routing separates paths while sharing one local socket namespace, and the hub demultiplexes replies using authenticated IPv4 flow ownership. The ordinary overlay path follows an enabled transport; no host default-route takeover.

**Tech Stack:** Go, Linux TUN and policy routing, systemd, bbolt, RFC 1929.

**Spec:** `docs/superpowers/specs/2026-11-21-systemd-vpn-control-design.md`.

## Global Constraints

- Baseline v0.3.1, CGO-free Linux builds, no rewrite of original workspace. Preserve group policy, server identity and traffic persistence.
- Hub `6881/TCP+UDP`, `51820/UDP` WG, `51821/UDP` AWG. Panel on explicit loopback and VPN address (VPN path bound to the TUN, never a public IP); keep existing application-owned NAT, no changes to host INPUT policy.
- `config.ClientModes()` order maps permanently to `1080–1089`. Managed SOCKS5 must require one shared generated credential pair; disable/rotate drains affected connections. Disabled TCP ports cannot be bound by another process while the daemon runs.
- Secrets mode `0600`, atomic config updates, root-only Unix socket, no credentials in journald. Server first-install login printed once, not on reinstall.

## Review Focus

- Multiple simultaneous TLS siblings must not cancel one another or redirect existing flows; cover with overlapping TCP and UDP sessions sharing one overlay source IP.
- WG and BitTorrent AWG must not roam each other's AWG crypto binding, and unsolicited group traffic must still find an authenticated primary route.
- Port collision must fail startup before systemd readiness instead of leaving a partial set; rotations must fail closed for old credentials and not move any flow.
- Reinstall must retain the DB, existing imports and proxy config, and respect a failed start without losing a newly created plaintext admin password.
- Non-default groups, public-interface panel exposure, and root-only control/config access must be covered by the deployment smoke scenario.

---

### Task 1: Shared SOCKS5 authentication and cancellation

**Files:** `btawg/internal/socks/server.go`; new `btawg/internal/socks/auth_test.go`.

**Interfaces:** `(*socks.Server).WithCredentials(username, password string) *socks.Server`. `Serve` must stop sessions on its context cancellation, even if the parent intentionally keeps the underlying bound listener.

- [ ] Test raw SOCKS5 negotiation: when configured, no-auth and wrong credentials are rejected; RFC 1929 with correct credentials reaches CONNECT. Simulate cancellation while an established connection is idle. Run `go test ./internal/socks -run 'Test(PasswordAuth|CancellationClosesSession)'` (red before implementation).
- [ ] Extend negotiation using length-prefixed fields and constant-time secret comparison; cancel accepted connections, ensure listeners can be retained by a separate accept-loop adapter. Keep current low-level no-auth tests and migrate product entrypoints to configured authentication.
- [ ] Verify `go test ./internal/socks -count=1` and selectively commit verified changes.

### Task 2: Linux service lifecycle and admin panel

**Files:** new `btawg/internal/service/{systemd,files,tui}.go`; `btawg/cmd/btawg-server/main.go`; new `btawg/cmd/btawg-server/service.go`; `btawg/internal/server/panel_listener.go`, `btawg/internal/panel/panel.go` and templates.

**Interfaces:** `service.Unit` carries role, executable and paths; `Install`, `State`, `Control`, `NotifyReady`, and atomic file writers are used by both commands. `(*server.Server).ListenPanel(ctx context.Context, port int) ([]net.Listener, error)` binds localhost plus VPN; start one panel handler on both. Expose `install`, `run`, and no-argument TUI entry on both binaries; keep meaningful legacy foreground flags on explicit `run`/existing forms.

- [ ] Test panel from both listener transports, first-install/restart identity, and safe config writes. Test unit failure/collision with temp root and real `systemd-analyze verify`; don't write local machine's production unit.
- [ ] Instantiate files under `/etc/btawg`, `/var/lib/btawg`, `/run/btawg-client`, `/usr/local/bin` and `/etc/systemd/system`; daemon reload, enable/start, restart on upgrade. Preserve a root-only pending admin password until it is successfully printed after installation. Use `Type=notify`, bounded timeouts, and synchronous status/action errors. Permit manual DB migration without changing existing keys or policies. Managed server fixed listener ports override legacy settings; panel reflects the active managed values and does not show them as editable.
- [ ] Verify focused command/server/panel tests and a PTY TUI scenario followed by `systemd-analyze verify`. Commit verified changes.

### Task 3: Simultaneous hub data paths on one IP

**Files:** `btawg/internal/server/{server,router,handshake_routes}.go`; new `btawg/internal/server/flow_routes.go` and tests; `btawg/internal/e2e/e2e_test.go`.

**Interfaces:** `packetRouter` distinguishes the authenticated `engineTun` that admitted an IPv4 flow. Per-mode identity is derived from carrier framing family and the listener's TCP/µTP class; one AWG device per carrier mode, separate native AWG and WG devices; TLS sessions keyed by user + mode.

- [ ] Reproduce TCP/UDP responses going to the wrong tunnel and same-user TLS siblings displacing each other. Also pin fallback for new unsolicited group connections and existing ACL checks. Run targeted server/e2e reproductions (red).
- [ ] Implement authenticated directional tuple tracking for TCP and UDP (include ICMP when needed for echo/errors), bounded cleanup and invalidation on teardown or revocation. Do not let a competing route take an active flow. Recheck policy on downlink and when a path receives a queued packet. Preserve handshake-based fallback only for traffic without a known path. Ensure AWG devices maintain independent peer crypto state without allocating a native UDP socket per carrier mode.
- [ ] Verify focused server and mixed-mode integration tests, then selectively commit verified changes.

### Task 4: Managed client proxy slots and TUI

**Files:** `btawg/cmd/btawg-client/{main,service,tui}.go`; `btawg/internal/client/{client,proxy,managed}.go`; `btawg/internal/tunsetup/managed_linux.go`; `btawg/internal/service/client_config.go`.

**Interfaces:** managed settings include a validated import, enabled canonical modes, SOCKS bind IPv4 and generated credentials. Command/control supports current status, setting one mode and rotating credentials. Config is authoritative while stopped; when active, one daemon owns config mutations over a Unix socket. No secret passed in request arguments or exposed in normal status. Changes take effect without restarting the daemon.

- [ ] Smoke test two real active modes, both TCP and UDP over SOCKS, disabled port ownership, continued unrelated streams after disabling, old auth denied after rotation, and live state across re-open/restart. Unit tests cover partial bind failure and persistence edges. Run before implementation (red).
- [ ] Reserve TCP listeners synchronously before readiness and close traffic for disabled modes. Use a stable `btawg0` address with automatically installed VPN prefixes, per-mode unnumbered TUN and socket marks for independent proxy routing in the same kernel socket namespace. Ordinary IPv4 VPN traffic selects an enabled path; add only managed prefixes, never alter the host default. Install/cleanup only rules and routes owned by the daemon. Keep per-mode reconnect and surface status/errors. Render checkbox/ports and root-only credential view/rotation in the TUI.
- [ ] Verify client, routing, SOCKS and end-to-end checks. Commit verified changes.

### Task 5: Deployment and acceptance

**Files:** `btawg/README.md`, and release docs only if required by changed artifact installation. Use scratch, removable Linux/network-namespace smoke scripts.

- [ ] Update the operator quickstart for both installs, password handling, commands, port table, disable/rotate semantics, VPS prerequisites and no automatic host firewall openings. Request an independent end-to-end review after verification.
- [ ] Build both CGO-free binaries; run changed integration checks and full Go module suite. On authorized VPS/laptop or isolated equivalents: install both services, launch both TUIs in a PTY, check real panel access and service operations, probe simultaneous SOCKS traffic/auth before and after toggles/rotation/restart, verify shipped configuration/state ownership and no changes in default route. Record concrete evidence or report any environment limitation without claiming completion.
