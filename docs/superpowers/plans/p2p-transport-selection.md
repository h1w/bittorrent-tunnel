# P2P Transport Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Choose real directional peer transports without changing SOCKS5 exit selection.

**Architecture:** A separate persistent peer policy feeds hub rendezvous and per-flow P2P routing. The hub approves direction, keys, protocol, addresses and lease; the peer transport authenticates before admitting packets.

**Tech Stack:** Go/Linux TUN, BitTorrent carriers, AWG, WireGuard, TLS 1.3.

**Spec:** `docs/superpowers/specs/p2p-transport-selection.md`

## Global Constraints

Ten real methods; no remapped protocol. P2P off leaves hub traffic as it was. P2P on means relay opt-in (false default). Incoming list and outgoing pools are separate. SOCKS5 selection and central services are unaffected.

## Review Focus

Empty vs omitted config, downgrade, direction reversal and spoofing, flow reuse and fragments, graceful shutdown/reactivation, no relay packet leak, per-port internet invariants.

### Task 1: Persistent policy and terminal setup

- [x] Add separate durable incoming policy, three outgoing pools, transport selection and opt-in relay to the TUI and control socket. Verify defaults, validation and saved settings.

### Task 2: Direct carrier establishment

- [x] Establish mode-qualified BitTorrent ext/req links over µTP or TCP; verify real socket traffic and TCP peers whose source differs from their advertised candidates.

### Task 3: Native underlay

- [x] Implement separate native AWG and WG UDP links with authenticated path discovery and no BitTorrent encapsulation. Verify raw datagrams and nomination lifecycle.

### Task 4: Hub negotiation and client flow routing

- [x] Issue directional grants, pin flows and preserve independent SOCKS5 routes. Run independent reviews, `go test -race ./...`, all ten direct modes over Linux TUN, explicit relay after denial, and the TCP/UDP egress cascade.
