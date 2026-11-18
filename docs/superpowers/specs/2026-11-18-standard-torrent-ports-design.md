# btawg: standard BitTorrent ports — short design

## Intent

Owner requirement: the deployment must look like ordinary torrent traffic —
the hub listens on a canonical BitTorrent port, and every DHT socket in the
system lives in the standard client port range 6881–6889. The hub always has
a public IP (owner's invariant), clients sit behind arbitrary NATs (their
traffic is purely outbound, which already works).

## Change

| Socket | Today | Becomes |
|---|---|---|
| Hub carrier (µTP/TCP listener) | `:7777` (config default) | `:6881` — canonical torrent port; `-carrier-port` stays |
| Hub DHT announcer | ephemeral UDP | first free of 6882–6889 (6881 is the carrier), else ephemeral |
| Client DHT discovery | ephemeral UDP | first free of 6881–6889, else ephemeral |
| Client µTP dial socket | ephemeral | unchanged — outbound connections from real clients are ephemeral too |

Implementation: one helper `listenUDPRange(min, max)` in `internal/dht` used by
both `NewAnnouncer` and `Discover`; config default 7777 → 6881. Never fatal:
if the whole range is busy, fall back to an ephemeral port rather than fail to
start.

## Non-goals

- NAT hole-punching / relay fallback (moot: the hub is public by invariant).
- Sharing one socket for µTP+DHT (libtorrent-style mux). Nice camouflage, but
  the announce already uses `implied_port=false` with the carrier's own port,
  and the hub is reachable — no correctness driver for MVP.

## Documentation

README: hub requires a public IP or a forward of 6881/udp; clients work behind
any NAT with no setup. Ports table updated to match.

## Verification

TDD: range-bind helper test (occupy part of the range → next free port;
occupy all → ephemeral fallback), config default test. Full suite + `-race`,
then a live run with the hub on 6881 and the whole traffic battery through it.
