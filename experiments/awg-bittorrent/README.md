# AWG inside BitTorrent wire messages

Reproducible research benchmark, not a production torrent VPN or DPI camouflage proof.

## Paths

All variants use the same official AmneziaWG v3.1.20261116 engine, userspace gVisor TUN, keys generated per case, S1–S4=32, H1–H4=101–104, Jc=4/Jmin=40/Jmax=100. Every case requires a successful authenticated AWG handshake on both peers.

- `awg-direct`: actual AWG datagrams over UDP through the same ordered delay emulator.
- `awg-bt-tcp`: actual AWG datagrams inside BitTorrent peer messages over kernel TCP with TCP_NODELAY.
- `awg-bt-libutp`: BitTorrent peer messages over reference C++ libutp.
- `awg-bt-go-default`: same over original pure-Go µTP.
- `awg-bt-go-nn`: pure-Go µTP with only the Nagle hold condition bypassed in a temporary source copy.
- `awg-bt-go-nn-dup`: preceding variant duplicates outer UDP packets; consumes additional bandwidth.
- `awg-bt-go-nn-2lanes`: two established peer connections, round-robin AWG datagrams. This is deliberate striping, NOT inner-flow-pinned ordering; reordering is measured and AWG replay-window behavior is relevant.
- `awg-bt-ext-utp`: extended (BEP 10, message id 20) carrier over pure-Go µTP (Nagle bypassed).
- `awg-bt-ext-tcp`: extended (BEP 10) carrier over kernel TCP.
- `awg-bt-webseed`: webseed (BEP 19) carrier over kernel TCP, HTTP range bodies, no BitTorrent handshake.

µTP target 5ms, send/receive buffers 64KiB. The helper under `../transport-matrix` generates a temporary modified dependency and modfile, not a module-cache change. Go dependency resolution may upgrade transitive crypto/net dependencies relative to the standalone baseline; direct AWG is therefore remeasured within this module.

## Actual outer messages and limits

Each connection exchanges a 68-byte BitTorrent handshake, matching experimental infohash, complementary bitfields, interested and unchoke. Each side maintains 32 outstanding requests for one 2048-byte block per virtual piece. Piece responses validate index, offset, length and outstanding request; received pieces immediately replenish request credit. Unknown message types, invalid sizes and unsolicited indices terminate the carrier and increment Invalid.

Each piece block contains uint16 big-endian datagram length, actual AWG datagram, and cryptographically random padding to 2048 bytes so every block reads as high-entropy content. All AWG packets, including handshake and junk, travel inside the carrier; no direct AWG UDP fallback exists for carrier variants. The experiment uses a fixed-peer custom Bind. The direct case uses a custom UDP Bind to traverse the identical delay emulator; unlike the earlier baseline it does not use NewDefaultBind.

**Not a hash-correct file exchange:** the bitfield advertises a virtual finite file, and AWG ciphertext substitutes for immutable content. File checksums do not validate; no metadata is served. This is request/piece wire-format encapsulation, not a full interoperable BitTorrent client. It cannot establish full passive-DPI camouflage. No DHT, tracker or real public swarm participates. Peer state is a minimal subset and retransmitted application requests are not implemented; reliable outer streams handle their own packet recovery. The virtual index space is finite and exhaustion fails rather than silently wrapping.

## Method

```sh
cd experiments/awg-bittorrent
go mod download
bash run.sh -count 400 -repeats 3 > results/comparison.jsonl 2> results/run.log
python3 analyze.py
```

Three repeats for all ten variants on `clean40` (20ms one-way impairment), 30 cases total. TCP variants traverse the same one-way delay via a write-side delay wrapper, so no localhost-only runs remain. No induced loss, rate limit, background load or artificial retransmission. Each case has one separately timed first echo, 50 sequential warmup echoes and 400 measured open-loop 256-byte messages at 10ms intervals. Application RTT is measured before the inner UDP write until the complete returned datagram, using a monotonic clock. It includes AWG crypto, gVisor networking, request scheduling, padding, transport and emulator. Outer connection setup is excluded; FirstEchoMS includes AWG session establishment. Finite two-second drain; missing remains visible.

All variants, TCP and UDP, share the same one-way 20ms delay; the delta column is the camouflage overhead on top of the channel. Pure-Go Nagle bypass changes sender policy only, not reliability, ACK, receive order or congestion logic. Duplicate outer UDP packets are experimental redundancy, not measured DPI-equivalent traffic. Simulated clean40 is not an actual remote VPS.

Output includes unique inner sequence accounting, RTT samples, missing, late over100ms, reordering, confirmed BitTorrent handshakes, requests, pieces and Invalid. BTBytes counts sent framed messages excluding handshakes. OuterBytes counts attempted UDP bytes plus estimated IP/UDP overhead, includes setup/warmup and duplicates. It is unavailable for TCP and zero there, not zero network cost.

## nDPI passive classification

`ndpi_verify.sh /path/to/ndpiReader` captures each variant's outer traffic to
`results/ndpi-pcaps/` (synthesized IP/TCP/UDP headers around the real outer
bytes) and `ndpi_verify.py` classifies it with nDPI. Result:
`results/ndpi-summary.md`. All BitTorrent carriers (TCP and µTP) are classified
as BitTorrent; webseed as HTTP; bare AWG as Unknown with Susp Entropy risk.
