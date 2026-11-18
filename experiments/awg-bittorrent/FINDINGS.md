# Findings — AWG-inside-BitTorrent (fixed record)

Authoritative record of what was experimented, what is kept, and what is
discarded. Generated 2026-11-18.

## Fixed setup

- AWG profile: `S1..S4=32`, `H1..H4=101..104`, `Jc=4`, `Jmin=40`, `Jmax=100`.
- Channel: `clean40` = 20 ms one-way delay, applied to every variant including
  bare AWG (UDP via the delay-emulator queue, TCP via a write-side delay
  wrapper). No localhost runs remain.
- Latency target: added p95 RTT ≤ 20 ms relative to direct AWG.
- Passive DPI: nDPI 6.1.0 (`ndpiReader`), offline over captured outer pcaps.

## What was experimented

3 camouflage methods, 9 carrier configurations, plus 1 bare-AWG baseline:

| Method | Wire shape | Configurations |
|---|---|---|
| 1. `request/piece` (BEP 3, id 7) | BT handshake + bitfield/interested/unchoke + `request`/`piece` | tcp, libutp, go-default, go-nn, go-nn-dup, go-nn-2lanes |
| 2. `extended` (BEP 10, id 20) | BT handshake + extension handshake + private `extended` messages | ext-utp, ext-tcp |
| 3. `webseed` (BEP 19) | HTTP GET + `206 Partial Content` bodies, no BT handshake | webseed |
| — baseline | bare AWG over UDP | awg-direct |

## Selection rule

Keep the methods/variants whose **outer traffic nDPI classifies as BitTorrent**.
Discard the rest.

## Kept — nDPI = BitTorrent (8 variants, 2 methods)

Direct AWG baseline p95 = 42.519 ms on clean40. All rows 1200/1200 delivered,
Invalid=0, nDPI risk=none.

| Variant | Method | Transport | p95 ms | Δ p95 vs AWG ms | Latency verdict |
|---|---|---|---:|---:|---|
| **awg-bt-ext-utp** | extended | µTP no-Nagle | 42.588 | **+0.069** | OK (best) |
| awg-bt-tcp | request/piece | TCP | 42.618 | +0.098 | OK |
| awg-bt-ext-tcp | extended | TCP | 42.621 | +0.102 | OK |
| awg-bt-go-nn | request/piece | µTP no-Nagle | 42.734 | +0.215 | OK |
| awg-bt-go-nn-2lanes | request/piece | µTP no-Nagle, 2 lanes | 42.771 | +0.252 | OK |
| awg-bt-go-nn-dup | request/piece | µTP no-Nagle + dup | 42.886 | +0.366 | OK |
| awg-bt-go-default | request/piece | µTP stock | 63.088 | +20.569 | marginal (>20 ms) |
| awg-bt-libutp | request/piece | µTP libutp | 63.156 | +20.637 | marginal (>20 ms) |

`go-default` and `libutp` pass nDPI but marginally exceed the 20 ms latency
target (their transport holds small packets); deprioritized, kept only because
they still classify as BitTorrent.

## Discarded — nDPI did not see BitTorrent

| Variant | nDPI result | Reason to discard |
|---|---|---|
| awg-bt-webseed | HTTP (2 flows) | Not BitTorrent; plus 3 HTTP risk flags (`Known Proto on Non Std Port`, `HTTP Susp User-Agent`, `Binary File/Data Transfer (Attempt)`). |
| awg-direct | Unknown (Susp Entropy) | Baseline, not camouflage; bare AWG reads as suspicious high-entropy UDP. |

## Recommended

`extended` over pure-Go µTP no-Nagle (`awg-bt-ext-utp`): +0.069 ms p95 vs
direct AWG, nDPI=BitTorrent with no risk flags.

## Honest limits

- Wire-format camouflage only, **not** hash-correct: AWG ciphertext substitutes
  for file blocks, piece SHA1 never validates. No metadata is served.
- Verified against **nDPI only** (one passive classifier), offline over pcaps
  with synthesized IP/TCP/UDP headers around the real outer bytes.
- Not tested against active probing (explicitly out of scope), and not on a
  real remote VPS link.
- Artifacts: `results/methods-summary.md` (latency), `results/ndpi-summary.md`
  (classification), `results/methods.jsonl` (raw), `results/ndpi-pcaps/`
  (captures), `METHODS.md` (wire shapes), `README.md` (method).
