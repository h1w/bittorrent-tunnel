# nDPI passive classification of outer traffic

nDPI 6.1.0 (ndpiReader), clean40 channel (20 ms one-way), 20 measured
AWG echoes per capture. Each pcap holds the real outer transport bytes
of the variant with synthesized IP/TCP/UDP headers (realistic 3-way TCP
handshake, MSS option).

| Variant | Method | Transport | nDPI detects | Flows | nDPI risk |
|---|---|---|---|---|---|
| awg-bt-ext-tcp | extended (BEP 10) | TCP | BitTorrent | 1 | none |
| awg-bt-ext-utp | extended (BEP 10) | uTP (no-Nagle) | BitTorrent | 1 | none |
| awg-bt-go-default | request/piece | uTP (pure-Go stock) | BitTorrent | 1 | none |
| awg-bt-go-nn-2lanes | request/piece | uTP (no-Nagle 2 lanes) | BitTorrent | 1 | none |
| awg-bt-go-nn-dup | request/piece | uTP (no-Nagle + dup) | BitTorrent | 1 | none |
| awg-bt-go-nn | request/piece | uTP (no-Nagle) | BitTorrent | 1 | none |
| awg-bt-libutp | request/piece | uTP (libutp) | BitTorrent | 1 | none |
| awg-bt-tcp | request/piece | TCP | BitTorrent | 1 | none |
| awg-bt-webseed | webseed (BEP 19) | HTTP/TCP | HTTP | 2 | Known Proto on Non Std Port, HTTP Susp User-Agent, Binary File/Data Transfer (Attempt) |
| awg-direct | baseline (no camouflage) | bare AWG UDP | Unknown | 1 | Susp Entropy |

Notes:
- BitTorrent detection is driven by the real `BitTorrent protocol` handshake and peer-message framing; µTP variants are detected as BitTorrent over the µTP/UDP transport.
- `awg-bt-webseed` is HTTP (two flows, one per direction); its risks are artifacts of the demo (`Known Proto on Non Std Port`, `HTTP Susp User-Agent`, `Binary File/Data Transfer (Attempt)`).
- `awg-direct` is `Unknown` with `Susp Entropy` risk: bare AWG ciphertext reads as high-entropy UDP, the exact signature camouflage is meant to avoid.
