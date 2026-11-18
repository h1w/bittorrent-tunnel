# AWG vs BitTorrent-carrier summary (median of 3 seeds)

| Variant | Channel | Direct AWG p95 ms | Variant p95 ms | Delta p95 vs direct ms | p99 ms | Max ms | Delivered | BT handshakes | Invalid |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| awg-bt-tcp | localhost | 0.450 | 0.532 | +0.082 | 0.678 | 0.962 | 1200/1200 | 2 | 0 |
| awg-bt-libutp | localhost | 0.450 | 3.277 | +2.827 | 3.498 | 4.189 | 1200/1200 | 2 | 0 |
| awg-bt-go-default | localhost | 0.450 | 3.144 | +2.694 | 3.230 | 3.430 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn | localhost | 0.450 | 0.682 | +0.232 | 0.854 | 0.975 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn-dup | localhost | 0.450 | 0.735 | +0.285 | 1.119 | 1.327 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn-2lanes | localhost | 0.450 | 0.671 | +0.221 | 0.980 | 1.309 | 1200/1200 | 4 | 0 |
| awg-bt-libutp | clean40 | 42.364 | 62.742 | +20.378 | 63.167 | 125.624 | 1200/1200 | 2 | 0 |
| awg-bt-go-default | clean40 | 42.364 | 62.103 | +19.739 | 62.480 | 124.564 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn | clean40 | 42.364 | 42.251 | -0.112 | 42.552 | 42.697 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn-dup | clean40 | 42.364 | 42.313 | -0.051 | 42.597 | 42.757 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn-2lanes | clean40 | 42.364 | 42.217 | -0.147 | 42.505 | 42.665 | 1200/1200 | 4 | 0 |

Delta = variant p95 - direct AWG p95. localhost and clean40 are different channels and are not directly comparable. Per-seed raw data: results/per-seed.md. Carrier is BitTorrent wire-format (handshake + request/piece), not a hash-correct file exchange.
