# Camouflage methods comparison (median of 3 seeds)

| Method | Channel | Direct AWG p95 ms | Variant p95 ms | Delta p95 vs direct ms | p99 ms | Max ms | Delivered | BT handshakes | Invalid |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| awg-bt-tcp | clean40 | 42.519 | 42.618 | +0.098 | 42.935 | 43.074 | 1200/1200 | 2 | 0 |
| awg-bt-libutp | clean40 | 42.519 | 63.156 | +20.637 | 63.659 | 127.551 | 1200/1200 | 2 | 0 |
| awg-bt-go-default | clean40 | 42.519 | 63.088 | +20.569 | 63.753 | 126.369 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn | clean40 | 42.519 | 42.734 | +0.215 | 43.047 | 43.553 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn-dup | clean40 | 42.519 | 42.886 | +0.366 | 43.397 | 43.611 | 1200/1200 | 2 | 0 |
| awg-bt-go-nn-2lanes | clean40 | 42.519 | 42.771 | +0.252 | 43.063 | 43.428 | 1200/1200 | 4 | 0 |
| awg-bt-ext-utp | clean40 | 42.519 | 42.588 | +0.069 | 42.963 | 43.885 | 1200/1200 | 2 | 0 |
| awg-bt-ext-tcp | clean40 | 42.519 | 42.621 | +0.102 | 42.866 | 43.445 | 1200/1200 | 2 | 0 |
| awg-bt-webseed | clean40 | 42.519 | 42.727 | +0.208 | 42.986 | 43.206 | 1200/1200 | 0 | 0 |

Channel: clean40 = 20 ms one-way delay (real link model), applied to every variant including direct AWG. Methods: awg-bt-* = request/piece (reference); awg-bt-ext-* = extended (BEP 10); awg-bt-webseed = webseed (BEP 19, HTTP, no BT handshake). Delta = variant p95 - direct AWG p95. All carriers are wire-format BitTorrent, not hash-correct file exchanges.
