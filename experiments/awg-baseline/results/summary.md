# Direct AWG clean localhost results

| Path | Repeat | Received | p50 RTT ms | p95 RTT ms | p99 RTT ms | Max RTT ms | First echo ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| udp-loopback | 0 | 1000/1000 | 0.087 | 0.162 | 0.247 | 0.347 | 0.080 |
| awg-userspace-loopback | 0 | 1000/1000 | 0.335 | 0.483 | 0.635 | 0.849 | 1.987 |
| udp-loopback | 1 | 1000/1000 | 0.092 | 0.141 | 0.196 | 0.296 | 0.061 |
| awg-userspace-loopback | 1 | 1000/1000 | 0.347 | 0.619 | 0.754 | 0.946 | 2.374 |
| udp-loopback | 2 | 1000/1000 | 0.090 | 0.148 | 0.195 | 0.308 | 0.169 |
| awg-userspace-loopback | 2 | 1000/1000 | 0.331 | 0.527 | 0.725 | 0.844 | 3.029 |

Actual AWG with userspace TUN and direct UDP. Localhost only; no WAN or outer camouflage. See README for profile and topology.
