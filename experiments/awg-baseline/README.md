# Direct AmneziaWG baseline

Actual official `amneziawg-go/v3` engine, pinned by go.mod/go.sum. Two independent devices use `conn.NewDefaultBind()` over localhost UDP, fresh ephemeral X25519 keypairs and userspace gVisor TUN interfaces. No µTP, BitTorrent framing, artificial delay, loss, proxy, NAT or internet path. No host routes/firewall/interfaces are modified. Successful authenticated AWG handshakes are required on both devices after traffic; private keys are not printed.

The fixed experimental AWG profile enables nonstandard H1–H4, 32-byte S1–S4 prefixes and four handshake junk packets, rather than silently testing only WireGuard-compatible defaults. It is one profile, not every possible AWG configuration; no extra header-protection key or CPS is configured. Exact configuration is printed in results/run.log.

```sh
cd experiments/awg-baseline
go run . > results/baseline.jsonl 2> results/run.log
```

Each of three repetitions measures raw kernel UDP then direct AWG. Each case sends 50 sequential warmup echoes, then 1000 open-loop 256-byte echoes at 10ms intervals. Monotonic timestamps start before the measured write. Reader records unique valid sequence numbers; missing messages remain visible. FirstEchoMS is a separate first-echo observation, not an Internet handshake benchmark. Subsequent RTT excludes setup and warmup. All sockets/devices close before the next case.

Limits: AWG includes the userspace network stack, while raw UDP uses the kernel application socket path. Their difference measures the complete local experimental path, not isolated cryptography cost. Both peers share one machine; CPU scheduling affects tails. No actual VPS/WAN, OS TUN routing, bandwidth throughput test or competing load is tested. The baseline cannot predict remote ping, passive DPI behavior or µTP performance. Results are local RTT, not one-way latency. Use the same topology when comparing future outer transports.
