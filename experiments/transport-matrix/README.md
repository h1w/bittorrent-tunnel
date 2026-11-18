# Interactive carrier matrix

Research harness, not a VPN, BitTorrent file-transfer implementation or DPI bypass proof.

## Run

Linux, Go 1.27+, C/C++ toolchain for reference libutp:

```sh
cd experiments/transport-matrix
go mod download
bash run.sh -repeats 3 -count 400 > results/matrix.jsonl 2> results/run.log
python3 analyze.py
```

`cmd/prepare` copies the pinned go-utp module into a temporary directory, asserts the expected Nagle condition, adds an experiment-only switch and generates a temporary modfile. The module cache is not modified; the runner removes its generated directory. Ten variants share one binary and run sequentially. The switch changes only between closed cases. No custom ACK or unreliable µTP mode is used.

## Configurations

1. Raw UDP baseline.
2. Reference C++ libutp, 100ms congestion target, 64KiB buffers.
3. Pure Go µTP, original Nagle, same target/buffers.
4. Pure Go without Nagle, 100ms target.
5. Pure Go without Nagle, 5ms target.
6. Pure Go without Nagle, 1ms target.
7. Variant 5 with 8KiB buffers.
8. Variant 5 with four flow-pinned connections.
9. Variant 5 with two copies of every outer datagram.
10. Four flow-pinned connections plus two copies.

These are ten carrier configurations, not ten independent protocols. Duplication occurs below µTP, so sequence numbers remain unchanged. It consumes extra bandwidth, affects congestion measurements and is not guaranteed to resemble ordinary BitTorrent behavior. Both copies share the same path and burst outage.

## Method

Four synthetic network scenarios share 20ms one-way delay:

- `clean`: no induced loss or rate cap.
- `loss1`: 1% independent loss per attempted outer datagram per direction.
- `burst50`: both directions drop transmissions during the first 50ms of each second.
- `load2mbit`: 2Mbit/s serialization per direction, 1% independent loss and two extra 1200-byte messages every 10ms. This intentionally overloads the raw offered rate; it measures congestion behavior, not unloaded protocol overhead.

Losses activate only after connection establishment; this is not a handshake robustness test. Each case sends a one-second warmup then 400 measured 256-byte records at 10ms aggregate intervals across four fixed flows. In multi-lane variants each flow remains pinned to one connection. Background messages map to lane zero. Both message header and payload are written as one length-prefixed record; reads use io.ReadFull. There is a bounded 64-record application queue per lane. Queue rejection counts as write error; its measured record remains missing.

Impairment uses ordered event queues per direction, with serialization when enabled. It does not spawn one timer per packet. Queue capacity is 4096 outer datagrams; drops at this bound are counted. Traffic uses real localhost UDP sockets. Measurements use one process's monotonic clock from enqueue until complete echo. RTT includes application queues and receiver processing, not initial discovery/handshake. The two-second observation drain is finite: not received by shutdown counts as missing, not proof of permanent network loss.

A seed fixes each direction's random generator, not identical lost application messages across implementations: different transports generate different packet counts. Relative burst timing is reset after setup, but exact scheduling remains OS-dependent. Three short repetitions are not confidence intervals. TCP fallback, direct AWG, BitTorrent request/piece, congestion due to other programs, actual game/call quality and classifiers are absent.

## Outputs

`results/matrix.jsonl` includes every case and sorted delivered RTT samples. Sorting discards packet timing order; max per-flow receive gap is recorded separately. `Missing`, `Over100`, `WriteErrors`, `Reordered`, `Drops` and `QueueDrops` prevent interpreting selective delivery as success. Deadline-miss rate is `(Over100 + Missing) / Sent`.

`WireBytes` includes setup, warmup, echoes, control and background traffic plus estimated IPv4/UDP headers. It is not measured NIC traffic or a clean payload-only expansion ratio. `summary.md` reports per-case p95 ranges, worst RTT, missing/deadline misses and total byte cost. Compare byte cost only within the same scenario and duration, noting drain behavior.

No result establishes the product's agreed +20ms p95 relative to direct AWG; the baseline here is raw UDP. No result establishes passive-DPI camouflage.
