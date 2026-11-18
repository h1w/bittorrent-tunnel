# Transport Matrix Implementation Plan

**Goal:** Compare ten concrete carrier configurations for interactive AWG-sized datagrams, recording delay, delivery and traffic costs without claiming VPN camouflage.

**Architecture:** A standalone experimental Go module uses real UDP sockets behind an ordered, bounded, event-driven impairment link. A generated Go source overlay adds one experiment-only Nagle switch to a pinned pure-Go dependency; no module-cache files are modified. Endpoints use UDP, reference libutp, or pure-Go µTP. Independent µTP lanes preserve each flow's lane; redundant packets are a separate hypothesis.

**Spec:** docs/specification.md. This is a research spike, not product implementation.

## Files

- experiments/transport-matrix/go.mod and go.sum: pinned isolated dependencies.
- experiments/transport-matrix/cmd/prepare/main.go: assert expected upstream code, generate temporary overlay and print its directory.
- experiments/transport-matrix/cmd/matrix/main.go: impairment channel, echo traffic, ten variants and JSONL observations.
- experiments/transport-matrix/run.sh: prepare overlay, execute matrix, clean generated files.
- experiments/transport-matrix/results/: raw observations and metadata.
- docs/specification.md: measured conclusions, limitations and next decision.

## Matrix

UDP baseline; reference libutp default target; pure-Go default target; pure-Go Nagle off at 100/5/1ms target; Nagle off at 5ms with 8KiB buffers; Nagle off at 5ms using four flow-pinned lanes; Nagle off at 5ms duplicating outer datagrams with independent loss; four lanes plus duplication. Exactly ten configurations; no claim that parameter choices are independent protocols.

## Steps

1. Implement bounded ordered network emulation, original-length validation, unique sequence accounting, seeded loss, timestamps and JSONL. Scenarios: 20ms one-way clean, 1% independent loss, periodic 50ms loss bursts, and a bounded 2Mbit/s link with two continuously paced 256-byte flows plus larger concurrent messages. Run three seeds; use the same scenario rules, not the false claim of identical losses for different wire traffic.
2. Prepare and build once, smoke actual output, then execute the complete matrix sequentially to avoid cross-case contention. Include 256-byte records, 10ms aggregate interval, at least 400 messages per case, warmup, drain deadline and exact missing counts. Count p95 deadline misses including missing messages, gaps per flow and estimated outer IPv4/UDP byte overhead.
3. Analyze JSONL: compare no-loss RTT to matching UDP, lossy tails, over-100ms fraction, delivery and byte cost. Save raw and aggregate data. Explicitly disclose synthetic link, short runs, no AWG/BitTorrent/DPI and initialization excluded from RTT.

## Review focus

- Stream record boundaries: io.ReadFull and complete writes, no truncated echo counted as success.
- Unreliable baseline: missing packets do not vanish from deadline-miss denominator.
- Lane multiplexing: fixed mapping by flow; don't stripe a single flow and claim its ordering is preserved.
- Impairment channel: timers never reorder no-jitter packets inside one direction; bound queue, account drops and cancellation.
- Shutdown: close transports and sockets, join worker goroutines and cancel queued sends before the next case.
