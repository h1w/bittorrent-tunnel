import json
import statistics
from collections import defaultdict
from pathlib import Path

root = Path(__file__).parent
rows = [json.loads(line) for line in (root / 'results/comparison.jsonl').read_text().splitlines()]
assert len(rows) == 39
assert len({(r['Mode'], r['Channel'], r['Repeat']) for r in rows}) == 39
for r in rows:
    assert r['Sent'] == 400
    assert r['Received'] + r['Missing'] == r['Sent']
    assert len(r['rtt_ms'] or []) == r['Received']
    assert r['Bad'] == 0
    if not r['Mode'].endswith('-direct'):
        assert r['Handshakes'] >= 2
        assert r['Pieces'] == 908
        assert r['Invalid'] == 0

# Per-seed raw dump.
seed_lines = ['# AWG nested comparison results (per seed)', '',
              '| Mode | Channel | Received | p50 RTT ms | p95 RTT ms | p99 RTT ms | Max RTT ms | First echo ms | Over 100ms | BT handshakes | BT bytes |',
              '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
for r in sorted(rows, key=lambda x: (x['Channel'], x['Mode'], x['Repeat'])):
    seed_lines.append(f"| {r['Mode']} | {r['Channel']} | {r['Received']}/{r['Sent']} | {r['P50']:.3f} | {r['P95']:.3f} | {r['P99']:.3f} | {r['Max']:.3f} | {r['FirstEchoMS']:.3f} | {r['Over100']} | {r['Handshakes']} | {r['BTBytes']} |")
(root / 'results/per-seed.md').write_text('\n'.join(seed_lines) + '\n')

# Aggregated comparison vs direct AWG (median of 3 seeds, baseline + delta).
agg = defaultdict(list)
for r in rows:
    agg[(r['Mode'], r['Channel'])].append(r)

def med(mode, channel, field):
    return statistics.median(x[field] for x in agg[(mode, channel)])

order = ['awg-bt-tcp', 'awg-bt-libutp', 'awg-bt-go-default', 'awg-bt-go-nn', 'awg-bt-go-nn-dup', 'awg-bt-go-nn-2lanes']
lines = ['# AWG vs BitTorrent-carrier summary (median of 3 seeds)', '',
         '| Variant | Channel | Direct AWG p95 ms | Variant p95 ms | Delta p95 vs direct ms | p99 ms | Max ms | Delivered | BT handshakes | Invalid |',
         '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
for channel in ['localhost', 'clean40']:
    base = med('awg-direct', channel, 'P95')
    for mode in order:
        if (mode, channel) not in agg:
            continue
        variant_p95 = med(mode, channel, 'P95')
        delta = variant_p95 - base
        lines.append(
            f"| {mode} | {channel} | {base:.3f} | {variant_p95:.3f} | {delta:+.3f} | "
            f"{med(mode, channel, 'P99'):.3f} | {med(mode, channel, 'Max'):.3f} | "
            f"{sum(x['Received'] for x in agg[(mode, channel)])}/{sum(x['Sent'] for x in agg[(mode, channel)])} | "
            f"{int(med(mode, channel, 'Handshakes'))} | {int(med(mode, channel, 'Invalid'))} |"
        )
lines += ['',
          'Delta = variant p95 - direct AWG p95. localhost and clean40 are different channels and are not directly comparable. Per-seed raw data: results/per-seed.md. Carrier is BitTorrent wire-format (handshake + request/piece), not a hash-correct file exchange.']
text = '\n'.join(lines) + '\n'
(root / 'results/summary.md').write_text(text)
print(text)
