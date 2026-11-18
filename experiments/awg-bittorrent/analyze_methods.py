import json
import statistics
from collections import defaultdict
from pathlib import Path

root = Path(__file__).parent
rows = [json.loads(line) for line in (root / 'results/methods.jsonl').read_text().splitlines()]

# 10 variants on clean40 (20 ms one-way) only.
assert len(rows) == 30, len(rows)
assert len({(r['Mode'], r['Channel'], r['Repeat']) for r in rows}) == 30
for r in rows:
    assert r['Sent'] == 400
    assert r['Received'] + r['Missing'] == r['Sent']
    assert len(r['rtt_ms'] or []) == r['Received']
    assert r['Bad'] == 0
    assert r['Invalid'] == 0

agg = defaultdict(list)
for r in rows:
    agg[(r['Mode'], r['Channel'])].append(r)

def med(mode, channel, field):
    return statistics.median(x[field] for x in agg[(mode, channel)])

lines = ['# Camouflage methods comparison (median of 3 seeds)', '',
         '| Method | Channel | Direct AWG p95 ms | Variant p95 ms | Delta p95 vs direct ms | p99 ms | Max ms | Delivered | BT handshakes | Invalid |',
         '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
for channel in ['clean40']:
    base = med('awg-direct', channel, 'P95')
    for mode in ['awg-bt-tcp', 'awg-bt-libutp', 'awg-bt-go-default', 'awg-bt-go-nn', 'awg-bt-go-nn-dup', 'awg-bt-go-nn-2lanes', 'awg-bt-ext-utp', 'awg-bt-ext-tcp', 'awg-bt-webseed']:
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
          'Channel: clean40 = 20 ms one-way delay (real link model), applied to every variant including direct AWG. Methods: awg-bt-* = request/piece (reference); awg-bt-ext-* = extended (BEP 10); awg-bt-webseed = webseed (BEP 19, HTTP, no BT handshake). Delta = variant p95 - direct AWG p95. All carriers are wire-format BitTorrent, not hash-correct file exchanges.']
text = '\n'.join(lines) + '\n'
(root / 'results/methods-summary.md').write_text(text)
print(text)
