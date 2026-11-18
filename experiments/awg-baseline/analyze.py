import json
from pathlib import Path

root = Path(__file__).parent
rows = [json.loads(line) for line in (root / 'results/baseline.jsonl').read_text().splitlines()]
assert len(rows) == 6
assert len({(r['Mode'], r['Repeat']) for r in rows}) == 6
for r in rows:
    assert r['Sent'] == 1000
    assert r['Received'] + r['Missing'] == r['Sent']
    assert len(r['rtt_ms'] or []) == r['Received']
    assert r['Bad'] == 0
lines = ['# Direct AWG clean localhost results', '', '| Path | Repeat | Received | p50 RTT ms | p95 RTT ms | p99 RTT ms | Max RTT ms | First echo ms |', '|---|---:|---:|---:|---:|---:|---:|---:|']
for r in rows:
    lines.append(f"| {r['Mode']} | {r['Repeat']} | {r['Received']}/{r['Sent']} | {r['P50']:.3f} | {r['P95']:.3f} | {r['P99']:.3f} | {r['Max']:.3f} | {r['FirstEchoMS']:.3f} |")
lines += ['', 'Actual AWG with userspace TUN and direct UDP. Localhost only; no WAN or outer camouflage. See README for profile and topology.']
text = '\n'.join(lines) + '\n'
(root / 'results/summary.md').write_text(text)
print(text)
