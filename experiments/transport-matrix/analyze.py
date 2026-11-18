#!/usr/bin/env python3
"""Aggregate completed JSONL cases; keep missing records in deadline denominator."""
import collections
import json
import pathlib
import statistics

root = pathlib.Path(__file__).parent
rows = [json.loads(line) for line in (root / 'results/matrix.jsonl').read_text().splitlines() if line.strip()]
groups = collections.defaultdict(list)
for row in rows:
    groups[row['Scenario'], row['Variant']].append(row)
lines = ['# Transport matrix observations', '', 'Each range covers case p95 values, not a confidence interval. RTT excludes handshake. Missing records count as deadline misses. Wire bytes include warmup, setup and background traffic and estimated IPv4/UDP headers, not Ethernet.', '', '| Scenario | Variant | Runs | p95 range ms | Worst RTT ms | Missing | >100ms or missing | Outer MiB |', '|---|---|---:|---:|---:|---:|---:|---:|']
summary = []
for (scenario, variant), values in groups.items():
    sent = sum(v['Sent'] for v in values)
    missing = sum(v['Missing'] for v in values)
    late = sum(v['Over100'] for v in values) + missing
    item = dict(scenario=scenario, variant=variant, runs=len(values), sent=sent, missing=missing, deadline_miss_pct=100*late/sent, p95_min=min(v['P95'] for v in values), p95_max=max(v['P95'] for v in values), worst=max(v['Max'] for v in values), bytes=sum(v['WireBytes'] for v in values), write_errors=sum(v['WriteErrors'] for v in values), reordered=sum(v['Reordered'] for v in values), queue_drops=sum(v['QueueDrops'] for v in values))
    summary.append(item)
    lines.append(f"| {scenario} | {variant} | {item['runs']} | {item['p95_min']:.1f}–{item['p95_max']:.1f} | {item['worst']:.1f} | {missing}/{sent} | {item['deadline_miss_pct']:.2f}% | {item['bytes']/1048576:.2f} |")
(root / 'results/summary.json').write_text(json.dumps(summary, indent=2) + '\n')
(root / 'results/summary.md').write_text('\n'.join(lines) + '\n')
print(f'{len(rows)} cases; {len(groups)} scenario/variant groups')
print('\n'.join(lines))
