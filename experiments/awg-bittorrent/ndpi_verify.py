#!/usr/bin/env python3
"""Classify captured outer-traffic pcaps with nDPI and emit results/ndpi-summary.md.

Usage: ndpi_verify.py /path/to/ndpiReader
The pcaps must already exist under results/ndpi-pcaps/ (see ndpi_verify.sh for
the capture step).
"""
import re
import subprocess
import sys
from pathlib import Path

ndpi = sys.argv[1]
root = Path(__file__).parent
pcap_dir = root / "results" / "ndpi-pcaps"

meta = {
    "awg-direct": ("baseline (no camouflage)", "bare AWG UDP"),
    "awg-bt-tcp": ("request/piece", "TCP"),
    "awg-bt-libutp": ("request/piece", "uTP (libutp)"),
    "awg-bt-go-default": ("request/piece", "uTP (pure-Go stock)"),
    "awg-bt-go-nn": ("request/piece", "uTP (no-Nagle)"),
    "awg-bt-go-nn-dup": ("request/piece", "uTP (no-Nagle + dup)"),
    "awg-bt-go-nn-2lanes": ("request/piece", "uTP (no-Nagle 2 lanes)"),
    "awg-bt-ext-utp": ("extended (BEP 10)", "uTP (no-Nagle)"),
    "awg-bt-ext-tcp": ("extended (BEP 10)", "TCP"),
    "awg-bt-webseed": ("webseed (BEP 19)", "HTTP/TCP"),
}


def classify(pcap):
    out = subprocess.run([ndpi, "-i", str(pcap)], capture_output=True,
                         text=True).stdout
    proto = ""
    m = re.search(r"^Detected protocols:\n(.*?)\n\n", out, re.S | re.M)
    if m:
        proto = ",".join(line.split()[0]
                         for line in m.group(1).strip().splitlines())
    flows = re.search(r"flows: (\d+)", out)
    risknames = []
    mr = re.search(r"Risk stats \[found (\d+)", out)
    if mr and int(mr.group(1)) > 0:
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("Risk stats"):
                for l2 in lines[i + 1:]:
                    s = l2.strip()
                    if not s or s.startswith("NOTE"):
                        break
                    mname = re.match(r"(.+?)\s+\d+\s+\[", s)
                    if mname:
                        risknames.append(mname.group(1))
                break
    return (proto, flows.group(1) if flows else "?",
            ", ".join(risknames) if risknames else "none")


rows = []
for pcap in sorted(pcap_dir.glob("*.pcap")):
    base = pcap.name[:-5]  # strip .pcap
    name = base[:-3]       # strip -s0
    proto, flows, risk = classify(pcap)
    method, transport = meta.get(name, (name, ""))
    rows.append((name, method, transport, proto, flows, risk))

lines = [
    "# nDPI passive classification of outer traffic", "",
    "nDPI 6.1.0 (ndpiReader), clean40 channel (20 ms one-way), 20 measured",
    "AWG echoes per capture. Each pcap holds the real outer transport bytes",
    "of the variant with synthesized IP/TCP/UDP headers (realistic 3-way TCP",
    "handshake, MSS option).", "",
    "| Variant | Method | Transport | nDPI detects | Flows | nDPI risk |",
    "|---|---|---|---|---|---|",
]
for name, method, transport, proto, flows, risk in rows:
    lines.append(f"| {name} | {method} | {transport} | {proto} | {flows} | {risk} |")
lines += [
    "", "Notes:",
    "- BitTorrent detection is driven by the real `BitTorrent protocol` handshake and peer-message framing; µTP variants are detected as BitTorrent over the µTP/UDP transport.",
    "- `awg-bt-webseed` is HTTP (two flows, one per direction); its risks are artifacts of the demo (`Known Proto on Non Std Port`, `HTTP Susp User-Agent`, `Binary File/Data Transfer (Attempt)`).",
    "- `awg-direct` is `Unknown` with `Susp Entropy` risk: bare AWG ciphertext reads as high-entropy UDP, the exact signature camouflage is meant to avoid.",
]
text = "\n".join(lines) + "\n"
(root / "results" / "ndpi-summary.md").write_text(text)
print(text)
