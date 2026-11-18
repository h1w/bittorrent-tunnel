#!/usr/bin/env bash
# Capture outer traffic for all variants and classify it with nDPI.
# Usage: ndpi_verify.sh /path/to/ndpiReader [count]
set -euo pipefail
cd "$(dirname "$0")"
NDPI=${1:?usage: ndpi_verify.sh /path/to/ndpiReader [count]}
COUNT=${2:-20}
rm -rf results/ndpi-pcaps
mkdir -p results/ndpi-pcaps
bash run.sh -capture results/ndpi-pcaps -count "$COUNT" -repeats 1 >/dev/null 2>results/ndpi-capture.log
python3 ndpi_verify.py "$NDPI"
