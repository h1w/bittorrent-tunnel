#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
helper=$(mktemp /tmp/btawg-prepare.XXXXXX)
(cd ../transport-matrix && go build -o "$helper" ./cmd/prepare)
work=$("$helper")
trap 'rm -r "$work"; rm "$helper"' EXIT
go build -modfile "$work/go.mod" -o "$work/bench" ./cmd/bench
"$work/bench" "$@"
