#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
work=$(go run ./cmd/prepare)
trap 'rm -r "$work"' EXIT
go build -modfile "$work/go.mod" -o "$work/matrix" ./cmd/matrix
"$work/matrix" "$@"
