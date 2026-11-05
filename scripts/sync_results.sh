#!/usr/bin/env bash
# Copy completed lines of the live experiment output (written outside the repo
# while runs are in progress) into results/raw/ for committing.
set -euo pipefail
SRC=${1:-/opt/tie-results}
DST=${2:-results/raw}
mkdir -p "$DST"
for f in "$SRC"/*.jsonl; do
  # only complete lines (a run may be mid-write)
  awk 'substr($0, length($0)) == "}"' "$f" > "$DST/$(basename "$f")"
done
wc -l "$DST"/*.jsonl
