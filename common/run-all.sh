#!/usr/bin/env bash
# Orchestrator: build, byte-match + cross-verify, then benchmark every library sequentially (quiet machine).
# Usage: common/run-all.sh [--skip-build] [--skip-bench] [--budget-ms N] [--libs a,b]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIBS=(noble liboqs openssl circl rustcrypto bouncycastle)
BUDGET=1000; BUILD=1; BENCH=1
while [[ $# -gt 0 ]]; do case "$1" in
  --skip-build) BUILD=0;; --skip-bench) BENCH=0;;
  --budget-ms) BUDGET="$2"; shift;; --libs) IFS=, read -ra LIBS <<<"$2"; shift;;
  *) echo "unknown arg $1"; exit 2;; esac; shift; done

if [[ $BUILD == 1 ]]; then for l in "${LIBS[@]}"; do echo "== build $l"; "$ROOT/libs/$l/run.sh" build; done; fi

for l in "${LIBS[@]}"; do echo "== vectors $l"; mkdir -p "$ROOT/results/$l"; "$ROOT/libs/$l/run.sh" vectors "$ROOT/results/$l/artifacts.json"; done
ALL=(noble liboqs openssl circl rustcrypto bouncycastle)
for v in "${LIBS[@]}"; do for s in "${ALL[@]}"; do
  [[ -f "$ROOT/results/$s/artifacts.json" ]] || continue
  echo "== crossverify: $v verifies $s"
  "$ROOT/libs/$v/run.sh" crossverify "$ROOT/results/$s/artifacts.json" "$ROOT/results/$v/crossverify-$s.json"
done; done

if [[ $BENCH == 1 ]]; then for l in "${LIBS[@]}"; do
  echo "== bench $l (budget ${BUDGET}ms)"
  rm -f "$ROOT/results/$l/bench.jsonl"
  "$ROOT/libs/$l/run.sh" bench --budget-ms "$BUDGET" --out "$ROOT/results/$l/bench.jsonl"
done; fi

node "$ROOT/common/check-match.mjs"
node "$ROOT/common/report.mjs"
