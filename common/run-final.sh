#!/usr/bin/env bash
# Resumable version of run-all.sh for long final runs: every (lib, step) writes a marker in results/.done/
# when it completes, so a restarted container picks up where it stopped. Steps per lib run sequentially.
# Usage: common/run-final.sh [--libs a,b]
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIBS=(noble liboqs openssl circl rustcrypto bouncycastle)
[[ "${1:-}" == --libs ]] && IFS=, read -ra LIBS <<<"$2"
DONE="$ROOT/results/.done"; mkdir -p "$DONE"
step() { # step <lib> <name> <cmd...>
  local l="$1" s="$2"; shift 2
  [[ -f "$DONE/$l.$s" ]] && { echo "== skip $l $s (done)"; return; }
  echo "== $s $l  $(date -u +%H:%M:%S)"
  if "$@"; then touch "$DONE/$l.$s"; else echo "!! $l $s failed (exit $?)"; fi
}
for l in "${LIBS[@]}"; do step "$l" build "$ROOT/libs/$l/run.sh" build; done
for l in "${LIBS[@]}"; do
  R="$ROOT/results/$l"; mkdir -p "$R"
  step "$l" bench   bash -c "rm -f '$R/bench.jsonl' && '$ROOT/libs/$l/run.sh' bench --budget-ms 1000 --out '$R/bench.jsonl'"
  step "$l" stages  bash -c "rm -f '$R/stages.jsonl' && '$ROOT/libs/$l/run.sh' stages --budget-ms 1000 --out '$R/stages.jsonl'"
  if [[ $l == noble ]]; then
    # noble's stack probes repeat each op ~20x; pure-JS SLH-DSA "s" ops take 1-20 s, so those sets get v0 only
    # (stack depth does not depend on s/f: same code path, different loop counts).
    FAST=ML-DSA-44,ML-DSA-65,ML-DSA-87,SLH-DSA-SHA2-128f,SLH-DSA-SHA2-192f,SLH-DSA-SHA2-256f,SLH-DSA-SHAKE-128f,SLH-DSA-SHAKE-192f,SLH-DSA-SHAKE-256f,Falcon-512,Falcon-1024
    SLOW=SLH-DSA-SHA2-128s,SLH-DSA-SHA2-192s,SLH-DSA-SHA2-256s,SLH-DSA-SHAKE-128s,SLH-DSA-SHAKE-192s,SLH-DSA-SHAKE-256s
    step "$l" memory bash -c "rm -f '$R/memory.jsonl' && '$ROOT/libs/$l/run.sh' memory --params $FAST --out '$R/memory.jsonl' && '$ROOT/libs/$l/run.sh' memory --params $SLOW --variants keygen.v0,sign.v0,verify.v0 --no-stages --out '$R/memory.slow.jsonl' && cat '$R/memory.slow.jsonl' >> '$R/memory.jsonl' && rm '$R/memory.slow.jsonl'"
  else
    step "$l" memory  bash -c "rm -f '$R/memory.jsonl' && '$ROOT/libs/$l/run.sh' memory --out '$R/memory.jsonl'"
  fi
  step "$l" validate "$ROOT/libs/$l/run.sh" validate "$ROOT/common/validation/validation.json.gz" "$R/validation.json"
done
node "$ROOT/common/check-match.mjs" || echo "!! match check reported problems (see results/MATCH.md)"
node "$ROOT/common/report.mjs"
node "$ROOT/common/report-phase2.mjs"
echo "== ALL DONE $(date -u +%H:%M:%S)"
