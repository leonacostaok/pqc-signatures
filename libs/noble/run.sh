#!/usr/bin/env bash
# Harness entry point for the noble (@noble/post-quantum, pure JS) library. See common/CONTRACT.md.
#   run.sh build
#   run.sh rowdot --out <new.json> [--forks 5] [--start 10]
#   run.sh vectors <out.json>
#   run.sh crossverify <artifacts.json> <out.json>
#   run.sh bench --out <file.jsonl> [--budget-ms N] [--params a,b] [--ops keygen,sign,verify] [--variants id,id]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NODE="${NODE_BIN:-node}"
export BUN_BIN="${BUN_BIN:-$HOME/.bun/bin/bun}"
[ -x "$BUN_BIN" ] || { [ -x /root/.bun/bin/bun ] && export BUN_BIN=/root/.bun/bin/bun; } || true

build() {
  # 1. dependencies (root package.json: @noble/post-quantum + @noble/hashes); offline after first run
  if [ ! -d "$ROOT/node_modules/@noble/post-quantum" ]; then
    (cd "$ROOT" && npm install --no-audit --no-fund)
  fi
  # 2. vendored noble sources = fresh copies from node_modules + patches/*.patch (pluggable hash
  #    layer, precomputation APIs). Rebuilt from scratch every time so the result is deterministic.
  local src="$ROOT/node_modules/@noble/post-quantum"
  mkdir -p "$HERE/build/vendor"
  for f in ml-dsa slh-dsa falcon _crystals utils; do
    cp "$src/$f.js" "$HERE/build/vendor/$f.js"
  done
  for f in ml-dsa slh-dsa falcon; do
    patch -s "$HERE/build/vendor/$f.js" "$HERE/patches/$f.patch"
  done
  # 3. smoke test: every backend loads and reproduces one reference vector
  "$NODE" --input-type=module -e "
    import { loadAlg, MESSAGE, seedOf } from '$HERE/src/algs.mjs';
    import { referenceInputs, digest } from '$HERE/src/refcheck.mjs';
    for (const b of ['pkg', 'vendor', 'fast']) {
      const ref = await referenceInputs('ML-DSA-44');
      const a = await loadAlg(b, 'ML-DSA-44');
      const k = a.keygen(seedOf('ML-DSA-44'));
      if (digest(a.sign(MESSAGE, k.secretKey)) !== ref.sig_sha256) throw new Error('smoke test failed for backend ' + b);
    }
    console.error('[noble] build ok: node ' + process.versions.node + ', vendor patches applied, backends pkg/vendor/fast load');
  "
  if [ -x "$BUN_BIN" ]; then echo "[noble] bun: $("$BUN_BIN" --version) at $BUN_BIN" >&2; else echo "[noble] bun not found (v4 variants will be skipped)" >&2; fi
}

cmd="${1:-}"; shift || true
case "$cmd" in
  build) build ;;
  rowdot) "$NODE" "$HERE/experiments/rowdot.mjs" "$@" ;;
  vectors) "$NODE" "$HERE/src/vectors.mjs" "$@" ;;
  crossverify) "$NODE" "$HERE/src/crossverify.mjs" "$@" ;;
  bench) "$NODE" "$HERE/src/bench.mjs" "$@" ;;
  stages) "$NODE" "$HERE/src/stages.mjs" "$@" ;;
  validate) "$NODE" "$HERE/src/validate.mjs" "$@" ;;
  memory) "$NODE" "$HERE/src/memory.mjs" "$@" ;;
  *) echo "usage: $0 {build|rowdot --out <new.json> [--forks 5]|vectors <out.json>|crossverify <in.json> <out.json>|bench|stages|memory --out <file.jsonl> [opts]|validate <suite.json.gz> <out.json>}" >&2; exit 2 ;;
esac
