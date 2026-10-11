#!/usr/bin/env bash
# CIRCL (Go) harness entry point. See common/CONTRACT.md.
#   run.sh build
#   run.sh vectors <out.json>
#   run.sh crossverify <artifacts.json> <out.json>
#   run.sh bench --out <file.jsonl> [--budget-ms N] [--params a,b] [--ops k,s,v] [--variants id,id]
#   run.sh validate <validation.json.gz> <out.json>          (phase 2)
#   run.sh stages --out <file.jsonl> [--budget-ms N] [--params a,b] [--stages x,y]   (phase 2)
#   run.sh memory --out <file.jsonl> [--params a,b]           (phase 2)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMMON="$ROOT/common"
BUILD="$HERE/build"
FLAVORS="default purego amd64v3 pgo"
export GOFLAGS=-mod=mod GOTOOLCHAIN=auto
# Note: commands run from the caller's cwd (relative paths in arguments stay valid);
# only the Go build steps run inside the module directory.

build() (
  cd "$HERE"
  mkdir -p "$BUILD"
  go mod download
  echo "go: $(go version)"
  # stages_ml65.go / stages_ml87.go are generated from the ML-DSA-44 template
  for m in 65 87; do
    sed -e "s/mldsa44i/mldsa${m}i/g" -e "s/mlStages44/mlStages${m}/g" -e "s/newMLStages44/newMLStages${m}/g" \
        -e "s/stages_ml44.go is the source/generated from stages_ml44.go (do not edit)/" \
        cmd/pqcbench/stages_ml44.go > cmd/pqcbench/stages_ml${m}.go
  done
  go build -o "$BUILD/pqcbench-default" -ldflags "-X main.flavor=default" ./cmd/pqcbench
  go build -tags purego -o "$BUILD/pqcbench-purego" -ldflags "-X main.flavor=purego" ./cmd/pqcbench
  GOAMD64=v3 go build -o "$BUILD/pqcbench-amd64v3" -ldflags "-X main.flavor=amd64v3" ./cmd/pqcbench
  if [ ! -s "$BUILD/default.pgo" ]; then
    echo "collecting CPU profile for PGO (one-time) ..."
    "$BUILD/pqcbench-default" profile --common "$COMMON" --out "$BUILD/default.pgo" --ms 150
  fi
  go build -pgo="$BUILD/default.pgo" -o "$BUILD/pqcbench-pgo" -ldflags "-X main.flavor=pgo" ./cmd/pqcbench
  echo "built: $(ls "$BUILD")"
)

need_build() {
  for f in $FLAVORS; do [ -x "$BUILD/pqcbench-$f" ] || { build >&2; return; }; done
}

cmd="${1:-}"; shift || true
case "$cmd" in
  build) build ;;
  vectors)
    need_build
    "$BUILD/pqcbench-default" vectors --common "$COMMON" --out "${1:?out.json}" ;;
  crossverify)
    need_build
    "$BUILD/pqcbench-default" crossverify --common "$COMMON" --in "${1:?artifacts.json}" --out "${2:?out.json}" ;;
  validate)
    need_build
    "$BUILD/pqcbench-default" validate --suite "${1:?validation.json.gz}" --out "${2:?out.json}" --bindir "$BUILD" ;;
  stages|memory)
    need_build
    out=""; prev=""
    for a in "$@"; do [ "$prev" = "--out" ] && out="$a"; prev="$a"; done
    [ -n "$out" ] || { echo "$cmd: --out required" >&2; exit 2; }
    mkdir -p "$(dirname "$out")"; : > "$out"
    # memory: no async preemption so no asyncPreempt frame lands on the painted stack
    [ "$cmd" = memory ] && export GODEBUG=asyncpreemptoff=1
    for f in $FLAVORS; do "$BUILD/pqcbench-$f" "$cmd" --common "$COMMON" "$@"; done ;;
  bench)
    need_build
    # find --out so we can truncate it once; every flavor binary then appends its own lines
    out=""; prev=""
    for a in "$@"; do [ "$prev" = "--out" ] && out="$a"; prev="$a"; done
    [ -n "$out" ] || { echo "bench: --out required" >&2; exit 2; }
    mkdir -p "$(dirname "$out")"; : > "$out"
    for f in $FLAVORS; do "$BUILD/pqcbench-$f" bench --common "$COMMON" "$@"; done ;;
  *) echo "usage: $0 {build|vectors <out>|crossverify <in> <out>|bench --out <file> [...]|validate <suite> <out>|stages --out <file> [...]|memory --out <file> [...]}" >&2; exit 2 ;;
esac
