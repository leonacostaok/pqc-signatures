#!/usr/bin/env bash
# RustCrypto (ml-dsa + slh-dsa) harness entry point. See common/CONTRACT.md.
#   run.sh build
#   run.sh vectors <out.json>
#   run.sh crossverify <artifacts.json> <out.json>
#   run.sh bench --out <file.jsonl> [--budget-ms N] [--params a,b] [--ops a,b] [--variants a,b]
#   run.sh validate <common/validation/validation.json.gz> <out.json>     (Phase 2 A)
#   run.sh stages --out <file.jsonl> [--budget-ms N] [--params a,b] [--stages x,y]   (Phase 2 B)
#   run.sh memory --out <file.jsonl> [--params a,b]                       (Phase 2 C)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export PQC_COMMON_DIR="$ROOT/common"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"   # 4 shared cores; be polite
export CARGO_TERM_COLOR=never
# Never cd: paths given by the caller (--out, artifacts) stay relative to the caller's cwd.

# One binary per build configuration: tag -> cargo profile, RUSTFLAGS, extra cargo args.
# Every tag gets its own target dir so changing RUSTFLAGS never invalidates another build.
NATIVE="-C target-cpu=native"
PGO_DIR="$HERE/target/pgo-data"
LLVM_BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
PROFDATA="$LLVM_BIN/llvm-profdata"
[ -x "$PROFDATA" ] || PROFDATA="$(command -v llvm-profdata || true)"

bin_of() { # tag -> path of the built binary
  case "$1" in
    base|native|mimalloc) echo "$HERE/target/$1/release/pqcbench" ;;
    *) echo "$HERE/target/$1/lto/pqcbench" ;;
  esac
}

build_tag() { # tag profile rustflags [extra cargo args...]
  local tag="$1" profile="$2" flags="$3"; shift 3
  echo ">> build [$tag] profile=$profile RUSTFLAGS='$flags' $*"
  PQC_BUILD_TAG="$tag" RUSTFLAGS="$flags" cargo build --quiet --manifest-path "$HERE/Cargo.toml" --profile "$profile" --target-dir "$HERE/target/$tag" "$@"
}

newest_src() { stat -c %Y "$HERE"/Cargo.toml "$HERE"/Cargo.lock "$HERE"/build.rs "$HERE"/src/*.rs 2>/dev/null | sort -n | tail -1; }
up_to_date() { [ -x "$1" ] && [ "$(stat -c %Y "$1")" -ge "$(newest_src)" ]; }

cmd_build() {
  cargo fetch --quiet --manifest-path "$HERE/Cargo.toml"
  build_tag base     release ""
  build_tag native   release "$NATIVE"
  build_tag lto      lto     ""
  build_tag mimalloc release "" --features mimalloc

  # PGO: one instrumented binary (native + fat LTO), trained separately per process, then one
  # optimised binary per process. Skipped when the final binaries are newer than the sources.
  local need=0 op
  for op in keygen sign verify; do up_to_date "$(bin_of pgo-$op)" || need=1; done
  if [ "$need" = 1 ]; then
    if [ -z "$PROFDATA" ] || [ ! -x "$PROFDATA" ]; then
      echo "!! llvm-profdata not found (rustup component add llvm-tools); PGO variants fall back to native+LTO without a profile"
      for op in keygen sign verify; do build_tag "pgo-$op" lto "$NATIVE"; done
      return
    fi
    rm -rf "$PGO_DIR"; mkdir -p "$PGO_DIR"
    build_tag pgo-gen lto "$NATIVE -C profile-generate=$PGO_DIR/raw"
    for op in keygen sign verify; do
      echo ">> PGO training [$op]"
      mkdir -p "$PGO_DIR/raw-$op"
      LLVM_PROFILE_FILE="$PGO_DIR/raw-$op/%p-%m.profraw" \
        "$(bin_of pgo-gen)" bench --out /dev/null --budget-ms 150 --ops "$op" --variants "$op.v3" 2>/dev/null
      "$PROFDATA" merge -o "$PGO_DIR/$op.profdata" "$PGO_DIR/raw-$op"/*.profraw
      build_tag "pgo-$op" lto "$NATIVE -C profile-use=$PGO_DIR/$op.profdata"
    done
  fi
  echo ">> build done:"; for t in base native lto mimalloc pgo-keygen pgo-sign pgo-verify; do "$(bin_of $t)" info; done
}

ensure_built() { up_to_date "$(bin_of base)" || cmd_build; }

case "${1:-}" in
  build) cmd_build ;;
  vectors)     ensure_built; "$(bin_of base)" vectors "$2" ;;
  crossverify) ensure_built; "$(bin_of base)" crossverify "$2" "$3" ;;
  validate)
    ensure_built; in="$2"; out="$3"; shift 3
    tmpd="$(mktemp -d "$HERE/target/validate.XXXXXX")"; parts=()
    for t in base native lto mimalloc pgo-keygen pgo-sign pgo-verify; do
      "$(bin_of $t)" validate "$in" "$tmpd/$t.json" "$@"; parts+=("$tmpd/$t.json")
    done
    mkdir -p "$(dirname "$out")"; "$(bin_of base)" validate-merge "$out" "${parts[@]}"; rm -rf "$tmpd"
    ;;
  stages)
    shift; ensure_built
    out=""; args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do [ "${args[$i]}" = "--out" ] && out="${args[$((i+1))]}"; done
    [ -n "$out" ] || { echo "stages: --out required" >&2; exit 2; }
    mkdir -p "$(dirname "$out")"; : > "$out"
    for t in base native lto pgo-verify; do "$(bin_of $t)" stages "${args[@]}"; done
    echo ">> $(wc -l < "$out") lines written to $out"
    ;;
  memory)
    shift; ensure_built
    out=""; args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do [ "${args[$i]}" = "--out" ] && out="${args[$((i+1))]}"; done
    [ -n "$out" ] || { echo "memory: --out required" >&2; exit 2; }
    mkdir -p "$(dirname "$out")"; : > "$out"
    for t in base native lto mimalloc pgo-keygen pgo-sign pgo-verify; do "$(bin_of $t)" memory "${args[@]}"; done
    echo ">> $(wc -l < "$out") lines written to $out"
    ;;
  bench)
    shift; ensure_built
    out=""; args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do [ "${args[$i]}" = "--out" ] && out="${args[$((i+1))]}"; done
    [ -n "$out" ] || { echo "bench: --out required" >&2; exit 2; }
    mkdir -p "$(dirname "$out")"; : > "$out"   # fresh file; every binary appends its variants
    for t in base native lto mimalloc pgo-keygen pgo-sign pgo-verify; do
      b="$(bin_of $t)"
      [ -x "$b" ] || { echo "missing binary for $t (run build)" >&2; exit 1; }
      "$b" bench "${args[@]}"
    done
    echo ">> $(wc -l < "$out") lines written to $out"
    ;;
  *) echo "usage: $0 build | vectors <out.json> | crossverify <in.json> <out.json> | bench --out <f.jsonl> [--budget-ms N] [--params a,b] [--ops a,b] [--variants a,b] | validate <suite.json.gz> <out.json> [--params a,b] [--kinds a,b] [--variants a,b] | stages --out <f.jsonl> [--budget-ms N] [--params a,b] [--stages a,b] [--variants a,b] | memory --out <f.jsonl> [--params a,b]" >&2; exit 2 ;;
esac
