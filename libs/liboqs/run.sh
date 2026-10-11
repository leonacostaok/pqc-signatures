#!/usr/bin/env bash
# liboqs harness for the pqc-signatures benchmark (see common/CONTRACT.md).
#
#   run.sh build
#   run.sh vectors <out.json>
#   run.sh crossverify <artifacts.json> <out.json>
#   run.sh bench --out <file.jsonl> [--budget-ms N] [--params a,b] [--ops keygen,sign,verify] [--variants id,id]
#
# Everything lives under libs/liboqs/: deps/liboqs (git checkout, pinned tag),
# build/<name>/ (one liboqs build + one driver binary per build flavour).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DEPS="$HERE/deps/liboqs"
BUILD="$HERE/build"
SRC="$HERE/src"
LIBOQS_TAG="0.16.0"
LIBOQS_REPO="https://github.com/open-quantum-safe/liboqs"
JOBS="${JOBS:-2}"
PY="python3 -I"

ALGS="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_falcon_512;SIG_falcon_1024"
for h in sha2 shake; do for s in 128s 128f 192s 192f 256s 256f; do ALGS="$ALGS;SIG_slh_dsa_pure_${h}_${s}"; done; done

CMAKE_COMMON=(-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON "-DOQS_MINIMAL_BUILD=$ALGS")
NATIVE=(-DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto)

# ---------------------------------------------------------------------------
# variant table: id|build|path|threads|name|description
# ---------------------------------------------------------------------------
VARIANTS=(
"keygen.v0|dist|api|1|baseline|Default liboqs 0.16.0 build (OQS_DIST_BUILD=ON, gcc 13 -O3, run-time AVX2 dispatch); OQS_SIG_keypair with the seed supplied through OQS_randombytes_custom_algorithm."
"keygen.v1|dist|direct|1|internal-seeded|Calls the vendored seeded keygen functions directly (mld_sign_keypair_internal(seed) / slh_keygen_internal(SK.seed,SK.prf,PK.seed)): no OQS_SIG dispatcher, no RNG callback, no per-call CPU-feature check."
"keygen.v2|native|api|1|march-native|liboqs built with OQS_DIST_BUILD=OFF and OQS_OPT_TARGET=auto (-march=native): all C code tuned for this CPU, AVX2/BMI2 backend bound at compile time, plus the AVX512VL SHA-3 callbacks re-selected at run time (non-dist builds otherwise drop them)."
"keygen.v3|clang|api|1|clang-native|Same -march=native non-dist configuration (AVX512VL SHA-3 callbacks re-selected) compiled with clang 18 instead of gcc 13 (different vectoriser and scheduler for the portable hash/polynomial C code)."
"keygen.v4|pgo|api|1|gcc-pgo|gcc profile-guided optimisation on the -march=native build (AVX512VL SHA-3 callbacks re-selected): -fprofile-generate, a training run over every param/op, then rebuild with -fprofile-use."
"keygen.v5|dist|api|4|pthread-x4|Baseline build; four pthreads generate keys concurrently from the same seed (batch throughput, wall per op = batch wall / batch size)."
"sign.v0|dist|api|1|baseline|Default liboqs build; OQS_SIG_sign with rnd = 0^32 (ML-DSA) / opt_rand = PK.seed (SLH-DSA) supplied through OQS_randombytes_custom_algorithm (FIPS deterministic variants)."
"sign.v1|dist|direct|1|internal-deterministic|Calls mld_sign_signature_internal with an all-zero rnd and slh_sign with addrnd = NULL directly: the standard deterministic variants without the dispatcher, the RNG callback or the per-call CPU check."
"sign.v2|native|api|1|march-native|liboqs built with OQS_DIST_BUILD=OFF, OQS_OPT_TARGET=auto (-march=native, compile-time AVX2 selection, AVX512VL SHA-3 callbacks re-selected at run time)."
"sign.v3|fasthash|api|1|fasthash|liboqs patched so slhdsa-c's private hash core uses OpenSSL's assembly SHA-256/SHA-512 block functions and liboqs's own AVX2 XKCP Keccak-f[1600] instead of its portable C versions (ML-DSA/Falcon unchanged)."
"sign.v4|pgo|api|1|gcc-pgo|gcc profile-guided optimisation (-fprofile-generate, training run, -fprofile-use) on top of -march=native, AVX512VL SHA-3 callbacks re-selected."
"sign.v5|dist|api|4|pthread-x4|Baseline build; four pthreads sign the same message concurrently (batch throughput)."
"verify.v0|dist|api|1|baseline|Default liboqs build; OQS_SIG_verify through the OQS_SIG dispatcher."
"verify.v1|dist|direct|1|internal-direct|mld_sign_verify_internal / slh_verify called directly, bypassing the OQS_SIG function-pointer dispatch and the per-call CPU-feature check."
"verify.v2|lto|api|1|gcc-lto|-march=native build with CMAKE_INTERPROCEDURAL_OPTIMIZATION=ON (gcc -flto) for liboqs and the driver (cross-module inlining of the hash and NTT helpers), AVX512VL SHA-3 callbacks re-selected."
"verify.v3|clang|api|1|clang-native|-march=native non-dist build compiled with clang 18 instead of gcc 13, AVX512VL SHA-3 callbacks re-selected."
"verify.v4|fasthash|api|1|fasthash|liboqs patched so SLH-DSA hashing uses OpenSSL SHA-2 block functions and liboqs's AVX2 Keccak permutation (ML-DSA/Falcon unchanged)."
"verify.v5|dist|api|4|pthread-x4|Baseline build; four pthreads verify the same signature concurrently (batch throughput)."
)

BUILDS=(dist native clang lto pgo fasthash)

log() { echo "[liboqs] $*" >&2; }

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
fetch_deps() {
  if [ ! -d "$DEPS/.git" ]; then
    log "cloning liboqs"
    mkdir -p "$HERE/deps"
    git clone -q "$LIBOQS_REPO" "$DEPS"
  fi
  if [ "$(git -C "$DEPS" describe --tags --exact-match 2>/dev/null || true)" != "$LIBOQS_TAG" ]; then
    git -C "$DEPS" fetch -q --tags origin || true
    git -C "$DEPS" checkout -q "$LIBOQS_TAG"
  fi
  # patched source tree for the "fasthash" flavour (git worktree + patch)
  if [ ! -f "$BUILD/src-fasthash/src/sig/slh_dsa/slh_dsa_c/slh_fasthash.c" ]; then
    log "preparing patched source tree (fasthash)"
    rm -rf "$BUILD/src-fasthash"
    git -C "$DEPS" worktree prune
    git -C "$DEPS" worktree add -q --detach "$BUILD/src-fasthash" "$LIBOQS_TAG"
    git -C "$BUILD/src-fasthash" apply "$HERE/patches/slh-fasthash.patch"
  fi
}

driver_cc() { # <build> <cc> <flags...>
  local b="$1" cc="$2"; shift 2
  "$cc" "$@" -Wall -o "$BUILD/$b/bench" "$SRC/bench.c" -I"$BUILD/$b/include" "$BUILD/$b/lib/liboqs.a" -lcrypto -lpthread
}

cmake_build() { # <build> <srcdir> <cmake args...>
  local b="$1" src="$2"; shift 2
  mkdir -p "$BUILD/$b"
  cmake -S "$src" -B "$BUILD/$b" "${CMAKE_COMMON[@]}" "$@" > "$BUILD/$b/cmake.log" 2>&1 || { tail -30 "$BUILD/$b/cmake.log" >&2; exit 1; }
  cmake --build "$BUILD/$b" -j"$JOBS" > "$BUILD/$b/build.log" 2>&1 || { tail -30 "$BUILD/$b/build.log" >&2; exit 1; }
}

build_one() {
  local b="$1"
  if [ -f "$BUILD/$b/.done" ] && [ "$BUILD/$b/bench" -nt "$SRC/bench.c" ] && [ "$BUILD/$b/bench" -nt "$HERE/run.sh" ]; then
    return
  fi
  rm -f "$BUILD/$b/.done"
  log "building flavour '$b'"
  case "$b" in
    dist)
      cmake_build dist "$DEPS"
      driver_cc dist gcc -O2 ;;
    native)
      cmake_build native "$DEPS" "${NATIVE[@]}"
      driver_cc native gcc -O3 -march=native ;;
    clang)
      cmake_build clang "$DEPS" "${NATIVE[@]}" -DCMAKE_C_COMPILER=clang
      driver_cc clang clang -O3 -march=native ;;
    lto)
      cmake_build lto "$DEPS" "${NATIVE[@]}" -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON
      driver_cc lto gcc -O3 -march=native -flto ;;
    fasthash)
      cmake_build fasthash "$BUILD/src-fasthash"
      driver_cc fasthash gcc -O2 ;;
    pgo)
      local pdir="$BUILD/pgo/profile"
      rm -rf "$pdir"; mkdir -p "$pdir"
      # stage 1: instrumented library + driver
      cmake_build pgo "$DEPS" "${NATIVE[@]}" "-DCMAKE_C_FLAGS=-fprofile-generate=$pdir -fprofile-update=atomic"
      driver_cc pgo gcc -O3 -march=native "-fprofile-generate=$pdir" -fprofile-update=atomic
      # stage 2: training run (all params, all ops, both API paths), outputs discarded
      make_spec
      log "pgo: training run"
      "$BUILD/pgo/bench" vectors "$BUILD/spec.txt" > /dev/null
      "$BUILD/pgo/bench" bench "$BUILD/spec.txt" --budget-ms 100 --path api > /dev/null
      "$BUILD/pgo/bench" bench "$BUILD/spec.txt" --budget-ms 50 --path direct --params ML-DSA-44,ML-DSA-65,ML-DSA-87,SLH-DSA-SHA2-128f,SLH-DSA-SHAKE-128f > /dev/null
      # stage 3: rebuild with the profile
      cmake_build pgo "$DEPS" "${NATIVE[@]}" "-DCMAKE_C_FLAGS=-fprofile-use=$pdir -fprofile-correction -Wno-missing-profile"
      driver_cc pgo gcc -O3 -march=native "-fprofile-use=$pdir" -fprofile-correction -Wno-missing-profile ;;
    *) log "unknown build $b"; exit 1 ;;
  esac
  touch "$BUILD/$b/.done"
}

cmd_build() {
  fetch_deps
  mkdir -p "$BUILD"
  for b in "${BUILDS[@]}"; do build_one "$b"; done
  make_spec
  log "build complete: ${BUILDS[*]}"
}

make_spec() {
  mkdir -p "$BUILD"
  $PY "$SRC/glue.py" spec "$ROOT/common/vectors.json" "$ROOT/common/reference.json" "$BUILD/spec.txt"
}

need_build() { [ -x "$BUILD/dist/bench" ] || cmd_build; make_spec; }

# ---------------------------------------------------------------------------
# vectors / crossverify
# ---------------------------------------------------------------------------
cmd_vectors() {
  local out="$1"; need_build
  "$BUILD/dist/bench" vectors "$BUILD/spec.txt" > "$BUILD/vectors.txt"
  $PY "$SRC/glue.py" vectors-json "$LIBOQS_TAG" "$BUILD/vectors.txt" "$out"
}

cmd_crossverify() {
  local in="$1" out="$2"; need_build
  local source
  source="$($PY "$SRC/glue.py" entries-flat "$in" "$BUILD/entries.txt")"
  "$BUILD/dist/bench" crossverify "$BUILD/spec.txt" "$BUILD/entries.txt" > "$BUILD/crossverify.txt"
  $PY "$SRC/glue.py" crossverify-json "$source" "$BUILD/crossverify.txt" "$out"
}

# ---------------------------------------------------------------------------
# bench
# ---------------------------------------------------------------------------
in_csv() { local list="$1" item="$2"; [ -z "$list" ] && return 0; [[ ",$list," == *",$item,"* ]]; }

cmd_bench() {
  local out="" budget=1000 params="" ops="" variants=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --budget-ms) budget="$2"; shift 2 ;;
      --params) params="$2"; shift 2 ;;
      --ops) ops="$2"; shift 2 ;;
      --variants) variants="$2"; shift 2 ;;
      *) log "unknown bench option $1"; exit 2 ;;
    esac
  done
  [ -n "$out" ] || { log "--out required"; exit 2; }
  need_build
  mkdir -p "$(dirname "$out")"
  : > "$out"
  local gccv clangv
  gccv="$(gcc -dumpfullversion)"; clangv="$(clang --version | head -1 | sed 's/.*version \([0-9.]*\).*/\1/')"
  for v in "${VARIANTS[@]}"; do
    IFS='|' read -r id b path threads name desc <<< "$v"
    local op="${id%%.*}"
    in_csv "$ops" "$op" || continue
    in_csv "$variants" "$id" || continue
    local cc="gcc $gccv"; [ "$b" = clang ] && cc="clang $clangv"
    local args=()
    case "$b" in native|clang|lto|pgo) args+=(--sha3 avx512vl) ;; esac
    args+=(--budget-ms "$budget" --path "$path" --threads "$threads" --variant "$id" --variant-name "$name" --variant-desc "$desc" --ops "$op" --runtime "liboqs $LIBOQS_TAG static, $cc, flavour=$b")
    [ -n "$params" ] && args+=(--params "$params")
    log "bench $id ($b/$path/t$threads)"
    "$BUILD/$b/bench" bench "$BUILD/spec.txt" "${args[@]}" >> "$out"
  done
  log "wrote $out ($(wc -l < "$out") lines)"
}

case "${1:-}" in
  build) cmd_build ;;
  vectors) cmd_vectors "$2" ;;
  crossverify) cmd_crossverify "$2" "$3" ;;
  bench) shift; cmd_bench "$@" ;;
  *) echo "usage: $0 build | vectors <out.json> | crossverify <in.json> <out.json> | bench --out <f.jsonl> [--budget-ms N] [--params a,b] [--ops a,b] [--variants a,b]" >&2; exit 2 ;;
esac
