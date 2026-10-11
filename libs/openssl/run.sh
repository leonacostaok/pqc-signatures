#!/usr/bin/env bash
# OpenSSL 3.5 (native ML-DSA / SLH-DSA providers) harness entry point.
# See common/CONTRACT.md. Everything is kept inside libs/openssl/{deps,build}.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DEPS="$HERE/deps"
SRC="$DEPS/openssl"
BUILD="$HERE/build"
BIN="$BUILD/bin"
VECTORS="$ROOT/common/vectors.json"
REFERENCE="$ROOT/common/reference.json"

OPENSSL_TAG="${OPENSSL_TAG:-openssl-3.5.9}"
JOBS="${JOBS:-2}"
CC="${CC:-gcc}"

# Three libcrypto flavours; each gets its own statically linked driver binary.
#   default : stock Configure (asm on, -O3)
#   noasm   : no-asm (pure C Keccak / SHA-2)
#   native  : -O3 -march=native -flto
FLAVOURS="default noasm native"
COMMON_OPTS="--libdir=lib no-shared no-tests no-apps no-docs no-engine no-legacy no-dso no-module no-comp no-zlib no-dtls no-ssl3"

flavour_opts() {
  case "$1" in
    default) echo "" ;;
    noasm)   echo "no-asm" ;;
    native)  echo "-O3 -march=native -flto -ffat-lto-objects" ;;
  esac
}
driver_cflags() {
  case "$1" in
    native) echo "-O3 -march=native -flto -w" ;;
    *)      echo "-O2" ;;
  esac
}

fetch() {
  if [ ! -f "$SRC/Configure" ]; then
    mkdir -p "$DEPS"
    git clone --depth 1 --branch "$OPENSSL_TAG" https://github.com/openssl/openssl "$SRC"
  fi
}

build_flavour() {
  local f="$1" obj="$BUILD/obj-$f" prefix="$BUILD/$f"
  if [ -f "$prefix/lib/libcrypto.a" ]; then
    echo "[openssl] $f: libcrypto.a present, skipping"
    return
  fi
  echo "[openssl] configuring $f"
  mkdir -p "$obj"
  ( cd "$obj" && perl "$SRC/Configure" linux-x86_64 --prefix="$prefix" $COMMON_OPTS $(flavour_opts "$f") > conf.log 2>&1 )
  echo "[openssl] building $f (-j$JOBS)"
  ( cd "$obj" && make -j"$JOBS" build_libs > build.log 2>&1 && make install_dev >> build.log 2>&1 ) \
    || { tail -n 30 "$obj/build.log"; echo "build of $f failed"; exit 1; }
}

build_driver() {
  local f="$1" prefix="$BUILD/$f" cflags
  cflags="$(driver_cflags "$f")"
  mkdir -p "$BIN"
  if [ -f "$BIN/pqc_driver_$f" ] && [ "$BIN/pqc_driver_$f" -nt "$HERE/src/pqc_driver.c" ] \
     && [ "$BIN/pqc_driver_$f" -nt "$prefix/lib/libcrypto.a" ]; then
    return
  fi
  echo "[openssl] compiling driver for $f"
  $CC $cflags -Wall -Wextra -Wno-unused-parameter -DBUILD_LABEL="\"$f\"" -DDRIVER_CFLAGS="\"$cflags\"" \
    -I"$prefix/include" "$HERE/src/pqc_driver.c" -o "$BIN/pqc_driver_$f" \
    "$prefix/lib/libcrypto.a" -lpthread -ldl
}

cmd_build() {
  fetch
  for f in $FLAVOURS; do build_flavour "$f"; done
  for f in $FLAVOURS; do build_driver "$f"; done
  echo "[openssl] build complete: $("$BIN/pqc_driver_default" version)"
}

need_build() {
  for f in $FLAVOURS; do
    [ -x "$BIN/pqc_driver_$f" ] || { echo "run '$0 build' first" >&2; exit 1; }
  done
}

case "${1:-}" in
  build)
    cmd_build ;;
  vectors)
    [ $# -eq 2 ] || { echo "usage: $0 vectors <out.json>" >&2; exit 2; }
    need_build
    mkdir -p "$(dirname "$2")"
    "$BIN/pqc_driver_default" vectors "$VECTORS" "$REFERENCE" "$2" ;;
  crossverify)
    [ $# -eq 3 ] || { echo "usage: $0 crossverify <artifacts.json> <out.json>" >&2; exit 2; }
    need_build
    mkdir -p "$(dirname "$3")"
    "$BIN/pqc_driver_default" crossverify "$VECTORS" "$2" "$3" ;;
  bench)
    shift
    need_build
    OUT=""; ARGS=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --budget-ms|--params|--ops|--variants) ARGS+=("$1" "$2"); shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
      esac
    done
    [ -n "$OUT" ] || { echo "usage: $0 bench --out <file.jsonl> [--budget-ms N] [--params a,b] [--ops ..] [--variants ..]" >&2; exit 2; }
    mkdir -p "$(dirname "$OUT")"
    # each binary only runs the variants that belong to its build flavour
    rc=0
    for f in $FLAVOURS; do
      "$BIN/pqc_driver_$f" bench "$VECTORS" "$REFERENCE" --out "$OUT" "${ARGS[@]}" || rc=1
    done
    exit $rc ;;
  list)
    need_build
    "$BIN/pqc_driver_default" list ;;
  *)
    echo "usage: $0 {build|vectors <out.json>|crossverify <artifacts.json> <out.json>|bench --out <f.jsonl> [...]|list}" >&2
    exit 2 ;;
esac
