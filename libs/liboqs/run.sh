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
  local src="$DEPS"; [ "$b" = fasthash ] && src="$BUILD/src-fasthash"
  local inc=(-I"$BUILD/$b/include" -I"$SRC")
  local obj="$BUILD/$b/obj"; mkdir -p "$obj"
  local objs=()
  "$cc" "$@" -Wall -c -o "$obj/bench.o" "$SRC/bench.c" "${inc[@]}" || exit 1
  "$cc" "$@" -c -o "$obj/memhook.o" "$SRC/memhook.c" || exit 1
  # slhdsa-c internals: compile the vendored slh_dsa.c into the driver with its globals renamed
  local ren=(-Dslh_alg_id=stg_slh_alg_id -Dslh_pk_sz=stg_slh_pk_sz -Dslh_sk_sz=stg_slh_sk_sz -Dslh_sig_sz=stg_slh_sig_sz
             -Dslh_keygen_internal=stg_slh_keygen_internal -Dslh_keygen=stg_slh_keygen -Dslh_sign_internal=stg_slh_sign_internal
             -Dslh_sign=stg_slh_sign -Dslh_verify_internal=stg_slh_verify_internal -Dslh_verify=stg_slh_verify)
  "$cc" "$@" -Wno-unused-function -c -o "$obj/stages_slh.o" "$SRC/stages_slh.c" "${inc[@]}" \
    -I"$src/src/sig/slh_dsa/slh_dsa_c" "-DSLH_DSA_C_SOURCE=\"$src/src/sig/slh_dsa/slh_dsa_c/slh_dsa.c\"" "${ren[@]}" || exit 1
  objs=("$obj/bench.o" "$obj/memhook.o" "$obj/stages_slh.o")
  # mldsa-native internals: one unit per (param set, backend) with liboqs's own flags
  local nn be
  for nn in 44 65 87; do
    for be in c x86_64; do
      local short=c extra=() cfg=config_c.h dir=ref
      if [ "$be" = x86_64 ]; then short=x86; extra=(-mavx2 -mbmi2 -mpopcnt); cfg=config_x86_64.h; dir=x86_64; fi
      "$cc" "$@" -std=gnu11 -Wno-unused-function -c -o "$obj/stages_mldsa_${nn}_${short}.o" "$SRC/stages_mldsa.c" "${inc[@]}" \
        -I"$src/src/sig/ml_dsa/mldsa-native_ml-dsa-${nn}_${dir}" -I"$src/src/common/pqclean_shims" "${extra[@]}" \
        -DMLD_CONFIG_PARAMETER_SET=$nn "-DMLD_CONFIG_FILE=\"../../integration/liboqs/$cfg\"" \
        -DSTG_NAME=stg_mldsa_${nn}_${short} "-DSTG_BACKEND_NAME=\"$be\"" || exit 1
      objs+=("$obj/stages_mldsa_${nn}_${short}.o")
    done
  done
  "$cc" "$@" -o "$BUILD/$b/bench" "${objs[@]}" "$BUILD/$b/lib/liboqs.a" -lcrypto -lpthread || exit 1
}

cmake_build() { # <build> <srcdir> <cmake args...>
  local b="$1" src="$2"; shift 2
  mkdir -p "$BUILD/$b"
  cmake -S "$src" -B "$BUILD/$b" "${CMAKE_COMMON[@]}" "$@" > "$BUILD/$b/cmake.log" 2>&1 || { tail -30 "$BUILD/$b/cmake.log" >&2; exit 1; }
  cmake --build "$BUILD/$b" -j"$JOBS" > "$BUILD/$b/build.log" 2>&1 || { tail -30 "$BUILD/$b/build.log" >&2; exit 1; }
}

build_one() {
  local b="$1"
  if [ -f "$BUILD/$b/.done" ] && [ "$BUILD/$b/bench" -nt "$SRC/bench.c" ] && [ "$BUILD/$b/bench" -nt "$HERE/run.sh" ] \
     && [ "$BUILD/$b/bench" -nt "$SRC/stages_mldsa.c" ] && [ "$BUILD/$b/bench" -nt "$SRC/stages_slh.c" ] && [ "$BUILD/$b/bench" -nt "$SRC/memhook.c" ]; then
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


# ---------------------------------------------------------------------------
# verify-stage variants: id|family|build|mode|sha3|name|description
#   mode tokens: c (portable C backend), ossl (OpenSSL SHAKE), cached (tr / A / NTT(t1*2^d) cache), oneway (1-way SHAKE128)
#   sha3: avx512vl = re-select liboqs's AVX512VL Keccak in non-dist builds, none = keep what the build dispatches
# ---------------------------------------------------------------------------
STAGE_VARIANTS=(
"decode.v0|ml-dsa|dist|-|-|lib-x86_64|liboqs mldsa-native x86_64 backend: mld_polyvecl_unpack_z (AVX2 polyz_unpack), mld_unpack_pk_t1, mld_sig_unpack_hints (hint validity check)."
"decode.v1|ml-dsa|dist|c|-|lib-c|Same functions from the portable C backend objects of the same library (compiled generic x86-64, no AVX2 unpacking)."
"decode.v2|ml-dsa|native|-|avx512vl|march-native|x86_64 backend from the OQS_DIST_BUILD=OFF -march=native build."
"decode.v3|ml-dsa|clang|-|avx512vl|clang-native|x86_64 backend from the clang 18 -march=native build."
"decode.v4|ml-dsa|pgo|-|avx512vl|gcc-pgo|x86_64 backend from the profile-guided build."
"decode.v5|ml-dsa|lto|-|avx512vl|gcc-lto|x86_64 backend from the -flto build (driver linked with -flto)."
"mu.v0|ml-dsa|dist|-|-|lib-shake|tr = SHAKE256(pk, 64), mu = SHAKE256(tr || 0 || |ctx| || ctx || M, 64) with liboqs's incremental SHAKE256 (XKCP, AVX512VL on this CPU), exactly as mld_H in sign.c."
"mu.v1|ml-dsa|dist|ossl|-|openssl-shake|Both SHAKE256 calls through OpenSSL 3 EVP (EVP_shake256 + DigestFinalXOF) instead of liboqs's XKCP."
"mu.v2|ml-dsa|dist|cached|-|cached-tr|tr = H(pk) cached per public key (pk compared bytewise on every call); only mu = H(tr, M') is recomputed."
"mu.v3|ml-dsa|native|-|none|xkcp-avx2|Non-dist build without the AVX512VL re-selection: liboqs's XKCP AVX2 Keccak instead of the AVX512VL one."
"mu.v4|ml-dsa|pgo|-|avx512vl|gcc-pgo|Profile-guided -march=native build."
"mu.v5|ml-dsa|clang|-|avx512vl|clang-native|clang 18 -march=native build."
"expandA.v0|ml-dsa|dist|-|-|lib-4way|mld_polyvec_matrix_expand: 4-way SHAKE128 (XKCP times4, AVX512VL here) + AVX2 rejection sampler, output in the backend's NTT lane order (undone for the canonical hash)."
"expandA.v1|ml-dsa|dist|c|-|lib-c|Portable C backend: same 4-way Keccak but the C rejection sampler (no AVX2 rej_uniform)."
"expandA.v2|ml-dsa|dist|oneway|-|oneway-shake|One SHAKE128 stream per matrix entry (mld_poly_uniform, nonce = i<<8|j) instead of 4 interleaved streams, then the backend's lane permutation."
"expandA.v3|ml-dsa|dist|cached|-|cached-A|A^ cached per public key (rho compared on every call) and copied into the working state: measures the floor of a key-cached verifier."
"expandA.v4|ml-dsa|native|-|none|xkcp-avx2-x4|Non-dist build without AVX512VL re-selection: XKCP AVX2 times4 Keccak for the 4-way expansion."
"expandA.v5|ml-dsa|pgo|-|avx512vl|gcc-pgo|Profile-guided -march=native build."
"w_approx.v0|ml-dsa|dist|-|-|lib-x86_64|NTT(z), SampleInBall + NTT(c), per row: A^_i o z^ (AVX2 pointwise-acc asm), NTT(t1_i 2^d), c^ o t1^, sub, invNTT (AVX2 asm), caddq; as in mld_sign_verify_internal."
"w_approx.v1|ml-dsa|dist|c|-|lib-c|Same sequence from the portable C backend (C NTT / invNTT / pointwise Montgomery)."
"w_approx.v2|ml-dsa|dist|cached|-|cached-t1hat|NTT(t1 * 2^d) precomputed and cached per public key; the stage only does NTT(z), NTT(c), the row products, subtraction and invNTT."
"w_approx.v3|ml-dsa|native|-|avx512vl|march-native|x86_64 backend from the -march=native build."
"w_approx.v4|ml-dsa|lto|-|avx512vl|gcc-lto|-flto build."
"w_approx.v5|ml-dsa|clang|-|avx512vl|clang-native|clang 18 build."
"hint_check.v0|ml-dsa|dist|-|-|lib-x86_64|||z||inf check, UseHint (AVX2 poly_use_hint), w1Encode (polyw1_pack), c~' = SHAKE256(mu || w1) with liboqs XKCP, constant-time compare."
"hint_check.v1|ml-dsa|dist|c|-|lib-c|Portable C backend: C chknorm / use_hint / polyw1_pack."
"hint_check.v2|ml-dsa|dist|ossl|-|openssl-shake|The challenge hash c~' through OpenSSL EVP SHAKE256 instead of liboqs XKCP."
"hint_check.v3|ml-dsa|native|-|none|xkcp-avx2|Non-dist build: XKCP AVX2 Keccak for the challenge hash instead of AVX512VL."
"hint_check.v4|ml-dsa|pgo|-|avx512vl|gcc-pgo|Profile-guided -march=native build."
"hint_check.v5|ml-dsa|clang|-|avx512vl|clang-native|clang 18 build."
"hmsg.v0|slh-dsa|dist|-|-|lib|slhdsa-c: mk_var (SHA-2 midstate of PK.seed), H_msg(R, PK.seed, PK.root, M') with its portable SHA-2/SHAKE, digest split into md / idx_tree / idx_leaf."
"hmsg.v1|slh-dsa|fasthash|-|-|fasthash|Same code with the hash core swapped: OpenSSL assembly SHA-256/512 block functions and liboqs's AVX2 XKCP Keccak-f[1600]."
"hmsg.v2|slh-dsa|native|-|-|march-native|slhdsa-c compiled with -march=native (gcc vectorises its Keccak / SHA-2 rounds for AVX2/AVX-512)."
"hmsg.v3|slh-dsa|clang|-|-|clang-native|slhdsa-c compiled with clang 18 -march=native."
"hmsg.v4|slh-dsa|pgo|-|-|gcc-pgo|Profile-guided gcc build."
"hmsg.v5|slh-dsa|lto|-|-|gcc-lto|-flto build: hash primitives inlined into the FORS/WOTS loops."
"fors.v0|slh-dsa|dist|-|-|lib|slhdsa-c fors_pk_from_sig: k leaf hashes (F), k*a tree hashes (H), one T_k compression."
"fors.v1|slh-dsa|fasthash|-|-|fasthash|OpenSSL SHA-2 block functions / AVX2 Keccak for F, H, T_k."
"fors.v2|slh-dsa|native|-|-|march-native|-march=native build."
"fors.v3|slh-dsa|clang|-|-|clang-native|clang 18 build."
"fors.v4|slh-dsa|pgo|-|-|gcc-pgo|Profile-guided build."
"fors.v5|slh-dsa|lto|-|-|gcc-lto|-flto build."
"ht_wots.v0|slh-dsa|dist|-|-|lib|d x wots_pk_from_sig (slhdsa-c): base-2^lg_w + checksum, len chains of F, one T_len; each layer fed its correct input (precomputed)."
"ht_wots.v1|slh-dsa|fasthash|-|-|fasthash|OpenSSL SHA-2 / AVX2 Keccak primitives for the chains."
"ht_wots.v2|slh-dsa|native|-|-|march-native|-march=native build."
"ht_wots.v3|slh-dsa|clang|-|-|clang-native|clang 18 build."
"ht_wots.v4|slh-dsa|pgo|-|-|gcc-pgo|Profile-guided build."
"ht_wots.v5|slh-dsa|lto|-|-|gcc-lto|-flto build."
"ht_auth.v0|slh-dsa|dist|-|-|lib|d x (h' auth-path H calls from the WOTS pk, slhdsa-c's xmss_pk_from_sig loop) + compare with PK.root."
"ht_auth.v1|slh-dsa|fasthash|-|-|fasthash|OpenSSL SHA-2 / AVX2 Keccak primitives for H."
"ht_auth.v2|slh-dsa|native|-|-|march-native|-march=native build."
"ht_auth.v3|slh-dsa|clang|-|-|clang-native|clang 18 build."
"ht_auth.v4|slh-dsa|pgo|-|-|gcc-pgo|Profile-guided build."
"ht_auth.v5|slh-dsa|lto|-|-|gcc-lto|-flto build."
"total|ml-dsa|dist|-|-|v0-pipeline|End-to-end verify assembled from the v0 stages (decode, mu, expandA, w_approx, hint_check)."
"total|slh-dsa|dist|-|-|v0-pipeline|End-to-end verify assembled from the v0 stages (hmsg, fors, ht_wots, ht_auth)."
"total_best|ml-dsa|dist|cached|-|best-pipeline|x86_64 backend with cached tr, cached A^ and cached NTT(t1 2^d) per public key (mu.v2 + expandA.v3 + w_approx.v2), default decode / hint_check."
"total_best|slh-dsa|fasthash|-|-|best-pipeline|The four SLH-DSA stages from the fasthash flavour (fastest hash primitives)."
)

# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------
cmd_validate() {
  local gz="$1" out="$2"; need_build
  $PY "$SRC/glue.py" cases-flat "$gz" "$BUILD/cases.txt" >&2
  local lines="$BUILD/validate.txt"; : > "$lines"
  for v in "${VARIANTS[@]}"; do
    IFS='|' read -r id b path threads name desc <<< "$v"
    local args=(--variant "$id" --path "$path" --threads "$threads")
    case "$b" in native|clang|lto|pgo) args+=(--sha3 avx512vl) ;; esac
    log "validate $id"
    "$BUILD/$b/bench" validate "$BUILD/spec.txt" "$BUILD/cases.txt" "${args[@]}" >> "$lines"
  done
  # sigver cases through the stage pipelines
  log "validate verify.total"
  "$BUILD/dist/bench" validate "$BUILD/spec.txt" "$BUILD/cases.txt" --variant verify.total --pipeline total >> "$lines"
  log "validate verify.total_best"
  "$BUILD/dist/bench" validate "$BUILD/spec.txt" "$BUILD/cases.txt" --variant verify.total_best --pipeline total_best --mode cached --skip-kind sigver --skip-params "$SLH_PARAMS" >> "$lines"
  "$BUILD/fasthash/bench" validate "$BUILD/spec.txt" "$BUILD/cases.txt" --variant verify.total_best --pipeline total_best --skip-kind sigver --skip-params "$MLD_PARAMS" >> "$lines"
  $PY "$SRC/glue.py" validate-json "$LIBOQS_TAG" "$lines" "$out"
}

MLD_PARAMS="ML-DSA-44,ML-DSA-65,ML-DSA-87"
SLH_PARAMS=""
for h in SHA2 SHAKE; do for s in 128s 128f 192s 192f 256s 256f; do SLH_PARAMS="$SLH_PARAMS,SLH-DSA-$h-$s"; done; done
SLH_PARAMS="${SLH_PARAMS#,}"

# ---------------------------------------------------------------------------
# stages
# ---------------------------------------------------------------------------
cmd_stages() {
  local out="" budget=1000 params="" stages=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --budget-ms) budget="$2"; shift 2 ;;
      --params) params="$2"; shift 2 ;;
      --stages) stages="$2"; shift 2 ;;
      *) log "unknown stages option $1"; exit 2 ;;
    esac
  done
  [ -n "$out" ] || { log "--out required"; exit 2; }
  need_build
  mkdir -p "$(dirname "$out")"; : > "$out"
  local gccv clangv
  gccv="$(gcc -dumpfullversion)"; clangv="$(clang --version | head -1 | sed 's/.*version \([0-9.]*\).*/\1/')"
  for v in "${STAGE_VARIANTS[@]}"; do
    IFS='|' read -r id fam b mode sha3 name desc <<< "$v"
    local stage="${id%%.*}"
    in_csv "$stages" "$stage" || continue
    local cc="gcc $gccv"; [ "$b" = clang ] && cc="clang $clangv"
    local args=(--budget-ms "$budget" --stage "$stage" --family "$fam" --variant "$id" --variant-name "$name" --variant-desc "$desc" --runtime "liboqs $LIBOQS_TAG static, $cc, flavour=$b")
    [ "$mode" != "-" ] && args+=(--mode "$mode")
    [ "$sha3" = avx512vl ] && args+=(--sha3 avx512vl)
    [ -n "$params" ] && args+=(--params "$params")
    if [ "$id" != "$stage.v0" ] && [ "$stage" != total ] && [ "$stage" != total_best ]; then
      local refs; refs="$($PY "$SRC/glue.py" stage-ref "$out" "$stage")"
      [ -n "$refs" ] && args+=(--ref "$refs")
    fi
    log "stages $id ($fam/$b/mode=$mode)"
    "$BUILD/$b/bench" stages "$BUILD/spec.txt" "${args[@]}" >> "$out"
  done
  log "wrote $out ($(wc -l < "$out") lines)"
}

# ---------------------------------------------------------------------------
# memory
# ---------------------------------------------------------------------------
cmd_memory() {
  local out="" params=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --params) params="$2"; shift 2 ;;
      *) log "unknown memory option $1"; exit 2 ;;
    esac
  done
  [ -n "$out" ] || { log "--out required"; exit 2; }
  need_build
  mkdir -p "$(dirname "$out")"; : > "$out"
  local pa=(); [ -n "$params" ] && pa=(--params "$params")
  for v in "${VARIANTS[@]}"; do
    IFS='|' read -r id b path threads name desc <<< "$v"
    local args=(--op "${id%%.*}" --variant "$id" --path "$path" --threads "$threads")
    case "$b" in native|clang|lto|pgo) args+=(--sha3 avx512vl) ;; esac
    log "memory $id"
    "$BUILD/$b/bench" memory "$BUILD/spec.txt" "${args[@]}" "${pa[@]}" >> "$out"
  done
  for v in "${STAGE_VARIANTS[@]}"; do
    IFS='|' read -r id fam b mode sha3 name desc <<< "$v"
    local stage="${id%%.*}"
    [ "$id" = "$stage.v0" ] || [ "$id" = total_best ] || continue
    local args=(--stage "$stage" --variant "$id" --family "$fam")
    [ "$mode" != "-" ] && args+=(--mode "$mode")
    log "memory $id ($fam)"
    "$BUILD/$b/bench" memory "$BUILD/spec.txt" "${args[@]}" "${pa[@]}" >> "$out"
  done
  log "wrote $out ($(wc -l < "$out") lines)"
}

case "${1:-}" in
  build) cmd_build ;;
  vectors) cmd_vectors "$2" ;;
  crossverify) cmd_crossverify "$2" "$3" ;;
  bench) shift; cmd_bench "$@" ;;
  validate) cmd_validate "$2" "$3" ;;
  stages) shift; cmd_stages "$@" ;;
  memory) shift; cmd_memory "$@" ;;
  *) echo "usage: $0 build | vectors <out.json> | crossverify <in.json> <out.json> | bench --out <f.jsonl> [opts] | validate <suite.json.gz> <out.json> | stages --out <f.jsonl> [--budget-ms N] [--params a,b] [--stages a,b] | memory --out <f.jsonl> [--params a,b]" >&2; exit 2 ;;
esac
