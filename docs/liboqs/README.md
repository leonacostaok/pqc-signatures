# liboqs (Open Quantum Safe, C)

Harness: `libs/liboqs/run.sh` (build / vectors / crossverify / bench), driver `libs/liboqs/src/bench.c`,
JSON glue `libs/liboqs/src/glue.py`, source patch `libs/liboqs/patches/slh-fasthash.patch`.

## Versions

| component | version |
|---|---|
| liboqs | **0.16.0** (tag `0.16.0`, commit `5a1a854b0`), cloned into `libs/liboqs/deps/liboqs` |
| ML-DSA implementation | mldsa-native (vendored, `src/sig/ml_dsa/mldsa-native_*`), portable C + x86_64 AVX2 backend |
| SLH-DSA implementation | slhdsa-c (vendored, `src/sig/slh_dsa/slh_dsa_c`), portable C with its own SHA-2 / Keccak |
| Falcon implementation | PQClean `falcon-512/1024` (clean + AVX2), cross-verify only |
| toolchain | gcc 13.3.0, clang 18.1.3, cmake 3.28.3, OpenSSL 3.0.13 (libcrypto, used by liboqs for SHA-2 and by the driver for SHA-256 digests) |
| driver | C11, `clock_gettime(CLOCK_MONOTONIC)` per op, `getrusage(RUSAGE_SELF)` over the measured loop, pthreads for batch variants |

Parameter sets: ML-DSA-44/65/87, all twelve pure SLH-DSA sets (liboqs names `SLH_DSA_PURE_{SHA2,SHAKE}_{128,192,256}{S,F}`),
Falcon-512/1024. All 15 ML-DSA/SLH-DSA sets byte-match `common/reference.json` (pk, sk and sig) in every variant.

## Build

`run.sh build` clones liboqs (git over GitHub), checks out the pinned tag and produces six static builds under
`libs/liboqs/build/<flavour>/` (`lib/liboqs.a` + a driver binary `bench` linked against it), restricted with
`OQS_MINIMAL_BUILD` to the 17 algorithms above so that each flavour builds in about a minute with `-j2`:

| flavour | liboqs configuration | driver flags |
|---|---|---|
| `dist` | liboqs defaults: `CMAKE_BUILD_TYPE=Release` (-O3), `OQS_DIST_BUILD=ON` (generic x86-64 code + AVX2 objects chosen at run time through `OQS_CPU_has_extension`), SHA-2 via OpenSSL, SHA-3 via XKCP (AVX2 / AVX512VL dispatched at run time) | gcc -O2 |
| `native` | `OQS_DIST_BUILD=OFF`, `OQS_OPT_TARGET=auto` (= `-march=native`), AVX2 backends selected at compile time | gcc -O3 -march=native |
| `clang` | as `native`, `CMAKE_C_COMPILER=clang` | clang -O3 -march=native |
| `lto` | as `native` plus `CMAKE_INTERPROCEDURAL_OPTIMIZATION=ON` (`-flto`) | gcc -O3 -march=native -flto |
| `pgo` | as `native` built twice: `-fprofile-generate`, a training run (`vectors` + a short `bench` over every param/op), then `-fprofile-use -fprofile-correction` | gcc -O3 -march=native with the same profile flags |
| `fasthash` | liboqs defaults applied to a patched checkout (`git worktree` + `patches/slh-fasthash.patch`): slhdsa-c's `sha2_256_compress` / `sha2_512_compress` call OpenSSL's `SHA256_Transform` / `SHA512_Transform` (assembly block functions) and `keccak_f1600` calls liboqs's own XKCP `KeccakP1600_Permute_24rounds_avx2` (run-time check, portable fallback) | gcc -O2 |

The build is idempotent (a flavour is skipped when its `.done` marker is newer than the sources) and works offline after
the first clone. Build logs are in `build/<flavour>/{cmake,build}.log`.

## How seeded key generation and deterministic signing were achieved

liboqs's public API (`OQS_SIG_keypair`, `OQS_SIG_sign`) is randomised and has no seed/rnd parameters. Two different,
independently checked routes are used; both reproduce the reference digests bit for bit.

**Route A, public API + custom RNG (baseline and all build-flavour variants).** The driver installs
`OQS_randombytes_custom_algorithm(fixed_randombytes)`, a stateless callback that hands out a fixed byte pattern. Every
call site in liboqs 0.16.0 asks for exactly the bytes the standard consumes, so the pattern is simply the value the
algorithm must use:

| op | what liboqs requests | pattern handed out |
|---|---|---|
| ML-DSA keygen | `mld_sign_keypair` -> `mld_randombytes(seed, 32)` | ξ (32 B) from `vectors.json` -> `ML-DSA.KeyGen_internal(ξ)` |
| ML-DSA sign | `mld_sign_signature` -> `mld_randombytes(rnd, 32)` | 32 zero bytes -> deterministic variant (FIPS 204 Alg. 2 with rnd = 0^32) |
| SLH-DSA keygen | `slh_keygen` -> `rbg(sk, 3n)` (one call) | `SK.seed ‖ SK.prf ‖ PK.seed` (3n B) -> identical to `slh_keygen_internal` |
| SLH-DSA sign | wrapper calls `OQS_randombytes(addrnd, n)` and passes it as opt_rand | `PK.seed` (= `sk[2n..3n)`) -> deterministic variant (FIPS 205: opt_rand = PK.seed) |
| Falcon | 48-byte keygen seed, 40-byte nonce | the vector seed, repeated (no byte match expected; it only makes runs reproducible) |

Pure mode with the empty context is what `OQS_SIG_sign`/`OQS_SIG_verify` do by default (they call the `*_with_ctx_str`
code path with `ctx = NULL, ctxlen = 0`, i.e. M' = 0x00 ‖ 0x00 ‖ M).

**Route B, internal functions (the `internal-*` variants, `--path direct`).** The static library exports the vendored
internal entry points, so the driver calls them directly:
`PQCP_MLDSA_NATIVE_MLDSA{44,65,87}_{C,X86_64}_keypair_internal(pk, sk, seed)`,
`..._signature_internal(sig, &len, m, mlen, pre = {0x00,0x00}, 2, rnd = 0^32, sk, externalmu = 0)` and
`..._verify_internal(...)` (the X86_64 set is used when the CPU has AVX2/BMI2/POPCNT, exactly the test liboqs makes),
plus slhdsa-c's `slh_keygen_internal(sk, pk, SK.seed, SK.prf, PK.seed, prm)`, `slh_sign(..., ctx = NULL, 0, sk, addrnd = NULL, prm)`
(addrnd = NULL selects opt_rand = PK.seed inside slhdsa-c) and `slh_verify(...)`. Falcon has no seeded internal API
in PQClean, so the direct path falls back to route A for Falcon.

**Checking.** `match` is computed at run time on every bench line: the SHA-256 of the produced pk and sk (keygen) or
signature (sign) is compared with `common/reference.json` after the warm-up and again after the measured loop (for the
threaded variants on every thread's buffers); for verify the result must be `true` on the reference triple and `false`
on a copy of the signature with one flipped bit, through the same code path as the measured op. Falcon lines carry
`"match_basis":"self-verify"` (output identical to a reference run inside the same process and signature verifies)
instead of `"reference"`. Nothing is hard-coded: the expected digests are read from `common/reference.json` each run.

## Running

```
libs/liboqs/run.sh build
libs/liboqs/run.sh vectors results/liboqs/artifacts.json
libs/liboqs/run.sh crossverify results/liboqs/artifacts.json results/liboqs/crossverify-liboqs.json
libs/liboqs/run.sh bench --out results/liboqs/bench.jsonl                      # full run (default budget 1000 ms)
libs/liboqs/run.sh bench --out /tmp/x.jsonl --budget-ms 200 --params ML-DSA-44 --ops sign --variants sign.v0,sign.v3
```

`bench` truncates the output file and writes one JSON line per (variant, op, param): 18 variants x 17 params = 306 lines.
With the default 1000 ms budget the full run takes roughly 25-30 minutes, dominated by the SLH-DSA `s` signing times
(a single SLH-DSA-SHAKE-256s signature takes a few seconds on the portable code, and at least 3 ops are always measured).

## Timing method

Warm-up: at least one op (up to 5 ops or 100 ms). Measured loop: until the budget has elapsed and at least 3 ops have
been timed (2 if one op exceeds 5 s), capped at 100 000 samples. Each op's wall time is taken with
`clock_gettime(CLOCK_MONOTONIC)`; CPU time is `getrusage(RUSAGE_SELF)` (user + sys, all threads) over the whole loop
divided by the number of ops, `cpu_util` = CPU / wall of the loop. Batch variants run a persistent pool of 4 pthreads
synchronised with barriers; each thread performs k ops per batch (k sized so that a batch lasts ~2 ms per thread,
1 <= k <= 64) and the recorded wall time per op is batch wall / (4k).

## Notes and caveats

- liboqs's SLH-DSA code (slhdsa-c) is pure portable C including its own SHA-2 and Keccak; it does not use liboqs's
  OpenSSL SHA-2 or XKCP AVX2 Keccak back-ends. That is why the SLH-DSA numbers are far behind the ML-DSA ones and why
  the `fasthash` flavour (a 100-line patch) is the only variant that moves them substantially.
- All flavours are static builds with `OQS_BUILD_ONLY_LIB=ON`; the shared library is not used.
- This machine (Intel Xeon @ 2.8 GHz, AVX2/AVX512VL, no SHA-NI) was shared with other builds during development, so
  the preliminary numbers below are noisy; the orchestrator regenerates the tables from a quiet run.

<!-- RESULTS -->
