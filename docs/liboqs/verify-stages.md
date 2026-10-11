# liboqs: verify split into stages

`run.sh stages --out results/liboqs/stages.jsonl [--budget-ms N] [--params a,b] [--stages x,y]`

## How the stages are reached

liboqs exposes only whole operations, so the stage entry points are built directly on the vendored
implementations inside `liboqs.a` (`libs/liboqs/src/stages_mldsa.c`, `libs/liboqs/src/stages_slh.c`,
compiled into every flavour's driver binary by `run.sh`):

- **ML-DSA (mldsa-native).** The building blocks that `mld_sign_verify_internal()` (`mldsa/src/sign.c`) calls
  are ordinary exported symbols of the static library (`PQCP_MLDSA_NATIVE_MLDSA<NN>_<X86_64|C>_polyvecl_unpack_z`,
  `_unpack_pk_t1`, `_sig_unpack_hints`, `_polyvec_matrix_expand_eager`, `_poly_challenge`, `_poly_ntt`,
  `_polyvec_matrix_pointwise_montgomery_row_eager`, `_poly_use_hint`, `_polyw1_pack`, ...). `stages_mldsa.c`
  is compiled six times (3 parameter sets x 2 backends) with exactly the `-D`/`-I` flags liboqs uses for the
  corresponding object library, so the `mld_*` names resolve to the library's own objects, and the stage bodies
  are the verify function's statements regrouped; nothing is reimplemented except the two helpers that are
  `static` in `sign.c` (`mld_H` = incremental SHAKE256 through liboqs's `OQS_SHA3_shake256_inc_*`, and the
  pure-mode prefix `0x00 || |ctx| || ctx`). Because `OQS_DIST_BUILD` compiles both backends into the library,
  the portable-C backend is available as a stage alternative in the same binary.
- **AVX2 lane order.** The x86_64 backend keeps NTT-domain polynomials in a custom coefficient order
  (`mld_poly_permute_bitrev_to_custom` / `nttunpack_avx2`). For the canonical `expandA` output the permutation
  is undone; it is recovered at run time by pushing the identity polynomial `0..255` through the library's own
  permutation function (it only moves 32-bit lanes), so no table had to be transcribed.
- **SLH-DSA (slhdsa-c).** `fors_pk_from_sig`, `wots_pk_from_sig`, `xmss_pk_from_sig` and `ht_verify` are `static`.
  `stages_slh.c` therefore `#include`s the flavour's unmodified `slh_dsa.c` with its ten global functions renamed
  through `-D` flags (`slh_verify` -> `stg_slh_verify`, ...): the static helpers become callable from the stage code
  while `liboqs.a` keeps its own copies, and the hash primitives (`prm->h_msg/h_f/h_h/h_t/chain`) remain the
  library's (so the `fasthash` flavour's OpenSSL/AVX2 primitives are picked up automatically). `ht_wots` and
  `ht_auth` are the two halves of slhdsa-c's `xmss_pk_from_sig` loop; the input message of every layer (FORS pk for
  layer 0, previous layer's root otherwise) is produced by an untimed reference pass (`prepare_layers`) using the
  library's own `xmss_pk_from_sig`.

Stage inputs always come from the previous stages computed outside the timed region; a stage call only
recomputes its own output from the state. Each line's `match` is true when (1) the variant's canonical output
equals the output of the library backend with default modes computed in the same process, and (2) for
alternatives, equals the `output_sha256` of the stage's `v0` line written earlier in the same run (`run.sh`
passes it as `--ref`). `total` / `total_best` lines carry `"true"` only if the pipeline accepted the reference
triple and rejected a one-bit-flipped signature. `total_best` is also run through `validate` (387 sigver cases).

Canonical outputs: `decode` SHA-256(c~); `mu` SHA-256(mu); `expandA` SHA-256 of A^ coefficients in [0,q), u32 LE,
row-major k x l x 256 in standard order; `w_approx` SHA-256 of w' in [0,q), u32 LE, k x 256; `hint_check`
SHA-256 of w1Encode(w1'); `hmsg` SHA-256(digest); `fors` SHA-256(PK_FORS); `ht_wots` SHA-256 of the d WOTS+ public
keys (layer 0 first); `ht_auth` SHA-256 of the d layer roots.

## Stage variants

Each stage has `v0` = the library's own code in the default (`dist`) build plus five alternatives. Mechanisms:

| mechanism | what changes | stages |
|---|---|---|
| `lib-c` | the same functions from liboqs's portable C backend objects (generic x86-64 code, no AVX2 asm/intrinsics) | decode, expandA, w_approx, hint_check |
| `openssl-shake` | the SHAKE256 calls go through OpenSSL 3 EVP (`EVP_shake256`, `EVP_DigestFinalXOF`) instead of liboqs's XKCP | mu, hint_check |
| `cached-tr` / `cached-A` / `cached-t1hat` | per-public-key cache (pk compared bytewise on every call) of tr = H(pk), of A^ = ExpandA(rho) and of NTT(t1 2^d); shows the floor for a verifier that sees the same key repeatedly | mu, expandA, w_approx |
| `oneway-shake` | ExpandA with one SHAKE128 stream per matrix entry (`mld_poly_uniform`, nonce i<<8 + j) instead of the 4-way interleaved sampler, then the backend's lane permutation | expandA |
| `xkcp-avx2` | the `native` build *without* re-selecting the AVX512VL callbacks: liboqs's XKCP AVX2 Keccak (and times4 AVX2) instead of the AVX512VL one | mu, expandA, hint_check |
| `march-native`, `clang-native`, `gcc-pgo`, `gcc-lto` | the stage code and library compiled in the respective flavour (see README) | all |
| `fasthash` | patched slhdsa-c hash core: OpenSSL SHA-256/512 block functions + liboqs AVX2 Keccak-f[1600] | SLH-DSA stages |

SLH-DSA stages are pure hash chains with no algorithmic freedom at the FIPS 205 level without rewriting the
tree walk (batched WOTS chains, fused auth hashing); those would be new implementations rather than liboqs
variants, so the SLH-DSA alternatives are the five build/hash-backend flavours (each one changes the generated
code of the hash core, which is where all the time goes). `total_best` for ML-DSA uses the x86_64 backend with
the three per-key caches (`mu.v2 + expandA.v3 + w_approx.v2`); for SLH-DSA it is the `fasthash` pipeline.

## Conclusions (preliminary, noisy shared machine; 150 ms budget, 7 params)

All 200 stage lines match their v0 canonical output, and both pipelines accept the reference and reject the
tampered signature (`total_best` also passes all 387 sigver cases of the validation suite).

**ML-DSA.** The v0 pipeline costs the same as the public API (ML-DSA-44 ~18-29 us depending on load). Per
stage (ML-DSA-44, quieter earlier run): expandA 6.6 us, mu 5.6 us, hint_check 4.8 us, w_approx 4.6 us, decode
0.7 us, i.e. two thirds of verification is SHAKE (matrix expansion + H(pk) + the challenge hash). Geometric-mean
speedups over v0 across the three parameter sets: `cached-A` 22.6x (expandA becomes a 20-56 KiB memcpy),
`cached-tr` 10.8x on mu (H(pk) over 1.3-2.6 KiB is the expensive half), `cached-t1hat` 1.9x on w_approx; the
assembled `total_best` is 2.2x (ML-DSA-44), 3.9x (65) and 13x (87, mostly noise in the v0 line) faster than
`total`. The portable C backend costs 0.14x on w_approx (C NTT vs AVX2 asm), 0.34x on decode, 0.54x on expandA
and 0.65x on hint_check: the AVX2 backend is worth 1.5-7x per stage. OpenSSL's SHAKE256 is slower than XKCP
(0.6x on mu and hint_check here; in the earlier run mu was 1.15x faster, so it depends on load/buffer size).
One-stream ExpandA is 0.30x of the 4-way one, i.e. the times4 Keccak is the single most valuable optimisation
in verification. The AVX2-Keccak (`xkcp-avx2`) lines are 0.32-0.67x of the AVX512VL ones, confirming that
non-dist builds lose a lot by never installing the AVX512VL callbacks. Compiler flavours (native/clang/pgo/lto)
sit within noise (0.8-1.4x) on the asm-dominated stages.

**SLH-DSA.** The hypertree WOTS+ stage is 70-90 % of verification time, FORS most of the rest, hmsg and the
auth paths are tiny. The alternatives change only the hash core: `fasthash` 1.2-1.4x on every stage,
`clang-native` 1.3x on hmsg/fors, `march-native` up to 1.6x on ht_auth, `gcc-pgo` 1.5x on fors; `gcc-lto`
within noise. `total_best` (fasthash pipeline) is 1.1-3x faster than `total` in this noisy run.

<!-- RESULTS -->

## Results

Generated by `common/report-phase2.mjs` from `results/liboqs/stages.jsonl`. Speedup = throughput vs the stage's v0. "coverage" = sum of v0 stage medians / end-to-end v0 total.

### ML-DSA-44

end-to-end v0 stages: 17.8 µs, best assembled: 8.2 µs (2.17×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` lib-x86_64 | 1.0 µs | 1.1 µs | 1 | 5.6% | 1.00× | ✓ |
| decode | `decode.v1` lib-c | 1.6 µs | 2.4 µs | 1 |  | 0.50× | ✓ |
| decode | `decode.v2` march-native | 0.7 µs | 0.8 µs | 1 |  | 1.49× | ✓ |
| decode | `decode.v3` clang-native | 0.4 µs | 0.5 µs | 1 |  | 2.20× | ✓ |
| decode | `decode.v4` gcc-pgo | 0.7 µs | 0.8 µs | 1 |  | 1.41× | ✓ |
| decode | `decode.v5` gcc-lto | 0.7 µs | 0.8 µs | 1 |  | 1.50× | ✓ |
| mu | `mu.v0` lib-shake | 2.8 µs | 3.4 µs | 1 | 15.6% | 1.00× | ✓ |
| mu | `mu.v1` openssl-shake | 5.0 µs | 6.0 µs | 1 |  | 0.57× | ✓ |
| mu | `mu.v2` cached-tr | 0.4 µs | 0.4 µs | 1 |  | 7.62× | ✓ |
| mu | `mu.v3` xkcp-avx2 | 4.0 µs | 4.7 µs | 1 |  | 0.71× | ✓ |
| mu | `mu.v4` gcc-pgo | 2.8 µs | 3.4 µs | 1 |  | 1.00× | ✓ |
| mu | `mu.v5` clang-native | 2.8 µs | 3.0 µs | 1 |  | 1.10× | ✓ |
| expandA | `expandA.v0` lib-4way | 6.6 µs | 7.3 µs | 1 | 36.9% | 1.00× | ✓ |
| expandA | `expandA.v1` lib-c | 10.1 µs | 10.8 µs | 1 |  | 0.69× | ✓ |
| expandA | `expandA.v2` oneway-shake | 21.3 µs | 24.5 µs | 1 |  | 0.30× | ✓ |
| expandA | `expandA.v3` cached-A | 0.1 µs | 0.2 µs | 1 |  | 42.14× | ✓ |
| expandA | `expandA.v4` xkcp-avx2-x4 | 9.7 µs | 11.0 µs | 1 |  | 0.67× | ✓ |
| expandA | `expandA.v5` gcc-pgo | 6.5 µs | 7.7 µs | 1 |  | 0.94× | ✓ |
| w_approx | `w_approx.v0` lib-x86_64 | 4.6 µs | 5.2 µs | 1 | 25.6% | 1.00× | ✓ |
| w_approx | `w_approx.v1` lib-c | 28.5 µs | 32.4 µs | 1 |  | 0.16× | ✓ |
| w_approx | `w_approx.v2` cached-t1hat | 3.6 µs | 3.9 µs | 1 |  | 1.34× | ✓ |
| w_approx | `w_approx.v3` march-native | 4.6 µs | 5.1 µs | 1 |  | 1.03× | ✓ |
| w_approx | `w_approx.v4` gcc-lto | 4.6 µs | 5.6 µs | 1 |  | 0.93× | ✓ |
| w_approx | `w_approx.v5` clang-native | 4.5 µs | 5.0 µs | 1 |  | 1.05× | ✓ |
| hint_check | `hint_check.v0` lib-x86_64 | 2.9 µs | 3.1 µs | 1 | 16.3% | 1.00× | ✓ |
| hint_check | `hint_check.v1` lib-c | 5.5 µs | 6.4 µs | 1 |  | 0.49× | ✓ |
| hint_check | `hint_check.v2` openssl-shake | 4.2 µs | 4.9 µs | 1 |  | 0.64× | ✓ |
| hint_check | `hint_check.v3` xkcp-avx2 | 3.5 µs | 3.8 µs | 1 |  | 0.82× | ✓ |
| hint_check | `hint_check.v4` gcc-pgo | 2.9 µs | 3.9 µs | 1 |  | 0.80× | ✓ |
| hint_check | `hint_check.v5` clang-native | 2.5 µs | 3.0 µs | 1 |  | 0.99× | ✓ |

### ML-DSA-65

end-to-end v0 stages: 28.3 µs, best assembled: 9.8 µs (2.90×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` lib-x86_64 | 1.0 µs | 1.1 µs | 1 | 3.6% | 1.00× | ✓ |
| decode | `decode.v1` lib-c | 2.1 µs | 2.3 µs | 1 |  | 0.52× | ✓ |
| decode | `decode.v2` march-native | 1.0 µs | 1.1 µs | 1 |  | 1.05× | ✓ |
| decode | `decode.v3` clang-native | 0.6 µs | 0.8 µs | 1 |  | 1.55× | ✓ |
| decode | `decode.v4` gcc-pgo | 1.0 µs | 1.1 µs | 1 |  | 1.09× | ✓ |
| decode | `decode.v5` gcc-lto | 0.9 µs | 1.1 µs | 1 |  | 1.08× | ✓ |
| mu | `mu.v0` lib-shake | 4.0 µs | 4.4 µs | 1 | 14.1% | 1.00× | ✓ |
| mu | `mu.v1` openssl-shake | 6.7 µs | 7.7 µs | 1 |  | 0.56× | ✓ |
| mu | `mu.v2` cached-tr | 0.4 µs | 0.4 µs | 1 |  | 10.32× | ✓ |
| mu | `mu.v3` xkcp-avx2 | 5.7 µs | 6.0 µs | 1 |  | 0.72× | ✓ |
| mu | `mu.v4` gcc-pgo | 4.0 µs | 4.7 µs | 1 |  | 0.91× | ✓ |
| mu | `mu.v5` clang-native | 4.0 µs | 4.3 µs | 1 |  | 1.02× | ✓ |
| expandA | `expandA.v0` lib-4way | 14.0 µs | 18.1 µs | 1 | 49.4% | 1.00× | ✓ |
| expandA | `expandA.v1` lib-c | 20.6 µs | 24.4 µs | 1 |  | 0.74× | ✓ |
| expandA | `expandA.v2` oneway-shake | 39.9 µs | 53.4 µs | 1 |  | 0.34× | ✓ |
| expandA | `expandA.v3` cached-A | 0.7 µs | 0.8 µs | 1 |  | 23.07× | ✓ |
| expandA | `expandA.v4` xkcp-avx2-x4 | 20.6 µs | 22.2 µs | 1 |  | 0.82× | ✓ |
| expandA | `expandA.v5` gcc-pgo | 14.2 µs | 17.6 µs | 1 |  | 1.02× | ✓ |
| w_approx | `w_approx.v0` lib-x86_64 | 6.4 µs | 7.8 µs | 1 | 22.7% | 1.00× | ✓ |
| w_approx | `w_approx.v1` lib-c | 40.8 µs | 45.7 µs | 1 |  | 0.17× | ✓ |
| w_approx | `w_approx.v2` cached-t1hat | 4.9 µs | 5.7 µs | 1 |  | 1.38× | ✓ |
| w_approx | `w_approx.v3` march-native | 6.4 µs | 7.0 µs | 1 |  | 1.11× | ✓ |
| w_approx | `w_approx.v4` gcc-lto | 6.3 µs | 6.8 µs | 1 |  | 1.16× | ✓ |
| w_approx | `w_approx.v5` clang-native | 6.3 µs | 7.3 µs | 1 |  | 1.07× | ✓ |
| hint_check | `hint_check.v0` lib-x86_64 | 2.6 µs | 2.9 µs | 1 | 9.1% | 1.00× | ✓ |
| hint_check | `hint_check.v1` lib-c | 6.0 µs | 6.4 µs | 1 |  | 0.46× | ✓ |
| hint_check | `hint_check.v2` openssl-shake | 3.8 µs | 4.1 µs | 1 |  | 0.71× | ✓ |
| hint_check | `hint_check.v3` xkcp-avx2 | 3.2 µs | 3.4 µs | 1 |  | 0.86× | ✓ |
| hint_check | `hint_check.v4` gcc-pgo | 2.6 µs | 2.8 µs | 1 |  | 1.04× | ✓ |
| hint_check | `hint_check.v5` clang-native | 2.3 µs | 2.5 µs | 1 |  | 1.13× | ✓ |

### ML-DSA-87

end-to-end v0 stages: 41.7 µs, best assembled: 13.4 µs (3.11×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` lib-x86_64 | 1.4 µs | 1.6 µs | 1 | 3.3% | 1.00× | ✓ |
| decode | `decode.v1` lib-c | 2.8 µs | 3.1 µs | 1 |  | 0.52× | ✓ |
| decode | `decode.v2` march-native | 1.3 µs | 1.7 µs | 1 |  | 0.94× | ✓ |
| decode | `decode.v3` clang-native | 0.8 µs | 1.0 µs | 1 |  | 1.65× | ✓ |
| decode | `decode.v4` gcc-pgo | 1.3 µs | 1.9 µs | 1 |  | 0.83× | ✓ |
| decode | `decode.v5` gcc-lto | 1.3 µs | 1.5 µs | 1 |  | 1.02× | ✓ |
| mu | `mu.v0` lib-shake | 5.2 µs | 6.8 µs | 1 | 12.4% | 1.00× | ✓ |
| mu | `mu.v1` openssl-shake | 8.4 µs | 9.0 µs | 1 |  | 0.75× | ✓ |
| mu | `mu.v2` cached-tr | 0.4 µs | 0.4 µs | 1 |  | 15.88× | ✓ |
| mu | `mu.v3` xkcp-avx2 | 7.4 µs | 8.3 µs | 1 |  | 0.82× | ✓ |
| mu | `mu.v4` gcc-pgo | 5.2 µs | 5.6 µs | 1 |  | 1.23× | ✓ |
| mu | `mu.v5` clang-native | 5.2 µs | 5.7 µs | 1 |  | 1.20× | ✓ |
| expandA | `expandA.v0` lib-4way | 22.5 µs | 25.6 µs | 1 | 54.0% | 1.00× | ✓ |
| expandA | `expandA.v1` lib-c | 34.7 µs | 37.0 µs | 1 |  | 0.70× | ✓ |
| expandA | `expandA.v2` oneway-shake | 74.9 µs | 99.0 µs | 1 |  | 0.26× | ✓ |
| expandA | `expandA.v3` cached-A | 1.3 µs | 1.5 µs | 1 |  | 17.42× | ✓ |
| expandA | `expandA.v4` xkcp-avx2-x4 | 33.4 µs | 37.1 µs | 1 |  | 0.69× | ✓ |
| expandA | `expandA.v5` gcc-pgo | 23.1 µs | 28.0 µs | 1 |  | 0.91× | ✓ |
| w_approx | `w_approx.v0` lib-x86_64 | 8.7 µs | 9.7 µs | 1 | 20.8% | 1.00× | ✓ |
| w_approx | `w_approx.v1` lib-c | 55.4 µs | 61.3 µs | 1 |  | 0.16× | ✓ |
| w_approx | `w_approx.v2` cached-t1hat | 6.7 µs | 7.5 µs | 1 |  | 1.30× | ✓ |
| w_approx | `w_approx.v3` march-native | 8.7 µs | 9.7 µs | 1 |  | 1.01× | ✓ |
| w_approx | `w_approx.v4` gcc-lto | 8.6 µs | 10.4 µs | 1 |  | 0.94× | ✓ |
| w_approx | `w_approx.v5` clang-native | 8.7 µs | 9.5 µs | 1 |  | 1.02× | ✓ |
| hint_check | `hint_check.v0` lib-x86_64 | 3.4 µs | 3.7 µs | 1 | 8.1% | 1.00× | ✓ |
| hint_check | `hint_check.v1` lib-c | 8.0 µs | 8.6 µs | 1 |  | 0.43× | ✓ |
| hint_check | `hint_check.v2` openssl-shake | 4.8 µs | 5.5 µs | 1 |  | 0.67× | ✓ |
| hint_check | `hint_check.v3` xkcp-avx2 | 4.2 µs | 4.6 µs | 1 |  | 0.78× | ✓ |
| hint_check | `hint_check.v4` gcc-pgo | 3.3 µs | 3.5 µs | 1 |  | 1.04× | ✓ |
| hint_check | `hint_check.v5` clang-native | 3.0 µs | 3.1 µs | 1 |  | 1.18× | ✓ |

### SLH-DSA-SHA2-128s

end-to-end v0 stages: 1.08 ms, best assembled: 802.8 µs (1.34×), coverage 53%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 1.4 µs | 1.6 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 1.0 µs | 1.1 µs | 1 |  | 1.49× | ✓ |
| hmsg | `hmsg.v2` march-native | 1.2 µs | 1.4 µs | 1 |  | 1.13× | ✓ |
| hmsg | `hmsg.v3` clang-native | 1.2 µs | 1.4 µs | 1 |  | 1.15× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 1.3 µs | 1.4 µs | 1 |  | 1.15× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 1.9 µs | 1.9 µs | 1 |  | 0.83× | ✓ |
| fors | `fors.v0` lib | 52.1 µs | 63.0 µs | 1 | 4.8% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 38.8 µs | 43.3 µs | 1 |  | 1.47× | ✓ |
| fors | `fors.v2` march-native | 47.2 µs | 55.1 µs | 1 |  | 1.17× | ✓ |
| fors | `fors.v3` clang-native | 44.4 µs | 47.5 µs | 1 |  | 1.35× | ✓ |
| fors | `fors.v4` gcc-pgo | 45.8 µs | 49.4 µs | 1 |  | 1.31× | ✓ |
| fors | `fors.v5` gcc-lto | 46.8 µs | 57.4 µs | 1 |  | 1.12× | ✓ |
| ht_wots | `ht_wots.v0` lib | 496.2 µs | 526.3 µs | 1 | 46.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 370.4 µs | 385.5 µs | 1 |  | 1.35× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 479.2 µs | 514.1 µs | 1 |  | 1.04× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 467.9 µs | 489.6 µs | 1 |  | 1.09× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 475.5 µs | 496.1 µs | 1 |  | 1.07× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 494.4 µs | 600.6 µs | 1 |  | 0.89× | ✓ |
| ht_auth | `ht_auth.v0` lib | 17.3 µs | 18.2 µs | 1 | 1.6% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 13.1 µs | 15.8 µs | 1 |  | 1.08× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 16.1 µs | 19.7 µs | 1 |  | 0.92× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 15.2 µs | 16.2 µs | 1 |  | 1.12× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 15.7 µs | 17.1 µs | 1 |  | 1.05× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 16.0 µs | 18.0 µs | 1 |  | 0.99× | ✓ |

### SLH-DSA-SHA2-128f

end-to-end v0 stages: 3.57 ms, best assembled: 2.39 ms (1.49×), coverage 46%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 1.9 µs | 2.0 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 1.4 µs | 1.5 µs | 1 |  | 1.39× | ✓ |
| hmsg | `hmsg.v2` march-native | 1.7 µs | 2.0 µs | 1 |  | 1.02× | ✓ |
| hmsg | `hmsg.v3` clang-native | 1.6 µs | 1.8 µs | 1 |  | 1.13× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 1.7 µs | 1.9 µs | 1 |  | 1.08× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 1.7 µs | 2.0 µs | 1 |  | 1.00× | ✓ |
| fors | `fors.v0` lib | 67.0 µs | 76.1 µs | 1 | 1.9% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 50.1 µs | 53.9 µs | 1 |  | 1.40× | ✓ |
| fors | `fors.v2` march-native | 61.0 µs | 66.3 µs | 1 |  | 1.15× | ✓ |
| fors | `fors.v3` clang-native | 57.6 µs | 64.9 µs | 1 |  | 1.17× | ✓ |
| fors | `fors.v4` gcc-pgo | 59.2 µs | 65.9 µs | 1 |  | 1.16× | ✓ |
| fors | `fors.v5` gcc-lto | 60.2 µs | 67.3 µs | 1 |  | 1.13× | ✓ |
| ht_wots | `ht_wots.v0` lib | 1.57 ms | 1.60 ms | 1 | 44.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 1.16 ms | 1.26 ms | 1 |  | 1.28× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 1.59 ms | 1.80 ms | 1 |  | 0.89× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 1.47 ms | 1.49 ms | 1 |  | 1.07× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 1.49 ms | 1.67 ms | 1 |  | 0.96× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 1.51 ms | 1.58 ms | 1 |  | 1.01× | ✓ |
| ht_auth | `ht_auth.v0` lib | 18.1 µs | 19.3 µs | 1 | 0.5% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 13.9 µs | 15.5 µs | 1 |  | 1.24× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 16.9 µs | 21.5 µs | 1 |  | 0.89× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 15.9 µs | 16.8 µs | 1 |  | 1.15× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 16.6 µs | 19.1 µs | 1 |  | 0.99× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 16.8 µs | 18.6 µs | 1 |  | 1.01× | ✓ |

### SLH-DSA-SHA2-192s

end-to-end v0 stages: 1.58 ms, best assembled: 1.17 ms (1.35×), coverage 55%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 2.1 µs | 2.3 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 1.5 µs | 2.1 µs | 1 |  | 1.12× | ✓ |
| hmsg | `hmsg.v2` march-native | 1.8 µs | 2.1 µs | 1 |  | 1.10× | ✓ |
| hmsg | `hmsg.v3` clang-native | 1.8 µs | 2.1 µs | 1 |  | 1.08× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 1.9 µs | 2.2 µs | 1 |  | 1.01× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 1.8 µs | 2.5 µs | 1 |  | 0.92× | ✓ |
| fors | `fors.v0` lib | 95.5 µs | 114.4 µs | 1 | 6.1% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 68.1 µs | 75.5 µs | 1 |  | 1.53× | ✓ |
| fors | `fors.v2` march-native | 85.4 µs | 112.3 µs | 1 |  | 1.02× | ✓ |
| fors | `fors.v3` clang-native | 85.5 µs | 101.7 µs | 1 |  | 1.13× | ✓ |
| fors | `fors.v4` gcc-pgo | 87.0 µs | 105.8 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v5` gcc-lto | 81.1 µs | 93.3 µs | 1 |  | 1.24× | ✓ |
| ht_wots | `ht_wots.v0` lib | 746.3 µs | 938.1 µs | 1 | 47.3% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 533.9 µs | 578.1 µs | 1 |  | 1.63× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 687.7 µs | 764.5 µs | 1 |  | 1.23× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 717.9 µs | 830.5 µs | 1 |  | 1.12× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 721.9 µs | 826.2 µs | 1 |  | 1.13× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 689.7 µs | 733.7 µs | 1 |  | 1.27× | ✓ |
| ht_auth | `ht_auth.v0` lib | 23.4 µs | 27.1 µs | 1 | 1.5% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 16.9 µs | 18.2 µs | 1 |  | 1.49× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 20.0 µs | 20.8 µs | 1 |  | 1.31× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 19.1 µs | 20.3 µs | 1 |  | 1.33× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 20.2 µs | 22.4 µs | 1 |  | 1.20× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 20.1 µs | 26.0 µs | 1 |  | 1.03× | ✓ |

### SLH-DSA-SHA2-192f

end-to-end v0 stages: 4.87 ms, best assembled: 3.49 ms (1.40×), coverage 56%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 2.2 µs | 2.5 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 1.5 µs | 2.1 µs | 1 |  | 1.15× | ✓ |
| hmsg | `hmsg.v2` march-native | 1.8 µs | 2.0 µs | 1 |  | 1.22× | ✓ |
| hmsg | `hmsg.v3` clang-native | 1.8 µs | 2.0 µs | 1 |  | 1.26× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 1.9 µs | 2.2 µs | 1 |  | 1.10× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 1.8 µs | 2.1 µs | 1 |  | 1.20× | ✓ |
| fors | `fors.v0` lib | 111.8 µs | 125.8 µs | 1 | 2.3% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 131.8 µs | 122.6 µs | 1 |  | 1.04× | ✓ |
| fors | `fors.v2` march-native | 100.2 µs | 126.4 µs | 1 |  | 1.01× | ✓ |
| fors | `fors.v3` clang-native | 118.6 µs | 119.6 µs | 1 |  | 1.05× | ✓ |
| fors | `fors.v4` gcc-pgo | 95.6 µs | 109.4 µs | 1 |  | 1.15× | ✓ |
| fors | `fors.v5` gcc-lto | 96.3 µs | 117.8 µs | 1 |  | 1.07× | ✓ |
| ht_wots | `ht_wots.v0` lib | 2.61 ms | 3.34 ms | 1 | 53.5% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 1.69 ms | 1.80 ms | 1 |  | 1.85× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 2.28 ms | 2.44 ms | 1 |  | 1.37× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 2.23 ms | 2.35 ms | 1 |  | 1.41× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 2.27 ms | 2.38 ms | 1 |  | 1.35× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 2.21 ms | 2.28 ms | 1 |  | 1.47× | ✓ |
| ht_auth | `ht_auth.v0` lib | 24.7 µs | 27.7 µs | 1 | 0.5% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 17.8 µs | 19.5 µs | 1 |  | 1.43× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 21.2 µs | 23.1 µs | 1 |  | 1.22× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 20.1 µs | 21.5 µs | 1 |  | 1.30× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 21.3 µs | 22.8 µs | 1 |  | 1.23× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 21.1 µs | 22.5 µs | 1 |  | 1.25× | ✓ |

### SLH-DSA-SHA2-256s

end-to-end v0 stages: 2.41 ms, best assembled: 1.95 ms (1.23×), coverage 105%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 2.2 µs | 2.7 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 1.5 µs | 1.8 µs | 1 |  | 1.56× | ✓ |
| hmsg | `hmsg.v2` march-native | 1.8 µs | 2.1 µs | 1 |  | 1.30× | ✓ |
| hmsg | `hmsg.v3` clang-native | 1.7 µs | 1.9 µs | 1 |  | 1.45× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 1.9 µs | 2.1 µs | 1 |  | 1.31× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 1.8 µs | 1.9 µs | 1 |  | 1.41× | ✓ |
| fors | `fors.v0` lib | 123.6 µs | 133.1 µs | 1 | 5.1% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 88.4 µs | 101.9 µs | 1 |  | 1.31× | ✓ |
| fors | `fors.v2` march-native | 107.0 µs | 116.6 µs | 1 |  | 1.15× | ✓ |
| fors | `fors.v3` clang-native | 127.1 µs | 134.4 µs | 1 |  | 0.99× | ✓ |
| fors | `fors.v4` gcc-pgo | 105.9 µs | 121.8 µs | 1 |  | 1.10× | ✓ |
| fors | `fors.v5` gcc-lto | 104.9 µs | 115.3 µs | 1 |  | 1.15× | ✓ |
| ht_wots | `ht_wots.v0` lib | 2.38 ms | 2.14 ms | 1 | 98.7% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 813.5 µs | 849.1 µs | 1 |  | 2.52× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 1.05 ms | 1.18 ms | 1 |  | 1.81× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 1.07 ms | 1.18 ms | 1 |  | 1.75× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 1.05 ms | 1.14 ms | 1 |  | 1.87× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 1.06 ms | 1.14 ms | 1 |  | 1.86× | ✓ |
| ht_auth | `ht_auth.v0` lib | 23.8 µs | 32.9 µs | 1 | 1.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 17.2 µs | 23.2 µs | 1 |  | 1.43× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 20.2 µs | 22.7 µs | 1 |  | 1.44× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 19.1 µs | 21.2 µs | 1 |  | 1.55× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 20.3 µs | 22.0 µs | 1 |  | 1.50× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 20.3 µs | 23.2 µs | 1 |  | 1.42× | ✓ |

### SLH-DSA-SHA2-256f

end-to-end v0 stages: 4.83 ms, best assembled: 3.77 ms (1.28×), coverage 57%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 3.6 µs | 3.6 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 1.5 µs | 1.8 µs | 1 |  | 1.96× | ✓ |
| hmsg | `hmsg.v2` march-native | 1.8 µs | 2.0 µs | 1 |  | 1.75× | ✓ |
| hmsg | `hmsg.v3` clang-native | 1.7 µs | 1.9 µs | 1 |  | 1.93× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 1.9 µs | 2.2 µs | 1 |  | 1.61× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 1.8 µs | 2.0 µs | 1 |  | 1.83× | ✓ |
| fors | `fors.v0` lib | 132.3 µs | 149.9 µs | 1 | 2.7% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 93.9 µs | 112.0 µs | 1 |  | 1.35× | ✓ |
| fors | `fors.v2` march-native | 114.1 µs | 129.7 µs | 1 |  | 1.15× | ✓ |
| fors | `fors.v3` clang-native | 110.3 µs | 126.6 µs | 1 |  | 1.17× | ✓ |
| fors | `fors.v4` gcc-pgo | 112.5 µs | 122.2 µs | 1 |  | 1.24× | ✓ |
| fors | `fors.v5` gcc-lto | 128.6 µs | 154.0 µs | 1 |  | 0.98× | ✓ |
| ht_wots | `ht_wots.v0` lib | 2.57 ms | 3.52 ms | 1 | 53.2% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 1.69 ms | 1.74 ms | 1 |  | 2.04× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 2.18 ms | 2.27 ms | 1 |  | 1.55× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 2.16 ms | 2.20 ms | 1 |  | 1.60× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 2.26 ms | 2.48 ms | 1 |  | 1.40× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 2.21 ms | 2.47 ms | 1 |  | 1.42× | ✓ |
| ht_auth | `ht_auth.v0` lib | 25.2 µs | 31.3 µs | 1 | 0.5% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 18.2 µs | 19.9 µs | 1 |  | 1.63× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 21.5 µs | 25.7 µs | 1 |  | 1.26× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 20.4 µs | 23.5 µs | 1 |  | 1.38× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 21.6 µs | 23.7 µs | 1 |  | 1.36× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 21.6 µs | 24.1 µs | 1 |  | 1.34× | ✓ |

### SLH-DSA-SHAKE-128s

end-to-end v0 stages: 1.81 ms, best assembled: 1.72 ms (1.06×), coverage 52%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 0.5 µs | 0.6 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 0.6 µs | 0.7 µs | 1 |  | 0.90× | ✓ |
| hmsg | `hmsg.v2` march-native | 0.5 µs | 0.8 µs | 1 |  | 0.73× | ✓ |
| hmsg | `hmsg.v3` clang-native | 0.5 µs | 0.6 µs | 1 |  | 1.07× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 0.5 µs | 0.7 µs | 1 |  | 0.87× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 0.5 µs | 0.5 µs | 1 |  | 1.17× | ✓ |
| fors | `fors.v0` lib | 89.4 µs | 113.1 µs | 1 | 4.9% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 80.9 µs | 85.8 µs | 1 |  | 1.32× | ✓ |
| fors | `fors.v2` march-native | 77.3 µs | 94.1 µs | 1 |  | 1.20× | ✓ |
| fors | `fors.v3` clang-native | 83.7 µs | 104.2 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v4` gcc-pgo | 75.8 µs | 80.5 µs | 1 |  | 1.40× | ✓ |
| fors | `fors.v5` gcc-lto | 75.9 µs | 83.8 µs | 1 |  | 1.34× | ✓ |
| ht_wots | `ht_wots.v0` lib | 816.3 µs | 943.0 µs | 1 | 45.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 756.7 µs | 811.0 µs | 1 |  | 1.16× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 732.2 µs | 851.9 µs | 1 |  | 1.11× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 714.6 µs | 812.2 µs | 1 |  | 1.18× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 671.7 µs | 709.5 µs | 1 |  | 1.35× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 666.6 µs | 691.3 µs | 1 |  | 1.37× | ✓ |
| ht_auth | `ht_auth.v0` lib | 30.7 µs | 36.5 µs | 1 | 1.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 27.8 µs | 29.9 µs | 1 |  | 1.25× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 26.1 µs | 27.9 µs | 1 |  | 1.35× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 28.6 µs | 35.4 µs | 1 |  | 1.05× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 25.9 µs | 28.2 µs | 1 |  | 1.32× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 25.8 µs | 27.9 µs | 1 |  | 1.33× | ✓ |

### SLH-DSA-SHAKE-128f

end-to-end v0 stages: 5.82 ms, best assembled: 5.06 ms (1.15×), coverage 104%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 0.5 µs | 0.6 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 0.7 µs | 0.7 µs | 1 |  | 0.83× | ✓ |
| hmsg | `hmsg.v2` march-native | 0.5 µs | 0.6 µs | 1 |  | 1.02× | ✓ |
| hmsg | `hmsg.v3` clang-native | 0.5 µs | 0.7 µs | 1 |  | 0.89× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 0.5 µs | 0.6 µs | 1 |  | 1.10× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 0.5 µs | 0.5 µs | 1 |  | 1.10× | ✓ |
| fors | `fors.v0` lib | 114.6 µs | 143.4 µs | 1 | 2.0% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 103.4 µs | 113.3 µs | 1 |  | 1.26× | ✓ |
| fors | `fors.v2` march-native | 98.7 µs | 115.5 µs | 1 |  | 1.23× | ✓ |
| fors | `fors.v3` clang-native | 106.3 µs | 118.9 µs | 1 |  | 1.21× | ✓ |
| fors | `fors.v4` gcc-pgo | 96.9 µs | 112.6 µs | 1 |  | 1.27× | ✓ |
| fors | `fors.v5` gcc-lto | 97.3 µs | 121.3 µs | 1 |  | 1.17× | ✓ |
| ht_wots | `ht_wots.v0` lib | 5.91 ms | 4.65 ms | 1 | 101.5% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 2.43 ms | 2.44 ms | 1 |  | 1.90× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 2.41 ms | 2.73 ms | 1 |  | 1.70× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 2.55 ms | 3.05 ms | 1 |  | 1.52× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 2.39 ms | 2.70 ms | 1 |  | 1.72× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 2.36 ms | 2.41 ms | 1 |  | 1.91× | ✓ |
| ht_auth | `ht_auth.v0` lib | 32.3 µs | 37.5 µs | 1 | 0.6% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 29.3 µs | 31.6 µs | 1 |  | 1.19× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 27.5 µs | 28.6 µs | 1 |  | 1.32× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 30.0 µs | 31.8 µs | 1 |  | 1.18× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 27.4 µs | 35.1 µs | 1 |  | 1.06× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 27.3 µs | 32.5 µs | 1 |  | 1.16× | ✓ |

### SLH-DSA-SHAKE-192s

end-to-end v0 stages: 2.75 ms, best assembled: 2.37 ms (1.16×), coverage 53%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 1.0 µs | 1.5 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 0.9 µs | 1.0 µs | 1 |  | 1.53× | ✓ |
| hmsg | `hmsg.v2` march-native | 0.8 µs | 0.9 µs | 1 |  | 1.60× | ✓ |
| hmsg | `hmsg.v3` clang-native | 0.9 µs | 1.0 µs | 1 |  | 1.37× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 0.9 µs | 1.2 µs | 1 |  | 1.23× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 0.8 µs | 0.9 µs | 1 |  | 1.62× | ✓ |
| fors | `fors.v0` lib | 129.4 µs | 135.8 µs | 1 | 4.7% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 118.3 µs | 125.5 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v2` march-native | 112.9 µs | 127.5 µs | 1 |  | 1.07× | ✓ |
| fors | `fors.v3` clang-native | 119.2 µs | 133.5 µs | 1 |  | 1.02× | ✓ |
| fors | `fors.v4` gcc-pgo | 112.5 µs | 137.1 µs | 1 |  | 0.99× | ✓ |
| fors | `fors.v5` gcc-lto | 112.1 µs | 140.0 µs | 1 |  | 0.94× | ✓ |
| ht_wots | `ht_wots.v0` lib | 1.31 ms | 1.48 ms | 1 | 47.5% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 1.18 ms | 1.21 ms | 1 |  | 1.23× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 1.04 ms | 1.12 ms | 1 |  | 1.33× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 1.18 ms | 1.38 ms | 1 |  | 1.07× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 1.03 ms | 1.15 ms | 1 |  | 1.30× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 1.03 ms | 1.17 ms | 1 |  | 1.28× | ✓ |
| ht_auth | `ht_auth.v0` lib | 31.7 µs | 36.2 µs | 1 | 1.2% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 29.0 µs | 31.3 µs | 1 |  | 1.13× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 27.1 µs | 30.3 µs | 1 |  | 1.19× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 29.6 µs | 33.0 µs | 1 |  | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 27.0 µs | 28.8 µs | 1 |  | 1.25× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 27.0 µs | 29.3 µs | 1 |  | 1.23× | ✓ |

### SLH-DSA-SHAKE-192f

end-to-end v0 stages: 7.98 ms, best assembled: 6.96 ms (1.15×), coverage 53%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 1.0 µs | 1.2 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 0.9 µs | 1.0 µs | 1 |  | 1.29× | ✓ |
| hmsg | `hmsg.v2` march-native | 0.8 µs | 0.9 µs | 1 |  | 1.33× | ✓ |
| hmsg | `hmsg.v3` clang-native | 0.9 µs | 1.0 µs | 1 |  | 1.20× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 0.8 µs | 0.9 µs | 1 |  | 1.32× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 0.8 µs | 0.9 µs | 1 |  | 1.34× | ✓ |
| fors | `fors.v0` lib | 153.2 µs | 168.4 µs | 1 | 1.9% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 138.8 µs | 147.6 µs | 1 |  | 1.13× | ✓ |
| fors | `fors.v2` march-native | 132.1 µs | 142.3 µs | 1 |  | 1.18× | ✓ |
| fors | `fors.v3` clang-native | 141.3 µs | 158.3 µs | 1 |  | 1.07× | ✓ |
| fors | `fors.v4` gcc-pgo | 133.0 µs | 155.5 µs | 1 |  | 1.07× | ✓ |
| fors | `fors.v5` gcc-lto | 131.6 µs | 168.0 µs | 1 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v0` lib | 4.02 ms | 4.43 ms | 1 | 50.3% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 3.39 ms | 3.51 ms | 1 |  | 1.27× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 3.25 ms | 3.67 ms | 1 |  | 1.20× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 3.43 ms | 3.57 ms | 1 |  | 1.25× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 3.19 ms | 3.58 ms | 1 |  | 1.23× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 3.19 ms | 3.43 ms | 1 |  | 1.30× | ✓ |
| ht_auth | `ht_auth.v0` lib | 33.5 µs | 36.9 µs | 1 | 0.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 37.5 µs | 38.1 µs | 1 |  | 0.97× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 28.8 µs | 35.2 µs | 1 |  | 1.04× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 31.3 µs | 33.9 µs | 1 |  | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 28.7 µs | 32.8 µs | 1 |  | 1.10× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 28.6 µs | 32.7 µs | 1 |  | 1.13× | ✓ |

### SLH-DSA-SHAKE-256s

end-to-end v0 stages: 3.91 ms, best assembled: 3.44 ms (1.14×), coverage 54%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 1.0 µs | 1.1 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 0.9 µs | 1.0 µs | 1 |  | 1.08× | ✓ |
| hmsg | `hmsg.v2` march-native | 0.8 µs | 1.0 µs | 1 |  | 1.10× | ✓ |
| hmsg | `hmsg.v3` clang-native | 0.9 µs | 1.1 µs | 1 |  | 1.01× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 1.4 µs | 1.5 µs | 1 |  | 0.70× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 0.8 µs | 1.0 µs | 1 |  | 1.13× | ✓ |
| fors | `fors.v0` lib | 176.1 µs | 200.8 µs | 1 | 4.5% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 175.9 µs | 184.9 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v2` march-native | 150.8 µs | 155.9 µs | 1 |  | 1.28× | ✓ |
| fors | `fors.v3` clang-native | 160.4 µs | 180.3 µs | 1 |  | 1.11× | ✓ |
| fors | `fors.v4` gcc-pgo | 152.9 µs | 182.7 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v5` gcc-lto | 152.1 µs | 162.7 µs | 1 |  | 1.23× | ✓ |
| ht_wots | `ht_wots.v0` lib | 1.88 ms | 1.91 ms | 1 | 48.2% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 1.77 ms | 1.86 ms | 1 |  | 1.02× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 1.54 ms | 1.54 ms | 1 |  | 1.24× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 1.69 ms | 1.79 ms | 1 |  | 1.06× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 1.54 ms | 1.56 ms | 1 |  | 1.21× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 1.55 ms | 1.61 ms | 1 |  | 1.19× | ✓ |
| ht_auth | `ht_auth.v0` lib | 33.4 µs | 36.6 µs | 1 | 0.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 30.7 µs | 33.6 µs | 1 |  | 1.08× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 28.6 µs | 30.4 µs | 1 |  | 1.20× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 30.9 µs | 32.7 µs | 1 |  | 1.12× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 28.7 µs | 30.6 µs | 1 |  | 1.20× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 28.6 µs | 29.9 µs | 1 |  | 1.23× | ✓ |

### SLH-DSA-SHAKE-256f

end-to-end v0 stages: 8.12 ms, best assembled: 7.25 ms (1.12×), coverage 56%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` lib | 1.0 µs | 1.1 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` fasthash | 0.9 µs | 1.0 µs | 1 |  | 1.10× | ✓ |
| hmsg | `hmsg.v2` march-native | 0.8 µs | 1.0 µs | 1 |  | 1.11× | ✓ |
| hmsg | `hmsg.v3` clang-native | 0.9 µs | 1.0 µs | 1 |  | 1.05× | ✓ |
| hmsg | `hmsg.v4` gcc-pgo | 0.9 µs | 1.4 µs | 1 |  | 0.77× | ✓ |
| hmsg | `hmsg.v5` gcc-lto | 0.8 µs | 0.9 µs | 1 |  | 1.15× | ✓ |
| fors | `fors.v0` lib | 188.4 µs | 204.7 µs | 1 | 2.3% | 1.00× | ✓ |
| fors | `fors.v1` fasthash | 172.9 µs | 184.1 µs | 1 |  | 1.09× | ✓ |
| fors | `fors.v2` march-native | 163.4 µs | 193.6 µs | 1 |  | 1.06× | ✓ |
| fors | `fors.v3` clang-native | 173.1 µs | 199.0 µs | 1 |  | 1.01× | ✓ |
| fors | `fors.v4` gcc-pgo | 163.7 µs | 180.2 µs | 1 |  | 1.11× | ✓ |
| fors | `fors.v5` gcc-lto | 162.8 µs | 188.4 µs | 1 |  | 1.08× | ✓ |
| ht_wots | `ht_wots.v0` lib | 4.30 ms | 5.18 ms | 1 | 53.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fasthash | 3.59 ms | 3.73 ms | 1 |  | 1.42× | ✓ |
| ht_wots | `ht_wots.v2` march-native | 3.30 ms | 3.34 ms | 1 |  | 1.59× | ✓ |
| ht_wots | `ht_wots.v3` clang-native | 3.60 ms | 3.73 ms | 1 |  | 1.42× | ✓ |
| ht_wots | `ht_wots.v4` gcc-pgo | 3.37 ms | 3.96 ms | 1 |  | 1.33× | ✓ |
| ht_wots | `ht_wots.v5` gcc-lto | 3.29 ms | 3.30 ms | 1 |  | 1.61× | ✓ |
| ht_auth | `ht_auth.v0` lib | 35.6 µs | 38.8 µs | 1 | 0.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fasthash | 32.7 µs | 34.8 µs | 1 |  | 1.11× | ✓ |
| ht_auth | `ht_auth.v2` march-native | 30.7 µs | 36.6 µs | 1 |  | 1.05× | ✓ |
| ht_auth | `ht_auth.v3` clang-native | 33.1 µs | 35.2 µs | 1 |  | 1.10× | ✓ |
| ht_auth | `ht_auth.v4` gcc-pgo | 30.7 µs | 37.9 µs | 1 |  | 1.01× | ✓ |
| ht_auth | `ht_auth.v5` gcc-lto | 30.6 µs | 34.2 µs | 1 |  | 1.12× | ✓ |

