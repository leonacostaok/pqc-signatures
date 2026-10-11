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

## Results (PRELIMINARY dev run, small budget, shared machine; regenerated by the orchestrator)

### Stage share of the v0 pipeline (median wall per stage)

| param | decode | mu | expandA | w_approx | hint_check | hmsg | fors | ht_wots | ht_auth | total | total_best |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 0.7 µs | 2.8 µs | 6.6 µs | 4.6 µs | 2.9 µs | — | — | — | — | 17.9 µs | 8.1 µs |
| ML-DSA-65 | 1.0 µs | 4.0 µs | 14.0 µs | 6.4 µs | 2.6 µs | — | — | — | — | 57.4 µs | 14.8 µs |
| ML-DSA-87 | 1.4 µs | 5.2 µs | 22.9 µs | 8.7 µs | 5.5 µs | — | — | — | — | 178.6 µs | 13.4 µs |
| SLH-DSA-SHA2-128s | — | — | — | — | — | 1.4 µs | 52.3 µs | 497.7 µs | 26.5 µs | 1.86 ms | 807.8 µs |
| SLH-DSA-SHA2-128f | — | — | — | — | — | 1.9 µs | 67.8 µs | 1.61 ms | 18.3 µs | 7.46 ms | 2.48 ms |
| SLH-DSA-SHAKE-128f | — | — | — | — | — | 0.6 µs | 115.8 µs | 6.83 ms | 32.7 µs | 15.36 ms | 9.71 ms |
| SLH-DSA-SHAKE-256s | — | — | — | — | — | 1.0 µs | 342.5 µs | 4.47 ms | 33.6 µs | 9.02 ms | 8.65 ms |

### Stage variants (speedup = throughput vs the stage's v0, geometric mean over params; match = canonical output equals v0)

#### decode

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `decode.v0` | lib-x86_64 | 1.00× | ML-DSA-44 0.7 µs, ML-DSA-65 1.0 µs, ML-DSA-87 1.4 µs | yes |
| `decode.v1` | lib-c | 0.34× | ML-DSA-44 1.6 µs, ML-DSA-65 4.3 µs, ML-DSA-87 2.8 µs | yes |
| `decode.v2` | march-native | 0.82× | ML-DSA-44 0.7 µs, ML-DSA-65 1.0 µs, ML-DSA-87 1.3 µs | yes |
| `decode.v3` | clang-native | 1.17× | ML-DSA-44 0.4 µs, ML-DSA-65 0.6 µs, ML-DSA-87 0.8 µs | yes |
| `decode.v4` | gcc-pgo | 0.62× | ML-DSA-44 0.7 µs, ML-DSA-65 0.9 µs, ML-DSA-87 3.2 µs | yes |
| `decode.v5` | gcc-lto | 0.82× | ML-DSA-44 0.7 µs, ML-DSA-65 0.9 µs, ML-DSA-87 1.3 µs | yes |

#### mu

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `mu.v0` | lib-shake | 1.00× | ML-DSA-44 2.8 µs, ML-DSA-65 4.0 µs, ML-DSA-87 5.2 µs | yes |
| `mu.v1` | openssl-shake | 0.62× | ML-DSA-44 4.8 µs, ML-DSA-65 13.0 µs, ML-DSA-87 8.2 µs | yes |
| `mu.v2` | cached-tr | 10.79× | ML-DSA-44 0.3 µs, ML-DSA-65 0.4 µs, ML-DSA-87 0.4 µs | yes |
| `mu.v3` | xkcp-avx2 | 0.67× | ML-DSA-44 4.0 µs, ML-DSA-65 5.7 µs, ML-DSA-87 7.4 µs | yes |
| `mu.v4` | gcc-pgo | 1.20× | ML-DSA-44 2.8 µs, ML-DSA-65 4.0 µs, ML-DSA-87 5.2 µs | yes |
| `mu.v5` | clang-native | 1.06× | ML-DSA-44 4.1 µs, ML-DSA-65 4.1 µs, ML-DSA-87 5.2 µs | yes |

#### expandA

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `expandA.v0` | lib-4way | 1.00× | ML-DSA-44 6.6 µs, ML-DSA-65 14.0 µs, ML-DSA-87 22.9 µs | yes |
| `expandA.v1` | lib-c | 0.54× | ML-DSA-44 9.7 µs, ML-DSA-65 20.5 µs, ML-DSA-87 35.4 µs | yes |
| `expandA.v2` | oneway-shake | 0.30× | ML-DSA-44 21.3 µs, ML-DSA-65 39.8 µs, ML-DSA-87 74.4 µs | yes |
| `expandA.v3` | cached-A | 22.64× | ML-DSA-44 0.1 µs, ML-DSA-65 0.7 µs, ML-DSA-87 1.3 µs | yes |
| `expandA.v4` | xkcp-avx2-x4 | 0.37× | ML-DSA-44 9.8 µs, ML-DSA-65 20.6 µs, ML-DSA-87 34.1 µs | yes |
| `expandA.v5` | gcc-pgo | 0.80× | ML-DSA-44 6.5 µs, ML-DSA-65 14.4 µs, ML-DSA-87 22.8 µs | yes |

#### w_approx

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `w_approx.v0` | lib-x86_64 | 1.00× | ML-DSA-44 4.6 µs, ML-DSA-65 6.4 µs, ML-DSA-87 8.7 µs | yes |
| `w_approx.v1` | lib-c | 0.14× | ML-DSA-44 28.3 µs, ML-DSA-65 40.3 µs, ML-DSA-87 55.5 µs | yes |
| `w_approx.v2` | cached-t1hat | 1.92× | ML-DSA-44 3.6 µs, ML-DSA-65 4.9 µs, ML-DSA-87 6.7 µs | yes |
| `w_approx.v3` | march-native | 1.10× | ML-DSA-44 4.6 µs, ML-DSA-65 6.4 µs, ML-DSA-87 8.7 µs | yes |
| `w_approx.v4` | gcc-lto | 0.92× | ML-DSA-44 4.6 µs, ML-DSA-65 6.4 µs, ML-DSA-87 8.7 µs | yes |
| `w_approx.v5` | clang-native | 0.87× | ML-DSA-44 4.5 µs, ML-DSA-65 6.4 µs, ML-DSA-87 8.8 µs | yes |

#### hint_check

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `hint_check.v0` | lib-x86_64 | 1.00× | ML-DSA-44 2.9 µs, ML-DSA-65 2.6 µs, ML-DSA-87 5.5 µs | yes |
| `hint_check.v1` | lib-c | 0.65× | ML-DSA-44 5.7 µs, ML-DSA-65 6.0 µs, ML-DSA-87 7.8 µs | yes |
| `hint_check.v2` | openssl-shake | 0.61× | ML-DSA-44 8.4 µs, ML-DSA-65 7.8 µs, ML-DSA-87 9.8 µs | yes |
| `hint_check.v3` | xkcp-avx2 | 0.32× | ML-DSA-44 4.0 µs, ML-DSA-65 4.5 µs, ML-DSA-87 4.2 µs | yes |
| `hint_check.v4` | gcc-pgo | 0.78× | ML-DSA-44 2.8 µs, ML-DSA-65 2.6 µs, ML-DSA-87 3.3 µs | yes |
| `hint_check.v5` | clang-native | 1.38× | ML-DSA-44 2.5 µs, ML-DSA-65 2.3 µs, ML-DSA-87 3.0 µs | yes |

#### hmsg

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `hmsg.v0` | lib | 1.00× | SHA2-128s 1.4 µs, SHA2-128f 1.9 µs, SHAKE-128f 0.6 µs, SHAKE-256s 1.0 µs | yes |
| `hmsg.v1` | fasthash | 1.21× | SHA2-128s 1.0 µs, SHA2-128f 1.4 µs, SHAKE-128f 0.5 µs, SHAKE-256s 0.9 µs | yes |
| `hmsg.v2` | march-native | 1.09× | SHA2-128s 1.2 µs, SHA2-128f 1.7 µs, SHAKE-128f 0.7 µs, SHAKE-256s 0.9 µs | yes |
| `hmsg.v3` | clang-native | 1.30× | SHA2-128s 1.2 µs, SHA2-128f 1.6 µs, SHAKE-128f 0.5 µs, SHAKE-256s 0.9 µs | yes |
| `hmsg.v4` | gcc-pgo | 0.99× | SHA2-128s 1.3 µs, SHA2-128f 1.7 µs, SHAKE-128f 0.5 µs, SHAKE-256s 0.8 µs | yes |
| `hmsg.v5` | gcc-lto | 1.11× | SHA2-128s 1.2 µs, SHA2-128f 3.1 µs, SHAKE-128f 0.5 µs, SHAKE-256s 0.8 µs | yes |

#### fors

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `fors.v0` | lib | 1.00× | SHA2-128s 52.3 µs, SHA2-128f 67.8 µs, SHAKE-128f 115.8 µs, SHAKE-256s 342.5 µs | yes |
| `fors.v1` | fasthash | 1.31× | SHA2-128s 38.5 µs, SHA2-128f 49.8 µs, SHAKE-128f 102.5 µs, SHAKE-256s 158.2 µs | yes |
| `fors.v2` | march-native | 1.03× | SHA2-128s 47.1 µs, SHA2-128f 61.1 µs, SHAKE-128f 97.6 µs, SHAKE-256s 150.6 µs | yes |
| `fors.v3` | clang-native | 1.30× | SHA2-128s 44.6 µs, SHA2-128f 57.9 µs, SHAKE-128f 108.1 µs, SHAKE-256s 159.8 µs | yes |
| `fors.v4` | gcc-pgo | 1.49× | SHA2-128s 45.9 µs, SHA2-128f 59.2 µs, SHAKE-128f 98.5 µs, SHAKE-256s 178.8 µs | yes |
| `fors.v5` | gcc-lto | 0.84× | SHA2-128s 46.3 µs, SHA2-128f 59.8 µs, SHAKE-128f 179.1 µs, SHAKE-256s 167.5 µs | yes |

#### ht_wots

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `ht_wots.v0` | lib | 1.00× | SHA2-128s 497.7 µs, SHA2-128f 1.61 ms, SHAKE-128f 6.83 ms, SHAKE-256s 4.47 ms | yes |
| `ht_wots.v1` | fasthash | 1.17× | SHA2-128s 386.3 µs, SHA2-128f 1.26 ms, SHAKE-128f 6.50 ms, SHAKE-256s 1.61 ms | yes |
| `ht_wots.v2` | march-native | 1.08× | SHA2-128s 477.0 µs, SHA2-128f 1.52 ms, SHAKE-128f 5.48 ms, SHAKE-256s 2.26 ms | yes |
| `ht_wots.v3` | clang-native | 0.94× | SHA2-128s 492.5 µs, SHA2-128f 1.55 ms, SHAKE-128f 3.18 ms, SHAKE-256s 4.87 ms | yes |
| `ht_wots.v4` | gcc-pgo | 1.04× | SHA2-128s 515.1 µs, SHA2-128f 1.76 ms, SHAKE-128f 2.39 ms, SHAKE-256s 1.57 ms | yes |
| `ht_wots.v5` | gcc-lto | 1.02× | SHA2-128s 474.8 µs, SHA2-128f 1.53 ms, SHAKE-128f 5.12 ms, SHAKE-256s 1.57 ms | yes |

#### ht_auth

| variant | name | geomean speedup | per param (median) | all match |
|---|---|---|---|---|
| `ht_auth.v0` | lib | 1.00× | SHA2-128s 26.5 µs, SHA2-128f 18.3 µs, SHAKE-128f 32.7 µs, SHAKE-256s 33.6 µs | yes |
| `ht_auth.v1` | fasthash | 1.37× | SHA2-128s 13.2 µs, SHA2-128f 14.0 µs, SHAKE-128f 29.1 µs, SHAKE-256s 30.3 µs | yes |
| `ht_auth.v2` | march-native | 1.61× | SHA2-128s 16.1 µs, SHA2-128f 16.9 µs, SHAKE-128f 27.6 µs, SHAKE-256s 28.6 µs | yes |
| `ht_auth.v3` | clang-native | 1.34× | SHA2-128s 15.2 µs, SHA2-128f 24.9 µs, SHAKE-128f 33.7 µs, SHAKE-256s 30.3 µs | yes |
| `ht_auth.v4` | gcc-pgo | 1.03× | SHA2-128s 15.7 µs, SHA2-128f 16.6 µs, SHAKE-128f 53.4 µs, SHAKE-256s 29.0 µs | yes |
| `ht_auth.v5` | gcc-lto | 1.15× | SHA2-128s 16.0 µs, SHA2-128f 17.1 µs, SHAKE-128f 27.5 µs, SHAKE-256s 28.7 µs | yes |

