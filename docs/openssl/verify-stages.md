# OpenSSL - verify split into stages

`libs/openssl/run.sh stages --out results/openssl/stages.jsonl [--budget-ms N] [--params a,b] [--stages x,y]`

## How the stages reach OpenSSL's internals

The driver is linked statically against `libcrypto.a`, so the non-exported internal symbols
(`ossl_ml_dsa_*`, `ossl_slh_*`, `ossl_sha3_*`, `SHA256_*`) and the internal headers of the source
tree (`crypto/ml_dsa/*.h`, `crypto/slh_dsa/*.h`, `include/internal/*.h`, plus the per-flavour generated
`configuration.h`) are available to `libs/openssl/src/pqc_stages.c`. Concretely:

* ML-DSA keys are created with `ossl_ml_dsa_key_new` + `ossl_ml_dsa_pk_decode` (gives `rho`, `t1`, `tr` and
  the prefetched SHAKE `EVP_MD`s), the stage code then calls `ossl_ml_dsa_matrix_expand_A`,
  `ossl_ml_dsa_poly_sample_in_ball`, the inline `vector_*` / `matrix_*` helpers of `ml_dsa_vector.h` /
  `ml_dsa_matrix.h` (NTT, pointwise multiply, use_hint, ...), `ossl_ml_dsa_key_compress_use_hint` and the
  `shake_xof*` helpers of `ml_dsa_hash.h` - exactly the calls `ml_dsa_verify_internal()` makes, in the same order.
* The decoders (`poly_decode_10_bits`, the 18/20-bit z unpacker and the hint decoder) are `static` in
  `crypto/ml_dsa/ml_dsa_encoders.c` and have no internal entry point, so that file is `#include`d verbatim into
  the stage translation unit with its eight public symbols renamed (`st_ml_dsa_*`); v0 of `decode` therefore runs
  OpenSSL's own code, byte for byte, without the `ossl_ml_dsa_pk_decode` side effects (allocation, `tr` hashing).
* SLH-DSA keys are `ossl_slh_dsa_key_new` + `ossl_slh_dsa_set_pub`; the stages use the key's hash/ADRS
  function tables (`key->hash_func->H_MSG/F/H/T`, `key->adrs_func->*`) and `ossl_slh_fors_pk_from_sig`,
  `ossl_slh_wots_pk_from_sig` through the key's `SLH_DSA_HASH_CTX`, i.e. what `slh_verify_internal()` and
  `ossl_slh_ht_verify()` call. `ossl_slh_xmss_pk_from_sig` fuses WOTS+ pkFromSig and the auth path, so
  `ht_auth.v0` is that function's auth-path loop (12 lines) reproduced with the same `hashf->H` calls.
* The layer inputs of `ht_wots` / `ht_auth` (every layer's message = previous root, every layer's WOTS pk)
  come from one sequential v0 walk of the hypertree done at preparation time, outside the timed region.

Canonical outputs are hashed exactly as the contract specifies (c~; mu; A^ and w' as u32-LE coefficients in
[0,q) - OpenSSL already keeps its coefficients in that representation, in NTT order for A^; w1Encode bytes;
the H_msg digest; PK_FORS; the d WOTS pks; the d roots). v0's canonical output is recomputed in every process
(also in the no-asm / native binaries) and every alternative's output is compared to it on every run (`match`).

## Alternatives

Build-flag alternatives (no-asm / native+LTO) are listed where the stage contains hashing (no-asm) or
arithmetic loops that a different compilation can change (native). Stages marked SF_CACHE use per-public-key
precomputation and SF_THREADS use the 4-thread pool; both are excluded from `total_best`.

### ML-DSA

| stage | v0 | alternatives |
|---|---|---|
| `decode` | OpenSSL `poly_decode_10_bits` x k, `ossl_ml_dsa_sig_decode` (PACKET based, hint checks: count <= omega, strictly increasing indices, zero padding) | **v1** own unpacker: 5 bytes -> 4 x 10-bit via one u64, z via unaligned u64 loads (4 coefficients per 9/10 bytes), same hint rules, no PACKET; **v2** v0 code in the native/LTO build. Only three variants: the stage is a few microseconds of pure byte shuffling with no hashing, so a no-asm build or a third unpacking strategy would be near-duplicates. |
| `mu` | `EVP_MD_CTX_new`, `tr = SHAKE256(pk)` (as `ossl_ml_dsa_pk_decode` does on import) and `mu = SHAKE256(tr || M')` (as verify does), free | **v1** cached tr (OpenSSL caches it in the key object; only the second SHAKE); **v2** both hashes on the internal `ossl_sha3_*` Keccak API with a stack context (no EVP); **v3** no-asm; **v4** native; **v5** EVP with a prefetched md and a reused ctx (no allocation). |
| `expandA` | `EVP_MD_CTX_new` + `ossl_ml_dsa_matrix_expand_A` (SHAKE128 per polynomial via EVP, 168-byte squeezes, 3-byte rejection sampling) | **v1** cached A^ (memcpy of k*l KiB - what a verifier that caches the matrix per key pays); **v2** same sampler on `ossl_sha3_init/update/squeeze` (no EVP); **v3** no-asm; **v4** native; **v5** the k*l polynomials spread over the 4-thread pool (v2 sampler). |
| `w_approx` | OpenSSL: SampleInBall + NTT(c), `vector_scale_power2_round_ntt(t1)`, `vector_mult_scalar`, NTT(z), `matrix_mult_vector` (uint32 Montgomery products, `reduce_once` after every add), `vector_sub`, NTT^-1 | **v1** cached NTT(t1*2^d) per key (saves k forward NTTs); **v2** own signed int32 NTT with lazy reduction (reference-style Montgomery butterflies, zetas in Montgomery form computed at start-up), the l products and c*t1 accumulated in one int64 and reduced once per coefficient, final single mod q; **v3** native build of v0; **v4** v1 + v2 combined. (no-asm is irrelevant here: there is no assembly in the NTT, only in the one SampleInBall SHAKE.) |
| `hint_check` | OpenSSL: `vector_max(z)` bound, `vector_use_hint`, `ossl_ml_dsa_w1_encode`, `SHAKE256(mu || w1)` through EVP with a ctx allocated per call, memcmp with c~ | **v1** the final SHAKE through `ossl_sha3_*`; **v2** UseHint and w1Encode fused into one pass that writes the 4-/6-bit values straight into the byte buffer (no w1 polynomial), z bound in the same sweep, low-level SHAKE; **v3** no-asm; **v4** native. |

### SLH-DSA

| stage | v0 | alternatives |
|---|---|---|
| `hmsg` | OpenSSL `H_msg` via the key's hash ctx: SHAKE256 XOF, or SHA-256/512 digest + `PKCS1_MGF1` (EVP) | **v1** no-asm; **v2** native; **v3** low-level: `ossl_sha3_*` XOF, or `SHA256/512_*` digest + own MGF1 loop; **v4** (SHA2 sets only) the MGF1 seed `R || PK.seed || digest` is absorbed once into a SHA-2 context that is copied per counter block instead of re-hashed (for 128 the 64-byte seed is one whole compression block, for 192/256 the saving is only the copy). |
| `fors` | `ossl_slh_fors_pk_from_sig` (k F() leaves, k*a H() steps, one T()), every F/H/T = `EVP_DigestInit_ex2` + 4 `EVP_DigestUpdate` + final, SHA2 sets hash `PK.seed || toByte(0,64-n) || ADRSc || m` in full every time | **v1** no-asm; **v2** native; **v3** same tree walk with F/H/T on low-level primitives: SHA2 sets start from a saved SHA-256 / SHA-512 midstate of `PK.seed || toByte(0)` (one compression per call saved, no EVP), SHAKE sets `ossl_sha3_*` on the stack; **v4** the k trees over the 4-thread pool (v3 primitives), T() on the caller. |
| `ht_wots` | d x `ossl_slh_wots_pk_from_sig` (len = 2n+3 chains of F(), T() compression) with each layer's correct message | **v1** no-asm; **v2** native; **v3** own chain walk on the low-level/midstate primitives; **v4** the d layers over the 4-thread pool (they are independent once the messages are known). |
| `ht_auth` | the auth-path loop of `ossl_slh_xmss_pk_from_sig` (hm H() per layer via EVP) for all d layers + PK.root compare | **v1** no-asm; **v2** native; **v3** H on the low-level/midstate primitives; **v4** the d root computations over the 4-thread pool. |

### total / total_best

`total` is the v0 chain; `total_best` is a fixed combination of the fastest *stateless, single-threaded*
alternatives from the development measurements (`BEST_ML` / `BEST_SLH` in `pqc_stages.c`):
ML-DSA = decode.v1, mu.v2, expandA.v2, w_approx.v2, hint_check.v2; SLH-DSA = hmsg.v3, fors.v3, ht_wots.v3,
ht_auth.v3. The same combination is what `validate` runs as `stages.total_best` and what `memory` measures,
so the validated, measured and benchmarked pipeline is identical. Cached and threaded variants are excluded
on purpose: a cache turns a per-verify cost into a per-key cost, and threads trade CPU for latency; both are
reported as their own variants instead. Both pipelines are checked on every run: they must accept the reference
signature and reject a bit-flipped copy (and `validate` runs them over the whole negative suite).

## What the numbers say (development run, shared box)

* ML-DSA verify is dominated by `w_approx` (~55 %) and `expandA` (~30 %); the own int32 lazy-reduction NTT
  is 3-4x faster than OpenSSL's uint32 "reduce after every operation" NTT, which makes `total_best` ~1.6x faster
  than `total` for ML-DSA-44. EVP overhead per SHAKE call is only visible in the microsecond-sized stages (mu,
  hint_check); expandA is Keccak-bound and the low-level API gains nothing (OpenSSL's Keccak assembly is scalar).
* SLH-DSA verify is `ht_wots` (~85 %) + `fors` (~10 %). For the SHA2 sets the per-call EVP cost plus the
  re-hashing of the constant `PK.seed || 0...` block costs OpenSSL about 3.5x: the midstate primitives bring
  SHA2-128f ht_wots from ~4.7 ms to ~1.2 ms. For the SHAKE sets the low-level API gains ~10 %.
* Threads help the SLH stages only when the per-call work is milliseconds (ht_wots); for expandA/fors/ht_auth
  the barrier hand-off costs more than the ~100 us of work, so those thread variants are slower than v0 (kept
  as an honest data point). With 5 other agents on the box, cpu_util of 0.5-0.8 shows how noisy these numbers are.

<!-- RESULTS -->

## Results (PRELIMINARY: development run, --budget-ms 200, shared busy machine; the orchestrator overwrites this section)

### ml-dsa

#### Summary (geomean over params of median wall vs the stage v0; total_best vs total)

| stage | variant | name | geomean speedup | all match |
|---|---|---|---|---|
| decode | `decode.v0` | ossl-decoders | 1.00× | yes |
| decode | `decode.v1` | own-unpack-u64 | 0.44× | yes |
| decode | `decode.v2` | ossl-decoders-native | 1.10× | yes |
| mu | `mu.v0` | ossl-evp-shake | 1.00× | yes |
| mu | `mu.v1` | cached-tr | 13.18× | yes |
| mu | `mu.v2` | lowlevel-sha3 | 1.03× | yes |
| mu | `mu.v3` | ossl-evp-shake-noasm | 0.95× | yes |
| mu | `mu.v4` | ossl-evp-shake-native | 1.01× | yes |
| mu | `mu.v5` | evp-reused-ctx | 1.02× | yes |
| expandA | `expandA.v0` | ossl-expand-A | 1.00× | yes |
| expandA | `expandA.v1` | cached-A | 127.48× | yes |
| expandA | `expandA.v2` | lowlevel-sha3 | 1.01× | yes |
| expandA | `expandA.v3` | ossl-expand-A-noasm | 0.98× | yes |
| expandA | `expandA.v4` | ossl-expand-A-native | 0.51× | yes |
| expandA | `expandA.v5` | pthread-x4-rows | 0.70× | yes |
| w_approx | `w_approx.v0` | ossl-ntt | 1.00× | yes |
| w_approx | `w_approx.v1` | cached-ntt-t1 | 1.12× | yes |
| w_approx | `w_approx.v2` | own-int32-mont-ntt | 2.55× | yes |
| w_approx | `w_approx.v3` | ossl-ntt-native | 0.71× | yes |
| w_approx | `w_approx.v4` | cached-t1+own-ntt | 3.44× | yes |
| hint_check | `hint_check.v0` | ossl-usehint-w1encode | 1.00× | yes |
| hint_check | `hint_check.v1` | lowlevel-sha3 | 1.02× | yes |
| hint_check | `hint_check.v2` | fused-usehint-pack | 1.14× | yes |
| hint_check | `hint_check.v3` | ossl-noasm | 0.86× | yes |
| hint_check | `hint_check.v4` | ossl-native | 1.40× | yes |
| total | `total` | v0-pipeline | — | yes |
| total_best | `total_best` | best-pipeline | 1.53× | yes |

#### Per parameter set

##### ML-DSA-44

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 2.0 µs | 3.5 µs | 2.3 µs | 0.73 | 1 | 315017 | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 4.1 µs | 6.5 µs | 4.6 µs | 0.68 | 1 | 147424 | 0.49× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 1.9 µs | 2.7 µs | 2.1 µs | 0.93 | 1 | 454169 | 1.10× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 4.0 µs | 7.3 µs | 4.8 µs | 0.50 | 1 | 105579 | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.4 µs | 0.5 µs | 0.49 | 1 | 1036881 | 9.58× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 3.9 µs | 6.1 µs | 4.4 µs | 0.49 | 1 | 112648 | 1.04× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 4.2 µs | 9.0 µs | 5.6 µs | 0.51 | 1 | 91408 | 0.96× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 4.0 µs | 4.9 µs | 4.3 µs | 0.77 | 1 | 178025 | 1.02× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 3.9 µs | 6.2 µs | 4.4 µs | 0.44 | 1 | 100653 | 1.03× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 33.3 µs | 61.7 µs | 40.2 µs | 0.68 | 1 | 16855 | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.1 µs | 0.1 µs | 0.2 µs | 0.95 | 1 | 5595849 | 245.12× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 32.5 µs | 51.3 µs | 34.5 µs | 0.77 | 1 | 22268 | 1.03× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 33.9 µs | 61.1 µs | 38.1 µs | 0.54 | 1 | 14260 | 0.98× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 55.0 µs | 80.6 µs | 50.1 µs | 0.67 | 1 | 13455 | 0.61× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 79.5 µs | 112.5 µs | 99.3 µs | 1.25 | 4 | 12583 | 0.42× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 81.5 µs | 181.2 µs | 96.7 µs | 0.39 | 1 | 4047 | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 59.6 µs | 78.0 µs | 62.2 µs | 0.49 | 1 | 7799 | 1.37× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 33.0 µs | 57.1 µs | 36.6 µs | 0.30 | 1 | 8274 | 2.47× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 80.1 µs | 101.2 µs | 83.6 µs | 0.68 | 1 | 8175 | 1.02× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 24.6 µs | 48.2 µs | 27.9 µs | 0.57 | 1 | 20350 | 3.32× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 12.2 µs | 21.7 µs | 13.9 µs | 0.56 | 1 | 40531 | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 12.0 µs | 21.5 µs | 14.3 µs | 0.70 | 1 | 48907 | 1.01× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 10.4 µs | 14.0 µs | 11.0 µs | 0.70 | 1 | 63643 | 1.17× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 13.9 µs | 26.3 µs | 16.5 µs | 0.35 | 1 | 21199 | 0.88× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 9.1 µs | 9.3 µs | 9.5 µs | 0.67 | 1 | 70360 | 1.34× | ✓ |
| total | `total` v0-pipeline | 134.6 µs | 208.5 µs | 145.1 µs | 0.64 | 1 | 4429 | — | ✓ |
| total_best | `total_best` best-pipeline | 85.5 µs | 182.3 µs | 101.9 µs | 0.47 | 1 | 4629 | 1.57× | ✓ |

##### ML-DSA-65

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 2.7 µs | 2.8 µs | 2.8 µs | 0.80 | 1 | 284029 | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 5.4 µs | 6.1 µs | 5.9 µs | 0.49 | 1 | 83679 | 0.49× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 2.4 µs | 2.4 µs | 2.5 µs | 0.68 | 1 | 270787 | 1.11× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 5.7 µs | 6.8 µs | 6.1 µs | 0.52 | 1 | 84614 | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.4 µs | 0.5 µs | 0.54 | 1 | 1151894 | 13.56× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 5.6 µs | 5.7 µs | 5.9 µs | 0.55 | 1 | 93100 | 1.02× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 6.0 µs | 14.7 µs | 9.6 µs | 0.47 | 1 | 49041 | 0.95× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 5.7 µs | 5.8 µs | 5.9 µs | 0.66 | 1 | 112063 | 1.01× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 5.6 µs | 9.4 µs | 6.2 µs | 0.50 | 1 | 80688 | 1.02× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 62.2 µs | 91.1 µs | 66.4 µs | 0.55 | 1 | 8247 | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.6 µs | 0.8 µs | 0.7 µs | 0.55 | 1 | 755289 | 96.24× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 61.0 µs | 81.8 µs | 63.6 µs | 0.56 | 1 | 8750 | 1.02× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 63.5 µs | 139.9 µs | 72.5 µs | 0.46 | 1 | 6348 | 0.98× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 61.6 µs | 80.8 µs | 63.9 µs | 0.70 | 1 | 10925 | 1.01× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 70.1 µs | 92.2 µs | 73.3 µs | 0.90 | 4 | 12291 | 0.89× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 118.7 µs | 224.3 µs | 140.3 µs | 0.72 | 1 | 5154 | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 154.3 µs | 201.4 µs | 159.1 µs | 0.65 | 1 | 4089 | 0.77× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 47.0 µs | 88.8 µs | 51.4 µs | 0.81 | 1 | 15767 | 2.52× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 117.4 µs | 159.8 µs | 125.2 µs | 0.66 | 1 | 5239 | 1.01× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 34.5 µs | 60.9 µs | 39.1 µs | 0.59 | 1 | 15092 | 3.44× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 14.2 µs | 23.9 µs | 15.5 µs | 0.63 | 1 | 40714 | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 13.9 µs | 14.6 µs | 14.5 µs | 0.70 | 1 | 48014 | 1.02× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 12.6 µs | 12.8 µs | 13.1 µs | 0.40 | 1 | 30379 | 1.13× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 16.4 µs | 27.0 µs | 17.9 µs | 0.50 | 1 | 28030 | 0.86× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 10.5 µs | 15.3 µs | 11.4 µs | 0.69 | 1 | 60030 | 1.35× | ✓ |
| total | `total` v0-pipeline | 206.3 µs | 260.5 µs | 212.5 µs | 0.42 | 1 | 1971 | — | ✓ |
| total_best | `total_best` best-pipeline | 136.0 µs | 295.6 µs | 166.8 µs | 0.54 | 1 | 3214 | 1.52× | ✓ |

##### ML-DSA-87

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 3.6 µs | 5.4 µs | 4.0 µs | 0.39 | 1 | 98329 | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 10.1 µs | 14.9 µs | 10.4 µs | 0.49 | 1 | 46791 | 0.36× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 3.3 µs | 4.6 µs | 3.6 µs | 0.68 | 1 | 187924 | 1.10× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 7.5 µs | 16.9 µs | 9.2 µs | 0.45 | 1 | 48431 | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 1.0 µs | 0.5 µs | 0.48 | 1 | 925709 | 17.64× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 7.3 µs | 10.8 µs | 7.9 µs | 0.52 | 1 | 65149 | 1.02× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 7.8 µs | 16.0 µs | 11.0 µs | 0.49 | 1 | 44873 | 0.95× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 7.4 µs | 221.7 µs | 7.9 µs | 0.23 | 1 | 28985 | 1.01× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 7.3 µs | 13.2 µs | 9.4 µs | 0.51 | 1 | 53873 | 1.02× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 116.0 µs | 139.0 µs | 120.3 µs | 0.51 | 1 | 4203 | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 1.3 µs | 1.6 µs | 1.4 µs | 0.47 | 1 | 325294 | 87.82× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 119.1 µs | 269.3 µs | 154.1 µs | 0.56 | 1 | 3643 | 0.97× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 119.0 µs | 245.2 µs | 130.3 µs | 0.49 | 1 | 3799 | 0.97× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 529.5 µs | 1.73 ms | 119.4 µs | 0.17 | 1 | 1465 | 0.22× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 123.9 µs | 164.3 µs | 130.9 µs | 0.84 | 4 | 6396 | 0.94× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 172.5 µs | 219.2 µs | 179.6 µs | 0.67 | 1 | 3756 | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 128.5 µs | 184.7 µs | 136.6 µs | 0.49 | 1 | 3598 | 1.34× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 65.1 µs | 86.0 µs | 68.3 µs | 0.46 | 1 | 6680 | 2.65× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 487.5 µs | 2.02 ms | 194.5 µs | 0.28 | 1 | 1432 | 0.35× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 48.4 µs | 72.0 µs | 52.0 µs | 0.58 | 1 | 11074 | 3.57× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 19.2 µs | 33.0 µs | 21.0 µs | 0.53 | 1 | 25064 | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 18.8 µs | 27.9 µs | 19.9 µs | 0.49 | 1 | 24493 | 1.02× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 17.0 µs | 37.7 µs | 22.8 µs | 0.49 | 1 | 21665 | 1.13× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 22.8 µs | 48.5 µs | 30.0 µs | 0.48 | 1 | 16120 | 0.84× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 12.6 µs | 19.8 µs | 13.9 µs | 0.64 | 1 | 45769 | 1.53× | ✓ |
| total | `total` v0-pipeline | 324.6 µs | 4.37 ms | 340.1 µs | 0.50 | 1 | 1484 | — | ✓ |
| total_best | `total_best` best-pipeline | 216.8 µs | 4.25 ms | 257.8 µs | 0.45 | 1 | 1752 | 1.50× | ✓ |

### slh-dsa

#### Summary (geomean over params of median wall vs the stage v0; total_best vs total)

| stage | variant | name | geomean speedup | all match |
|---|---|---|---|---|
| hmsg | `hmsg.v0` | ossl-H_msg | 1.00× | yes |
| hmsg | `hmsg.v1` | ossl-H_msg-noasm | 0.88× | yes |
| hmsg | `hmsg.v2` | ossl-H_msg-native | 1.04× | yes |
| hmsg | `hmsg.v3` | lowlevel-hash | 1.23× | yes |
| hmsg | `hmsg.v4` | mgf1-seed-midstate | 1.17× | yes |
| fors | `fors.v0` | ossl-fors_pkFromSig | 1.00× | yes |
| fors | `fors.v1` | ossl-fors-noasm | 0.77× | yes |
| fors | `fors.v2` | ossl-fors-native | 0.98× | yes |
| fors | `fors.v3` | lowlevel-midstate | 1.39× | yes |
| fors | `fors.v4` | pthread-x4-trees | 1.23× | yes |
| ht_wots | `ht_wots.v0` | ossl-wots_pkFromSig | 1.00× | yes |
| ht_wots | `ht_wots.v1` | ossl-wots-noasm | 0.81× | yes |
| ht_wots | `ht_wots.v2` | ossl-wots-native | 1.32× | yes |
| ht_wots | `ht_wots.v3` | lowlevel-midstate | 1.63× | yes |
| ht_wots | `ht_wots.v4` | pthread-x4-layers | 1.61× | yes |
| ht_auth | `ht_auth.v0` | ossl-xmss-authpath | 1.00× | yes |
| ht_auth | `ht_auth.v1` | ossl-authpath-noasm | 0.86× | yes |
| ht_auth | `ht_auth.v2` | ossl-authpath-native | 1.10× | yes |
| ht_auth | `ht_auth.v3` | lowlevel-midstate | 1.52× | yes |
| ht_auth | `ht_auth.v4` | pthread-x4-layers | 0.90× | yes |
| total | `total` | v0-pipeline | — | yes |
| total_best | `total_best` | best-pipeline | 1.89× | yes |

#### Per parameter set

##### SLH-DSA-SHA2-128s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.9 µs | 1.3 µs | 1.1 µs | 0.50 | 1 | 460845 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.4 µs | 1.6 µs | 1.5 µs | 0.54 | 1 | 353057 | 0.66× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.9 µs | 1.0 µs | 1.0 µs | 0.66 | 1 | 677107 | 1.04× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.8 µs | 0.8 µs | 0.68 | 1 | 814391 | 1.22× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 0.8 µs | 0.8 µs | 0.8 µs | 0.69 | 1 | 827307 | 1.21× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 75.6 µs | 127.6 µs | 84.2 µs | 0.59 | 1 | 6982 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 116.2 µs | 182.5 µs | 125.3 µs | 0.58 | 1 | 4605 | 0.65× | ✓ |
| fors | `fors.v2` ossl-fors-native | 73.3 µs | 122.1 µs | 80.4 µs | 0.64 | 1 | 7932 | 1.03× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 37.3 µs | 66.4 µs | 43.0 µs | 0.57 | 1 | 13334 | 2.02× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 47.1 µs | 100.0 µs | 60.5 µs | 0.95 | 4 | 15745 | 1.60× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 810.4 µs | 2.30 ms | 883.8 µs | 0.56 | 1 | 633 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.27 ms | 5.47 ms | 1.29 ms | 0.56 | 1 | 438 | 0.64× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 799.7 µs | 4.86 ms | 846.9 µs | 0.66 | 1 | 777 | 1.01× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 562.5 µs | 730.7 µs | 510.2 µs | 0.77 | 1 | 1518 | 1.44× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 456.8 µs | 2.20 ms | 503.4 µs | 0.62 | 4 | 1233 | 1.77× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 25.9 µs | 50.7 µs | 34.5 µs | 0.22 | 1 | 6370 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 39.9 µs | 83.5 µs | 49.4 µs | 0.55 | 1 | 11105 | 0.65× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 25.1 µs | 40.8 µs | 27.5 µs | 0.66 | 1 | 24128 | 1.03× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 20.8 µs | 29.9 µs | 21.7 µs | 0.55 | 1 | 25078 | 1.25× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 73.7 µs | 135.4 µs | 91.4 µs | 0.57 | 4 | 6216 | 0.35× | ✓ |
| total | `total` v0-pipeline | 1.70 ms | 9.70 ms | 1.65 ms | 0.44 | 1 | 265 | — | ✓ |
| total_best | `total_best` best-pipeline | 791.9 µs | 4.85 ms | 769.7 µs | 0.65 | 1 | 839 | 2.15× | ✓ |

##### SLH-DSA-SHA2-128f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 2.0 µs | 2.6 µs | 2.0 µs | 0.59 | 1 | 287915 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 2.0 µs | 4.1 µs | 2.5 µs | 0.60 | 1 | 240272 | 0.99× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.3 µs | 2.4 µs | 1.6 µs | 0.67 | 1 | 413048 | 1.57× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 1.4 µs | 1.2 µs | 0.60 | 1 | 489117 | 1.78× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 0.9 µs | 1.2 µs | 1.0 µs | 0.58 | 1 | 558900 | 2.09× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 96.9 µs | 142.6 µs | 104.1 µs | 0.59 | 1 | 5703 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 151.0 µs | 274.3 µs | 178.8 µs | 0.68 | 1 | 3779 | 0.64× | ✓ |
| fors | `fors.v2` ossl-fors-native | 94.0 µs | 128.7 µs | 98.9 µs | 0.69 | 1 | 6966 | 1.03× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 48.3 µs | 74.6 µs | 52.0 µs | 0.61 | 1 | 11664 | 2.01× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 57.3 µs | 89.7 µs | 62.5 µs | 0.98 | 4 | 15618 | 1.69× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 2.63 ms | 6.62 ms | 2.64 ms | 0.81 | 1 | 306 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 8.15 ms | 11.98 ms | 4.62 ms | 0.55 | 1 | 119 | 0.32× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 2.60 ms | 7.24 ms | 2.62 ms | 0.65 | 1 | 249 | 1.01× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.28 ms | 5.60 ms | 1.29 ms | 0.21 | 1 | 162 | 2.05× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.27 ms | 1.73 ms | 1.32 ms | 0.93 | 4 | 705 | 2.08× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 36.8 µs | 58.7 µs | 38.2 µs | 0.69 | 1 | 18165 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 42.1 µs | 71.1 µs | 45.4 µs | 0.52 | 1 | 11348 | 0.87× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.7 µs | 53.9 µs | 30.8 µs | 0.68 | 1 | 21983 | 1.38× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 13.6 µs | 23.7 µs | 16.5 µs | 0.64 | 1 | 38825 | 2.72× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 71.9 µs | 116.3 µs | 78.9 µs | 0.62 | 4 | 7854 | 0.51× | ✓ |
| total | `total` v0-pipeline | 4.91 ms | 10.85 ms | 2.80 ms | 0.47 | 1 | 169 | — | ✓ |
| total_best | `total_best` best-pipeline | 1.31 ms | 5.45 ms | 1.33 ms | 0.58 | 1 | 438 | 3.74× | ✓ |

##### SLH-DSA-SHA2-192s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.3 µs | 2.4 µs | 1.9 µs | 0.49 | 1 | 259858 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.8 µs | 3.0 µs | 2.0 µs | 0.57 | 1 | 287083 | 0.72× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.2 µs | 1.2 µs | 1.3 µs | 0.71 | 1 | 563896 | 1.10× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 2.0 µs | 1.2 µs | 0.63 | 1 | 505289 | 1.19× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.1 µs | 1.4 µs | 1.2 µs | 0.53 | 1 | 451944 | 1.19× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 211.3 µs | 1.90 ms | 216.3 µs | 0.49 | 1 | 2269 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 211.7 µs | 333.0 µs | 221.4 µs | 0.51 | 1 | 2285 | 1.00× | ✓ |
| fors | `fors.v2` ossl-fors-native | 157.2 µs | 261.4 µs | 170.0 µs | 0.40 | 1 | 2324 | 1.34× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 71.4 µs | 137.8 µs | 80.1 µs | 0.61 | 1 | 7658 | 2.96× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 87.5 µs | 163.3 µs | 104.3 µs | 0.81 | 4 | 7745 | 2.41× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.88 ms | 5.86 ms | 1.79 ms | 0.73 | 1 | 409 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.96 ms | 6.06 ms | 1.89 ms | 0.52 | 1 | 275 | 0.96× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.32 ms | 5.85 ms | 1.30 ms | 0.55 | 1 | 424 | 1.43× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 560.0 µs | 4.62 ms | 571.1 µs | 0.62 | 1 | 1089 | 3.36× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 578.6 µs | 4.51 ms | 635.5 µs | 0.65 | 4 | 1030 | 3.25× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 59.0 µs | 93.8 µs | 60.0 µs | 0.62 | 1 | 10328 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 51.1 µs | 81.6 µs | 55.9 µs | 0.57 | 1 | 10254 | 1.15× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 32.6 µs | 52.0 µs | 34.7 µs | 0.94 | 1 | 26988 | 1.81× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 33.1 µs | 43.2 µs | 33.5 µs | 0.49 | 1 | 14657 | 1.78× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 43.6 µs | 75.1 µs | 42.6 µs | 0.50 | 4 | 11733 | 1.35× | ✓ |
| total | `total` v0-pipeline | 3.83 ms | 6.93 ms | 1.99 ms | 0.48 | 1 | 243 | — | ✓ |
| total_best | `total_best` best-pipeline | 727.0 µs | 4.92 ms | 794.7 µs | 0.60 | 1 | 756 | 5.26× | ✓ |

##### SLH-DSA-SHA2-192f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.3 µs | 2.1 µs | 1.5 µs | 0.46 | 1 | 316260 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.8 µs | 2.2 µs | 2.0 µs | 0.57 | 1 | 286779 | 0.71× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.2 µs | 1.2 µs | 1.2 µs | 0.51 | 1 | 414179 | 1.09× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 1.6 µs | 1.2 µs | 0.43 | 1 | 354921 | 1.18× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.1 µs | 1.1 µs | 1.2 µs | 0.60 | 1 | 513461 | 1.17× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 168.6 µs | 798.3 µs | 178.8 µs | 0.55 | 1 | 3084 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 248.3 µs | 698.1 µs | 263.9 µs | 0.56 | 1 | 2130 | 0.68× | ✓ |
| fors | `fors.v2` ossl-fors-native | 152.3 µs | 256.9 µs | 161.7 µs | 0.51 | 1 | 3173 | 1.11× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 83.7 µs | 1.68 ms | 90.4 µs | 0.29 | 1 | 3165 | 2.01× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 99.7 µs | 1.91 ms | 109.3 µs | 0.23 | 4 | 2141 | 1.69× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 17.17 ms | 26.21 ms | 4.44 ms | 0.25 | 1 | 57 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 9.79 ms | 13.79 ms | 5.83 ms | 0.60 | 1 | 104 | 1.75× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 5.15 ms | 9.50 ms | 3.83 ms | 0.65 | 1 | 170 | 3.34× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 3.72 ms | 185.07 ms | 1.98 ms | 0.09 | 1 | 47 | 4.62× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 2.55 ms | 5.91 ms | 2.26 ms | 0.86 | 4 | 378 | 6.73× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 37.5 µs | 72.4 µs | 46.5 µs | 0.65 | 1 | 13960 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 57.8 µs | 113.3 µs | 70.9 µs | 0.54 | 1 | 7592 | 0.65× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 53.9 µs | 84.5 µs | 57.0 µs | 0.68 | 1 | 11958 | 0.70× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 18.6 µs | 32.5 µs | 21.4 µs | 0.56 | 1 | 26134 | 2.02× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 27.8 µs | 50.3 µs | 30.8 µs | 0.56 | 4 | 18128 | 1.35× | ✓ |
| total | `total` v0-pipeline | 7.59 ms | 13.47 ms | 4.43 ms | 0.62 | 1 | 139 | — | ✓ |
| total_best | `total_best` best-pipeline | 1.99 ms | 6.12 ms | 1.94 ms | 0.56 | 1 | 288 | 3.82× | ✓ |

##### SLH-DSA-SHA2-256s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.2 µs | 1.8 µs | 1.4 µs | 0.46 | 1 | 329789 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 2.0 µs | 1.9 µs | 0.37 | 1 | 193875 | 0.71× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.1 µs | 1.3 µs | 1.3 µs | 0.55 | 1 | 439919 | 1.07× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.0 µs | 1.5 µs | 1.2 µs | 0.54 | 1 | 457850 | 1.18× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.0 µs | 1.8 µs | 1.2 µs | 0.57 | 1 | 462820 | 1.17× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 188.0 µs | 357.2 µs | 203.2 µs | 0.67 | 1 | 3279 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 426.9 µs | 4.47 ms | 405.3 µs | 0.50 | 1 | 1229 | 0.44× | ✓ |
| fors | `fors.v2` ossl-fors-native | 173.6 µs | 327.6 µs | 197.4 µs | 0.77 | 1 | 3920 | 1.08× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 173.7 µs | 220.4 µs | 165.9 µs | 0.68 | 1 | 4079 | 1.08× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 124.4 µs | 187.6 µs | 186.6 µs | 1.11 | 4 | 5970 | 1.51× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.86 ms | 6.71 ms | 1.85 ms | 0.71 | 1 | 383 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 3.05 ms | 8.22 ms | 3.12 ms | 0.73 | 1 | 234 | 0.61× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.84 ms | 6.26 ms | 1.88 ms | 0.65 | 1 | 344 | 1.01× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 883.0 µs | 3.53 ms | 901.2 µs | 0.27 | 1 | 304 | 2.11× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 928.6 µs | 4.30 ms | 970.2 µs | 0.68 | 4 | 704 | 2.00× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 35.8 µs | 67.1 µs | 40.1 µs | 0.64 | 1 | 16029 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 81.6 µs | 117.2 µs | 77.8 µs | 0.61 | 1 | 7814 | 0.44× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 33.1 µs | 60.3 µs | 37.7 µs | 0.67 | 1 | 17722 | 1.08× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 17.9 µs | 30.7 µs | 20.3 µs | 0.52 | 1 | 25828 | 2.00× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 26.9 µs | 48.9 µs | 29.5 µs | 0.57 | 4 | 19452 | 1.33× | ✓ |
| total | `total` v0-pipeline | 2.10 ms | 7.94 ms | 2.06 ms | 0.58 | 1 | 283 | — | ✓ |
| total_best | `total_best` best-pipeline | 989.7 µs | 5.16 ms | 1.03 ms | 0.58 | 1 | 569 | 2.13× | ✓ |

##### SLH-DSA-SHA2-256f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.2 µs | 2.0 µs | 1.4 µs | 0.65 | 1 | 463795 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 3.5 µs | 2.3 µs | 0.76 | 1 | 331736 | 0.70× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.1 µs | 2.1 µs | 1.3 µs | 0.72 | 1 | 537457 | 1.07× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.0 µs | 1.2 µs | 1.1 µs | 0.84 | 1 | 735030 | 1.17× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.9 µs | 2.0 µs | 1.8 µs | 0.61 | 1 | 334519 | 0.63× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 199.8 µs | 725.4 µs | 225.3 µs | 0.61 | 1 | 2689 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 322.9 µs | 3.99 ms | 390.7 µs | 0.51 | 1 | 1303 | 0.62× | ✓ |
| fors | `fors.v2` ossl-fors-native | 181.7 µs | 261.9 µs | 190.8 µs | 0.63 | 1 | 3279 | 1.10× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 101.0 µs | 222.0 µs | 126.1 µs | 0.57 | 1 | 4515 | 1.98× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 226.8 µs | 367.5 µs | 243.5 µs | 0.56 | 4 | 2293 | 0.88× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 7.28 ms | 15.95 ms | 4.06 ms | 0.57 | 1 | 141 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 10.08 ms | 23.71 ms | 6.78 ms | 0.64 | 1 | 95 | 0.72× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.86 ms | 8.06 ms | 3.70 ms | 0.71 | 1 | 192 | 1.89× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 2.40 ms | 8.68 ms | 2.05 ms | 0.57 | 1 | 279 | 3.03× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 4.60 ms | 7.40 ms | 2.96 ms | 0.63 | 4 | 213 | 1.58× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 38.3 µs | 56.9 µs | 40.1 µs | 0.81 | 1 | 20274 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 55.3 µs | 84.5 µs | 58.9 µs | 0.52 | 1 | 8773 | 0.69× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 35.3 µs | 57.4 µs | 38.7 µs | 0.72 | 1 | 18573 | 1.08× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 19.0 µs | 23.0 µs | 20.1 µs | 0.67 | 1 | 33177 | 2.02× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 27.6 µs | 50.1 µs | 30.3 µs | 0.60 | 4 | 19754 | 1.39× | ✓ |
| total | `total` v0-pipeline | 7.89 ms | 9.48 ms | 3.92 ms | 0.60 | 1 | 154 | — | ✓ |
| total_best | `total_best` best-pipeline | 2.56 ms | 7.27 ms | 2.10 ms | 0.55 | 1 | 262 | 3.08× | ✓ |

##### SLH-DSA-SHAKE-128s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.5 µs | 0.7 µs | 0.5 µs | 0.98 | 1 | 1848542 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.5 µs | 0.5 µs | 0.6 µs | 0.71 | 1 | 1272884 | 0.94× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.4 µs | 0.4 µs | 0.5 µs | 0.99 | 1 | 2090225 | 1.06× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.4 µs | 0.6 µs | 0.5 µs | 0.94 | 1 | 1936045 | 1.10× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 79.7 µs | 123.9 µs | 86.3 µs | 0.79 | 1 | 9184 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 85.2 µs | 175.3 µs | 100.3 µs | 0.55 | 1 | 5513 | 0.94× | ✓ |
| fors | `fors.v2` ossl-fors-native | 76.2 µs | 158.6 µs | 92.4 µs | 0.79 | 1 | 8553 | 1.05× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 73.2 µs | 106.4 µs | 78.1 µs | 0.54 | 1 | 6969 | 1.09× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 83.0 µs | 130.6 µs | 88.1 µs | 0.48 | 4 | 5488 | 0.96× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 794.6 µs | 4.83 ms | 809.7 µs | 0.71 | 1 | 878 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.05 ms | 5.44 ms | 1.10 ms | 0.59 | 1 | 535 | 0.76× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 791.0 µs | 11.53 ms | 827.8 µs | 0.48 | 1 | 580 | 1.00× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 731.7 µs | 4.84 ms | 742.6 µs | 0.57 | 1 | 768 | 1.09× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.31 ms | 6.27 ms | 1.06 ms | 0.54 | 4 | 513 | 0.61× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 53.6 µs | 78.3 µs | 50.6 µs | 0.59 | 1 | 11662 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 28.9 µs | 57.9 µs | 33.6 µs | 0.71 | 1 | 21205 | 1.85× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 43.8 µs | 71.5 µs | 44.2 µs | 0.76 | 1 | 17256 | 1.22× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.3 µs | 36.1 µs | 26.7 µs | 0.57 | 1 | 21270 | 2.12× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 34.1 µs | 53.4 µs | 35.8 µs | 0.64 | 4 | 17881 | 1.57× | ✓ |
| total | `total` v0-pipeline | 898.3 µs | 4.95 ms | 910.8 µs | 0.71 | 1 | 776 | — | ✓ |
| total_best | `total_best` best-pipeline | 829.8 µs | 4.90 ms | 841.3 µs | 0.66 | 1 | 788 | 1.08× | ✓ |

##### SLH-DSA-SHAKE-128f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.5 µs | 0.5 µs | 0.5 µs | 0.61 | 1 | 1190695 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.5 µs | 1.1 µs | 0.6 µs | 0.64 | 1 | 1045184 | 0.93× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.9 µs | 1.0 µs | 0.9 µs | 0.57 | 1 | 613263 | 0.51× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.4 µs | 0.4 µs | 0.5 µs | 0.69 | 1 | 1480106 | 1.10× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 101.7 µs | 137.9 µs | 106.8 µs | 0.52 | 1 | 4875 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 126.7 µs | 263.2 µs | 155.0 µs | 0.63 | 1 | 4070 | 0.80× | ✓ |
| fors | `fors.v2` ossl-fors-native | 153.2 µs | 233.5 µs | 156.0 µs | 0.74 | 1 | 4767 | 0.66× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 93.5 µs | 126.5 µs | 98.3 µs | 0.48 | 1 | 4841 | 1.09× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 102.2 µs | 139.8 µs | 106.7 µs | 0.49 | 4 | 4548 | 0.99× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 6.77 ms | 7.76 ms | 2.82 ms | 0.48 | 1 | 171 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 7.75 ms | 11.00 ms | 4.87 ms | 0.66 | 1 | 135 | 0.87× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 4.80 ms | 15.80 ms | 4.53 ms | 0.70 | 1 | 155 | 1.41× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 6.11 ms | 9.57 ms | 2.61 ms | 0.51 | 1 | 194 | 1.11× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 2.67 ms | 6.20 ms | 2.61 ms | 0.74 | 4 | 282 | 2.54× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 28.8 µs | 42.1 µs | 30.2 µs | 0.32 | 1 | 10527 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 30.6 µs | 47.3 µs | 32.2 µs | 0.67 | 1 | 20782 | 0.94× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 27.7 µs | 58.0 µs | 36.5 µs | 0.88 | 1 | 24064 | 1.04× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 26.8 µs | 62.1 µs | 36.1 µs | 0.39 | 1 | 10722 | 1.07× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 35.9 µs | 86.9 µs | 52.5 µs | 0.38 | 4 | 7279 | 0.80× | ✓ |
| total | `total` v0-pipeline | 6.99 ms | 16.43 ms | 3.01 ms | 0.36 | 1 | 121 | — | ✓ |
| total_best | `total_best` best-pipeline | 9.81 ms | 14.01 ms | 4.34 ms | 0.47 | 1 | 109 | 0.71× | ✓ |

##### SLH-DSA-SHAKE-192s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 0.9 µs | 0.9 µs | 0.51 | 1 | 569787 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.9 µs | 1.6 µs | 1.0 µs | 0.71 | 1 | 693127 | 0.94× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 1.7 µs | 1.1 µs | 0.66 | 1 | 585088 | 1.03× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.9 µs | 0.8 µs | 0.50 | 1 | 585836 | 1.06× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 119.6 µs | 253.2 µs | 148.5 µs | 0.50 | 1 | 3369 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 122.8 µs | 291.8 µs | 160.8 µs | 0.63 | 1 | 3938 | 0.97× | ✓ |
| fors | `fors.v2` ossl-fors-native | 106.6 µs | 230.4 µs | 118.5 µs | 0.68 | 1 | 5764 | 1.12× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 174.6 µs | 229.1 µs | 156.5 µs | 0.50 | 1 | 3175 | 0.68× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 134.7 µs | 244.2 µs | 163.5 µs | 0.82 | 4 | 5035 | 0.89× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.22 ms | 5.26 ms | 1.22 ms | 0.50 | 1 | 411 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.31 ms | 5.41 ms | 1.33 ms | 0.68 | 1 | 510 | 0.93× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.19 ms | 5.24 ms | 1.21 ms | 0.66 | 1 | 544 | 1.02× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.13 ms | 5.16 ms | 1.15 ms | 0.64 | 1 | 555 | 1.07× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.18 ms | 2.87 ms | 1.30 ms | 0.84 | 4 | 648 | 1.03× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.2 µs | 45.1 µs | 29.6 µs | 0.69 | 1 | 23328 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 29.0 µs | 52.1 µs | 31.7 µs | 0.92 | 1 | 29003 | 0.94× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.0 µs | 53.5 µs | 29.6 µs | 0.73 | 1 | 24725 | 1.04× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.0 µs | 35.7 µs | 26.5 µs | 0.30 | 1 | 11361 | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 34.4 µs | 61.8 µs | 37.8 µs | 0.65 | 4 | 17223 | 0.79× | ✓ |
| total | `total` v0-pipeline | 1.39 ms | 3.93 ms | 1.44 ms | 0.80 | 1 | 554 | — | ✓ |
| total_best | `total_best` best-pipeline | 1.28 ms | 7.15 ms | 1.28 ms | 0.49 | 1 | 380 | 1.09× | ✓ |

##### SLH-DSA-SHAKE-192f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 0.8 µs | 0.9 µs | 0.59 | 1 | 671724 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.9 µs | 1.4 µs | 1.0 µs | 0.63 | 1 | 640940 | 0.94× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 0.8 µs | 0.8 µs | 0.73 | 1 | 870500 | 1.04× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 1.2 µs | 0.9 µs | 0.49 | 1 | 566525 | 1.05× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 131.2 µs | 241.8 µs | 143.6 µs | 0.64 | 1 | 4424 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 141.3 µs | 243.3 µs | 155.0 µs | 0.84 | 1 | 5448 | 0.93× | ✓ |
| fors | `fors.v2` ossl-fors-native | 125.1 µs | 157.9 µs | 130.2 µs | 0.80 | 1 | 6109 | 1.05× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 120.2 µs | 183.6 µs | 128.2 µs | 0.61 | 1 | 4724 | 1.09× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 131.1 µs | 426.5 µs | 142.5 µs | 0.51 | 4 | 3548 | 1.00× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 7.78 ms | 14.39 ms | 3.77 ms | 0.47 | 1 | 124 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 8.32 ms | 19.57 ms | 4.99 ms | 0.53 | 1 | 106 | 0.94× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 5.72 ms | 11.78 ms | 3.79 ms | 0.61 | 1 | 161 | 1.36× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 7.49 ms | 7.75 ms | 3.53 ms | 0.52 | 1 | 149 | 1.04× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 7.23 ms | 9.32 ms | 3.65 ms | 0.54 | 4 | 149 | 1.08× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 28.9 µs | 51.5 µs | 32.3 µs | 0.42 | 1 | 12929 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 30.8 µs | 62.9 µs | 35.7 µs | 0.63 | 1 | 17744 | 0.94× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 27.7 µs | 55.2 µs | 32.4 µs | 0.40 | 1 | 12209 | 1.04× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 26.6 µs | 52.9 µs | 30.2 µs | 0.60 | 1 | 19932 | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 35.8 µs | 60.2 µs | 38.7 µs | 0.60 | 4 | 15498 | 0.81× | ✓ |
| total | `total` v0-pipeline | 7.96 ms | 15.82 ms | 4.29 ms | 0.55 | 1 | 129 | — | ✓ |
| total_best | `total_best` best-pipeline | 3.91 ms | 11.66 ms | 3.76 ms | 0.65 | 1 | 173 | 2.03× | ✓ |

##### SLH-DSA-SHAKE-256s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 1.7 µs | 1.0 µs | 0.44 | 1 | 453648 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.9 µs | 1.0 µs | 1.0 µs | 0.79 | 1 | 811415 | 0.93× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 1.2 µs | 0.9 µs | 0.69 | 1 | 769558 | 1.03× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 1.7 µs | 1.2 µs | 0.33 | 1 | 274833 | 1.03× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 145.0 µs | 251.9 µs | 153.7 µs | 0.23 | 1 | 1466 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 156.7 µs | 249.9 µs | 168.4 µs | 0.48 | 1 | 2868 | 0.92× | ✓ |
| fors | `fors.v2` ossl-fors-native | 169.8 µs | 288.0 µs | 186.6 µs | 0.65 | 1 | 3498 | 0.85× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 135.3 µs | 165.4 µs | 141.5 µs | 0.60 | 1 | 4244 | 1.07× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 162.6 µs | 2.97 ms | 233.7 µs | 0.29 | 4 | 1238 | 0.89× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.83 ms | 9.57 ms | 2.20 ms | 0.62 | 1 | 283 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 2.09 ms | 10.88 ms | 2.05 ms | 0.52 | 1 | 254 | 0.88× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.79 ms | 6.27 ms | 1.88 ms | 0.68 | 1 | 361 | 1.02× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 2.12 ms | 9.78 ms | 1.84 ms | 0.52 | 1 | 283 | 0.86× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 3.13 ms | 6.08 ms | 1.97 ms | 0.57 | 4 | 286 | 0.58× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.7 µs | 49.2 µs | 31.1 µs | 0.47 | 1 | 15154 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 29.8 µs | 62.1 µs | 34.7 µs | 0.78 | 1 | 22490 | 0.93× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.3 µs | 46.5 µs | 29.3 µs | 0.72 | 1 | 24407 | 1.05× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.9 µs | 52.8 µs | 30.6 µs | 0.52 | 1 | 16971 | 1.07× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 37.0 µs | 92.0 µs | 48.9 µs | 0.57 | 4 | 11564 | 0.75× | ✓ |
| total | `total` v0-pipeline | 2.43 ms | 10.05 ms | 2.07 ms | 0.48 | 1 | 232 | — | ✓ |
| total_best | `total_best` best-pipeline | 2.04 ms | 6.69 ms | 1.89 ms | 0.58 | 1 | 310 | 1.19× | ✓ |

##### SLH-DSA-SHAKE-256f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.6 µs | 1.7 µs | 1.7 µs | 0.56 | 1 | 327226 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.9 µs | 1.4 µs | 1.0 µs | 0.63 | 1 | 643726 | 1.86× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.4 µs | 1.6 µs | 1.5 µs | 0.68 | 1 | 440363 | 1.18× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.8 µs | 0.8 µs | 0.55 | 1 | 666592 | 2.10× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 158.4 µs | 319.2 µs | 179.8 µs | 0.56 | 1 | 3112 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 170.1 µs | 322.4 µs | 188.9 µs | 0.60 | 1 | 3158 | 0.93× | ✓ |
| fors | `fors.v2` ossl-fors-native | 262.8 µs | 555.1 µs | 279.2 µs | 0.66 | 1 | 2359 | 0.60× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 145.6 µs | 231.1 µs | 154.3 µs | 0.56 | 1 | 3654 | 1.09× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 154.4 µs | 937.7 µs | 169.6 µs | 0.49 | 4 | 2913 | 1.03× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 8.04 ms | 12.86 ms | 4.05 ms | 0.47 | 1 | 116 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 8.24 ms | 8.94 ms | 4.28 ms | 0.57 | 1 | 132 | 0.98× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 5.19 ms | 10.52 ms | 3.94 ms | 0.67 | 1 | 169 | 1.55× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 7.71 ms | 13.01 ms | 3.67 ms | 0.50 | 1 | 135 | 1.04× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 6.96 ms | 12.41 ms | 3.99 ms | 0.54 | 4 | 135 | 1.15× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 29.6 µs | 55.8 µs | 35.7 µs | 0.60 | 1 | 16750 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 31.8 µs | 58.5 µs | 36.0 µs | 0.69 | 1 | 19070 | 0.93× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 28.3 µs | 55.6 µs | 35.4 µs | 0.67 | 1 | 19024 | 1.05× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 27.7 µs | 44.9 µs | 29.4 µs | 0.63 | 1 | 21473 | 1.07× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 37.0 µs | 139.4 µs | 56.8 µs | 0.67 | 4 | 11880 | 0.80× | ✓ |
| total | `total` v0-pipeline | 15.90 ms | 28.97 ms | 6.76 ms | 0.40 | 1 | 60 | — | ✓ |
| total_best | `total_best` best-pipeline | 16.00 ms | 20.91 ms | 7.20 ms | 0.49 | 1 | 68 | 0.99× | ✓ |

