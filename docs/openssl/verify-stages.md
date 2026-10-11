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

## What the numbers say (development run, shared box, load average 5-9 on 4 cores)

* ML-DSA verify is dominated by `w_approx` (~55 %) and `expandA` (~30 %). The own int32 lazy-reduction NTT is
  2.5x faster than OpenSSL's uint32 "reduce after every operation" NTT (3.4x with the cached NTT(t1*2^d)),
  which makes `total_best` 1.5-1.7x faster than `total`. EVP overhead per SHAKE call is only visible in the
  microsecond-sized stages (mu, hint_check, 2-12 %); expandA is Keccak-bound and the low-level API gains
  nothing (OpenSSL's Keccak assembly is scalar, so a 4-way SHAKE would be the real lever and OpenSSL has none).
  The own decoder gains ~10 % over the PACKET-based one. The cached variants show what a per-key cache buys:
  mu with cached tr 13x (the pk hash dominates mu for a 64-byte message), cached A^ >100x.
* Surprise to confirm on the quiet machine: the `-O3 -march=native -flto` build is consistently *slower* for
  `w_approx` (0.7x, two runs) and not better for expandA, while it helps hint_check (1.3x) and decode (1.1x);
  the likely cause is LTO/AVX-512 code generation for the Montgomery butterflies (frequency/port effects),
  the `no-asm` build costs 5-25 % wherever SHAKE is involved.
* SLH-DSA verify is `ht_wots` (~85 %) + `fors` (~10 %). For the SHA2 sets the per-call EVP cost plus the
  re-hashing of the constant `PK.seed || 0...` block costs OpenSSL about 3.5x: the midstate primitives bring
  SHA2-128f ht_wots from ~4.7 ms to ~1.2 ms; over all 12 sets the low-level/midstate variants give 1.4-1.7x
  per stage (SHAKE sets ~1.1x) and `total_best` 1.56x geomean over `total`.
* Threads help only where the per-call work is milliseconds: ht_wots 1.75x (limited by the busy box), fors
  1.2x; for expandA / ht_auth (tens of microseconds) the barrier hand-off costs more than the work and the
  thread variants are slower than v0 - kept as honest data points. cpu_util of 0.5-0.9 in the tables shows
  how noisy these development numbers are.

<!-- RESULTS -->

## Results (PRELIMINARY: development run, --budget-ms 200, shared busy machine; the orchestrator overwrites this section)

### ml-dsa

#### Summary (geomean over params of median wall vs the stage v0; total_best vs total)

| stage | variant | name | geomean speedup | all match |
|---|---|---|---|---|
| decode | `decode.v0` | ossl-decoders | 1.00× | yes |
| decode | `decode.v1` | own-unpack-u64 | 1.12× | yes |
| decode | `decode.v2` | ossl-decoders-native | 1.10× | yes |
| mu | `mu.v0` | ossl-evp-shake | 1.00× | yes |
| mu | `mu.v1` | cached-tr | 13.18× | yes |
| mu | `mu.v2` | lowlevel-sha3 | 1.02× | yes |
| mu | `mu.v3` | ossl-evp-shake-noasm | 0.96× | yes |
| mu | `mu.v4` | ossl-evp-shake-native | 1.01× | yes |
| mu | `mu.v5` | evp-reused-ctx | 0.99× | yes |
| expandA | `expandA.v0` | ossl-expand-A | 1.00× | yes |
| expandA | `expandA.v1` | cached-A | 137.61× | yes |
| expandA | `expandA.v2` | lowlevel-sha3 | 1.01× | yes |
| expandA | `expandA.v3` | ossl-expand-A-noasm | 0.74× | yes |
| expandA | `expandA.v4` | ossl-expand-A-native | 0.77× | yes |
| expandA | `expandA.v5` | pthread-x4-rows | 0.75× | yes |
| w_approx | `w_approx.v0` | ossl-ntt | 1.00× | yes |
| w_approx | `w_approx.v1` | cached-ntt-t1 | 1.36× | yes |
| w_approx | `w_approx.v2` | own-int32-mont-ntt | 2.49× | yes |
| w_approx | `w_approx.v3` | ossl-ntt-native | 0.73× | yes |
| w_approx | `w_approx.v4` | cached-t1+own-ntt | 3.44× | yes |
| hint_check | `hint_check.v0` | ossl-usehint-w1encode | 1.00× | yes |
| hint_check | `hint_check.v1` | lowlevel-sha3 | 1.02× | yes |
| hint_check | `hint_check.v2` | fused-usehint-pack | 1.12× | yes |
| hint_check | `hint_check.v3` | ossl-noasm | 0.87× | yes |
| hint_check | `hint_check.v4` | ossl-native | 1.33× | yes |
| total | `total` | v0-pipeline | — | yes |
| total_best | `total_best` | best-pipeline | 1.67× | yes |

#### Per parameter set

##### ML-DSA-44

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 2.0 µs | 2.2 µs | 2.2 µs | 0.51 | 1 | 233685 | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 1.8 µs | 2.9 µs | 2.1 µs | 0.68 | 1 | 330083 | 1.13× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 1.9 µs | 1.9 µs | 2.0 µs | 1.00 | 1 | 492385 | 1.09× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 4.0 µs | 5.0 µs | 4.3 µs | 0.77 | 1 | 178484 | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.5 µs | 0.5 µs | 0.86 | 1 | 1815254 | 9.54× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 3.9 µs | 5.8 µs | 4.3 µs | 0.93 | 1 | 216818 | 1.03× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 4.2 µs | 4.4 µs | 4.4 µs | 0.91 | 1 | 205504 | 0.96× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 4.0 µs | 7.4 µs | 5.0 µs | 0.96 | 1 | 192584 | 1.01× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 3.9 µs | 8.2 µs | 4.9 µs | 0.86 | 1 | 173993 | 1.03× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 33.1 µs | 71.1 µs | 42.5 µs | 0.90 | 1 | 21150 | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.1 µs | 0.1 µs | 0.1 µs | 0.90 | 1 | 6649620 | 312.45× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 32.6 µs | 50.1 µs | 34.7 µs | 0.87 | 1 | 24945 | 1.02× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 34.4 µs | 70.0 µs | 42.6 µs | 0.81 | 1 | 19028 | 0.96× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 33.0 µs | 60.3 µs | 39.8 µs | 0.84 | 1 | 21233 | 1.00× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 41.9 µs | 90.4 µs | 56.9 µs | 0.83 | 4 | 14504 | 0.79× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 80.6 µs | 123.5 µs | 88.8 µs | 0.82 | 1 | 9192 | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 59.5 µs | 81.6 µs | 62.6 µs | 0.92 | 1 | 14641 | 1.36× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 32.9 µs | 52.8 µs | 36.1 µs | 0.70 | 1 | 19442 | 2.45× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 80.3 µs | 128.4 µs | 89.3 µs | 0.77 | 1 | 8674 | 1.00× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 24.5 µs | 36.2 µs | 26.1 µs | 0.73 | 1 | 28144 | 3.29× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 12.2 µs | 17.0 µs | 13.0 µs | 0.99 | 1 | 76567 | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 12.1 µs | 25.2 µs | 15.2 µs | 0.78 | 1 | 51476 | 1.01× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 10.4 µs | 19.6 µs | 13.6 µs | 0.69 | 1 | 50969 | 1.17× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 13.9 µs | 16.4 µs | 14.6 µs | 0.76 | 1 | 52020 | 0.88× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 9.1 µs | 11.3 µs | 9.6 µs | 0.95 | 1 | 98448 | 1.34× | ✓ |
| total | `total` v0-pipeline | 132.9 µs | 191.2 µs | 141.6 µs | 0.84 | 1 | 5949 | — | ✓ |
| total_best | `total_best` best-pipeline | 100.6 µs | 174.2 µs | 113.3 µs | 0.94 | 1 | 8286 | 1.32× | ✓ |

##### ML-DSA-65

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 2.7 µs | 5.0 µs | 3.0 µs | 0.99 | 1 | 324434 | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 2.4 µs | 2.4 µs | 2.5 µs | 0.70 | 1 | 279704 | 1.12× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 2.4 µs | 2.5 µs | 2.6 µs | 0.89 | 1 | 346923 | 1.11× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 5.7 µs | 5.9 µs | 6.0 µs | 0.99 | 1 | 164939 | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.5 µs | 0.5 µs | 0.95 | 1 | 1983215 | 13.61× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 5.6 µs | 5.7 µs | 5.9 µs | 0.63 | 1 | 107683 | 1.02× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 6.0 µs | 10.4 µs | 6.7 µs | 0.90 | 1 | 133833 | 0.96× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 5.7 µs | 9.3 µs | 6.3 µs | 0.94 | 1 | 148392 | 1.01× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 6.2 µs | 12.2 µs | 8.7 µs | 0.51 | 1 | 58379 | 0.92× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 61.6 µs | 90.7 µs | 65.9 µs | 0.67 | 1 | 10189 | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.6 µs | 0.7 µs | 0.7 µs | 0.97 | 1 | 1377223 | 95.76× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 61.2 µs | 91.2 µs | 66.1 µs | 0.90 | 1 | 13584 | 1.01× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 64.4 µs | 108.6 µs | 72.3 µs | 0.93 | 1 | 12876 | 0.96× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 61.8 µs | 109.4 µs | 69.3 µs | 0.70 | 1 | 10053 | 1.00× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 108.3 µs | 1.76 ms | 155.3 µs | 0.65 | 4 | 4160 | 0.57× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 118.8 µs | 182.4 µs | 130.7 µs | 0.68 | 1 | 5166 | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 86.2 µs | 118.8 µs | 92.4 µs | 0.72 | 1 | 7789 | 1.38× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 50.7 µs | 108.7 µs | 69.1 µs | 0.83 | 1 | 12013 | 2.35× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 172.5 µs | 224.0 µs | 177.2 µs | 0.80 | 1 | 4502 | 0.69× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 34.4 µs | 71.5 µs | 40.3 µs | 0.78 | 1 | 19350 | 3.45× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 14.3 µs | 32.6 µs | 16.8 µs | 0.76 | 1 | 45456 | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 14.1 µs | 33.0 µs | 18.6 µs | 0.77 | 1 | 41468 | 1.01× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 13.1 µs | 30.6 µs | 18.4 µs | 0.76 | 1 | 41343 | 1.09× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 16.4 µs | 26.5 µs | 18.0 µs | 0.83 | 1 | 46204 | 0.87× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 10.9 µs | 17.1 µs | 12.1 µs | 0.97 | 1 | 79840 | 1.32× | ✓ |
| total | `total` v0-pipeline | 207.5 µs | 415.5 µs | 238.0 µs | 0.49 | 1 | 2061 | — | ✓ |
| total_best | `total_best` best-pipeline | 134.0 µs | 302.6 µs | 176.7 µs | 0.75 | 1 | 4257 | 1.55× | ✓ |

##### ML-DSA-87

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 3.6 µs | 3.8 µs | 3.9 µs | 0.74 | 1 | 190742 | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 3.2 µs | 5.9 µs | 3.8 µs | 0.76 | 1 | 197727 | 1.12× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 3.3 µs | 6.6 µs | 4.3 µs | 0.95 | 1 | 221919 | 1.10× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 7.4 µs | 11.6 µs | 8.2 µs | 0.82 | 1 | 98922 | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.7 µs | 0.5 µs | 0.80 | 1 | 1602371 | 17.64× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 7.3 µs | 7.4 µs | 7.7 µs | 0.80 | 1 | 103820 | 1.02× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 7.8 µs | 19.1 µs | 9.8 µs | 0.93 | 1 | 94647 | 0.96× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 7.4 µs | 9.0 µs | 7.9 µs | 0.99 | 1 | 125291 | 1.01× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 7.3 µs | 7.5 µs | 7.6 µs | 0.71 | 1 | 93065 | 1.02× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 115.2 µs | 142.1 µs | 119.6 µs | 0.73 | 1 | 6074 | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 1.3 µs | 1.4 µs | 1.4 µs | 0.83 | 1 | 589971 | 87.10× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 114.3 µs | 165.4 µs | 122.9 µs | 0.85 | 1 | 6942 | 1.01× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 265.9 µs | 316.2 µs | 252.7 µs | 0.94 | 1 | 3718 | 0.43× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 248.1 µs | 290.2 µs | 239.9 µs | 0.97 | 1 | 4043 | 0.46× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 123.0 µs | 162.6 µs | 128.8 µs | 0.95 | 4 | 7358 | 0.94× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 174.1 µs | 335.1 µs | 193.5 µs | 0.75 | 1 | 3893 | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 128.9 µs | 190.7 µs | 137.9 µs | 0.91 | 1 | 6632 | 1.35× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 65.1 µs | 91.9 µs | 69.1 µs | 0.89 | 1 | 12890 | 2.67× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 309.0 µs | 393.9 µs | 316.5 µs | 0.85 | 1 | 2695 | 0.56× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 48.6 µs | 76.6 µs | 52.1 µs | 0.87 | 1 | 16680 | 3.58× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 19.2 µs | 30.5 µs | 20.7 µs | 0.84 | 1 | 40661 | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 18.9 µs | 26.4 µs | 20.0 µs | 0.94 | 1 | 46992 | 1.02× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 17.3 µs | 21.9 µs | 18.3 µs | 0.85 | 1 | 46455 | 1.11× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 22.2 µs | 41.0 µs | 24.6 µs | 0.82 | 1 | 33281 | 0.87× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 14.4 µs | 21.7 µs | 15.6 µs | 0.90 | 1 | 57823 | 1.34× | ✓ |
| total | `total` v0-pipeline | 481.0 µs | 3.53 ms | 463.1 µs | 0.51 | 1 | 1094 | — | ✓ |
| total_best | `total_best` best-pipeline | 211.2 µs | 327.9 µs | 226.6 µs | 0.99 | 1 | 4379 | 2.28× | ✓ |

### slh-dsa

#### Summary (geomean over params of median wall vs the stage v0; total_best vs total)

| stage | variant | name | geomean speedup | all match |
|---|---|---|---|---|
| hmsg | `hmsg.v0` | ossl-H_msg | 1.00× | yes |
| hmsg | `hmsg.v1` | ossl-H_msg-noasm | 0.75× | yes |
| hmsg | `hmsg.v2` | ossl-H_msg-native | 0.89× | yes |
| hmsg | `hmsg.v3` | lowlevel-hash | 1.08× | yes |
| hmsg | `hmsg.v4` | mgf1-seed-midstate | 1.25× | yes |
| fors | `fors.v0` | ossl-fors_pkFromSig | 1.00× | yes |
| fors | `fors.v1` | ossl-fors-noasm | 0.72× | yes |
| fors | `fors.v2` | ossl-fors-native | 1.00× | yes |
| fors | `fors.v3` | lowlevel-midstate | 1.44× | yes |
| fors | `fors.v4` | pthread-x4-trees | 1.23× | yes |
| ht_wots | `ht_wots.v0` | ossl-wots_pkFromSig | 1.00× | yes |
| ht_wots | `ht_wots.v1` | ossl-wots-noasm | 0.83× | yes |
| ht_wots | `ht_wots.v2` | ossl-wots-native | 1.10× | yes |
| ht_wots | `ht_wots.v3` | lowlevel-midstate | 1.68× | yes |
| ht_wots | `ht_wots.v4` | pthread-x4-layers | 1.75× | yes |
| ht_auth | `ht_auth.v0` | ossl-xmss-authpath | 1.00× | yes |
| ht_auth | `ht_auth.v1` | ossl-authpath-noasm | 0.75× | yes |
| ht_auth | `ht_auth.v2` | ossl-authpath-native | 0.96× | yes |
| ht_auth | `ht_auth.v3` | lowlevel-midstate | 1.38× | yes |
| ht_auth | `ht_auth.v4` | pthread-x4-layers | 0.85× | yes |
| total | `total` | v0-pipeline | — | yes |
| total_best | `total_best` | best-pipeline | 1.56× | yes |

#### Per parameter set

##### SLH-DSA-SHA2-128s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.9 µs | 1.0 µs | 1.0 µs | 0.72 | 1 | 730596 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 2.8 µs | 2.9 µs | 2.8 µs | 0.92 | 1 | 332767 | 0.33× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.9 µs | 1.5 µs | 1.1 µs | 0.94 | 1 | 872040 | 1.03× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.8 µs | 0.8 µs | 0.99 | 1 | 1217402 | 1.22× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 0.8 µs | 1.0 µs | 0.8 µs | 0.91 | 1 | 1081667 | 1.21× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 76.1 µs | 98.2 µs | 79.6 µs | 0.84 | 1 | 10576 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 243.7 µs | 284.1 µs | 249.6 µs | 0.93 | 1 | 3737 | 0.31× | ✓ |
| fors | `fors.v2` ossl-fors-native | 73.7 µs | 126.0 µs | 82.0 µs | 0.55 | 1 | 6745 | 1.03× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 37.5 µs | 57.7 µs | 39.1 µs | 0.96 | 1 | 24585 | 2.03× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 72.8 µs | 128.6 µs | 91.5 µs | 1.02 | 4 | 11154 | 1.05× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 804.6 µs | 1.56 ms | 893.4 µs | 0.88 | 1 | 983 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.25 ms | 4.70 ms | 1.37 ms | 0.84 | 1 | 611 | 0.64× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 844.9 µs | 1.45 ms | 921.1 µs | 0.85 | 1 | 917 | 0.95× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 381.3 µs | 481.4 µs | 393.7 µs | 0.75 | 1 | 1897 | 2.11× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 336.6 µs | 503.2 µs | 464.4 µs | 1.14 | 4 | 2450 | 2.39× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 25.8 µs | 43.3 µs | 27.8 µs | 0.74 | 1 | 26412 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 38.4 µs | 64.3 µs | 41.6 µs | 0.76 | 1 | 18355 | 0.67× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 25.2 µs | 50.6 µs | 32.1 µs | 0.73 | 1 | 22799 | 1.02× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 12.8 µs | 16.7 µs | 13.6 µs | 0.91 | 1 | 67115 | 2.01× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 21.1 µs | 27.1 µs | 22.2 µs | 0.92 | 4 | 41165 | 1.22× | ✓ |
| total | `total` v0-pipeline | 1.40 ms | 5.25 ms | 1.34 ms | 0.84 | 1 | 627 | — | ✓ |
| total_best | `total_best` best-pipeline | 683.6 µs | 736.8 µs | 677.0 µs | 0.91 | 1 | 1343 | 2.05× | ✓ |

##### SLH-DSA-SHA2-128f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.5 µs | 2.1 µs | 1.7 µs | 0.77 | 1 | 440974 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 2.0 µs | 3.2 µs | 2.2 µs | 0.79 | 1 | 358604 | 0.78× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.7 µs | 2.5 µs | 1.9 µs | 0.76 | 1 | 404003 | 0.90× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 1.6 µs | 1.2 µs | 0.81 | 1 | 657914 | 1.37× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.0 µs | 1.7 µs | 1.1 µs | 0.83 | 1 | 736370 | 1.60× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 96.6 µs | 136.1 µs | 104.0 µs | 0.81 | 1 | 7836 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 265.4 µs | 356.7 µs | 246.0 µs | 0.73 | 1 | 2984 | 0.36× | ✓ |
| fors | `fors.v2` ossl-fors-native | 153.3 µs | 201.4 µs | 155.6 µs | 0.94 | 1 | 6023 | 0.63× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 55.1 µs | 104.7 µs | 63.2 µs | 0.49 | 1 | 7723 | 1.75× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 57.4 µs | 95.8 µs | 62.7 µs | 0.93 | 4 | 14789 | 1.68× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 2.79 ms | 6.57 ms | 2.64 ms | 0.72 | 1 | 273 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 4.01 ms | 7.99 ms | 4.07 ms | 0.88 | 1 | 217 | 0.70× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.95 ms | 8.02 ms | 3.95 ms | 0.92 | 1 | 234 | 0.71× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.57 ms | 5.30 ms | 1.52 ms | 0.77 | 1 | 508 | 1.77× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.28 ms | 2.25 ms | 1.31 ms | 0.91 | 4 | 696 | 2.18× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.4 µs | 51.6 µs | 31.5 µs | 0.84 | 1 | 26587 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 62.1 µs | 110.1 µs | 64.3 µs | 0.77 | 1 | 12055 | 0.44× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.8 µs | 30.9 µs | 27.8 µs | 0.98 | 1 | 35310 | 1.02× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 19.7 µs | 25.4 µs | 19.2 µs | 0.75 | 1 | 38921 | 1.39× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 22.3 µs | 42.0 µs | 27.1 µs | 1.00 | 4 | 36906 | 1.23× | ✓ |
| total | `total` v0-pipeline | 2.67 ms | 6.85 ms | 2.69 ms | 0.75 | 1 | 278 | — | ✓ |
| total_best | `total_best` best-pipeline | 1.30 ms | 1.84 ms | 1.31 ms | 0.92 | 1 | 699 | 2.05× | ✓ |

##### SLH-DSA-SHA2-192s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.3 µs | 1.9 µs | 1.4 µs | 0.88 | 1 | 630685 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 1.9 µs | 1.9 µs | 0.79 | 1 | 422847 | 0.72× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.2 µs | 2.0 µs | 1.3 µs | 0.82 | 1 | 623474 | 1.08× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 2.0 µs | 1.3 µs | 0.84 | 1 | 659146 | 1.18× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.1 µs | 1.3 µs | 1.2 µs | 0.91 | 1 | 772666 | 1.18× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 144.6 µs | 213.4 µs | 157.0 µs | 0.87 | 1 | 5558 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 210.9 µs | 257.5 µs | 217.6 µs | 0.90 | 1 | 4137 | 0.69× | ✓ |
| fors | `fors.v2` ossl-fors-native | 134.2 µs | 273.4 µs | 170.9 µs | 0.91 | 1 | 5351 | 1.08× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 71.4 µs | 133.1 µs | 80.7 µs | 0.69 | 1 | 8575 | 2.03× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 80.5 µs | 130.5 µs | 88.7 µs | 0.99 | 4 | 11113 | 1.80× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.19 ms | 1.96 ms | 1.29 ms | 0.93 | 1 | 720 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.80 ms | 5.88 ms | 1.89 ms | 0.76 | 1 | 402 | 0.66× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.16 ms | 2.67 ms | 1.28 ms | 0.86 | 1 | 675 | 1.03× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 568.3 µs | 896.5 µs | 601.4 µs | 0.94 | 1 | 1565 | 2.10× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 604.4 µs | 2.67 ms | 729.0 µs | 0.75 | 4 | 1035 | 1.97× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 35.4 µs | 54.3 µs | 37.5 µs | 0.46 | 1 | 12208 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 51.6 µs | 77.0 µs | 55.2 µs | 0.85 | 1 | 15392 | 0.69× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 33.1 µs | 54.1 µs | 38.2 µs | 0.95 | 1 | 24958 | 1.07× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 17.6 µs | 34.3 µs | 20.2 µs | 0.76 | 1 | 37653 | 2.01× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 26.5 µs | 31.5 µs | 27.7 µs | 0.97 | 4 | 34945 | 1.34× | ✓ |
| total | `total` v0-pipeline | 1.34 ms | 5.41 ms | 1.34 ms | 0.75 | 1 | 558 | — | ✓ |
| total_best | `total_best` best-pipeline | 655.8 µs | 4.73 ms | 699.3 µs | 0.67 | 1 | 962 | 2.04× | ✓ |

##### SLH-DSA-SHA2-192f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.3 µs | 1.6 µs | 1.4 µs | 0.88 | 1 | 640880 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 2.6 µs | 2.0 µs | 0.85 | 1 | 434698 | 0.72× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 2.3 µs | 2.6 µs | 2.3 µs | 0.88 | 1 | 380017 | 0.53× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 1.2 µs | 1.2 µs | 0.68 | 1 | 585422 | 1.19× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.1 µs | 1.7 µs | 1.2 µs | 0.78 | 1 | 641645 | 1.18× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 167.9 µs | 245.1 µs | 177.8 µs | 0.48 | 1 | 2714 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 246.8 µs | 342.1 µs | 258.2 µs | 0.93 | 1 | 3585 | 0.68× | ✓ |
| fors | `fors.v2` ossl-fors-native | 157.2 µs | 288.3 µs | 174.4 µs | 0.86 | 1 | 4942 | 1.07× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 83.2 µs | 116.7 µs | 88.8 µs | 0.87 | 1 | 9801 | 2.02× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 93.0 µs | 160.8 µs | 103.0 µs | 0.72 | 4 | 6953 | 1.81× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 3.78 ms | 7.70 ms | 3.76 ms | 0.91 | 1 | 241 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 10.09 ms | 21.73 ms | 7.79 ms | 0.67 | 1 | 86 | 0.37× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.73 ms | 5.21 ms | 3.84 ms | 0.95 | 1 | 247 | 1.01× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.81 ms | 3.95 ms | 1.83 ms | 0.87 | 1 | 475 | 2.09× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.83 ms | 5.90 ms | 1.84 ms | 0.79 | 4 | 427 | 2.07× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 37.5 µs | 58.4 µs | 40.3 µs | 0.96 | 1 | 23928 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 54.1 µs | 91.1 µs | 59.0 µs | 0.90 | 1 | 15230 | 0.69× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 35.0 µs | 77.3 µs | 40.6 µs | 0.91 | 1 | 22338 | 1.07× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 18.6 µs | 30.3 µs | 20.3 µs | 0.88 | 1 | 43145 | 2.02× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 77.0 µs | 109.5 µs | 91.5 µs | 0.88 | 4 | 9600 | 0.49× | ✓ |
| total | `total` v0-pipeline | 12.00 ms | 31.48 ms | 5.31 ms | 0.36 | 1 | 68 | — | ✓ |
| total_best | `total_best` best-pipeline | 3.54 ms | 7.63 ms | 2.90 ms | 0.69 | 1 | 239 | 3.39× | ✓ |

##### SLH-DSA-SHA2-256s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.2 µs | 1.9 µs | 1.4 µs | 0.98 | 1 | 708755 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 1.9 µs | 1.9 µs | 0.93 | 1 | 502089 | 0.71× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.2 µs | 2.3 µs | 1.6 µs | 0.77 | 1 | 491458 | 1.06× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.0 µs | 2.1 µs | 1.3 µs | 0.97 | 1 | 724475 | 1.18× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.0 µs | 2.0 µs | 1.4 µs | 0.86 | 1 | 612089 | 1.17× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 188.7 µs | 297.1 µs | 206.2 µs | 0.91 | 1 | 4389 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 272.9 µs | 309.0 µs | 279.9 µs | 0.96 | 1 | 3437 | 0.69× | ✓ |
| fors | `fors.v2` ossl-fors-native | 176.2 µs | 321.6 µs | 195.3 µs | 0.59 | 1 | 3009 | 1.07× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 92.4 µs | 116.3 µs | 96.6 µs | 0.74 | 1 | 7708 | 2.04× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 102.2 µs | 133.0 µs | 109.0 µs | 0.97 | 4 | 8893 | 1.85× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.80 ms | 6.32 ms | 1.84 ms | 0.62 | 1 | 338 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 2.76 ms | 4.02 ms | 2.78 ms | 0.92 | 1 | 331 | 0.65× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.78 ms | 2.46 ms | 1.78 ms | 0.91 | 1 | 512 | 1.01× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 867.8 µs | 1.03 ms | 887.4 µs | 0.88 | 1 | 989 | 2.07× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 715.6 µs | 1.08 ms | 962.7 µs | 1.26 | 4 | 1307 | 2.51× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 36.0 µs | 62.0 µs | 39.7 µs | 0.89 | 1 | 22507 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 52.1 µs | 82.8 µs | 56.7 µs | 0.85 | 1 | 14984 | 0.69× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 33.5 µs | 52.7 µs | 35.8 µs | 0.76 | 1 | 21196 | 1.07× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 17.8 µs | 29.7 µs | 19.8 µs | 0.78 | 1 | 39348 | 2.02× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 29.1 µs | 90.8 µs | 49.6 µs | 0.95 | 4 | 19174 | 1.23× | ✓ |
| total | `total` v0-pipeline | 2.00 ms | 2.72 ms | 2.07 ms | 0.97 | 1 | 472 | — | ✓ |
| total_best | `total_best` best-pipeline | 971.1 µs | 1.16 ms | 993.7 µs | 0.96 | 1 | 968 | 2.06× | ✓ |

##### SLH-DSA-SHA2-256f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.2 µs | 1.5 µs | 1.3 µs | 0.74 | 1 | 552782 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 3.4 µs | 2.0 µs | 0.98 | 1 | 487376 | 0.71× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.2 µs | 2.2 µs | 1.4 µs | 0.66 | 1 | 464373 | 1.06× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.0 µs | 1.7 µs | 1.2 µs | 0.90 | 1 | 771814 | 1.19× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.0 µs | 1.1 µs | 1.1 µs | 0.80 | 1 | 710470 | 1.18× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 198.0 µs | 251.8 µs | 208.6 µs | 0.85 | 1 | 4093 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 296.4 µs | 480.8 µs | 310.2 µs | 0.83 | 1 | 2675 | 0.67× | ✓ |
| fors | `fors.v2` ossl-fors-native | 186.2 µs | 294.5 µs | 203.1 µs | 0.81 | 1 | 3970 | 1.06× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 98.2 µs | 127.3 µs | 103.0 µs | 0.96 | 1 | 9343 | 2.02× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 107.6 µs | 136.8 µs | 112.8 µs | 0.98 | 4 | 8700 | 1.84× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 3.68 ms | 5.43 ms | 3.74 ms | 0.94 | 1 | 251 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 10.22 ms | 11.91 ms | 8.71 ms | 0.98 | 1 | 113 | 0.36× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.77 ms | 7.75 ms | 3.72 ms | 0.84 | 1 | 225 | 0.98× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.80 ms | 2.23 ms | 1.88 ms | 0.99 | 1 | 528 | 2.04× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.82 ms | 5.54 ms | 1.82 ms | 0.80 | 4 | 442 | 2.03× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 38.5 µs | 57.1 µs | 40.2 µs | 0.73 | 1 | 18178 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 60.6 µs | 138.6 µs | 81.4 µs | 0.80 | 1 | 9792 | 0.63× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 35.8 µs | 67.3 µs | 40.4 µs | 0.89 | 1 | 22153 | 1.07× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 19.0 µs | 27.8 µs | 20.2 µs | 0.85 | 1 | 42090 | 2.03× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 27.8 µs | 47.6 µs | 30.5 µs | 0.97 | 4 | 31988 | 1.38× | ✓ |
| total | `total` v0-pipeline | 3.99 ms | 7.02 ms | 4.28 ms | 0.95 | 1 | 222 | — | ✓ |
| total_best | `total_best` best-pipeline | 2.01 ms | 3.45 ms | 2.03 ms | 0.93 | 1 | 461 | 1.99× | ✓ |

##### SLH-DSA-SHAKE-128s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.5 µs | 0.5 µs | 0.5 µs | 1.00 | 1 | 2001879 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.5 µs | 0.9 µs | 0.6 µs | 1.00 | 1 | 1734744 | 0.96× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 1.0 µs | 0.9 µs | 0.90 | 1 | 1041844 | 0.59× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.4 µs | 0.4 µs | 0.5 µs | 0.69 | 1 | 1522015 | 1.10× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 80.3 µs | 140.3 µs | 87.8 µs | 0.76 | 1 | 8698 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 83.0 µs | 117.8 µs | 88.7 µs | 1.00 | 1 | 11263 | 0.97× | ✓ |
| fors | `fors.v2` ossl-fors-native | 77.0 µs | 128.2 µs | 85.6 µs | 0.38 | 1 | 4429 | 1.04× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 73.3 µs | 130.6 µs | 84.2 µs | 0.88 | 1 | 10502 | 1.10× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 85.2 µs | 163.6 µs | 101.4 µs | 0.91 | 4 | 8983 | 0.94× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.50 ms | 5.03 ms | 1.38 ms | 0.78 | 1 | 564 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 893.6 µs | 1.70 ms | 1.04 ms | 0.96 | 1 | 925 | 1.68× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 778.7 µs | 1.26 ms | 799.1 µs | 0.85 | 1 | 1067 | 1.93× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 731.4 µs | 1.38 ms | 735.3 µs | 0.79 | 1 | 1068 | 2.05× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 789.0 µs | 4.10 ms | 820.3 µs | 0.73 | 4 | 887 | 1.90× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.2 µs | 56.1 µs | 34.0 µs | 0.74 | 1 | 21833 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 28.2 µs | 58.3 µs | 33.8 µs | 0.96 | 1 | 28334 | 0.96× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.2 µs | 45.8 µs | 29.0 µs | 0.56 | 1 | 19503 | 1.04× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.0 µs | 44.8 µs | 29.6 µs | 0.87 | 1 | 29582 | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 33.8 µs | 53.9 µs | 35.6 µs | 0.98 | 4 | 27502 | 0.81× | ✓ |
| total | `total` v0-pipeline | 912.2 µs | 2.17 ms | 945.3 µs | 0.86 | 1 | 908 | — | ✓ |
| total_best | `total_best` best-pipeline | 892.7 µs | 4.92 ms | 1.17 ms | 0.80 | 1 | 683 | 1.02× | ✓ |

##### SLH-DSA-SHAKE-128f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.5 µs | 0.6 µs | 0.5 µs | 0.86 | 1 | 1619329 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 1.2 µs | 0.9 µs | 0.99 | 1 | 1061045 | 0.55× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.4 µs | 0.6 µs | 0.5 µs | 0.63 | 1 | 1268609 | 1.06× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.4 µs | 0.5 µs | 0.5 µs | 0.99 | 1 | 2073585 | 1.11× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 102.5 µs | 140.1 µs | 109.0 µs | 0.81 | 1 | 7409 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 106.3 µs | 149.5 µs | 114.0 µs | 0.94 | 1 | 8265 | 0.96× | ✓ |
| fors | `fors.v2` ossl-fors-native | 98.2 µs | 143.1 µs | 106.6 µs | 0.77 | 1 | 7194 | 1.04× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 93.5 µs | 161.9 µs | 106.6 µs | 0.83 | 1 | 7820 | 1.10× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 103.0 µs | 148.9 µs | 111.2 µs | 0.98 | 4 | 8831 | 1.00× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 3.03 ms | 8.89 ms | 3.00 ms | 0.75 | 1 | 250 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 3.05 ms | 4.17 ms | 3.15 ms | 0.97 | 1 | 309 | 0.99× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 2.74 ms | 6.81 ms | 2.74 ms | 0.79 | 1 | 287 | 1.10× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 2.70 ms | 3.51 ms | 2.69 ms | 0.94 | 1 | 348 | 1.12× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 2.63 ms | 3.95 ms | 2.66 ms | 0.92 | 4 | 347 | 1.15× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 28.8 µs | 52.0 µs | 33.3 µs | 0.44 | 1 | 13154 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 29.8 µs | 58.4 µs | 34.1 µs | 0.96 | 1 | 28140 | 0.96× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 27.9 µs | 52.8 µs | 32.2 µs | 0.92 | 1 | 28614 | 1.03× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 26.5 µs | 46.8 µs | 29.7 µs | 0.62 | 1 | 20731 | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 35.6 µs | 65.8 µs | 40.1 µs | 0.90 | 4 | 22371 | 0.81× | ✓ |
| total | `total` v0-pipeline | 3.05 ms | 7.00 ms | 3.05 ms | 0.89 | 1 | 292 | — | ✓ |
| total_best | `total_best` best-pipeline | 2.80 ms | 6.77 ms | 2.80 ms | 0.78 | 1 | 277 | 1.09× | ✓ |

##### SLH-DSA-SHAKE-192s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 1.6 µs | 1.0 µs | 0.73 | 1 | 714391 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 1.4 µs | 1.0 µs | 0.78 | 1 | 793219 | 0.96× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 0.8 µs | 0.8 µs | 1.00 | 1 | 1193063 | 1.04× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 1.7 µs | 1.1 µs | 0.77 | 1 | 714784 | 1.04× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 112.6 µs | 151.3 µs | 121.0 µs | 0.66 | 1 | 5485 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 116.5 µs | 186.8 µs | 129.3 µs | 0.97 | 1 | 7510 | 0.97× | ✓ |
| fors | `fors.v2` ossl-fors-native | 107.9 µs | 138.7 µs | 113.5 µs | 0.90 | 1 | 7884 | 1.04× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 102.5 µs | 142.0 µs | 110.3 µs | 0.77 | 1 | 6979 | 1.10× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 174.6 µs | 227.5 µs | 158.1 µs | 0.84 | 4 | 5343 | 0.64× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 2.13 ms | 3.56 ms | 1.83 ms | 0.86 | 1 | 470 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.35 ms | 2.05 ms | 1.37 ms | 0.90 | 1 | 657 | 1.58× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.20 ms | 5.23 ms | 1.28 ms | 0.79 | 1 | 618 | 1.77× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.14 ms | 3.41 ms | 1.15 ms | 0.81 | 1 | 701 | 1.87× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.17 ms | 2.01 ms | 1.23 ms | 0.89 | 4 | 727 | 1.82× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.2 µs | 52.7 µs | 31.8 µs | 0.80 | 1 | 25176 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 28.2 µs | 59.5 µs | 34.5 µs | 0.95 | 1 | 27559 | 0.96× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 44.8 µs | 65.5 µs | 42.0 µs | 0.82 | 1 | 19658 | 0.61× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.0 µs | 54.1 µs | 30.0 µs | 0.81 | 1 | 26864 | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 34.2 µs | 60.0 µs | 39.3 µs | 0.94 | 4 | 23830 | 0.80× | ✓ |
| total | `total` v0-pipeline | 1.44 ms | 5.54 ms | 1.46 ms | 0.74 | 1 | 505 | — | ✓ |
| total_best | `total_best` best-pipeline | 1.31 ms | 3.26 ms | 1.31 ms | 0.88 | 1 | 666 | 1.10× | ✓ |

##### SLH-DSA-SHAKE-192f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 0.8 µs | 0.9 µs | 0.89 | 1 | 1011589 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 1.4 µs | 1.0 µs | 0.96 | 1 | 997959 | 0.96× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 1.5 µs | 1.1 µs | 0.70 | 1 | 660150 | 1.02× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.8 µs | 0.8 µs | 0.94 | 1 | 1127944 | 1.06× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 133.4 µs | 258.4 µs | 153.3 µs | 0.96 | 1 | 6269 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 137.2 µs | 192.5 µs | 147.7 µs | 0.92 | 1 | 6244 | 0.97× | ✓ |
| fors | `fors.v2` ossl-fors-native | 129.6 µs | 276.1 µs | 157.4 µs | 0.79 | 1 | 4997 | 1.03× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 133.2 µs | 285.3 µs | 166.2 µs | 0.94 | 1 | 5686 | 1.00× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 131.7 µs | 257.5 µs | 151.9 µs | 0.89 | 4 | 5886 | 1.01× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 6.44 ms | 8.90 ms | 5.70 ms | 0.91 | 1 | 159 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 4.03 ms | 5.07 ms | 4.05 ms | 0.96 | 1 | 237 | 1.60× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.98 ms | 10.39 ms | 3.74 ms | 0.69 | 1 | 184 | 1.62× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 3.85 ms | 7.58 ms | 4.02 ms | 0.84 | 1 | 210 | 1.67× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 3.60 ms | 6.34 ms | 3.76 ms | 0.94 | 4 | 249 | 1.79× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 28.9 µs | 46.8 µs | 31.0 µs | 0.85 | 1 | 27457 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 29.9 µs | 50.4 µs | 32.0 µs | 0.97 | 1 | 30363 | 0.96× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 27.9 µs | 48.1 µs | 30.7 µs | 0.79 | 1 | 25577 | 1.03× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 28.6 µs | 62.4 µs | 38.9 µs | 0.86 | 1 | 22135 | 1.01× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 67.6 µs | 103.5 µs | 65.1 µs | 0.95 | 4 | 14572 | 0.43× | ✓ |
| total | `total` v0-pipeline | 4.93 ms | 10.67 ms | 5.12 ms | 0.86 | 1 | 168 | — | ✓ |
| total_best | `total_best` best-pipeline | 4.80 ms | 13.84 ms | 4.39 ms | 0.75 | 1 | 171 | 1.03× | ✓ |

##### SLH-DSA-SHAKE-256s

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 0.8 µs | 0.9 µs | 0.98 | 1 | 1113939 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 0.9 µs | 0.9 µs | 1.00 | 1 | 1104013 | 0.96× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 1.0 µs | 0.9 µs | 0.86 | 1 | 989441 | 1.04× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.8 µs | 0.8 µs | 0.97 | 1 | 1167654 | 1.06× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 147.1 µs | 203.0 µs | 157.1 µs | 0.81 | 1 | 5130 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 151.4 µs | 183.9 µs | 158.5 µs | 0.96 | 1 | 6037 | 0.97× | ✓ |
| fors | `fors.v2` ossl-fors-native | 138.9 µs | 201.7 µs | 150.5 µs | 0.79 | 1 | 5240 | 1.06× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 132.8 µs | 190.0 µs | 142.1 µs | 0.65 | 1 | 4566 | 1.11× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 157.3 µs | 269.3 µs | 179.6 µs | 1.00 | 4 | 5554 | 0.94× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.99 ms | 6.78 ms | 2.26 ms | 0.77 | 1 | 340 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.91 ms | 5.98 ms | 2.70 ms | 0.90 | 1 | 334 | 1.04× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.87 ms | 6.15 ms | 1.94 ms | 0.72 | 1 | 368 | 1.07× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 2.29 ms | 5.74 ms | 2.26 ms | 0.87 | 1 | 383 | 0.87× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.73 ms | 2.35 ms | 1.78 ms | 0.93 | 4 | 523 | 1.15× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.6 µs | 46.2 µs | 30.4 µs | 0.84 | 1 | 27559 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 28.7 µs | 65.5 µs | 32.5 µs | 0.95 | 1 | 29167 | 0.96× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.4 µs | 54.4 µs | 31.2 µs | 0.77 | 1 | 24753 | 1.05× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 36.9 µs | 74.0 µs | 40.2 µs | 0.75 | 1 | 18608 | 0.75× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 52.0 µs | 91.2 µs | 55.0 µs | 0.78 | 4 | 14203 | 0.53× | ✓ |
| total | `total` v0-pipeline | 2.06 ms | 6.17 ms | 2.34 ms | 0.81 | 1 | 345 | — | ✓ |
| total_best | `total_best` best-pipeline | 1.89 ms | 5.95 ms | 1.98 ms | 0.83 | 1 | 420 | 1.09× | ✓ |

##### SLH-DSA-SHAKE-256f

| stage | variant | median | p95 | CPU/op | util | thr | ops/s | vs v0 | match |
|---|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 1.0 µs | 0.9 µs | 0.84 | 1 | 930742 | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 1.3 µs | 1.0 µs | 0.75 | 1 | 791068 | 0.97× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.3 µs | 1.8 µs | 1.5 µs | 0.78 | 1 | 520808 | 0.62× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.5 µs | 1.7 µs | 1.3 µs | 0.74 | 1 | 551805 | 0.54× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 158.9 µs | 286.8 µs | 174.1 µs | 0.76 | 1 | 4357 | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 164.2 µs | 321.5 µs | 183.6 µs | 0.68 | 1 | 3700 | 0.97× | ✓ |
| fors | `fors.v2` ossl-fors-native | 175.8 µs | 316.7 µs | 207.4 µs | 0.92 | 1 | 4453 | 0.90× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 176.0 µs | 285.8 µs | 192.3 µs | 0.85 | 1 | 4439 | 0.90× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 154.2 µs | 260.6 µs | 170.5 µs | 0.96 | 4 | 5612 | 1.03× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 4.20 ms | 9.58 ms | 4.00 ms | 0.74 | 1 | 185 | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 4.61 ms | 9.05 ms | 4.42 ms | 0.74 | 1 | 169 | 0.91× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 6.12 ms | 10.60 ms | 4.53 ms | 0.68 | 1 | 151 | 0.69× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 3.65 ms | 5.10 ms | 3.72 ms | 0.94 | 1 | 252 | 1.15× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 4.57 ms | 6.11 ms | 4.40 ms | 0.89 | 4 | 201 | 0.92× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 29.6 µs | 58.9 µs | 37.4 µs | 0.88 | 1 | 23470 | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 46.6 µs | 74.9 µs | 47.1 µs | 0.89 | 1 | 18990 | 0.64× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 46.7 µs | 79.7 µs | 50.6 µs | 0.86 | 1 | 17014 | 0.63× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 27.1 µs | 53.4 µs | 33.7 µs | 0.82 | 1 | 24302 | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 38.2 µs | 78.3 µs | 51.8 µs | 0.76 | 4 | 14580 | 0.77× | ✓ |
| total | `total` v0-pipeline | 5.38 ms | 13.15 ms | 4.90 ms | 0.75 | 1 | 152 | — | ✓ |
| total_best | `total_best` best-pipeline | 4.25 ms | 8.82 ms | 4.08 ms | 0.73 | 1 | 178 | 1.27× | ✓ |

