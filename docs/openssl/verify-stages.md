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

## Results

Generated by `common/report-phase2.mjs` from `results/openssl/stages.jsonl`. Speedup = throughput vs the stage's v0. "coverage" = sum of v0 stage medians / end-to-end v0 total.

### ML-DSA-44

end-to-end v0 stages: 134.8 µs, best assembled: 81.9 µs (1.65×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 2.0 µs | 2.3 µs | 1 | 1.5% | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 1.8 µs | 2.0 µs | 1 |  | 1.16× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 1.9 µs | 2.0 µs | 1 |  | 1.18× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 4.0 µs | 4.3 µs | 1 | 3.0% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.5 µs | 1 |  | 9.06× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 3.9 µs | 4.2 µs | 1 |  | 1.02× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 4.2 µs | 5.6 µs | 1 |  | 0.78× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 4.0 µs | 4.3 µs | 1 |  | 1.01× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 3.9 µs | 4.2 µs | 1 |  | 1.04× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 33.5 µs | 35.7 µs | 1 | 24.8% | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.1 µs | 0.1 µs | 1 |  | 261.48× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 32.6 µs | 37.5 µs | 1 |  | 0.95× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 34.4 µs | 42.6 µs | 1 |  | 0.83× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 33.0 µs | 36.4 µs | 1 |  | 0.98× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 103.8 µs | 145.8 µs | 4 |  | 0.34× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 80.6 µs | 87.7 µs | 1 | 59.8% | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 59.6 µs | 64.4 µs | 1 |  | 1.36× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 32.9 µs | 35.9 µs | 1 |  | 2.41× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 80.1 µs | 87.1 µs | 1 |  | 1.00× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 24.8 µs | 33.3 µs | 1 |  | 2.61× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 12.3 µs | 14.2 µs | 1 | 9.1% | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 12.1 µs | 13.7 µs | 1 |  | 1.03× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 10.4 µs | 11.9 µs | 1 |  | 1.20× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 13.9 µs | 14.9 µs | 1 |  | 0.96× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 9.1 µs | 10.3 µs | 1 |  | 1.39× | ✓ |

### ML-DSA-65

end-to-end v0 stages: 205.0 µs, best assembled: 130.0 µs (1.58×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 2.7 µs | 3.4 µs | 1 | 1.3% | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 2.4 µs | 2.9 µs | 1 |  | 1.15× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 2.4 µs | 3.0 µs | 1 |  | 1.12× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 5.7 µs | 6.2 µs | 1 | 2.8% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.5 µs | 1 |  | 13.47× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 5.6 µs | 5.9 µs | 1 |  | 1.07× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 6.0 µs | 6.3 µs | 1 |  | 1.00× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 5.7 µs | 6.1 µs | 1 |  | 1.04× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 5.6 µs | 5.8 µs | 1 |  | 1.09× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 62.6 µs | 67.3 µs | 1 | 30.6% | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.6 µs | 0.7 µs | 1 |  | 96.77× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 61.2 µs | 70.3 µs | 1 |  | 0.95× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 64.4 µs | 66.9 µs | 1 |  | 1.01× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 61.8 µs | 73.7 µs | 1 |  | 0.91× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 114.2 µs | 182.4 µs | 4 |  | 0.56× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 120.2 µs | 138.5 µs | 1 | 58.6% | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 86.9 µs | 100.1 µs | 1 |  | 1.37× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 47.0 µs | 53.3 µs | 1 |  | 2.61× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 121.2 µs | 146.5 µs | 1 |  | 0.95× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 34.5 µs | 38.2 µs | 1 |  | 3.63× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 14.3 µs | 16.1 µs | 1 | 7.0% | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 14.0 µs | 15.2 µs | 1 |  | 1.06× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 12.9 µs | 13.7 µs | 1 |  | 1.18× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 16.4 µs | 18.3 µs | 1 |  | 0.88× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 10.9 µs | 13.0 µs | 1 |  | 1.23× | ✓ |

### ML-DSA-87

end-to-end v0 stages: 321.2 µs, best assembled: 210.7 µs (1.52×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` ossl-decoders | 3.7 µs | 4.7 µs | 1 | 1.1% | 1.00× | ✓ |
| decode | `decode.v1` own-unpack-u64 | 3.2 µs | 3.4 µs | 1 |  | 1.44× | ✓ |
| decode | `decode.v2` ossl-decoders-native | 3.3 µs | 3.9 µs | 1 |  | 1.25× | ✓ |
| mu | `mu.v0` ossl-evp-shake | 7.4 µs | 7.9 µs | 1 | 2.3% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.4 µs | 0.5 µs | 1 |  | 17.20× | ✓ |
| mu | `mu.v2` lowlevel-sha3 | 7.3 µs | 7.7 µs | 1 |  | 1.03× | ✓ |
| mu | `mu.v3` ossl-evp-shake-noasm | 7.8 µs | 10.3 µs | 1 |  | 0.76× | ✓ |
| mu | `mu.v4` ossl-evp-shake-native | 7.4 µs | 9.3 µs | 1 |  | 0.84× | ✓ |
| mu | `mu.v5` evp-reused-ctx | 7.3 µs | 7.9 µs | 1 |  | 1.01× | ✓ |
| expandA | `expandA.v0` ossl-expand-A | 117.8 µs | 134.0 µs | 1 | 36.7% | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 1.3 µs | 1.4 µs | 1 |  | 96.03× | ✓ |
| expandA | `expandA.v2` lowlevel-sha3 | 114.3 µs | 129.5 µs | 1 |  | 1.01× | ✓ |
| expandA | `expandA.v3` ossl-expand-A-noasm | 122.9 µs | 145.9 µs | 1 |  | 0.91× | ✓ |
| expandA | `expandA.v4` ossl-expand-A-native | 115.2 µs | 124.1 µs | 1 |  | 1.08× | ✓ |
| expandA | `expandA.v5` pthread-x4-rows | 124.4 µs | 242.4 µs | 4 |  | 0.97× | ✓ |
| w_approx | `w_approx.v0` ossl-ntt | 171.5 µs | 189.4 µs | 1 | 53.4% | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 128.0 µs | 139.3 µs | 1 |  | 1.37× | ✓ |
| w_approx | `w_approx.v2` own-int32-mont-ntt | 66.6 µs | 76.1 µs | 1 |  | 2.50× | ✓ |
| w_approx | `w_approx.v3` ossl-ntt-native | 169.7 µs | 181.9 µs | 1 |  | 1.05× | ✓ |
| w_approx | `w_approx.v4` cached-t1+own-ntt | 48.4 µs | 52.2 µs | 1 |  | 3.64× | ✓ |
| hint_check | `hint_check.v0` ossl-usehint-w1encode | 19.4 µs | 22.5 µs | 1 | 6.0% | 1.00× | ✓ |
| hint_check | `hint_check.v1` lowlevel-sha3 | 18.9 µs | 22.2 µs | 1 |  | 1.00× | ✓ |
| hint_check | `hint_check.v2` fused-usehint-pack | 17.3 µs | 18.1 µs | 1 |  | 1.25× | ✓ |
| hint_check | `hint_check.v3` ossl-noasm | 22.2 µs | 23.5 µs | 1 |  | 0.96× | ✓ |
| hint_check | `hint_check.v4` ossl-native | 14.5 µs | 16.3 µs | 1 |  | 1.36× | ✓ |

### SLH-DSA-SHA2-128s

end-to-end v0 stages: 926.3 µs, best assembled: 453.7 µs (2.04×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.9 µs | 1.1 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.4 µs | 1.6 µs | 1 |  | 0.73× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.9 µs | 1.0 µs | 1 |  | 1.20× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.9 µs | 1 |  | 1.29× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 0.8 µs | 0.8 µs | 1 |  | 1.38× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 75.2 µs | 84.5 µs | 1 | 8.1% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 117.3 µs | 139.9 µs | 1 |  | 0.60× | ✓ |
| fors | `fors.v2` ossl-fors-native | 83.9 µs | 103.1 µs | 1 |  | 0.82× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 37.5 µs | 45.5 µs | 1 |  | 1.86× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 110.9 µs | 165.4 µs | 4 |  | 0.72× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 813.0 µs | 866.5 µs | 1 | 87.8% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.29 ms | 1.36 ms | 1 |  | 0.64× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 816.8 µs | 908.9 µs | 1 |  | 0.95× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 395.4 µs | 427.9 µs | 1 |  | 2.05× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 261.3 µs | 599.3 µs | 4 |  | 3.30× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 25.8 µs | 29.3 µs | 1 | 2.8% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 68.3 µs | 59.8 µs | 1 |  | 0.49× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 25.2 µs | 27.8 µs | 1 |  | 1.04× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 12.8 µs | 16.4 µs | 1 |  | 1.79× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 86.2 µs | 114.6 µs | 4 |  | 0.32× | ✓ |

### SLH-DSA-SHA2-128f

end-to-end v0 stages: 2.68 ms, best assembled: 1.33 ms (2.02×), coverage 111%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.3 µs | 1.6 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 2.0 µs | 2.0 µs | 1 |  | 0.79× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.3 µs | 1.4 µs | 1 |  | 1.08× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 1.3 µs | 1 |  | 1.21× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.0 µs | 1.1 µs | 1 |  | 1.43× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 97.0 µs | 113.9 µs | 1 | 3.6% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 148.6 µs | 173.8 µs | 1 |  | 0.66× | ✓ |
| fors | `fors.v2` ossl-fors-native | 94.8 µs | 120.9 µs | 1 |  | 0.94× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 76.4 µs | 74.5 µs | 1 |  | 1.53× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 119.2 µs | 189.5 µs | 4 |  | 0.87× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 2.84 ms | 3.29 ms | 1 | 105.8% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 4.10 ms | 4.27 ms | 1 |  | 0.77× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 4.32 ms | 3.79 ms | 1 |  | 0.88× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.24 ms | 1.36 ms | 1 |  | 2.45× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 484.8 µs | 1.56 ms | 4 |  | 6.11× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.4 µs | 31.7 µs | 1 | 1.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 41.7 µs | 54.1 µs | 1 |  | 0.58× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.9 µs | 33.7 µs | 1 |  | 0.92× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 13.6 µs | 17.8 µs | 1 |  | 1.78× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 98.7 µs | 131.6 µs | 4 |  | 0.30× | ✓ |

### SLH-DSA-SHA2-192s

end-to-end v0 stages: 1.47 ms, best assembled: 657.7 µs (2.23×), coverage 91%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.3 µs | 1.4 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.8 µs | 1.9 µs | 1 |  | 0.76× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.2 µs | 1.5 µs | 1 |  | 0.94× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 1.1 µs | 1 |  | 1.26× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.1 µs | 1.2 µs | 1 |  | 1.18× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 146.8 µs | 166.2 µs | 1 | 10.0% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 399.3 µs | 384.5 µs | 1 |  | 0.43× | ✓ |
| fors | `fors.v2` ossl-fors-native | 135.9 µs | 161.8 µs | 1 |  | 1.02× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 71.6 µs | 86.6 µs | 1 |  | 1.92× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 124.1 µs | 211.8 µs | 4 |  | 1.24× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.15 ms | 1.32 ms | 1 | 78.5% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.81 ms | 2.01 ms | 1 |  | 0.65× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.20 ms | 1.42 ms | 1 |  | 0.91× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 562.6 µs | 561.7 µs | 1 |  | 2.34× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 344.5 µs | 829.5 µs | 4 |  | 3.64× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 35.5 µs | 44.6 µs | 1 | 2.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 52.0 µs | 67.2 µs | 1 |  | 0.66× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 33.1 µs | 39.5 µs | 1 |  | 1.13× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 17.6 µs | 19.4 µs | 1 |  | 2.30× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 95.3 µs | 126.8 µs | 4 |  | 0.44× | ✓ |

### SLH-DSA-SHA2-192f

end-to-end v0 stages: 4.09 ms, best assembled: 2.01 ms (2.03×), coverage 96%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.3 µs | 1.4 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.8 µs | 2.4 µs | 1 |  | 0.59× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.7 µs | 1.8 µs | 1 |  | 0.77× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.1 µs | 1.2 µs | 1 |  | 1.17× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.1 µs | 1.2 µs | 1 |  | 1.21× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 169.3 µs | 193.4 µs | 1 | 4.1% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 260.1 µs | 303.0 µs | 1 |  | 0.63× | ✓ |
| fors | `fors.v2` ossl-fors-native | 156.9 µs | 168.4 µs | 1 |  | 1.15× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 83.1 µs | 90.4 µs | 1 |  | 2.14× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 119.5 µs | 211.0 µs | 4 |  | 1.54× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 3.71 ms | 3.92 ms | 1 | 90.8% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 6.03 ms | 7.41 ms | 1 |  | 0.53× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.58 ms | 3.60 ms | 1 |  | 1.10× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.80 ms | 1.88 ms | 1 |  | 2.06× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 998.9 µs | 2.96 ms | 4 |  | 3.68× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 57.8 µs | 57.1 µs | 1 | 1.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 54.0 µs | 57.9 µs | 1 |  | 1.00× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 35.0 µs | 40.4 µs | 1 |  | 1.44× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 18.6 µs | 23.7 µs | 1 |  | 2.33× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 109.6 µs | 152.8 µs | 4 |  | 0.50× | ✓ |

### SLH-DSA-SHA2-256s

end-to-end v0 stages: 1.99 ms, best assembled: 994.7 µs (2.00×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.2 µs | 1.3 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 1.9 µs | 1 |  | 0.71× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.2 µs | 1.5 µs | 1 |  | 0.93× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.0 µs | 1.2 µs | 1 |  | 1.09× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.0 µs | 1.1 µs | 1 |  | 1.20× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 188.7 µs | 216.3 µs | 1 | 9.5% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 272.8 µs | 291.7 µs | 1 |  | 0.74× | ✓ |
| fors | `fors.v2` ossl-fors-native | 176.3 µs | 206.4 µs | 1 |  | 1.06× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 94.5 µs | 115.6 µs | 1 |  | 1.86× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 135.4 µs | 239.7 µs | 4 |  | 1.58× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.75 ms | 1.85 ms | 1 | 87.7% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 2.86 ms | 3.34 ms | 1 |  | 0.55× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.77 ms | 1.84 ms | 1 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 868.4 µs | 927.4 µs | 1 |  | 1.97× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 522.4 µs | 1.58 ms | 4 |  | 3.27× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 36.0 µs | 43.6 µs | 1 | 1.8% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 52.1 µs | 58.6 µs | 1 |  | 0.75× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 33.5 µs | 35.5 µs | 1 |  | 1.24× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 17.9 µs | 23.5 µs | 1 |  | 1.84× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 96.7 µs | 130.6 µs | 4 |  | 0.42× | ✓ |

### SLH-DSA-SHA2-256f

end-to-end v0 stages: 3.97 ms, best assembled: 1.92 ms (2.07×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 1.2 µs | 1.4 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.7 µs | 1.8 µs | 1 |  | 0.76× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 1.1 µs | 1.3 µs | 1 |  | 1.04× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.0 µs | 1.1 µs | 1 |  | 1.17× | ✓ |
| hmsg | `hmsg.v4` mgf1-seed-midstate | 1.0 µs | 1.1 µs | 1 |  | 1.14× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 199.4 µs | 213.0 µs | 1 | 5.0% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 290.3 µs | 303.2 µs | 1 |  | 0.71× | ✓ |
| fors | `fors.v2` ossl-fors-native | 196.1 µs | 222.1 µs | 1 |  | 0.96× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 98.4 µs | 106.4 µs | 1 |  | 2.00× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 141.9 µs | 251.9 µs | 4 |  | 1.44× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 3.75 ms | 4.12 ms | 1 | 94.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 5.69 ms | 5.70 ms | 1 |  | 0.72× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.66 ms | 3.73 ms | 1 |  | 1.10× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.82 ms | 2.09 ms | 1 |  | 1.94× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.02 ms | 3.01 ms | 4 |  | 3.77× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 38.5 µs | 45.7 µs | 1 | 1.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 55.4 µs | 60.5 µs | 1 |  | 0.76× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 35.9 µs | 43.5 µs | 1 |  | 1.04× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 19.0 µs | 21.2 µs | 1 |  | 2.15× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 100.8 µs | 137.4 µs | 4 |  | 0.43× | ✓ |

### SLH-DSA-SHAKE-128s

end-to-end v0 stages: 916.4 µs, best assembled: 845.2 µs (1.08×), coverage 108%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.5 µs | 0.5 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.5 µs | 0.5 µs | 1 |  | 0.95× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.4 µs | 0.5 µs | 1 |  | 1.02× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.4 µs | 0.5 µs | 1 |  | 1.04× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 155.5 µs | 146.6 µs | 1 | 17.0% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 83.0 µs | 98.1 µs | 1 |  | 1.48× | ✓ |
| fors | `fors.v2` ossl-fors-native | 76.8 µs | 81.4 µs | 1 |  | 1.80× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 74.8 µs | 103.0 µs | 1 |  | 1.35× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 131.2 µs | 214.1 µs | 4 |  | 1.08× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 809.1 µs | 877.9 µs | 1 | 88.3% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 834.4 µs | 900.8 µs | 1 |  | 0.98× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 782.0 µs | 947.2 µs | 1 |  | 0.92× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 738.0 µs | 786.7 µs | 1 |  | 1.12× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 498.0 µs | 1.17 ms | 4 |  | 1.87× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.2 µs | 32.0 µs | 1 | 3.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 28.2 µs | 32.2 µs | 1 |  | 0.98× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.3 µs | 32.2 µs | 1 |  | 1.00× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.0 µs | 30.0 µs | 1 |  | 1.07× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 108.1 µs | 150.2 µs | 4 |  | 0.28× | ✓ |

### SLH-DSA-SHAKE-128f

end-to-end v0 stages: 2.94 ms, best assembled: 2.78 ms (1.06×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.5 µs | 0.5 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.5 µs | 0.5 µs | 1 |  | 0.94× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.4 µs | 0.5 µs | 1 |  | 1.07× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.4 µs | 0.5 µs | 1 |  | 1.10× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 105.7 µs | 134.8 µs | 1 | 3.6% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 106.3 µs | 130.8 µs | 1 |  | 1.04× | ✓ |
| fors | `fors.v2` ossl-fors-native | 105.5 µs | 126.9 µs | 1 |  | 1.07× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 93.7 µs | 116.8 µs | 1 |  | 1.17× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 131.5 µs | 231.2 µs | 4 |  | 1.03× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 2.77 ms | 2.79 ms | 1 | 94.1% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 2.96 ms | 3.59 ms | 1 |  | 0.77× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 2.84 ms | 3.39 ms | 1 |  | 0.82× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 2.58 ms | 2.79 ms | 1 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.39 ms | 3.86 ms | 4 |  | 1.96× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 28.8 µs | 36.0 µs | 1 | 1.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 29.8 µs | 31.3 µs | 1 |  | 1.17× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 27.8 µs | 30.9 µs | 1 |  | 1.17× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 26.5 µs | 29.7 µs | 1 |  | 1.22× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 101.1 µs | 138.7 µs | 4 |  | 0.34× | ✓ |

### SLH-DSA-SHAKE-192s

end-to-end v0 stages: 1.40 ms, best assembled: 1.27 ms (1.10×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 0.9 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 1.0 µs | 1 |  | 0.90× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 0.9 µs | 1 |  | 0.95× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.8 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 111.9 µs | 117.5 µs | 1 | 8.0% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 116.7 µs | 138.2 µs | 1 |  | 0.85× | ✓ |
| fors | `fors.v2` ossl-fors-native | 111.0 µs | 133.0 µs | 1 |  | 0.87× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 102.7 µs | 117.0 µs | 1 |  | 1.00× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 142.7 µs | 256.0 µs | 4 |  | 0.79× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.26 ms | 1.56 ms | 1 | 89.9% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.31 ms | 1.82 ms | 1 |  | 0.86× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.18 ms | 1.22 ms | 1 |  | 1.28× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.20 ms | 1.39 ms | 1 |  | 1.10× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 761.6 µs | 1.84 ms | 4 |  | 1.91× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.2 µs | 34.0 µs | 1 | 1.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 28.4 µs | 36.0 µs | 1 |  | 0.94× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.3 µs | 33.7 µs | 1 |  | 0.95× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.1 µs | 33.5 µs | 1 |  | 1.01× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 105.0 µs | 147.3 µs | 4 |  | 0.30× | ✓ |

### SLH-DSA-SHAKE-192f

end-to-end v0 stages: 4.01 ms, best assembled: 3.75 ms (1.07×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 0.9 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 1.0 µs | 1 |  | 0.85× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 1.1 µs | 1 |  | 0.81× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.8 µs | 1 |  | 1.10× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 131.4 µs | 145.4 µs | 1 | 3.3% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 162.1 µs | 197.8 µs | 1 |  | 0.74× | ✓ |
| fors | `fors.v2` ossl-fors-native | 155.8 µs | 167.3 µs | 1 |  | 0.87× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 120.6 µs | 144.2 µs | 1 |  | 0.99× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 149.2 µs | 278.6 µs | 4 |  | 0.93× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 3.89 ms | 4.31 ms | 1 | 97.1% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 4.28 ms | 4.97 ms | 1 |  | 0.88× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.94 ms | 4.55 ms | 1 |  | 0.94× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 3.60 ms | 4.36 ms | 1 |  | 0.98× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.92 ms | 4.87 ms | 4 |  | 2.56× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 29.1 µs | 39.5 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 30.1 µs | 33.7 µs | 1 |  | 1.18× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 28.0 µs | 33.9 µs | 1 |  | 1.17× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 26.6 µs | 34.9 µs | 1 |  | 1.12× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 106.3 µs | 150.7 µs | 4 |  | 0.34× | ✓ |

### SLH-DSA-SHAKE-256s

end-to-end v0 stages: 2.09 ms, best assembled: 1.87 ms (1.11×), coverage 96%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 1.0 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 1.6 µs | 1.7 µs | 1 |  | 0.59× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 0.8 µs | 1 |  | 1.18× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 1.0 µs | 1.2 µs | 1 |  | 0.86× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 148.4 µs | 181.1 µs | 1 | 7.1% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 155.1 µs | 199.4 µs | 1 |  | 0.91× | ✓ |
| fors | `fors.v2` ossl-fors-native | 142.8 µs | 182.1 µs | 1 |  | 1.00× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 136.3 µs | 156.8 µs | 1 |  | 1.14× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 159.6 µs | 297.9 µs | 4 |  | 1.10× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 1.83 ms | 2.41 ms | 1 | 87.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 1.96 ms | 2.21 ms | 1 |  | 1.08× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 1.94 ms | 2.39 ms | 1 |  | 1.01× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 1.69 ms | 1.82 ms | 1 |  | 1.31× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.01 ms | 2.60 ms | 4 |  | 2.45× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 27.6 µs | 30.9 µs | 1 | 1.3% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 28.8 µs | 37.7 µs | 1 |  | 0.81× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 26.4 µs | 31.9 µs | 1 |  | 0.98× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 25.3 µs | 29.2 µs | 1 |  | 1.06× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 108.4 µs | 152.3 µs | 4 |  | 0.27× | ✓ |

### SLH-DSA-SHAKE-256f

end-to-end v0 stages: 4.20 ms, best assembled: 3.89 ms (1.08×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` ossl-H_msg | 0.8 µs | 1.1 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` ossl-H_msg-noasm | 0.8 µs | 0.9 µs | 1 |  | 1.18× | ✓ |
| hmsg | `hmsg.v2` ossl-H_msg-native | 0.8 µs | 0.9 µs | 1 |  | 1.27× | ✓ |
| hmsg | `hmsg.v3` lowlevel-hash | 0.8 µs | 0.9 µs | 1 |  | 1.23× | ✓ |
| fors | `fors.v0` ossl-fors_pkFromSig | 180.4 µs | 222.8 µs | 1 | 4.3% | 1.00× | ✓ |
| fors | `fors.v1` ossl-fors-noasm | 165.4 µs | 198.5 µs | 1 |  | 1.11× | ✓ |
| fors | `fors.v2` ossl-fors-native | 149.3 µs | 163.4 µs | 1 |  | 1.37× | ✓ |
| fors | `fors.v3` lowlevel-midstate | 142.1 µs | 155.0 µs | 1 |  | 1.43× | ✓ |
| fors | `fors.v4` pthread-x4-trees | 173.1 µs | 358.0 µs | 4 |  | 1.21× | ✓ |
| ht_wots | `ht_wots.v0` ossl-wots_pkFromSig | 3.89 ms | 4.79 ms | 1 | 92.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` ossl-wots-noasm | 4.28 ms | 4.97 ms | 1 |  | 0.95× | ✓ |
| ht_wots | `ht_wots.v2` ossl-wots-native | 3.90 ms | 4.25 ms | 1 |  | 1.11× | ✓ |
| ht_wots | `ht_wots.v3` lowlevel-midstate | 3.61 ms | 3.71 ms | 1 |  | 1.28× | ✓ |
| ht_wots | `ht_wots.v4` pthread-x4-layers | 1.85 ms | 4.96 ms | 4 |  | 2.70× | ✓ |
| ht_auth | `ht_auth.v0` ossl-xmss-authpath | 29.5 µs | 34.6 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` ossl-authpath-noasm | 30.8 µs | 34.6 µs | 1 |  | 0.98× | ✓ |
| ht_auth | `ht_auth.v2` ossl-authpath-native | 42.3 µs | 41.7 µs | 1 |  | 0.83× | ✓ |
| ht_auth | `ht_auth.v3` lowlevel-midstate | 27.1 µs | 32.0 µs | 1 |  | 1.09× | ✓ |
| ht_auth | `ht_auth.v4` pthread-x4-layers | 107.2 µs | 149.7 µs | 4 |  | 0.31× | ✓ |

