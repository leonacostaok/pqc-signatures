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
| `decode` | OpenSSL `poly_decode_10_bits` x k, `ossl_ml_dsa_sig_decode` (PACKET based, hint checks: count <= omega, strictly increasing indices, zero padding) | **v1** own unpacker: 5 bytes -> 4 x 10-bit via one u64, z through a 64-bit shift register, same hint rules, no PACKET; **v2** v0 code in the native/LTO build. Only three variants: the stage is a few microseconds of pure byte shuffling with no hashing, so a no-asm build or a third unpacking strategy would be near-duplicates. |
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
