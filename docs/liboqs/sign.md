# liboqs: sign

`sign` = (sk, msg) -> sig, pure mode, empty context, **deterministic**: ML-DSA with rnd = 0^32, SLH-DSA with
opt_rand = PK.seed. Every variant must reproduce `sig_sha256` of `common/reference.json` (checked at run time).
Hedged/randomised signing is never measured.

What dominates: ML-DSA signing is matrix expansion + rejection-sampling loop (NTTs, decomposition, SHAKE-256 of the
commitment; typically 3-5 attempts), tens to a few hundred microseconds with the AVX2 backend. SLH-DSA signing is
FORS + d XMSS trees, i.e. millions of hash compressions for the `s` sets: with liboqs's portable slhdsa-c code it
takes from ~50 ms (SHA2-128f) to several seconds (SHAKE-256s), so the hash core is everything.

## Variants

| id | name | mechanism |
|---|---|---|
| sign.v0 | baseline | liboqs default build; `OQS_SIG_sign(sig, sig_buf, &len, msg, 64, sk)`. The standard deterministic variants are obtained by making liboqs's RNG return the deterministic values: `OQS_randombytes_custom_algorithm` hands out 32 zero bytes when mldsa-native asks for `rnd`, and `PK.seed` when the slhdsa-c wrapper asks for its n-byte `addrnd`. |
| sign.v1 | internal-deterministic | Same binary; `PQCP_MLDSA_NATIVE_MLDSA*_X86_64_signature_internal(sig, &len, m, mlen, pre = 00‖00, 2, rnd = 0^32, sk, externalmu = 0)` and `slh_sign(sig, m, mlen, NULL, 0, sk, addrnd = NULL, prm)` are called directly: no dispatcher, no RNG call, no per-call CPU check, no `OQS_SIG` length bookkeeping. |
| sign.v2 | march-native | `OQS_DIST_BUILD=OFF`, `-march=native` build: CPU-specific code generation for the C parts (slhdsa-c hashing, mldsa-native C helpers, rejection sampling) and compile-time binding of the AVX2 backend. |
| sign.v3 | fasthash | liboqs rebuilt from a patched checkout (`patches/slh-fasthash.patch`, ~100 lines): slhdsa-c's `sha2_256_compress`/`sha2_512_compress` now call OpenSSL's `SHA256_Transform`/`SHA512_Transform` (hand-written AVX2/SSSE3 block functions; SHA-NI where available) and its `keccak_f1600` calls liboqs's own XKCP `KeccakP1600_Permute_24rounds_avx2` (state copied to a 32-byte aligned buffer, portable fallback when AVX2 is absent). The SLH-DSA algorithm code is untouched, only the primitives are swapped, so the output is bit-identical. ML-DSA and Falcon already use liboqs's XKCP Keccak and are unchanged. |
| sign.v4 | gcc-pgo | Profile-guided `-march=native` build (`-fprofile-generate` -> training over all params/ops -> `-fprofile-use -fprofile-correction`); the rejection-sampling loop and WOTS chain loops get profile-driven layout, unrolling and inlining. |
| sign.v5 | pthread-x4 | Baseline build; four pthreads sign the same message with the same key concurrently (own signature buffers), batch throughput reported (`threads = 4`). |

## Conclusion (preliminary, noisy shared machine)

To be confirmed by the quiet run: for ML-DSA all single-thread variants land within noise of the baseline (the
AVX2 assembly dominates), with `internal-deterministic` a few percent ahead on ML-DSA-44 where the fixed overhead
is largest. For SLH-DSA the picture is different: `fasthash` is the clear winner (roughly 1.5-2x on the SHA2 sets
from OpenSSL's AVX2 SHA-256 and about 1.5x on the SHAKE sets from the AVX2 Keccak), while `march-native` and `pgo`
give modest gains and the `pthread-x4` variant multiplies throughput by the number of free cores. Falcon signing
benefits slightly from the compiler variants (floating-point FFT code in C).

<!-- RESULTS -->
