# liboqs: verify

`verify` = (pk, msg, sig) -> bool, pure mode, empty context. Every variant must return `true` on the reference
(pk, msg, sig) and `false` on the signature with one flipped bit, both checked through the same code path on every
run; `output_sha256` is `"true"` only if both hold.

What dominates: ML-DSA verification is matrix expansion (SHAKE-128 x4), a handful of NTTs and one SHAKE-256; it is
the cheapest ML-DSA operation (tens of microseconds with AVX2). SLH-DSA verification recomputes FORS and the d WOTS+
authentication paths: tens of thousands of hash compressions, ~1-10 ms on the portable slhdsa-c code, again
entirely hash-bound. Falcon verification is NTT-only and fast.

## Variants

| id | name | mechanism |
|---|---|---|
| verify.v0 | baseline | liboqs default build; `OQS_SIG_verify(sig, msg, 64, signature, len, pk)` through the `OQS_SIG` dispatcher (no randomness involved, no RNG trickery needed). |
| verify.v1 | internal-direct | Same binary; `PQCP_MLDSA_NATIVE_MLDSA*_X86_64_verify_internal(sig, len, m, mlen, pre = 00‖00, 2, pk, 0)` and `slh_verify(m, mlen, sig, len, NULL, 0, pk, prm)` are called directly. Skips the function-pointer dispatch, the `OQS_CPU_has_extension` checks performed on every call and the wrapper's length handling. Verify is the shortest ML-DSA op, so fixed per-call overhead matters most here. |
| verify.v2 | gcc-lto | `-march=native` non-dist build with `CMAKE_INTERPROCEDURAL_OPTIMIZATION=ON` (gcc `-flto`), driver also linked with `-flto`: lets gcc inline the SHA-2/Keccak/NTT helpers across translation units (slhdsa-c calls its hash functions through small per-parameter-set wrappers that LTO can specialise). |
| verify.v3 | clang-native | `-march=native` non-dist build compiled with clang 18 instead of gcc 13. |
| verify.v4 | fasthash | Patched liboqs (`patches/slh-fasthash.patch`): slhdsa-c's SHA-256/SHA-512 compression functions are replaced by OpenSSL's assembly block functions and its Keccak-f[1600] by liboqs's AVX2 XKCP permutation; ML-DSA/Falcon unaffected. Targets the hash-bound SLH-DSA verification. |
| verify.v5 | pthread-x4 | Baseline build; four pthreads verify the same signature concurrently, batch throughput reported (`threads = 4`). Verification is the operation most often run at scale (many signatures per second on a server), so the parallel variant is the most practically relevant one. |

## Conclusion (preliminary, noisy shared machine)

To be confirmed by the quiet run: `internal-direct` gives the largest single-thread improvement for ML-DSA verify
of all ML-DSA variants (the fixed overhead is a visible fraction of a ~20-30 µs op). For SLH-DSA, `fasthash` is
again the standout (1.5-2x), `gcc-lto` and `clang` are worth a few percent at best, and `pthread-x4` scales
verification throughput with the free cores.

<!-- RESULTS -->
