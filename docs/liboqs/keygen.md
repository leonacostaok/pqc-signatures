# liboqs: keygen

`keygen` = seed -> (pk, sk). ML-DSA: ξ (32 B) -> `ML-DSA.KeyGen_internal`; SLH-DSA: `SK.seed ‖ SK.prf ‖ PK.seed`
-> `slh_keygen_internal`. Every variant must reproduce `pk_sha256` **and** `sk_sha256` of `common/reference.json`
(checked at run time, see README). Falcon keygen is included for completeness (`match_basis = self-verify`).

What dominates: ML-DSA keygen is SHAKE-128 matrix expansion (4-way AVX2 Keccak in the x86_64 backend), one NTT per
polynomial and a SHAKE-256 of the public key; it runs in tens of microseconds. SLH-DSA keygen computes the top XMSS
tree (2^h' WOTS+ public keys, i.e. thousands to hundreds of thousands of hash compressions); on the portable
slhdsa-c code this is milliseconds (f sets) to a quarter of a second (SHAKE-256s).

## Variants

| id | name | mechanism |
|---|---|---|
| keygen.v0 | baseline | liboqs default build (`OQS_DIST_BUILD=ON`, gcc -O3, run-time AVX2 dispatch). `OQS_SIG_new` once, then `OQS_SIG_keypair(sig, pk, sk)`; the seed enters through `OQS_randombytes_custom_algorithm` (the only way to seed the public API). |
| keygen.v1 | internal-seeded | Same binary, but the vendored seeded functions are called directly: `PQCP_MLDSA_NATIVE_MLDSA*_X86_64_keypair_internal(pk, sk, ξ)` and `slh_keygen_internal(sk, pk, SK.seed, SK.prf, PK.seed, prm)`. Removes the `OQS_SIG` function-pointer hop, the RNG callback and the per-call `OQS_CPU_has_extension` checks, and shows what a user with a seed API would get. Expected effect: at most a microsecond on ML-DSA, nothing on SLH-DSA. |
| keygen.v2 | march-native | Separate liboqs build with `OQS_DIST_BUILD=OFF`, `OQS_OPT_TARGET=auto` (`-march=native`). Portable C (slhdsa-c hashing, Falcon, the parts of mldsa-native that are not assembly) is compiled for this exact CPU, and the AVX2 backend is bound at compile time. Expected effect: small gain for SLH-DSA hashing (better scheduling, no dispatch), none for the hand-written AVX2 assembly. |
| keygen.v3 | clang-native | Same configuration compiled with clang 18 (`CMAKE_C_COMPILER=clang`). Different optimiser for the SHA-2/Keccak rounds and the WOTS chains; clang tends to unroll and vectorise the slhdsa-c Keccak differently than gcc. |
| keygen.v4 | gcc-pgo | `-march=native` build instrumented with `-fprofile-generate`, trained on all params and ops (`vectors` + short `bench`), rebuilt with `-fprofile-use -fprofile-correction`. Helps hot-loop layout and inlining decisions in the hash core and rejection sampling. |
| keygen.v5 | pthread-x4 | Baseline build; a pool of four pthreads each run k keygens per batch from the same seed (independent output buffers; the RNG callback is stateless so it is thread-safe). Reports batch throughput: `wall_ns_*` = batch wall / (4k), `ops_per_sec` over the whole loop, `threads = 4`, CPU per op from `getrusage` (all threads). Expected effect: up to 4x throughput on a quiet 4-core box; on this shared machine it mostly shows how many cores were free. |

Implementation notes: the variants are selected by `run.sh` as (build flavour, `--path api|direct`, `--threads N`)
for the same driver source; the keygen output of every thread/iteration is hashed and compared with the reference
after warm-up and after the loop.

## Conclusion (preliminary, noisy shared machine)

To be confirmed by the quiet run: ML-DSA keygen is already running the AVX2 backend in the baseline, so build-flavour
variants change little, and `internal-seeded` only trims the dispatcher overhead (a few percent on ML-DSA-44).
For SLH-DSA, `march-native` / `clang` / `pgo` are worth a few percent to tens of percent because the hash core is
compiled C; the only large single-thread win for SLH-DSA comes from the `fasthash` patch used in sign/verify (it was
not assigned to keygen so that keygen could exercise the compiler-level variants instead). The threaded variant
scales keygen almost linearly when cores are free.

<!-- RESULTS -->
