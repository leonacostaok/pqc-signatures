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
| keygen.v2 | march-native | Separate liboqs build with `OQS_DIST_BUILD=OFF`, `OQS_OPT_TARGET=auto` (`-march=native`). Portable C (slhdsa-c hashing, Falcon, the parts of mldsa-native that are not assembly) is compiled for this exact CPU, and the AVX2 backend is bound at compile time. Because non-dist builds never install liboqs's AVX512VL SHA-3 backend (README, notes), the driver re-selects it through `OQS_SHA3_set_callbacks`. Expected effect: small gain for SLH-DSA hashing (better scheduling, no dispatch), none for the hand-written AVX2 assembly. |
| keygen.v3 | clang-native | Same configuration compiled with clang 18 (`CMAKE_C_COMPILER=clang`). Different optimiser for the SHA-2/Keccak rounds and the WOTS chains; clang tends to unroll and vectorise the slhdsa-c Keccak differently than gcc. |
| keygen.v4 | gcc-pgo | `-march=native` build instrumented with `-fprofile-generate`, trained on all params and ops (`vectors` + short `bench`), rebuilt with `-fprofile-use -fprofile-correction`. Helps hot-loop layout and inlining decisions in the hash core and rejection sampling. |
| keygen.v5 | pthread-x4 | Baseline build; a pool of four pthreads each run k keygens per batch from the same seed (independent output buffers; the RNG callback is stateless so it is thread-safe). Reports batch throughput: `wall_ns_*` = batch wall / (4k), `ops_per_sec` over the whole loop, `threads = 4`, CPU per op from `getrusage` (all threads). Expected effect: up to 4x throughput on a quiet 4-core box; on this shared machine it mostly shows how many cores were free. |

Implementation notes: the variants are selected by `run.sh` as (build flavour, `--path api|direct`, `--threads N`)
for the same driver source; the keygen output of every thread/iteration is hashed and compared with the reference
after warm-up and after the loop.

## Conclusion (preliminary, noisy shared machine)

Dev numbers (200 ms budget, other agents benchmarking on the same 4 cores, so +-20 % swings between identical
configurations are common): ML-DSA keygen already runs the AVX2 backend plus the AVX512VL Keccak in the baseline, so
the single-thread variants are within noise of each other (`internal-seeded` only trims a dispatcher hop, ~1 us).
Without the AVX512VL callback re-selection, every non-dist build was 20-30 % *slower* on ML-DSA; that was the most
useful finding of this process. For SLH-DSA, `march-native`, `clang` and `pgo` gain 10-60 % on the SHAKE sets
(gcc/clang vectorise slhdsa-c's Keccak better with `-march=native`) and little on the SHA2 sets. The threaded variant
gives 1.2-2.2x on the loaded machine and should approach 4x on a quiet one.

<!-- RESULTS -->

## Results (PRELIMINARY dev run: --budget-ms 200, 11 of 17 params, shared/loaded machine; the orchestrator overwrites this section)

From `results/liboqs/bench.jsonl` (liboqs 0.16.0). Speedup = throughput vs `keygen.v0`.

### Summary (geometric mean speedup over measured params)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all outputs match |
|---|---|---|---|---|
| `keygen.v0` | baseline | 1.00× | 1.00× | yes |
| `keygen.v1` | internal-seeded | 1.03× | 0.98× | yes |
| `keygen.v2` | march-native | 1.08× | 0.93× | yes |
| `keygen.v3` | clang-native | 1.01× | 1.00× | yes |
| `keygen.v4` | gcc-pgo | 1.10× | 0.92× | yes |
| `keygen.v5` | pthread-x4 | 1.51× | 1.12× | yes |

### Per parameter set

#### ML-DSA-44

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 16.1 µs | 27.1 µs | 17.8 µs | 0.97 | 1 | 54548.79 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 16.0 µs | 29.1 µs | 20.2 µs | 1.00 | 1 | 49226.82 | 0.90× | ✓ |
| `keygen.v2` march-native | 15.8 µs | 20.2 µs | 17.0 µs | 0.99 | 1 | 57927.21 | 1.06× | ✓ |
| `keygen.v3` clang-native | 16.1 µs | 17.2 µs | 16.8 µs | 1.00 | 1 | 59487.28 | 1.09× | ✓ |
| `keygen.v4` gcc-pgo | 15.8 µs | 30.2 µs | 17.8 µs | 0.99 | 1 | 55952.64 | 1.03× | ✓ |
| `keygen.v5` pthread-x4 | 10.0 µs | 20.2 µs | 18.2 µs | 1.56 | 4 | 85707.01 | 1.57× | ✓ |

#### ML-DSA-65

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 27.3 µs | 44.1 µs | 29.3 µs | 0.95 | 1 | 32585.90 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 27.2 µs | 39.9 µs | 29.0 µs | 0.99 | 1 | 34234.73 | 1.05× | ✓ |
| `keygen.v2` march-native | 27.1 µs | 41.5 µs | 29.1 µs | 0.99 | 1 | 33996.84 | 1.04× | ✓ |
| `keygen.v3` clang-native | 27.2 µs | 31.4 µs | 28.4 µs | 1.00 | 1 | 35192.49 | 1.08× | ✓ |
| `keygen.v4` gcc-pgo | 27.2 µs | 38.2 µs | 28.6 µs | 1.00 | 1 | 34961.62 | 1.07× | ✓ |
| `keygen.v5` pthread-x4 | 25.3 µs | 37.2 µs | 42.0 µs | 1.61 | 4 | 38269.28 | 1.17× | ✓ |

#### ML-DSA-87

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 41.9 µs | 104.5 µs | 53.4 µs | 0.96 | 1 | 18039.27 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 41.9 µs | 64.5 µs | 45.3 µs | 0.99 | 1 | 21937.07 | 1.22× | ✓ |
| `keygen.v2` march-native | 41.5 µs | 60.2 µs | 44.0 µs | 1.00 | 1 | 22636.56 | 1.25× | ✓ |
| `keygen.v3` clang-native | 41.4 µs | 48.4 µs | 43.0 µs | 1.00 | 1 | 23177.15 | 1.28× | ✓ |
| `keygen.v4` gcc-pgo | 41.4 µs | 60.6 µs | 44.4 µs | 0.99 | 1 | 22402.45 | 1.24× | ✓ |
| `keygen.v5` pthread-x4 | 38.7 µs | 54.8 µs | 55.4 µs | 1.45 | 4 | 26135.17 | 1.45× | ✓ |

#### SLH-DSA-SHA2-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 78.50 ms | 78.50 ms | 78.62 ms | 0.99 | 1 | 12.60 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 72.31 ms | 72.31 ms | 72.36 ms | 1.00 | 1 | 13.80 | 1.10× | ✓ |
| `keygen.v2` march-native | 78.03 ms | 78.03 ms | 84.37 ms | 0.99 | 1 | 11.77 | 0.93× | ✓ |
| `keygen.v3` clang-native | 117.57 ms | 117.57 ms | 115.24 ms | 0.99 | 1 | 8.64 | 0.69× | ✓ |
| `keygen.v4` gcc-pgo | 112.93 ms | 112.93 ms | 111.31 ms | 1.00 | 1 | 8.98 | 0.71× | ✓ |
| `keygen.v5` pthread-x4 | 44.13 ms | 44.13 ms | 76.69 ms | 1.82 | 4 | 23.77 | 1.89× | ✓ |

#### SLH-DSA-SHA2-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 1.14 ms | 1.51 ms | 1.19 ms | 0.99 | 1 | 833.54 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 1.12 ms | 1.23 ms | 1.14 ms | 1.00 | 1 | 875.51 | 1.05× | ✓ |
| `keygen.v2` march-native | 1.13 ms | 1.79 ms | 1.20 ms | 0.98 | 1 | 818.40 | 0.98× | ✓ |
| `keygen.v3` clang-native | 1.88 ms | 3.05 ms | 2.01 ms | 0.99 | 1 | 494.72 | 0.59× | ✓ |
| `keygen.v4` gcc-pgo | 1.09 ms | 1.15 ms | 1.11 ms | 1.00 | 1 | 902.74 | 1.08× | ✓ |
| `keygen.v5` pthread-x4 | 916.5 µs | 2.18 ms | 1.39 ms | 1.37 | 4 | 991.28 | 1.19× | ✓ |

#### SLH-DSA-SHA2-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 4.48 ms | 6.06 ms | 4.82 ms | 0.98 | 1 | 203.32 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 4.38 ms | 4.63 ms | 4.41 ms | 1.00 | 1 | 226.52 | 1.11× | ✓ |
| `keygen.v2` march-native | 4.24 ms | 4.42 ms | 4.26 ms | 1.00 | 1 | 233.63 | 1.15× | ✓ |
| `keygen.v3` clang-native | 4.15 ms | 4.27 ms | 4.17 ms | 1.00 | 1 | 239.87 | 1.18× | ✓ |
| `keygen.v4` gcc-pgo | 4.20 ms | 4.47 ms | 4.31 ms | 1.00 | 1 | 231.94 | 1.14× | ✓ |
| `keygen.v5` pthread-x4 | 3.97 ms | 7.57 ms | 6.54 ms | 1.54 | 4 | 236.13 | 1.16× | ✓ |

#### SLH-DSA-SHAKE-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 146.67 ms | 146.67 ms | 145.96 ms | 1.00 | 1 | 6.82 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 130.27 ms | 130.27 ms | 157.36 ms | 1.00 | 1 | 6.34 | 0.93× | ✓ |
| `keygen.v2` march-native | 107.76 ms | 107.76 ms | 107.37 ms | 1.00 | 1 | 9.30 | 1.36× | ✓ |
| `keygen.v3` clang-native | 120.88 ms | 120.88 ms | 121.93 ms | 0.99 | 1 | 8.15 | 1.19× | ✓ |
| `keygen.v4` gcc-pgo | 113.04 ms | 113.04 ms | 110.01 ms | 0.98 | 1 | 8.91 | 1.31× | ✓ |
| `keygen.v5` pthread-x4 | 83.74 ms | 83.74 ms | 156.49 ms | 1.87 | 4 | 11.94 | 1.75× | ✓ |

#### SLH-DSA-SHAKE-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 2.63 ms | 3.63 ms | 2.74 ms | 1.00 | 1 | 363.94 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 2.02 ms | 2.11 ms | 2.03 ms | 1.00 | 1 | 491.43 | 1.35× | ✓ |
| `keygen.v2` march-native | 1.67 ms | 1.88 ms | 1.70 ms | 0.99 | 1 | 585.45 | 1.61× | ✓ |
| `keygen.v3` clang-native | 1.83 ms | 3.28 ms | 2.10 ms | 1.00 | 1 | 474.89 | 1.30× | ✓ |
| `keygen.v4` gcc-pgo | 1.66 ms | 1.91 ms | 1.71 ms | 1.00 | 1 | 584.02 | 1.60× | ✓ |
| `keygen.v5` pthread-x4 | 1.13 ms | 1.74 ms | 2.24 ms | 1.81 | 4 | 809.59 | 2.22× | ✓ |

#### SLH-DSA-SHAKE-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 7.68 ms | 7.76 ms | 7.67 ms | 1.00 | 1 | 130.13 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 7.89 ms | 8.41 ms | 7.89 ms | 0.98 | 1 | 124.39 | 0.96× | ✓ |
| `keygen.v2` march-native | 9.84 ms | 13.13 ms | 9.33 ms | 1.00 | 1 | 106.87 | 0.82× | ✓ |
| `keygen.v3` clang-native | 7.12 ms | 13.69 ms | 8.00 ms | 0.99 | 1 | 123.91 | 0.95× | ✓ |
| `keygen.v4` gcc-pgo | 6.51 ms | 6.76 ms | 6.55 ms | 1.00 | 1 | 152.37 | 1.17× | ✓ |
| `keygen.v5` pthread-x4 | 4.48 ms | 5.25 ms | 8.26 ms | 1.79 | 4 | 217.35 | 1.67× | ✓ |

#### Falcon-512

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 7.85 ms | 8.24 ms | 7.91 ms | 1.00 | 1 | 126.03 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 8.40 ms | 12.09 ms | 9.07 ms | 0.99 | 1 | 109.19 | 0.87× | ✓ |
| `keygen.v2` march-native | 7.96 ms | 9.66 ms | 8.32 ms | 0.96 | 1 | 116.08 | 0.92× | ✓ |
| `keygen.v3` clang-native | 7.03 ms | 7.83 ms | 7.30 ms | 1.00 | 1 | 136.99 | 1.09× | ✓ |
| `keygen.v4` gcc-pgo | 7.81 ms | 8.38 ms | 7.94 ms | 1.00 | 1 | 125.93 | 1.00× | ✓ |
| `keygen.v5` pthread-x4 | 5.42 ms | 6.46 ms | 9.55 ms | 1.84 | 4 | 192.36 | 1.53× | ✓ |

#### Falcon-1024

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` baseline | 17.58 ms | 17.77 ms | 17.50 ms | 0.99 | 1 | 56.86 | 1.00× | ✓ |
| `keygen.v1` internal-seeded | 18.31 ms | 21.41 ms | 18.27 ms | 0.96 | 1 | 52.57 | 0.92× | ✓ |
| `keygen.v2` march-native | 17.46 ms | 17.99 ms | 17.30 ms | 0.99 | 1 | 57.23 | 1.01× | ✓ |
| `keygen.v3` clang-native | 18.22 ms | 23.13 ms | 18.61 ms | 1.00 | 1 | 53.73 | 0.94× | ✓ |
| `keygen.v4` gcc-pgo | 17.77 ms | 18.25 ms | 17.64 ms | 1.00 | 1 | 56.51 | 0.99× | ✓ |
| `keygen.v5` pthread-x4 | 12.73 ms | 15.83 ms | 22.92 ms | 1.76 | 4 | 76.96 | 1.35× | ✓ |

