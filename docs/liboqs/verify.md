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
| verify.v2 | gcc-lto | `-march=native` non-dist build with `CMAKE_INTERPROCEDURAL_OPTIMIZATION=ON` (gcc `-flto`), driver also linked with `-flto`: lets gcc inline the SHA-2/Keccak/NTT helpers across translation units (slhdsa-c calls its hash functions through small per-parameter-set wrappers that LTO can specialise). AVX512VL SHA-3 callbacks re-selected at run time (README, notes). |
| verify.v3 | clang-native | `-march=native` non-dist build compiled with clang 18 instead of gcc 13, AVX512VL SHA-3 callbacks re-selected. |
| verify.v4 | fasthash | Patched liboqs (`patches/slh-fasthash.patch`): slhdsa-c's SHA-256/SHA-512 compression functions are replaced by OpenSSL's assembly block functions and its Keccak-f[1600] by liboqs's AVX2 XKCP permutation; ML-DSA/Falcon unaffected. Targets the hash-bound SLH-DSA verification. |
| verify.v5 | pthread-x4 | Baseline build; four pthreads verify the same signature concurrently, batch throughput reported (`threads = 4`). Verification is the operation most often run at scale (many signatures per second on a server), so the parallel variant is the most practically relevant one. |

## Conclusion (preliminary, noisy shared machine)

Dev numbers (noisy): ML-DSA verify is within noise for every single-thread variant; the dispatcher hop removed by
`internal-direct` is below the measurement noise on this loaded machine (expect a few percent on ML-DSA-44 in the
quiet run). For SLH-DSA, `fasthash` is the standout (1.2-2.1x, largest on the SHA2 sets), `internal-direct`,
`gcc-lto` and `clang` land between 1.0x and 1.6x on the SHA2/SHAKE-128 sets, and `pthread-x4` gives 1.2-2.5x
throughput on the loaded box.

<!-- RESULTS -->

## Results (PRELIMINARY dev run: --budget-ms 200, 11 of 17 params, shared/loaded machine; the orchestrator overwrites this section)

From `results/liboqs/bench.jsonl` (liboqs 0.16.0). Speedup = throughput vs `verify.v0`.

### Summary (geometric mean speedup over measured params)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all outputs match |
|---|---|---|---|---|
| `verify.v0` | baseline | 1.00× | 1.00× | yes |
| `verify.v1` | internal-direct | 1.02× | 0.98× | yes |
| `verify.v2` | gcc-lto | 0.99× | 1.02× | yes |
| `verify.v3` | clang-native | 1.03× | 0.97× | yes |
| `verify.v4` | fasthash | 1.13× | 0.89× | yes |
| `verify.v5` | pthread-x4 | 1.41× | 1.08× | yes |

### Per parameter set

#### ML-DSA-44

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 17.9 µs | 29.4 µs | 19.7 µs | 0.96 | 1 | 48658.83 | 1.00× | ✓ |
| `verify.v1` internal-direct | 17.9 µs | 32.5 µs | 22.2 µs | 0.94 | 1 | 42432.79 | 0.87× | ✓ |
| `verify.v2` gcc-lto | 17.8 µs | 29.8 µs | 19.7 µs | 0.99 | 1 | 50499.57 | 1.04× | ✓ |
| `verify.v3` clang-native | 17.6 µs | 22.6 µs | 18.7 µs | 0.94 | 1 | 50164.28 | 1.03× | ✓ |
| `verify.v4` fasthash | 18.1 µs | 32.5 µs | 22.1 µs | 0.99 | 1 | 44626.61 | 0.92× | ✓ |
| `verify.v5` pthread-x4 | 15.7 µs | 45.4 µs | 26.0 µs | 1.28 | 4 | 49106.37 | 1.01× | ✓ |

#### ML-DSA-65

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 28.7 µs | 47.5 µs | 31.5 µs | 0.98 | 1 | 31037.46 | 1.00× | ✓ |
| `verify.v1` internal-direct | 30.3 µs | 57.7 µs | 39.0 µs | 0.99 | 1 | 25333.39 | 0.82× | ✓ |
| `verify.v2` gcc-lto | 28.1 µs | 50.3 µs | 33.0 µs | 0.98 | 1 | 29684.76 | 0.96× | ✓ |
| `verify.v3` clang-native | 27.7 µs | 48.0 µs | 30.2 µs | 0.99 | 1 | 32867.97 | 1.06× | ✓ |
| `verify.v4` fasthash | 29.6 µs | 47.9 µs | 35.4 µs | 0.99 | 1 | 27877.72 | 0.90× | ✓ |
| `verify.v5` pthread-x4 | 23.5 µs | 41.8 µs | 34.8 µs | 1.45 | 4 | 41638.79 | 1.34× | ✓ |

#### ML-DSA-87

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 42.3 µs | 60.5 µs | 44.3 µs | 1.00 | 1 | 22540.27 | 1.00× | ✓ |
| `verify.v1` internal-direct | 42.6 µs | 77.3 µs | 48.4 µs | 0.97 | 1 | 20031.78 | 0.89× | ✓ |
| `verify.v2` gcc-lto | 42.1 µs | 74.4 µs | 49.4 µs | 1.00 | 1 | 20143.35 | 0.89× | ✓ |
| `verify.v3` clang-native | 41.5 µs | 79.6 µs | 47.8 µs | 1.00 | 1 | 20844.65 | 0.92× | ✓ |
| `verify.v4` fasthash | 42.6 µs | 74.1 µs | 50.0 µs | 0.97 | 1 | 19411.91 | 0.86× | ✓ |
| `verify.v5` pthread-x4 | 34.1 µs | 56.7 µs | 48.6 µs | 1.38 | 4 | 28409.13 | 1.26× | ✓ |

#### SLH-DSA-SHA2-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 597.5 µs | 1.33 ms | 780.8 µs | 0.97 | 1 | 1243.65 | 1.00× | ✓ |
| `verify.v1` internal-direct | 567.7 µs | 653.4 µs | 574.4 µs | 0.99 | 1 | 1729.11 | 1.39× | ✓ |
| `verify.v2` gcc-lto | 540.4 µs | 997.1 µs | 627.7 µs | 1.00 | 1 | 1592.75 | 1.28× | ✓ |
| `verify.v3` clang-native | 536.7 µs | 622.2 µs | 548.5 µs | 1.00 | 1 | 1822.48 | 1.47× | ✓ |
| `verify.v4` fasthash | 433.0 µs | 777.4 µs | 521.5 µs | 0.98 | 1 | 1884.26 | 1.52× | ✓ |
| `verify.v5` pthread-x4 | 375.8 µs | 737.8 µs | 734.7 µs | 1.64 | 4 | 2235.08 | 1.80× | ✓ |

#### SLH-DSA-SHA2-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 3.24 ms | 3.60 ms | 2.71 ms | 1.00 | 1 | 369.30 | 1.00× | ✓ |
| `verify.v1` internal-direct | 1.72 ms | 2.37 ms | 1.79 ms | 0.99 | 1 | 551.08 | 1.49× | ✓ |
| `verify.v2` gcc-lto | 2.86 ms | 3.01 ms | 2.86 ms | 1.00 | 1 | 349.51 | 0.95× | ✓ |
| `verify.v3` clang-native | 1.59 ms | 2.24 ms | 1.65 ms | 0.99 | 1 | 598.71 | 1.62× | ✓ |
| `verify.v4` fasthash | 1.28 ms | 1.50 ms | 1.30 ms | 1.00 | 1 | 765.66 | 2.07× | ✓ |
| `verify.v5` pthread-x4 | 963.7 µs | 1.42 ms | 1.99 ms | 1.88 | 4 | 942.87 | 2.55× | ✓ |

#### SLH-DSA-SHA2-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 2.48 ms | 2.79 ms | 2.51 ms | 0.99 | 1 | 395.15 | 1.00× | ✓ |
| `verify.v1` internal-direct | 2.49 ms | 2.72 ms | 2.53 ms | 1.00 | 1 | 394.73 | 1.00× | ✓ |
| `verify.v2` gcc-lto | 2.41 ms | 3.10 ms | 2.55 ms | 0.99 | 1 | 388.26 | 0.98× | ✓ |
| `verify.v3` clang-native | 2.35 ms | 2.54 ms | 2.37 ms | 0.99 | 1 | 418.72 | 1.06× | ✓ |
| `verify.v4` fasthash | 1.84 ms | 2.07 ms | 1.88 ms | 1.00 | 1 | 531.57 | 1.35× | ✓ |
| `verify.v5` pthread-x4 | 2.05 ms | 3.06 ms | 3.17 ms | 1.52 | 4 | 479.46 | 1.21× | ✓ |

#### SLH-DSA-SHAKE-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 1.03 ms | 1.72 ms | 1.15 ms | 1.00 | 1 | 871.44 | 1.00× | ✓ |
| `verify.v1` internal-direct | 973.4 µs | 1.20 ms | 993.8 µs | 0.98 | 1 | 991.25 | 1.14× | ✓ |
| `verify.v2` gcc-lto | 790.9 µs | 1.68 ms | 911.9 µs | 0.96 | 1 | 1055.01 | 1.21× | ✓ |
| `verify.v3` clang-native | 863.6 µs | 1.64 ms | 1.02 ms | 0.99 | 1 | 966.95 | 1.11× | ✓ |
| `verify.v4` fasthash | 874.8 µs | 1.21 ms | 939.9 µs | 0.99 | 1 | 1054.47 | 1.21× | ✓ |
| `verify.v5` pthread-x4 | 660.7 µs | 1.63 ms | 1.12 ms | 1.41 | 4 | 1255.64 | 1.44× | ✓ |

#### SLH-DSA-SHAKE-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 3.31 ms | 4.76 ms | 3.43 ms | 0.97 | 1 | 282.34 | 1.00× | ✓ |
| `verify.v1` internal-direct | 3.03 ms | 4.21 ms | 3.14 ms | 0.99 | 1 | 314.03 | 1.11× | ✓ |
| `verify.v2` gcc-lto | 2.58 ms | 3.35 ms | 2.65 ms | 0.99 | 1 | 372.55 | 1.32× | ✓ |
| `verify.v3` clang-native | 2.67 ms | 4.51 ms | 2.86 ms | 0.98 | 1 | 343.18 | 1.22× | ✓ |
| `verify.v4` fasthash | 2.77 ms | 3.93 ms | 2.93 ms | 0.97 | 1 | 330.88 | 1.17× | ✓ |
| `verify.v5` pthread-x4 | 2.07 ms | 3.55 ms | 3.34 ms | 1.53 | 4 | 458.71 | 1.62× | ✓ |

#### SLH-DSA-SHAKE-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 4.23 ms | 4.60 ms | 4.24 ms | 0.97 | 1 | 229.08 | 1.00× | ✓ |
| `verify.v1` internal-direct | 4.27 ms | 4.76 ms | 4.34 ms | 0.99 | 1 | 228.20 | 1.00× | ✓ |
| `verify.v2` gcc-lto | 5.18 ms | 9.47 ms | 6.20 ms | 0.99 | 1 | 159.96 | 0.70× | ✓ |
| `verify.v3` clang-native | 6.65 ms | 6.90 ms | 6.63 ms | 1.00 | 1 | 150.79 | 0.66× | ✓ |
| `verify.v4` fasthash | 3.71 ms | 3.96 ms | 3.75 ms | 1.00 | 1 | 266.60 | 1.16× | ✓ |
| `verify.v5` pthread-x4 | 4.02 ms | 5.78 ms | 5.28 ms | 1.42 | 4 | 269.40 | 1.18× | ✓ |

#### Falcon-512

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 40.0 µs | 66.1 µs | 43.6 µs | 0.96 | 1 | 22021.55 | 1.00× | ✓ |
| `verify.v1` internal-direct | 39.9 µs | 67.2 µs | 44.8 µs | 1.00 | 1 | 22295.83 | 1.01× | ✓ |
| `verify.v2` gcc-lto | 39.8 µs | 56.9 µs | 41.3 µs | 0.98 | 1 | 23719.41 | 1.08× | ✓ |
| `verify.v3` clang-native | 66.7 µs | 96.1 µs | 62.6 µs | 0.97 | 1 | 15457.71 | 0.70× | ✓ |
| `verify.v4` fasthash | 60.8 µs | 96.5 µs | 61.3 µs | 1.00 | 1 | 16258.27 | 0.74× | ✓ |
| `verify.v5` pthread-x4 | 27.2 µs | 48.4 µs | 52.7 µs | 1.73 | 4 | 32846.11 | 1.49× | ✓ |

#### Falcon-1024

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` baseline | 76.2 µs | 131.5 µs | 85.5 µs | 0.99 | 1 | 11568.93 | 1.00× | ✓ |
| `verify.v1` internal-direct | 114.0 µs | 160.7 µs | 114.0 µs | 1.00 | 1 | 8751.25 | 0.76× | ✓ |
| `verify.v2` gcc-lto | 139.7 µs | 179.4 µs | 128.7 µs | 0.99 | 1 | 7722.63 | 0.67× | ✓ |
| `verify.v3` clang-native | 78.1 µs | 135.6 µs | 89.2 µs | 0.95 | 1 | 10598.85 | 0.92× | ✓ |
| `verify.v4` fasthash | 77.6 µs | 96.3 µs | 80.3 µs | 1.00 | 1 | 12445.41 | 1.08× | ✓ |
| `verify.v5` pthread-x4 | 63.9 µs | 118.2 µs | 98.1 µs | 1.32 | 4 | 13411.36 | 1.16× | ✓ |

