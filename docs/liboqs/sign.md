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
| sign.v2 | march-native | `OQS_DIST_BUILD=OFF`, `-march=native` build: CPU-specific code generation for the C parts (slhdsa-c hashing, mldsa-native C helpers, rejection sampling) and compile-time binding of the AVX2 backend; AVX512VL SHA-3 callbacks re-selected at run time (README, notes). |
| sign.v3 | fasthash | liboqs rebuilt from a patched checkout (`patches/slh-fasthash.patch`, ~100 lines): slhdsa-c's `sha2_256_compress`/`sha2_512_compress` now call OpenSSL's `SHA256_Transform`/`SHA512_Transform` (hand-written AVX2/SSSE3 block functions; SHA-NI where available) and its `keccak_f1600` calls liboqs's own XKCP `KeccakP1600_Permute_24rounds_avx2` (lanes remapped into XKCP's permuted AVX2 state order and back, 32-byte aligned buffer, portable fallback when AVX2 is absent). The SLH-DSA algorithm code is untouched, only the primitives are swapped, so the output is bit-identical. ML-DSA and Falcon already use liboqs's XKCP Keccak and are unchanged. |
| sign.v4 | gcc-pgo | Profile-guided `-march=native` build (`-fprofile-generate` -> training over all params/ops -> `-fprofile-use -fprofile-correction`); the rejection-sampling loop and WOTS chain loops get profile-driven layout, unrolling and inlining. |
| sign.v5 | pthread-x4 | Baseline build; four pthreads sign the same message with the same key concurrently (own signature buffers), batch throughput reported (`threads = 4`). |

## Conclusion (preliminary, noisy shared machine)

Dev numbers (noisy): for ML-DSA all single-thread variants land within noise of the baseline (the AVX2 assembly
and the rejection loop dominate; the deterministic internal call saves nothing measurable). For SLH-DSA the
mechanisms that touch the hash core matter: `fasthash` gives 1.1-1.4x (OpenSSL's AVX2 SHA-256/512 block functions on
the SHA2 sets; the XKCP AVX2 Keccak on the SHAKE sets, where the 2x25-lane remap per permutation eats part of the
gain), and `march-native`/`pgo` give 1.2-1.5x on the SHAKE sets because gcc vectorises slhdsa-c's portable Keccak
much better with AVX2/AVX-512 enabled. `pthread-x4` gives 1.3-2.2x on the loaded box. Falcon is unaffected by
everything except the compiler (within noise).

<!-- RESULTS -->

## Results (PRELIMINARY dev run: --budget-ms 200, 11 of 17 params, shared/loaded machine; the orchestrator overwrites this section)

From `results/liboqs/bench.jsonl` (liboqs 0.16.0). Speedup = throughput vs `sign.v0`.

### Summary (geometric mean speedup over measured params)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all outputs match |
|---|---|---|---|---|
| `sign.v0` | baseline | 1.00× | 1.00× | yes |
| `sign.v1` | internal-deterministic | 0.95× | 1.04× | yes |
| `sign.v2` | march-native | 1.09× | 0.92× | yes |
| `sign.v3` | fasthash | 1.09× | 0.92× | yes |
| `sign.v4` | gcc-pgo | 1.06× | 0.95× | yes |
| `sign.v5` | pthread-x4 | 1.53× | 1.03× | yes |

### Per parameter set

#### ML-DSA-44

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 26.4 µs | 41.8 µs | 28.5 µs | 0.94 | 1 | 33096.36 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 26.1 µs | 46.3 µs | 28.7 µs | 0.89 | 1 | 30814.51 | 0.93× | ✓ |
| `sign.v2` march-native | 26.1 µs | 48.2 µs | 31.5 µs | 0.99 | 1 | 31481.45 | 0.95× | ✓ |
| `sign.v3` fasthash | 26.5 µs | 51.6 µs | 35.1 µs | 0.96 | 1 | 27494.20 | 0.83× | ✓ |
| `sign.v4` gcc-pgo | 31.6 µs | 52.9 µs | 36.3 µs | 0.99 | 1 | 27298.97 | 0.82× | ✓ |
| `sign.v5` pthread-x4 | 26.3 µs | 47.5 µs | 34.4 µs | 1.22 | 4 | 35305.36 | 1.07× | ✓ |

#### ML-DSA-65

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 101.7 µs | 140.7 µs | 109.7 µs | 1.00 | 1 | 9092.09 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 103.7 µs | 205.0 µs | 126.5 µs | 0.99 | 1 | 7802.59 | 0.86× | ✓ |
| `sign.v2` march-native | 107.5 µs | 211.3 µs | 131.7 µs | 0.98 | 1 | 7461.43 | 0.82× | ✓ |
| `sign.v3` fasthash | 103.0 µs | 199.1 µs | 122.1 µs | 0.97 | 1 | 7979.96 | 0.88× | ✓ |
| `sign.v4` gcc-pgo | 127.1 µs | 199.1 µs | 133.7 µs | 1.00 | 1 | 7474.31 | 0.82× | ✓ |
| `sign.v5` pthread-x4 | 82.5 µs | 121.3 µs | 125.7 µs | 1.60 | 4 | 12754.67 | 1.40× | ✓ |

#### ML-DSA-87

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 74.4 µs | 122.8 µs | 84.1 µs | 1.00 | 1 | 11832.41 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 75.5 µs | 148.1 µs | 92.8 µs | 0.99 | 1 | 10661.96 | 0.90× | ✓ |
| `sign.v2` march-native | 73.6 µs | 105.9 µs | 79.3 µs | 0.99 | 1 | 12493.64 | 1.06× | ✓ |
| `sign.v3` fasthash | 80.5 µs | 141.8 µs | 92.8 µs | 1.00 | 1 | 10754.91 | 0.91× | ✓ |
| `sign.v4` gcc-pgo | 75.9 µs | 96.8 µs | 80.2 µs | 0.98 | 1 | 12244.49 | 1.03× | ✓ |
| `sign.v5` pthread-x4 | 43.3 µs | 64.8 µs | 82.3 µs | 1.71 | 4 | 20842.16 | 1.76× | ✓ |

#### SLH-DSA-SHA2-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 575.41 ms | 575.41 ms | 591.96 ms | 0.99 | 1 | 1.67 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 622.32 ms | 622.32 ms | 611.72 ms | 0.99 | 1 | 1.62 | 0.97× | ✓ |
| `sign.v2` march-native | 593.03 ms | 593.03 ms | 604.04 ms | 0.99 | 1 | 1.64 | 0.98× | ✓ |
| `sign.v3` fasthash | 557.87 ms | 557.87 ms | 529.73 ms | 0.99 | 1 | 1.87 | 1.12× | ✓ |
| `sign.v4` gcc-pgo | 542.00 ms | 542.00 ms | 550.90 ms | 1.00 | 1 | 1.81 | 1.08× | ✓ |
| `sign.v5` pthread-x4 | 366.28 ms | 366.28 ms | 687.34 ms | 1.88 | 4 | 2.73 | 1.63× | ✓ |

#### SLH-DSA-SHA2-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 33.61 ms | 35.80 ms | 33.60 ms | 0.99 | 1 | 29.61 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 29.26 ms | 39.93 ms | 33.82 ms | 1.00 | 1 | 29.55 | 1.00× | ✓ |
| `sign.v2` march-native | 26.64 ms | 27.74 ms | 26.96 ms | 1.00 | 1 | 36.98 | 1.25× | ✓ |
| `sign.v3` fasthash | 32.55 ms | 36.02 ms | 29.13 ms | 1.00 | 1 | 34.24 | 1.16× | ✓ |
| `sign.v4` gcc-pgo | 27.38 ms | 28.29 ms | 27.48 ms | 1.00 | 1 | 36.34 | 1.23× | ✓ |
| `sign.v5` pthread-x4 | 15.07 ms | 15.88 ms | 28.47 ms | 1.88 | 4 | 66.02 | 2.23× | ✓ |

#### SLH-DSA-SHA2-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 96.57 ms | 96.57 ms | 95.96 ms | 0.99 | 1 | 10.36 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 95.90 ms | 95.90 ms | 95.75 ms | 0.99 | 1 | 10.38 | 1.00× | ✓ |
| `sign.v2` march-native | 89.09 ms | 89.09 ms | 88.90 ms | 0.99 | 1 | 11.20 | 1.08× | ✓ |
| `sign.v3` fasthash | 70.95 ms | 70.95 ms | 70.67 ms | 1.00 | 1 | 14.11 | 1.36× | ✓ |
| `sign.v4` gcc-pgo | 116.77 ms | 116.77 ms | 110.92 ms | 0.98 | 1 | 8.82 | 0.85× | ✓ |
| `sign.v5` pthread-x4 | 51.97 ms | 51.97 ms | 96.97 ms | 1.94 | 4 | 19.95 | 1.93× | ✓ |

#### SLH-DSA-SHAKE-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 1.32 s | 1.32 s | 1.26 s | 0.99 | 1 | 0.78 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 1.23 s | 1.23 s | 1.16 s | 0.99 | 1 | 0.85 | 1.09× | ✓ |
| `sign.v2` march-native | 904.00 ms | 904.00 ms | 892.08 ms | 0.99 | 1 | 1.11 | 1.42× | ✓ |
| `sign.v3` fasthash | 874.62 ms | 874.62 ms | 874.18 ms | 1.00 | 1 | 1.14 | 1.46× | ✓ |
| `sign.v4` gcc-pgo | 844.70 ms | 844.70 ms | 850.16 ms | 1.00 | 1 | 1.17 | 1.50× | ✓ |
| `sign.v5` pthread-x4 | 675.33 ms | 675.33 ms | 1.13 s | 1.67 | 4 | 1.48 | 1.89× | ✓ |

#### SLH-DSA-SHAKE-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 51.08 ms | 51.08 ms | 50.47 ms | 1.00 | 1 | 19.81 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 47.82 ms | 47.85 ms | 47.88 ms | 1.00 | 1 | 20.88 | 1.05× | ✓ |
| `sign.v2` march-native | 39.68 ms | 39.96 ms | 39.68 ms | 1.00 | 1 | 25.16 | 1.27× | ✓ |
| `sign.v3` fasthash | 45.72 ms | 46.37 ms | 44.45 ms | 0.99 | 1 | 22.25 | 1.12× | ✓ |
| `sign.v4` gcc-pgo | 39.65 ms | 39.81 ms | 39.41 ms | 1.00 | 1 | 25.32 | 1.28× | ✓ |
| `sign.v5` pthread-x4 | 39.19 ms | 39.19 ms | 50.69 ms | 1.35 | 4 | 26.55 | 1.34× | ✓ |

#### SLH-DSA-SHAKE-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 168.66 ms | 168.66 ms | 177.04 ms | 1.00 | 1 | 5.64 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 191.34 ms | 191.34 ms | 183.98 ms | 1.00 | 1 | 5.42 | 0.96× | ✓ |
| `sign.v2` march-native | 146.94 ms | 146.94 ms | 148.64 ms | 1.00 | 1 | 6.71 | 1.19× | ✓ |
| `sign.v3` fasthash | 140.92 ms | 140.92 ms | 140.70 ms | 1.00 | 1 | 7.11 | 1.26× | ✓ |
| `sign.v4` gcc-pgo | 137.49 ms | 137.49 ms | 143.47 ms | 1.00 | 1 | 6.96 | 1.23× | ✓ |
| `sign.v5` pthread-x4 | 122.41 ms | 122.41 ms | 168.06 ms | 1.37 | 4 | 8.17 | 1.45× | ✓ |

#### Falcon-512

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 236.1 µs | 395.1 µs | 277.6 µs | 0.99 | 1 | 3585.85 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 260.5 µs | 672.6 µs | 342.3 µs | 0.99 | 1 | 2886.48 | 0.80× | ✓ |
| `sign.v2` march-native | 210.4 µs | 300.7 µs | 225.0 µs | 0.98 | 1 | 4357.14 | 1.22× | ✓ |
| `sign.v3` fasthash | 220.8 µs | 394.8 µs | 262.9 µs | 1.00 | 1 | 3804.30 | 1.06× | ✓ |
| `sign.v4` gcc-pgo | 235.9 µs | 370.4 µs | 266.5 µs | 1.00 | 1 | 3751.61 | 1.05× | ✓ |
| `sign.v5` pthread-x4 | 194.4 µs | 389.1 µs | 259.1 µs | 1.15 | 4 | 4448.82 | 1.24× | ✓ |

#### Falcon-1024

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` baseline | 459.2 µs | 675.3 µs | 478.3 µs | 0.99 | 1 | 2080.73 | 1.00× | ✓ |
| `sign.v1` internal-deterministic | 472.2 µs | 603.2 µs | 485.8 µs | 0.98 | 1 | 2018.66 | 0.97× | ✓ |
| `sign.v2` march-native | 455.1 µs | 756.5 µs | 516.1 µs | 0.99 | 1 | 1924.24 | 0.92× | ✓ |
| `sign.v3` fasthash | 463.7 µs | 505.2 µs | 466.3 µs | 1.00 | 1 | 2142.07 | 1.03× | ✓ |
| `sign.v4` gcc-pgo | 480.2 µs | 522.4 µs | 481.9 µs | 1.00 | 1 | 2074.15 | 1.00× | ✓ |
| `sign.v5` pthread-x4 | 375.0 µs | 588.4 µs | 591.3 µs | 1.59 | 4 | 2696.22 | 1.30× | ✓ |

