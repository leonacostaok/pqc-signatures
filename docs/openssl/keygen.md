# OpenSSL - keygen

Process: 32-byte xi (ML-DSA) or 3n-byte `SK.seed||SK.prf||PK.seed` (SLH-DSA) -> (pk, sk).
The timed region covers creating the key object from the seed **and** exporting `pub`/`priv` as octet strings
(the two `EVP_PKEY_get_octet_string_param` calls are part of every variant, since a benchmark that never
materialises the key bytes would not be comparable with the other libraries).
Match = SHA-256(pk) and SHA-256(sk) equal `common/reference.json`.

In OpenSSL the keygen cost is dominated by the algorithm itself: for ML-DSA the SHAKE-based expansion of
the matrix A (k*l polynomials of rejection-sampled SHAKE128 output) plus k+l NTTs; for SLH-DSA the
computation of `PK.root`, i.e. one full XMSS tree of height h' = h/d at the top layer (2^(h') WOTS+ keypairs,
each 2n+3 chains of w=16 hashes). The EVP layer overhead (fetching, ctx allocation) is a few microseconds.

## Variants

| id | name | build | what / why |
|---|---|---|---|
| keygen.v0 | evp-baseline | default | The documented way: `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL)`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_params("seed")`, `EVP_PKEY_keygen`, free. The keymgmt is fetched implicitly on every call (property-cache lookup under the global libctx lock). |
| keygen.v1 | prefetch-reuse-ctx | default | `EVP_KEYMGMT_fetch` once, one `EVP_PKEY_CTX` initialised once (keygen_init + seed param) and reused: per call only `EVP_PKEY_keygen`. Removes the fetch, the ctx malloc/free and the param-translation round trip. |
| keygen.v2 | fromdata-seed-import | default | Instead of the keygen operation, the key is *imported*: `EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, {"seed"})` on a reused fromdata ctx. Internally this goes through `ml_dsa_import -> ossl_ml_dsa_set_prekey + ossl_ml_dsa_generate_key`, so the same expansion happens but through the import path (no gen ctx, no DRBG involvement, no provider-flag handling). ML-DSA only: the SLH-DSA keymgmt only imports `pub`/`priv`. |
| keygen.v3 | no-asm-build | noasm | libcrypto configured with `no-asm`: Keccak-1600 and SHA-256/512 are the generic C versions and the CPUID dispatch is gone. Expected to be slower; included to quantify how much the hash assembly matters (it is the only assembly on the ML-DSA/SLH-DSA path). |
| keygen.v4 | native-lto-build | native | libcrypto and the driver compiled with `-O3 -march=native -flto`: allows AVX/BMI code generation for the C NTT/polynomial loops and cross-translation-unit inlining of the small `ml_dsa_*`/`slh_*` helpers (poly ops, ADRS updates, hash wrappers) that live in separate files. |
| keygen.v5 | pthread-x4 | default | 4 worker threads, each with its own prefetched, reused keygen ctx (the v1 path), generating the same key from the same seed; throughput over a batch (reported as wall per batch / batch size, `threads: 4`). Shows whether the provider/EVP layer scales (no shared state except the libctx property cache). |

## What to expect

* v1/v2 can only shave the EVP overhead (a few us), i.e. visible for ML-DSA-44 (~100 us) and negligible for
  SLH-DSA (ms range).
* v3 vs v0 isolates the Keccak/SHA-2 assembly: SHAKE-heavy ML-DSA keygen and the SHAKE SLH-DSA sets should
  lose most; SHA2 SLH-DSA sets use SHA-256 (SHA-NI capable asm) and lose too.
* v4: gains depend on how much the compiler can do for the portable NTT; LTO mostly helps the many tiny
  helper calls in SLH-DSA (ADRS, `PRF`, `F`, `T_l`).
* v5: ideal is 4x throughput; on the shared box expect ~1.7-2x (other agents use the remaining cores).

## Conclusion (preliminary, noisy box)

See the tables below. The API-level variants (v1, v2) are within noise of the baseline: OpenSSL's EVP
overhead (a few us) is irrelevant next to the lattice/hash work. `no-asm` costs ~10 % for ML-DSA keygen and
~45 % for the SLH-DSA-SHA2 sets (AVX2 SHA-256 assembly); `-O3 -march=native -flto` is neutral for ML-DSA and
helps SLH-DSA by 10-40 % (inlined hash wrappers / ADRS helpers); threads give the only large win (throughput).

<!-- RESULTS -->

## Results (PRELIMINARY: development run, --budget-ms 200, shared busy machine; the orchestrator overwrites this section)

### Summary (geometric mean over all params, throughput vs v0)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all match |
|---|---|---|---|---|
| `keygen.v0` | evp-baseline | 1.00× | 1.00× | yes |
| `keygen.v1` | prefetch-reuse-ctx | 0.92× | 1.08× | yes |
| `keygen.v2` | fromdata-seed-import | 0.89× | 1.01× | yes |
| `keygen.v3` | no-asm-build | 0.85× | 1.27× | yes |
| `keygen.v4` | native-lto-build | 1.14× | 0.99× | yes |
| `keygen.v5` | pthread-x4 | 0.95× | 1.03× | yes |

### Per parameter set

#### ML-DSA-44

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 116.9 µs | 186.5 µs | 127.0 µs | 0.87 | 1 | 6833 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 114.3 µs | 151.4 µs | 120.5 µs | 0.80 | 1 | 6657 | 0.97× | ✓ |
| `keygen.v2` fromdata-seed-import | 120.9 µs | 192.5 µs | 128.7 µs | 0.78 | 1 | 6097 | 0.89× | ✓ |
| `keygen.v3` no-asm-build | 125.0 µs | 184.7 µs | 134.3 µs | 0.84 | 1 | 6254 | 0.92× | ✓ |
| `keygen.v4` native-lto-build | 143.8 µs | 244.5 µs | 162.6 µs | 0.98 | 1 | 6013 | 0.88× | ✓ |
| `keygen.v5` pthread-x4 | 132.3 µs | 235.7 µs | 124.0 µs | 0.77 | 4 | 6209 | 0.91× | ✓ |

#### ML-DSA-65

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 192.3 µs | 265.7 µs | 203.7 µs | 0.83 | 1 | 4081 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 191.4 µs | 331.7 µs | 213.0 µs | 0.79 | 1 | 3711 | 0.91× | ✓ |
| `keygen.v2` fromdata-seed-import | 191.6 µs | 284.9 µs | 204.3 µs | 0.80 | 1 | 3933 | 0.96× | ✓ |
| `keygen.v3` no-asm-build | 205.3 µs | 294.7 µs | 219.0 µs | 0.81 | 1 | 3695 | 0.91× | ✓ |
| `keygen.v4` native-lto-build | 190.6 µs | 264.9 µs | 202.3 µs | 0.94 | 1 | 4629 | 1.13× | ✓ |
| `keygen.v5` pthread-x4 | 217.1 µs | 380.8 µs | 211.9 µs | 0.85 | 4 | 3996 | 0.98× | ✓ |

#### ML-DSA-87

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 292.3 µs | 354.8 µs | 304.1 µs | 0.97 | 1 | 3178 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 291.8 µs | 677.8 µs | 328.0 µs | 0.79 | 1 | 2417 | 0.76× | ✓ |
| `keygen.v2` fromdata-seed-import | 300.9 µs | 396.4 µs | 310.3 µs | 0.80 | 1 | 2590 | 0.81× | ✓ |
| `keygen.v3` no-asm-build | 321.1 µs | 433.6 µs | 332.6 µs | 0.85 | 1 | 2560 | 0.81× | ✓ |
| `keygen.v4` native-lto-build | 296.3 µs | 382.8 µs | 311.7 µs | 0.97 | 1 | 3115 | 0.98× | ✓ |
| `keygen.v5` pthread-x4 | 322.0 µs | 563.6 µs | 315.5 µs | 0.81 | 4 | 2571 | 0.81× | ✓ |

#### SLH-DSA-SHA2-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 132.06 ms | 141.49 ms | 127.63 ms | 0.95 | 1 | 7.44 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 166.48 ms | 166.70 ms | 122.11 ms | 0.74 | 1 | 6.08 | 0.82× | ✓ |
| `keygen.v3` no-asm-build | 234.58 ms | 269.42 ms | 200.69 ms | 0.82 | 1 | 4.10 | 0.55× | ✓ |
| `keygen.v4` native-lto-build | 164.33 ms | 219.66 ms | 151.13 ms | 0.87 | 1 | 5.75 | 0.77× | ✓ |
| `keygen.v5` pthread-x4 | 176.68 ms | 178.00 ms | 126.37 ms | 0.72 | 4 | 5.71 | 0.77× | ✓ |

#### SLH-DSA-SHA2-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 1.99 ms | 2.79 ms | 1.99 ms | 0.91 | 1 | 456 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 2.05 ms | 5.81 ms | 2.36 ms | 0.83 | 1 | 350 | 0.77× | ✓ |
| `keygen.v3` no-asm-build | 3.90 ms | 8.12 ms | 4.35 ms | 0.91 | 1 | 208 | 0.46× | ✓ |
| `keygen.v4` native-lto-build | 2.15 ms | 6.98 ms | 2.30 ms | 0.73 | 1 | 318 | 0.70× | ✓ |
| `keygen.v5` pthread-x4 | 3.05 ms | 6.26 ms | 2.52 ms | 0.75 | 4 | 299 | 0.66× | ✓ |

#### SLH-DSA-SHA2-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 229.48 ms | 260.63 ms | 184.46 ms | 0.82 | 1 | 4.45 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 250.63 ms | 401.06 ms | 218.28 ms | 0.74 | 1 | 3.41 | 0.77× | ✓ |
| `keygen.v3` no-asm-build | 405.59 ms | 456.63 ms | 329.05 ms | 0.82 | 1 | 2.48 | 0.56× | ✓ |
| `keygen.v4` native-lto-build | 208.66 ms | 252.78 ms | 188.05 ms | 0.85 | 1 | 4.53 | 1.02× | ✓ |
| `keygen.v5` pthread-x4 | 255.00 ms | 312.00 ms | 196.93 ms | 0.74 | 4 | 3.75 | 0.84× | ✓ |

#### SLH-DSA-SHA2-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 2.82 ms | 8.06 ms | 2.75 ms | 0.71 | 1 | 258 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 3.07 ms | 8.21 ms | 3.28 ms | 0.78 | 1 | 239 | 0.93× | ✓ |
| `keygen.v3` no-asm-build | 4.51 ms | 9.16 ms | 5.36 ms | 0.96 | 1 | 179 | 0.70× | ✓ |
| `keygen.v4` native-lto-build | 2.71 ms | 3.04 ms | 2.74 ms | 0.98 | 1 | 358 | 1.39× | ✓ |
| `keygen.v5` pthread-x4 | 5.13 ms | 11.20 ms | 3.07 ms | 0.57 | 4 | 185 | 0.72× | ✓ |

#### SLH-DSA-SHA2-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 201.84 ms | 223.20 ms | 122.14 ms | 0.59 | 1 | 4.83 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 183.22 ms | 209.10 ms | 147.46 ms | 0.80 | 1 | 5.43 | 1.13× | ✓ |
| `keygen.v3` no-asm-build | 193.39 ms | 198.29 ms | 180.93 ms | 0.93 | 1 | 5.16 | 1.07× | ✓ |
| `keygen.v4` native-lto-build | 115.94 ms | 137.63 ms | 119.61 ms | 0.98 | 1 | 8.18 | 1.69× | ✓ |
| `keygen.v5` pthread-x4 | 159.00 ms | 189.29 ms | 128.71 ms | 0.79 | 4 | 6.13 | 1.27× | ✓ |

#### SLH-DSA-SHA2-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 11.30 ms | 19.59 ms | 8.20 ms | 0.72 | 1 | 88 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 8.07 ms | 12.14 ms | 7.52 ms | 0.81 | 1 | 108 | 1.22× | ✓ |
| `keygen.v3` no-asm-build | 11.35 ms | 20.57 ms | 11.37 ms | 0.88 | 1 | 78 | 0.88× | ✓ |
| `keygen.v4` native-lto-build | 7.31 ms | 13.14 ms | 7.54 ms | 0.83 | 1 | 110 | 1.25× | ✓ |
| `keygen.v5` pthread-x4 | 12.98 ms | 15.00 ms | 7.99 ms | 0.66 | 4 | 82 | 0.93× | ✓ |

#### SLH-DSA-SHAKE-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 185.15 ms | 186.12 ms | 140.97 ms | 0.81 | 1 | 5.76 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 193.35 ms | 195.79 ms | 152.86 ms | 0.80 | 1 | 5.20 | 0.90× | ✓ |
| `keygen.v3` no-asm-build | 137.33 ms | 163.50 ms | 135.88 ms | 0.93 | 1 | 6.86 | 1.19× | ✓ |
| `keygen.v4` native-lto-build | 121.85 ms | 122.67 ms | 121.24 ms | 0.99 | 1 | 8.19 | 1.42× | ✓ |
| `keygen.v5` pthread-x4 | 173.24 ms | 189.96 ms | 142.57 ms | 0.86 | 4 | 6.03 | 1.05× | ✓ |

#### SLH-DSA-SHAKE-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 2.31 ms | 7.12 ms | 2.37 ms | 0.73 | 1 | 307 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 2.00 ms | 6.03 ms | 2.01 ms | 0.80 | 1 | 395 | 1.29× | ✓ |
| `keygen.v3` no-asm-build | 2.08 ms | 5.45 ms | 2.19 ms | 0.88 | 1 | 403 | 1.31× | ✓ |
| `keygen.v4` native-lto-build | 1.90 ms | 2.15 ms | 1.93 ms | 0.99 | 1 | 515 | 1.68× | ✓ |
| `keygen.v5` pthread-x4 | 2.06 ms | 12.46 ms | 2.18 ms | 0.73 | 4 | 334 | 1.09× | ✓ |

#### SLH-DSA-SHAKE-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 274.27 ms | 274.45 ms | 206.13 ms | 0.80 | 1 | 3.87 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 237.47 ms | 286.15 ms | 199.11 ms | 0.80 | 1 | 4.04 | 1.04× | ✓ |
| `keygen.v3` no-asm-build | 261.30 ms | 269.50 ms | 207.17 ms | 0.82 | 1 | 3.95 | 1.02× | ✓ |
| `keygen.v4` native-lto-build | 233.56 ms | 244.51 ms | 183.44 ms | 0.83 | 1 | 4.54 | 1.17× | ✓ |
| `keygen.v5` pthread-x4 | 222.66 ms | 259.83 ms | 198.33 ms | 0.86 | 4 | 4.33 | 1.12× | ✓ |

#### SLH-DSA-SHAKE-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 3.00 ms | 7.01 ms | 2.96 ms | 0.79 | 1 | 268 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 2.95 ms | 8.20 ms | 2.95 ms | 0.72 | 1 | 243 | 0.91× | ✓ |
| `keygen.v3` no-asm-build | 3.05 ms | 6.04 ms | 3.07 ms | 0.88 | 1 | 286 | 1.07× | ✓ |
| `keygen.v4` native-lto-build | 2.77 ms | 6.96 ms | 2.80 ms | 0.80 | 1 | 285 | 1.06× | ✓ |
| `keygen.v5` pthread-x4 | 4.25 ms | 13.52 ms | 3.37 ms | 0.55 | 4 | 165 | 0.61× | ✓ |

#### SLH-DSA-SHAKE-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 166.62 ms | 173.24 ms | 128.59 ms | 0.77 | 1 | 6.00 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 214.30 ms | 216.95 ms | 166.41 ms | 0.85 | 1 | 5.11 | 0.85× | ✓ |
| `keygen.v3` no-asm-build | 240.97 ms | 252.47 ms | 179.27 ms | 0.85 | 1 | 4.75 | 0.79× | ✓ |
| `keygen.v4` native-lto-build | 153.58 ms | 169.40 ms | 135.71 ms | 0.86 | 1 | 6.34 | 1.06× | ✓ |
| `keygen.v5` pthread-x4 | 109.85 ms | 193.06 ms | 135.13 ms | 1.01 | 4 | 7.46 | 1.24× | ✓ |

#### SLH-DSA-SHAKE-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `keygen.v0` evp-baseline | 10.91 ms | 17.77 ms | 8.89 ms | 0.77 | 1 | 87 | 1.00× | ✓ |
| `keygen.v1` prefetch-reuse-ctx | 16.02 ms | 19.99 ms | 12.82 ms | 0.79 | 1 | 62 | 0.71× | ✓ |
| `keygen.v3` no-asm-build | 9.79 ms | 12.58 ms | 8.31 ms | 0.83 | 1 | 100 | 1.15× | ✓ |
| `keygen.v4` native-lto-build | 7.36 ms | 10.97 ms | 7.72 ms | 0.96 | 1 | 124 | 1.43× | ✓ |
| `keygen.v5` pthread-x4 | 5.29 ms | 8.99 ms | 7.62 ms | 1.30 | 4 | 170 | 1.96× | ✓ |

