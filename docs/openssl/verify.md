# OpenSSL - verify

Process: (pk, msg, sig) -> bool. The public key is an `EVP_PKEY` imported from the raw `pub` bytes
with `EVP_PKEY_fromdata` outside the timed region; the signature is the reference signature produced by
`sign.v0`. Every variant must return true for it and false for a one-bit-flipped copy (checked before
the loop and again after the loop on the same, possibly reused, context). `output_sha256` is `"true"`/`"false"`.

ML-DSA verification = SHAKE256(tr || M') to get mu, expand A from rho (SHAKE128), one NTT multiply and
the hint/commitment hash; it is cheaper than signing but still SHAKE dominated. SLH-DSA verification
recomputes the FORS root and d WOTS+ public keys / XMSS auth paths: ms range, hash bound.

## Variants

| id | name | build | what / why |
|---|---|---|---|
| verify.v0 | evp-baseline | default | Documented way, per call: `EVP_PKEY_CTX_new_from_pkey`, `EVP_PKEY_verify_message_init(ctx, NULL, NULL)` (implicit `EVP_SIGNATURE` fetch), `EVP_PKEY_verify`, free. |
| verify.v1 | prefetch-reuse-ctx | default | `EVP_SIGNATURE_fetch` once, one verify ctx initialised once and reused for every call: per call only `EVP_PKEY_verify`. Saves fetch, allocation and the init-time digest fetches. |
| verify.v2 | external-mu | default | OpenSSL's ML-DSA signature implementation accepts the FIPS 204 mu instead of the message (`"mu"=1`, `OSSL_SIGNATURE_PARAM_MU`). The driver caches `tr = SHAKE256(pk, 64)` per key and per call computes `mu = SHAKE256(tr || 0x00 || 0x00 || msg, 64)` with a reused `EVP_MD_CTX`, then verifies mu on a reused ctx. This is the "external mu" flow used by HSM/TLS offload designs; it moves the message hashing out of the provider and lets a caller skip the `tr` recomputation that the provider would otherwise do from the encoded public key. ML-DSA only (no such interface for SLH-DSA). |
| verify.v3 | no-asm-build | noasm | `no-asm` libcrypto, baseline API path. |
| verify.v4 | native-lto-build | native | `-O3 -march=native -flto` libcrypto + driver, baseline API path. |
| verify.v5 | pthread-x4 | default | 4 worker threads, each with its own prefetched reused verify ctx on the shared public key, throughput over a batch, `threads: 4`. |

## What to expect

* ML-DSA-44 verify ~130 us: the EVP setup is ~5 %, so v1 should show a small gain; v2 adds one short
  SHAKE256 call in the driver but saves the same work inside the provider, so it should be within noise
  of v1 (OpenSSL stores `tr` in the key object already, the saving is only the message encoding copy).
* v3/v4 as for sign.
* v5 near-linear throughput scaling; verification has no shared mutable state at all.

## Conclusion (preliminary, noisy box)

See below. Reusing the context is the only API-level change that is (slightly) positive; external mu
is within noise of the reused ctx for ML-DSA (the provider already caches `tr` in the key). The native/LTO
build gives a few percent on SLH-DSA verify (hash-wrapper inlining); `no-asm` costs ~40 % on the SHA2
sets (AVX2 SHA-256 assembly) and ~5-10 % on SHAKE/ML-DSA (scalar Keccak assembly); threads scale throughput.

<!-- RESULTS -->

## Results (PRELIMINARY: development run, --budget-ms 200, shared busy machine; the orchestrator overwrites this section)

### Summary (geometric mean over all params, throughput vs v0)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all match |
|---|---|---|---|---|
| `verify.v0` | evp-baseline | 1.00× | 1.00× | yes |
| `verify.v1` | prefetch-reuse-ctx | 1.11× | 0.95× | yes |
| `verify.v2` | external-mu | 1.22× | 0.97× | yes |
| `verify.v3` | no-asm-build | 0.77× | 1.28× | yes |
| `verify.v4` | native-lto-build | 1.05× | 1.01× | yes |
| `verify.v5` | pthread-x4 | 0.91× | 1.05× | yes |

### Per parameter set

#### ML-DSA-44

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 130.8 µs | 212.4 µs | 140.8 µs | 0.61 | 1 | 4315 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 134.5 µs | 252.0 µs | 160.1 µs | 0.95 | 1 | 5954 | 1.38× | ✓ |
| `verify.v2` external-mu | 129.3 µs | 170.6 µs | 137.7 µs | 0.94 | 1 | 6800 | 1.58× | ✓ |
| `verify.v3` no-asm-build | 141.3 µs | 169.4 µs | 145.3 µs | 0.99 | 1 | 6841 | 1.59× | ✓ |
| `verify.v4` native-lto-build | 126.7 µs | 203.8 µs | 139.2 µs | 0.77 | 1 | 5568 | 1.29× | ✓ |
| `verify.v5` pthread-x4 | 135.7 µs | 163.8 µs | 136.8 µs | 0.99 | 4 | 7203 | 1.67× | ✓ |

#### ML-DSA-65

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 203.0 µs | 289.4 µs | 216.6 µs | 0.96 | 1 | 4433 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 198.7 µs | 228.2 µs | 205.6 µs | 0.97 | 1 | 4727 | 1.07× | ✓ |
| `verify.v2` external-mu | 199.2 µs | 235.2 µs | 207.2 µs | 0.98 | 1 | 4734 | 1.07× | ✓ |
| `verify.v3` no-asm-build | 216.4 µs | 246.6 µs | 221.4 µs | 0.92 | 1 | 4152 | 0.94× | ✓ |
| `verify.v4` native-lto-build | 216.3 µs | 388.7 µs | 233.2 µs | 0.77 | 1 | 3298 | 0.74× | ✓ |
| `verify.v5` pthread-x4 | 400.9 µs | 557.7 µs | 314.9 µs | 0.95 | 4 | 3021 | 0.68× | ✓ |

#### ML-DSA-87

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 328.0 µs | 416.3 µs | 332.1 µs | 0.93 | 1 | 2788 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 364.3 µs | 666.1 µs | 411.6 µs | 0.87 | 1 | 2116 | 0.76× | ✓ |
| `verify.v2` external-mu | 316.9 µs | 364.8 µs | 327.4 µs | 0.98 | 1 | 2999 | 1.08× | ✓ |
| `verify.v3` no-asm-build | 338.5 µs | 383.8 µs | 346.9 µs | 0.85 | 1 | 2439 | 0.87× | ✓ |
| `verify.v4` native-lto-build | 355.2 µs | 611.6 µs | 380.8 µs | 0.50 | 1 | 1324 | 0.47× | ✓ |
| `verify.v5` pthread-x4 | 325.1 µs | 666.6 µs | 358.4 µs | 0.95 | 4 | 2640 | 0.95× | ✓ |

#### SLH-DSA-SHA2-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 932.8 µs | 1.79 ms | 1.06 ms | 0.87 | 1 | 815 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 988.7 µs | 3.44 ms | 1.09 ms | 0.58 | 1 | 535 | 0.66× | ✓ |
| `verify.v3` no-asm-build | 1.43 ms | 1.92 ms | 1.43 ms | 0.86 | 1 | 598 | 0.73× | ✓ |
| `verify.v4` native-lto-build | 1.37 ms | 1.77 ms | 1.28 ms | 0.98 | 1 | 765 | 0.94× | ✓ |
| `verify.v5` pthread-x4 | 908.7 µs | 1.02 ms | 910.3 µs | 0.98 | 4 | 1076 | 1.32× | ✓ |

#### SLH-DSA-SHA2-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 2.74 ms | 3.59 ms | 2.76 ms | 0.96 | 1 | 349 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 2.80 ms | 5.16 ms | 2.93 ms | 0.95 | 1 | 323 | 0.93× | ✓ |
| `verify.v3` no-asm-build | 9.21 ms | 20.36 ms | 5.56 ms | 0.50 | 1 | 91 | 0.26× | ✓ |
| `verify.v4` native-lto-build | 2.60 ms | 2.87 ms | 2.63 ms | 0.99 | 1 | 378 | 1.08× | ✓ |
| `verify.v5` pthread-x4 | 2.70 ms | 2.99 ms | 2.76 ms | 1.01 | 4 | 365 | 1.05× | ✓ |

#### SLH-DSA-SHA2-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 1.41 ms | 2.17 ms | 1.55 ms | 0.98 | 1 | 635 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 1.40 ms | 2.24 ms | 1.46 ms | 0.90 | 1 | 616 | 0.97× | ✓ |
| `verify.v3` no-asm-build | 2.31 ms | 4.55 ms | 2.43 ms | 0.90 | 1 | 372 | 0.59× | ✓ |
| `verify.v4` native-lto-build | 1.31 ms | 1.96 ms | 1.39 ms | 0.99 | 1 | 716 | 1.13× | ✓ |
| `verify.v5` pthread-x4 | 1.35 ms | 2.07 ms | 1.36 ms | 0.89 | 4 | 659 | 1.04× | ✓ |

#### SLH-DSA-SHA2-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 7.61 ms | 29.16 ms | 6.66 ms | 0.63 | 1 | 94 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 4.00 ms | 6.04 ms | 3.97 ms | 0.88 | 1 | 221 | 2.35× | ✓ |
| `verify.v3` no-asm-build | 6.44 ms | 10.39 ms | 6.36 ms | 0.91 | 1 | 144 | 1.53× | ✓ |
| `verify.v4` native-lto-build | 5.56 ms | 8.34 ms | 5.25 ms | 0.96 | 1 | 183 | 1.95× | ✓ |
| `verify.v5` pthread-x4 | 5.00 ms | 11.00 ms | 4.35 ms | 0.73 | 4 | 168 | 1.78× | ✓ |

#### SLH-DSA-SHA2-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 2.41 ms | 7.78 ms | 2.40 ms | 0.72 | 1 | 298 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 2.00 ms | 2.47 ms | 2.02 ms | 0.96 | 1 | 473 | 1.59× | ✓ |
| `verify.v3` no-asm-build | 3.39 ms | 7.59 ms | 3.44 ms | 0.82 | 1 | 238 | 0.80× | ✓ |
| `verify.v4` native-lto-build | 3.39 ms | 4.74 ms | 3.37 ms | 0.99 | 1 | 294 | 0.99× | ✓ |
| `verify.v5` pthread-x4 | 3.20 ms | 10.89 ms | 2.54 ms | 0.60 | 4 | 238 | 0.80× | ✓ |

#### SLH-DSA-SHA2-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 4.37 ms | 9.65 ms | 4.20 ms | 0.82 | 1 | 195 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 4.36 ms | 19.65 ms | 4.33 ms | 0.62 | 1 | 142 | 0.73× | ✓ |
| `verify.v3` no-asm-build | 6.62 ms | 10.39 ms | 6.98 ms | 0.99 | 1 | 142 | 0.73× | ✓ |
| `verify.v4` native-lto-build | 4.05 ms | 7.81 ms | 4.37 ms | 0.94 | 1 | 214 | 1.10× | ✓ |
| `verify.v5` pthread-x4 | 9.51 ms | 15.50 ms | 5.78 ms | 0.56 | 4 | 97 | 0.50× | ✓ |

#### SLH-DSA-SHAKE-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 921.4 µs | 1.17 ms | 936.8 µs | 0.91 | 1 | 974 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 920.7 µs | 1.58 ms | 937.8 µs | 0.91 | 1 | 968 | 0.99× | ✓ |
| `verify.v3` no-asm-build | 1.07 ms | 6.27 ms | 1.34 ms | 0.66 | 1 | 490 | 0.50× | ✓ |
| `verify.v4` native-lto-build | 919.5 µs | 1.99 ms | 1.12 ms | 0.96 | 1 | 857 | 0.88× | ✓ |
| `verify.v5` pthread-x4 | 1.68 ms | 2.51 ms | 1.28 ms | 0.81 | 4 | 636 | 0.65× | ✓ |

#### SLH-DSA-SHAKE-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 3.00 ms | 3.54 ms | 3.04 ms | 0.98 | 1 | 324 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 2.94 ms | 3.24 ms | 2.97 ms | 0.98 | 1 | 329 | 1.01× | ✓ |
| `verify.v3` no-asm-build | 7.40 ms | 10.10 ms | 5.44 ms | 0.77 | 1 | 142 | 0.44× | ✓ |
| `verify.v4` native-lto-build | 2.90 ms | 3.97 ms | 2.93 ms | 0.93 | 1 | 319 | 0.98× | ✓ |
| `verify.v5` pthread-x4 | 4.64 ms | 8.21 ms | 3.67 ms | 0.77 | 4 | 209 | 0.64× | ✓ |

#### SLH-DSA-SHAKE-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 1.84 ms | 4.91 ms | 1.78 ms | 0.83 | 1 | 464 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 1.39 ms | 2.92 ms | 1.58 ms | 0.97 | 1 | 612 | 1.32× | ✓ |
| `verify.v3` no-asm-build | 1.51 ms | 2.50 ms | 1.60 ms | 0.95 | 1 | 597 | 1.29× | ✓ |
| `verify.v4` native-lto-build | 1.36 ms | 2.47 ms | 1.44 ms | 0.95 | 1 | 660 | 1.42× | ✓ |
| `verify.v5` pthread-x4 | 2.80 ms | 5.86 ms | 2.30 ms | 0.86 | 4 | 376 | 0.81× | ✓ |

#### SLH-DSA-SHAKE-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 4.39 ms | 10.92 ms | 4.97 ms | 0.91 | 1 | 182 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 4.02 ms | 4.81 ms | 4.06 ms | 0.95 | 1 | 233 | 1.28× | ✓ |
| `verify.v3` no-asm-build | 8.20 ms | 19.20 ms | 5.47 ms | 0.64 | 1 | 117 | 0.64× | ✓ |
| `verify.v4` native-lto-build | 3.82 ms | 6.41 ms | 4.02 ms | 0.94 | 1 | 235 | 1.29× | ✓ |
| `verify.v5` pthread-x4 | 7.17 ms | 8.18 ms | 4.90 ms | 0.71 | 4 | 145 | 0.79× | ✓ |

#### SLH-DSA-SHAKE-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 2.05 ms | 6.04 ms | 2.12 ms | 0.84 | 1 | 398 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 2.02 ms | 2.55 ms | 2.11 ms | 0.98 | 1 | 466 | 1.17× | ✓ |
| `verify.v3` no-asm-build | 5.18 ms | 6.83 ms | 4.43 ms | 1.00 | 1 | 225 | 0.56× | ✓ |
| `verify.v4` native-lto-build | 1.99 ms | 4.32 ms | 2.41 ms | 0.98 | 1 | 407 | 1.02× | ✓ |
| `verify.v5` pthread-x4 | 3.13 ms | 22.33 ms | 2.52 ms | 0.58 | 4 | 232 | 0.58× | ✓ |

#### SLH-DSA-SHAKE-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `verify.v0` evp-baseline | 6.44 ms | 12.41 ms | 5.71 ms | 0.82 | 1 | 144 | 1.00× | ✓ |
| `verify.v1` prefetch-reuse-ctx | 4.28 ms | 7.27 ms | 5.17 ms | 0.99 | 1 | 192 | 1.33× | ✓ |
| `verify.v3` no-asm-build | 4.27 ms | 5.24 ms | 4.36 ms | 0.97 | 1 | 223 | 1.55× | ✓ |
| `verify.v4` native-lto-build | 4.31 ms | 8.88 ms | 5.52 ms | 0.99 | 1 | 179 | 1.24× | ✓ |
| `verify.v5` pthread-x4 | 4.50 ms | 6.89 ms | 4.63 ms | 0.95 | 4 | 205 | 1.42× | ✓ |

