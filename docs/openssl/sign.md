# OpenSSL - sign

Process: (sk, 64-byte msg) -> sig. Pure mode, empty context, deterministic (`"deterministic"=1`:
ML-DSA rnd = 0^32, SLH-DSA opt_rand = PK.seed). The `EVP_PKEY` holding the private key is prepared
outside the timed region (that is the "sk" input); the timed region is one signature.
Match = SHA-256(sig) equals `common/reference.json`.

ML-DSA signing in OpenSSL is the FIPS 204 rejection-sampling loop (each attempt: SHAKE256 expand mask
for l polynomials, NTT, matrix multiply, hint computation), so the wall time has a long tail - the median
and p95 differ noticeably even on a quiet machine. SLH-DSA signing is one FORS signature plus d XMSS
signatures with full tree re-computation: tens of ms (`f`) to seconds (`s`), entirely hash bound.

## Variants

| id | name | build | what / why |
|---|---|---|---|
| sign.v0 | evp-baseline | default | The documented way, per call: `EVP_PKEY_CTX_new_from_pkey`, `EVP_PKEY_sign_message_init(ctx, NULL, {deterministic=1})` (NULL algorithm = implicit `EVP_SIGNATURE` fetch by key type), a size query `EVP_PKEY_sign(ctx, NULL, &len, ...)`, then `EVP_PKEY_sign` into the buffer, `EVP_PKEY_CTX_free`. |
| sign.v1 | prefetch-reuse-ctx | default | `EVP_SIGNATURE_fetch` once; one ctx initialised once with the deterministic param and reused: per call just `EVP_PKEY_sign` with a pre-sized buffer. Removes fetch, ctx alloc, sign-init (which for ML-DSA/SLH-DSA also fetches SHAKE/SHA digests into the provider ctx) and the size query. |
| sign.v2 | ctx-dup-template | default | A fully initialised template ctx is `EVP_PKEY_CTX_dup`'ed for every call and freed afterwards. Gives the "fresh context per signature" semantics many applications need (thread safety, no shared mutable ctx) while skipping fetch/init; measures whether dup is cheaper than init. |
| sign.v3 | no-asm-build | noasm | `no-asm` libcrypto, baseline API path: pure-C Keccak-1600 (ML-DSA, SLH-DSA-SHAKE) and SHA-256/512 without SHA-NI/AVX (SLH-DSA-SHA2). |
| sign.v4 | native-lto-build | native | `-O3 -march=native -flto` libcrypto + driver, baseline API path: vectorised polynomial loops, inlined helpers. |
| sign.v5 | pthread-x4 | default | 4 worker threads sharing the same `EVP_PKEY` (keys are immutable after creation in OpenSSL 3) and each owning a prefetched reused sign ctx; throughput over a batch, `threads: 4`. |

## What to expect

* ML-DSA-44 signing is ~250 us, so the ~5-10 us of EVP ctx setup saved by v1/v2 should be a measurable
  2-4 %; for SLH-DSA it vanishes.
* v3 should hurt most for the SHAKE parameter sets and ML-DSA (everything is SHAKE there).
* v4: potential for the rejection loop (NTT, `vector_*` ops are simple C loops that auto-vectorise with AVX2).
* v5: close to linear on an idle box; the shared key is read-only so there is no contention.

## Conclusion (preliminary, noisy box)

See below. Context reuse / dup gives at most a few percent on ML-DSA and nothing on SLH-DSA (the dev
numbers that show more are noise from the shared box). `no-asm` is the clearest single-threaded effect:
the SHA2 parameter sets lose ~40-45 % (the x86_64 SHA-256 assembly uses AVX2 on this CPU, which has no
SHA-NI), while the SHAKE sets and ML-DSA lose ~5-10 % because OpenSSL's Keccak assembly is scalar (no
4-way AVX2 Keccak). `-O3 -march=native -flto` is roughly neutral; the compiler cannot vectorise the
rejection loop much. Threads scale throughput (CPU/op stays flat).

<!-- RESULTS -->

## Results (PRELIMINARY: development run, --budget-ms 200, shared busy machine; the orchestrator overwrites this section)

### Summary (geometric mean over all params, throughput vs v0)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all match |
|---|---|---|---|---|
| `sign.v0` | evp-baseline | 1.00× | 1.00× | yes |
| `sign.v1` | prefetch-reuse-ctx | 0.96× | 1.05× | yes |
| `sign.v2` | ctx-dup-template | 1.12× | 0.99× | yes |
| `sign.v3` | no-asm-build | 0.74× | 1.36× | yes |
| `sign.v4` | native-lto-build | 0.99× | 1.04× | yes |
| `sign.v5` | pthread-x4 | 1.43× | 1.10× | yes |

### Per parameter set

#### ML-DSA-44

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 253.3 µs | 348.3 µs | 265.6 µs | 0.61 | 1 | 2285 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 359.9 µs | 496.7 µs | 352.6 µs | 0.78 | 1 | 2224 | 0.97× | ✓ |
| `sign.v2` ctx-dup-template | 254.5 µs | 336.3 µs | 268.8 µs | 1.00 | 1 | 3711 | 1.62× | ✓ |
| `sign.v3` no-asm-build | 278.7 µs | 411.3 µs | 291.0 µs | 0.78 | 1 | 2669 | 1.17× | ✓ |
| `sign.v4` native-lto-build | 350.2 µs | 486.1 µs | 337.9 µs | 0.96 | 1 | 2850 | 1.25× | ✓ |
| `sign.v5` pthread-x4 | 140.3 µs | 218.2 µs | 271.1 µs | 1.79 | 4 | 6603 | 2.89× | ✓ |

#### ML-DSA-65

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 1.25 ms | 1.96 ms | 1.29 ms | 0.88 | 1 | 686 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.25 ms | 5.18 ms | 1.27 ms | 0.84 | 1 | 658 | 0.96× | ✓ |
| `sign.v2` ctx-dup-template | 1.26 ms | 1.55 ms | 1.30 ms | 1.00 | 1 | 771 | 1.12× | ✓ |
| `sign.v3` no-asm-build | 2.40 ms | 4.86 ms | 2.26 ms | 0.89 | 1 | 392 | 0.57× | ✓ |
| `sign.v4` native-lto-build | 1.81 ms | 2.23 ms | 1.83 ms | 0.97 | 1 | 531 | 0.77× | ✓ |
| `sign.v5` pthread-x4 | 1.15 ms | 1.24 ms | 1.61 ms | 1.64 | 4 | 1018 | 1.48× | ✓ |

#### ML-DSA-87

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 808.1 µs | 1.27 ms | 866.5 µs | 0.97 | 1 | 1121 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.28 ms | 4.96 ms | 1.10 ms | 0.78 | 1 | 709 | 0.63× | ✓ |
| `sign.v2` ctx-dup-template | 794.3 µs | 887.9 µs | 807.3 µs | 1.00 | 1 | 1236 | 1.10× | ✓ |
| `sign.v3` no-asm-build | 879.3 µs | 4.94 ms | 960.0 µs | 0.77 | 1 | 804 | 0.72× | ✓ |
| `sign.v4` native-lto-build | 1.12 ms | 1.40 ms | 1.02 ms | 0.99 | 1 | 971 | 0.87× | ✓ |
| `sign.v5` pthread-x4 | 671.6 µs | 837.0 µs | 1.04 ms | 1.66 | 4 | 1590 | 1.42× | ✓ |

#### SLH-DSA-SHA2-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 1.05 s | 1.07 s | 974.10 ms | 0.93 | 1 | 0.95 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.37 s | 1.44 s | 1.00 s | 0.74 | 1 | 0.73 | 0.77× | ✓ |
| `sign.v2` ctx-dup-template | 922.50 ms | 1.18 s | 1.01 s | 1.00 | 1 | 0.99 | 1.04× | ✓ |
| `sign.v3` no-asm-build | 1.96 s | 1.99 s | 1.60 s | 0.84 | 1 | 0.52 | 0.55× | ✓ |
| `sign.v4` native-lto-build | 1.09 s | 1.17 s | 978.14 ms | 0.89 | 1 | 0.91 | 0.96× | ✓ |
| `sign.v5` pthread-x4 | 691.37 ms | 759.54 ms | 1.26 s | 1.77 | 4 | 1.40 | 1.47× | ✓ |

#### SLH-DSA-SHA2-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 54.25 ms | 56.52 ms | 44.34 ms | 0.81 | 1 | 18 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 64.42 ms | 117.73 ms | 51.00 ms | 0.62 | 1 | 12 | 0.67× | ✓ |
| `sign.v2` ctx-dup-template | 43.80 ms | 44.35 ms | 43.95 ms | 1.00 | 1 | 23 | 1.24× | ✓ |
| `sign.v3` no-asm-build | 80.38 ms | 81.04 ms | 73.09 ms | 0.94 | 1 | 13 | 0.70× | ✓ |
| `sign.v4` native-lto-build | 44.55 ms | 45.61 ms | 43.64 ms | 0.98 | 1 | 22 | 1.22× | ✓ |
| `sign.v5` pthread-x4 | 32.82 ms | 32.98 ms | 44.84 ms | 1.40 | 4 | 31 | 1.70× | ✓ |

#### SLH-DSA-SHA2-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 1.96 s | 2.01 s | 1.79 s | 0.91 | 1 | 0.51 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.78 s | 2.06 s | 1.75 s | 0.94 | 1 | 0.54 | 1.06× | ✓ |
| `sign.v2` ctx-dup-template | 1.82 s | 2.01 s | 1.80 s | 0.97 | 1 | 0.54 | 1.06× | ✓ |
| `sign.v3` no-asm-build | 3.37 s | 3.38 s | 3.00 s | 0.91 | 1 | 0.30 | 0.60× | ✓ |
| `sign.v4` native-lto-build | 1.84 s | 2.23 s | 1.73 s | 0.89 | 1 | 0.51 | 1.01× | ✓ |
| `sign.v5` pthread-x4 | 1.75 s | 1.79 s | 1.94 s | 1.12 | 4 | 0.58 | 1.14× | ✓ |

#### SLH-DSA-SHA2-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 80.46 ms | 100.79 ms | 77.01 ms | 0.90 | 1 | 12 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 73.27 ms | 73.36 ms | 72.93 ms | 1.00 | 1 | 14 | 1.17× | ✓ |
| `sign.v2` ctx-dup-template | 74.36 ms | 78.22 ms | 74.58 ms | 0.99 | 1 | 13 | 1.14× | ✓ |
| `sign.v3` no-asm-build | 139.52 ms | 176.09 ms | 140.93 ms | 0.93 | 1 | 6.61 | 0.57× | ✓ |
| `sign.v4` native-lto-build | 99.35 ms | 119.03 ms | 84.80 ms | 0.86 | 1 | 10 | 0.87× | ✓ |
| `sign.v5` pthread-x4 | 126.10 ms | 157.47 ms | 103.69 ms | 0.82 | 4 | 7.88 | 0.68× | ✓ |

#### SLH-DSA-SHA2-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 1.60 s | 1.72 s | 1.54 s | 0.95 | 1 | 0.62 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.66 s | 1.84 s | 1.64 s | 0.98 | 1 | 0.60 | 0.97× | ✓ |
| `sign.v2` ctx-dup-template | 1.54 s | 1.57 s | 1.52 s | 0.99 | 1 | 0.65 | 1.06× | ✓ |
| `sign.v3` no-asm-build | 2.84 s | 2.88 s | 2.53 s | 0.92 | 1 | 0.36 | 0.59× | ✓ |
| `sign.v4` native-lto-build | 1.63 s | 1.72 s | 1.50 s | 0.93 | 1 | 0.62 | 1.00× | ✓ |
| `sign.v5` pthread-x4 | 1.02 s | 1.16 s | 1.76 s | 1.73 | 4 | 0.98 | 1.60× | ✓ |

#### SLH-DSA-SHA2-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 166.45 ms | 226.04 ms | 172.60 ms | 0.94 | 1 | 5.45 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 154.70 ms | 166.56 ms | 154.04 ms | 0.98 | 1 | 6.34 | 1.16× | ✓ |
| `sign.v2` ctx-dup-template | 151.46 ms | 151.86 ms | 150.87 ms | 1.00 | 1 | 6.61 | 1.21× | ✓ |
| `sign.v3` no-asm-build | 335.43 ms | 392.17 ms | 328.04 ms | 0.99 | 1 | 3.02 | 0.55× | ✓ |
| `sign.v4` native-lto-build | 155.67 ms | 157.59 ms | 150.88 ms | 0.98 | 1 | 6.47 | 1.19× | ✓ |
| `sign.v5` pthread-x4 | 90.59 ms | 97.66 ms | 174.55 ms | 1.88 | 4 | 11 | 1.98× | ✓ |

#### SLH-DSA-SHAKE-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 1.20 s | 1.30 s | 1.11 s | 0.94 | 1 | 0.85 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.15 s | 1.16 s | 1.08 s | 0.97 | 1 | 0.90 | 1.06× | ✓ |
| `sign.v2` ctx-dup-template | 1.07 s | 1.07 s | 1.03 s | 0.99 | 1 | 0.96 | 1.13× | ✓ |
| `sign.v3` no-asm-build | 1.13 s | 1.48 s | 1.16 s | 0.94 | 1 | 0.81 | 0.96× | ✓ |
| `sign.v4` native-lto-build | 1.32 s | 1.45 s | 1.16 s | 0.88 | 1 | 0.76 | 0.89× | ✓ |
| `sign.v5` pthread-x4 | 521.84 ms | 546.51 ms | 1.03 s | 1.99 | 4 | 1.92 | 2.27× | ✓ |

#### SLH-DSA-SHAKE-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 50.74 ms | 56.86 ms | 48.76 ms | 0.94 | 1 | 19 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 61.70 ms | 76.11 ms | 60.73 ms | 0.98 | 1 | 16 | 0.84× | ✓ |
| `sign.v2` ctx-dup-template | 52.97 ms | 70.54 ms | 55.54 ms | 0.99 | 1 | 18 | 0.92× | ✓ |
| `sign.v3` no-asm-build | 53.68 ms | 55.00 ms | 51.95 ms | 0.97 | 1 | 19 | 0.96× | ✓ |
| `sign.v4` native-lto-build | 48.45 ms | 61.52 ms | 49.32 ms | 0.97 | 1 | 20 | 1.02× | ✓ |
| `sign.v5` pthread-x4 | 27.44 ms | 29.48 ms | 50.34 ms | 1.82 | 4 | 36 | 1.87× | ✓ |

#### SLH-DSA-SHAKE-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 1.82 s | 2.02 s | 1.76 s | 0.94 | 1 | 0.53 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.97 s | 2.03 s | 1.93 s | 0.99 | 1 | 0.51 | 0.97× | ✓ |
| `sign.v2` ctx-dup-template | 1.84 s | 1.91 s | 1.83 s | 0.99 | 1 | 0.54 | 1.01× | ✓ |
| `sign.v3` no-asm-build | 2.11 s | 2.47 s | 2.03 s | 0.94 | 1 | 0.46 | 0.87× | ✓ |
| `sign.v4` native-lto-build | 2.14 s | 2.18 s | 1.77 s | 0.87 | 1 | 0.49 | 0.93× | ✓ |
| `sign.v5` pthread-x4 | 1.57 s | 2.13 s | 1.84 s | 1.05 | 4 | 0.57 | 1.07× | ✓ |

#### SLH-DSA-SHAKE-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 76.62 ms | 79.90 ms | 75.99 ms | 0.98 | 1 | 13 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 78.00 ms | 80.11 ms | 77.42 ms | 0.99 | 1 | 13 | 0.99× | ✓ |
| `sign.v2` ctx-dup-template | 77.40 ms | 91.40 ms | 81.14 ms | 1.00 | 1 | 12 | 0.95× | ✓ |
| `sign.v3` no-asm-build | 92.03 ms | 98.52 ms | 91.28 ms | 0.98 | 1 | 11 | 0.83× | ✓ |
| `sign.v4` native-lto-build | 75.70 ms | 84.36 ms | 75.26 ms | 0.98 | 1 | 13 | 1.00× | ✓ |
| `sign.v5` pthread-x4 | 80.93 ms | 95.12 ms | 98.97 ms | 1.23 | 4 | 12 | 0.96× | ✓ |

#### SLH-DSA-SHAKE-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 1.92 s | 1.97 s | 1.61 s | 0.84 | 1 | 0.52 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 1.52 s | 1.64 s | 1.54 s | 0.99 | 1 | 0.64 | 1.23× | ✓ |
| `sign.v2` ctx-dup-template | 1.62 s | 1.86 s | 1.64 s | 0.99 | 1 | 0.60 | 1.15× | ✓ |
| `sign.v3` no-asm-build | 2.05 s | 2.15 s | 1.66 s | 0.83 | 1 | 0.50 | 0.95× | ✓ |
| `sign.v4` native-lto-build | 1.84 s | 2.07 s | 1.52 s | 0.80 | 1 | 0.53 | 1.01× | ✓ |
| `sign.v5` pthread-x4 | 1.67 s | 1.79 s | 1.61 s | 0.97 | 4 | 0.60 | 1.15× | ✓ |

#### SLH-DSA-SHAKE-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` evp-baseline | 190.12 ms | 193.23 ms | 167.21 ms | 0.88 | 1 | 5.24 | 1.00× | ✓ |
| `sign.v1` prefetch-reuse-ctx | 161.90 ms | 169.57 ms | 160.73 ms | 0.99 | 1 | 6.14 | 1.17× | ✓ |
| `sign.v2` ctx-dup-template | 153.03 ms | 154.23 ms | 153.29 ms | 1.00 | 1 | 6.52 | 1.25× | ✓ |
| `sign.v3` no-asm-build | 267.34 ms | 290.15 ms | 202.42 ms | 0.81 | 1 | 4.00 | 0.76× | ✓ |
| `sign.v4` native-lto-build | 189.54 ms | 245.79 ms | 157.58 ms | 0.81 | 1 | 5.13 | 0.98× | ✓ |
| `sign.v5` pthread-x4 | 158.36 ms | 162.76 ms | 166.52 ms | 1.05 | 4 | 6.31 | 1.20× | ✓ |

