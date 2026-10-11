# rustcrypto: verify

Process: pk bytes + message + signature bytes → bool. ML-DSA: `VerifyingKey::<P>::decode(pk)`
(pkDecode + `ExpandA` + NTT(2^d·t1) + `tr` = SHAKE-256(pk)), `Signature::decode(sig)` (sigDecode with
hint validation), `verify_with_context(msg, b"", &sig)`. SLH-DSA: `VerifyingKey::try_from(pk)`,
`Signature::try_from(sig)`, `Verifier::verify(msg, &sig)` (FORS pk from signature, then d XMSS
authentication paths; verification is the cheap direction of SLH-DSA, ~2–10 ms).

Cost structure: ML-DSA verify = pkDecode/ExpandA (K·L SHAKE-128 polynomials, as expensive as the rest
of verify combined), sigDecode, SampleInBall, NTT(z), one A·z product, UseHint, w1Encode and a SHAKE-256
over μ‖w1. SLH-DSA verify is hash-bound: k FORS roots (each a Merkle path of length a) plus d·(h'+len)
WOTS+/XMSS hashes.

## Variants

| id | name | what / why / how |
|---|---|---|
| `verify.v0` | default | Baseline: `cargo build --release`, stateless byte API: decode pk and signature on every call, verify. Single thread. Result must be `true` on the reference triple and `false` on a signature with one flipped bit (checked once per bench line, outside the timed loop). |
| `verify.v1` | native | `-C target-cpu=native`: AVX2/AVX-512 auto-vectorisation of the NTT, A·z, `UseHint`, `w1Encode`, and of the bit-unpacking in `pkDecode`/`sigDecode`. |
| `verify.v2` | lto | Fat LTO + codegen-units=1 + panic=abort: cross-crate inlining of the `digest`/`keccak`/`sha2` and `module-lattice` call chains; verification has many small hash invocations (SLH-DSA WOTS+ chains are thousands of 1-block hashes), so call overhead matters. |
| `verify.v3` | pgo | native + fat LTO + PGO trained only on the verify workload (instrumented binary runs `verify.v3` for all 15 params). Verify has few data-dependent branches, so this mostly buys better inlining/layout decisions than the sign-trained or generic profile. |
| `verify.v4` | keycache | API-path change: `VerifyingKey` decoded once and reused, so A_hat, NTT(2^d·t1) and `tr` are precomputed and the timed region is signature decode + `Verify_internal`. This is the case of a verifier that checks many signatures under the same key (certificate chains, firmware, log servers). SLH-DSA key decode is a 32–64-byte copy, so no change is expected there. Default build. |
| `verify.v5` | par | 16 independent verifications per batch on a 4-thread `rayon` pool (stateless path as v0 inside each task). Throughput with `threads = 4`; all 16 results must be `true` and the tampered signature must be rejected for `match`. |

## Conclusion (preliminary, noisy shared machine; final numbers below the marker are regenerated)

See the preliminary table below. Expectation: `keycache` roughly halves ML-DSA verify time (ExpandA
gone), build flags give moderate gains, SLH-DSA verify only benefits from flags and parallelism.

<!-- RESULTS -->

## Results (PRELIMINARY: dev run with --budget-ms 200 on a loaded 4-core box; the orchestrator overwrites this section)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all outputs match |
|---|---|---|---|---|
| `verify.v0` | default | 1.00× | 1.00× | yes |
| `verify.v1` | native | 0.87× | 1.18× | yes |
| `verify.v2` | lto | 1.20× | 0.96× | yes |
| `verify.v3` | pgo | 1.26× | 0.93× | yes |
| `verify.v4` | keycache | 1.93× | 0.62× | yes |
| `verify.v5` | par | 1.23× | 1.12× | yes |

| param | variant | median | CPU/op | CPU util | thr | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | `verify.v0` default | 101.8 µs | 112.2 µs | 0.80 | 1 | 7107.2 | 1.00× | ✓ |
| ML-DSA-44 | `verify.v1` native | 111.5 µs | 129.2 µs | 0.75 | 1 | 5808.4 | 0.82× | ✓ |
| ML-DSA-44 | `verify.v2` lto | 100.8 µs | 118.1 µs | 0.91 | 1 | 7742.7 | 1.09× | ✓ |
| ML-DSA-44 | `verify.v3` pgo | 104.2 µs | 112.8 µs | 0.92 | 1 | 8146.4 | 1.15× | ✓ |
| ML-DSA-44 | `verify.v4` keycache | 47.2 µs | 55.5 µs | 0.95 | 1 | 17085.9 | 2.40× | ✓ |
| ML-DSA-44 | `verify.v5` par | 105.4 µs | 120.3 µs | 1.24 | 4 | 10314.9 | 1.45× | ✓ |
| ML-DSA-87 | `verify.v0` default | 265.0 µs | 278.5 µs | 0.98 | 1 | 3524.3 | 1.00× | ✓ |
| ML-DSA-87 | `verify.v1` native | 326.0 µs | 361.6 µs | 0.69 | 1 | 1904.3 | 0.54× | ✓ |
| ML-DSA-87 | `verify.v2` lto | 263.6 µs | 283.2 µs | 0.94 | 1 | 3319.8 | 0.94× | ✓ |
| ML-DSA-87 | `verify.v3` pgo | 270.2 µs | 280.9 µs | 0.94 | 1 | 3362.2 | 0.95× | ✓ |
| ML-DSA-87 | `verify.v4` keycache | 92.8 µs | 99.8 µs | 0.94 | 1 | 9416.0 | 2.67× | ✓ |
| ML-DSA-87 | `verify.v5` par | 332.9 µs | 431.5 µs | 1.15 | 4 | 2670.4 | 0.76× | ✓ |
| SLH-DSA-SHA2-128f | `verify.v0` default | 2.24 ms | 2.25 ms | 0.98 | 1 | 435.8 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | `verify.v1` native | 1.85 ms | 1.87 ms | 0.94 | 1 | 504.3 | 1.16× | ✓ |
| SLH-DSA-SHA2-128f | `verify.v2` lto | 2.18 ms | 2.32 ms | 0.92 | 1 | 398.1 | 0.91× | ✓ |
| SLH-DSA-SHA2-128f | `verify.v3` pgo | 1.83 ms | 1.84 ms | 0.92 | 1 | 500.5 | 1.15× | ✓ |
| SLH-DSA-SHA2-128f | `verify.v4` keycache | 2.24 ms | 2.26 ms | 0.98 | 1 | 431.4 | 0.99× | ✓ |
| SLH-DSA-SHA2-128f | `verify.v5` par | 2.04 ms | 2.36 ms | 1.11 | 4 | 471.3 | 1.08× | ✓ |
| SLH-DSA-SHAKE-128s | `verify.v0` default | 3.41 ms | 2.27 ms | 0.53 | 1 | 233.2 | 1.00× | ✓ |
| SLH-DSA-SHAKE-128s | `verify.v1` native | 3.48 ms | 3.52 ms | 0.93 | 1 | 263.4 | 1.13× | ✓ |
| SLH-DSA-SHAKE-128s | `verify.v2` lto | 1.78 ms | 1.77 ms | 0.91 | 1 | 510.7 | 2.19× | ✓ |
| SLH-DSA-SHAKE-128s | `verify.v3` pgo | 1.94 ms | 2.01 ms | 0.95 | 1 | 475.4 | 2.04× | ✓ |
| SLH-DSA-SHAKE-128s | `verify.v4` keycache | 1.89 ms | 1.90 ms | 0.96 | 1 | 507.4 | 2.18× | ✓ |
| SLH-DSA-SHAKE-128s | `verify.v5` par | 2.02 ms | 2.06 ms | 0.92 | 4 | 445.3 | 1.91× | ✓ |
