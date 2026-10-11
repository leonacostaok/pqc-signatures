# rustcrypto: sign

Process: sk bytes + message → signature bytes (pure mode, empty context, deterministic). ML-DSA:
`ExpandedSigningKey::<P>::from_expanded(sk)` (skDecode, deprecated-but-available) then
`sign_deterministic(msg, b"")` then `Signature::encode()`. SLH-DSA: `SigningKey::<P>::try_from(sk)` then
`Signer::try_sign(msg)` (= `slh_sign` with `opt_rand = PK.seed`) then `Signature::to_bytes()`.

Cost structure: ML-DSA signing = skDecode (which includes re-expanding the K·L matrix A_hat with
SHAKE-128 and the NTTs of s1, s2, t0) + the rejection-sampling loop (each attempt: ExpandMask with
SHAKE-256, one A·y product, decompose, SHAKE-256 of μ‖w1, SampleInBall, two products and the norm
checks). SLH-DSA signing = one FORS signature plus d XMSS signatures, each of which rebuilds an entire
XMSS subtree (2^h' leaves) from the secret seed; the `s` sets do d = 7–8 trees of 2^9 leaves and are
therefore 0.5–3 s per signature in this pure-Rust code.

## Variants

| id | name | what / why / how |
|---|---|---|
| `sign.v0` | default | Baseline: `cargo build --release`, stateless byte API: decode sk on every call, sign, encode. Single thread. |
| `sign.v1` | native | `-C target-cpu=native`. Targets the vectorisable parts of the rejection loop (NTT, pointwise products, `Decompose`/`HighBits`, norm checks, hint packing) with AVX2/AVX-512; the SHAKE-dominated parts (`ExpandMask`, `SampleInBall`, SLH-DSA entirely) stay scalar. |
| `sign.v2` | lto | Fat LTO + codegen-units=1 + panic=abort. The ML-DSA rejection loop and the SLH-DSA tree walk call tiny generic functions from `module-lattice`, `hybrid-array`, `digest`, `keccak`/`sha2` on every polynomial coefficient / hash block; whole-program inlining removes those call boundaries and lets the hash states live in registers. |
| `sign.v3` | pgo | native + fat LTO + PGO with a profile trained only on the sign workload (all 15 params through `sign.v3` in the instrumented binary). Signing has the most data-dependent branching of the three processes (rejection sampling, `SampleInBall`, hint computation), which is exactly what PGO's branch-probability and hot/cold layout improve. |
| `sign.v4` | keycache | API-path change: decode the key once (`ExpandedSigningKey` with A_hat and NTT(s1, s2, t0) precomputed; `SigningKey` for SLH-DSA) and reuse the object, so the timed region is only `Sign_internal` + encoding. This is what a long-lived signer (TLS server, CA) does. For ML-DSA it removes the full `ExpandA` and three NTTs per signature; for SLH-DSA the decode is a 64–128-byte copy, so no change is expected (included to show that honestly). Default build. |
| `sign.v5` | par | 16 independent signatures per batch over a 4-thread `rayon` pool (same stateless path as v0 inside each task). Reports throughput; `cpu_ns_per_op` and `cpu_util` show the real cost. Deterministic signing, so every signature in the batch is checked against `sig_sha256`. |

Randomized / hedged signing is deliberately absent (it cannot byte-match). Every variant's signature
(all 16 for the batch variant) is hashed after the measured loop and compared with `sig_sha256`.

## Conclusion (preliminary, noisy shared machine; final numbers below the marker are regenerated)

See the preliminary table below. Expectation: `keycache` is the big win for ML-DSA (A_hat expansion is
a large fraction of a stateless sign), build flags give moderate gains, `par` is the only thing that
helps SLH-DSA-*s* signing latency-wise (as throughput).

<!-- RESULTS -->

## Results (PRELIMINARY: dev run with --budget-ms 200 on a loaded 4-core box; the orchestrator overwrites this section)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all outputs match |
|---|---|---|---|---|
| `sign.v0` | default | 1.00× | 1.00× | yes |
| `sign.v1` | native | 0.76× | 1.17× | yes |
| `sign.v2` | lto | 0.93× | 0.98× | yes |
| `sign.v3` | pgo | 0.91× | 0.96× | yes |
| `sign.v4` | keycache | 1.18× | 0.85× | yes |
| `sign.v5` | par | 1.15× | 1.00× | yes |

| param | variant | median | CPU/op | CPU util | thr | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | `sign.v0` default | 213.3 µs | 231.6 µs | 0.99 | 1 | 4264.3 | 1.00× | ✓ |
| ML-DSA-44 | `sign.v1` native | 191.4 µs | 199.6 µs | 0.96 | 1 | 4793.3 | 1.12× | ✓ |
| ML-DSA-44 | `sign.v2` lto | 175.9 µs | 194.1 µs | 0.86 | 1 | 4437.3 | 1.04× | ✓ |
| ML-DSA-44 | `sign.v3` pgo | 181.5 µs | 206.6 µs | 0.94 | 1 | 4551.9 | 1.07× | ✓ |
| ML-DSA-44 | `sign.v4` keycache | 144.1 µs | 147.3 µs | 1.00 | 1 | 6771.4 | 1.59× | ✓ |
| ML-DSA-44 | `sign.v5` par | 181.6 µs | 193.4 µs | 1.13 | 4 | 5834.1 | 1.37× | ✓ |
| ML-DSA-87 | `sign.v0` default | 574.8 µs | 575.4 µs | 1.00 | 1 | 1733.5 | 1.00× | ✓ |
| ML-DSA-87 | `sign.v1` native | 651.6 µs | 695.4 µs | 0.92 | 1 | 1329.5 | 0.77× | ✓ |
| ML-DSA-87 | `sign.v2` lto | 573.1 µs | 590.1 µs | 0.95 | 1 | 1607.8 | 0.93× | ✓ |
| ML-DSA-87 | `sign.v3` pgo | 664.2 µs | 726.2 µs | 0.87 | 1 | 1203.2 | 0.69× | ✓ |
| ML-DSA-87 | `sign.v4` keycache | 363.3 µs | 374.1 µs | 1.00 | 1 | 2670.2 | 1.54× | ✓ |
| ML-DSA-87 | `sign.v5` par | 598.7 µs | 653.1 µs | 1.04 | 4 | 1599.5 | 0.92× | ✓ |
| SLH-DSA-SHA2-128f | `sign.v0` default | 37.20 ms | 36.49 ms | 0.98 | 1 | 26.9 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | `sign.v1` native | 42.64 ms | 34.90 ms | 0.75 | 1 | 21.6 | 0.80× | ✓ |
| SLH-DSA-SHA2-128f | `sign.v2` lto | 37.81 ms | 35.62 ms | 0.94 | 1 | 26.5 | 0.98× | ✓ |
| SLH-DSA-SHA2-128f | `sign.v3` pgo | 41.14 ms | 29.36 ms | 0.76 | 1 | 26.0 | 0.97× | ✓ |
| SLH-DSA-SHA2-128f | `sign.v4` keycache | 38.95 ms | 43.42 ms | 0.99 | 1 | 22.8 | 0.85× | ✓ |
| SLH-DSA-SHA2-128f | `sign.v5` par | 27.37 ms | 36.89 ms | 1.35 | 4 | 36.7 | 1.36× | ✓ |
| SLH-DSA-SHAKE-128s | `sign.v0` default | 2.07 s | 2.09 s | 0.99 | 1 | 0.5 | 1.00× | ✓ |
| SLH-DSA-SHAKE-128s | `sign.v1` native | 4.25 s | 3.90 s | 0.91 | 1 | 0.2 | 0.49× | ✓ |
| SLH-DSA-SHAKE-128s | `sign.v2` lto | 2.65 s | 2.34 s | 0.86 | 1 | 0.4 | 0.77× | ✓ |
| SLH-DSA-SHAKE-128s | `sign.v3` pgo | 2.21 s | 1.94 s | 0.86 | 1 | 0.4 | 0.94× | ✓ |
| SLH-DSA-SHAKE-128s | `sign.v4` keycache | 2.24 s | 2.21 s | 0.99 | 1 | 0.4 | 0.95× | ✓ |
| SLH-DSA-SHAKE-128s | `sign.v5` par | 2.09 s | 2.20 s | 1.05 | 4 | 0.5 | 1.01× | ✓ |
