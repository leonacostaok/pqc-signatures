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
