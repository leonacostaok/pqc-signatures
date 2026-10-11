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
