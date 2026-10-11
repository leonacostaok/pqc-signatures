# noble — verify

`verify(pk, msg, sig) → bool`. What the baseline does:

* **ML-DSA**: pkDecode; tr = SHAKE256(pk); sigDecode + hint decode; μ; SampleInBall; L forward NTTs
  of z; **ExpandA on the fly** (K·L SHAKE128 samplings — about 60–70 % of the baseline's verify time);
  K NTTs of t1·2^d; K·L products; K inverse NTTs; UseHint; SHAKE256 of w1. The expensive part is
  entirely a function of the public key.
* **SLH-DSA**: k FORS root recomputations (F + a·H each), T_k, then d WOTS+ public-key
  recomputations (up to len·15 F each) and d authentication paths (h′·H). Cheap compared to sign
  (nothing to enumerate), still thousands of tiny hashes.
* **Falcon**: HashToPoint (SHAKE256), decompress s2, NTT(s2)·NTT(h), one inverse NTT, norm check.

## Variants

| id | name | what / why / how |
|---|---|---|
| verify.v0 | baseline | `alg.verify(sig, msg, pk)` from the installed package under Node 22. |
| verify.v1 | native-hash | Vendored noble with SHAKE/SHA-2 served by `node:crypto` (shim described in keygen.v1). ML-DSA verify is XOF-dominated (ExpandA + tr + μ + c̃ + SampleInBall), so this is where the native XOF should pay off most; SLH-DSA-SHAKE gains per hash call, SLH-DSA-SHA2 is expected to lose to noble's JS SHA-256 on tiny inputs. |
| verify.v2 | fastjs | The hot-path rewrite (keygen.v2): lazy branch-free NTT, fused accumulate of the K·L products, inlined UseHint, unrolled Keccak for ExpandA and the hashes; SLH-DSA with direct compression-function calls and allocation-free WOTS/auth-path code. A is still expanded per verification (baseline semantics). Falcon skipped. |
| verify.v3 | pkcache | Per-public-key precomputation reused across verifications, on the vendored (otherwise baseline) code: **ML-DSA** `expandPk(pk)` = pkDecode + tr + ExpandA + NTT(t1·2^d) once; `verifyPrecomputed` does only sigDecode, μ, SampleInBall, NTT(z), the products and the hint reconstruction. **Falcon**: NTT(h) in Montgomery form cached. **SLH-DSA**: only the decoded pk and the `PK.seed` hash midstates can be cached (the hash context), so no measurable change is expected — included for completeness of the mechanism, documented as such. |
| verify.v4 | bun | Unmodified package under Bun 1.4.2 (JavaScriptCore). |
| verify.v5 | workers-x4 | Four `worker_threads` each verifying with the unmodified baseline; throughput over the batch, CPU over all threads. |

On every run each variant must return `true` for the reference (pk, msg, sig) in every iteration and
`false` for the signature with one flipped bit (`tamper_rejected`); `output_sha256` is `"true"` only
if both hold.

<!-- RESULTS -->

_Preliminary dev-run numbers (budget 200 ms, 4-core box shared with five other agents building/benchmarking at the same time — noisy, no SLH-DSA "s" sets; the orchestrator's quiet run overwrites this section)._

### verify — median wall per op (ms), speedup vs v0 in parentheses (ops/s ratio), all variants matched the reference

| param | verify.v0 baseline | verify.v1 native-hash | verify.v2 fastjs | verify.v3 pkcache | verify.v4 bun | verify.v5 workers-x4 |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | 1.195 (1.00×) | 1.569 (0.75×) | 0.556 (2.15×) | 0.890 (1.53×) | 2.015 (0.60×) | 2.141 (0.61×) |
| ML-DSA-65 | 2.541 (1.00×) | 1.304 (1.70×) | 0.967 (2.25×) | 1.439 (1.70×) | 3.176 (0.76×) | 4.111 (0.58×) |
| ML-DSA-87 | 3.307 (1.00×) | 4.033 (0.96×) | 1.563 (2.05×) | 1.284 (2.62×) | 4.726 (0.74×) | 4.376 (0.72×) |
| SLH-DSA-SHA2-128f | 6.631 (1.00×) | 14.860 (0.46×) | 3.643 (1.56×) | 7.090 (0.86×) | 8.216 (0.80×) | 9.916 (0.54×) |
| SLH-DSA-SHA2-192f | 15.843 (1.00×) | 26.067 (0.57×) | 6.252 (2.33×) | 10.572 (1.29×) | 13.206 (1.10×) | 15.923 (1.03×) |
| SLH-DSA-SHA2-256f | 11.025 (1.00×) | 25.438 (0.46×) | 7.606 (1.55×) | 12.034 (0.97×) | 13.520 (0.86×) | 23.916 (0.47×) |
| SLH-DSA-SHAKE-128f | 41.537 (1.00×) | 34.885 (1.25×) | 16.215 (2.56×) | 39.829 (1.06×) | 29.556 (1.42×) | 41.298 (1.03×) |
| SLH-DSA-SHAKE-192f | 54.649 (1.00×) | 38.367 (1.37×) | 20.943 (2.59×) | 54.143 (1.01×) | 41.359 (1.31×) | 68.753 (0.80×) |
| SLH-DSA-SHAKE-256f | 62.668 (1.00×) | 47.064 (1.29×) | 39.942 (1.80×) | 54.266 (1.12×) | 53.991 (1.21×) | 68.418 (0.86×) |
| Falcon-512 | 0.558 (1.00×) | 0.615 (0.91×) | n/a | 0.628 (1.12×) | 0.753 (0.89×) | 0.543 (0.98×) |
| Falcon-1024 | 1.136 (1.00×) | 1.061 (1.01×) | n/a | 0.855 (1.31×) | 1.707 (0.41×) | 1.016 (1.08×) |

**Preliminary conclusion.** ML-DSA verify is dominated by ExpandA, so both removing it (pkcache v3: 1.5–2.6×) and making it cheap (fastjs v2: 2.0–2.3×, native XOF v1: up to 1.7×) pay off; the fastjs rewrite is the better single-key choice, pkcache is the better choice when the same public key verifies many signatures. For SLH-DSA, v2 is 1.5–2.6× faster; pkcache does nothing (as documented, there is nothing key-only to cache) and native SHA-2 hashing is a 2× loss while native SHAKE is a 1.3× gain. Falcon verify is already small (one NTT product); only pkcache gives a measurable 1.1–1.3×.
