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
