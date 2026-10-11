# Bouncy Castle: verify variants

Process: (pk, msg, sig) -> bool. ML-DSA verification (`MLDSAEngine.verifyInternal`) decodes z/h, re-expands the
matrix A from rho (SHAKE128, per call), computes `w1' = A z - c 2^d t1` in the NTT domain and recomputes the
challenge hash. SLH-DSA verification recomputes the FORS roots and walks d XMSS authentication paths: much
cheaper than signing but still thousands of hash calls, and for the "f" sets the large signature is the main input.

Every variant must return `true` for the reference (pk, msg, sig) on every iteration and `false` for a signature
with one flipped bit (checked once per cell through the same code path); `output_sha256` is `"true"` only if both hold.

| id | name | what | why it might help |
|---|---|---|---|
| verify.v0 | `jca` | **Baseline.** `Signature.getInstance("ML-DSA" or "SLH-DSA", "BC")`, `initVerify(publicKey)`, `update(msg)`, `verify(sig)`; new `Signature` per op. `PublicKey` built once via `KeyFactory` + X.509 SPKI. | - |
| verify.v1 | `lightweight` | `new MLDSASigner()` / `new SLHDSASigner()`, `init(false, publicKeyParameters)`, `verifySignature(...)`; new verifier per op. | Same reasoning as for signing: avoids provider lookup, SPI re-initialisation and (SLH-DSA) the message buffering stream. |
| verify.v2 | `reuse-verifier` | One lightweight verifier initialised once per public key and reused for every op. | `MLDSASigner.init(false, pk)` computes `tr = SHAKE256(rho || t1)` over the whole public key and absorbs it into the message digest state, and clones rho/t1; with reuse that hash over 1.3-2.6 KB is paid once (BC keeps a copy of the absorbed state and forks it per message). For SLH-DSA only the key clones are saved. |
| verify.v3 | `parallel` | Batch of verifications over a 4-thread pool, one initialised verifier per lane; throughput, `threads = 4`. | Verification is the operation most often done in bulk (certificate chains, batches of transactions); shows how BC scales when the matrix expansion and NTTs of several verifications run concurrently. |
| verify.v4 | `parallelgc` | `lightweight` code path in a child JVM with `-XX:+UseParallelGC -Xms2g -Xmx2g -Xmn1200m -XX:+AlwaysPreTouch`. | ML-DSA verify allocates the whole A matrix (k*l `int[256]`), z, h, t1, w1 per call; a throughput collector with a big pre-touched young generation makes those allocations nearly free and removes G1's barriers. |
| verify.v5 | `inline-aggressive` | `lightweight` code path in a child JVM with larger C2 inlining budgets: `-XX:MaxInlineLevel=30 -XX:MaxInlineSize=120 -XX:FreqInlineSize=1200 -XX:InlineSmallCode=6000 -XX:MaxNodeLimit=240000 -XX:NodeLimitFudgeFactor=8000`. | BC's ML-DSA code is written as many small methods (`Reduce.montgomeryReduce`, `Poly.getCoeffIndex`, `Rounding.*`, Keccak helpers) called from hot loops; verification is the most call-dense op. Raising the inlining thresholds lets C2 inline the whole NTT/pointwise layer into the loops and vectorise across what were call boundaries. |

Implementation notes: the tamper check flips bit 0 of the middle byte of the signature (inside z for ML-DSA, inside
the FORS/XMSS part for SLH-DSA); BC returns `false` (never throws) for malformed ML-DSA signatures, as documented
in the `MLDSASigner` javadoc. For the parallel variant the tamper check runs the whole batch with the bad signature
and requires every lane to reject.

<!-- RESULTS -->
