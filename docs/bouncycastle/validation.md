# Bouncy Castle: validation suite

`libs/bouncycastle/run.sh validate common/validation/validation.json.gz results/bouncycastle/validation.json`

The suite (651 cases: NIST ACVP FIPS 204/205 keyGen / deterministic sigGen / sigVer with contexts, plus the
negative/edge suite derived from `common/vectors.json`) is run through **every variant of the matching process**:

| case kind | variants it is run through |
|---|---|
| `keygen` (seed -> pk, sk) | `keygen.v0` jca, `v1` jca-reuse, `v2` lightweight, `v3` internal-seed, `v4` parallel (all 4 lanes must agree), `v5` parallelgc (child JVM with its flags) |
| `siggen` (sk, msg, ctx -> sig) | `sign.v0` jca, `v1` lightweight, `v2` reuse-signer, `v3` parallel, `v4` c2-only (child JVM), `v5` epsilon-nogc (child JVM) |
| `sigver` (pk, msg, ctx, sig -> bool) | `verify.v0` jca, `v1` lightweight, `v2` reuse-verifier, `v3` parallel, `v4` parallelgc (child JVM), `v5` inline-aggressive (child JVM), and the stage pipelines `total.v0` (all v0 stages) and `total_best` (composition from `results/bouncycastle/stages.jsonl`, see verify-stages.md) |

Implementation (`Validate.java`, `CaseOps.java`):

* **Contexts.** Lightweight API: `signer.init(forSigning, new ParametersWithContext(key, ctx))`; JCA:
  `Signature.setParameter(new ContextParameterSpec(ctx))` before `initSign`/`initVerify`. A context longer than
  255 bytes makes BC throw `IllegalArgumentException("context too long")`, which is recorded as a rejection for
  sigver and as a failure for siggen (the suite has none).
* **Secret keys are imported, never regenerated.** `sk_hex` is the FIPS encoding (ML-DSA expanded
  `rho||K||tr||s1||s2||t0`, SLH-DSA `SK.seed||SK.prf||PK.seed||PK.root`), loaded with
  `new MLDSAPrivateKeyParameters(params, sk, null)` (BC derives t1 itself) / `new SLHDSAPrivateKeyParameters(params, sk)`,
  and for the JCA variant converted to a `PrivateKey` through PKCS#8 + `KeyFactory`.
* **Reuse variants** keep their initialised signer/verifier in a cache keyed by (variant, param, SHA-256(key),
  ctx), exactly as a long-lived verifier process would, so a stale state after a rejected signature would show up as
  a failure on the next case with the same key. `jca-reuse` keygen keeps one `KeyPairGenerator` per parameter set and
  swaps the seed source underneath its `SecureRandom`.
* **Parallel variants** run every case on all lanes (4 threads, one initialised engine each) and require the lanes
  to agree.
* **Child-JVM variants** (`keygen.v5`, `sign.v4`, `sign.v5`, `verify.v4`, `verify.v5`) run the whole suite in a
  child JVM started with their flags; results are streamed back as JSON lines.
* **Malformed input** (wrong lengths, bad hint encodings, truncated/extended signatures) must yield `false`: BC's
  `MLDSASigner.verifySignature` returns `false` (never throws) for a malformed signature; the SLH-DSA path and the
  stage pipelines reject on length before parsing. Any exception during verification is caught and recorded as
  `false` with the exception text in `error`.
* `got` holds the verify result (sigver), `pk-ok/sk-ok` flags (keygen) or the SHA-256 of the produced signature
  (siggen); `pass` is `got == expect` resp. byte equality with the expected pk/sk/signature. The summary counts
  pass/fail/skipped per variant. Nothing is skipped: the slowest siggen cases (SLH-DSA-*-256s, ~1-2 s each) are run
  through all six sign variants.

## Findings

All 4680 results pass (651 cases x the variants of their process: 195 keygen cases x 6, 69 siggen x 6,
387 sigver x 8 incl. `total.v0` and `total_best`), with zero skips; the full run took ~16 minutes on the shared dev box (five child JVMs included), dominated by the
SLH-DSA "s" siggen cases in the six sign variants. Nothing had to be explained away:

* BC 1.86 agrees with the NIST ACVP vectors for all 15 parameter sets, with and without contexts (contexts of 0-255
  bytes are in the suite), for seed-based keygen, deterministic signing with imported FIPS-encoded secret keys, and
  signature verification; every ACVP "reason" (modified message / signature parts / commitment / hint / too large /
  too small) and every negative case of our own (wrong context in both directions, flipped pk, truncated or extended
  signature, all-zero signature, z coefficient = gamma1, hint count > omega, non-increasing hint indices, non-zero hint
  padding) is rejected by every verify variant, including the caching `reuse-verifier` and the stage pipelines.
* The caching variants were the point of this exercise: `reuse-verifier` keeps an initialised `MLDSASigner` per
  (pk, ctx) and `total_best` keeps nothing between cases, and both reject everything the fresh variants reject. One
  pitfall surfaced in the memory driver rather than here: a `StackOverflowError` thrown inside a reused `MLDSASigner`
  leaves its SHAKE state in "squeezing" mode and every later call throws ("attempt to absorb while squeezing"), so a
  reused signer must be discarded after any error.
* BC's ML-DSA verify returns `false` (never throws) for malformed signatures, as its javadoc says; the SLH-DSA path
  rejects wrong signature lengths before parsing (`SIG` would throw on a length mismatch otherwise). No exception
  reached the "exception treated as reject" path in this run (`error` is null for every sigver result).

<!-- RESULTS -->

## Results (preliminary dev run on a shared 4-core box)

| variant | pass | fail | skipped |
|---|---|---|---|
| `keygen.v0` | 195 | 0 | 0 |
| `keygen.v1` | 195 | 0 | 0 |
| `keygen.v2` | 195 | 0 | 0 |
| `keygen.v3` | 195 | 0 | 0 |
| `keygen.v4` | 195 | 0 | 0 |
| `keygen.v5` | 195 | 0 | 0 |
| `sign.v0` | 69 | 0 | 0 |
| `sign.v1` | 69 | 0 | 0 |
| `sign.v2` | 69 | 0 | 0 |
| `sign.v3` | 69 | 0 | 0 |
| `sign.v4` | 69 | 0 | 0 |
| `sign.v5` | 69 | 0 | 0 |
| `total.v0` | 387 | 0 | 0 |
| `total_best` | 387 | 0 | 0 |
| `verify.v0` | 387 | 0 | 0 |
| `verify.v1` | 387 | 0 | 0 |
| `verify.v2` | 387 | 0 | 0 |
| `verify.v3` | 387 | 0 | 0 |
| `verify.v4` | 387 | 0 | 0 |
| `verify.v5` | 387 | 0 | 0 |

Total results: 4680, failures: 0
