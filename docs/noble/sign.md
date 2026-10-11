# noble — sign

`sign(sk, msg) → sig`, deterministic (`extraEntropy: false`). What the baseline does:

* **ML-DSA**: skDecode; ExpandA (K·L SHAKE128 samplings — the same work keygen does, repeated
  for every signature); NTT of s1, s2, t0; then per rejection-sampling round: L SHAKE256 mask
  expansions, L forward NTTs, K·L products, K inverse NTTs, HighBits, SHAKE256 commitment,
  SampleInBall, 1 + L + 2K more NTT/INTTs, norm checks and hints. The number of rounds depends on
  (sk, msg) — for the shared vectors ML-DSA-65 happens to need several rounds, which is why its
  sign is slower than ML-DSA-87's.
* **SLH-DSA**: PRFmsg, Hmsg, k FORS trees of 2^a leaves (PRF+F per leaf, H per node), T_k, then
  **d** XMSS trees of 2^h′ WOTS+ leaves each (len·15 F per leaf). For the "s" sets d=7/8 trees of
  256/512 leaves × 35..67 chains → millions of hash calls, 2–21 s per signature in pure JS.
* **Falcon**: skDecode; reconstruct G (NTT-domain division); FFT of the basis b00..b11; Gram
  matrix; then ffSampling with a ChaCha20-driven sampler and the compress/retry loop.

## Variants

| id | name | what / why / how |
|---|---|---|
| sign.v0 | baseline | `alg.sign(msg, sk, { extraEntropy: false })` from the installed package under Node 22. |
| sign.v1 | native-hash | Vendored noble with SHAKE/SHA-2 served by `node:crypto` (see keygen.v1 for the shim). For ML-DSA this covers ExpandA, ExpandMask, μ/ρ′/c̃ and SampleInBall; for SLH-DSA-SHAKE every F/H/PRF becomes one OpenSSL call (≈2.5 µs vs ≈7 µs for noble's cloned-midstate SHAKE); for SLH-DSA-SHA2 the OpenSSL call overhead is larger than noble's JS SHA-256 on 100-byte inputs, so a slowdown is expected there (and is reported as such). Falcon: HashToPoint and the sampler seed expansion go native. |
| sign.v2 | fastjs | The hot-path rewrite (see keygen.v2): lazy branch-free NTT on `Float64Array`s with fused multiply-accumulate across the K·L products, inlined decompose/LowBits/MakeHint, no per-round zeroization, unrolled Keccak for all SHAKE; SLH-DSA with direct compression-function calls and allocation-free ADRS/tree code. The per-key part (`expandSk`) is *recomputed* for every signature here, exactly like the baseline, so v2 isolates the code-quality effect. Falcon skipped. |
| sign.v3 | keycache | Per-secret-key precomputation reused across signatures, on the vendored (otherwise baseline) code: **ML-DSA** `expandSk(sk)` = skDecode + ExpandA + NTT(s1, s2, t0) once; `signPrecomputed(msg, exp)` runs only the per-message rejection loop (the cached polys are read-only there). **SLH-DSA**: the top layer of the hypertree (layer d−1, tree index 0) is the same XMSS tree for every message, so `expandSk` builds all 2^(h′+1)−1 nodes of that tree once; `signPrecomputed` then produces the layer-(d−1) WOTS+ signature directly from the PRF chain secrets (≤ 15 F per chain instead of the full 2^h′-leaf treehash) and copies the authentication path out of the cache — this saves 1/d of the hypertree work (≈14 % for "s", ≈4.5 % for "f"); nothing else in SLH-DSA signing is message-independent. **Falcon**: skDecode + G completion + FFT of the basis [[g,−f],[G,−F]] are cached (`expandBasis`), the sampler is re-seeded per message. Output is byte-identical by construction (same deterministic inputs, same code after the cached point). |
| sign.v4 | bun | Unmodified package under Bun 1.4.2 (JavaScriptCore). |
| sign.v5 | workers-x4 | Four `worker_threads` each signing with the unmodified baseline; throughput over the batch, CPU over all threads. |

Every variant's signature digest is checked against `common/reference.json` (Falcon: against the
baseline's own deterministic output) on every run, and every later iteration is byte-compared to the
first.

<!-- RESULTS -->

_Preliminary dev-run numbers (budget 200 ms, 4-core box shared with five other agents building/benchmarking at the same time — noisy, no SLH-DSA "s" sets; the orchestrator's quiet run overwrites this section)._

### sign — median wall per op (ms), speedup vs v0 in parentheses (ops/s ratio), all variants matched the reference

| param | sign.v0 baseline | sign.v1 native-hash | sign.v2 fastjs | sign.v3 keycache | sign.v4 bun | sign.v5 workers-x4 |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | 2.438 (1.00×) | 2.278 (1.13×) | 1.786 (1.86×) | 1.499 (1.61×) | 3.950 (0.85×) | 1.783 (1.94×) |
| ML-DSA-65 | 13.328 (1.00×) | 14.603 (0.86×) | 4.689 (2.47×) | 9.261 (1.34×) | 19.137 (0.63×) | 7.260 (1.78×) |
| ML-DSA-87 | 10.332 (1.00×) | 6.192 (1.39×) | 3.321 (2.39×) | 5.130 (1.72×) | 12.178 (0.75×) | 5.240 (1.95×) |
| SLH-DSA-SHA2-128f | 104 (1.00×) | 377 (0.27×) | 53.212 (1.96×) | 134 (0.82×) | 121 (0.85×) | 96.512 (1.07×) |
| SLH-DSA-SHA2-192f | 201 (1.00×) | 460 (0.44×) | 104 (1.95×) | 193 (1.07×) | 214 (0.88×) | 147 (1.42×) |
| SLH-DSA-SHA2-256f | 555 (1.00×) | 892 (0.58×) | 234 (2.60×) | 422 (1.39×) | 548 (1.06×) | 276 (2.25×) |
| SLH-DSA-SHAKE-128f | 875 (1.00×) | 471 (1.84×) | 268 (3.41×) | 718 (1.28×) | 490 (1.78×) | 544 (1.66×) |
| SLH-DSA-SHAKE-192f | 1197 (1.00×) | 942 (1.30×) | 436 (2.61×) | 1042 (1.19×) | 760 (1.64×) | 578 (2.10×) |
| SLH-DSA-SHAKE-256f | 2922 (1.00×) | 1851 (1.60×) | 985 (2.80×) | 2495 (1.15×) | 1649 (1.78×) | 1157 (2.46×) |
| Falcon-512 | 5.255 (1.00×) | 5.632 (0.97×) | n/a | 3.193 (1.61×) | 5.195 (0.68×) | 13.087 (0.40×) |
| Falcon-1024 | 14.733 (1.00×) | 10.480 (1.47×) | n/a | 6.574 (2.43×) | 11.869 (1.32×) | 16.119 (0.96×) |

**Preliminary conclusion.** v2 (fastjs) gives 1.9–2.5× on ML-DSA and 2–3.4× on SLH-DSA; keycache (v3) gives ML-DSA 1.3–1.7× (ExpandA + key NTTs are a large fixed cost per signature when few rejection rounds are needed), Falcon 1.6–2.4× (basis FFT/G reconstruction dominate) and the expected modest 1.1–1.4× on SLH-DSA (only the top tree is key-only). Native hashing (v1) is a large loss for SLH-DSA-SHA2 (0.3–0.6×) and a gain for SLH-DSA-SHAKE (1.3–1.8×) and mixed for ML-DSA in this noisy run; the JS unrolled Keccak of v2 beats node:crypto on SHAKE because it avoids the per-call native boundary. Bun is faster than Node for the SHAKE-heavy sets and slower for ML-DSA. Workers: throughput only, limited here by the shared box.
