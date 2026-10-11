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
