# noble — keygen

`keygen(seed) → (pk, sk)`. What the baseline does per family, which is what the variants attack:

* **ML-DSA**: SHAKE256(ξ‖k‖ℓ) → (ρ, ρ′, K); ExpandS = 9/11/15 SHAKE256 rejection samplings;
  ExpandA = K·L = 16/30/56 SHAKE128 rejection samplings (each ≈5 Keccak permutations); L forward
  NTTs, K·L pointwise products, K inverse NTTs; Power2Round; pack. In the baseline about half of the
  time is Keccak, the rest is NTT/polynomial arithmetic through noble's generic `FFTCore`.
* **SLH-DSA**: one full XMSS tree of the top layer: 2^h′ WOTS+ public keys (h′ = 3/4 for "f",
  8/9 for "s"), i.e. 2^h′ · len · 15 calls of F plus 2^h′ PRF chains and T_len, then 2^h′−1 calls of
  H. Pure hashing (SHA-256 / SHA-512 / SHAKE256) on tiny inputs; per-call overhead dominates.
* **Falcon**: NTRU-solve with big-integer arithmetic driven by a SHAKE256 Gaussian sampler;
  dominated by `BigInt` math, SHAKE is a minor part.

## Variants

| id | name | what / why / how |
|---|---|---|
| keygen.v0 | baseline | `alg.keygen(seed)` from the installed package under Node 22. |
| keygen.v1 | native-hash | Same noble code (vendored copy) but every `@noble/hashes` SHAKE128/SHAKE256/SHA-256/SHA-512 call is served by `node:crypto` (OpenSSL) through a drop-in shim (`src/native-hash.mjs`). Why: noble's JS Keccak costs ≈5.5 µs per permutation; OpenSSL does the whole SHAKE call in ≈2.5 µs including the call overhead, so XOF-heavy ML-DSA keygen should win. For the XOF readers (`XOF128/XOF256.get(x,y)`) the shim squeezes a fixed guess (5 SHAKE128 blocks for `RejNTTPoly`, 3 SHAKE256 blocks for `RejBoundedPoly`) in one native call and, if the sampler needs more, recomputes with double the `outputLength` (SHAKE outputs are prefixes of longer outputs, so this is exact). For SLH-DSA SHA-2 the per-call overhead of OpenSSL on a 100-byte input is *higher* than noble's JS SHA-256 (1.9 µs vs 0.9 µs measured), so this variant is expected to lose there — it is kept because it is the same mechanism and the result is informative. |
| keygen.v2 | fastjs | Pure-JS rewrite of the hot paths (`src/fast-ml-dsa.mjs`, `src/fast-slh-dsa.mjs`, `src/fast-keccak.mjs`). ML-DSA: FIPS 204 Alg. 41/42 NTT written out with **lazy reduction** — polynomials are `Float64Array`s, `a·b mod q` is `t − ⌊t·q⁻¹⌋·q` (result in (−q, 2q), never corrected), butterfly outputs are not reduced; coefficients grow ≤ 2q per stage so after 8 stages they are < 17q < 2²⁸ and every product stays < 2⁵¹ (exact in a double); one canonicalizing pass at the end. This removes every data-dependent branch from the butterflies (3× faster than the fully reduced loop in isolation). Matrix–vector products accumulate L pointwise products in a `Float64Array` and reduce once (7·(q−1)² < 2⁵³). Power2Round/decompose are inlined loops without per-coefficient objects. SHAKE128/256 run on a **generated, fully unrolled Keccak-f[1600]** (`new Function` source with all 50 state words in locals, one round per loop iteration; 2.4× noble's `keccakP`). SLH-DSA: F/H/PRF call the SHA-2 **compression function directly** on a pre-padded 64/128-byte block from the cached `PK.seed‖0…` midstate (`_SHA256.set(); process(view, 0)`), or reset the 200-byte sponge from the cached `PK.seed` state and run the unrolled Keccak once; ADRS words are written through fixed-offset helpers instead of noble's `setAddr({...})` (which allocates an object and does 8 `Object.hasOwn` checks per call); tree walks hash in place between fixed buffers. Falcon is not rewritten (skipped). |
| keygen.v3 | fastjs+native | The v2 rewrite with its SHAKE/SHA-2 calls routed to `node:crypto` (the "everything" variant). Tells whether OpenSSL still beats the unrolled JS Keccak once the rest of the code is fast. |
| keygen.v4 | bun | The unmodified package executed by Bun 1.4.2 (JavaScriptCore) instead of Node (V8); same source, different JIT, GC and typed-array implementation. |
| keygen.v5 | workers-x4 | Throughput: four `worker_threads`, each running the unmodified baseline on its own copy of the inputs; a batch is k ops per worker, wall per op = batch wall / (4k), CPU over the loop covers all threads. Shows how much of the 4-core box a single-threaded JS library leaves on the table. |

Correctness: every variant's pk and sk digests are compared against `common/reference.json` on every
run (Falcon: against the baseline's own output), see README.

<!-- RESULTS -->

_Preliminary dev-run numbers (budget 200 ms, 4-core box shared with five other agents building/benchmarking at the same time — noisy, no SLH-DSA "s" sets; the orchestrator's quiet run overwrites this section)._

### keygen — median wall per op (ms), speedup vs v0 in parentheses (ops/s ratio), all variants matched the reference

| param | keygen.v0 baseline | keygen.v1 native-hash | keygen.v2 fastjs | keygen.v3 fastjs+native | keygen.v4 bun | keygen.v5 workers-x4 |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | 1.018 (1.00×) | 0.688 (1.32×) | 0.517 (1.90×) | 0.437 (1.55×) | 1.478 (0.59×) | 0.763 (1.19×) |
| ML-DSA-65 | 1.857 (1.00×) | 1.028 (2.05×) | 0.888 (2.58×) | 0.615 (2.68×) | 2.540 (0.92×) | 2.314 (1.05×) |
| ML-DSA-87 | 2.836 (1.00×) | 1.536 (1.64×) | 1.524 (1.77×) | 1.358 (1.78×) | 4.328 (0.60×) | 4.282 (0.72×) |
| SLH-DSA-SHA2-128f | 4.196 (1.00×) | 9.763 (0.43×) | 2.200 (1.79×) | 9.255 (0.38×) | 4.436 (0.94×) | 3.623 (1.06×) |
| SLH-DSA-SHA2-192f | 6.733 (1.00×) | 14.743 (0.46×) | 3.385 (1.97×) | 11.694 (0.48×) | 7.636 (0.76×) | 5.458 (1.21×) |
| SLH-DSA-SHA2-256f | 17.500 (1.00×) | 38.783 (0.51×) | 10.169 (1.89×) | 41.729 (0.47×) | 29.195 (0.58×) | 25.910 (0.71×) |
| SLH-DSA-SHAKE-128f | 26.464 (1.00×) | 28.250 (1.00×) | 10.639 (2.44×) | 14.648 (1.46×) | 22.075 (1.17×) | 16.326 (1.45×) |
| SLH-DSA-SHAKE-192f | 38.861 (1.00×) | 43.351 (1.03×) | 17.586 (2.21×) | 27.418 (1.65×) | 51.177 (0.84×) | 29.215 (1.36×) |
| SLH-DSA-SHAKE-256f | 106 (1.00×) | 133 (0.85×) | 40.557 (2.60×) | 67.971 (1.55×) | 90.085 (1.19×) | 101 (0.98×) |
| Falcon-512 | 251 (1.00×) | 234 (1.17×) | n/a | n/a | 260 (1.05×) | 181 (1.35×) |
| Falcon-1024 | 685 (1.00×) | 764 (0.93×) | n/a | n/a | 752 (0.93×) | 500 (1.33×) |

**Preliminary conclusion.** The pure-JS rewrite (v2) is the clear win: 1.8–2.6× on every ML-DSA and SLH-DSA set, from the branch-free lazily-reduced NTT and, above all, the unrolled Keccak (keygen is hash-bound). The node:crypto layer (v1) helps ML-DSA (1.3–2×, XOF-bound) and is neutral for SLH-SHAKE, but *halves* SLH-DSA-SHA2 keygen: an OpenSSL call on a 100-byte input costs more than noble's JS SHA-256 compression. Consequently v3 (fastjs+native) only beats v2 for ML-DSA, where the per-call overhead is amortised over 5-block squeezes. Bun is slower than Node on this code except for the SHAKE sets. The worker variant scales poorly in this noisy run (other agents were using the cores); expect ≈3–4× throughput on the quiet machine. Falcon keygen is BigInt-bound and untouched by the hash variants.
