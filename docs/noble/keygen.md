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
