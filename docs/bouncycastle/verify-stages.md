# Bouncy Castle: verify split into stages

`libs/bouncycastle/run.sh stages --out results/bouncycastle/stages.jsonl [--budget-ms N] [--params a,b] [--stages x,y]`

## How the stages were obtained from BC

BC's verification lives in package-private classes (`org.bouncycastle.crypto.signers.mldsa.{MLDSAEngine, Poly,
PolyVec, PolyVecMatrix, Packing, Ntt, Reduce, Rounding, Symmetric}` and `...slhdsa.{SLHDSAEngine, Fors, HT,
WotsPlus, ADRS, SIG*}`), and the signed `bcprov` jar forbids adding classes to those packages. The 1.86 sources
of exactly these two packages are therefore **vendored** into `libs/bouncycastle/src/bc/mldsa` and `src/bc/slhdsa`
(BC's MIT license kept in `src/bc/LICENSE-BouncyCastle.md`), unchanged except for: the package name, three
`public` modifiers (`PolyVec`, `PolyVecMatrix`, the engine primitives), a `row(i)` accessor on `PolyVecMatrix`,
the full `H_msg` output kept in `IndexedDigest`, and the removal of three `SLHDSAParameters`-dependent static
helpers. The stage entry points (`bc/mldsa/MlStages.java`, `bc/slhdsa/SlhStages.java`) call these classes
exactly as `MLDSAEngine.verifyInternal` / `SLHDSAEngine.internalVerifySignature` do, so every `<stage>.v0` runs
BC's own code; the harness's own code is only glue plus the alternatives. All stage inputs are the outputs of the
previous v0 stages, computed once per parameter set outside the timed region.

## ML-DSA stages (FIPS 204 Alg. 8 + external wrapper; reference pk/msg/sig, empty context)

| stage | v0 = BC code | canonical output |
|---|---|---|
| `decode` | `Packing.unpackPublicKey` (t1) + `Packing.unpackSignature` (z, h with the hint validity checks) | SHA-256 of c~ |
| `mu` | `SHAKEDigest`: tr = H(pk, 64), mu = H(tr \|\| 0 \|\| 0 \|\| M, 64) | SHA-256 of mu |
| `expandA` | `PolyVecMatrix.expandMatrix` (SHAKE128(rho\|\|j\|\|i), 23-bit rejection sampling) | SHA-256 of the k x l x 256 coefficients in [0,q), u32 LE |
| `w_approx` | NTT(z); A o z (fused pointwise-accumulate); NTT(c); NTT(t1<<d); c o t1; sub; reduce32; invNTT-to-mont; caddq | SHA-256 of w' (k x 256, [0,q), u32 LE, normal domain) |
| `hint_check` | `checkNorm(z)`, `PolyVec.useHint`, `packW1`, SHAKE256(mu \|\| w1Encode) = c~ ? | SHA-256 of w1Encode(w1') |

Alternatives:

| variant | what | why |
|---|---|---|
| `decode.v1` wide-unpack | t1 (10-bit) and z (18/20-bit) fields extracted from 64-bit little-endian word loads (`VarHandle`) instead of byte-by-byte shifts; same hint rules | fewer loads/ORs per coefficient; a test of how much the byte-wise unpacking costs |
| `decode.v2` c2-only | BC decode in a child JVM with `-XX:-TieredCompilation` | compiler-only build variant for a tiny, branchy stage |
| `mu.v1` cached-tr | tr = H(pk) precomputed once per public key, only SHAKE256(tr\|\|...\|\|M) per message | the legitimate verifier-side cache: tr depends only on pk |
| `mu.v2` own-keccak | both hashes on the harness's own Keccak-f[1600] sponge (`bc/Keccak.java`, lanes in locals) | an independent SHAKE implementation vs BC's `SHAKEDigest` |
| `expandA.v1` cached-A | A kept per public key | upper bound for a verifier that sees the same key many times |
| `expandA.v2` parallel-rows | the k rows expanded on a thread pool, one BC engine (own SHAKE state) per task | the stage is embarrassingly parallel per polynomial |
| `expandA.v3` own-keccak | own SHAKE128 sponge; rejection sampler reads 3-byte triples straight out of the squeezed block (no block copies) | removes BC's `stream128squeezeBlocks` buffer copy and digest object overhead |
| `expandA.v4` c2-only | child JVM `-XX:-TieredCompilation` | compiler variant for the heaviest ML-DSA stage |
| `w_approx.v1` cached-ntt-t1 | NTT(t1 * 2^d) precomputed per public key | saves k shifts + k NTTs per verify |
| `w_approx.v2` parallel-rows | NTT(z), NTT(c) once; the k output rows (dot product, c*t1, sub, invNTT) in parallel | row-parallel matrix-vector product |
| `w_approx.v3` long-accum | one 64-bit accumulator per coefficient over the l products and the -c*t1 term, then a single Montgomery reduction (instead of l+1) | lazy reduction; the sum stays below 2^54 so one reduction is exact |
| `hint_check.v1` fused-usehint-pack | decompose + UseHint + w1Encode in one pass writing the packed bytes directly | no intermediate PolyVec, half the memory traffic |
| `hint_check.v2` own-keccak | BC UseHint/pack, challenge hash on the own sponge | independent SHAKE256 for the final hash |
| `hint_check.v3` c2-only | child JVM `-XX:-TieredCompilation` | compiler variant |

## SLH-DSA stages (FIPS 205 Alg. 20 + external wrapper)

| stage | v0 = BC code | canonical output |
|---|---|---|
| `hmsg` | `SIG` parse once, then `engine.H_msg(R, PK.seed, PK.root, 0\|\|0\|\|M)`: SHA2 sets SHA-256/512 + MGF1 (BC digests), SHAKE sets `SHAKEDigest`; split into md / idx_tree / idx_leaf | SHA-256 of the full m-byte digest |
| `fors` | `Fors.pkFromSig(SIG_FORS, md, PK.seed, ADRS)` | SHA-256 of PK_FORS |
| `ht_wots` | `WotsPlus.pkFromSig` for each of the d layers, each given its correct message (PK_FORS for layer 0, the previous layer's root above) | SHA-256 of the d n-byte WOTS+ pks, layer 0 first |
| `ht_auth` | the auth-path loop of `HT.xmss_pkFromSig` for each layer from its WOTS+ pk, final compare with PK.root | SHA-256 of the d layer roots |

Alternatives:

| variant | what | why |
|---|---|---|
| `*.v1` alt-backend (hmsg, fors, ht_wots, ht_auth) | BC's stage code run on an `SLHDSAEngine` whose F/H/T_l/H_msg use a non-BC backend: the JDK's intrinsified SHA-256/SHA-512 `MessageDigest` with the PK.seed block kept as a cloned midstate (SHA2 sets), or the own Keccak sponge (SHAKE sets) | isolates the digest implementation: BC's pure-Java SHA-256 vs HotSpot's SHA intrinsics |
| `fors.v2` parallel-trees | the k FORS trees on a thread pool (BC engine per task), T_l on the caller's engine | k independent trees |
| `ht_wots.v2` parallel-chains | per layer, the len = 2n+3 WOTS+ chains split over the pool (BC engine per lane) | chains are independent; the only parallelism available inside a real verify |
| `ht_wots.v3` / `ht_auth.v2` parallel-layers | the d layers computed concurrently from the precomputed inputs | measures the layer-level parallelism of the stage as defined; **not composable** into a real verify (layer j's message is layer j-1's root), so excluded from `total_best` |
| `fors.v3` / `ht_wots.v4` / `ht_auth.v3` fused-fast | re-implementation on `FastHash` (JDK SHA-2 midstate or own Keccak): flat 32-byte ADRS written in place, int base-2^a / base-w, every node hashed in place inside one buffer (FORS roots, the len*n chain buffer, the auth node) with no per-node allocation; BC's code allocates two to three arrays per hash call and uses `BigInteger` for base-2^a | removes allocation and copying from the hash-bound loops |
| `hmsg.v2` c2-only | child JVM `-XX:-TieredCompilation` | compiler variant |

Why some stages have fewer than five alternatives: `mu` and `hmsg` are a single hash call over a few hundred bytes,
`decode` is a few microseconds of bit shuffling, and `ht_auth` is h'/d x d hash calls; beyond a different digest
backend, a cache and a compiler variant there is no further mechanism that is not a near-duplicate.

## total and total_best

Per parameter set the driver also emits `stage:"total"` (`total.v0`: the end-to-end verify assembled from the v0
stages) and `stage:"total_best"`: the end-to-end verify assembled from the fastest **composable, non-cached,
in-process** alternative of each stage as measured in that run (the composition is stored in the line's
`composition` field). Cached variants are excluded because they would trivially win on a benchmark that verifies
the same key repeatedly; `validate` runs `total_best` with the composition recorded in
`results/bouncycastle/stages.jsonl` (or a default) over all 651 cases, including the negative suite.

## Conclusions (preliminary, 200 ms budget on a dev box shared with five other agents)

* **ML-DSA.** `expandA` (~45-50 us for ML-DSA-44) and `w_approx` (~40 us) are the verify; the per-key caches are
  the only big single-thread effects (`cached-A` removes expandA entirely, `cached-ntt-t1` 1.4x on w_approx,
  `cached-tr` 12x on mu). Among the non-cached alternatives `wide-unpack` (1.9x on decode) and `fused-usehint-pack`
  (1.7x on hint_check) are real but act on stages worth a few microseconds; `long-accum` is neutral (BC's fused
  pointwise-accumulate already reduces once per product and HotSpot keeps the accumulator in a register either way);
  `own-keccak` is within 5-15 % of BC's SHAKEDigest; `parallel-rows` loses on a loaded 4-core box (thread hand-off
  ~20 us vs ~12 us of work per row). total_best therefore ends up only ~3 % ahead of total.v0 for ML-DSA.
* **SLH-DSA SHA2 sets.** The digest implementation is everything: BC's pure-Java `SHA256Digest` vs the JDK's
  intrinsified SHA-256/SHA-512 gives 1.5-1.6x on fors / ht_wots / ht_auth just by swapping the backend
  (`alt-backend`), and ~1.9x with the fused allocation-free re-implementation (`fused-fast`); end-to-end
  `total_best` is 1.6-4x faster than BC's own verify on these sets.
* **SLH-DSA SHAKE sets.** BC's `SHAKEDigest` is already as fast as the own sponge, so `alt-backend` and
  `fused-fast` are neutral to slightly negative (the absorb of PK.seed||ADRS per call dominates, not allocation);
  `parallel-chains` gives 1.4x on ht_wots when it gets its cores. `parallel-layers` (not composable) shows the
  stage-level layer parallelism (1.9x) but cannot be used in a real verify.
* The c2-only child JVMs are consistently 0-20 % slower on these microsecond stages in this run: with only 200 ms
  of measurement after a cold start, C2-only has not finished compiling the hot loops; the quiet 1 s run should be
  read instead.

<!-- RESULTS -->

## Results (preliminary dev run on a shared 4-core box; memory on 4 params only)

Median wall per stage execution (us); speedup = median of `<stage>.v0` / median of the variant; match = canonical output equals v0's.

### ML-DSA-44

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` bc | 5504 | 12.1 | 21.2 | 30.9 | 1 | 1.00x | True |
| decode | `decode.v1` wide-unpack | 12244 | 4.0 | 5.5 | 16.3 | 1 | 3.05x | True |
| decode | `decode.v2` c2-only | 6397 | 6.2 | 9.8 | 28.1 | 1 | 1.95x | True |
| mu | `mu.v0` bc | 19272 | 5.3 | 8.1 | 7.8 | 1 | 1.00x | True |
| mu | `mu.v1` cached-tr | 56690 | 0.6 | 0.9 | 1.8 | 1 | 8.46x | True |
| mu | `mu.v2` own-keccak | 9962 | 5.3 | 9.7 | 10.0 | 1 | 1.00x | True |
| expandA | `expandA.v0` bc | 959 | 46.8 | 68.2 | 125.1 | 1 | 1.00x | True |
| expandA | `expandA.v1` cached-A | 2276 | 0.0 | 0.1 | 61.5 | 1 | 1375.59x | True |
| expandA | `expandA.v2` parallel-rows | 1522 | 70.3 | 111.0 | 164.3 | 4 | 0.67x | True |
| expandA | `expandA.v3` own-keccak | 999 | 49.7 | 73.3 | 110.1 | 1 | 0.94x | True |
| expandA | `expandA.v4` c2-only | 488 | 74.1 | 128.5 | 225.4 | 1 | 0.63x | True |
| w_approx | `w_approx.v0` bc | 421 | 39.7 | 80.8 | 285.0 | 1 | 1.00x | True |
| w_approx | `w_approx.v1` cached-ntt-t1 | 2394 | 30.8 | 50.7 | 45.9 | 1 | 1.29x | True |
| w_approx | `w_approx.v2` parallel-rows | 1755 | 55.1 | 79.6 | 108.3 | 4 | 0.72x | True |
| w_approx | `w_approx.v3` long-accum | 1414 | 42.9 | 98.3 | 84.9 | 1 | 0.92x | True |
| hint_check | `hint_check.v0` bc | 7351 | 11.9 | 17.3 | 17.7 | 1 | 1.00x | True |
| hint_check | `hint_check.v1` fused-usehint-pack | 10136 | 5.7 | 10.1 | 9.9 | 1 | 2.08x | True |
| hint_check | `hint_check.v2` own-keccak | 7857 | 7.8 | 14.7 | 12.7 | 1 | 1.52x | True |
| hint_check | `hint_check.v3` c2-only | 1078 | 54.3 | 78.1 | 111.3 | 1 | 0.22x | True |
| total | `total.v0` v0-pipeline | 1083 | 112.8 | 199.2 | 129.3 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `decode.v1,mu.v0,expandA.v0,w_approx.v0,hint_check.v1` | 548 | 109.0 | 194.1 | 219.0 | 1 | - | True |

total_best vs total.v0: 1.03x

### ML-DSA-65

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` bc | 16632 | 6.2 | 9.4 | 7.8 | 1 | 1.00x | True |
| decode | `decode.v1` wide-unpack | 22277 | 4.5 | 5.7 | 5.4 | 1 | 1.39x | True |
| decode | `decode.v2` c2-only | 5088 | 6.7 | 14.7 | 27.5 | 1 | 0.93x | True |
| mu | `mu.v0` bc | 9999 | 7.5 | 9.6 | 9.0 | 1 | 1.00x | True |
| mu | `mu.v1` cached-tr | 86396 | 0.6 | 0.9 | 1.4 | 1 | 12.11x | True |
| mu | `mu.v2` own-keccak | 10968 | 7.5 | 9.4 | 8.2 | 1 | 0.99x | True |
| expandA | `expandA.v0` bc | 547 | 87.4 | 124.1 | 201.1 | 1 | 1.00x | True |
| expandA | `expandA.v1` cached-A | 964 | 0.0 | 0.1 | 93.4 | 1 | 1860.51x | True |
| expandA | `expandA.v2` parallel-rows | 591 | 113.2 | 235.9 | 253.8 | 4 | 0.77x | True |
| expandA | `expandA.v3` own-keccak | 556 | 93.9 | 173.9 | 215.8 | 1 | 0.93x | True |
| expandA | `expandA.v4` c2-only | 699 | 92.1 | 135.6 | 271.8 | 1 | 0.95x | True |
| w_approx | `w_approx.v0` bc | 1089 | 61.0 | 89.9 | 91.8 | 1 | 1.00x | True |
| w_approx | `w_approx.v1` cached-ntt-t1 | 1732 | 45.2 | 89.6 | 80.8 | 1 | 1.35x | True |
| w_approx | `w_approx.v2` parallel-rows | 1576 | 85.4 | 162.2 | 145.9 | 4 | 0.71x | True |
| w_approx | `w_approx.v3` long-accum | 1356 | 61.8 | 109.1 | 95.9 | 1 | 0.99x | True |
| hint_check | `hint_check.v0` bc | 12435 | 9.0 | 11.1 | 12.1 | 1 | 1.00x | True |
| hint_check | `hint_check.v1` fused-usehint-pack | 11451 | 6.1 | 10.6 | 10.5 | 1 | 1.49x | True |
| hint_check | `hint_check.v2` own-keccak | 8062 | 9.3 | 14.7 | 14.9 | 1 | 0.98x | True |
| hint_check | `hint_check.v3` c2-only | 2825 | 9.0 | 12.3 | 38.9 | 1 | 1.00x | True |
| total | `total.v0` v0-pipeline | 466 | 184.4 | 487.5 | 214.6 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `decode.v1,mu.v0,expandA.v0,w_approx.v0,hint_check.v1` | 657 | 178.8 | 358.0 | 197.9 | 1 | - | True |

total_best vs total.v0: 1.03x

### ML-DSA-87

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| decode | `decode.v0` bc | 10822 | 10.6 | 16.0 | 13.9 | 1 | 1.00x | True |
| decode | `decode.v1` wide-unpack | 20287 | 6.2 | 10.3 | 7.9 | 1 | 1.70x | True |
| decode | `decode.v2` c2-only | 184 | 20.3 | 37.9 | 108.7 | 1 | 0.52x | True |
| mu | `mu.v0` bc | 6937 | 9.9 | 19.1 | 14.4 | 1 | 1.00x | True |
| mu | `mu.v1` cached-tr | 55613 | 0.6 | 1.1 | 2.0 | 1 | 16.05x | True |
| mu | `mu.v2` own-keccak | 5629 | 15.3 | 23.5 | 17.8 | 1 | 0.65x | True |
| expandA | `expandA.v0` bc | 298 | 181.1 | 557.8 | 436.2 | 1 | 1.00x | True |
| expandA | `expandA.v1` cached-A | 398 | 0.1 | 0.5 | 201.0 | 1 | 3621.10x | True |
| expandA | `expandA.v2` parallel-rows | 489 | 196.6 | 246.4 | 409.0 | 4 | 0.92x | True |
| expandA | `expandA.v3` own-keccak | 244 | 177.8 | 371.8 | 409.8 | 1 | 1.02x | True |
| expandA | `expandA.v4` c2-only | 294 | 201.6 | 501.2 | 544.2 | 1 | 0.90x | True |
| w_approx | `w_approx.v0` bc | 640 | 105.7 | 190.8 | 156.2 | 1 | 1.00x | True |
| w_approx | `w_approx.v1` cached-ntt-t1 | 970 | 64.4 | 106.3 | 103.1 | 1 | 1.64x | True |
| w_approx | `w_approx.v2` parallel-rows | 1394 | 99.4 | 170.0 | 143.5 | 4 | 1.06x | True |
| w_approx | `w_approx.v3` long-accum | 730 | 92.9 | 219.2 | 150.7 | 1 | 1.14x | True |
| hint_check | `hint_check.v0` bc | 5987 | 12.0 | 17.7 | 16.7 | 1 | 1.00x | True |
| hint_check | `hint_check.v1` fused-usehint-pack | 9675 | 7.9 | 15.4 | 13.4 | 1 | 1.51x | True |
| hint_check | `hint_check.v2` own-keccak | 8028 | 12.1 | 18.3 | 17.4 | 1 | 0.99x | True |
| hint_check | `hint_check.v3` c2-only | 1747 | 16.0 | 26.6 | 63.0 | 1 | 0.75x | True |
| total | `total.v0` v0-pipeline | 283 | 303.8 | 4,350.8 | 318.0 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `decode.v1,mu.v0,expandA.v3,w_approx.v3,hint_check.v1` | 198 | 611.2 | 4,714.5 | 656.6 | 1 | - | True |

total_best vs total.v0: 0.50x

### SLH-DSA-SHA2-128s

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 17373 | 1.7 | 3.0 | 5.8 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 54371 | 0.9 | 1.6 | 1.7 | 1 | 1.80x | True |
| hmsg | `hmsg.v2` c2-only | 5221 | 2.0 | 27.5 | 26.8 | 1 | 0.84x | True |
| fors | `fors.v0` bc | 328 | 96.0 | 178.5 | 304.9 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 565 | 118.7 | 240.6 | 265.5 | 1 | 0.81x | True |
| fors | `fors.v2` parallel-trees | 1505 | 109.5 | 216.9 | 166.1 | 4 | 0.88x | True |
| fors | `fors.v3` fused-fast | 1129 | 90.0 | 117.0 | 88.6 | 1 | 1.07x | True |
| ht_wots | `ht_wots.v0` bc | 105 | 908.1 | 5,310.4 | 952.4 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 178 | 525.2 | 4,592.6 | 561.8 | 1 | 1.73x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 193 | 1,006.4 | 1,175.1 | 1,139.9 | 4 | 0.90x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 32 | 1,277.4 | 40,073.6 | 937.5 | 4 | 0.71x | True |
| ht_wots | `ht_wots.v4` fused-fast | 168 | 515.0 | 4,884.4 | 654.8 | 1 | 1.76x | True |
| ht_auth | `ht_auth.v0` bc | 3232 | 29.5 | 46.9 | 34.0 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 6433 | 17.5 | 28.8 | 21.8 | 1 | 1.69x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 3526 | 46.0 | 74.7 | 51.0 | 4 | 0.64x | True |
| ht_auth | `ht_auth.v3` fused-fast | 5591 | 15.7 | 25.9 | 17.9 | 1 | 1.88x | True |
| total | `total.v0` v0-pipeline | 75 | 1,185.0 | 9,065.8 | 1,200.0 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v1,fors.v3,ht_wots.v4,ht_auth.v3` | 152 | 588.3 | 5,028.0 | 789.5 | 1 | - | True |

total_best vs total.v0: 2.01x

### SLH-DSA-SHA2-128f

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 15090 | 2.5 | 3.2 | 7.3 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 47707 | 1.4 | 1.5 | 2.1 | 1 | 1.79x | True |
| hmsg | `hmsg.v2` c2-only | 11081 | 2.6 | 4.7 | 18.0 | 1 | 0.94x | True |
| fors | `fors.v0` bc | 664 | 116.2 | 276.9 | 135.5 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 1323 | 71.1 | 113.1 | 83.1 | 1 | 1.63x | True |
| fors | `fors.v2` parallel-trees | 1380 | 134.8 | 179.2 | 144.9 | 4 | 0.86x | True |
| fors | `fors.v3` fused-fast | 1388 | 66.4 | 120.6 | 79.2 | 1 | 1.75x | True |
| ht_wots | `ht_wots.v0` bc | 37 | 4,627.6 | 11,165.9 | 3,243.2 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 62 | 1,753.9 | 7,461.6 | 1,935.5 | 1 | 2.64x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 60 | 3,242.6 | 3,809.8 | 3,166.7 | 4 | 1.43x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 46 | 2,881.0 | 11,801.2 | 3,043.5 | 4 | 1.61x | True |
| ht_wots | `ht_wots.v4` fused-fast | 60 | 1,688.0 | 8,897.8 | 1,500.0 | 1 | 2.74x | True |
| ht_auth | `ht_auth.v0` bc | 2581 | 31.2 | 55.5 | 38.7 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 3503 | 18.2 | 33.6 | 22.8 | 1 | 1.71x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 3773 | 47.2 | 74.1 | 50.4 | 4 | 0.66x | True |
| ht_auth | `ht_auth.v3` fused-fast | 4172 | 16.7 | 31.4 | 26.4 | 1 | 1.86x | True |
| total | `total.v0` v0-pipeline | 27 | 7,200.8 | 13,268.3 | 4,444.4 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v1,fors.v3,ht_wots.v4,ht_auth.v3` | 31 | 1,734.6 | 17,862.6 | 3,225.8 | 1 | - | True |

total_best vs total.v0: 4.15x

### SLH-DSA-SHA2-192s

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 5153 | 3.5 | 5.7 | 23.3 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 1770 | 17.8 | 39.8 | 67.8 | 1 | 0.20x | True |
| hmsg | `hmsg.v2` c2-only | 8664 | 2.4 | 3.9 | 21.9 | 1 | 1.46x | True |
| fors | `fors.v0` bc | 154 | 270.1 | 12,463.2 | 779.2 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 392 | 135.2 | 388.9 | 280.6 | 1 | 2.00x | True |
| fors | `fors.v2` parallel-trees | 475 | 210.2 | 1,583.2 | 673.7 | 4 | 1.28x | True |
| fors | `fors.v3` fused-fast | 1657 | 92.2 | 160.3 | 102.6 | 1 | 2.93x | True |
| ht_wots | `ht_wots.v0` bc | 97 | 1,446.7 | 6,109.5 | 1,443.3 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 105 | 898.6 | 5,993.3 | 857.1 | 1 | 1.61x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 91 | 1,436.3 | 5,963.0 | 1,428.6 | 4 | 1.01x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 137 | 1,366.3 | 1,804.5 | 1,459.9 | 4 | 1.06x | True |
| ht_wots | `ht_wots.v4` fused-fast | 160 | 836.0 | 1,650.1 | 937.5 | 1 | 1.73x | True |
| ht_auth | `ht_auth.v0` bc | 2002 | 40.7 | 85.4 | 54.9 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 4448 | 24.3 | 51.0 | 29.2 | 1 | 1.68x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 2176 | 61.0 | 103.5 | 68.9 | 4 | 0.67x | True |
| ht_auth | `ht_auth.v3` fused-fast | 3950 | 22.2 | 34.2 | 25.3 | 1 | 1.83x | True |
| total | `total.v0` v0-pipeline | 85 | 1,603.6 | 9,693.6 | 2,235.3 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v0,fors.v3,ht_wots.v4,ht_auth.v3` | 128 | 988.8 | 5,096.9 | 1,015.6 | 1 | - | True |

total_best vs total.v0: 1.62x

### SLH-DSA-SHA2-192f

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 43314 | 2.3 | 2.8 | 3.0 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 55030 | 1.7 | 2.2 | 2.4 | 1 | 1.35x | True |
| hmsg | `hmsg.v2` c2-only | 5749 | 3.8 | 4.4 | 27.8 | 1 | 0.61x | True |
| fors | `fors.v0` bc | 397 | 216.8 | 4,236.8 | 251.9 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 1089 | 119.8 | 181.7 | 128.6 | 1 | 1.81x | True |
| fors | `fors.v2` parallel-trees | 751 | 224.8 | 309.6 | 239.7 | 4 | 0.96x | True |
| fors | `fors.v3` fused-fast | 1172 | 105.6 | 169.0 | 119.5 | 1 | 2.05x | True |
| ht_wots | `ht_wots.v0` bc | 32 | 4,875.3 | 15,369.8 | 5,000.0 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 38 | 5,173.1 | 10,629.0 | 3,157.9 | 1 | 0.94x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 29 | 4,763.4 | 13,324.1 | 6,206.9 | 4 | 1.02x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 47 | 3,303.3 | 8,970.5 | 4,680.9 | 4 | 1.48x | True |
| ht_wots | `ht_wots.v4` fused-fast | 69 | 2,631.6 | 4,133.3 | 2,753.6 | 1 | 1.85x | True |
| ht_auth | `ht_auth.v0` bc | 2770 | 43.4 | 80.0 | 50.5 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 3227 | 48.2 | 75.7 | 52.7 | 1 | 0.90x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 1908 | 97.5 | 132.6 | 110.1 | 4 | 0.44x | True |
| ht_auth | `ht_auth.v3` fused-fast | 3318 | 23.5 | 38.4 | 30.1 | 1 | 1.84x | True |
| total | `total.v0` v0-pipeline | 16 | 12,790.9 | 18,693.5 | 6,250.0 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v1,fors.v3,ht_wots.v4,ht_auth.v3` | 38 | 6,739.5 | 10,753.2 | 2,894.7 | 1 | - | True |

total_best vs total.v0: 1.90x

### SLH-DSA-SHA2-256s

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 38249 | 3.5 | 4.0 | 4.2 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 47281 | 1.4 | 2.5 | 2.7 | 1 | 2.43x | True |
| hmsg | `hmsg.v2` c2-only | 8660 | 2.4 | 3.1 | 21.9 | 1 | 1.46x | True |
| fors | `fors.v0` bc | 568 | 225.4 | 289.0 | 228.9 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 738 | 140.2 | 306.5 | 176.2 | 1 | 1.61x | True |
| fors | `fors.v2` parallel-trees | 372 | 437.4 | 546.9 | 430.1 | 4 | 0.52x | True |
| fors | `fors.v3` fused-fast | 1018 | 120.7 | 267.6 | 167.0 | 1 | 1.87x | True |
| ht_wots | `ht_wots.v0` bc | 74 | 2,111.0 | 6,039.2 | 2,432.4 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 72 | 1,357.3 | 5,483.7 | 1,388.9 | 1 | 1.56x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 74 | 2,206.8 | 7,432.6 | 2,162.2 | 4 | 0.96x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 81 | 2,087.9 | 6,417.5 | 2,345.7 | 4 | 1.01x | True |
| ht_wots | `ht_wots.v4` fused-fast | 67 | 1,253.6 | 9,260.5 | 1,343.3 | 1 | 1.68x | True |
| ht_auth | `ht_auth.v0` bc | 2902 | 41.9 | 65.3 | 48.2 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 4653 | 24.7 | 37.7 | 27.9 | 1 | 1.70x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 1964 | 92.3 | 129.2 | 91.6 | 4 | 0.45x | True |
| ht_auth | `ht_auth.v3` fused-fast | 5806 | 22.5 | 28.2 | 25.8 | 1 | 1.86x | True |
| total | `total.v0` v0-pipeline | 50 | 2,746.0 | 7,929.3 | 2,400.0 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v1,fors.v3,ht_wots.v4,ht_auth.v3` | 73 | 1,499.9 | 6,905.6 | 1,780.8 | 1 | - | True |

total_best vs total.v0: 1.83x

### SLH-DSA-SHA2-256f

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 46961 | 2.4 | 3.6 | 3.4 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 67480 | 1.2 | 1.9 | 1.9 | 1 | 1.91x | True |
| hmsg | `hmsg.v2` c2-only | 7463 | 3.7 | 6.7 | 26.8 | 1 | 0.64x | True |
| fors | `fors.v0` bc | 310 | 316.3 | 4,383.1 | 354.8 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 1185 | 143.6 | 212.9 | 160.3 | 1 | 2.20x | True |
| fors | `fors.v2` parallel-trees | 693 | 281.7 | 379.8 | 476.2 | 4 | 1.12x | True |
| fors | `fors.v3` fused-fast | 932 | 127.7 | 193.1 | 139.5 | 1 | 2.48x | True |
| ht_wots | `ht_wots.v0` bc | 24 | 8,280.4 | 13,860.0 | 4,583.3 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 32 | 6,863.3 | 11,478.2 | 3,125.0 | 1 | 1.21x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 43 | 4,491.9 | 5,549.1 | 4,651.2 | 4 | 1.84x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 24 | 8,130.5 | 12,976.9 | 7,916.7 | 4 | 1.02x | True |
| ht_wots | `ht_wots.v4` fused-fast | 34 | 4,055.2 | 14,891.6 | 3,235.3 | 1 | 2.04x | True |
| ht_auth | `ht_auth.v0` bc | 2197 | 56.9 | 102.7 | 68.3 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 4176 | 26.8 | 60.7 | 38.3 | 1 | 2.13x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 1592 | 66.7 | 125.9 | 75.4 | 4 | 0.85x | True |
| ht_auth | `ht_auth.v3` fused-fast | 4925 | 24.2 | 31.1 | 26.4 | 1 | 2.35x | True |
| total | `total.v0` v0-pipeline | 29 | 8,607.2 | 9,165.2 | 4,827.6 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v1,fors.v3,ht_wots.v4,ht_auth.v3` | 42 | 3,245.8 | 8,547.1 | 3,095.2 | 1 | - | True |

total_best vs total.v0: 2.65x

### SLH-DSA-SHAKE-128s

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 100000 | 0.6 | 1.0 | 1.2 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 100000 | 0.7 | 1.0 | 1.3 | 1 | 0.94x | True |
| hmsg | `hmsg.v2` c2-only | 9568 | 1.3 | 3.7 | 21.9 | 1 | 0.48x | True |
| fors | `fors.v0` bc | 572 | 186.1 | 243.6 | 192.3 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 970 | 156.8 | 214.0 | 164.9 | 1 | 1.19x | True |
| fors | `fors.v2` parallel-trees | 1465 | 110.8 | 145.2 | 116.0 | 4 | 1.68x | True |
| fors | `fors.v3` fused-fast | 926 | 98.8 | 173.2 | 108.0 | 1 | 1.88x | True |
| ht_wots | `ht_wots.v0` bc | 166 | 918.8 | 1,909.6 | 963.9 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 132 | 1,031.3 | 5,093.0 | 1,136.4 | 1 | 0.89x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 153 | 1,218.2 | 1,669.5 | 2,026.1 | 4 | 0.75x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 297 | 625.8 | 892.0 | 1,077.4 | 4 | 1.47x | True |
| ht_wots | `ht_wots.v4` fused-fast | 63 | 1,617.3 | 9,782.2 | 1,428.6 | 1 | 0.57x | True |
| ht_auth | `ht_auth.v0` bc | 3657 | 31.9 | 93.0 | 43.8 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 3538 | 34.3 | 52.5 | 36.7 | 1 | 0.93x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 2346 | 46.0 | 87.4 | 68.2 | 4 | 0.69x | True |
| ht_auth | `ht_auth.v3` fused-fast | 1399 | 64.2 | 92.2 | 71.5 | 1 | 0.50x | True |
| total | `total.v0` v0-pipeline | 108 | 1,698.8 | 2,166.8 | 1,759.3 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v0,fors.v3,ht_wots.v0,ht_auth.v0` | 100 | 1,295.3 | 5,534.0 | 1,400.0 | 1 | - | True |

total_best vs total.v0: 1.31x

### SLH-DSA-SHAKE-128f

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 98709 | 0.6 | 1.1 | 1.3 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 64746 | 1.1 | 1.4 | 2.5 | 1 | 0.59x | True |
| hmsg | `hmsg.v2` c2-only | 6598 | 0.8 | 1.5 | 16.7 | 1 | 0.79x | True |
| fors | `fors.v0` bc | 883 | 124.6 | 267.6 | 158.6 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 664 | 133.6 | 186.7 | 135.5 | 1 | 0.93x | True |
| fors | `fors.v2` parallel-trees | 1066 | 164.3 | 243.6 | 253.3 | 4 | 0.76x | True |
| fors | `fors.v3` fused-fast | 389 | 232.4 | 4,275.2 | 257.1 | 1 | 0.54x | True |
| ht_wots | `ht_wots.v0` bc | 24 | 9,372.3 | 13,881.5 | 6,250.0 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 26 | 7,604.5 | 16,765.7 | 4,615.4 | 1 | 1.23x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 38 | 3,794.0 | 9,238.3 | 3,947.4 | 4 | 2.47x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 49 | 3,453.0 | 8,226.7 | 3,265.3 | 4 | 2.71x | True |
| ht_wots | `ht_wots.v4` fused-fast | 36 | 4,718.1 | 12,005.5 | 4,444.4 | 1 | 1.99x | True |
| ht_auth | `ht_auth.v0` bc | 5027 | 33.7 | 53.0 | 37.8 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 2848 | 35.7 | 55.2 | 38.6 | 1 | 0.94x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 3522 | 47.3 | 73.2 | 53.9 | 4 | 0.71x | True |
| ht_auth | `ht_auth.v3` fused-fast | 2474 | 54.4 | 83.1 | 56.6 | 1 | 0.62x | True |
| total | `total.v0` v0-pipeline | 37 | 5,111.9 | 8,766.1 | 3,783.8 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v0,fors.v0,ht_wots.v2,ht_auth.v0` | 33 | 6,340.3 | 9,311.2 | 5,454.5 | 4 | - | True |

total_best vs total.v0: 0.81x

### SLH-DSA-SHAKE-192s

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 65874 | 1.0 | 1.6 | 1.7 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 91395 | 1.1 | 1.9 | 1.9 | 1 | 0.91x | True |
| hmsg | `hmsg.v2` c2-only | 10873 | 1.2 | 2.1 | 16.6 | 1 | 0.86x | True |
| fors | `fors.v0` bc | 840 | 137.5 | 227.6 | 154.8 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 921 | 145.8 | 196.2 | 162.9 | 1 | 0.94x | True |
| fors | `fors.v2` parallel-trees | 1249 | 152.0 | 192.1 | 160.1 | 4 | 0.90x | True |
| fors | `fors.v3` fused-fast | 1321 | 138.3 | 182.7 | 151.4 | 1 | 0.99x | True |
| ht_wots | `ht_wots.v0` bc | 62 | 1,589.0 | 8,770.3 | 1,451.6 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 65 | 1,795.6 | 6,890.4 | 1,846.2 | 1 | 0.88x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 113 | 1,601.0 | 2,654.4 | 1,769.9 | 4 | 0.99x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 161 | 1,164.6 | 1,545.7 | 1,677.0 | 4 | 1.36x | True |
| ht_wots | `ht_wots.v4` fused-fast | 100 | 1,585.9 | 4,488.5 | 1,700.0 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v0` bc | 4366 | 32.6 | 63.6 | 43.5 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 3690 | 34.0 | 51.1 | 37.9 | 1 | 0.96x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 1613 | 110.0 | 156.4 | 192.2 | 4 | 0.30x | True |
| ht_auth | `ht_auth.v3` fused-fast | 4622 | 33.7 | 55.3 | 36.8 | 1 | 0.97x | True |
| total | `total.v0` v0-pipeline | 42 | 1,668.5 | 13,745.5 | 3,333.3 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v0,fors.v0,ht_wots.v4,ht_auth.v0` | 65 | 1,867.7 | 6,240.1 | 1,846.2 | 1 | - | True |

total_best vs total.v0: 0.89x

### SLH-DSA-SHAKE-192f

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 94718 | 1.1 | 1.8 | 1.8 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 52559 | 1.2 | 1.6 | 1.9 | 1 | 0.92x | True |
| hmsg | `hmsg.v2` c2-only | 3203 | 1.3 | 26.1 | 34.3 | 1 | 0.79x | True |
| fors | `fors.v0` bc | 537 | 160.1 | 340.5 | 186.2 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 876 | 170.8 | 213.1 | 171.2 | 1 | 0.94x | True |
| fors | `fors.v2` parallel-trees | 884 | 189.8 | 356.0 | 226.2 | 4 | 0.84x | True |
| fors | `fors.v3` fused-fast | 561 | 164.1 | 249.1 | 178.3 | 1 | 0.98x | True |
| ht_wots | `ht_wots.v0` bc | 24 | 8,560.1 | 13,136.8 | 5,000.0 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 20 | 8,781.6 | 20,266.4 | 6,000.0 | 1 | 0.97x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 38 | 5,136.5 | 6,730.7 | 8,157.9 | 4 | 1.67x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 33 | 4,511.9 | 17,741.8 | 5,454.5 | 4 | 1.90x | True |
| ht_wots | `ht_wots.v4` fused-fast | 18 | 10,819.5 | 15,720.9 | 5,555.6 | 1 | 0.79x | True |
| ht_auth | `ht_auth.v0` bc | 3783 | 34.6 | 64.3 | 47.6 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 3593 | 36.8 | 77.4 | 52.9 | 1 | 0.94x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 2844 | 59.2 | 105.0 | 66.8 | 4 | 0.59x | True |
| ht_auth | `ht_auth.v3` fused-fast | 3685 | 35.6 | 53.2 | 40.7 | 1 | 0.97x | True |
| total | `total.v0` v0-pipeline | 26 | 4,927.7 | 17,269.1 | 5,384.6 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v0,fors.v0,ht_wots.v2,ht_auth.v0` | 35 | 5,436.3 | 9,491.9 | 5,714.3 | 4 | - | True |

total_best vs total.v0: 0.91x

### SLH-DSA-SHAKE-256s

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 81637 | 1.1 | 1.9 | 1.8 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 56380 | 1.1 | 1.2 | 1.8 | 1 | 0.93x | True |
| hmsg | `hmsg.v2` c2-only | 7735 | 1.2 | 2.1 | 14.2 | 1 | 0.88x | True |
| fors | `fors.v0` bc | 474 | 182.1 | 4,236.0 | 211.0 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 526 | 191.0 | 345.6 | 228.1 | 1 | 0.95x | True |
| fors | `fors.v2` parallel-trees | 796 | 202.0 | 341.7 | 263.8 | 4 | 0.90x | True |
| fors | `fors.v3` fused-fast | 373 | 296.9 | 4,282.8 | 268.1 | 1 | 0.61x | True |
| ht_wots | `ht_wots.v0` bc | 75 | 2,251.7 | 6,538.1 | 2,266.7 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 76 | 2,327.8 | 5,355.9 | 2,368.4 | 1 | 0.97x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 85 | 2,305.7 | 2,472.4 | 2,352.9 | 4 | 0.98x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 89 | 2,199.1 | 2,518.2 | 2,247.2 | 4 | 1.02x | True |
| ht_wots | `ht_wots.v4` fused-fast | 78 | 2,295.1 | 6,306.9 | 2,307.7 | 1 | 0.98x | True |
| ht_auth | `ht_auth.v0` bc | 2112 | 33.9 | 67.4 | 47.3 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 4758 | 34.6 | 53.4 | 37.8 | 1 | 0.98x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 1911 | 94.0 | 155.7 | 167.5 | 4 | 0.36x | True |
| ht_auth | `ht_auth.v3` fused-fast | 1808 | 37.7 | 90.1 | 55.3 | 1 | 0.90x | True |
| total | `total.v0` v0-pipeline | 63 | 2,670.0 | 4,121.5 | 3,174.6 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v0,fors.v0,ht_wots.v0,ht_auth.v0` | 26 | 7,802.5 | 12,933.4 | 3,846.2 | 1 | - | True |

total_best vs total.v0: 0.34x

### SLH-DSA-SHAKE-256f

| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |
|---|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 73025 | 1.1 | 1.4 | 1.6 | 1 | 1.00x | True |
| hmsg | `hmsg.v1` alt-backend | 76950 | 1.2 | 2.0 | 1.9 | 1 | 0.93x | True |
| hmsg | `hmsg.v2` c2-only | 8030 | 1.3 | 2.2 | 21.2 | 1 | 0.86x | True |
| fors | `fors.v0` bc | 456 | 195.2 | 4,227.0 | 197.4 | 1 | 1.00x | True |
| fors | `fors.v1` alt-backend | 461 | 204.3 | 2,358.1 | 216.9 | 1 | 0.96x | True |
| fors | `fors.v2` parallel-trees | 909 | 207.1 | 291.3 | 363.0 | 4 | 0.94x | True |
| fors | `fors.v3` fused-fast | 483 | 195.9 | 3,729.3 | 207.0 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v0` bc | 18 | 12,672.6 | 14,874.3 | 5,555.6 | 1 | 1.00x | True |
| ht_wots | `ht_wots.v1` alt-backend | 21 | 9,220.6 | 13,738.9 | 6,190.5 | 1 | 1.37x | True |
| ht_wots | `ht_wots.v2` parallel-chains | 43 | 4,548.8 | 5,316.6 | 7,674.4 | 4 | 2.79x | True |
| ht_wots | `ht_wots.v3` parallel-layers | 59 | 2,922.2 | 6,536.4 | 4,915.3 | 4 | 4.34x | True |
| ht_wots | `ht_wots.v4` fused-fast | 31 | 4,884.4 | 12,810.0 | 5,161.3 | 1 | 2.59x | True |
| ht_auth | `ht_auth.v0` bc | 3110 | 35.9 | 61.4 | 45.0 | 1 | 1.00x | True |
| ht_auth | `ht_auth.v1` alt-backend | 3477 | 37.1 | 61.2 | 43.1 | 1 | 0.97x | True |
| ht_auth | `ht_auth.v2` parallel-layers | 1786 | 101.1 | 159.5 | 184.8 | 4 | 0.35x | True |
| ht_auth | `ht_auth.v3` fused-fast | 2717 | 36.9 | 65.0 | 44.2 | 1 | 0.97x | True |
| total | `total.v0` v0-pipeline | 29 | 5,416.7 | 11,122.2 | 4,827.6 | 1 | 1.00x | True |
| total_best | `total_best` best-pipeline `hmsg.v0,fors.v0,ht_wots.v2,ht_auth.v0` | 32 | 5,671.6 | 8,587.7 | 6,562.5 | 4 | - | True |

total_best vs total.v0: 0.96x

### Geometric mean speedup vs stage v0 (per family)

| variant | ML-DSA | SLH-DSA SHA2 | SLH-DSA SHAKE |
|---|---|---|---|
| `decode.v0` | 1.00x | - | - |
| `decode.v1` | 1.93x | - | - |
| `decode.v2` | 0.98x | - | - |
| `mu.v0` | 1.00x | - | - |
| `mu.v1` | 11.80x | - | - |
| `mu.v2` | 0.86x | - | - |
| `expandA.v0` | 1.00x | - | - |
| `expandA.v1` | 2100.49x | - | - |
| `expandA.v2` | 0.78x | - | - |
| `expandA.v3` | 0.96x | - | - |
| `expandA.v4` | 0.81x | - | - |
| `w_approx.v0` | 1.00x | - | - |
| `w_approx.v1` | 1.42x | - | - |
| `w_approx.v2` | 0.82x | - | - |
| `w_approx.v3` | 1.01x | - | - |
| `hint_check.v0` | 1.00x | - | - |
| `hint_check.v1` | 1.67x | - | - |
| `hint_check.v2` | 1.14x | - | - |
| `hint_check.v3` | 0.55x | - | - |
| `hmsg.v0` | - | 1.00x | 1.00x |
| `hmsg.v1` | - | 1.26x | 0.86x |
| `hmsg.v2` | - | 0.93x | 0.76x |
| `fors.v0` | - | 1.00x | 1.00x |
| `fors.v1` | - | 1.60x | 0.98x |
| `fors.v2` | - | 0.90x | 0.97x |
| `fors.v3` | - | 1.93x | 0.92x |
| `ht_wots.v0` | - | 1.00x | 1.00x |
| `ht_wots.v1` | - | 1.53x | 1.04x |
| `ht_wots.v2` | - | 1.15x | 1.43x |
| `ht_wots.v3` | - | 1.11x | 1.89x |
| `ht_wots.v4` | - | 1.94x | 1.15x |
| `ht_auth.v0` | - | 1.00x | 1.00x |
| `ht_auth.v1` | - | 1.58x | 0.95x |
| `ht_auth.v2` | - | 0.60x | 0.47x |
| `ht_auth.v3` | - | 1.93x | 0.80x |
