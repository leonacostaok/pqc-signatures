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

## Results

Generated by `common/report-phase2.mjs` from `results/bouncycastle/stages.jsonl`. Speedup = throughput vs the stage's v0. "coverage" = sum of v0 stage medians / end-to-end v0 total.

### ML-DSA-44

end-to-end v0 stages: 112.1 µs, best assembled: 119.4 µs (0.94×), coverage 94%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` bc | 5.1 µs | 9.2 µs | 1 | 4.5% | 1.00× | ✓ |
| decode | `decode.v1` wide-unpack | 3.2 µs | 4.2 µs | 1 |  | 1.67× | ✓ |
| decode | `decode.v2` c2-only | 4.4 µs | 16.4 µs | 1 |  | 0.50× | ✓ |
| mu | `mu.v0` bc | 5.3 µs | 7.5 µs | 1 | 4.7% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.8 µs | 1.9 µs | 1 |  | 3.69× | ✓ |
| mu | `mu.v2` own-keccak | 5.3 µs | 6.9 µs | 1 |  | 1.01× | ✓ |
| expandA | `expandA.v0` bc | 46.7 µs | 107.4 µs | 1 | 41.6% | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.0 µs | 63.9 µs | 1 |  | 1.60× | ✓ |
| expandA | `expandA.v2` parallel-rows | 118.8 µs | 278.2 µs | 4 |  | 0.52× | ✓ |
| expandA | `expandA.v3` own-keccak | 49.6 µs | 108.3 µs | 1 |  | 0.96× | ✓ |
| expandA | `expandA.v4` c2-only | 47.6 µs | 150.6 µs | 1 |  | 0.80× | ✓ |
| w_approx | `w_approx.v0` bc | 40.5 µs | 71.5 µs | 1 | 36.1% | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 31.4 µs | 56.3 µs | 1 |  | 1.25× | ✓ |
| w_approx | `w_approx.v2` parallel-rows | 108.2 µs | 190.6 µs | 4 |  | 0.54× | ✓ |
| w_approx | `w_approx.v3` long-accum | 42.6 µs | 62.7 µs | 1 |  | 1.12× | ✓ |
| hint_check | `hint_check.v0` bc | 7.8 µs | 12.3 µs | 1 | 7.0% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fused-usehint-pack | 6.1 µs | 9.8 µs | 1 |  | 1.22× | ✓ |
| hint_check | `hint_check.v2` own-keccak | 7.7 µs | 12.0 µs | 1 |  | 1.02× | ✓ |
| hint_check | `hint_check.v3` c2-only | 7.7 µs | 15.1 µs | 1 |  | 0.96× | ✓ |

### ML-DSA-65

end-to-end v0 stages: 178.8 µs, best assembled: 174.5 µs (1.03×), coverage 94%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` bc | 6.5 µs | 8.3 µs | 1 | 3.7% | 1.00× | ✓ |
| decode | `decode.v1` wide-unpack | 4.7 µs | 5.8 µs | 1 |  | 1.43× | ✓ |
| decode | `decode.v2` c2-only | 7.4 µs | 24.6 µs | 1 |  | 0.41× | ✓ |
| mu | `mu.v0` bc | 7.5 µs | 9.9 µs | 1 | 4.2% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.6 µs | 1.4 µs | 1 |  | 7.21× | ✓ |
| mu | `mu.v2` own-keccak | 7.5 µs | 10.0 µs | 1 |  | 0.99× | ✓ |
| expandA | `expandA.v0` bc | 86.2 µs | 192.6 µs | 1 | 48.2% | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.0 µs | 100.3 µs | 1 |  | 1.92× | ✓ |
| expandA | `expandA.v2` parallel-rows | 193.0 µs | 464.9 µs | 4 |  | 0.51× | ✓ |
| expandA | `expandA.v3` own-keccak | 94.0 µs | 213.6 µs | 1 |  | 0.89× | ✓ |
| expandA | `expandA.v4` c2-only | 90.7 µs | 254.5 µs | 1 |  | 0.79× | ✓ |
| w_approx | `w_approx.v0` bc | 59.5 µs | 106.4 µs | 1 | 33.2% | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 43.6 µs | 75.6 µs | 1 |  | 1.41× | ✓ |
| w_approx | `w_approx.v2` parallel-rows | 132.7 µs | 230.5 µs | 4 |  | 0.60× | ✓ |
| w_approx | `w_approx.v3` long-accum | 61.4 µs | 92.2 µs | 1 |  | 1.13× | ✓ |
| hint_check | `hint_check.v0` bc | 8.7 µs | 12.1 µs | 1 | 4.9% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fused-usehint-pack | 6.1 µs | 10.3 µs | 1 |  | 1.15× | ✓ |
| hint_check | `hint_check.v2` own-keccak | 8.9 µs | 12.8 µs | 1 |  | 0.94× | ✓ |
| hint_check | `hint_check.v3` c2-only | 11.4 µs | 21.3 µs | 1 |  | 0.67× | ✓ |

### ML-DSA-87

end-to-end v0 stages: 294.7 µs, best assembled: 283.4 µs (1.04×), coverage 94%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` bc | 8.4 µs | 10.5 µs | 1 | 2.8% | 1.00× | ✓ |
| decode | `decode.v1` wide-unpack | 6.3 µs | 8.3 µs | 1 |  | 1.27× | ✓ |
| decode | `decode.v2` c2-only | 8.9 µs | 43.2 µs | 1 |  | 0.28× | ✓ |
| mu | `mu.v0` bc | 9.7 µs | 12.2 µs | 1 | 3.3% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.6 µs | 1.5 µs | 1 |  | 8.48× | ✓ |
| mu | `mu.v2` own-keccak | 9.8 µs | 11.4 µs | 1 |  | 1.10× | ✓ |
| expandA | `expandA.v0` bc | 164.6 µs | 371.3 µs | 1 | 55.8% | 1.00× | ✓ |
| expandA | `expandA.v1` cached-A | 0.1 µs | 185.6 µs | 1 |  | 2.02× | ✓ |
| expandA | `expandA.v2` parallel-rows | 244.9 µs | 661.8 µs | 4 |  | 0.72× | ✓ |
| expandA | `expandA.v3` own-keccak | 174.5 µs | 370.0 µs | 1 |  | 1.01× | ✓ |
| expandA | `expandA.v4` c2-only | 165.5 µs | 415.2 µs | 1 |  | 0.94× | ✓ |
| w_approx | `w_approx.v0` bc | 81.9 µs | 120.5 µs | 1 | 27.8% | 1.00× | ✓ |
| w_approx | `w_approx.v1` cached-ntt-t1 | 63.0 µs | 96.5 µs | 1 |  | 1.22× | ✓ |
| w_approx | `w_approx.v2` parallel-rows | 145.3 µs | 262.7 µs | 4 |  | 0.63× | ✓ |
| w_approx | `w_approx.v3` long-accum | 87.2 µs | 123.3 µs | 1 |  | 0.98× | ✓ |
| hint_check | `hint_check.v0` bc | 11.5 µs | 15.8 µs | 1 | 3.9% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fused-usehint-pack | 8.0 µs | 13.0 µs | 1 |  | 1.23× | ✓ |
| hint_check | `hint_check.v2` own-keccak | 11.7 µs | 16.7 µs | 1 |  | 0.94× | ✓ |
| hint_check | `hint_check.v3` c2-only | 11.7 µs | 23.5 µs | 1 |  | 0.80× | ✓ |

### SLH-DSA-SHA2-128s

end-to-end v0 stages: 956.1 µs, best assembled: 570.1 µs (1.68×), coverage 102%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 1.7 µs | 2.8 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.0 µs | 1.6 µs | 1 |  | 1.60× | ✓ |
| hmsg | `hmsg.v2` c2-only | 1.7 µs | 5.0 µs | 1 |  | 0.77× | ✓ |
| fors | `fors.v0` bc | 85.4 µs | 91.4 µs | 1 | 8.9% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 53.7 µs | 71.6 µs | 1 |  | 1.37× | ✓ |
| fors | `fors.v2` parallel-trees | 121.1 µs | 223.2 µs | 4 |  | 0.69× | ✓ |
| fors | `fors.v3` fused-fast | 46.3 µs | 56.8 µs | 1 |  | 1.61× | ✓ |
| ht_wots | `ht_wots.v0` bc | 861.5 µs | 971.5 µs | 1 | 90.1% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 523.7 µs | 578.4 µs | 1 |  | 1.70× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 932.1 µs | 1.70 ms | 4 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 493.0 µs | 1.23 ms | 4 |  | 1.91× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 488.6 µs | 536.6 µs | 1 |  | 1.81× | ✓ |
| ht_auth | `ht_auth.v0` bc | 28.3 µs | 36.8 µs | 1 | 3.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 17.7 µs | 20.4 µs | 1 |  | 1.81× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 89.5 µs | 151.9 µs | 4 |  | 0.38× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 15.8 µs | 18.5 µs | 1 |  | 1.99× | ✓ |

### SLH-DSA-SHA2-128f

end-to-end v0 stages: 2.82 ms, best assembled: 1.68 ms (1.68×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 2.5 µs | 4.3 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.4 µs | 2.0 µs | 1 |  | 1.61× | ✓ |
| hmsg | `hmsg.v2` c2-only | 2.5 µs | 6.5 µs | 1 |  | 0.71× | ✓ |
| fors | `fors.v0` bc | 113.7 µs | 129.3 µs | 1 | 4.0% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 70.7 µs | 81.4 µs | 1 |  | 1.62× | ✓ |
| fors | `fors.v2` parallel-trees | 141.0 µs | 261.0 µs | 4 |  | 0.86× | ✓ |
| fors | `fors.v3` fused-fast | 60.0 µs | 72.7 µs | 1 |  | 1.83× | ✓ |
| ht_wots | `ht_wots.v0` bc | 2.65 ms | 2.76 ms | 1 | 94.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 1.66 ms | 1.74 ms | 1 |  | 1.59× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 3.07 ms | 5.48 ms | 4 |  | 0.86× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 1.42 ms | 3.85 ms | 4 |  | 1.90× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 1.57 ms | 1.79 ms | 1 |  | 1.45× | ✓ |
| ht_auth | `ht_auth.v0` bc | 31.8 µs | 40.5 µs | 1 | 1.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 17.8 µs | 23.6 µs | 1 |  | 1.71× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 99.8 µs | 170.4 µs | 4 |  | 0.37× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 16.8 µs | 20.3 µs | 1 |  | 2.01× | ✓ |

### SLH-DSA-SHA2-192s

end-to-end v0 stages: 1.49 ms, best assembled: 935.4 µs (1.59×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 2.4 µs | 3.2 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.3 µs | 1.9 µs | 1 |  | 1.60× | ✓ |
| hmsg | `hmsg.v2` c2-only | 2.5 µs | 6.0 µs | 1 |  | 0.68× | ✓ |
| fors | `fors.v0` bc | 188.5 µs | 197.7 µs | 1 | 12.7% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 96.8 µs | 114.9 µs | 1 |  | 1.72× | ✓ |
| fors | `fors.v2` parallel-trees | 175.6 µs | 348.2 µs | 4 |  | 1.08× | ✓ |
| fors | `fors.v3` fused-fast | 86.8 µs | 103.3 µs | 1 |  | 1.90× | ✓ |
| ht_wots | `ht_wots.v0` bc | 1.23 ms | 1.31 ms | 1 | 82.9% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 811.0 µs | 880.5 µs | 1 |  | 1.46× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 1.27 ms | 2.39 ms | 4 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 643.7 µs | 1.62 ms | 4 |  | 1.96× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 808.5 µs | 861.6 µs | 1 |  | 1.51× | ✓ |
| ht_auth | `ht_auth.v0` bc | 45.0 µs | 49.4 µs | 1 | 3.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 22.0 µs | 25.7 µs | 1 |  | 1.92× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 99.8 µs | 171.1 µs | 4 |  | 0.45× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 21.2 µs | 24.2 µs | 1 |  | 2.04× | ✓ |

### SLH-DSA-SHA2-192f

end-to-end v0 stages: 4.30 ms, best assembled: 2.81 ms (1.53×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 2.4 µs | 3.5 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.3 µs | 2.1 µs | 1 |  | 1.65× | ✓ |
| hmsg | `hmsg.v2` c2-only | 2.2 µs | 5.9 µs | 1 |  | 0.81× | ✓ |
| fors | `fors.v0` bc | 218.1 µs | 226.1 µs | 1 | 5.1% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 115.9 µs | 139.7 µs | 1 |  | 1.60× | ✓ |
| fors | `fors.v2` parallel-trees | 206.8 µs | 420.1 µs | 4 |  | 1.03× | ✓ |
| fors | `fors.v3` fused-fast | 101.6 µs | 113.0 µs | 1 |  | 1.98× | ✓ |
| ht_wots | `ht_wots.v0` bc | 4.05 ms | 4.56 ms | 1 | 94.1% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 2.57 ms | 2.83 ms | 1 |  | 1.63× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 4.28 ms | 7.84 ms | 4 |  | 1.05× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 2.00 ms | 5.90 ms | 4 |  | 2.18× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 2.62 ms | 2.86 ms | 1 |  | 1.59× | ✓ |
| ht_auth | `ht_auth.v0` bc | 47.7 µs | 55.4 µs | 1 | 1.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 23.4 µs | 33.0 µs | 1 |  | 1.68× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 116.3 µs | 206.5 µs | 4 |  | 0.43× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 22.6 µs | 27.0 µs | 1 |  | 2.05× | ✓ |

### SLH-DSA-SHA2-256s

end-to-end v0 stages: 2.27 ms, best assembled: 1.40 ms (1.62×), coverage 96%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 2.4 µs | 3.3 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.3 µs | 2.4 µs | 1 |  | 1.40× | ✓ |
| hmsg | `hmsg.v2` c2-only | 2.3 µs | 6.3 µs | 1 |  | 0.71× | ✓ |
| fors | `fors.v0` bc | 246.0 µs | 259.9 µs | 1 | 10.8% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 125.9 µs | 145.6 µs | 1 |  | 1.79× | ✓ |
| fors | `fors.v2` parallel-trees | 215.7 µs | 468.9 µs | 4 |  | 1.14× | ✓ |
| fors | `fors.v3` fused-fast | 116.8 µs | 148.8 µs | 1 |  | 1.73× | ✓ |
| ht_wots | `ht_wots.v0` bc | 1.88 ms | 2.02 ms | 1 | 82.7% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 1.25 ms | 1.30 ms | 1 |  | 1.55× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 1.56 ms | 3.13 ms | 4 |  | 1.24× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 1.05 ms | 2.68 ms | 4 |  | 1.93× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 1.24 ms | 1.33 ms | 1 |  | 1.50× | ✓ |
| ht_auth | `ht_auth.v0` bc | 46.3 µs | 53.6 µs | 1 | 2.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 22.6 µs | 33.2 µs | 1 |  | 1.61× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 104.8 µs | 188.3 µs | 4 |  | 0.46× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 21.6 µs | 25.7 µs | 1 |  | 2.06× | ✓ |

### SLH-DSA-SHA2-256f

end-to-end v0 stages: 4.38 ms, best assembled: 2.76 ms (1.59×), coverage 97%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 2.4 µs | 3.3 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.3 µs | 1.9 µs | 1 |  | 1.71× | ✓ |
| hmsg | `hmsg.v2` c2-only | 2.3 µs | 5.7 µs | 1 |  | 0.80× | ✓ |
| fors | `fors.v0` bc | 268.0 µs | 303.6 µs | 1 | 6.1% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 138.7 µs | 163.0 µs | 1 |  | 1.84× | ✓ |
| fors | `fors.v2` parallel-trees | 209.6 µs | 443.5 µs | 4 |  | 1.39× | ✓ |
| fors | `fors.v3` fused-fast | 121.9 µs | 144.1 µs | 1 |  | 2.09× | ✓ |
| ht_wots | `ht_wots.v0` bc | 3.94 ms | 4.20 ms | 1 | 90.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 2.65 ms | 2.88 ms | 1 |  | 1.44× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 3.58 ms | 7.03 ms | 4 |  | 1.16× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 1.80 ms | 4.95 ms | 4 |  | 2.41× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 2.56 ms | 2.71 ms | 1 |  | 1.57× | ✓ |
| ht_auth | `ht_auth.v0` bc | 49.6 µs | 55.9 µs | 1 | 1.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 24.0 µs | 29.1 µs | 1 |  | 1.88× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 104.2 µs | 182.0 µs | 4 |  | 0.49× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 23.5 µs | 30.7 µs | 1 |  | 1.80× | ✓ |

### SLH-DSA-SHAKE-128s

end-to-end v0 stages: 1.08 ms, best assembled: 1.04 ms (1.03×), coverage 96%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 0.6 µs | 1.1 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 0.7 µs | 1.2 µs | 1 |  | 0.94× | ✓ |
| hmsg | `hmsg.v2` c2-only | 1.1 µs | 5.1 µs | 1 |  | 0.34× | ✓ |
| fors | `fors.v0` bc | 95.8 µs | 110.0 µs | 1 | 8.9% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 105.6 µs | 119.8 µs | 1 |  | 0.91× | ✓ |
| fors | `fors.v2` parallel-trees | 140.7 µs | 257.5 µs | 4 |  | 0.71× | ✓ |
| fors | `fors.v3` fused-fast | 100.4 µs | 113.3 µs | 1 |  | 0.97× | ✓ |
| ht_wots | `ht_wots.v0` bc | 903.3 µs | 929.2 µs | 1 | 83.9% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 1.04 ms | 1.15 ms | 1 |  | 0.79× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 1.08 ms | 1.97 ms | 4 |  | 0.81× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 532.5 µs | 1.28 ms | 4 |  | 1.63× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 1.01 ms | 1.09 ms | 1 |  | 0.84× | ✓ |
| ht_auth | `ht_auth.v0` bc | 31.9 µs | 36.2 µs | 1 | 3.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 34.9 µs | 39.7 µs | 1 |  | 0.90× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 88.1 µs | 146.4 µs | 4 |  | 0.38× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 33.9 µs | 40.1 µs | 1 |  | 0.90× | ✓ |

### SLH-DSA-SHAKE-128f

end-to-end v0 stages: 3.45 ms, best assembled: 4.61 ms (0.75×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 0.6 µs | 1.2 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 0.7 µs | 1.3 µs | 1 |  | 0.86× | ✓ |
| hmsg | `hmsg.v2` c2-only | 0.7 µs | 4.2 µs | 1 |  | 0.48× | ✓ |
| fors | `fors.v0` bc | 123.9 µs | 133.8 µs | 1 | 3.6% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 137.3 µs | 159.6 µs | 1 |  | 0.82× | ✓ |
| fors | `fors.v2` parallel-trees | 147.6 µs | 276.2 µs | 4 |  | 0.83× | ✓ |
| fors | `fors.v3` fused-fast | 128.4 µs | 140.2 µs | 1 |  | 0.95× | ✓ |
| ht_wots | `ht_wots.v0` bc | 3.21 ms | 3.44 ms | 1 | 93.3% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 3.57 ms | 3.80 ms | 1 |  | 0.89× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 2.88 ms | 5.54 ms | 4 |  | 1.14× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 1.67 ms | 4.43 ms | 4 |  | 2.00× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 3.66 ms | 3.82 ms | 1 |  | 0.89× | ✓ |
| ht_auth | `ht_auth.v0` bc | 33.5 µs | 40.9 µs | 1 | 1.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 37.1 µs | 40.9 µs | 1 |  | 1.01× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 97.1 µs | 165.4 µs | 4 |  | 0.38× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 35.9 µs | 42.5 µs | 1 |  | 0.97× | ✓ |

### SLH-DSA-SHAKE-192s

end-to-end v0 stages: 1.65 ms, best assembled: 1.87 ms (0.88×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 1.0 µs | 1.6 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.1 µs | 1.7 µs | 1 |  | 0.95× | ✓ |
| hmsg | `hmsg.v2` c2-only | 1.1 µs | 4.5 µs | 1 |  | 0.62× | ✓ |
| fors | `fors.v0` bc | 135.7 µs | 148.5 µs | 1 | 8.2% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 150.7 µs | 163.7 µs | 1 |  | 0.91× | ✓ |
| fors | `fors.v2` parallel-trees | 137.2 µs | 268.9 µs | 4 |  | 0.98× | ✓ |
| fors | `fors.v3` fused-fast | 140.3 µs | 153.1 µs | 1 |  | 0.97× | ✓ |
| ht_wots | `ht_wots.v0` bc | 1.44 ms | 1.49 ms | 1 | 87.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 1.58 ms | 1.60 ms | 1 |  | 0.94× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 1.34 ms | 2.67 ms | 4 |  | 1.10× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 807.0 µs | 2.02 ms | 4 |  | 1.87× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 1.61 ms | 2.04 ms | 1 |  | 0.74× | ✓ |
| ht_auth | `ht_auth.v0` bc | 32.4 µs | 36.5 µs | 1 | 2.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 35.0 µs | 40.0 µs | 1 |  | 0.90× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 89.3 µs | 148.8 µs | 4 |  | 0.37× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 34.0 µs | 43.3 µs | 1 |  | 0.83× | ✓ |

### SLH-DSA-SHAKE-192f

end-to-end v0 stages: 4.90 ms, best assembled: 4.68 ms (1.05×), coverage 96%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 2.0 µs | 3.0 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.1 µs | 2.0 µs | 1 |  | 1.49× | ✓ |
| hmsg | `hmsg.v2` c2-only | 1.1 µs | 5.0 µs | 1 |  | 1.03× | ✓ |
| fors | `fors.v0` bc | 162.1 µs | 182.7 µs | 1 | 3.3% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 174.7 µs | 198.6 µs | 1 |  | 0.93× | ✓ |
| fors | `fors.v2` parallel-trees | 195.0 µs | 405.7 µs | 4 |  | 0.84× | ✓ |
| fors | `fors.v3` fused-fast | 167.0 µs | 185.7 µs | 1 |  | 0.98× | ✓ |
| ht_wots | `ht_wots.v0` bc | 4.53 ms | 5.18 ms | 1 | 92.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 4.85 ms | 4.93 ms | 1 |  | 1.06× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 4.76 ms | 9.00 ms | 4 |  | 1.09× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 2.33 ms | 6.63 ms | 4 |  | 2.19× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 5.78 ms | 6.73 ms | 1 |  | 0.77× | ✓ |
| ht_auth | `ht_auth.v0` bc | 34.3 µs | 49.3 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 37.0 µs | 46.4 µs | 1 |  | 1.05× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 96.0 µs | 163.0 µs | 4 |  | 0.45× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 35.7 µs | 45.0 µs | 1 |  | 1.11× | ✓ |

### SLH-DSA-SHAKE-256s

end-to-end v0 stages: 2.44 ms, best assembled: 2.24 ms (1.09×), coverage 97%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 1.1 µs | 1.8 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.1 µs | 1.9 µs | 1 |  | 0.97× | ✓ |
| hmsg | `hmsg.v2` c2-only | 1.1 µs | 4.3 µs | 1 |  | 0.72× | ✓ |
| fors | `fors.v0` bc | 180.1 µs | 199.6 µs | 1 | 7.4% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 193.2 µs | 219.5 µs | 1 |  | 0.92× | ✓ |
| fors | `fors.v2` parallel-trees | 202.0 µs | 434.2 µs | 4 |  | 0.92× | ✓ |
| fors | `fors.v3` fused-fast | 184.5 µs | 207.9 µs | 1 |  | 0.97× | ✓ |
| ht_wots | `ht_wots.v0` bc | 2.16 ms | 2.28 ms | 1 | 88.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 2.35 ms | 2.41 ms | 1 |  | 0.93× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 1.99 ms | 3.94 ms | 4 |  | 1.13× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 1.19 ms | 2.97 ms | 4 |  | 1.97× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 2.35 ms | 2.68 ms | 1 |  | 0.85× | ✓ |
| ht_auth | `ht_auth.v0` bc | 33.6 µs | 40.6 µs | 1 | 1.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 35.7 µs | 39.1 µs | 1 |  | 1.03× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 103.4 µs | 174.1 µs | 4 |  | 0.36× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 34.2 µs | 38.6 µs | 1 |  | 1.05× | ✓ |

### SLH-DSA-SHAKE-256f

end-to-end v0 stages: 4.93 ms, best assembled: 4.24 ms (1.16×), coverage 103%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` bc | 1.1 µs | 1.8 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` alt-backend | 1.1 µs | 2.0 µs | 1 |  | 0.89× | ✓ |
| hmsg | `hmsg.v2` c2-only | 1.2 µs | 4.9 µs | 1 |  | 0.57× | ✓ |
| fors | `fors.v0` bc | 197.1 µs | 222.3 µs | 1 | 4.0% | 1.00× | ✓ |
| fors | `fors.v1` alt-backend | 209.0 µs | 233.7 µs | 1 |  | 0.93× | ✓ |
| fors | `fors.v2` parallel-trees | 174.5 µs | 350.8 µs | 4 |  | 1.22× | ✓ |
| fors | `fors.v3` fused-fast | 198.8 µs | 224.3 µs | 1 |  | 0.99× | ✓ |
| ht_wots | `ht_wots.v0` bc | 4.86 ms | 5.38 ms | 1 | 98.7% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` alt-backend | 4.95 ms | 5.21 ms | 1 |  | 1.03× | ✓ |
| ht_wots | `ht_wots.v2` parallel-chains | 3.66 ms | 7.49 ms | 4 |  | 1.43× | ✓ |
| ht_wots | `ht_wots.v3` parallel-layers | 2.45 ms | 7.08 ms | 4 |  | 2.14× | ✓ |
| ht_wots | `ht_wots.v4` fused-fast | 5.03 ms | 5.26 ms | 1 |  | 1.02× | ✓ |
| ht_auth | `ht_auth.v0` bc | 35.8 µs | 44.5 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` alt-backend | 38.2 µs | 45.1 µs | 1 |  | 1.00× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 95.4 µs | 164.9 µs | 4 |  | 0.42× | ✓ |
| ht_auth | `ht_auth.v3` fused-fast | 36.8 µs | 41.6 µs | 1 |  | 1.09× | ✓ |

