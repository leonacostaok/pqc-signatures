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

## Conclusions (preliminary, dev box shared with other agents)

See the tables below the marker. The headline: for the SHA2 parameter sets the digest implementation is everything,
the JDK's SHA-256 intrinsics (alt-backend / fused-fast) make the hash-bound stages several times faster than BC's
pure-Java SHA-256; for SHAKE sets the own Keccak is on par with BC's. For ML-DSA, `expandA` and `w_approx` dominate
and the only large single-thread gains are the per-key caches; the lazy-reduction and fused variants are small
effects within the noise of the dev box.

<!-- RESULTS -->
