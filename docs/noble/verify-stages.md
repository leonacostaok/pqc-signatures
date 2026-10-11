# noble — verify split into stages

`libs/noble/run.sh stages --out results/noble/stages.jsonl [--budget-ms N] [--params a,b] [--stages x,y] [--variants id,id]`

## How the stages were obtained

noble's `verify` is one closure per parameter set; the stages are exposed by the vendored copy
(`build/vendor/*.js`, built from `patches/`) as an additional `stages` object that calls the *same
internal helpers* `verify` uses (`publicCoder`/`sigCoder`, `shake256`, `XOF128` + `RejNTTPoly`,
`SampleInBall`, `crystals.NTT`, `MultiplyNTTs`, `polyUseHint`, `W1Vec`; for SLH-DSA `getContext`,
`hashMsgCoder`, `setAddr`, `computeRoot`, `chainLengths`, `thash1/thashN`). The `v0` of every stage is
therefore noble's own code, with the loop boundaries of FIPS 204 Alg. 8 / FIPS 205 Alg. 20 made
callable. The fast rewrites (`src/fast-ml-dsa.mjs`, `src/fast-slh-dsa.mjs`) expose the same
`stages` interface, and `src/stage-impls.mjs` adds stand-alone alternatives. `src/stage-lib.mjs`
holds the two end-to-end pipelines (`mlPipeline`, `slhPipeline`) that chain any stage set, used for
the `total` / `total_best` lines and by `validate` (`stages.total`, `stages.total_best`).

Inputs of a stage are the canonical values of the previous stages, computed once per param by
noble's own stage functions outside the timed region (`canonicalContext`). Every alternative's output
is canonicalised (`c~` bytes; mu bytes; A^ / w' as u32 little-endian coefficients in [0, q); the
`w1Encode` bytes; SLH-DSA digests / PK_FORS / the d WOTS pks / the d roots) and SHA-256'd; `match`
compares it with v0's digest on every run. `total` must additionally return `true` on the reference
and `false` on a bit-flipped signature.

Message formatting: the stages work on M' = 0x00 ‖ |ctx| ‖ ctx ‖ msg (the pure external interface),
with the empty context for the benchmark and the suite's contexts in `validate`.

## Stage alternatives

### ML-DSA

| stage | v0 | alternatives |
|---|---|---|
| `decode` | noble `pkDecode`/`sigDecode` through the generic bit-coders (`bitsCoder` with per-coefficient decode closures) and the hint validity rules | **v1 word-unpack**: straight-line unpackers (t1: 5 bytes → 4 × 10-bit; z: 9 bytes → 4 × 18-bit or 5 bytes → 2 × 20-bit, `γ1 − v` applied inline; hint table decoded in place), no generic bit buffer. **v2 bun**: v0 code under Bun. (Only two: decoding is byte shuffling with no hashing or arithmetic to replace; a worker/cache variant would be meaningless here.) |
| `mu` | tr = SHAKE256(pk, 64), μ = SHAKE256(tr ‖ M', 64) with `@noble/hashes` | **v1 native-shake** (node:crypto), **v2 fast-keccak** (unrolled Keccak-f[1600], `src/fast-shake.mjs`), **v3 tr-cache** (tr depends only on pk → cached per key; the stage absorbs only tr ‖ M'), **v4 bun** |
| `expandA` | noble `XOF128` reader + `RejNTTPoly` (k·l SHAKE128 samplings) | **v1 native-shake** (one OpenSSL SHAKE128 call per entry, 5 blocks squeezed at once, extended on demand), **v2 fast-keccak**, **v3 A-cache** (A^ is a function of ρ only → cached per public key; the stage is a map lookup, i.e. the "verifier under one key" case), **v4 workers-x4** (the k rows are expanded by four `worker_threads` running noble's code; latency of one matrix with transferred Int32Array buffers), **v5 bun** |
| `w_approx` | noble: SampleInBall, NTT(z), NTT(t1·2^d) via `@noble/curves` `FFTCore` with field closures and `%`, `MultiplyNTTs` + `polyAdd` per product, NTT⁻¹ | **v1 lazy-ntt** (fast-ml-dsa: branch-free lazily reduced NTT on `Float64Array`, reciprocal quotient estimate, fused multiply-accumulate over the l products, one canonicalising pass), **v2 t1hat-cache** (NTT(t1·2^d) precomputed per pk with noble's NTT; the rest is v0 code), **v3 int32-mod-ntt** (inlined `Int32Array` NTT, every butterfly/product fully reduced with `%` — isolates "no closures" from "lazy reduction"), **v4 bun** |
| `hint_check` | noble: ‖z‖∞ check, `UseHint` with per-coefficient decompose objects, `w1Encode` via bit-coder, SHAKE256(μ ‖ w1), hint-count check, compare | **v1 fastjs** (inlined UseHint loop, unrolled-Keccak SHAKE256), **v2 native-shake**, **v3 bun** |

### SLH-DSA

| stage | v0 | alternatives |
|---|---|---|
| `hmsg` | noble: signature parse, H_msg (SHA2: SHA-256/512 + MGF1; SHAKE: SHAKE256), md / idx_tree / idx_leaf split | **v1 native-hash**, **v2 fast-keccak** (SHAKE sets only — for the SHA2 sets the fast rewrite's H_msg is literally noble's code, so it is not emitted as a separate variant), **v3 bun** |
| `fors` | noble `fors_pkFromSig` (k × (F + a × H), T_k) with cloned-midstate hashers and `setAddr({...})` objects | **v1 fastjs** (SHA-2 compression function / Keccak permutation called directly on a pre-padded block from the PK.seed midstate; fixed-offset ADRS writes; in-place auth-path hashing), **v2 native-hash**, **v3 bun** |
| `ht_wots` | noble `wots_pkFromSig` for all d layers, each layer given its correct input (FORS pk, then the previous layer's root) | **v1 fastjs**, **v2 native-hash**, **v3 bun** |
| `ht_auth` | noble `computeRoot` (auth path) for all d layers + compare with PK.root | **v1 fastjs**, **v2 native-hash**, **v3 bun** |

SLH-DSA verify is nothing but tiny hash calls, so the only meaningful axes are *which hash
implementation* (noble JS / direct compression function / OpenSSL / JSC) — there is no key-dependent
precomputation (every address differs) and the per-op work (≤ 50 ms) is too small to split across
threads profitably; three real alternatives per stage are therefore all that is honest.

### End-to-end lines

* `total` (`total.v0`, "noble-stages"): v0 stages chained: decode → mu → expandA → w_approx → hint_check
  (ML-DSA) / hmsg → fors → ht_wots → ht_auth (SLH-DSA).
* `total_best` (`total_best.v0`, "fast-stages"): the fastest **cache-free** alternative of every
  stage: word-unpack decode, fast-keccak mu and expandA, lazy-ntt w_approx, fastjs hint_check;
  fastjs hmsg/fors/ht_wots/ht_auth. Cached alternatives (tr-cache, A-cache, t1hat-cache) are excluded
  on purpose: they only apply when the same public key is verified repeatedly, which `validate` (one
  key per case) does not model. Both pipelines go through the whole validation suite
  (`stages.total`, `stages.total_best` in `validate`).

<!-- RESULTS -->

## Results

Generated by `common/report-phase2.mjs` from `results/noble/stages.jsonl`. Speedup = throughput vs the stage's v0. "coverage" = sum of v0 stage medians / end-to-end v0 total.

### ML-DSA-44

end-to-end v0 stages: 1.42 ms, best assembled: 474.2 µs (3.00×), coverage 102%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` noble | 56.7 µs | 99.3 µs | 1 | 4.0% | 1.00× | ✓ |
| decode | `decode.v1` word-unpack | 27.6 µs | 65.6 µs | 1 |  | 1.63× | ✓ |
| decode | `decode.v2` bun | 33.6 µs | 57.5 µs | 1 |  | 1.77× | ✓ |
| mu | `mu.v0` noble | 59.1 µs | 75.0 µs | 1 | 4.2% | 1.00× | ✓ |
| mu | `mu.v1` native-shake | 8.8 µs | 24.4 µs | 1 |  | 3.31× | ✓ |
| mu | `mu.v2` fast-keccak | 30.3 µs | 43.6 µs | 1 |  | 1.73× | ✓ |
| mu | `mu.v3` tr-cache | 7.2 µs | 16.8 µs | 1 |  | 4.82× | ✓ |
| mu | `mu.v4` bun | 43.7 µs | 71.6 µs | 1 |  | 1.10× | ✓ |
| expandA | `expandA.v0` noble | 461.5 µs | 641.2 µs | 1 | 32.4% | 1.00× | ✓ |
| expandA | `expandA.v1` native-shake | 84.2 µs | 323.6 µs | 1 |  | 2.09× | ✓ |
| expandA | `expandA.v2` fast-keccak | 239.6 µs | 500.4 µs | 1 |  | 1.26× | ✓ |
| expandA | `expandA.v3` A-cache | 0.1 µs | 137.1 µs | 1 |  | 4.62× | ✓ |
| expandA | `expandA.v4` workers-x4 | 606.2 µs | 1.84 ms | 4 |  | 0.69× | ✓ |
| expandA | `expandA.v5` bun | 389.0 µs | 814.8 µs | 1 |  | 0.84× | ✓ |
| w_approx | `w_approx.v0` noble | 808.1 µs | 1.03 ms | 1 | 56.7% | 1.00× | ✓ |
| w_approx | `w_approx.v1` lazy-ntt | 174.0 µs | 304.6 µs | 1 |  | 3.51× | ✓ |
| w_approx | `w_approx.v2` t1hat-cache | 504.6 µs | 645.8 µs | 1 |  | 1.62× | ✓ |
| w_approx | `w_approx.v3` int32-mod-ntt | 581.5 µs | 709.3 µs | 1 |  | 1.44× | ✓ |
| w_approx | `w_approx.v4` bun | 1.39 ms | 1.59 ms | 1 |  | 0.65× | ✓ |
| hint_check | `hint_check.v0` noble | 69.6 µs | 115.8 µs | 1 | 4.9% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fastjs | 54.2 µs | 92.8 µs | 1 |  | 1.21× | ✓ |
| hint_check | `hint_check.v2` native-shake | 33.3 µs | 76.8 µs | 1 |  | 1.59× | ✓ |
| hint_check | `hint_check.v3` bun | 102.3 µs | 194.7 µs | 1 |  | 0.67× | ✓ |

### ML-DSA-65

end-to-end v0 stages: 2.18 ms, best assembled: 839.4 µs (2.60×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` noble | 107.2 µs | 151.9 µs | 1 | 4.9% | 1.00× | ✓ |
| decode | `decode.v1` word-unpack | 53.8 µs | 91.6 µs | 1 |  | 1.80× | ✓ |
| decode | `decode.v2` bun | 50.4 µs | 82.4 µs | 1 |  | 1.89× | ✓ |
| mu | `mu.v0` noble | 84.2 µs | 108.6 µs | 1 | 3.9% | 1.00× | ✓ |
| mu | `mu.v1` native-shake | 17.8 µs | 37.0 µs | 1 |  | 3.22× | ✓ |
| mu | `mu.v2` fast-keccak | 41.6 µs | 52.1 µs | 1 |  | 2.16× | ✓ |
| mu | `mu.v3` tr-cache | 7.3 µs | 16.9 µs | 1 |  | 6.79× | ✓ |
| mu | `mu.v4` bun | 66.9 µs | 110.5 µs | 1 |  | 1.09× | ✓ |
| expandA | `expandA.v0` noble | 898.2 µs | 1.29 ms | 1 | 41.1% | 1.00× | ✓ |
| expandA | `expandA.v1` native-shake | 168.7 µs | 629.3 µs | 1 |  | 2.15× | ✓ |
| expandA | `expandA.v2` fast-keccak | 431.3 µs | 781.0 µs | 1 |  | 1.67× | ✓ |
| expandA | `expandA.v3` A-cache | 0.2 µs | 270.4 µs | 1 |  | 4.89× | ✓ |
| expandA | `expandA.v4` workers-x4 | 996.4 µs | 2.99 ms | 4 |  | 0.92× | ✓ |
| expandA | `expandA.v5` bun | 670.3 µs | 1.32 ms | 1 |  | 1.07× | ✓ |
| w_approx | `w_approx.v0` noble | 1.04 ms | 1.31 ms | 1 | 47.5% | 1.00× | ✓ |
| w_approx | `w_approx.v1` lazy-ntt | 214.6 µs | 368.4 µs | 1 |  | 3.73× | ✓ |
| w_approx | `w_approx.v2` t1hat-cache | 734.9 µs | 972.8 µs | 1 |  | 1.39× | ✓ |
| w_approx | `w_approx.v3` int32-mod-ntt | 888.2 µs | 1.14 ms | 1 |  | 1.14× | ✓ |
| w_approx | `w_approx.v4` bun | 2.10 ms | 2.41 ms | 1 |  | 0.55× | ✓ |
| hint_check | `hint_check.v0` noble | 78.1 µs | 134.4 µs | 1 | 3.6% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fastjs | 71.9 µs | 119.6 µs | 1 |  | 1.11× | ✓ |
| hint_check | `hint_check.v2` native-shake | 44.5 µs | 93.8 µs | 1 |  | 1.45× | ✓ |
| hint_check | `hint_check.v3` bun | 144.5 µs | 230.0 µs | 1 |  | 0.61× | ✓ |

### ML-DSA-87

end-to-end v0 stages: 3.57 ms, best assembled: 2.03 ms (1.76×), coverage 96%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` noble | 125.2 µs | 191.4 µs | 1 | 3.5% | 1.00× | ✓ |
| decode | `decode.v1` word-unpack | 64.0 µs | 118.4 µs | 1 |  | 1.68× | ✓ |
| decode | `decode.v2` bun | 70.3 µs | 129.4 µs | 1 |  | 1.40× | ✓ |
| mu | `mu.v0` noble | 109.9 µs | 147.6 µs | 1 | 3.1% | 1.00× | ✓ |
| mu | `mu.v1` native-shake | 19.0 µs | 32.9 µs | 1 |  | 4.77× | ✓ |
| mu | `mu.v2` fast-keccak | 58.8 µs | 87.5 µs | 1 |  | 1.70× | ✓ |
| mu | `mu.v3` tr-cache | 6.9 µs | 14.2 µs | 1 |  | 10.88× | ✓ |
| mu | `mu.v4` bun | 82.3 µs | 132.2 µs | 1 |  | 1.23× | ✓ |
| expandA | `expandA.v0` noble | 1.67 ms | 2.27 ms | 1 | 46.7% | 1.00× | ✓ |
| expandA | `expandA.v1` native-shake | 340.1 µs | 1.29 ms | 1 |  | 1.81× | ✓ |
| expandA | `expandA.v2` fast-keccak | 824.5 µs | 1.58 ms | 1 |  | 1.42× | ✓ |
| expandA | `expandA.v3` A-cache | 0.5 µs | 470.3 µs | 1 |  | 4.73× | ✓ |
| expandA | `expandA.v4` workers-x4 | 1.59 ms | 5.05 ms | 4 |  | 0.94× | ✓ |
| expandA | `expandA.v5` bun | 1.61 ms | 2.83 ms | 1 |  | 0.88× | ✓ |
| w_approx | `w_approx.v0` noble | 1.42 ms | 1.71 ms | 1 | 39.8% | 1.00× | ✓ |
| w_approx | `w_approx.v1` lazy-ntt | 345.4 µs | 561.4 µs | 1 |  | 3.03× | ✓ |
| w_approx | `w_approx.v2` t1hat-cache | 1.06 ms | 1.36 ms | 1 |  | 1.26× | ✓ |
| w_approx | `w_approx.v3` int32-mod-ntt | 1.80 ms | 1.84 ms | 1 |  | 0.90× | ✓ |
| w_approx | `w_approx.v4` bun | 4.16 ms | 4.32 ms | 1 |  | 0.39× | ✓ |
| hint_check | `hint_check.v0` noble | 104.2 µs | 168.0 µs | 1 | 2.9% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fastjs | 93.3 µs | 155.9 µs | 1 |  | 1.05× | ✓ |
| hint_check | `hint_check.v2` native-shake | 59.6 µs | 115.2 µs | 1 |  | 1.50× | ✓ |
| hint_check | `hint_check.v3` bun | 325.6 µs | 396.2 µs | 1 |  | 0.41× | ✓ |

### SLH-DSA-SHA2-128s

end-to-end v0 stages: 2.28 ms, best assembled: 1.17 ms (1.95×), coverage 93%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 18.6 µs | 30.1 µs | 1 | 0.8% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 26.0 µs | 53.3 µs | 1 |  | 0.53× | ✓ |
| hmsg | `hmsg.v3` bun | 15.4 µs | 38.7 µs | 1 |  | 0.86× | ✓ |
| fors | `fors.v0` noble | 178.6 µs | 213.6 µs | 1 | 7.8% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 96.5 µs | 118.4 µs | 1 |  | 1.77× | ✓ |
| fors | `fors.v2` native-hash | 435.7 µs | 554.9 µs | 1 |  | 0.42× | ✓ |
| fors | `fors.v3` bun | 259.1 µs | 335.5 µs | 1 |  | 0.64× | ✓ |
| ht_wots | `ht_wots.v0` noble | 1.86 ms | 2.04 ms | 1 | 81.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 978.7 µs | 1.06 ms | 1 |  | 1.89× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 4.71 ms | 5.57 ms | 1 |  | 0.41× | ✓ |
| ht_wots | `ht_wots.v3` bun | 2.00 ms | 2.60 ms | 1 |  | 0.85× | ✓ |
| ht_auth | `ht_auth.v0` noble | 66.1 µs | 92.5 µs | 1 | 2.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 35.2 µs | 52.1 µs | 1 |  | 1.68× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 149.5 µs | 209.2 µs | 1 |  | 0.47× | ✓ |
| ht_auth | `ht_auth.v3` bun | 68.1 µs | 114.2 µs | 1 |  | 0.84× | ✓ |

### SLH-DSA-SHA2-128f

end-to-end v0 stages: 6.59 ms, best assembled: 3.32 ms (1.99×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 30.4 µs | 45.5 µs | 1 | 0.5% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 29.0 µs | 54.7 µs | 1 |  | 0.86× | ✓ |
| hmsg | `hmsg.v3` bun | 23.4 µs | 59.4 µs | 1 |  | 0.85× | ✓ |
| fors | `fors.v0` noble | 236.9 µs | 270.6 µs | 1 | 3.6% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 129.4 µs | 163.3 µs | 1 |  | 1.62× | ✓ |
| fors | `fors.v2` native-hash | 550.1 µs | 706.7 µs | 1 |  | 0.41× | ✓ |
| fors | `fors.v3` bun | 306.5 µs | 444.4 µs | 1 |  | 0.61× | ✓ |
| ht_wots | `ht_wots.v0` noble | 6.13 ms | 6.39 ms | 1 | 93.1% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 2.93 ms | 3.07 ms | 1 |  | 2.10× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 16.06 ms | 19.57 ms | 1 |  | 0.38× | ✓ |
| ht_wots | `ht_wots.v3` bun | 7.64 ms | 8.69 ms | 1 |  | 0.78× | ✓ |
| ht_auth | `ht_auth.v0` noble | 90.6 µs | 135.2 µs | 1 | 1.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 46.5 µs | 65.8 µs | 1 |  | 2.01× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 202.0 µs | 289.0 µs | 1 |  | 0.50× | ✓ |
| ht_auth | `ht_auth.v3` bun | 87.3 µs | 158.7 µs | 1 |  | 0.88× | ✓ |

### SLH-DSA-SHA2-192s

end-to-end v0 stages: 3.99 ms, best assembled: 2.48 ms (1.61×), coverage 103%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 29.6 µs | 51.3 µs | 1 | 0.7% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 26.9 µs | 50.2 µs | 1 |  | 1.05× | ✓ |
| hmsg | `hmsg.v3` bun | 25.3 µs | 50.5 µs | 1 |  | 1.06× | ✓ |
| fors | `fors.v0` noble | 870.5 µs | 926.1 µs | 1 | 21.8% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 480.5 µs | 550.7 µs | 1 |  | 1.65× | ✓ |
| fors | `fors.v2` native-hash | 738.6 µs | 975.9 µs | 1 |  | 1.05× | ✓ |
| fors | `fors.v3` bun | 785.1 µs | 1.04 ms | 1 |  | 0.94× | ✓ |
| ht_wots | `ht_wots.v0` noble | 3.03 ms | 3.27 ms | 1 | 76.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 1.47 ms | 1.69 ms | 1 |  | 1.97× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 7.09 ms | 8.42 ms | 1 |  | 0.43× | ✓ |
| ht_wots | `ht_wots.v3` bun | 3.99 ms | 4.47 ms | 1 |  | 0.80× | ✓ |
| ht_auth | `ht_auth.v0` noble | 190.2 µs | 253.5 µs | 1 | 4.8% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 120.6 µs | 149.5 µs | 1 |  | 1.71× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 177.4 µs | 243.5 µs | 1 |  | 1.16× | ✓ |
| ht_auth | `ht_auth.v3` bun | 192.5 µs | 268.1 µs | 1 |  | 0.98× | ✓ |

### SLH-DSA-SHA2-192f

end-to-end v0 stages: 10.32 ms, best assembled: 5.80 ms (1.78×), coverage 104%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 36.1 µs | 56.8 µs | 1 | 0.4% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 28.0 µs | 49.6 µs | 1 |  | 1.19× | ✓ |
| hmsg | `hmsg.v3` bun | 36.1 µs | 80.1 µs | 1 |  | 0.82× | ✓ |
| fors | `fors.v0` noble | 957.4 µs | 1.08 ms | 1 | 9.3% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 554.2 µs | 644.8 µs | 1 |  | 1.70× | ✓ |
| fors | `fors.v2` native-hash | 845.9 µs | 1.05 ms | 1 |  | 1.15× | ✓ |
| fors | `fors.v3` bun | 929.1 µs | 1.20 ms | 1 |  | 0.94× | ✓ |
| ht_wots | `ht_wots.v0` noble | 9.56 ms | 10.22 ms | 1 | 92.7% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 4.90 ms | 5.45 ms | 1 |  | 1.86× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 19.96 ms | 22.72 ms | 1 |  | 0.49× | ✓ |
| ht_wots | `ht_wots.v3` bun | 12.05 ms | 13.75 ms | 1 |  | 0.82× | ✓ |
| ht_auth | `ht_auth.v0` noble | 213.6 µs | 287.9 µs | 1 | 2.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 155.4 µs | 214.8 µs | 1 |  | 1.33× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 224.9 µs | 319.0 µs | 1 |  | 1.03× | ✓ |
| ht_auth | `ht_auth.v3` bun | 222.1 µs | 299.5 µs | 1 |  | 0.98× | ✓ |

### SLH-DSA-SHA2-256s

end-to-end v0 stages: 5.98 ms, best assembled: 3.76 ms (1.59×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 33.6 µs | 61.1 µs | 1 | 0.6% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 24.2 µs | 48.9 µs | 1 |  | 1.27× | ✓ |
| hmsg | `hmsg.v3` bun | 33.0 µs | 71.3 µs | 1 |  | 0.89× | ✓ |
| fors | `fors.v0` noble | 882.0 µs | 1.06 ms | 1 | 14.7% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 657.2 µs | 784.4 µs | 1 |  | 1.33× | ✓ |
| fors | `fors.v2` native-hash | 891.3 µs | 1.17 ms | 1 |  | 1.02× | ✓ |
| fors | `fors.v3` bun | 1.64 ms | 1.63 ms | 1 |  | 0.67× | ✓ |
| ht_wots | `ht_wots.v0` noble | 4.78 ms | 5.15 ms | 1 | 79.9% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 2.55 ms | 2.75 ms | 1 |  | 1.89× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 9.54 ms | 11.30 ms | 1 |  | 0.50× | ✓ |
| ht_wots | `ht_wots.v3` bun | 5.82 ms | 6.73 ms | 1 |  | 0.83× | ✓ |
| ht_auth | `ht_auth.v0` noble | 163.1 µs | 201.9 µs | 1 | 2.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 127.6 µs | 174.1 µs | 1 |  | 1.15× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 190.0 µs | 284.9 µs | 1 |  | 0.80× | ✓ |
| ht_auth | `ht_auth.v3` bun | 211.2 µs | 295.2 µs | 1 |  | 0.69× | ✓ |

### SLH-DSA-SHA2-256f

end-to-end v0 stages: 10.66 ms, best assembled: 6.73 ms (1.58×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 54.9 µs | 69.5 µs | 1 | 0.5% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 28.3 µs | 51.4 µs | 1 |  | 1.37× | ✓ |
| hmsg | `hmsg.v3` bun | 36.9 µs | 80.0 µs | 1 |  | 0.93× | ✓ |
| fors | `fors.v0` noble | 881.7 µs | 1.03 ms | 1 | 8.3% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 687.8 µs | 801.7 µs | 1 |  | 1.27× | ✓ |
| fors | `fors.v2` native-hash | 857.6 µs | 1.16 ms | 1 |  | 0.95× | ✓ |
| fors | `fors.v3` bun | 1.11 ms | 1.52 ms | 1 |  | 0.71× | ✓ |
| ht_wots | `ht_wots.v0` noble | 9.40 ms | 9.80 ms | 1 | 88.2% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 5.10 ms | 5.66 ms | 1 |  | 1.72× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 18.34 ms | 21.17 ms | 1 |  | 0.52× | ✓ |
| ht_wots | `ht_wots.v3` bun | 12.12 ms | 13.37 ms | 1 |  | 0.76× | ✓ |
| ht_auth | `ht_auth.v0` noble | 193.5 µs | 256.3 µs | 1 | 1.8% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 141.8 µs | 195.8 µs | 1 |  | 1.30× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 212.6 µs | 298.6 µs | 1 |  | 0.98× | ✓ |
| ht_auth | `ht_auth.v3` bun | 235.5 µs | 339.5 µs | 1 |  | 0.77× | ✓ |

### SLH-DSA-SHAKE-128s

end-to-end v0 stages: 12.30 ms, best assembled: 4.95 ms (2.49×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 16.3 µs | 26.6 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 14.4 µs | 30.1 µs | 1 |  | 0.89× | ✓ |
| hmsg | `hmsg.v2` fast-keccak | 12.0 µs | 20.2 µs | 1 |  | 1.30× | ✓ |
| hmsg | `hmsg.v3` bun | 13.0 µs | 30.3 µs | 1 |  | 0.98× | ✓ |
| fors | `fors.v0` noble | 1.11 ms | 1.25 ms | 1 | 9.0% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 466.9 µs | 528.1 µs | 1 |  | 2.37× | ✓ |
| fors | `fors.v2` native-hash | 520.8 µs | 1.01 ms | 1 |  | 1.43× | ✓ |
| fors | `fors.v3` bun | 827.3 µs | 974.5 µs | 1 |  | 1.29× | ✓ |
| ht_wots | `ht_wots.v0` noble | 10.77 ms | 11.43 ms | 1 | 87.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 4.21 ms | 4.50 ms | 1 |  | 2.56× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 5.22 ms | 9.34 ms | 1 |  | 1.37× | ✓ |
| ht_wots | `ht_wots.v3` bun | 7.68 ms | 8.25 ms | 1 |  | 1.44× | ✓ |
| ht_auth | `ht_auth.v0` noble | 380.2 µs | 442.6 µs | 1 | 3.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 153.1 µs | 183.4 µs | 1 |  | 2.48× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 181.8 µs | 386.0 µs | 1 |  | 1.31× | ✓ |
| ht_auth | `ht_auth.v3` bun | 284.7 µs | 333.6 µs | 1 |  | 1.37× | ✓ |

### SLH-DSA-SHAKE-128f

end-to-end v0 stages: 40.07 ms, best assembled: 16.39 ms (2.44×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 26.8 µs | 41.4 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 20.5 µs | 35.8 µs | 1 |  | 1.22× | ✓ |
| hmsg | `hmsg.v2` fast-keccak | 19.8 µs | 30.8 µs | 1 |  | 1.37× | ✓ |
| hmsg | `hmsg.v3` bun | 25.0 µs | 58.3 µs | 1 |  | 0.85× | ✓ |
| fors | `fors.v0` noble | 2.35 ms | 2.19 ms | 1 | 5.9% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 597.5 µs | 681.0 µs | 1 |  | 3.17× | ✓ |
| fors | `fors.v2` native-hash | 777.4 µs | 1.66 ms | 1 |  | 1.41× | ✓ |
| fors | `fors.v3` bun | 1.06 ms | 1.18 ms | 1 |  | 1.84× | ✓ |
| ht_wots | `ht_wots.v0` noble | 37.62 ms | 44.66 ms | 1 | 93.9% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 15.56 ms | 16.66 ms | 1 |  | 2.67× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 28.45 ms | 33.06 ms | 1 |  | 1.48× | ✓ |
| ht_wots | `ht_wots.v3` bun | 29.24 ms | 33.28 ms | 1 |  | 1.35× | ✓ |
| ht_auth | `ht_auth.v0` noble | 435.7 µs | 506.2 µs | 1 | 1.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 184.1 µs | 243.7 µs | 1 |  | 2.12× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 349.1 µs | 563.7 µs | 1 |  | 0.99× | ✓ |
| ht_auth | `ht_auth.v3` bun | 320.1 µs | 423.8 µs | 1 |  | 1.26× | ✓ |

### SLH-DSA-SHAKE-192s

end-to-end v0 stages: 18.44 ms, best assembled: 7.71 ms (2.39×), coverage 103%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 22.0 µs | 31.4 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 13.5 µs | 24.8 µs | 1 |  | 1.33× | ✓ |
| hmsg | `hmsg.v2` fast-keccak | 15.5 µs | 25.0 µs | 1 |  | 1.27× | ✓ |
| hmsg | `hmsg.v3` bun | 17.6 µs | 38.6 µs | 1 |  | 0.95× | ✓ |
| fors | `fors.v0` noble | 1.60 ms | 1.79 ms | 1 | 8.7% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 635.8 µs | 712.0 µs | 1 |  | 2.49× | ✓ |
| fors | `fors.v2` native-hash | 910.3 µs | 1.76 ms | 1 |  | 1.08× | ✓ |
| fors | `fors.v3` bun | 1.15 ms | 1.32 ms | 1 |  | 1.36× | ✓ |
| ht_wots | `ht_wots.v0` noble | 16.97 ms | 17.25 ms | 1 | 92.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 7.02 ms | 8.22 ms | 1 |  | 2.10× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 15.48 ms | 16.93 ms | 1 |  | 1.13× | ✓ |
| ht_wots | `ht_wots.v3` bun | 12.64 ms | 13.25 ms | 1 |  | 1.32× | ✓ |
| ht_auth | `ht_auth.v0` noble | 385.0 µs | 476.4 µs | 1 | 2.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 156.1 µs | 217.4 µs | 1 |  | 2.25× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 182.7 µs | 420.5 µs | 1 |  | 1.28× | ✓ |
| ht_auth | `ht_auth.v3` bun | 286.9 µs | 349.6 µs | 1 |  | 1.42× | ✓ |

### SLH-DSA-SHAKE-192f

end-to-end v0 stages: 54.15 ms, best assembled: 22.16 ms (2.44×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 29.9 µs | 41.8 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 20.2 µs | 33.5 µs | 1 |  | 1.33× | ✓ |
| hmsg | `hmsg.v2` fast-keccak | 22.0 µs | 32.6 µs | 1 |  | 1.29× | ✓ |
| hmsg | `hmsg.v3` bun | 23.5 µs | 51.4 µs | 1 |  | 0.99× | ✓ |
| fors | `fors.v0` noble | 1.98 ms | 2.30 ms | 1 | 3.6% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 801.7 µs | 963.9 µs | 1 |  | 2.36× | ✓ |
| fors | `fors.v2` native-hash | 942.3 µs | 2.05 ms | 1 |  | 1.25× | ✓ |
| fors | `fors.v3` bun | 1.43 ms | 1.67 ms | 1 |  | 1.41× | ✓ |
| ht_wots | `ht_wots.v0` noble | 50.48 ms | 52.70 ms | 1 | 93.2% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 20.98 ms | 21.52 ms | 1 |  | 2.42× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 39.74 ms | 44.32 ms | 1 |  | 1.32× | ✓ |
| ht_wots | `ht_wots.v3` bun | 39.99 ms | 45.11 ms | 1 |  | 1.17× | ✓ |
| ht_auth | `ht_auth.v0` noble | 415.9 µs | 486.8 µs | 1 | 0.8% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 182.4 µs | 228.3 µs | 1 |  | 2.20× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 350.8 µs | 588.2 µs | 1 |  | 0.92× | ✓ |
| ht_auth | `ht_auth.v3` bun | 315.3 µs | 408.8 µs | 1 |  | 1.24× | ✓ |

### SLH-DSA-SHAKE-256s

end-to-end v0 stages: 28.24 ms, best assembled: 11.59 ms (2.44×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 24.3 µs | 37.0 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 15.1 µs | 27.9 µs | 1 |  | 1.42× | ✓ |
| hmsg | `hmsg.v2` fast-keccak | 17.2 µs | 27.2 µs | 1 |  | 1.38× | ✓ |
| hmsg | `hmsg.v3` bun | 17.9 µs | 39.4 µs | 1 |  | 1.13× | ✓ |
| fors | `fors.v0` noble | 2.19 ms | 2.62 ms | 1 | 7.7% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 833.5 µs | 966.8 µs | 1 |  | 2.71× | ✓ |
| fors | `fors.v2` native-hash | 1.05 ms | 2.13 ms | 1 |  | 1.36× | ✓ |
| fors | `fors.v3` bun | 1.57 ms | 1.75 ms | 1 |  | 1.51× | ✓ |
| ht_wots | `ht_wots.v0` noble | 26.02 ms | 26.75 ms | 1 | 92.1% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 9.95 ms | 10.05 ms | 1 |  | 2.67× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 21.26 ms | 23.66 ms | 1 |  | 1.25× | ✓ |
| ht_wots | `ht_wots.v3` bun | 18.10 ms | 19.99 ms | 1 |  | 1.37× | ✓ |
| ht_auth | `ht_auth.v0` noble | 392.6 µs | 445.6 µs | 1 | 1.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 162.0 µs | 206.2 µs | 1 |  | 2.19× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 211.8 µs | 453.3 µs | 1 |  | 1.10× | ✓ |
| ht_auth | `ht_auth.v3` bun | 299.8 µs | 387.9 µs | 1 |  | 1.19× | ✓ |

### SLH-DSA-SHAKE-256f

end-to-end v0 stages: 58.06 ms, best assembled: 23.15 ms (2.51×), coverage 97%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` noble | 27.8 µs | 40.6 µs | 1 | 0.0% | 1.00× | ✓ |
| hmsg | `hmsg.v1` native-hash | 20.8 µs | 35.8 µs | 1 |  | 1.12× | ✓ |
| hmsg | `hmsg.v2` fast-keccak | 21.6 µs | 33.6 µs | 1 |  | 1.16× | ✓ |
| hmsg | `hmsg.v3` bun | 23.6 µs | 54.2 µs | 1 |  | 0.85× | ✓ |
| fors | `fors.v0` noble | 2.40 ms | 2.74 ms | 1 | 4.1% | 1.00× | ✓ |
| fors | `fors.v1` fastjs | 900.6 µs | 1.03 ms | 1 |  | 2.69× | ✓ |
| fors | `fors.v2` native-hash | 1.35 ms | 2.47 ms | 1 |  | 1.25× | ✓ |
| fors | `fors.v3` bun | 1.68 ms | 2.06 ms | 1 |  | 1.35× | ✓ |
| ht_wots | `ht_wots.v0` noble | 53.21 ms | 54.33 ms | 1 | 91.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` fastjs | 21.57 ms | 23.03 ms | 1 |  | 2.36× | ✓ |
| ht_wots | `ht_wots.v2` native-hash | 42.02 ms | 48.41 ms | 1 |  | 1.24× | ✓ |
| ht_wots | `ht_wots.v3` bun | 48.45 ms | 51.55 ms | 1 |  | 1.06× | ✓ |
| ht_auth | `ht_auth.v0` noble | 435.0 µs | 494.9 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` fastjs | 180.7 µs | 235.4 µs | 1 |  | 2.14× | ✓ |
| ht_auth | `ht_auth.v2` native-hash | 232.5 µs | 484.3 µs | 1 |  | 1.15× | ✓ |
| ht_auth | `ht_auth.v3` bun | 324.1 µs | 390.6 µs | 1 |  | 1.29× | ✓ |

