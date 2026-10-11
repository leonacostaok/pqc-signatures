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

_Preliminary dev-run numbers (budget 150 ms, three params, machine shared with five other agents — noisy; the orchestrator's quiet run overwrites this section)._

**decode** — median wall per op (ms), speedup vs v0 in parentheses

| param | decode.v0 noble | decode.v1 word-unpack | decode.v2 bun |
|---|---:|---:|---:|
| ML-DSA-44 | 0.043 | 0.030 (1.46×) | 0.034 (1.29×) |

**mu** — median wall per op (ms), speedup vs v0 in parentheses

| param | mu.v0 noble | mu.v1 native-shake | mu.v2 fast-keccak | mu.v3 tr-cache | mu.v4 bun |
|---|---:|---:|---:|---:|---:|
| ML-DSA-44 | 0.125 | 0.009 (14.71×) | 0.030 (4.23×) | 0.007 (18.80×) | 0.086 (1.46×) |

**expandA** — median wall per op (ms), speedup vs v0 in parentheses

| param | expandA.v0 noble | expandA.v1 native-shake | expandA.v2 fast-keccak | expandA.v3 A-cache | expandA.v4 workers-x4 | expandA.v5 bun |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | 0.484 | 0.153 (3.15×) | 0.227 (2.13×) | 0.000 (2271.98×) | 0.758 (0.64×) | 0.347 (1.39×) |

**w_approx** — median wall per op (ms), speedup vs v0 in parentheses

| param | w_approx.v0 noble | w_approx.v1 lazy-ntt | w_approx.v2 t1hat-cache | w_approx.v3 int32-mod-ntt | w_approx.v4 bun |
|---|---:|---:|---:|---:|---:|
| ML-DSA-44 | 0.757 | 0.135 (5.61×) | 0.512 (1.48×) | 0.553 (1.37×) | 1.398 (0.54×) |

**hint_check** — median wall per op (ms), speedup vs v0 in parentheses

| param | hint_check.v0 noble | hint_check.v1 fastjs | hint_check.v2 native-shake | hint_check.v3 bun |
|---|---:|---:|---:|---:|
| ML-DSA-44 | 0.066 | 0.052 (1.28×) | 0.034 (1.96×) | 0.098 (0.68×) |

**hmsg** — median wall per op (ms), speedup vs v0 in parentheses

| param | hmsg.v0 noble | hmsg.v1 native-hash | hmsg.v2 fast-keccak | hmsg.v3 bun |
|---|---:|---:|---:|---:|
| SLH-DSA-SHA2-128f | 0.027 | 0.029 (0.91×) | n/a | 0.046 (0.58×) |
| SLH-DSA-SHAKE-128f | 0.023 | 0.020 (1.15×) | 0.028 (0.84×) | 0.035 (0.66×) |

**fors** — median wall per op (ms), speedup vs v0 in parentheses

| param | fors.v0 noble | fors.v1 fastjs | fors.v2 native-hash | fors.v3 bun |
|---|---:|---:|---:|---:|
| SLH-DSA-SHA2-128f | 0.417 | 0.133 (3.14×) | 0.631 (0.66×) | 0.534 (0.78×) |
| SLH-DSA-SHAKE-128f | 2.595 | 0.580 (4.47×) | 1.172 (2.21×) | 1.091 (2.38×) |

**ht_wots** — median wall per op (ms), speedup vs v0 in parentheses

| param | ht_wots.v0 noble | ht_wots.v1 fastjs | ht_wots.v2 native-hash | ht_wots.v3 bun |
|---|---:|---:|---:|---:|
| SLH-DSA-SHA2-128f | 9.825 | 3.059 (3.21×) | 13.742 (0.71×) | 7.153 (1.37×) |
| SLH-DSA-SHAKE-128f | 55.262 | 16.614 (3.33×) | 33.101 (1.67×) | 27.639 (2.00×) |

**ht_auth** — median wall per op (ms), speedup vs v0 in parentheses

| param | ht_auth.v0 noble | ht_auth.v1 fastjs | ht_auth.v2 native-hash | ht_auth.v3 bun |
|---|---:|---:|---:|---:|
| SLH-DSA-SHA2-128f | 0.092 | 0.046 (1.99×) | 0.201 (0.46×) | 0.148 (0.62×) |
| SLH-DSA-SHAKE-128f | 0.418 | 0.178 (2.35×) | 0.347 (1.20×) | 0.324 (1.29×) |

**total** — median wall per op (ms), speedup vs v0 in parentheses

| param | total.v0 noble-stages |
|---|---:|
| ML-DSA-44 | 1.471 |
| SLH-DSA-SHA2-128f | 6.778 |
| SLH-DSA-SHAKE-128f | 79.780 |

**total_best** — median wall per op (ms), speedup vs v0 in parentheses

| param | total_best.v0 fast-stages |
|---|---:|
| ML-DSA-44 | 1.199 |
| SLH-DSA-SHA2-128f | 6.572 |
| SLH-DSA-SHAKE-128f | 26.037 |

**Preliminary conclusion.** ML-DSA: `expandA` and `w_approx` are the two big stages (≈ 0.5 + 0.75 ms of a 1.5 ms verify for ML-DSA-44 in this run); the lazy-reduction NTT (`w_approx.v1`, ≈ 5×) is the single largest win and the `int32-mod-ntt` alternative shows that about a third of it comes from removing the generic field closures and two thirds from lazy reduction; `t1hat-cache` saves the k forward NTTs (≈ 1.5×). For `expandA`, OpenSSL SHAKE (≈ 3×) beats the unrolled JS Keccak (≈ 2×) because one native call squeezes all five blocks; the worker-parallel version loses (message round-trip and buffer transfer exceed the 0.5 ms of work), and `A-cache` is the degenerate best case. `mu` is dominated by hashing the 1.3–2.6 KB public key, so `tr-cache` (≈ 17×) and native SHAKE (≈ 14×) both make it negligible. `decode` word-unpack gains ≈ 1.4× on an already small stage. SLH-DSA: `ht_wots` (the d WOTS+ chain recomputations) is the bulk of verify, `fors` next, `hmsg` and `ht_auth` are negligible; the direct compression-function rewrite gives ≈ 3× on both hash families, native hashing gains only for SHAKE (and loses for SHA2, as in the bench), Bun is faster than Node for the SHAKE sets and slower for SHA2. `total_best` reproduces the `verify.v2` results of the bench (within noise) and passed the whole validation suite.
