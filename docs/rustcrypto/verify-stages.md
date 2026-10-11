# rustcrypto: verify split into stages

`run.sh stages --out results/rustcrypto/stages.jsonl [--budget-ms N] [--params a,b] [--stages x,y]`

## How the internals were reached

`ml-dsa` and `slh-dsa` keep everything below the `SigningKey`/`VerifyingKey` API private. The two crates
are therefore **vendored** into `libs/rustcrypto/vendor/{ml-dsa,slh-dsa}` (copied from the crates.io
sources of ml-dsa 0.1.1 and slh-dsa 0.2.0-rc.5, licences kept) and patched only for visibility:

* every private module is `#[doc(hidden)] pub mod ...`, every `pub(crate)` became `pub`, the structs
  that carry decoded signatures (`Signature { c_tilde, z, h }`, `ForsSignature`, `HypertreeSig`,
  `XmssSig`, `WotsSig`) and the `MuBuilder` helper got public fields/constructors, and two private
  sampling helpers (`rej_ntt_poly`, `coeff_from_three_bytes`) were made public;
* nothing algorithmic was changed, the Phase-1 variants still byte-match `common/reference.json`
  (`run.sh vectors` checks this) and `Cargo.toml` points at the vendored paths.

The stage code itself lives in the harness (`src/stages_mldsa.rs`, `src/stages_slhdsa.rs`,
`src/fasthash.rs`, driver in `src/stages.rs`). "v0" of every stage calls the crate's own functions
(`expand_a`, `sample_in_ball`, `Hint::use_hint`, `P::encode_w1`, `fors_pk_from_sig`,
`wots_pk_from_sig`, the `HashSuite` `f/h/t/h_msg`, ...). Stage inputs are produced from the previous v0
stages once per parameter set, outside the timed region. Every alternative's full output (not only the
canonical bytes) is compared with v0's output on every run, and `match` reports that.

Two `stage:"total"` / `stage:"total_best"` lines per parameter set time the end-to-end verify built
from the v0 stages and from the fastest stateless alternatives (composition listed below). Both are also
run through the whole validation suite (`run.sh validate`) as the variants `total.v0` /
`total_best.v0`.

Build-flag alternatives (`native`, `lto`, `pgo`) run the v0 implementation inside the corresponding
binary (`target/native`, `target/lto`, `target/pgo-verify`, i.e. the verify-trained PGO profile), so
`run.sh stages` runs four binaries and appends to one file.

## ML-DSA stages and alternatives

| stage | v0 (crate) | alternatives |
|---|---|---|
| `decode` | `split_vk` + `decode_t1`, `split_sig` + `decode_z` + `Hint::bit_unpack` (FIPS hint validity rules) + the `\|\|z\|\|∞ < γ1−β` check that the crate's `Signature::decode` performs | **v1 fastunpack**: u64-window unpacking (5 bytes → 4 t1 coefficients, 9 bytes → 4 z coefficients for γ1 = 2¹⁷, 5 bytes → 2 for 2¹⁹), direct hint index scan — replaces the crate's generic per-bit cursor. **v2 native, v3 lto, v4 pgo** builds. **v5 rayon**: the k + l polynomial unpackings of v1 on a 4-thread pool (expected to lose: the work is ~1 µs per polynomial). |
| `mu` | `H(pk, 64)` then `MuBuilder` (tr ‖ 0 ‖ |ctx| ‖ ctx ‖ M) with the crate's `ShakeState` | **v1 trcache**: tr cached per key (what a cached `VerifyingKey` stores), only the µ SHAKE runs. **v2 directsha3**: the `sha3` crate's `Shake256` with `finalize_xof_into` instead of the `shake` crate + `ShakeState` (which clones the sponge before squeezing). **v3 native, v4 lto, v5 pgo**. |
| `expandA` | `expand_a`: k·l sequential SHAKE-128 rejection samplings | **v1 x4keccak**: four matrix entries at once on a 4-lane AVX2 Keccak-f[1600] (`fasthash.rs`, one `__m256i` per state word, self-tested against the `keccak` crate at start-up); the 3-byte stream parser is the same, so the output is bit-identical. **v2 rayon**: rows in parallel (crate `rej_ntt_poly`). **v3 cachedA**: A^ cached per key (the crate's `VerifyingKey` keeps it) — the stage is the clone of the cached matrix. **v4 fastparse**: scalar raw SHAKE-128 on the `keccak` permutation (no `digest` buffering/state clone) with the same parser. **v5 pgo**. |
| `w_approx` | `sample_in_ball`, `ntt` (Barrett with u128 products via `module-lattice`), `A^ ∘ NTT(z) − NTT(c) ∘ NTT(t1·2ᵈ)`, `ntt_inverse` | **v1 montgomery**: pqcrystals-reference-style i32 arithmetic — plain-domain NTT with 2³²-scaled zetas, the l row products accumulated lazily in i64 with one Montgomery reduction per coefficient, `invntt_tomont`, `caddq` into [0, q). **v2 t1hat-precomp**: `NTT(t1·2ᵈ)` precomputed per key (as the crate's `VerifyingKey` does), crate algebra otherwise. **v3 rayon**: rows of w' in parallel. **v4 lazyacc**: crate NTTs but the l products of a row accumulated in u64 and reduced once (one native `%` per coefficient instead of l Barrett reductions). **v5 pgo**. |
| `hint_check` | `infinity_norm`, `Hint::use_hint` (ct_select + two `%` per coefficient), `encode_w1`, `H(µ ‖ w1Encode)` compared with c~ | **v1 nonct**: non-constant-time Decompose/UseHint (verification handles public data only): native division by the public constant 2γ2, branches instead of ct_select, direct 4/6-bit packer; crate SHAKE. **v2 sparse-raw**: HighBits for every coefficient, the hint applied only at the ≤ ω hinted positions, final SHAKE-256 on the raw permutation. **v3 native, v4 lto, v5 pgo**. |

Canonical outputs follow the contract: SHA-256 of c~ (decode), µ, A^ coefficients as u32 LE row-major
k×l×256, w' coefficients in [0, q) as u32 LE k×256, and the w1Encode bytes. For `decode` the match
check additionally compares ρ, t1, z and the hint bits with v0, for `hint_check` the boolean result.

`total_best` (ML-DSA) = decode.v1 + mu.v2 + expandA.v1 (v4 when AVX2 is missing) + w_approx.v1 +
hint_check.v2 — the fastest *stateless* alternatives; the cached ones (mu.v1, expandA.v3,
w_approx.v2) are what Phase-1 `verify.v4 keycache` measures end to end.

## SLH-DSA stages and alternatives

| stage | v0 (crate) | alternatives |
|---|---|---|
| `hmsg` | `Signature::try_from` (full parse into nested arrays), `P::h_msg` (SHAKE256, or SHA-256/512 + MGF1), `split_digest` | **v1 zerocopy**: length check + borrowed R/FORS/HT slices, crate `h_msg`. **v2 rawhmsg**: zero-copy parse + H_msg on the raw permutation / compression function; for SHA-2 the MGF1 seed prefix (R ‖ PK.seed ‖ digest) is hashed once as a midstate and only the counter block is recomputed. **v3 native, v4 lto, v5 pgo**. |
| `fors` | `fors_pk_from_sig`: F/H through the `digest` API, cloning a PK.seed-prefixed hasher per call, T over the k roots | **v1 rawhash**: fused single-block hashing — one padded block on `keccak-f` or `compress256/512` from a PK.seed midstate, byte-array addresses, borrowed slices. **v2 x4keccak**: the k trees walked four at a time in lockstep on the 4-lane Keccak (same height a, so no masking); SHA2 sets fall back to the scalar raw path. **v3 rayon**: trees in parallel (crate hashes). **v4 native, v5 pgo**. |
| `ht_wots` | `wots_pk_from_sig` for each of the d layers, given the layer's correct message (FORS pk, then the previous layer's root, prepared from the v0 pipeline) | **v1 rawhash** as above. **v2 x4keccak**: all d·len chains flattened and advanced four at a time; lanes whose chain is finished keep hashing a dummy until the group ends. **v3 rayon**: layers in parallel. **v4 native, v5 pgo**. |
| `ht_auth` | the auth-path loop of the crate's `xmss_pk_from_sig` (crate `h` with its `HashTree` address) for every layer, given the layer's WOTS pk, plus the final compare with PK.root | **v1 rawhash**. **v2 x4keccak**: the d layers' paths climbed four at a time (same h'). **v3 rayon**: layers in parallel. **v4 native, v5 pgo**. |

Canonical outputs: SHA-256 of the m-byte H_msg digest, of PK_FORS, of the d WOTS public keys
(layer 0 first) and of the d layer roots. SHA2 sets have no 4-lane variant (there is no multi-lane SHA-2
implementation in RustCrypto and writing an AVX2 8-way SHA-256/512 was out of scope), so their `x4`
lines use the scalar raw path and are expected to equal `rawhash`; this is stated rather than padded
with a different name.

`total_best` (SLH-DSA) = hmsg.v2 + fors.v2 + per layer ht_wots.v2 (x4 across the chains of one layer)
and ht_auth.v1 (a single layer's path is sequential). Note that the lockstep-across-layers trick of
the `ht_wots`/`ht_auth` stage benchmarks is not available end to end: layer j's WOTS message is layer
j−1's root, so the pipeline is inherently serial across layers.

## Why some stages have fewer "real" alternatives

`decode` and `mu` are tiny (microseconds) and have one natural algorithmic alternative each; the other
slots are build flags and a (deliberately included, likely negative) rayon result. `hmsg` is a single
hash call. The heavy stages (`expandA`, `w_approx`, `fors`, `ht_wots`) carry the genuinely different
implementations.

## Conclusion (preliminary; the tables below are regenerated by the orchestrator)

Dev-run headlines (loaded shared box, so treat as indicative):

* **ML-DSA**: `w_approx.v1 montgomery` ≈ 1.6–1.7× over the crate's u128-Barrett constant-time
  algebra, `hint_check.v1/v2` ≈ 1.3–1.8×, `expandA.v1 x4keccak` ≈ 1.4× (ML-DSA-44) to 2.4× (ML-DSA-87,
  56 polynomials to batch), `decode.v1` ≈ 1.2×; `total_best` ≈ 2–3× `total` (ML-DSA-87: 487 → 246 µs).
  The cached variants (`mu.v1`, `expandA.v3`, `w_approx.v2`) show what a long-lived `VerifyingKey`
  saves: ExpandA is ~30 % of a stateless verify.
* **SLH-DSA SHAKE sets**: fused raw hashing (`*.v1 rawhash`) is 2× over the crate (which clones a
  200-byte sponge and goes through the `digest` buffering for every F/H), and the 4-lane AVX2 Keccak
  with the work-list chain scheduler (`*.v2 x4keccak`) reaches 5–7× over the crate for `fors`,
  `ht_wots` and `ht_auth` (SHAKE-128f: ht_wots 5.7 ms → 2.8 ms → 1.1 ms). `total_best` is ≈ 4.7× `total`
  (SHAKE-128f 6.1 → 1.3 ms, SHAKE-256s 4.1 → 0.87 ms).
* **SLH-DSA SHA2 sets**: the crate already keeps a PK.seed midstate and the `sha2` compression
  function is the same, so `rawhash` is at parity (±5 %), the `x4` variants dispatch to `rawhash`
  (there is no multi-lane SHA-2 here) and `total_best` ≈ `total`. The only real SHA2 win is
  `hmsg.v2` (MGF1 midstate + zero-copy parse, microseconds).
* rayon pays off only where a stage is big enough to amortise the pool (`ht_wots`); `decode`,
  `mu`, `expandA` rows and `fors` trees are too small on a 4-core box.
* A first version of the x4 WOTS variant ran chains in lockstep over the maximum length and was
  *slower* than scalar raw (≈ 2× wasted permutations because chain lengths are uniform in 0..15); the
  work-list scheduler fixed that, and replacing variable-count AVX2 shifts by an unrolled round with
  immediate rotations roughly doubled the kernel speed. Both are kept in the code as the final form.

<!-- RESULTS -->

## Results

Generated by `common/report-phase2.mjs` from `results/rustcrypto/stages.jsonl`. Speedup = throughput vs the stage's v0. "coverage" = sum of v0 stage medians / end-to-end v0 total.

### ML-DSA-44

end-to-end v0 stages: 102.5 µs, best assembled: 58.4 µs (1.75×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` crate | 5.6 µs | 6.5 µs | 1 | 5.4% | 1.00× | ✓ |
| decode | `decode.v1` fastunpack | 4.4 µs | 4.7 µs | 1 |  | 1.39× | ✓ |
| decode | `decode.v2` native | 5.9 µs | 6.8 µs | 1 |  | 0.96× | ✓ |
| decode | `decode.v3` lto | 5.3 µs | 6.2 µs | 1 |  | 1.05× | ✓ |
| decode | `decode.v4` pgo | 6.2 µs | 8.2 µs | 1 |  | 0.80× | ✓ |
| decode | `decode.v5` rayon | 102.3 µs | 234.0 µs | 4 |  | 0.06× | ✓ |
| mu | `mu.v0` crate | 4.6 µs | 5.3 µs | 1 | 4.5% | 1.00× | ✓ |
| mu | `mu.v1` trcache | 0.6 µs | 0.9 µs | 1 |  | 6.12× | ✓ |
| mu | `mu.v2` directsha3 | 5.3 µs | 6.8 µs | 1 |  | 0.79× | ✓ |
| mu | `mu.v3` native | 4.3 µs | 4.9 µs | 1 |  | 1.08× | ✓ |
| mu | `mu.v4` lto | 4.5 µs | 4.8 µs | 1 |  | 1.11× | ✓ |
| mu | `mu.v5` pgo | 4.4 µs | 5.1 µs | 1 |  | 1.03× | ✓ |
| expandA | `expandA.v0` crate | 39.9 µs | 45.2 µs | 1 | 39.0% | 1.00× | ✓ |
| expandA | `expandA.v1` x4keccak | 16.7 µs | 18.5 µs | 1 |  | 2.47× | ✓ |
| expandA | `expandA.v2` rayon | 158.9 µs | 329.4 µs | 4 |  | 0.27× | ✓ |
| expandA | `expandA.v3` cachedA | 1.2 µs | 1.5 µs | 1 |  | 28.30× | ✓ |
| expandA | `expandA.v4` fastparse | 37.0 µs | 40.9 µs | 1 |  | 1.11× | ✓ |
| expandA | `expandA.v5` pgo | 37.0 µs | 45.1 µs | 1 |  | 1.02× | ✓ |
| w_approx | `w_approx.v0` crate | 39.1 µs | 42.4 µs | 1 | 38.2% | 1.00× | ✓ |
| w_approx | `w_approx.v1` montgomery | 24.0 µs | 27.4 µs | 1 |  | 1.54× | ✓ |
| w_approx | `w_approx.v2` t1hat-precomp | 29.9 µs | 35.4 µs | 1 |  | 1.17× | ✓ |
| w_approx | `w_approx.v3` rayon | 177.6 µs | 343.1 µs | 4 |  | 0.23× | ✓ |
| w_approx | `w_approx.v4` lazyacc | 38.7 µs | 41.5 µs | 1 |  | 1.01× | ✓ |
| w_approx | `w_approx.v5` pgo | 41.1 µs | 43.4 µs | 1 |  | 0.99× | ✓ |
| hint_check | `hint_check.v0` crate | 14.4 µs | 15.7 µs | 1 | 14.0% | 1.00× | ✓ |
| hint_check | `hint_check.v1` nonct | 8.2 µs | 10.0 µs | 1 |  | 1.54× | ✓ |
| hint_check | `hint_check.v2` sparse-raw | 9.2 µs | 10.7 µs | 1 |  | 1.46× | ✓ |
| hint_check | `hint_check.v3` native | 15.1 µs | 16.0 µs | 1 |  | 0.98× | ✓ |
| hint_check | `hint_check.v4` lto | 13.3 µs | 13.9 µs | 1 |  | 1.13× | ✓ |
| hint_check | `hint_check.v5` pgo | 14.5 µs | 15.6 µs | 1 |  | 1.00× | ✓ |

### ML-DSA-65

end-to-end v0 stages: 164.8 µs, best assembled: 92.2 µs (1.79×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` crate | 7.8 µs | 8.4 µs | 1 | 4.8% | 1.00× | ✓ |
| decode | `decode.v1` fastunpack | 6.5 µs | 6.8 µs | 1 |  | 1.24× | ✓ |
| decode | `decode.v2` native | 8.3 µs | 9.8 µs | 1 |  | 0.85× | ✓ |
| decode | `decode.v3` lto | 7.3 µs | 8.1 µs | 1 |  | 1.05× | ✓ |
| decode | `decode.v4` pgo | 8.4 µs | 12.2 µs | 1 |  | 0.69× | ✓ |
| decode | `decode.v5` rayon | 98.0 µs | 238.4 µs | 4 |  | 0.07× | ✓ |
| mu | `mu.v0` crate | 6.6 µs | 8.1 µs | 1 | 4.0% | 1.00× | ✓ |
| mu | `mu.v1` trcache | 0.6 µs | 0.6 µs | 1 |  | 12.64× | ✓ |
| mu | `mu.v2` directsha3 | 7.3 µs | 8.1 µs | 1 |  | 0.99× | ✓ |
| mu | `mu.v3` native | 6.1 µs | 6.6 µs | 1 |  | 1.23× | ✓ |
| mu | `mu.v4` lto | 6.4 µs | 6.8 µs | 1 |  | 1.19× | ✓ |
| mu | `mu.v5` pgo | 6.4 µs | 8.5 µs | 1 |  | 0.95× | ✓ |
| expandA | `expandA.v0` crate | 76.2 µs | 81.2 µs | 1 | 46.2% | 1.00× | ✓ |
| expandA | `expandA.v1` x4keccak | 33.8 µs | 36.5 µs | 1 |  | 2.23× | ✓ |
| expandA | `expandA.v2` rayon | 182.4 µs | 414.9 µs | 4 |  | 0.41× | ✓ |
| expandA | `expandA.v3` cachedA | 2.6 µs | 2.9 µs | 1 |  | 28.61× | ✓ |
| expandA | `expandA.v4` fastparse | 70.2 µs | 74.8 µs | 1 |  | 1.09× | ✓ |
| expandA | `expandA.v5` pgo | 70.0 µs | 82.9 µs | 1 |  | 0.98× | ✓ |
| w_approx | `w_approx.v0` crate | 58.6 µs | 69.0 µs | 1 | 35.6% | 1.00× | ✓ |
| w_approx | `w_approx.v1` montgomery | 34.2 µs | 36.9 µs | 1 |  | 1.90× | ✓ |
| w_approx | `w_approx.v2` t1hat-precomp | 44.7 µs | 51.2 µs | 1 |  | 1.36× | ✓ |
| w_approx | `w_approx.v3` rayon | 171.2 µs | 362.1 µs | 4 |  | 0.36× | ✓ |
| w_approx | `w_approx.v4` lazyacc | 55.4 µs | 58.5 µs | 1 |  | 1.21× | ✓ |
| w_approx | `w_approx.v5` pgo | 82.2 µs | 83.8 µs | 1 |  | 0.84× | ✓ |
| hint_check | `hint_check.v0` crate | 16.8 µs | 17.6 µs | 1 | 10.2% | 1.00× | ✓ |
| hint_check | `hint_check.v1` nonct | 10.6 µs | 11.5 µs | 1 |  | 1.52× | ✓ |
| hint_check | `hint_check.v2` sparse-raw | 12.0 µs | 14.5 µs | 1 |  | 1.20× | ✓ |
| hint_check | `hint_check.v3` native | 17.4 µs | 19.6 µs | 1 |  | 0.90× | ✓ |
| hint_check | `hint_check.v4` lto | 15.9 µs | 17.9 µs | 1 |  | 0.98× | ✓ |
| hint_check | `hint_check.v5` pgo | 17.4 µs | 18.4 µs | 1 |  | 0.94× | ✓ |

### ML-DSA-87

end-to-end v0 stages: 268.4 µs, best assembled: 136.4 µs (1.97×), coverage 106%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` crate | 10.3 µs | 12.1 µs | 1 | 3.8% | 1.00× | ✓ |
| decode | `decode.v1` fastunpack | 8.4 µs | 9.1 µs | 1 |  | 1.31× | ✓ |
| decode | `decode.v2` native | 11.4 µs | 12.6 µs | 1 |  | 0.96× | ✓ |
| decode | `decode.v3` lto | 13.1 µs | 13.7 µs | 1 |  | 0.88× | ✓ |
| decode | `decode.v4` pgo | 11.1 µs | 13.4 µs | 1 |  | 0.90× | ✓ |
| decode | `decode.v5` rayon | 104.3 µs | 256.7 µs | 4 |  | 0.09× | ✓ |
| mu | `mu.v0` crate | 8.6 µs | 10.0 µs | 1 | 3.2% | 1.00× | ✓ |
| mu | `mu.v1` trcache | 0.5 µs | 0.6 µs | 1 |  | 15.72× | ✓ |
| mu | `mu.v2` directsha3 | 9.3 µs | 10.2 µs | 1 |  | 0.97× | ✓ |
| mu | `mu.v3` native | 8.2 µs | 9.5 µs | 1 |  | 1.05× | ✓ |
| mu | `mu.v4` lto | 8.4 µs | 11.0 µs | 1 |  | 0.89× | ✓ |
| mu | `mu.v5` pgo | 8.3 µs | 9.2 µs | 1 |  | 1.09× | ✓ |
| expandA | `expandA.v0` crate | 158.0 µs | 204.0 µs | 1 | 58.9% | 1.00× | ✓ |
| expandA | `expandA.v1` x4keccak | 57.8 µs | 63.9 µs | 1 |  | 3.20× | ✓ |
| expandA | `expandA.v2` rayon | 220.0 µs | 509.4 µs | 4 |  | 0.88× | ✓ |
| expandA | `expandA.v3` cachedA | 3.5 µs | 3.8 µs | 1 |  | 54.16× | ✓ |
| expandA | `expandA.v4` fastparse | 130.1 µs | 140.9 µs | 1 |  | 1.45× | ✓ |
| expandA | `expandA.v5` pgo | 139.7 µs | 171.4 µs | 1 |  | 1.19× | ✓ |
| w_approx | `w_approx.v0` crate | 84.9 µs | 89.9 µs | 1 | 31.6% | 1.00× | ✓ |
| w_approx | `w_approx.v1` montgomery | 46.7 µs | 53.0 µs | 1 |  | 1.69× | ✓ |
| w_approx | `w_approx.v2` t1hat-precomp | 66.3 µs | 70.9 µs | 1 |  | 1.27× | ✓ |
| w_approx | `w_approx.v3` rayon | 166.3 µs | 370.9 µs | 4 |  | 0.46× | ✓ |
| w_approx | `w_approx.v4` lazyacc | 75.3 µs | 83.1 µs | 1 |  | 1.07× | ✓ |
| w_approx | `w_approx.v5` pgo | 84.4 µs | 91.8 µs | 1 |  | 0.97× | ✓ |
| hint_check | `hint_check.v0` crate | 22.4 µs | 23.5 µs | 1 | 8.4% | 1.00× | ✓ |
| hint_check | `hint_check.v1` nonct | 14.2 µs | 16.2 µs | 1 |  | 1.45× | ✓ |
| hint_check | `hint_check.v2` sparse-raw | 16.1 µs | 18.7 µs | 1 |  | 1.25× | ✓ |
| hint_check | `hint_check.v3` native | 23.2 µs | 25.5 µs | 1 |  | 0.92× | ✓ |
| hint_check | `hint_check.v4` lto | 21.1 µs | 23.2 µs | 1 |  | 0.99× | ✓ |
| hint_check | `hint_check.v5` pgo | 23.3 µs | 28.8 µs | 1 |  | 0.79× | ✓ |

### SLH-DSA-SHA2-128s

end-to-end v0 stages: 749.6 µs, best assembled: 754.4 µs (0.99×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 3.0 µs | 3.3 µs | 1 | 0.4% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.3 µs | 1.5 µs | 1 |  | 2.20× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.4 µs | 1.6 µs | 1 |  | 2.20× | ✓ |
| hmsg | `hmsg.v3` native | 2.7 µs | 3.0 µs | 1 |  | 1.10× | ✓ |
| hmsg | `hmsg.v4` lto | 2.3 µs | 2.6 µs | 1 |  | 1.31× | ✓ |
| hmsg | `hmsg.v5` pgo | 2.7 µs | 3.5 µs | 1 |  | 0.97× | ✓ |
| fors | `fors.v0` crate | 63.6 µs | 67.8 µs | 1 | 8.5% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 64.0 µs | 67.6 µs | 1 |  | 1.00× | ✓ |
| fors | `fors.v2` x4keccak | 63.8 µs | 68.7 µs | 1 |  | 0.97× | ✓ |
| fors | `fors.v3` rayon | 81.8 µs | 218.3 µs | 4 |  | 0.82× | ✓ |
| fors | `fors.v4` native | 48.6 µs | 52.5 µs | 1 |  | 1.29× | ✓ |
| fors | `fors.v5` pgo | 48.4 µs | 54.3 µs | 1 |  | 1.24× | ✓ |
| ht_wots | `ht_wots.v0` crate | 659.2 µs | 681.4 µs | 1 | 87.9% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 669.0 µs | 714.5 µs | 1 |  | 0.96× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 667.2 µs | 683.2 µs | 1 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 430.6 µs | 1.16 ms | 4 |  | 1.55× | ✓ |
| ht_wots | `ht_wots.v4` native | 587.5 µs | 680.4 µs | 1 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 552.1 µs | 628.7 µs | 1 |  | 1.08× | ✓ |
| ht_auth | `ht_auth.v0` crate | 22.0 µs | 26.1 µs | 1 | 2.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 21.9 µs | 27.6 µs | 1 |  | 0.92× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 21.9 µs | 24.9 µs | 1 |  | 1.05× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 18.2 µs | 119.1 µs | 4 |  | 0.54× | ✓ |
| ht_auth | `ht_auth.v4` native | 16.8 µs | 18.5 µs | 1 |  | 1.40× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 16.8 µs | 21.8 µs | 1 |  | 1.20× | ✓ |

### SLH-DSA-SHA2-128f

end-to-end v0 stages: 2.21 ms, best assembled: 2.25 ms (0.98×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 5.0 µs | 5.5 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.9 µs | 2.4 µs | 1 |  | 2.31× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.7 µs | 1.9 µs | 1 |  | 2.92× | ✓ |
| hmsg | `hmsg.v3` native | 5.0 µs | 5.7 µs | 1 |  | 0.96× | ✓ |
| hmsg | `hmsg.v4` lto | 3.9 µs | 4.2 µs | 1 |  | 1.31× | ✓ |
| hmsg | `hmsg.v5` pgo | 4.2 µs | 5.0 µs | 1 |  | 1.10× | ✓ |
| fors | `fors.v0` crate | 81.1 µs | 94.8 µs | 1 | 3.7% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 82.4 µs | 90.8 µs | 1 |  | 1.04× | ✓ |
| fors | `fors.v2` x4keccak | 81.9 µs | 86.4 µs | 1 |  | 1.11× | ✓ |
| fors | `fors.v3` rayon | 102.4 µs | 273.8 µs | 4 |  | 0.89× | ✓ |
| fors | `fors.v4` native | 62.6 µs | 69.9 µs | 1 |  | 1.36× | ✓ |
| fors | `fors.v5` pgo | 62.1 µs | 71.1 µs | 1 |  | 1.34× | ✓ |
| ht_wots | `ht_wots.v0` crate | 2.08 ms | 2.25 ms | 1 | 94.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 2.09 ms | 2.11 ms | 1 |  | 1.06× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 2.13 ms | 2.18 ms | 1 |  | 1.03× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 762.4 µs | 2.59 ms | 4 |  | 2.83× | ✓ |
| ht_wots | `ht_wots.v4` native | 1.71 ms | 1.92 ms | 1 |  | 1.16× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 1.72 ms | 2.00 ms | 1 |  | 1.13× | ✓ |
| ht_auth | `ht_auth.v0` crate | 23.1 µs | 25.0 µs | 1 | 1.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 23.4 µs | 26.1 µs | 1 |  | 0.95× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 23.4 µs | 26.6 µs | 1 |  | 0.93× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 21.5 µs | 147.2 µs | 4 |  | 0.43× | ✓ |
| ht_auth | `ht_auth.v4` native | 17.9 µs | 21.9 µs | 1 |  | 1.13× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 17.7 µs | 22.8 µs | 1 |  | 1.09× | ✓ |

### SLH-DSA-SHA2-192s

end-to-end v0 stages: 1.07 ms, best assembled: 1.09 ms (0.98×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 4.5 µs | 4.7 µs | 1 | 0.4% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.1 µs | 1.3 µs | 1 |  | 3.78× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.2 µs | 1.4 µs | 1 |  | 3.37× | ✓ |
| hmsg | `hmsg.v3` native | 4.1 µs | 4.4 µs | 1 |  | 1.09× | ✓ |
| hmsg | `hmsg.v4` lto | 3.1 µs | 3.4 µs | 1 |  | 1.41× | ✓ |
| hmsg | `hmsg.v5` pgo | 4.5 µs | 4.9 µs | 1 |  | 0.96× | ✓ |
| fors | `fors.v0` crate | 82.0 µs | 86.7 µs | 1 | 7.7% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 80.7 µs | 91.2 µs | 1 |  | 0.94× | ✓ |
| fors | `fors.v2` x4keccak | 80.2 µs | 86.5 µs | 1 |  | 1.00× | ✓ |
| fors | `fors.v3` rayon | 120.5 µs | 345.4 µs | 4 |  | 0.63× | ✓ |
| fors | `fors.v4` native | 71.5 µs | 76.2 µs | 1 |  | 1.14× | ✓ |
| fors | `fors.v5` pgo | 69.6 µs | 77.0 µs | 1 |  | 1.12× | ✓ |
| ht_wots | `ht_wots.v0` crate | 964.1 µs | 1.02 ms | 1 | 90.5% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 1.03 ms | 1.12 ms | 1 |  | 0.92× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 984.2 µs | 1.06 ms | 1 |  | 0.98× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 585.3 µs | 1.61 ms | 4 |  | 1.70× | ✓ |
| ht_wots | `ht_wots.v4` native | 775.6 µs | 846.7 µs | 1 |  | 1.22× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 769.1 µs | 787.1 µs | 1 |  | 1.31× | ✓ |
| ht_auth | `ht_auth.v0` crate | 20.0 µs | 22.6 µs | 1 | 1.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 20.0 µs | 22.6 µs | 1 |  | 1.00× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 19.5 µs | 20.5 µs | 1 |  | 1.10× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 13.4 µs | 92.4 µs | 4 |  | 0.65× | ✓ |
| ht_auth | `ht_auth.v4` native | 17.5 µs | 18.9 µs | 1 |  | 1.20× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 17.3 µs | 20.2 µs | 1 |  | 1.12× | ✓ |

### SLH-DSA-SHA2-192f

end-to-end v0 stages: 3.14 ms, best assembled: 3.26 ms (0.96×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 10.0 µs | 11.7 µs | 1 | 0.3% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.6 µs | 1.8 µs | 1 |  | 6.67× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.2 µs | 1.5 µs | 1 |  | 8.09× | ✓ |
| hmsg | `hmsg.v3` native | 9.9 µs | 11.5 µs | 1 |  | 1.06× | ✓ |
| hmsg | `hmsg.v4` lto | 7.8 µs | 8.3 µs | 1 |  | 1.48× | ✓ |
| hmsg | `hmsg.v5` pgo | 10.6 µs | 11.4 µs | 1 |  | 1.07× | ✓ |
| fors | `fors.v0` crate | 95.7 µs | 103.2 µs | 1 | 3.0% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 93.5 µs | 107.4 µs | 1 |  | 0.97× | ✓ |
| fors | `fors.v2` x4keccak | 98.0 µs | 115.6 µs | 1 |  | 0.90× | ✓ |
| fors | `fors.v3` rayon | 43.9 µs | 222.9 µs | 4 |  | 1.39× | ✓ |
| fors | `fors.v4` native | 83.5 µs | 95.2 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v5` pgo | 82.4 µs | 100.2 µs | 1 |  | 1.04× | ✓ |
| ht_wots | `ht_wots.v0` crate | 3.03 ms | 3.20 ms | 1 | 96.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 3.12 ms | 3.30 ms | 1 |  | 0.98× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 3.09 ms | 3.13 ms | 1 |  | 1.02× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 1.02 ms | 3.58 ms | 4 |  | 3.05× | ✓ |
| ht_wots | `ht_wots.v4` native | 2.51 ms | 2.63 ms | 1 |  | 1.21× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 2.46 ms | 2.53 ms | 1 |  | 1.26× | ✓ |
| ht_auth | `ht_auth.v0` crate | 21.0 µs | 25.0 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 20.7 µs | 25.1 µs | 1 |  | 1.02× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 20.7 µs | 22.2 µs | 1 |  | 1.15× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 29.1 µs | 194.1 µs | 4 |  | 0.33× | ✓ |
| ht_auth | `ht_auth.v4` native | 18.6 µs | 20.9 µs | 1 |  | 1.22× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 18.1 µs | 20.3 µs | 1 |  | 1.27× | ✓ |

### SLH-DSA-SHA2-256s

end-to-end v0 stages: 1.63 ms, best assembled: 1.69 ms (0.97×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 7.1 µs | 7.4 µs | 1 | 0.4% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.2 µs | 1.3 µs | 1 |  | 5.86× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.2 µs | 1.3 µs | 1 |  | 5.55× | ✓ |
| hmsg | `hmsg.v3` native | 6.9 µs | 7.5 µs | 1 |  | 0.98× | ✓ |
| hmsg | `hmsg.v4` lto | 6.2 µs | 6.6 µs | 1 |  | 1.12× | ✓ |
| hmsg | `hmsg.v5` pgo | 8.5 µs | 8.9 µs | 1 |  | 0.83× | ✓ |
| fors | `fors.v0` crate | 106.1 µs | 119.3 µs | 1 | 6.5% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 106.3 µs | 134.0 µs | 1 |  | 0.91× | ✓ |
| fors | `fors.v2` x4keccak | 102.0 µs | 105.8 µs | 1 |  | 1.16× | ✓ |
| fors | `fors.v3` rayon | 102.9 µs | 301.1 µs | 4 |  | 1.09× | ✓ |
| fors | `fors.v4` native | 92.7 µs | 109.1 µs | 1 |  | 1.11× | ✓ |
| fors | `fors.v5` pgo | 89.5 µs | 97.3 µs | 1 |  | 1.25× | ✓ |
| ht_wots | `ht_wots.v0` crate | 1.48 ms | 1.53 ms | 1 | 90.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 1.63 ms | 1.84 ms | 1 |  | 0.84× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 1.50 ms | 1.62 ms | 1 |  | 0.93× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 814.2 µs | 2.35 ms | 4 |  | 1.83× | ✓ |
| ht_wots | `ht_wots.v4` native | 1.22 ms | 1.23 ms | 1 |  | 1.22× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 1.23 ms | 1.33 ms | 1 |  | 1.14× | ✓ |
| ht_auth | `ht_auth.v0` crate | 20.2 µs | 25.0 µs | 1 | 1.2% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 19.6 µs | 24.6 µs | 1 |  | 1.01× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 19.5 µs | 22.0 µs | 1 |  | 1.12× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 18.8 µs | 145.9 µs | 4 |  | 0.41× | ✓ |
| ht_auth | `ht_auth.v4` native | 17.8 µs | 20.1 µs | 1 |  | 1.26× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 17.1 µs | 19.4 µs | 1 |  | 1.31× | ✓ |

### SLH-DSA-SHA2-256f

end-to-end v0 stages: 3.15 ms, best assembled: 3.24 ms (0.97×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 12.8 µs | 13.5 µs | 1 | 0.4% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.1 µs | 1.3 µs | 1 |  | 9.94× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.2 µs | 1.4 µs | 1 |  | 9.58× | ✓ |
| hmsg | `hmsg.v3` native | 12.7 µs | 13.6 µs | 1 |  | 0.98× | ✓ |
| hmsg | `hmsg.v4` lto | 9.9 µs | 11.4 µs | 1 |  | 1.19× | ✓ |
| hmsg | `hmsg.v5` pgo | 14.2 µs | 15.0 µs | 1 |  | 0.90× | ✓ |
| fors | `fors.v0` crate | 117.9 µs | 163.1 µs | 1 | 3.7% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 115.6 µs | 158.5 µs | 1 |  | 1.03× | ✓ |
| fors | `fors.v2` x4keccak | 138.0 µs | 159.0 µs | 1 |  | 1.03× | ✓ |
| fors | `fors.v3` rayon | 118.8 µs | 354.3 µs | 4 |  | 1.28× | ✓ |
| fors | `fors.v4` native | 98.8 µs | 111.0 µs | 1 |  | 1.47× | ✓ |
| fors | `fors.v5` pgo | 95.7 µs | 100.9 µs | 1 |  | 1.62× | ✓ |
| ht_wots | `ht_wots.v0` crate | 3.04 ms | 3.43 ms | 1 | 96.5% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 3.12 ms | 3.27 ms | 1 |  | 1.04× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 3.48 ms | 3.76 ms | 1 |  | 0.91× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 1.40 ms | 4.47 ms | 4 |  | 2.44× | ✓ |
| ht_wots | `ht_wots.v4` native | 2.53 ms | 2.64 ms | 1 |  | 1.30× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 2.53 ms | 2.58 ms | 1 |  | 1.34× | ✓ |
| ht_auth | `ht_auth.v0` crate | 21.6 µs | 23.8 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 21.4 µs | 34.5 µs | 1 |  | 0.70× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 21.1 µs | 28.8 µs | 1 |  | 0.84× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 33.8 µs | 205.0 µs | 4 |  | 0.28× | ✓ |
| ht_auth | `ht_auth.v4` native | 20.5 µs | 25.6 µs | 1 |  | 0.93× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 18.4 µs | 19.7 µs | 1 |  | 1.23× | ✓ |

### SLH-DSA-SHAKE-128s

end-to-end v0 stages: 1.86 ms, best assembled: 414.4 µs (4.49×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 2.6 µs | 2.8 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 0.9 µs | 1.2 µs | 1 |  | 2.35× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 0.6 µs | 0.8 µs | 1 |  | 3.49× | ✓ |
| hmsg | `hmsg.v3` native | 3.2 µs | 3.4 µs | 1 |  | 0.81× | ✓ |
| hmsg | `hmsg.v4` lto | 1.8 µs | 2.0 µs | 1 |  | 1.39× | ✓ |
| hmsg | `hmsg.v5` pgo | 2.5 µs | 2.7 µs | 1 |  | 1.02× | ✓ |
| fors | `fors.v0` crate | 169.3 µs | 203.8 µs | 1 | 9.1% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 83.8 µs | 110.4 µs | 1 |  | 1.84× | ✓ |
| fors | `fors.v2` x4keccak | 33.5 µs | 40.4 µs | 1 |  | 5.05× | ✓ |
| fors | `fors.v3` rayon | 187.0 µs | 508.9 µs | 4 |  | 1.00× | ✓ |
| fors | `fors.v4` native | 146.1 µs | 172.9 µs | 1 |  | 1.18× | ✓ |
| fors | `fors.v5` pgo | 145.0 µs | 163.4 µs | 1 |  | 1.25× | ✓ |
| ht_wots | `ht_wots.v0` crate | 1.63 ms | 1.97 ms | 1 | 87.8% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 806.5 µs | 865.2 µs | 1 |  | 2.22× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 319.1 µs | 336.3 µs | 1 |  | 5.87× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 699.8 µs | 2.21 ms | 4 |  | 2.64× | ✓ |
| ht_wots | `ht_wots.v4` native | 1.59 ms | 1.60 ms | 1 |  | 1.24× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 1.61 ms | 1.76 ms | 1 |  | 1.13× | ✓ |
| ht_auth | `ht_auth.v0` crate | 56.7 µs | 61.2 µs | 1 | 3.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 27.3 µs | 31.2 µs | 1 |  | 1.95× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 11.2 µs | 12.7 µs | 1 |  | 4.76× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 70.7 µs | 225.1 µs | 4 |  | 0.65× | ✓ |
| ht_auth | `ht_auth.v4` native | 50.1 µs | 55.3 µs | 1 |  | 1.11× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 50.4 µs | 55.9 µs | 1 |  | 1.09× | ✓ |

### SLH-DSA-SHAKE-128f

end-to-end v0 stages: 6.03 ms, best assembled: 1.28 ms (4.72×), coverage 97%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 4.0 µs | 4.3 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 0.9 µs | 1.0 µs | 1 |  | 4.08× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 0.5 µs | 0.7 µs | 1 |  | 6.53× | ✓ |
| hmsg | `hmsg.v3` native | 4.5 µs | 4.8 µs | 1 |  | 0.89× | ✓ |
| hmsg | `hmsg.v4` lto | 2.9 µs | 3.5 µs | 1 |  | 1.19× | ✓ |
| hmsg | `hmsg.v5` pgo | 3.6 µs | 5.4 µs | 1 |  | 0.78× | ✓ |
| fors | `fors.v0` crate | 208.3 µs | 243.7 µs | 1 | 3.5% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 100.1 µs | 107.1 µs | 1 |  | 2.27× | ✓ |
| fors | `fors.v2` x4keccak | 41.7 µs | 45.6 µs | 1 |  | 5.29× | ✓ |
| fors | `fors.v3` rayon | 139.1 µs | 467.7 µs | 4 |  | 1.58× | ✓ |
| fors | `fors.v4` native | 187.9 µs | 221.9 µs | 1 |  | 1.09× | ✓ |
| fors | `fors.v5` pgo | 184.3 µs | 191.3 µs | 1 |  | 1.28× | ✓ |
| ht_wots | `ht_wots.v0` crate | 5.61 ms | 5.78 ms | 1 | 93.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 2.77 ms | 2.78 ms | 1 |  | 2.09× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 1.08 ms | 1.09 ms | 1 |  | 5.31× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 2.15 ms | 7.41 ms | 4 |  | 2.56× | ✓ |
| ht_wots | `ht_wots.v4` native | 5.60 ms | 5.68 ms | 1 |  | 1.02× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 5.64 ms | 5.88 ms | 1 |  | 0.98× | ✓ |
| ht_auth | `ht_auth.v0` crate | 58.7 µs | 65.0 µs | 1 | 1.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 28.3 µs | 33.1 µs | 1 |  | 1.96× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 11.6 µs | 12.9 µs | 1 |  | 5.04× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 27.8 µs | 155.9 µs | 4 |  | 1.25× | ✓ |
| ht_auth | `ht_auth.v4` native | 53.7 µs | 62.7 µs | 1 |  | 1.02× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 52.2 µs | 56.4 µs | 1 |  | 1.15× | ✓ |

### SLH-DSA-SHAKE-192s

end-to-end v0 stages: 2.79 ms, best assembled: 609.9 µs (4.57×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 4.7 µs | 5.5 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.3 µs | 1.6 µs | 1 |  | 3.56× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.0 µs | 1.1 µs | 1 |  | 4.96× | ✓ |
| hmsg | `hmsg.v3` native | 4.3 µs | 4.6 µs | 1 |  | 1.22× | ✓ |
| hmsg | `hmsg.v4` lto | 3.2 µs | 3.5 µs | 1 |  | 1.54× | ✓ |
| hmsg | `hmsg.v5` pgo | 3.9 µs | 4.4 µs | 1 |  | 1.27× | ✓ |
| fors | `fors.v0` crate | 230.6 µs | 244.9 µs | 1 | 8.3% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 111.2 µs | 136.8 µs | 1 |  | 1.75× | ✓ |
| fors | `fors.v2` x4keccak | 49.7 µs | 59.6 µs | 1 |  | 4.10× | ✓ |
| fors | `fors.v3` rayon | 233.8 µs | 621.6 µs | 4 |  | 0.99× | ✓ |
| fors | `fors.v4` native | 206.9 µs | 223.1 µs | 1 |  | 1.09× | ✓ |
| fors | `fors.v5` pgo | 206.9 µs | 231.3 µs | 1 |  | 1.06× | ✓ |
| ht_wots | `ht_wots.v0` crate | 2.49 ms | 2.60 ms | 1 | 89.2% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 1.25 ms | 1.43 ms | 1 |  | 1.76× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 514.0 µs | 550.2 µs | 1 |  | 4.69× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 1.07 ms | 3.69 ms | 4 |  | 2.12× | ✓ |
| ht_wots | `ht_wots.v4` native | 2.51 ms | 2.72 ms | 1 |  | 0.96× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 2.55 ms | 3.02 ms | 1 |  | 0.86× | ✓ |
| ht_auth | `ht_auth.v0` crate | 56.5 µs | 62.9 µs | 1 | 2.0% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 27.2 µs | 30.2 µs | 1 |  | 2.07× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 11.5 µs | 12.4 µs | 1 |  | 5.08× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 26.7 µs | 172.7 µs | 4 |  | 0.94× | ✓ |
| ht_auth | `ht_auth.v4` native | 50.4 µs | 61.5 µs | 1 |  | 1.01× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 50.1 µs | 53.3 µs | 1 |  | 1.18× | ✓ |

### SLH-DSA-SHAKE-192f

end-to-end v0 stages: 7.87 ms, best assembled: 1.73 ms (4.55×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 10.1 µs | 11.6 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.3 µs | 1.9 µs | 1 |  | 6.24× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.0 µs | 1.4 µs | 1 |  | 8.49× | ✓ |
| hmsg | `hmsg.v3` native | 10.1 µs | 11.6 µs | 1 |  | 1.01× | ✓ |
| hmsg | `hmsg.v4` lto | 7.9 µs | 8.4 µs | 1 |  | 1.40× | ✓ |
| hmsg | `hmsg.v5` pgo | 8.4 µs | 9.2 µs | 1 |  | 1.26× | ✓ |
| fors | `fors.v0` crate | 280.0 µs | 303.2 µs | 1 | 3.6% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 131.2 µs | 151.1 µs | 1 |  | 2.02× | ✓ |
| fors | `fors.v2` x4keccak | 54.9 µs | 61.8 µs | 1 |  | 4.98× | ✓ |
| fors | `fors.v3` rayon | 199.2 µs | 646.6 µs | 4 |  | 1.32× | ✓ |
| fors | `fors.v4` native | 256.2 µs | 311.6 µs | 1 |  | 0.97× | ✓ |
| fors | `fors.v5` pgo | 248.5 µs | 292.9 µs | 1 |  | 1.04× | ✓ |
| ht_wots | `ht_wots.v0` crate | 7.58 ms | 7.77 ms | 1 | 96.3% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 3.76 ms | 3.81 ms | 1 |  | 2.02× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 1.55 ms | 1.56 ms | 1 |  | 4.99× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 3.13 ms | 10.59 ms | 4 |  | 2.47× | ✓ |
| ht_wots | `ht_wots.v4` native | 7.51 ms | 8.15 ms | 1 |  | 0.94× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 8.21 ms | 8.71 ms | 1 |  | 0.89× | ✓ |
| ht_auth | `ht_auth.v0` crate | 58.7 µs | 69.2 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 28.8 µs | 37.2 µs | 1 |  | 1.84× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 12.1 µs | 17.4 µs | 1 |  | 3.98× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 37.7 µs | 194.0 µs | 4 |  | 1.08× | ✓ |
| ht_auth | `ht_auth.v4` native | 53.4 µs | 62.2 µs | 1 |  | 1.12× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 52.3 µs | 56.6 µs | 1 |  | 1.22× | ✓ |

### SLH-DSA-SHAKE-256s

end-to-end v0 stages: 4.13 ms, best assembled: 879.8 µs (4.69×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 7.3 µs | 8.3 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.3 µs | 1.6 µs | 1 |  | 5.23× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.0 µs | 1.1 µs | 1 |  | 7.38× | ✓ |
| hmsg | `hmsg.v3` native | 8.6 µs | 9.0 µs | 1 |  | 0.92× | ✓ |
| hmsg | `hmsg.v4` lto | 5.3 µs | 6.1 µs | 1 |  | 1.36× | ✓ |
| hmsg | `hmsg.v5` pgo | 6.8 µs | 7.5 µs | 1 |  | 1.11× | ✓ |
| fors | `fors.v0` crate | 296.6 µs | 315.6 µs | 1 | 7.2% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 146.0 µs | 167.2 µs | 1 |  | 1.90× | ✓ |
| fors | `fors.v2` x4keccak | 59.5 µs | 69.2 µs | 1 |  | 4.57× | ✓ |
| fors | `fors.v3` rayon | 220.5 µs | 619.3 µs | 4 |  | 1.35× | ✓ |
| fors | `fors.v4` native | 278.6 µs | 311.9 µs | 1 |  | 1.02× | ✓ |
| fors | `fors.v5` pgo | 263.1 µs | 273.5 µs | 1 |  | 1.17× | ✓ |
| ht_wots | `ht_wots.v0` crate | 3.70 ms | 3.98 ms | 1 | 89.7% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 1.86 ms | 1.92 ms | 1 |  | 2.10× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 763.4 µs | 837.3 µs | 1 |  | 4.76× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 1.85 ms | 5.39 ms | 4 |  | 2.14× | ✓ |
| ht_wots | `ht_wots.v4` native | 3.68 ms | 3.89 ms | 1 |  | 1.04× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 3.69 ms | 3.72 ms | 1 |  | 1.09× | ✓ |
| ht_auth | `ht_auth.v0` crate | 56.4 µs | 62.5 µs | 1 | 1.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 27.9 µs | 31.5 µs | 1 |  | 1.99× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 10.3 µs | 14.6 µs | 1 |  | 4.28× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 72.4 µs | 223.4 µs | 4 |  | 0.72× | ✓ |
| ht_auth | `ht_auth.v4` native | 51.6 µs | 58.0 µs | 1 |  | 1.09× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 50.0 µs | 56.4 µs | 1 |  | 1.12× | ✓ |

### SLH-DSA-SHAKE-256f

end-to-end v0 stages: 8.50 ms, best assembled: 1.99 ms (4.26×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` crate | 13.1 µs | 14.1 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` zerocopy | 1.3 µs | 1.5 µs | 1 |  | 9.50× | ✓ |
| hmsg | `hmsg.v2` rawhmsg | 1.0 µs | 1.1 µs | 1 |  | 12.78× | ✓ |
| hmsg | `hmsg.v3` native | 13.0 µs | 14.4 µs | 1 |  | 0.98× | ✓ |
| hmsg | `hmsg.v4` lto | 9.9 µs | 10.5 µs | 1 |  | 1.35× | ✓ |
| hmsg | `hmsg.v5` pgo | 11.2 µs | 12.9 µs | 1 |  | 1.09× | ✓ |
| fors | `fors.v0` crate | 314.4 µs | 325.4 µs | 1 | 3.7% | 1.00× | ✓ |
| fors | `fors.v1` rawhash | 157.8 µs | 170.7 µs | 1 |  | 1.83× | ✓ |
| fors | `fors.v2` x4keccak | 60.9 µs | 68.6 µs | 1 |  | 4.74× | ✓ |
| fors | `fors.v3` rayon | 238.0 µs | 730.7 µs | 4 |  | 1.20× | ✓ |
| fors | `fors.v4` native | 286.3 µs | 331.1 µs | 1 |  | 0.98× | ✓ |
| fors | `fors.v5` pgo | 294.3 µs | 356.5 µs | 1 |  | 0.91× | ✓ |
| ht_wots | `ht_wots.v0` crate | 8.10 ms | 8.97 ms | 1 | 95.3% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` rawhash | 4.11 ms | 4.71 ms | 1 |  | 1.93× | ✓ |
| ht_wots | `ht_wots.v2` x4keccak | 1.64 ms | 1.77 ms | 1 |  | 5.17× | ✓ |
| ht_wots | `ht_wots.v3` rayon | 3.16 ms | 10.59 ms | 4 |  | 2.86× | ✓ |
| ht_wots | `ht_wots.v4` native | 7.65 ms | 8.30 ms | 1 |  | 1.10× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 8.38 ms | 8.92 ms | 1 |  | 1.02× | ✓ |
| ht_auth | `ht_auth.v0` crate | 60.0 µs | 78.3 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` rawhash | 29.9 µs | 32.5 µs | 1 |  | 2.43× | ✓ |
| ht_auth | `ht_auth.v2` x4keccak | 13.0 µs | 14.6 µs | 1 |  | 5.33× | ✓ |
| ht_auth | `ht_auth.v3` rayon | 35.3 µs | 181.7 µs | 4 |  | 1.28× | ✓ |
| ht_auth | `ht_auth.v4` native | 54.3 µs | 65.4 µs | 1 |  | 1.20× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 53.4 µs | 62.1 µs | 1 |  | 1.26× | ✓ |

