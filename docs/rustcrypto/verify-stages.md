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

See the preliminary results below. Headlines from the dev run: for ML-DSA, `w_approx.v1 montgomery`
and `hint_check.v1/v2` are 1.5–2× faster than the crate's constant-time u128-Barrett code paths,
`expandA.v1 x4keccak` gains ~1.4×, and `total_best` is roughly 2–3× faster than `total` (part of
that is the stateless decode/expand that the crate recomputes on every `VerifyingKey::decode`). For
SLH-DSA the fused raw hashing alone gives 2–5× on the SHAKE sets (the crate clones a full sponge state
per F/H call) and 1.0–1.1× on SHA2 sets (where the crate already keeps a midstate); 4-lane Keccak adds
another 1.2–1.5× on top for the batchable stages. rayon only pays off for `ht_wots`, whose d layers
are big enough to amortise the pool.

<!-- RESULTS -->

## Results (PRELIMINARY: dev run on a loaded shared box, short budgets; the orchestrator overwrites this section)

### Geomean speedup vs <stage>.v0 over the measured params

| stage | variant | name | geomean speedup | CPU/op vs v0 | all match |
|---|---|---|---|---|---|
| decode | `decode.v0` | crate | 1.00× | 1.00× | yes |
| decode | `decode.v1` | fastunpack | 0.79× | 1.20× | yes |
| decode | `decode.v2` | native | 0.15× | 1.74× | yes |
| decode | `decode.v3` | lto | 0.64× | 0.87× | yes |
| decode | `decode.v4` | pgo | 0.12× | 1.08× | yes |
| decode | `decode.v5` | rayon | 0.41× | 2.80× | yes |
| mu | `mu.v0` | crate | 1.00× | 1.00× | yes |
| mu | `mu.v1` | trcache | 20.25× | 0.05× | yes |
| mu | `mu.v2` | directsha3 | 1.94× | 0.49× | yes |
| mu | `mu.v3` | native | 0.53× | 1.08× | yes |
| mu | `mu.v4` | lto | 3.25× | 0.42× | yes |
| mu | `mu.v5` | pgo | 1.31× | 0.44× | yes |
| expandA | `expandA.v0` | crate | 1.00× | 1.00× | yes |
| expandA | `expandA.v1` | x4keccak | 1.20× | 0.84× | yes |
| expandA | `expandA.v2` | rayon | 0.84× | 1.21× | yes |
| expandA | `expandA.v3` | cachedA | 46.14× | 0.02× | yes |
| expandA | `expandA.v4` | fastparse | 1.80× | 0.57× | yes |
| expandA | `expandA.v5` | pgo | 1.54× | 0.56× | yes |
| w_approx | `w_approx.v0` | crate | 1.00× | 1.00× | yes |
| w_approx | `w_approx.v1` | montgomery | 1.71× | 0.56× | yes |
| w_approx | `w_approx.v2` | t1hat-precomp | 1.38× | 0.72× | yes |
| w_approx | `w_approx.v3` | rayon | 0.87× | 1.16× | yes |
| w_approx | `w_approx.v4` | lazyacc | 1.02× | 0.93× | yes |
| w_approx | `w_approx.v5` | pgo | 1.45× | 1.03× | yes |
| hint_check | `hint_check.v0` | crate | 1.00× | 1.00× | yes |
| hint_check | `hint_check.v1` | nonct | 1.27× | 0.80× | yes |
| hint_check | `hint_check.v2` | sparse-raw | 1.24× | 0.80× | yes |
| hint_check | `hint_check.v3` | native | 0.56× | 1.56× | yes |
| hint_check | `hint_check.v4` | lto | 1.58× | 0.88× | yes |
| hint_check | `hint_check.v5` | pgo | 1.43× | 1.04× | yes |
| total | `total.v0` | v0-stages | 1.00× | 1.00× | yes |
| total_best | `total_best.v0` | best-stages | 1.06× | 1.03× | yes |
| hmsg | `hmsg.v0` | crate | 1.00× | 1.00× | yes |
| hmsg | `hmsg.v1` | zerocopy | 2.72× | 0.38× | yes |
| hmsg | `hmsg.v2` | rawhmsg | 6.48× | 0.27× | yes |
| hmsg | `hmsg.v3` | native | 0.96× | 1.09× | yes |
| hmsg | `hmsg.v4` | lto | 2.49× | 0.71× | yes |
| hmsg | `hmsg.v5` | pgo | 1.44× | 0.85× | yes |
| fors | `fors.v0` | crate | 1.00× | 1.00× | yes |
| fors | `fors.v1` | rawhash | 1.17× | 0.69× | yes |
| fors | `fors.v2` | x4keccak | 1.36× | 0.68× | yes |
| fors | `fors.v3` | rayon | 0.86× | 1.03× | yes |
| fors | `fors.v4` | native | 0.76× | 1.12× | yes |
| fors | `fors.v5` | pgo | 0.89× | 0.81× | yes |
| ht_wots | `ht_wots.v0` | crate | 1.00× | 1.00× | yes |
| ht_wots | `ht_wots.v1` | rawhash | 1.33× | 0.91× | yes |
| ht_wots | `ht_wots.v2` | x4keccak | 1.35× | 1.24× | yes |
| ht_wots | `ht_wots.v3` | rayon | 1.62× | 1.00× | yes |
| ht_wots | `ht_wots.v4` | native | 1.24× | 1.19× | yes |
| ht_wots | `ht_wots.v5` | pgo | 1.66× | 0.87× | yes |
| ht_auth | `ht_auth.v0` | crate | 1.00× | 1.00× | yes |
| ht_auth | `ht_auth.v1` | rawhash | 1.51× | 0.70× | yes |
| ht_auth | `ht_auth.v2` | x4keccak | 1.45× | 0.68× | yes |
| ht_auth | `ht_auth.v3` | rayon | 0.80× | 1.22× | yes |
| ht_auth | `ht_auth.v4` | native | 0.70× | 1.20× | yes |
| ht_auth | `ht_auth.v5` | pgo | 1.19× | 0.83× | yes |

### Per parameter set (median wall per op)

| param | stage | variant | median | CPU/op | thr | speedup | match |
|---|---|---|---|---|---|---|---|
| ML-DSA-65 | decode | `decode.v0` crate | 7.3 µs | 8.8 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | decode | `decode.v1` fastunpack | 12.7 µs | 10.6 µs | 1 | 0.79× | ✓ |
| ML-DSA-65 | decode | `decode.v5` rayon | 23.8 µs | 24.7 µs | 4 | 0.41× | ✓ |
| ML-DSA-65 | decode | `decode.v2` native | 15.9 µs | 15.4 µs | 1 | 0.15× | ✓ |
| ML-DSA-65 | decode | `decode.v3` lto | 6.9 µs | 7.7 µs | 1 | 0.64× | ✓ |
| ML-DSA-65 | decode | `decode.v4` pgo | 7.4 µs | 9.5 µs | 1 | 0.12× | ✓ |
| ML-DSA-65 | mu | `mu.v0` crate | 16.0 µs | 16.7 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | mu | `mu.v1` trcache | 0.6 µs | 0.8 µs | 1 | 20.25× | ✓ |
| ML-DSA-65 | mu | `mu.v2` directsha3 | 7.3 µs | 8.1 µs | 1 | 1.94× | ✓ |
| ML-DSA-65 | mu | `mu.v3` native | 17.0 µs | 17.9 µs | 1 | 0.53× | ✓ |
| ML-DSA-65 | mu | `mu.v4` lto | 6.4 µs | 7.0 µs | 1 | 3.25× | ✓ |
| ML-DSA-65 | mu | `mu.v5` pgo | 6.5 µs | 7.4 µs | 1 | 1.31× | ✓ |
| ML-DSA-65 | expandA | `expandA.v0` crate | 140.1 µs | 136.9 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | expandA | `expandA.v1` x4keccak | 108.1 µs | 114.3 µs | 1 | 1.20× | ✓ |
| ML-DSA-65 | expandA | `expandA.v2` rayon | 161.9 µs | 165.5 µs | 4 | 0.84× | ✓ |
| ML-DSA-65 | expandA | `expandA.v3` cachedA | 2.5 µs | 2.9 µs | 1 | 46.14× | ✓ |
| ML-DSA-65 | expandA | `expandA.v4` fastparse | 70.4 µs | 78.6 µs | 1 | 1.80× | ✓ |
| ML-DSA-65 | expandA | `expandA.v5` pgo | 70.9 µs | 76.8 µs | 1 | 1.54× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v0` crate | 58.7 µs | 66.8 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v1` montgomery | 34.2 µs | 37.6 µs | 1 | 1.71× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v2` t1hat-precomp | 44.5 µs | 48.4 µs | 1 | 1.38× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v3` rayon | 66.3 µs | 77.6 µs | 4 | 0.87× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v4` lazyacc | 55.4 µs | 62.2 µs | 1 | 1.02× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v5` pgo | 61.0 µs | 69.0 µs | 1 | 1.45× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v0` crate | 16.9 µs | 19.4 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v1` nonct | 14.8 µs | 15.6 µs | 1 | 1.27× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v2` sparse-raw | 12.0 µs | 15.6 µs | 1 | 1.24× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v3` native | 33.1 µs | 30.2 µs | 1 | 0.56× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v4` lto | 16.0 µs | 17.0 µs | 1 | 1.58× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v5` pgo | 17.4 µs | 20.3 µs | 1 | 1.43× | ✓ |
| ML-DSA-65 | total | `total.v0` v0-stages | 164.0 µs | 169.8 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | total_best | `total_best.v0` best-stages | 123.8 µs | 128.6 µs | 1 | 1.41× | ✓ |
| SLH-DSA-SHA2-128f | total | `total.v0` v0-stages | 4.27 ms | 3.36 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | total_best | `total_best.v0` best-stages | 8.34 ms | 4.38 ms | 1 | 0.76× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v0` crate | 5.1 µs | 5.4 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v1` zerocopy | 1.9 µs | 2.1 µs | 1 | 2.62× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v2` rawhmsg | 1.7 µs | 2.0 µs | 1 | 4.13× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v3` native | 5.1 µs | 5.4 µs | 1 | 0.57× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v4` lto | 3.9 µs | 4.5 µs | 1 | 1.84× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v5` pgo | 4.2 µs | 5.4 µs | 1 | 0.73× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v0` crate | 82.8 µs | 96.1 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v1` rawhash | 83.2 µs | 92.7 µs | 1 | 0.91× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v2` x4keccak | 89.5 µs | 99.1 µs | 1 | 0.84× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v3` rayon | 89.5 µs | 95.0 µs | 4 | 0.85× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v4` native | 62.9 µs | 65.4 µs | 1 | 1.78× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v5` pgo | 61.7 µs | 71.2 µs | 1 | 0.90× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v0` crate | 2.11 ms | 2.11 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v1` rawhash | 2.13 ms | 2.13 ms | 1 | 0.92× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v2` x4keccak | 8.19 ms | 4.23 ms | 1 | 0.45× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v3` rayon | 2.20 ms | 2.17 ms | 4 | 0.94× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v4` native | 1.70 ms | 1.70 ms | 1 | 1.70× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v5` pgo | 1.92 ms | 1.78 ms | 1 | 0.81× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v0` crate | 23.3 µs | 25.2 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v1` rawhash | 23.4 µs | 25.4 µs | 1 | 1.04× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v2` x4keccak | 25.4 µs | 28.0 µs | 1 | 0.94× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v3` rayon | 30.1 µs | 33.5 µs | 4 | 0.76× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v4` native | 17.9 µs | 19.0 µs | 1 | 1.61× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v5` pgo | 17.6 µs | 19.5 µs | 1 | 1.06× | ✓ |
| SLH-DSA-SHAKE-192s | total | `total.v0` v0-stages | 5.52 ms | 3.37 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | total_best | `total_best.v0` best-stages | 3.92 ms | 3.77 ms | 1 | 1.11× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v0` crate | 4.4 µs | 5.8 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v1` zerocopy | 1.3 µs | 2.0 µs | 1 | 2.82× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v2` rawhmsg | 1.0 µs | 1.1 µs | 1 | 10.18× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v3` native | 6.5 µs | 6.9 µs | 1 | 1.61× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v4` lto | 3.3 µs | 3.5 µs | 1 | 3.37× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v5` pgo | 3.8 µs | 4.1 µs | 1 | 2.85× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v0` crate | 230.5 µs | 239.9 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v1` rawhash | 111.5 µs | 119.3 µs | 1 | 1.51× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v2` x4keccak | 99.7 µs | 107.7 µs | 1 | 2.19× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v3` rayon | 237.0 µs | 255.1 µs | 4 | 0.86× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v4` native | 440.7 µs | 445.1 µs | 1 | 0.32× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v5` pgo | 207.5 µs | 214.0 µs | 1 | 0.87× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v0` crate | 10.56 ms | 2.85 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v1` rawhash | 2.98 ms | 2.33 ms | 1 | 1.92× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v2` x4keccak | 1.94 ms | 2.19 ms | 1 | 4.00× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v3` rayon | 2.50 ms | 2.79 ms | 4 | 2.79× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v4` native | 8.97 ms | 4.96 ms | 1 | 0.91× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v5` pgo | 2.52 ms | 2.52 ms | 1 | 3.42× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v0` crate | 56.4 µs | 59.2 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v1` rawhash | 27.3 µs | 29.0 µs | 1 | 2.20× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v2` x4keccak | 23.3 µs | 24.5 µs | 1 | 2.23× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v3` rayon | 62.3 µs | 65.9 µs | 4 | 0.84× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v4` native | 104.2 µs | 113.0 µs | 1 | 0.30× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v5` pgo | 50.2 µs | 52.3 µs | 1 | 1.33× | ✓ |
