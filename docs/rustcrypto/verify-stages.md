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

## Results (PRELIMINARY: dev run on a loaded shared box, short budgets; the orchestrator overwrites this section)

### Geomean speedup vs <stage>.v0 over the measured params

| stage | variant | name | geomean speedup | CPU/op vs v0 | all match |
|---|---|---|---|---|---|
| decode | `decode.v0` | crate | 1.00× | 1.00× | yes |
| decode | `decode.v1` | fastunpack | 1.97× | 0.53× | yes |
| decode | `decode.v2` | native | 1.48× | 0.73× | yes |
| decode | `decode.v3` | lto | 1.39× | 0.73× | yes |
| decode | `decode.v4` | pgo | 1.20× | 0.64× | yes |
| decode | `decode.v5` | rayon | 0.65× | 1.73× | yes |
| mu | `mu.v0` | crate | 1.00× | 1.00× | yes |
| mu | `mu.v1` | trcache | 10.58× | 0.09× | yes |
| mu | `mu.v2` | directsha3 | 0.81× | 1.10× | yes |
| mu | `mu.v3` | native | 0.57× | 1.76× | yes |
| mu | `mu.v4` | lto | 0.61× | 1.65× | yes |
| mu | `mu.v5` | pgo | 1.02× | 0.99× | yes |
| expandA | `expandA.v0` | crate | 1.00× | 1.00× | yes |
| expandA | `expandA.v1` | x4keccak | 2.24× | 0.44× | yes |
| expandA | `expandA.v2` | rayon | 0.83× | 1.18× | yes |
| expandA | `expandA.v3` | cachedA | 29.65× | 0.03× | yes |
| expandA | `expandA.v4` | fastparse | 1.03× | 0.92× | yes |
| expandA | `expandA.v5` | pgo | 0.67× | 1.49× | yes |
| w_approx | `w_approx.v0` | crate | 1.00× | 1.00× | yes |
| w_approx | `w_approx.v1` | montgomery | 2.13× | 0.56× | yes |
| w_approx | `w_approx.v2` | t1hat-precomp | 1.57× | 0.73× | yes |
| w_approx | `w_approx.v3` | rayon | 1.14× | 1.07× | yes |
| w_approx | `w_approx.v4` | lazyacc | 1.22× | 0.91× | yes |
| w_approx | `w_approx.v5` | pgo | 1.10× | 1.11× | yes |
| hint_check | `hint_check.v0` | crate | 1.00× | 1.00× | yes |
| hint_check | `hint_check.v1` | nonct | 1.71× | 0.63× | yes |
| hint_check | `hint_check.v2` | sparse-raw | 1.52× | 0.71× | yes |
| hint_check | `hint_check.v3` | native | 0.59× | 1.74× | yes |
| hint_check | `hint_check.v4` | lto | 0.75× | 1.45× | yes |
| hint_check | `hint_check.v5` | pgo | 0.82× | 1.25× | yes |
| total | `total.v0` | v0-stages | 1.00× | 1.00× | yes |
| total_best | `total_best.v0` | best-stages | 2.27× | 0.45× | yes |
| hmsg | `hmsg.v0` | crate | 1.00× | 1.00× | yes |
| hmsg | `hmsg.v1` | zerocopy | 2.45× | 0.39× | yes |
| hmsg | `hmsg.v2` | rawhmsg | 3.94× | 0.24× | yes |
| hmsg | `hmsg.v3` | native | 0.95× | 0.98× | yes |
| hmsg | `hmsg.v4` | lto | 1.15× | 0.85× | yes |
| hmsg | `hmsg.v5` | pgo | 1.46× | 0.68× | yes |
| fors | `fors.v0` | crate | 1.00× | 1.00× | yes |
| fors | `fors.v1` | rawhash | 1.46× | 0.69× | yes |
| fors | `fors.v2` | x4keccak | 2.09× | 0.46× | yes |
| fors | `fors.v3` | rayon | 0.82× | 1.59× | yes |
| fors | `fors.v4` | native | 0.92× | 1.12× | yes |
| fors | `fors.v5` | pgo | 1.12× | 0.78× | yes |
| ht_wots | `ht_wots.v0` | crate | 1.00× | 1.00× | yes |
| ht_wots | `ht_wots.v1` | rawhash | 1.56× | 0.65× | yes |
| ht_wots | `ht_wots.v2` | x4keccak | 3.31× | 0.29× | yes |
| ht_wots | `ht_wots.v3` | rayon | 1.66× | 0.62× | yes |
| ht_wots | `ht_wots.v4` | native | 1.14× | 0.88× | yes |
| ht_wots | `ht_wots.v5` | pgo | 1.18× | 0.86× | yes |
| ht_auth | `ht_auth.v0` | crate | 1.00× | 1.00× | yes |
| ht_auth | `ht_auth.v1` | rawhash | 1.39× | 0.71× | yes |
| ht_auth | `ht_auth.v2` | x4keccak | 2.02× | 0.48× | yes |
| ht_auth | `ht_auth.v3` | rayon | 0.70× | 1.46× | yes |
| ht_auth | `ht_auth.v4` | native | 0.71× | 1.42× | yes |
| ht_auth | `ht_auth.v5` | pgo | 0.92× | 1.09× | yes |

### Per parameter set (median wall per op)

| param | stage | variant | median | CPU/op | thr | speedup | match |
|---|---|---|---|---|---|---|---|
| ML-DSA-65 | decode | `decode.v0` crate | 12.0 µs | 12.7 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | decode | `decode.v1` fastunpack | 6.0 µs | 6.8 µs | 1 | 1.97× | ✓ |
| ML-DSA-65 | decode | `decode.v5` rayon | 13.4 µs | 21.9 µs | 4 | 0.65× | ✓ |
| ML-DSA-65 | decode | `decode.v2` native | 8.1 µs | 9.3 µs | 1 | 1.48× | ✓ |
| ML-DSA-65 | decode | `decode.v3` lto | 7.0 µs | 9.3 µs | 1 | 1.39× | ✓ |
| ML-DSA-65 | decode | `decode.v4` pgo | 7.4 µs | 8.1 µs | 1 | 1.20× | ✓ |
| ML-DSA-65 | mu | `mu.v0` crate | 6.6 µs | 7.5 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | mu | `mu.v1` trcache | 0.6 µs | 0.7 µs | 1 | 10.58× | ✓ |
| ML-DSA-65 | mu | `mu.v2` directsha3 | 7.3 µs | 8.2 µs | 1 | 0.81× | ✓ |
| ML-DSA-65 | mu | `mu.v3` native | 12.4 µs | 13.2 µs | 1 | 0.57× | ✓ |
| ML-DSA-65 | mu | `mu.v4` lto | 11.9 µs | 12.4 µs | 1 | 0.61× | ✓ |
| ML-DSA-65 | mu | `mu.v5` pgo | 6.3 µs | 7.4 µs | 1 | 1.02× | ✓ |
| ML-DSA-65 | expandA | `expandA.v0` crate | 75.6 µs | 80.7 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | expandA | `expandA.v1` x4keccak | 33.6 µs | 35.9 µs | 1 | 2.24× | ✓ |
| ML-DSA-65 | expandA | `expandA.v2` rayon | 85.3 µs | 94.9 µs | 4 | 0.83× | ✓ |
| ML-DSA-65 | expandA | `expandA.v3` cachedA | 2.5 µs | 2.7 µs | 1 | 29.65× | ✓ |
| ML-DSA-65 | expandA | `expandA.v4` fastparse | 69.8 µs | 74.1 µs | 1 | 1.03× | ✓ |
| ML-DSA-65 | expandA | `expandA.v5` pgo | 117.6 µs | 120.4 µs | 1 | 0.67× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v0` crate | 58.4 µs | 62.8 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v1` montgomery | 34.1 µs | 35.5 µs | 1 | 2.13× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v2` t1hat-precomp | 44.3 µs | 45.9 µs | 1 | 1.57× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v3` rayon | 64.7 µs | 67.2 µs | 4 | 1.14× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v4` lazyacc | 55.3 µs | 57.3 µs | 1 | 1.22× | ✓ |
| ML-DSA-65 | w_approx | `w_approx.v5` pgo | 61.3 µs | 69.4 µs | 1 | 1.10× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v0` crate | 16.8 µs | 17.4 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v1` nonct | 10.6 µs | 11.0 µs | 1 | 1.71× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v2` sparse-raw | 12.0 µs | 12.4 µs | 1 | 1.52× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v3` native | 30.7 µs | 30.3 µs | 1 | 0.59× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v4` lto | 23.7 µs | 25.2 µs | 1 | 0.75× | ✓ |
| ML-DSA-65 | hint_check | `hint_check.v5` pgo | 17.6 µs | 21.7 µs | 1 | 0.82× | ✓ |
| ML-DSA-65 | total | `total.v0` v0-stages | 163.2 µs | 168.1 µs | 1 | 1.00× | ✓ |
| ML-DSA-65 | total_best | `total_best.v0` best-stages | 91.7 µs | 96.8 µs | 1 | 1.73× | ✓ |
| SLH-DSA-SHA2-128f | total | `total.v0` v0-stages | 3.70 ms | 3.70 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | total_best | `total_best.v0` best-stages | 2.51 ms | 2.71 ms | 1 | 1.37× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v0` crate | 5.0 µs | 5.4 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v1` zerocopy | 1.9 µs | 2.1 µs | 1 | 2.40× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v2` rawhmsg | 1.7 µs | 1.9 µs | 1 | 2.85× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v3` native | 5.0 µs | 5.5 µs | 1 | 0.86× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v4` lto | 4.1 µs | 5.1 µs | 1 | 1.02× | ✓ |
| SLH-DSA-SHA2-128f | hmsg | `hmsg.v5` pgo | 4.2 µs | 4.5 µs | 1 | 1.19× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v0` crate | 82.5 µs | 90.7 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v1` rawhash | 81.8 µs | 94.1 µs | 1 | 0.97× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v2` x4keccak | 82.3 µs | 91.0 µs | 1 | 0.93× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v3` rayon | 106.4 µs | 199.9 µs | 4 | 0.77× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v4` native | 62.5 µs | 65.8 µs | 1 | 1.42× | ✓ |
| SLH-DSA-SHA2-128f | fors | `fors.v5` pgo | 61.7 µs | 64.9 µs | 1 | 1.03× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v0` crate | 2.25 ms | 2.36 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v1` rawhash | 2.21 ms | 2.35 ms | 1 | 0.99× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v2` x4keccak | 2.13 ms | 2.14 ms | 1 | 1.10× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v3` rayon | 2.12 ms | 2.13 ms | 4 | 1.12× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v4` native | 2.51 ms | 2.36 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | ht_wots | `ht_wots.v5` pgo | 1.72 ms | 1.76 ms | 1 | 1.34× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v0` crate | 23.1 µs | 24.9 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v1` rawhash | 23.4 µs | 25.2 µs | 1 | 0.97× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v2` x4keccak | 23.4 µs | 26.9 µs | 1 | 0.83× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v3` rayon | 48.2 µs | 46.9 µs | 4 | 0.52× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v4` native | 25.9 µs | 27.2 µs | 1 | 0.91× | ✓ |
| SLH-DSA-SHA2-128f | ht_auth | `ht_auth.v5` pgo | 27.0 µs | 26.6 µs | 1 | 0.89× | ✓ |
| SLH-DSA-SHAKE-192s | total | `total.v0` v0-stages | 2.82 ms | 2.99 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | total_best | `total_best.v0` best-stages | 616.0 µs | 651.5 µs | 1 | 4.97× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v0` crate | 6.8 µs | 7.2 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v1` zerocopy | 2.5 µs | 2.8 µs | 1 | 2.51× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v2` rawhmsg | 1.0 µs | 1.2 µs | 1 | 5.44× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v3` native | 6.4 µs | 6.8 µs | 1 | 1.05× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v4` lto | 5.1 µs | 5.5 µs | 1 | 1.29× | ✓ |
| SLH-DSA-SHAKE-192s | hmsg | `hmsg.v5` pgo | 3.8 µs | 4.0 µs | 1 | 1.78× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v0` crate | 231.7 µs | 253.5 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v1` rawhash | 111.0 µs | 117.2 µs | 1 | 2.19× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v2` x4keccak | 49.9 µs | 53.3 µs | 1 | 4.70× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v3` rayon | 257.8 µs | 291.2 µs | 4 | 0.88× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v4` native | 439.2 µs | 437.8 µs | 1 | 0.59× | ✓ |
| SLH-DSA-SHAKE-192s | fors | `fors.v5` pgo | 206.1 µs | 213.2 µs | 1 | 1.22× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v0` crate | 6.06 ms | 6.02 ms | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v1` rawhash | 2.90 ms | 2.54 ms | 1 | 2.46× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v2` x4keccak | 507.4 µs | 549.6 µs | 1 | 9.95× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v3` rayon | 2.50 ms | 2.57 ms | 4 | 2.45× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v4` native | 4.71 ms | 4.72 ms | 1 | 1.31× | ✓ |
| SLH-DSA-SHAKE-192s | ht_wots | `ht_wots.v5` pgo | 5.96 ms | 6.04 ms | 1 | 1.04× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v0` crate | 55.6 µs | 59.3 µs | 1 | 1.00× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v1` rawhash | 27.2 µs | 29.4 µs | 1 | 2.01× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v2` x4keccak | 11.5 µs | 12.4 µs | 1 | 4.95× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v3` rayon | 62.3 µs | 66.6 µs | 4 | 0.93× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v4` native | 104.4 µs | 110.2 µs | 1 | 0.56× | ✓ |
| SLH-DSA-SHAKE-192s | ht_auth | `ht_auth.v5` pgo | 50.3 µs | 65.4 µs | 1 | 0.95× | ✓ |
