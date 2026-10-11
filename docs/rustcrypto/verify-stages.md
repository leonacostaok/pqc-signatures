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
