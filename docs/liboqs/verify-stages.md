# liboqs: verify split into stages

`run.sh stages --out results/liboqs/stages.jsonl [--budget-ms N] [--params a,b] [--stages x,y]`

## How the stages are reached

liboqs exposes only whole operations, so the stage entry points are built directly on the vendored
implementations inside `liboqs.a` (`libs/liboqs/src/stages_mldsa.c`, `libs/liboqs/src/stages_slh.c`,
compiled into every flavour's driver binary by `run.sh`):

- **ML-DSA (mldsa-native).** The building blocks that `mld_sign_verify_internal()` (`mldsa/src/sign.c`) calls
  are ordinary exported symbols of the static library (`PQCP_MLDSA_NATIVE_MLDSA<NN>_<X86_64|C>_polyvecl_unpack_z`,
  `_unpack_pk_t1`, `_sig_unpack_hints`, `_polyvec_matrix_expand_eager`, `_poly_challenge`, `_poly_ntt`,
  `_polyvec_matrix_pointwise_montgomery_row_eager`, `_poly_use_hint`, `_polyw1_pack`, ...). `stages_mldsa.c`
  is compiled six times (3 parameter sets x 2 backends) with exactly the `-D`/`-I` flags liboqs uses for the
  corresponding object library, so the `mld_*` names resolve to the library's own objects, and the stage bodies
  are the verify function's statements regrouped; nothing is reimplemented except the two helpers that are
  `static` in `sign.c` (`mld_H` = incremental SHAKE256 through liboqs's `OQS_SHA3_shake256_inc_*`, and the
  pure-mode prefix `0x00 || |ctx| || ctx`). Because `OQS_DIST_BUILD` compiles both backends into the library,
  the portable-C backend is available as a stage alternative in the same binary.
- **AVX2 lane order.** The x86_64 backend keeps NTT-domain polynomials in a custom coefficient order
  (`mld_poly_permute_bitrev_to_custom` / `nttunpack_avx2`). For the canonical `expandA` output the permutation
  is undone; it is recovered at run time by pushing the identity polynomial `0..255` through the library's own
  permutation function (it only moves 32-bit lanes), so no table had to be transcribed.
- **SLH-DSA (slhdsa-c).** `fors_pk_from_sig`, `wots_pk_from_sig`, `xmss_pk_from_sig` and `ht_verify` are `static`.
  `stages_slh.c` therefore `#include`s the flavour's unmodified `slh_dsa.c` with its ten global functions renamed
  through `-D` flags (`slh_verify` -> `stg_slh_verify`, ...): the static helpers become callable from the stage code
  while `liboqs.a` keeps its own copies, and the hash primitives (`prm->h_msg/h_f/h_h/h_t/chain`) remain the
  library's (so the `fasthash` flavour's OpenSSL/AVX2 primitives are picked up automatically). `ht_wots` and
  `ht_auth` are the two halves of slhdsa-c's `xmss_pk_from_sig` loop; the input message of every layer (FORS pk for
  layer 0, previous layer's root otherwise) is produced by an untimed reference pass (`prepare_layers`) using the
  library's own `xmss_pk_from_sig`.

Stage inputs always come from the previous stages computed outside the timed region; a stage call only
recomputes its own output from the state. Each line's `match` is true when (1) the variant's canonical output
equals the output of the library backend with default modes computed in the same process, and (2) for
alternatives, equals the `output_sha256` of the stage's `v0` line written earlier in the same run (`run.sh`
passes it as `--ref`). `total` / `total_best` lines carry `"true"` only if the pipeline accepted the reference
triple and rejected a one-bit-flipped signature. `total_best` is also run through `validate` (387 sigver cases).

Canonical outputs: `decode` SHA-256(c~); `mu` SHA-256(mu); `expandA` SHA-256 of A^ coefficients in [0,q), u32 LE,
row-major k x l x 256 in standard order; `w_approx` SHA-256 of w' in [0,q), u32 LE, k x 256; `hint_check`
SHA-256 of w1Encode(w1'); `hmsg` SHA-256(digest); `fors` SHA-256(PK_FORS); `ht_wots` SHA-256 of the d WOTS+ public
keys (layer 0 first); `ht_auth` SHA-256 of the d layer roots.

## Stage variants

Each stage has `v0` = the library's own code in the default (`dist`) build plus five alternatives. Mechanisms:

| mechanism | what changes | stages |
|---|---|---|
| `lib-c` | the same functions from liboqs's portable C backend objects (generic x86-64 code, no AVX2 asm/intrinsics) | decode, expandA, w_approx, hint_check |
| `openssl-shake` | the SHAKE256 calls go through OpenSSL 3 EVP (`EVP_shake256`, `EVP_DigestFinalXOF`) instead of liboqs's XKCP | mu, hint_check |
| `cached-tr` / `cached-A` / `cached-t1hat` | per-public-key cache (pk compared bytewise on every call) of tr = H(pk), of A^ = ExpandA(rho) and of NTT(t1 2^d); shows the floor for a verifier that sees the same key repeatedly | mu, expandA, w_approx |
| `oneway-shake` | ExpandA with one SHAKE128 stream per matrix entry (`mld_poly_uniform`, nonce i<<8 + j) instead of the 4-way interleaved sampler, then the backend's lane permutation | expandA |
| `xkcp-avx2` | the `native` build *without* re-selecting the AVX512VL callbacks: liboqs's XKCP AVX2 Keccak (and times4 AVX2) instead of the AVX512VL one | mu, expandA, hint_check |
| `march-native`, `clang-native`, `gcc-pgo`, `gcc-lto` | the stage code and library compiled in the respective flavour (see README) | all |
| `fasthash` | patched slhdsa-c hash core: OpenSSL SHA-256/512 block functions + liboqs AVX2 Keccak-f[1600] | SLH-DSA stages |

SLH-DSA stages are pure hash chains with no algorithmic freedom at the FIPS 205 level without rewriting the
tree walk (batched WOTS chains, fused auth hashing); those would be new implementations rather than liboqs
variants, so the SLH-DSA alternatives are the five build/hash-backend flavours (each one changes the generated
code of the hash core, which is where all the time goes). `total_best` for ML-DSA uses the x86_64 backend with
the three per-key caches (`mu.v2 + expandA.v3 + w_approx.v2`); for SLH-DSA it is the `fasthash` pipeline.

## Conclusions (preliminary, noisy shared machine)

ML-DSA-44 verify (~29 us total in the pipeline, same as the public API) splits into roughly expandA 6.6 us,
mu 5.6 us (two SHAKE256 passes: H(pk) dominates), hint_check 4.8 us (one SHAKE256 over mu||w1), w_approx 4.6 us,
decode 0.7 us. Per-key caching removes expandA and the H(pk) half of mu entirely: `total_best` is ~2.3x
faster than `total` (12.9 vs 28.9 us dev numbers). The portable C backend is 3-6x slower for w_approx and about
1.5-2x slower for expandA/hint_check; OpenSSL's SHAKE is a little faster than liboqs's XKCP for the single long
absorb of H(pk) (mu) but slower on hint_check. One-way SHAKE expansion costs 3x the 4-way one. For SLH-DSA the
WOTS stage dominates verification (~50% ht_wots, ~2% ht_auth, FORS ~2%... exact shares in the tables) and only
the hash core matters, which is what `fasthash` and the compiler flavours change.

<!-- RESULTS -->
