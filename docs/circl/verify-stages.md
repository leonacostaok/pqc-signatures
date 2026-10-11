# CIRCL: verify split into stages (Phase 2 B)

`libs/circl/run.sh stages --out results/circl/stages.jsonl [--budget-ms N] [--params a,b] [--stages x,y]`

## How the internals were reached

CIRCL keeps all ML-DSA arithmetic in Go `internal` packages (`sign/mldsa/mldsa44/internal`,
`sign/internal/dilithium`, `internal/sha3`, `simd/keccakf1600`) and the SLH-DSA building blocks are
unexported, so they cannot be called from another module. The harness therefore **vendors verbatim copies**
of those packages under `libs/circl/vendorcircl/` (BSD-3-Clause `LICENSE` kept, import paths rewritten,
`package internal` renamed to `mldsa44i`/`mldsa65i`/`mldsa87i`, upstream `scheme.go` dropped from slhdsa)
and adds one file per package, `stages.go`, with the stage entry points and the alternatives. Everything
else is unchanged upstream v1.6.5 code, including the AVX2 assembly, so `<stage>.v0` is CIRCL's own
implementation of that stage. `vectors`, `bench` and `crossverify` still use the upstream module; the
vendored tree is only used by `stages`, by `validate`'s `verify.total`/`verify.total_best` variants and by
`memory`. The vendored code reproduces `common/reference.json` and the v0 pipeline verifies the reference
signatures (checked at start-up of every `stages` run).

Stage inputs are precomputed from the previous v0 stages on the reference (pk, msg, sig, empty ctx);
only the stage itself is in the timed region; canonical outputs are hashed outside it. Every alternative's
canonical output is compared with v0's on every run (`match`), and `hint_check`/`ht_auth`/`total*` must
also return true. The builds are the same four binaries as in Phase 1; `run.sh stages` runs them in
sequence and each emits only its variants (`amd64v3`, `pgo`, `purego` variants = v0 code path in that build).

## ML-DSA stages and alternatives

| stage | v0 (CIRCL) | alternatives |
|---|---|---|
| `decode` | `DecodePk`: copy rho + `UnpackT1`; `DecodeSig`: `unpackedSignature.Unpack` (c~, z with `Exceeds(gamma1-beta)`, strict `UnpackHint`) | v1 **cached-pk**: pkDecode cached per key (what `PublicKey` stores), only sigDecode. v2 **fused-z**: own unpack loop with the infinity-norm test fused into the bit-unpacking (one pass, early exit) instead of CIRCL's unpack-then-`Exceeds`; the hint decoder is CIRCL's. v3 amd64v3, v4 pgo. (no purego: the stage has no assembly except `Exceeds`.) |
| `mu` | `Tr` = SHAKE256(pk, 64), `Mu` = SHAKE256(tr \|\| 0 \|\| len(ctx) \|\| ctx \|\| M, 64) with CIRCL `internal/sha3` | v1 **cached-tr** (tr per key, as `PublicKey` caches it). v2 **stdlib-sha3**: Go `crypto/sha3` SHAKE256 (assembly Keccak on amd64) for both hashes. v3 **midstate**: SHAKE state with tr \|\| 0 \|\| len(ctx) \|\| ctx pre-absorbed per (key, ctx), cloned per message. v4 amd64v3, v5 pgo. |
| `expandA` | `Mat.Derive`: 4 SHAKE128 streams at a time on the AVX2 4-way Keccak-f1600 | v1 **scalar-1way**: same binary, `PolyDeriveUniform` one stream at a time (isolates the x4 gain). v2 **purego** build (no x4 at all). v3 **parallel-rows**: K goroutines, one row each, x4 inside the row. v4 **cached-A**: A^ cached per key (the stage becomes a pointer reuse; included because it is what CIRCL's `PublicKey.Unpack` does and what `total_best` uses). v5 amd64v3. |
| `w_approx` | NTT(z); `PolyDotHat` rows; `MulBy2toD` + NTT(t1); `PolyDeriveUniformBall` + NTT(c); `MulHat`; `Sub`; `ReduceLe2Q`; `InvNTT`; `NormalizeAssumingLe2Q` (AVX2 NTT/pointwise) | v1 **purego** (generic NTT). v2 **cached-t1hat**: NTT(t1 2^d) precomputed per key (saves K forward NTTs). v3 **parallel-rows**: K rows (dot product, c t1 term, Sub, InvNTT) on goroutines, NTT(z)/NTT(c) shared. v4 amd64v3, v5 pgo. |
| `hint_check` | `Exceeds`, `VecK.UseHint` (vector `Decompose` + correction), `PackW1`, SHAKE256(mu \|\| w1), compare | v1 **fused-usehint-pack**: scalar decompose + hint correction per coefficient written straight into the w1Encode buffer (no decomposed / w1 vectors; own `useHintScalar`, since CIRCL's scalar `useHint` only covers gamma2=(q-1)/32). v2 **stdlib-sha3** for the challenge hash. v3 amd64v3, v4 pgo. (no purego: only ML-DSA-65/87's `PackLe16` has assembly here.) |

Canonical outputs: `decode` = SHA-256(c~); `mu` = SHA-256(mu); `expandA` = SHA-256 of A^ as u32 LE in [0,q)
row-major (CIRCL stores exactly the rejection-sampled NTT-domain values, so no conversion); `w_approx` =
SHA-256 of w' as u32 LE in [0,q) (CIRCL's `NormalizeAssumingLe2Q` output is already in [0,q) and in the
normal domain, the Montgomery factors cancel between `MulHat` and `InvNTT`); `hint_check` = SHA-256 of
w1Encode(w1') (`PackW1` = FIPS 204 w1Encode: 6-bit for ML-DSA-44, 4-bit for 65/87).

`total` = DecodePk+DecodeSig -> Tr+Mu -> ExpandA -> WApprox -> HintCheck (the work of `UnmarshalBinary` +
`Verify`). `total_best` = per-(key, ctx) cache of pkDecode, tr, A^, NTT(t1 2^d) and the mu midstate (built
untimed, rebuilt when the key or ctx changes), then fused z decode (decode.v2), midstate mu (mu.v3),
cached A (expandA.v4), cached t1hat (w_approx.v2), fused hint/pack (hint_check.v1). It is a static choice
made from the development numbers; the parallel-rows variants were never faster at these sizes (goroutine
hand-off costs a few microseconds, the whole stage costs 10-60 us) and are excluded.

## SLH-DSA stages and alternatives

| stage | v0 (CIRCL) | alternatives |
|---|---|---|
| `hmsg` | `signature.fromBytes` (R, k FORS pairs with a auth nodes each, d hypertree layers), `params.HashMsg` (SHA-256 + MGF1-SHA-256/512 or SHAKE256), `parseMsg` | v1 purego (SHA2 sets lose the stdlib SHA-256 assembly; SHAKE sets are unaffected because CIRCL's Keccak is pure Go). v2 **lazy-parse**: length check + slice R only; the structure parse (hundreds of small slice headers) is deferred. v3 **stdlib-sha3** (SHAKE sets only; SHA2 sets have no second H_msg backend, so no line). v4 amd64v3, v5 pgo. |
| `fors` | `forsPkFromSig` on CIRCL's hasher `state` (F, H, T with the fixed `PK.seed \|\| pad \|\| ADRS \|\| msg` input buffers) | v1 purego. v2 **parallel-trees**: the k tree roots on min(k, GOMAXPROCS) goroutines with separate states, T over the roots sequential. v3 **alt-hash**: SHA2 sets: SHA-256/512 **midstate** with the first block `PK.seed \|\| toByte(0, 64-n or 128-n)` compressed once and restored per call via `encoding.BinaryUnmarshaler` (one compression less for every F/H/T call); SHAKE sets: Go `crypto/sha3` SHAKE256 backend. v4 amd64v3, v5 pgo. |
| `ht_wots` | d x `wotsPkFromSig` (given each layer's input message) | v1 purego, v2 **parallel-layers** (min(d, GOMAXPROCS) goroutines, separate states), v3 alt-hash (as above, for F and T), v4 amd64v3, v5 pgo. |
| `ht_auth` | d x the auth-path half of `xmssPkFromSig` (given each layer's WOTS+ pk) + `bytes.Equal` with PK.root | v1 purego, v2 parallel-layers, v3 alt-hash (for H), v4 amd64v3, v5 pgo. |

Canonical outputs: `hmsg` = SHA-256(digest, m bytes); `fors` = SHA-256(PK_FORS); `ht_wots` = SHA-256 of the d
WOTS+ public keys (n bytes each, layer 0 first); `ht_auth` = SHA-256 of the d layer roots.

`total` = parse -> HashMsg -> forsPkFromSig -> d x (wots pk, auth path) -> compare, the work of
`slhdsa.Verify`. `total_best` = lazy parse, then for **SHA2 sets** the midstate hashers (fors/ht_wots/ht_auth
v3), for **SHAKE sets** CIRCL's own hashers (the stdlib SHA-3 backend measured 1.0x, so v0 is kept);
layers sequential. The parallel-layer variants should win on a quiet machine (d = 7..22 independent layers)
but could not be assessed on the shared box.

## Preliminary conclusion (noisy shared box, `--budget-ms 150`, 4 params)

- ML-DSA: `expandA` is the biggest single stage (18 us of 42 us for ML-DSA-44, 64 us of 107 us for 87) and the
  4-way Keccak is worth 2.3x over scalar sampling; caching A per key removes it entirely. `mu` midstate is
  8-16x over hashing pk again; `cached-t1hat` gives 1.2x on `w_approx`; the fused UseHint+pack gives 1.5x on
  ML-DSA-44 (6-bit path) and ~1.05x on 87 (CIRCL's 4-bit path uses AVX2 `PackLe16`). `purego` costs 2.3x on
  expandA and 4x on w_approx. The stdlib SHA-3 backend is not faster than CIRCL's pure-Go Keccak for these
  short inputs. `total_best` is 2.7x (44) / 3.9x (87) faster than `total`.
- SLH-DSA SHA2: the SHA-2 midstate is the real win: 1.7x on `fors`/`ht_wots` (F/T calls with 16-byte inputs
  go from two compressions to one) and 3.2x on `ht_auth` (H); `total_best` is 1.7x `total` for SHA2-128f.
  `purego` costs 2.5x (stdlib SHA-256 assembly gone).
- SLH-DSA SHAKE: no alternative helps single-threaded; CIRCL's Keccak is pure Go and the stdlib's assembly
  Keccak is not faster for 136-byte inputs. Only parallelism can help here.
- `lazy-parse` removes 5-12x of the (small) `hmsg` cost: CIRCL's `fromBytes` allocates one slice header per
  FORS auth node and per hypertree layer.

<!-- RESULTS -->

_Preliminary numbers: `--budget-ms 150`, shared 4-core box, 4 params. Speedup = v0 median / variant median; `total` vs `total_best` listed last._


**ML-DSA-44**

| stage | variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | speedup vs v0 | match |
|---|---|---|---:|---:|---:|---:|---:|---|
| decode | decode.v0 | circl | 1 | 2.74 | 3.38 | 0.52 | 1.00x | True |
| decode | decode.v1 | cached-pk | 1 | 1.92 | 2.77 | 0.90 | 1.42x | True |
| decode | decode.v2 | fused-z | 1 | 2.41 | 3.40 | 0.95 | 1.14x | True |
| decode | decode.v3 | amd64v3 | 1 | 5.88 | 5.06 | 1.01 | 0.47x | True |
| decode | decode.v4 | pgo | 1 | 2.79 | 3.11 | 0.58 | 0.98x | True |
| mu | mu.v0 | circl | 1 | 4.29 | 4.93 | 0.95 | 1.00x | True |
| mu | mu.v1 | cached-tr | 1 | 1.00 | 1.12 | 1.05 | 4.28x | True |
| mu | mu.v2 | stdlib-sha3 | 1 | 4.74 | 6.37 | 0.97 | 0.91x | True |
| mu | mu.v3 | midstate | 1 | 0.51 | 0.93 | 1.07 | 8.38x | True |
| mu | mu.v4 | amd64v3 | 1 | 3.98 | 4.26 | 1.02 | 1.08x | True |
| mu | mu.v5 | pgo | 1 | 4.37 | 4.67 | 1.03 | 0.98x | True |
| expandA | expandA.v0 | circl-x4 | 1 | 18.61 | 24.89 | 0.75 | 1.00x | True |
| expandA | expandA.v1 | scalar-1way | 1 | 42.18 | 50.65 | 0.75 | 0.44x | True |
| expandA | expandA.v2 | purego | 1 | 44.25 | 62.70 | 0.79 | 0.42x | True |
| expandA | expandA.v3 | parallel-rows | 4 | 20.33 | 31.51 | 0.97 | 0.92x | True |
| expandA | expandA.v4 | cached-A | 1 | 0.03 | 0.12 | 3.99 | 744.24x | True |
| expandA | expandA.v5 | amd64v3 | 1 | 18.29 | 19.65 | 0.93 | 1.02x | True |
| w_approx | w_approx.v0 | circl | 1 | 9.04 | 10.61 | 1.00 | 1.00x | True |
| w_approx | w_approx.v1 | purego | 1 | 37.85 | 46.93 | 1.00 | 0.24x | True |
| w_approx | w_approx.v2 | cached-t1hat | 1 | 7.43 | 9.69 | 0.90 | 1.22x | True |
| w_approx | w_approx.v3 | parallel-rows | 4 | 20.32 | 36.65 | 1.12 | 0.44x | True |
| w_approx | w_approx.v4 | amd64v3 | 1 | 8.89 | 10.33 | 1.01 | 1.02x | True |
| w_approx | w_approx.v5 | pgo | 1 | 9.07 | 9.54 | 1.01 | 1.00x | True |
| hint_check | hint_check.v0 | circl | 1 | 9.17 | 10.18 | 0.63 | 1.00x | True |
| hint_check | hint_check.v1 | fused-usehint-pack | 1 | 6.03 | 7.67 | 0.52 | 1.52x | True |
| hint_check | hint_check.v2 | stdlib-sha3 | 1 | 6.59 | 7.94 | 0.88 | 1.39x | True |
| hint_check | hint_check.v3 | amd64v3 | 1 | 6.26 | 6.85 | 0.92 | 1.47x | True |
| hint_check | hint_check.v4 | pgo | 1 | 6.11 | 7.01 | 0.71 | 1.50x | True |
| total | total | v0-pipeline | 1 | 41.77 | 47.44 | 0.95 | (reference) | True |
| total_best | total_best | best-pipeline | 1 | 15.67 | 18.56 | 0.97 | 0.00x vs total | True |

**ML-DSA-87**

| stage | variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | speedup vs v0 | match |
|---|---|---|---:|---:|---:|---:|---:|---|
| decode | decode.v0 | circl | 1 | 5.14 | 6.26 | 0.98 | 1.00x | True |
| decode | decode.v1 | cached-pk | 1 | 3.38 | 4.19 | 0.96 | 1.52x | True |
| decode | decode.v2 | fused-z | 1 | 6.84 | 6.66 | 0.99 | 0.75x | True |
| decode | decode.v3 | amd64v3 | 1 | 5.12 | 5.54 | 0.98 | 1.00x | True |
| decode | decode.v4 | pgo | 1 | 8.17 | 8.68 | 0.99 | 0.63x | True |
| mu | mu.v0 | circl | 1 | 8.08 | 9.06 | 0.96 | 1.00x | True |
| mu | mu.v1 | cached-tr | 1 | 0.51 | 0.79 | 1.08 | 15.76x | True |
| mu | mu.v2 | stdlib-sha3 | 1 | 8.84 | 10.51 | 0.57 | 0.91x | True |
| mu | mu.v3 | midstate | 1 | 0.50 | 0.67 | 0.98 | 16.13x | True |
| mu | mu.v4 | amd64v3 | 1 | 7.51 | 7.99 | 1.00 | 1.08x | True |
| mu | mu.v5 | pgo | 1 | 8.11 | 9.41 | 0.99 | 1.00x | True |
| expandA | expandA.v0 | circl-x4 | 1 | 63.78 | 68.84 | 0.63 | 1.00x | True |
| expandA | expandA.v1 | scalar-1way | 1 | 148.18 | 155.85 | 0.82 | 0.43x | True |
| expandA | expandA.v2 | purego | 1 | 143.18 | 188.80 | 1.00 | 0.45x | True |
| expandA | expandA.v3 | parallel-rows | 4 | 90.93 | 99.95 | 0.97 | 0.70x | True |
| expandA | expandA.v4 | cached-A | 1 | 0.03 | 0.27 | 9.06 | 2551.32x | True |
| expandA | expandA.v5 | amd64v3 | 1 | 63.94 | 70.10 | 0.57 | 1.00x | True |
| w_approx | w_approx.v0 | circl | 1 | 18.86 | 19.93 | 1.01 | 1.00x | True |
| w_approx | w_approx.v1 | purego | 1 | 81.03 | 111.15 | 1.00 | 0.23x | True |
| w_approx | w_approx.v2 | cached-t1hat | 1 | 15.52 | 16.27 | 1.01 | 1.22x | True |
| w_approx | w_approx.v3 | parallel-rows | 4 | 28.95 | 49.28 | 1.23 | 0.65x | True |
| w_approx | w_approx.v4 | amd64v3 | 1 | 18.67 | 19.92 | 0.61 | 1.01x | True |
| w_approx | w_approx.v5 | pgo | 1 | 18.85 | 19.70 | 1.00 | 1.00x | True |
| hint_check | hint_check.v0 | circl | 1 | 8.58 | 10.38 | 0.77 | 1.00x | True |
| hint_check | hint_check.v1 | fused-usehint-pack | 1 | 8.12 | 8.66 | 0.98 | 1.06x | True |
| hint_check | hint_check.v2 | stdlib-sha3 | 1 | 8.65 | 9.19 | 0.97 | 0.99x | True |
| hint_check | hint_check.v3 | amd64v3 | 1 | 8.21 | 9.54 | 0.63 | 1.05x | True |
| hint_check | hint_check.v4 | pgo | 1 | 8.18 | 8.62 | 1.01 | 1.05x | True |
| total | total | v0-pipeline | 1 | 106.77 | 111.94 | 1.00 | (reference) | True |
| total_best | total_best | best-pipeline | 1 | 27.08 | 28.45 | 1.00 | 0.00x vs total | True |

**SLH-DSA-SHA2-128f**

| stage | variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | speedup vs v0 | match |
|---|---|---|---:|---:|---:|---:|---:|---|
| hmsg | hmsg.v0 | circl | 1 | 7.88 | 15.81 | 1.16 | 1.00x | True |
| hmsg | hmsg.v1 | purego | 1 | 7.00 | 16.59 | 1.05 | 1.13x | True |
| hmsg | hmsg.v2 | lazy-parse | 1 | 1.41 | 2.12 | 1.12 | 5.57x | True |
| hmsg | hmsg.v4 | amd64v3 | 1 | 4.97 | 17.92 | 1.01 | 1.58x | True |
| hmsg | hmsg.v5 | pgo | 1 | 5.33 | 16.90 | 1.38 | 1.48x | True |
| fors | fors.v0 | circl | 1 | 100.50 | 108.17 | 0.68 | 1.00x | True |
| fors | fors.v1 | purego | 1 | 255.72 | 268.59 | 0.95 | 0.39x | True |
| fors | fors.v2 | parallel-trees | 4 | 108.58 | 176.05 | 1.30 | 0.93x | True |
| fors | fors.v3 | alt-hash | 1 | 57.04 | 64.26 | 0.81 | 1.76x | True |
| fors | fors.v4 | amd64v3 | 1 | 101.15 | 106.63 | 0.41 | 0.99x | True |
| fors | fors.v5 | pgo | 1 | 115.03 | 176.48 | 1.05 | 0.87x | True |
| ht_wots | ht_wots.v0 | circl | 1 | 2,639.58 | 2,652.89 | 0.99 | 1.00x | True |
| ht_wots | ht_wots.v1 | purego | 1 | 6,801.05 | 6,900.23 | 1.00 | 0.39x | True |
| ht_wots | ht_wots.v2 | parallel-layers | 4 | 2,655.80 | 2,685.11 | 0.99 | 0.99x | True |
| ht_wots | ht_wots.v3 | alt-hash | 1 | 1,590.88 | 1,730.89 | 0.99 | 1.66x | True |
| ht_wots | ht_wots.v4 | amd64v3 | 1 | 2,647.20 | 2,667.00 | 0.66 | 1.00x | True |
| ht_wots | ht_wots.v5 | pgo | 1 | 3,380.78 | 3,968.18 | 0.74 | 0.78x | True |
| ht_auth | ht_auth.v0 | circl | 1 | 54.96 | 50.86 | 0.86 | 1.00x | True |
| ht_auth | ht_auth.v1 | purego | 1 | 86.84 | 96.31 | 0.95 | 0.63x | True |
| ht_auth | ht_auth.v2 | parallel-layers | 4 | 31.23 | 50.17 | 1.13 | 1.76x | True |
| ht_auth | ht_auth.v3 | alt-hash | 1 | 17.42 | 25.02 | 0.90 | 3.16x | True |
| ht_auth | ht_auth.v4 | amd64v3 | 1 | 29.34 | 32.08 | 0.92 | 1.87x | True |
| ht_auth | ht_auth.v5 | pgo | 1 | 34.01 | 59.91 | 1.01 | 1.62x | True |
| total | total | v0-pipeline | 1 | 2,779.42 | 2,795.98 | 0.91 | (reference) | True |
| total_best | total_best | best-pipeline | 1 | 1,663.23 | 1,685.99 | 0.97 | 0.00x vs total | True |

**SLH-DSA-SHAKE-128f**

| stage | variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | speedup vs v0 | match |
|---|---|---|---:|---:|---:|---:|---:|---|
| hmsg | hmsg.v0 | circl | 1 | 6.73 | 17.48 | 1.35 | 1.00x | True |
| hmsg | hmsg.v1 | purego | 1 | 6.04 | 15.75 | 1.03 | 1.11x | True |
| hmsg | hmsg.v2 | lazy-parse | 1 | 0.57 | 0.97 | 1.11 | 11.80x | True |
| hmsg | hmsg.v3 | stdlib-sha3 | 1 | 4.54 | 13.45 | 1.37 | 1.48x | True |
| hmsg | hmsg.v4 | amd64v3 | 1 | 7.24 | 30.02 | 0.99 | 0.93x | True |
| hmsg | hmsg.v5 | pgo | 1 | 8.56 | 26.11 | 0.97 | 0.79x | True |
| fors | fors.v0 | circl | 1 | 112.73 | 160.21 | 0.72 | 1.00x | True |
| fors | fors.v1 | purego | 1 | 114.71 | 138.09 | 0.99 | 0.98x | True |
| fors | fors.v2 | parallel-trees | 4 | 175.51 | 207.12 | 1.00 | 0.64x | True |
| fors | fors.v3 | alt-hash | 1 | 110.57 | 133.51 | 0.98 | 1.02x | True |
| fors | fors.v4 | amd64v3 | 1 | 101.23 | 126.01 | 0.98 | 1.11x | True |
| fors | fors.v5 | pgo | 1 | 124.08 | 163.96 | 0.74 | 0.91x | True |
| ht_wots | ht_wots.v0 | circl | 1 | 2,999.47 | 3,182.28 | 1.00 | 1.00x | True |
| ht_wots | ht_wots.v1 | purego | 1 | 3,157.10 | 3,428.50 | 1.00 | 0.95x | True |
| ht_wots | ht_wots.v2 | parallel-layers | 4 | 3,092.41 | 3,338.20 | 0.98 | 0.97x | True |
| ht_wots | ht_wots.v3 | alt-hash | 1 | 3,025.59 | 3,038.18 | 0.99 | 0.99x | True |
| ht_wots | ht_wots.v4 | amd64v3 | 1 | 2,802.59 | 2,812.89 | 0.89 | 1.07x | True |
| ht_wots | ht_wots.v5 | pgo | 1 | 3,172.95 | 3,189.81 | 0.99 | 0.95x | True |
| ht_auth | ht_auth.v0 | circl | 1 | 34.39 | 49.39 | 0.97 | 1.00x | True |
| ht_auth | ht_auth.v1 | purego | 1 | 34.29 | 45.16 | 0.98 | 1.00x | True |
| ht_auth | ht_auth.v2 | parallel-layers | 4 | 57.29 | 70.95 | 0.96 | 0.60x | True |
| ht_auth | ht_auth.v3 | alt-hash | 1 | 32.22 | 38.95 | 0.99 | 1.07x | True |
| ht_auth | ht_auth.v4 | amd64v3 | 1 | 30.07 | 33.93 | 0.91 | 1.14x | True |
| ht_auth | ht_auth.v5 | pgo | 1 | 34.68 | 38.49 | 0.97 | 0.99x | True |
| total | total | v0-pipeline | 1 | 3,110.73 | 3,255.46 | 1.00 | (reference) | True |
| total_best | total_best | best-pipeline | 1 | 3,305.64 | 3,381.66 | 0.97 | 0.00x vs total | True |
