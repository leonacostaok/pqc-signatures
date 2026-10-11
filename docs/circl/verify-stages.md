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

## Results

Generated by `common/report-phase2.mjs` from `results/circl/stages.jsonl`. Speedup = throughput vs the stage's v0. "coverage" = sum of v0 stage medians / end-to-end v0 total.

### ML-DSA-44

end-to-end v0 stages: 42.0 µs, best assembled: 15.7 µs (2.68×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` circl | 2.8 µs | 3.3 µs | 1 | 6.6% | 1.00× | ✓ |
| decode | `decode.v1` cached-pk | 1.9 µs | 2.8 µs | 1 |  | 1.16× | ✓ |
| decode | `decode.v2` fused-z | 2.4 µs | 2.8 µs | 1 |  | 1.13× | ✓ |
| decode | `decode.v3` amd64v3 | 2.7 µs | 3.4 µs | 1 |  | 0.97× | ✓ |
| decode | `decode.v4` pgo | 2.8 µs | 3.5 µs | 1 |  | 0.91× | ✓ |
| mu | `mu.v0` circl | 4.3 µs | 4.8 µs | 1 | 10.2% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.5 µs | 0.7 µs | 1 |  | 8.40× | ✓ |
| mu | `mu.v2` stdlib-sha3 | 4.7 µs | 6.4 µs | 1 |  | 0.74× | ✓ |
| mu | `mu.v3` midstate | 0.9 µs | 1.1 µs | 1 |  | 5.14× | ✓ |
| mu | `mu.v4` amd64v3 | 4.0 µs | 4.9 µs | 1 |  | 0.95× | ✓ |
| mu | `mu.v5` pgo | 4.4 µs | 6.8 µs | 1 |  | 0.70× | ✓ |
| expandA | `expandA.v0` circl-x4 | 18.4 µs | 21.6 µs | 1 | 43.8% | 1.00× | ✓ |
| expandA | `expandA.v1` scalar-1way | 42.1 µs | 51.3 µs | 1 |  | 0.42× | ✓ |
| expandA | `expandA.v2` purego | 40.0 µs | 42.3 µs | 1 |  | 0.52× | ✓ |
| expandA | `expandA.v3` parallel-rows | 35.3 µs | 57.6 µs | 4 |  | 0.56× | ✓ |
| expandA | `expandA.v4` cached-A | 0.0 µs | 0.2 µs | 1 |  | 710.09× | ✓ |
| expandA | `expandA.v5` amd64v3 | 18.4 µs | 21.7 µs | 1 |  | 1.01× | ✓ |
| w_approx | `w_approx.v0` circl | 9.1 µs | 11.1 µs | 1 | 21.6% | 1.00× | ✓ |
| w_approx | `w_approx.v1` purego | 37.8 µs | 46.1 µs | 1 |  | 0.24× | ✓ |
| w_approx | `w_approx.v2` cached-t1hat | 7.4 µs | 8.3 µs | 1 |  | 1.36× | ✓ |
| w_approx | `w_approx.v3` parallel-rows | 39.2 µs | 54.3 µs | 4 |  | 0.27× | ✓ |
| w_approx | `w_approx.v4` amd64v3 | 8.9 µs | 10.7 µs | 1 |  | 1.04× | ✓ |
| w_approx | `w_approx.v5` pgo | 9.0 µs | 11.5 µs | 1 |  | 0.98× | ✓ |
| hint_check | `hint_check.v0` circl | 6.5 µs | 8.1 µs | 1 | 15.5% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fused-usehint-pack | 6.0 µs | 7.4 µs | 1 |  | 1.09× | ✓ |
| hint_check | `hint_check.v2` stdlib-sha3 | 6.6 µs | 9.2 µs | 1 |  | 0.88× | ✓ |
| hint_check | `hint_check.v3` amd64v3 | 6.3 µs | 7.2 µs | 1 |  | 1.11× | ✓ |
| hint_check | `hint_check.v4` pgo | 6.1 µs | 8.0 µs | 1 |  | 1.00× | ✓ |

### ML-DSA-65

end-to-end v0 stages: 66.8 µs, best assembled: 19.6 µs (3.41×), coverage 98%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` circl | 3.6 µs | 4.7 µs | 1 | 5.4% | 1.00× | ✓ |
| decode | `decode.v1` cached-pk | 2.4 µs | 2.8 µs | 1 |  | 1.67× | ✓ |
| decode | `decode.v2` fused-z | 3.4 µs | 4.9 µs | 1 |  | 0.98× | ✓ |
| decode | `decode.v3` amd64v3 | 3.6 µs | 4.9 µs | 1 |  | 0.96× | ✓ |
| decode | `decode.v4` pgo | 3.7 µs | 5.0 µs | 1 |  | 0.95× | ✓ |
| mu | `mu.v0` circl | 6.2 µs | 6.8 µs | 1 | 9.3% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.5 µs | 0.7 µs | 1 |  | 11.64× | ✓ |
| mu | `mu.v2` stdlib-sha3 | 6.8 µs | 8.5 µs | 1 |  | 0.82× | ✓ |
| mu | `mu.v3` midstate | 0.5 µs | 0.7 µs | 1 |  | 11.96× | ✓ |
| mu | `mu.v4` amd64v3 | 5.8 µs | 7.3 µs | 1 |  | 0.92× | ✓ |
| mu | `mu.v5` pgo | 6.3 µs | 7.7 µs | 1 |  | 0.89× | ✓ |
| expandA | `expandA.v0` circl-x4 | 35.6 µs | 41.4 µs | 1 | 53.3% | 1.00× | ✓ |
| expandA | `expandA.v1` scalar-1way | 80.1 µs | 88.1 µs | 1 |  | 0.47× | ✓ |
| expandA | `expandA.v2` purego | 78.5 µs | 94.4 µs | 1 |  | 0.44× | ✓ |
| expandA | `expandA.v3` parallel-rows | 70.8 µs | 139.3 µs | 4 |  | 0.55× | ✓ |
| expandA | `expandA.v4` cached-A | 0.0 µs | 0.2 µs | 1 |  | 1366.20× | ✓ |
| expandA | `expandA.v5` amd64v3 | 35.5 µs | 41.7 µs | 1 |  | 0.99× | ✓ |
| w_approx | `w_approx.v0` circl | 13.0 µs | 14.2 µs | 1 | 19.4% | 1.00× | ✓ |
| w_approx | `w_approx.v1` purego | 53.6 µs | 64.3 µs | 1 |  | 0.22× | ✓ |
| w_approx | `w_approx.v2` cached-t1hat | 10.6 µs | 12.0 µs | 1 |  | 1.17× | ✓ |
| w_approx | `w_approx.v3` parallel-rows | 49.3 µs | 76.5 µs | 4 |  | 0.27× | ✓ |
| w_approx | `w_approx.v4` amd64v3 | 12.8 µs | 16.5 µs | 1 |  | 0.85× | ✓ |
| w_approx | `w_approx.v5` pgo | 13.0 µs | 15.3 µs | 1 |  | 0.92× | ✓ |
| hint_check | `hint_check.v0` circl | 7.0 µs | 9.5 µs | 1 | 10.4% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fused-usehint-pack | 6.3 µs | 7.6 µs | 1 |  | 1.28× | ✓ |
| hint_check | `hint_check.v2` stdlib-sha3 | 6.9 µs | 8.0 µs | 1 |  | 1.20× | ✓ |
| hint_check | `hint_check.v3` amd64v3 | 6.6 µs | 8.7 µs | 1 |  | 1.08× | ✓ |
| hint_check | `hint_check.v4` pgo | 6.9 µs | 7.8 µs | 1 |  | 1.22× | ✓ |

### ML-DSA-87

end-to-end v0 stages: 110.8 µs, best assembled: 27.1 µs (4.08×), coverage 95%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| decode | `decode.v0` circl | 5.1 µs | 6.0 µs | 1 | 4.6% | 1.00× | ✓ |
| decode | `decode.v1` cached-pk | 3.4 µs | 4.3 µs | 1 |  | 1.44× | ✓ |
| decode | `decode.v2` fused-z | 4.7 µs | 5.3 µs | 1 |  | 1.15× | ✓ |
| decode | `decode.v3` amd64v3 | 5.2 µs | 6.1 µs | 1 |  | 0.97× | ✓ |
| decode | `decode.v4` pgo | 5.2 µs | 6.0 µs | 1 |  | 0.99× | ✓ |
| mu | `mu.v0` circl | 8.1 µs | 9.9 µs | 1 | 7.3% | 1.00× | ✓ |
| mu | `mu.v1` cached-tr | 0.5 µs | 0.7 µs | 1 |  | 16.98× | ✓ |
| mu | `mu.v2` stdlib-sha3 | 8.8 µs | 10.0 µs | 1 |  | 1.00× | ✓ |
| mu | `mu.v3` midstate | 0.5 µs | 0.7 µs | 1 |  | 18.02× | ✓ |
| mu | `mu.v4` amd64v3 | 7.5 µs | 9.1 µs | 1 |  | 1.11× | ✓ |
| mu | `mu.v5` pgo | 8.1 µs | 9.8 µs | 1 |  | 1.04× | ✓ |
| expandA | `expandA.v0` circl-x4 | 64.1 µs | 72.8 µs | 1 | 57.9% | 1.00× | ✓ |
| expandA | `expandA.v1` scalar-1way | 148.7 µs | 163.9 µs | 1 |  | 0.44× | ✓ |
| expandA | `expandA.v2` purego | 144.2 µs | 176.4 µs | 1 |  | 0.41× | ✓ |
| expandA | `expandA.v3` parallel-rows | 76.8 µs | 172.8 µs | 4 |  | 0.86× | ✓ |
| expandA | `expandA.v4` cached-A | 0.0 µs | 0.2 µs | 1 |  | 2360.35× | ✓ |
| expandA | `expandA.v5` amd64v3 | 63.8 µs | 70.1 µs | 1 |  | 1.04× | ✓ |
| w_approx | `w_approx.v0` circl | 18.9 µs | 20.6 µs | 1 | 17.0% | 1.00× | ✓ |
| w_approx | `w_approx.v1` purego | 84.8 µs | 124.2 µs | 1 |  | 0.17× | ✓ |
| w_approx | `w_approx.v2` cached-t1hat | 15.5 µs | 16.7 µs | 1 |  | 1.23× | ✓ |
| w_approx | `w_approx.v3` parallel-rows | 59.6 µs | 96.6 µs | 4 |  | 0.33× | ✓ |
| w_approx | `w_approx.v4` amd64v3 | 18.8 µs | 22.9 µs | 1 |  | 0.89× | ✓ |
| w_approx | `w_approx.v5` pgo | 18.9 µs | 22.5 µs | 1 |  | 0.91× | ✓ |
| hint_check | `hint_check.v0` circl | 8.6 µs | 10.0 µs | 1 | 7.7% | 1.00× | ✓ |
| hint_check | `hint_check.v1` fused-usehint-pack | 8.1 µs | 10.3 µs | 1 |  | 0.98× | ✓ |
| hint_check | `hint_check.v2` stdlib-sha3 | 8.7 µs | 10.1 µs | 1 |  | 0.98× | ✓ |
| hint_check | `hint_check.v3` amd64v3 | 8.2 µs | 8.9 µs | 1 |  | 1.13× | ✓ |
| hint_check | `hint_check.v4` pgo | 8.2 µs | 9.0 µs | 1 |  | 1.13× | ✓ |

### SLH-DSA-SHA2-128s

end-to-end v0 stages: 981.4 µs, best assembled: 576.6 µs (1.70×), coverage 96%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 3.2 µs | 7.8 µs | 1 | 0.3% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 4.5 µs | 8.7 µs | 1 |  | 0.79× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.0 µs | 1.5 µs | 1 |  | 3.85× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 2.8 µs | 6.7 µs | 1 |  | 1.11× | ✓ |
| hmsg | `hmsg.v5` pgo | 2.6 µs | 6.2 µs | 1 |  | 1.15× | ✓ |
| fors | `fors.v0` circl | 79.0 µs | 98.9 µs | 1 | 8.0% | 1.00× | ✓ |
| fors | `fors.v1` purego | 203.2 µs | 231.4 µs | 1 |  | 0.42× | ✓ |
| fors | `fors.v2` parallel-trees | 116.9 µs | 230.1 µs | 4 |  | 0.78× | ✓ |
| fors | `fors.v3` alt-hash | 44.3 µs | 58.3 µs | 1 |  | 1.70× | ✓ |
| fors | `fors.v4` amd64v3 | 79.5 µs | 91.1 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v5` pgo | 84.2 µs | 115.7 µs | 1 |  | 0.88× | ✓ |
| ht_wots | `ht_wots.v0` circl | 832.5 µs | 979.6 µs | 1 | 84.8% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 2.17 ms | 2.35 ms | 1 |  | 0.42× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 541.1 µs | 1.26 ms | 4 |  | 1.77× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 515.1 µs | 590.2 µs | 1 |  | 1.66× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 828.2 µs | 852.9 µs | 1 |  | 1.16× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 942.9 µs | 1.12 ms | 1 |  | 0.90× | ✓ |
| ht_auth | `ht_auth.v0` circl | 27.2 µs | 34.1 µs | 1 | 2.8% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 68.7 µs | 79.8 µs | 1 |  | 0.43× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 51.7 µs | 86.2 µs | 4 |  | 0.57× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 15.6 µs | 21.0 µs | 1 |  | 1.64× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 27.3 µs | 32.2 µs | 1 |  | 1.07× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 29.4 µs | 36.7 µs | 1 |  | 0.97× | ✓ |

### SLH-DSA-SHA2-128f

end-to-end v0 stages: 2.90 ms, best assembled: 1.77 ms (1.64×), coverage 101%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 4.2 µs | 10.0 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 8.7 µs | 13.6 µs | 1 |  | 0.65× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.4 µs | 2.1 µs | 1 |  | 4.03× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 4.1 µs | 9.1 µs | 1 |  | 1.04× | ✓ |
| hmsg | `hmsg.v5` pgo | 4.1 µs | 9.4 µs | 1 |  | 1.04× | ✓ |
| fors | `fors.v0` circl | 104.1 µs | 129.9 µs | 1 | 3.6% | 1.00× | ✓ |
| fors | `fors.v1` purego | 261.4 µs | 284.0 µs | 1 |  | 0.46× | ✓ |
| fors | `fors.v2` parallel-trees | 134.9 µs | 266.8 µs | 4 |  | 0.92× | ✓ |
| fors | `fors.v3` alt-hash | 57.3 µs | 67.2 µs | 1 |  | 1.89× | ✓ |
| fors | `fors.v4` amd64v3 | 102.0 µs | 115.4 µs | 1 |  | 1.14× | ✓ |
| fors | `fors.v5` pgo | 107.8 µs | 144.9 µs | 1 |  | 0.94× | ✓ |
| ht_wots | `ht_wots.v0` circl | 2.78 ms | 3.07 ms | 1 | 95.9% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 6.93 ms | 7.38 ms | 1 |  | 0.42× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 1.35 ms | 3.83 ms | 4 |  | 2.38× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 1.61 ms | 1.73 ms | 1 |  | 1.80× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 2.73 ms | 2.76 ms | 1 |  | 1.12× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 3.06 ms | 3.62 ms | 1 |  | 0.89× | ✓ |
| ht_auth | `ht_auth.v0` circl | 31.0 µs | 42.3 µs | 1 | 1.1% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 76.8 µs | 89.7 µs | 1 |  | 0.46× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 56.6 µs | 95.4 µs | 4 |  | 0.59× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 17.1 µs | 21.3 µs | 1 |  | 1.97× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 29.5 µs | 33.0 µs | 1 |  | 1.27× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 31.8 µs | 43.9 µs | 1 |  | 1.00× | ✓ |

### SLH-DSA-SHA2-192s

end-to-end v0 stages: 1.45 ms, best assembled: 843.6 µs (1.71×), coverage 102%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 5.2 µs | 11.8 µs | 1 | 0.4% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 7.2 µs | 12.0 µs | 1 |  | 0.87× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.2 µs | 2.1 µs | 1 |  | 4.24× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 3.9 µs | 8.9 µs | 1 |  | 1.26× | ✓ |
| hmsg | `hmsg.v5` pgo | 3.4 µs | 8.1 µs | 1 |  | 1.39× | ✓ |
| fors | `fors.v0` circl | 217.8 µs | 240.3 µs | 1 | 15.1% | 1.00× | ✓ |
| fors | `fors.v1` purego | 372.0 µs | 398.5 µs | 1 |  | 0.61× | ✓ |
| fors | `fors.v2` parallel-trees | 157.6 µs | 321.2 µs | 4 |  | 1.44× | ✓ |
| fors | `fors.v3` alt-hash | 80.7 µs | 100.8 µs | 1 |  | 2.38× | ✓ |
| fors | `fors.v4` amd64v3 | 201.9 µs | 224.0 µs | 1 |  | 1.06× | ✓ |
| fors | `fors.v5` pgo | 138.9 µs | 154.6 µs | 1 |  | 1.55× | ✓ |
| ht_wots | `ht_wots.v0` circl | 1.22 ms | 1.35 ms | 1 | 84.1% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 3.17 ms | 3.57 ms | 1 |  | 0.38× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 695.7 µs | 1.74 ms | 4 |  | 1.99× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 730.2 µs | 831.1 µs | 1 |  | 1.63× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 1.24 ms | 1.39 ms | 1 |  | 0.97× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 1.47 ms | 1.82 ms | 1 |  | 0.79× | ✓ |
| ht_auth | `ht_auth.v0` circl | 34.6 µs | 45.1 µs | 1 | 2.4% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 87.0 µs | 101.0 µs | 1 |  | 0.45× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 63.1 µs | 106.1 µs | 4 |  | 0.69× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 19.7 µs | 23.0 µs | 1 |  | 1.98× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 34.3 µs | 38.1 µs | 1 |  | 1.18× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 34.5 µs | 42.7 µs | 1 |  | 1.04× | ✓ |

### SLH-DSA-SHA2-192f

end-to-end v0 stages: 4.33 ms, best assembled: 2.96 ms (1.46×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 4.5 µs | 12.6 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 6.1 µs | 12.9 µs | 1 |  | 0.85× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.3 µs | 2.1 µs | 1 |  | 4.61× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 4.7 µs | 11.8 µs | 1 |  | 1.04× | ✓ |
| hmsg | `hmsg.v5` pgo | 4.9 µs | 11.8 µs | 1 |  | 0.94× | ✓ |
| fors | `fors.v0` circl | 234.7 µs | 284.7 µs | 1 | 5.4% | 1.00× | ✓ |
| fors | `fors.v1` purego | 440.2 µs | 491.2 µs | 1 |  | 0.57× | ✓ |
| fors | `fors.v2` parallel-trees | 198.0 µs | 441.3 µs | 4 |  | 1.26× | ✓ |
| fors | `fors.v3` alt-hash | 92.1 µs | 115.8 µs | 1 |  | 2.46× | ✓ |
| fors | `fors.v4` amd64v3 | 215.3 µs | 233.2 µs | 1 |  | 1.20× | ✓ |
| fors | `fors.v5` pgo | 164.7 µs | 185.9 µs | 1 |  | 1.52× | ✓ |
| ht_wots | `ht_wots.v0` circl | 4.00 ms | 4.75 ms | 1 | 92.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 10.19 ms | 10.68 ms | 1 |  | 0.45× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 1.99 ms | 6.00 ms | 4 |  | 2.35× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 2.47 ms | 2.90 ms | 1 |  | 1.62× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 3.93 ms | 4.15 ms | 1 |  | 1.15× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 4.63 ms | 5.42 ms | 1 |  | 0.91× | ✓ |
| ht_auth | `ht_auth.v0` circl | 37.0 µs | 43.3 µs | 1 | 0.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 97.6 µs | 118.2 µs | 1 |  | 0.37× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 69.3 µs | 123.8 µs | 4 |  | 0.58× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 21.4 µs | 27.3 µs | 1 |  | 1.61× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 36.9 µs | 45.2 µs | 1 |  | 0.95× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 36.8 µs | 40.7 µs | 1 |  | 1.07× | ✓ |

### SLH-DSA-SHA2-256s

end-to-end v0 stages: 2.11 ms, best assembled: 1.27 ms (1.67×), coverage 154%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 6.0 µs | 14.8 µs | 1 | 0.3% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 5.9 µs | 12.8 µs | 1 |  | 0.94× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.2 µs | 2.0 µs | 1 |  | 5.73× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 5.3 µs | 12.5 µs | 1 |  | 1.10× | ✓ |
| hmsg | `hmsg.v5` pgo | 5.1 µs | 12.0 µs | 1 |  | 1.14× | ✓ |
| fors | `fors.v0` circl | 288.0 µs | 311.1 µs | 1 | 13.6% | 1.00× | ✓ |
| fors | `fors.v1` purego | 474.7 µs | 493.7 µs | 1 |  | 0.64× | ✓ |
| fors | `fors.v2` parallel-trees | 181.4 µs | 411.1 µs | 4 |  | 1.62× | ✓ |
| fors | `fors.v3` alt-hash | 126.3 µs | 149.9 µs | 1 |  | 2.11× | ✓ |
| fors | `fors.v4` amd64v3 | 242.3 µs | 253.9 µs | 1 |  | 1.25× | ✓ |
| fors | `fors.v5` pgo | 184.1 µs | 224.3 µs | 1 |  | 1.42× | ✓ |
| ht_wots | `ht_wots.v0` circl | 2.93 ms | 2.70 ms | 1 | 138.7% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 4.84 ms | 5.10 ms | 1 |  | 0.54× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 996.6 µs | 3.21 ms | 4 |  | 2.49× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 1.17 ms | 1.46 ms | 1 |  | 1.88× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 1.87 ms | 1.97 ms | 1 |  | 1.37× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 2.08 ms | 2.56 ms | 1 |  | 1.11× | ✓ |
| ht_auth | `ht_auth.v0` circl | 35.3 µs | 46.1 µs | 1 | 1.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 88.9 µs | 101.7 µs | 1 |  | 0.46× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 72.6 µs | 127.7 µs | 4 |  | 0.61× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 20.0 µs | 27.9 µs | 1 |  | 1.59× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 35.0 µs | 40.9 µs | 1 |  | 1.14× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 35.1 µs | 38.8 µs | 1 |  | 1.21× | ✓ |

### SLH-DSA-SHA2-256f

end-to-end v0 stages: 4.17 ms, best assembled: 2.50 ms (1.67×), coverage 100%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 6.8 µs | 14.6 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 7.6 µs | 15.6 µs | 1 |  | 0.87× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.2 µs | 2.0 µs | 1 |  | 6.23× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 4.2 µs | 10.9 µs | 1 |  | 1.31× | ✓ |
| hmsg | `hmsg.v5` pgo | 4.3 µs | 11.5 µs | 1 |  | 1.31× | ✓ |
| fors | `fors.v0` circl | 302.9 µs | 328.4 µs | 1 | 7.3% | 1.00× | ✓ |
| fors | `fors.v1` purego | 513.4 µs | 578.9 µs | 1 |  | 0.56× | ✓ |
| fors | `fors.v2` parallel-trees | 182.7 µs | 401.9 µs | 4 |  | 1.71× | ✓ |
| fors | `fors.v3` alt-hash | 112.5 µs | 140.0 µs | 1 |  | 2.37× | ✓ |
| fors | `fors.v4` amd64v3 | 252.4 µs | 267.9 µs | 1 |  | 1.23× | ✓ |
| fors | `fors.v5` pgo | 210.2 µs | 258.2 µs | 1 |  | 1.27× | ✓ |
| ht_wots | `ht_wots.v0` circl | 3.81 ms | 4.06 ms | 1 | 91.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 10.46 ms | 10.82 ms | 1 |  | 0.37× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 1.76 ms | 5.45 ms | 4 |  | 2.16× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 2.33 ms | 2.50 ms | 1 |  | 1.60× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 3.84 ms | 3.93 ms | 1 |  | 1.03× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 4.72 ms | 5.34 ms | 1 |  | 0.78× | ✓ |
| ht_auth | `ht_auth.v0` circl | 37.8 µs | 43.6 µs | 1 | 0.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 94.6 µs | 104.8 µs | 1 |  | 0.41× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 60.7 µs | 109.9 µs | 4 |  | 0.65× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 21.5 µs | 24.8 µs | 1 |  | 1.75× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 37.6 µs | 45.5 µs | 1 |  | 0.95× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 37.7 µs | 42.4 µs | 1 |  | 1.02× | ✓ |

### SLH-DSA-SHAKE-128s

end-to-end v0 stages: 1.14 ms, best assembled: 1.02 ms (1.12×), coverage 88%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 3.4 µs | 8.0 µs | 1 | 0.3% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 2.6 µs | 6.5 µs | 1 |  | 1.13× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 0.6 µs | 1.0 µs | 1 |  | 6.80× | ✓ |
| hmsg | `hmsg.v3` stdlib-sha3 | 3.1 µs | 7.5 µs | 1 |  | 1.08× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 2.1 µs | 5.5 µs | 1 |  | 1.41× | ✓ |
| hmsg | `hmsg.v5` pgo | 2.3 µs | 6.3 µs | 1 |  | 1.27× | ✓ |
| fors | `fors.v0` circl | 85.8 µs | 105.4 µs | 1 | 7.6% | 1.00× | ✓ |
| fors | `fors.v1` purego | 89.5 µs | 103.8 µs | 1 |  | 1.01× | ✓ |
| fors | `fors.v2` parallel-trees | 116.8 µs | 217.7 µs | 4 |  | 0.87× | ✓ |
| fors | `fors.v3` alt-hash | 85.2 µs | 99.3 µs | 1 |  | 1.06× | ✓ |
| fors | `fors.v4` amd64v3 | 78.7 µs | 85.0 µs | 1 |  | 1.23× | ✓ |
| fors | `fors.v5` pgo | 94.7 µs | 104.4 µs | 1 |  | 1.01× | ✓ |
| ht_wots | `ht_wots.v0` circl | 880.9 µs | 1.06 ms | 1 | 77.6% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 874.5 µs | 911.3 µs | 1 |  | 1.17× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 594.1 µs | 1.28 ms | 4 |  | 1.79× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 880.8 µs | 1.02 ms | 1 |  | 1.04× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 816.2 µs | 881.0 µs | 1 |  | 1.17× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 904.3 µs | 955.9 µs | 1 |  | 1.12× | ✓ |
| ht_auth | `ht_auth.v0` circl | 29.9 µs | 41.6 µs | 1 | 2.6% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 30.7 µs | 35.5 µs | 1 |  | 1.17× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 61.5 µs | 104.0 µs | 4 |  | 0.62× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 29.9 µs | 37.3 µs | 1 |  | 1.13× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 27.8 µs | 34.6 µs | 1 |  | 1.21× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 31.7 µs | 34.9 µs | 1 |  | 1.19× | ✓ |

### SLH-DSA-SHAKE-128f

end-to-end v0 stages: 3.24 ms, best assembled: 3.23 ms (1.00×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 3.9 µs | 10.6 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 3.4 µs | 9.7 µs | 1 |  | 1.03× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 0.6 µs | 1.0 µs | 1 |  | 8.34× | ✓ |
| hmsg | `hmsg.v3` stdlib-sha3 | 5.3 µs | 12.0 µs | 1 |  | 0.83× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 3.2 µs | 8.5 µs | 1 |  | 1.18× | ✓ |
| hmsg | `hmsg.v5` pgo | 2.8 µs | 6.9 µs | 1 |  | 1.38× | ✓ |
| fors | `fors.v0` circl | 110.0 µs | 132.0 µs | 1 | 3.4% | 1.00× | ✓ |
| fors | `fors.v1` purego | 116.5 µs | 140.8 µs | 1 |  | 0.92× | ✓ |
| fors | `fors.v2` parallel-trees | 146.3 µs | 292.9 µs | 4 |  | 0.86× | ✓ |
| fors | `fors.v3` alt-hash | 108.4 µs | 119.2 µs | 1 |  | 1.10× | ✓ |
| fors | `fors.v4` amd64v3 | 101.0 µs | 112.7 µs | 1 |  | 1.17× | ✓ |
| fors | `fors.v5` pgo | 121.0 µs | 134.6 µs | 1 |  | 0.97× | ✓ |
| ht_wots | `ht_wots.v0` circl | 3.05 ms | 3.18 ms | 1 | 94.0% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 3.16 ms | 3.68 ms | 1 |  | 0.87× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 1.76 ms | 4.90 ms | 4 |  | 1.88× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 3.14 ms | 3.65 ms | 1 |  | 0.87× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 2.83 ms | 2.96 ms | 1 |  | 1.09× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 3.16 ms | 3.25 ms | 1 |  | 0.99× | ✓ |
| ht_auth | `ht_auth.v0` circl | 47.5 µs | 52.1 µs | 1 | 1.5% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 34.3 µs | 46.7 µs | 1 |  | 1.10× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 60.1 µs | 102.4 µs | 4 |  | 0.80× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 32.2 µs | 42.4 µs | 1 |  | 1.23× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 30.1 µs | 37.7 µs | 1 |  | 1.37× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 34.7 µs | 42.1 µs | 1 |  | 1.21× | ✓ |

### SLH-DSA-SHAKE-192s

end-to-end v0 stages: 1.52 ms, best assembled: 1.49 ms (1.01×), coverage 104%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 3.4 µs | 10.5 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 3.5 µs | 9.4 µs | 1 |  | 1.04× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.0 µs | 1.4 µs | 1 |  | 5.24× | ✓ |
| hmsg | `hmsg.v3` stdlib-sha3 | 4.6 µs | 12.6 µs | 1 |  | 0.86× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 3.0 µs | 7.7 µs | 1 |  | 1.27× | ✓ |
| hmsg | `hmsg.v5` pgo | 3.4 µs | 8.4 µs | 1 |  | 1.14× | ✓ |
| fors | `fors.v0` circl | 117.7 µs | 134.6 µs | 1 | 7.8% | 1.00× | ✓ |
| fors | `fors.v1` purego | 126.5 µs | 155.3 µs | 1 |  | 0.87× | ✓ |
| fors | `fors.v2` parallel-trees | 161.0 µs | 338.0 µs | 4 |  | 0.80× | ✓ |
| fors | `fors.v3` alt-hash | 122.7 µs | 155.3 µs | 1 |  | 0.86× | ✓ |
| fors | `fors.v4` amd64v3 | 106.9 µs | 123.1 µs | 1 |  | 1.09× | ✓ |
| fors | `fors.v5` pgo | 130.6 µs | 150.8 µs | 1 |  | 0.88× | ✓ |
| ht_wots | `ht_wots.v0` circl | 1.43 ms | 1.64 ms | 1 | 94.2% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 1.40 ms | 1.67 ms | 1 |  | 0.97× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 941.7 µs | 2.26 ms | 4 |  | 1.78× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 1.33 ms | 1.41 ms | 1 |  | 1.15× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 1.22 ms | 1.25 ms | 1 |  | 1.30× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 1.39 ms | 1.46 ms | 1 |  | 1.11× | ✓ |
| ht_auth | `ht_auth.v0` circl | 29.2 µs | 34.8 µs | 1 | 1.9% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 30.1 µs | 34.5 µs | 1 |  | 1.01× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 46.8 µs | 81.0 µs | 4 |  | 0.66× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 49.0 µs | 47.1 µs | 1 |  | 0.74× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 26.6 µs | 29.2 µs | 1 |  | 1.19× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 31.0 µs | 35.1 µs | 1 |  | 0.99× | ✓ |

### SLH-DSA-SHAKE-192f

end-to-end v0 stages: 4.29 ms, best assembled: 4.22 ms (1.02×), coverage 99%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 4.0 µs | 12.8 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 4.2 µs | 10.7 µs | 1 |  | 1.04× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 2.1 µs | 2.1 µs | 1 |  | 4.10× | ✓ |
| hmsg | `hmsg.v3` stdlib-sha3 | 3.8 µs | 11.1 µs | 1 |  | 1.07× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 4.0 µs | 10.6 µs | 1 |  | 1.11× | ✓ |
| hmsg | `hmsg.v5` pgo | 3.8 µs | 9.6 µs | 1 |  | 1.14× | ✓ |
| fors | `fors.v0` circl | 138.0 µs | 169.3 µs | 1 | 3.2% | 1.00× | ✓ |
| fors | `fors.v1` purego | 147.1 µs | 176.4 µs | 1 |  | 0.95× | ✓ |
| fors | `fors.v2` parallel-trees | 157.8 µs | 319.4 µs | 4 |  | 1.03× | ✓ |
| fors | `fors.v3` alt-hash | 140.0 µs | 162.2 µs | 1 |  | 1.05× | ✓ |
| fors | `fors.v4` amd64v3 | 125.3 µs | 134.8 µs | 1 |  | 1.25× | ✓ |
| fors | `fors.v5` pgo | 153.2 µs | 170.1 µs | 1 |  | 1.00× | ✓ |
| ht_wots | `ht_wots.v0` circl | 4.09 ms | 4.94 ms | 1 | 95.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 4.34 ms | 4.75 ms | 1 |  | 1.03× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 2.35 ms | 6.44 ms | 4 |  | 2.17× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 4.53 ms | 5.18 ms | 1 |  | 0.95× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 3.78 ms | 4.20 ms | 1 |  | 1.19× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 4.48 ms | 4.87 ms | 1 |  | 0.98× | ✓ |
| ht_auth | `ht_auth.v0` circl | 32.5 µs | 44.6 µs | 1 | 0.8% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 33.3 µs | 40.3 µs | 1 |  | 1.11× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 60.5 µs | 101.9 µs | 4 |  | 0.71× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 32.5 µs | 39.7 µs | 1 |  | 1.13× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 28.8 µs | 34.8 µs | 1 |  | 1.27× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 34.0 µs | 42.1 µs | 1 |  | 1.06× | ✓ |

### SLH-DSA-SHAKE-256s

end-to-end v0 stages: 2.17 ms, best assembled: 2.14 ms (1.01×), coverage 112%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 4.1 µs | 13.0 µs | 1 | 0.2% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 4.6 µs | 12.7 µs | 1 |  | 0.99× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.0 µs | 1.3 µs | 1 |  | 7.09× | ✓ |
| hmsg | `hmsg.v3` stdlib-sha3 | 5.2 µs | 12.6 µs | 1 |  | 0.94× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 3.6 µs | 9.7 µs | 1 |  | 1.19× | ✓ |
| hmsg | `hmsg.v5` pgo | 4.2 µs | 11.7 µs | 1 |  | 1.02× | ✓ |
| fors | `fors.v0` circl | 150.8 µs | 187.9 µs | 1 | 6.9% | 1.00× | ✓ |
| fors | `fors.v1` purego | 157.3 µs | 173.5 µs | 1 |  | 1.08× | ✓ |
| fors | `fors.v2` parallel-trees | 143.8 µs | 297.9 µs | 4 |  | 1.24× | ✓ |
| fors | `fors.v3` alt-hash | 157.6 µs | 187.0 µs | 1 |  | 0.99× | ✓ |
| fors | `fors.v4` amd64v3 | 134.2 µs | 146.1 µs | 1 |  | 1.28× | ✓ |
| fors | `fors.v5` pgo | 168.6 µs | 208.4 µs | 1 |  | 0.91× | ✓ |
| ht_wots | `ht_wots.v0` circl | 2.24 ms | 2.73 ms | 1 | 103.3% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 2.01 ms | 2.08 ms | 1 |  | 1.31× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 1.16 ms | 3.33 ms | 4 |  | 2.36× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 2.02 ms | 2.21 ms | 1 |  | 1.23× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 1.80 ms | 1.96 ms | 1 |  | 1.38× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 2.11 ms | 2.30 ms | 1 |  | 1.18× | ✓ |
| ht_auth | `ht_auth.v0` circl | 29.1 µs | 36.9 µs | 1 | 1.3% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 30.0 µs | 36.5 µs | 1 |  | 0.99× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 52.1 µs | 90.7 µs | 4 |  | 0.66× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 30.6 µs | 39.7 µs | 1 |  | 0.94× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 26.1 µs | 32.0 µs | 1 |  | 1.14× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 30.8 µs | 34.3 µs | 1 |  | 1.07× | ✓ |

### SLH-DSA-SHAKE-256f

end-to-end v0 stages: 4.62 ms, best assembled: 4.26 ms (1.09×), coverage 94%

| stage | variant | median | CPU/op | threads | share of v0 total | speedup | match |
|---|---|---|---|---|---|---|---|
| hmsg | `hmsg.v0` circl | 5.1 µs | 13.8 µs | 1 | 0.1% | 1.00× | ✓ |
| hmsg | `hmsg.v1` purego | 4.2 µs | 11.8 µs | 1 |  | 1.16× | ✓ |
| hmsg | `hmsg.v2` lazy-parse | 1.0 µs | 1.7 µs | 1 |  | 6.49× | ✓ |
| hmsg | `hmsg.v3` stdlib-sha3 | 4.5 µs | 13.0 µs | 1 |  | 1.06× | ✓ |
| hmsg | `hmsg.v4` amd64v3 | 4.0 µs | 11.8 µs | 1 |  | 1.19× | ✓ |
| hmsg | `hmsg.v5` pgo | 4.6 µs | 13.1 µs | 1 |  | 1.05× | ✓ |
| fors | `fors.v0` circl | 161.0 µs | 204.7 µs | 1 | 3.5% | 1.00× | ✓ |
| fors | `fors.v1` purego | 170.4 µs | 203.0 µs | 1 |  | 1.02× | ✓ |
| fors | `fors.v2` parallel-trees | 139.7 µs | 307.9 µs | 4 |  | 1.36× | ✓ |
| fors | `fors.v3` alt-hash | 166.0 µs | 176.9 µs | 1 |  | 1.17× | ✓ |
| fors | `fors.v4` amd64v3 | 143.3 µs | 163.7 µs | 1 |  | 1.26× | ✓ |
| fors | `fors.v5` pgo | 179.3 µs | 198.0 µs | 1 |  | 1.05× | ✓ |
| ht_wots | `ht_wots.v0` circl | 4.13 ms | 4.23 ms | 1 | 89.4% | 1.00× | ✓ |
| ht_wots | `ht_wots.v1` purego | 4.33 ms | 4.62 ms | 1 |  | 0.92× | ✓ |
| ht_wots | `ht_wots.v2` parallel-layers | 2.36 ms | 6.35 ms | 4 |  | 1.90× | ✓ |
| ht_wots | `ht_wots.v3` alt-hash | 4.57 ms | 5.27 ms | 1 |  | 0.81× | ✓ |
| ht_wots | `ht_wots.v4` amd64v3 | 3.86 ms | 4.78 ms | 1 |  | 0.88× | ✓ |
| ht_wots | `ht_wots.v5` pgo | 4.34 ms | 4.81 ms | 1 |  | 0.89× | ✓ |
| ht_auth | `ht_auth.v0` circl | 32.0 µs | 41.2 µs | 1 | 0.7% | 1.00× | ✓ |
| ht_auth | `ht_auth.v1` purego | 32.8 µs | 38.1 µs | 1 |  | 1.09× | ✓ |
| ht_auth | `ht_auth.v2` parallel-layers | 59.4 µs | 103.1 µs | 4 |  | 0.65× | ✓ |
| ht_auth | `ht_auth.v3` alt-hash | 33.4 µs | 44.1 µs | 1 |  | 0.95× | ✓ |
| ht_auth | `ht_auth.v4` amd64v3 | 28.3 µs | 35.4 µs | 1 |  | 1.18× | ✓ |
| ht_auth | `ht_auth.v5` pgo | 33.5 µs | 38.5 µs | 1 |  | 1.08× | ✓ |

