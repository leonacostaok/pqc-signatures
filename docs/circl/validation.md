# CIRCL: validation suite (Phase 2 A)

`libs/circl/run.sh validate common/validation/validation.json.gz results/circl/validation.json`

## What is run

The suite (651 cases: NIST ACVP FIPS 204/205 keyGen / sigGen / sigVer vectors with contexts, plus a
negative/edge suite) is run through **every variant of the matching process**:

| case kind | variants | cases |
|---|---|---|
| `keygen` | `keygen.v0 .. keygen.v5` (baseline, purego, amd64v3, pgo, gc-off, parallel) | 195 |
| `siggen` | `sign.v0 .. sign.v5` (baseline, pre-unpacked key, purego, amd64v3, pgo, parallel) | 69 |
| `sigver` | `verify.v0 .. verify.v5` (baseline, pre-unpacked key, purego, amd64v3, pgo, parallel) **plus** the stage pipelines `verify.total` (v0 stages) and `verify.total_best` (fastest alternatives, see verify-stages.md) | 387 |

That is 195x6 + 69x6 + 387x8 = **4680 results**. Variants that live in another build flavor are run by
the default binary spawning `pqcbench-purego`, `pqcbench-amd64v3` and `pqcbench-pgo` as sub-processes
(`validate --only-own`) and merging their results, so each build really executes its own code.

How the inputs reach the library:
- keygen: `seed_hex` -> `mldsa.NewKeyFromSeed` / `slhdsa.GenerateKey(bytes.NewReader(seed))`; pass iff pk **and**
  sk bytes equal the expected encodings.
- siggen: `sk_hex` is imported with `PrivateKey.UnmarshalBinary` (never regenerated from a seed), the context
  goes to `SignTo(sk, msg, ctx, false, sig)` / `SignDeterministic(priv, NewMessage(msg), ctx)`; pass iff the
  signature bytes equal `expect_sig_hex`. Nothing is skipped: the 12 SLH-DSA "s" sigGen cases cost ~2 s each
  per variant, which is why a full `validate` takes about 6-7 minutes.
- sigver: `pk_hex` imported with `PublicKey.UnmarshalBinary`, verify with the given ctx; pass iff the boolean
  equals `expect`. Every case runs under `recover()`: a Go panic (e.g. `UnmarshalBinary` rejecting a public
  key of the wrong length, which my harness turns into a panic) is recorded in `error` and counted as
  `got=false`, which passes only when `expect` is false. No case crashed the process.
- The parallel variants run the case on all 4 workers; the outputs must all be identical, otherwise the case fails.
- Cases for unsupported parameters would be skipped; the suite has none (Falcon is absent).

## Results

**4680 / 4680 pass, 0 failures, 0 skipped** for all 20 variants (see `results/circl/validation.json`,
`summary`). In particular all negative cases are rejected by every variant, including the caching ones:

- `verify.v1`/`verify.v5` (pre-unpacked public key): the cached `ExpandA` / `tr` belong to the key, not to the
  signature, so wrong message, wrong context, flipped signature bits, truncated / extended / all-zero signatures
  are rejected exactly like in the baseline; the "wrong public key" and "public key bit flipped" cases use a
  different key, so a fresh unpack happens.
- `verify.total_best` (per-(pk, ctx) caches of pkDecode, tr, A^, NTT(t1 2^d) and the mu midstate; fused z decode;
  fused UseHint/pack): rejects all 258 negative cases and the ACVP "modified ..." cases, which exercises the
  fused bound check (`z coefficient out of range (= gamma1)`), the strict hint decoding (`hint count exceeds
  omega`, `hint indices not strictly increasing`, `nonzero padding after last hint index`) and the
  context-dependent midstate (`wrong context` cases in both directions).
- `sign.v1`/`sign.v5` (pre-unpacked private key): the ACVP sigGen vectors with 0..255-byte contexts are
  reproduced bit-exactly, so CIRCL's pure-mode framing `0 || len(ctx) || ctx || M` and the deterministic rnd
  handling are correct for both families.

No library bug was found in CIRCL v1.6.5 by this suite. The only behaviour worth noting is that
`mldsa.PublicKey.UnmarshalBinary` / `slhdsa.PublicKey.UnmarshalBinary` report wrong-length inputs as an
`error` (the ACVP negative suite has none of those for pk, but the harness maps the error to "false" anyway),
and `mldsa.Verify` returns `false` (not an error) for signatures of the wrong length.

<!-- RESULTS -->
