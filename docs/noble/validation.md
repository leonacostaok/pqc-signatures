# noble — validation suite

`libs/noble/run.sh validate common/validation/validation.json.gz results/noble/validation.json [--params a,b] [--variants id,id] [--skip-slow]`

The suite (651 cases: NIST ACVP FIPS 204/205 keyGen / deterministic sigGen / sigVer with contexts, plus
the negative/edge suite derived from `common/vectors.json`) is run through **every variant of the
matching process**: `keygen` cases through `keygen.v0..v5`, `siggen` through `sign.v0..v5`, `sigver`
through `verify.v0..v5` and through the two end-to-end stage pipelines (`stages.total` = noble's
v0 stages, `stages.total_best` = the fastest cache-free stage alternatives, see
[verify-stages.md](verify-stages.md)). Each variant runs in its own child process (Node or Bun, hash
layer via `NOBLE_PQ_HASH`); the worker variants distribute the cases over four `worker_threads`.

How each case kind is executed:

* `keygen`: `alg.keygen(seed)`; pass iff pk **and** sk equal the expected hex.
* `siggen`: the FIPS-encoded `sk_hex` is used directly (noble's `sign` takes the encoded secret key,
  no regeneration); `sign(msg, sk, { context, extraEntropy: false })`, or `expandSk(sk)` +
  `signPrecomputed(msg, exp, { context, extraEntropy: false })` for `sign.v3`; pass iff the
  signature equals the expected hex.
* `sigver`: `verify(sig, msg, pk, { context })` (or `expandPk` + `verifyPrecomputed` for `verify.v3`,
  or the stage pipeline); any exception counts as `false`; pass iff the result equals `expect`.
  Malformed inputs (wrong lengths, bad hint encodings, out-of-range z) are rejected by noble's coders
  with `false` or an exception, never a crash.

The cache variants deserve the emphasis the contract puts on them: `sign.v3` builds the expanded key
from the case's own `sk` and `verify.v3` expands the case's own `pk` (one key per case), so a
precomputation that silently kept state from a previous key would show up as a failure here.

Nothing is skipped by default. The SLH-DSA "s" `siggen` cases (2 per set) take 2–21 s each in pure
JS, i.e. ≈ 1–2 minutes per sign variant; `--skip-slow` records them as `skipped` for quick dev runs.
Falcon is not in the suite.

## Results

<!-- RESULTS -->
