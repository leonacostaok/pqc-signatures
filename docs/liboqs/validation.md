# liboqs: validation suite

`run.sh validate common/validation/validation.json.gz results/liboqs/validation.json`

## What is run

The 651 cases (NIST ACVP FIPS 204 / FIPS 205 keyGen, sigGen and sigVer vectors with contexts, plus the
negative/edge suite) are converted by `src/glue.py` into a flat text file and fed to every driver binary.
Every case is run through every variant of the matching process, exactly as the bench runs them (same
binary, same API path, same thread count, same SHA-3 callback selection):

| cases | variants | how the context reaches liboqs |
|---|---|---|
| keygen (195) | keygen.v0..v5 | seed through `OQS_randombytes_custom_algorithm` (api path) or `mld_sign_keypair_internal` / `slh_keygen_internal` (direct path) |
| siggen (69) | sign.v0..v5 | `OQS_SIG_sign_with_ctx_str` with the FIPS-encoded `sk_hex` imported as is; deterministic through the RNG callback (rnd = 0^32 / opt_rand = PK.seed taken from the imported sk); direct path: `mld_sign_signature_internal` with pre = 0x00 ‖ |ctx| ‖ ctx and `slh_sign(ctx)` with addrnd = NULL |
| sigver (387) | verify.v0..v5, plus `verify.total` (v0 stage pipeline) and `verify.total_best` (cached ML-DSA pipeline / fasthash SLH-DSA pipeline) | `OQS_SIG_verify_with_ctx_str`; direct: `mld_sign_verify_internal(pre)` / `slh_verify(ctx)`; pipelines: the stage code with the same prefix/context |

The four-thread variants run each case on four worker threads at once and pass only if all four agree with the
expected result. No case is skipped: the twelve SLH-DSA "s" siggen cases take 1-3 s each per sign variant and
are simply run.

Malformed input handling: liboqs's `OQS_SIG_verify*` takes no public-key length, so a key of the wrong length
cannot be handed to the library safely; the driver rejects it (`got:false`, error "pk length N rejected by
driver"), which is what any caller must do. Wrong signature lengths are passed through and rejected by the
library (`MLD_ERR_FAIL` for `siglen != CRYPTO_BYTES`; slhdsa-c's `sig_sz != slh_sig_sz`). Hint encoding
violations (count > omega, non-increasing indices, non-zero padding) are rejected inside
`mld_sig_unpack_hints`; z out of range by `mld_polyvecl_chknorm`. An error return counts as `false`; no case
crashes.

Output: `results/liboqs/validation.json` = `{lib, lib_version, results:[{id, variant, pass, got, error}], summary}`.

## Results and failures

See the summary below (generated from the last dev run). Every variant passes every case; there are no
library bugs to report for liboqs 0.16.0 on this suite. The one behaviour worth noting is the public-key length
issue above (API design, not a bug), and that `OQS_SIG_sign_with_ctx_str` for SLH-DSA always draws n bytes of
randomness even for the deterministic variant, which is why the driver's RNG callback has to hand out PK.seed.

<!-- RESULTS -->
