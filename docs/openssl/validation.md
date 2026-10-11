# OpenSSL - validation suite (ACVP + negative cases)

`libs/openssl/run.sh validate common/validation/validation.json.gz results/openssl/validation.json`

## How it runs

* `run.sh` decompresses the suite once (`gzip -dc`, cached under `libs/openssl/build/validate/`; libcrypto is
  built `no-zlib` so the driver has no inflater) and runs it through the three driver binaries
  (`default`, `noasm`, `native`), each of which executes the variants of its own build flavour. The per-build
  partial files are merged by `pqc_driver_default merge-validate` into the contract format
  (`results[]` with `id`, `variant`, `pass`, `got`, `error`, plus a per-variant `summary`).
* Every case is turned into a per-case parameter record (name, message, context, seed / imported key) and run
  through `libs/openssl/src/pqc_validate.c`:
  * **keygen** cases: `seed_hex` through `keygen.v0..v5` (the `pthread-x4` variant is exercised as a single
    worker, which is exactly the code each of its threads runs); `pass` = pk **and** sk byte-equal to
    `expect_pk_hex` / `expect_sk_hex`. `keygen.v2` (fromdata seed import) is ML-DSA only, hence 75 cases.
  * **siggen** cases: `sk_hex` is imported with `EVP_PKEY_fromdata(... "priv" ...)` (never regenerated from a
    seed), the context is passed as the `context-string` signature parameter, `deterministic=1`; `pass` =
    signature byte-equal to `expect_sig_hex`. Nothing is skipped: the SLH-DSA "s" cases (1-2 s each) are run
    by every sign variant.
  * **sigver** cases: `pk_hex` is imported with `fromdata("pub")` - a wrong-length key makes the import fail and
    the variant reports `false` without touching the signature; wrong-length / malformed signatures make
    `EVP_PKEY_verify` return 0 (`ossl_ml_dsa_sig_decode` rejects bad hint encodings, SLH-DSA rejects any size
    mismatch up front). `verify.v2` (external mu, ML-DSA only) builds mu with the case's context.
    `got` is the verify result, `pass` = `got == expect`.
  * **sigver through the stage pipelines**: for every stage alternative of the build a full pipeline is run in
    which that stage uses the alternative and all others use v0 (`stages.<stage>.vN`), so each alternative -
    in particular the caching ones (cached tr / cached A / cached NTT(t1)) and the threaded ones - is shown to
    reject every negative case; plus `stages.total` (all v0) and `stages.total_best` (the combination used for
    the `total_best` benchmark line). The pipeline's caches are derived from the case's public key only.
* Exceptions cannot happen in C; an error return from any OpenSSL call is mapped to `false`, and the whole
  suite ran without a crash (asserted by the exit status of all three binaries).

## Results

| process / pipeline | variants | cases per variant | pass | fail |
|---|---|---|---|---|
| keygen | v0, v1, v3, v4, v5 (v2: ML-DSA only, 75) | 195 | all | 0 |
| sign | v0..v5 | 69 | all | 0 |
| verify | v0, v1, v3, v4, v5 (v2: ML-DSA only, 99) | 387 | all | 0 |
| stage pipelines ML-DSA | 20 stage alternatives + total + total_best | 99 (387 for total/total_best) | all | 0 |
| stage pipelines SLH-DSA | 19 stage alternatives (+ hmsg.v4 on the 144 SHA2 cases) | 288 | all | 0 |

12,363 (case, variant) results, **0 failures, 0 skipped** (`results/openssl/validation.json`). Every NIST ACVP
keyGen/sigGen/sigVer vector (pure interface, with and without context) is reproduced bit-exactly by every
variant, and all 258 negative/edge cases (wrong message, wrong context in either direction, wrong/flipped
public key, truncated/extended/all-zero/bit-flipped signatures, z = gamma1, hint count > omega, non-increasing
hint indices, non-zero hint padding, flipped R / FORS / last-layer sections) are rejected by every variant and
every stage pipeline.

No library bug was found. Two observations worth recording:

* OpenSSL's `ossl_ml_dsa_sig_decode` does not range-check z itself (20-/18-bit unpack only); the
  `z = gamma1` case is rejected by the `||z||inf < gamma1 - beta` check that FIPS 204 Alg. 8 puts after the
  hash comparison input is computed. Both the EVP path and the staged pipelines therefore reject it in
  `hint_check`, as specified; the own decoder (`decode.v1`) mirrors that behaviour on purpose.
* The suite's signature-length cases (truncated / extended / "too small" / "too large") are rejected before
  any arithmetic: `ossl_ml_dsa_sig_decode` fails on the PACKET length and `slh_verify_internal` compares
  `sig_len` with the parameter set's size up front. A wrong-length public key (not in the suite) would already
  fail in `EVP_PKEY_fromdata` (`ossl_ml_dsa_pk_decode` / `ossl_slh_dsa_set_pub` length checks), which the
  driver maps to `false` as the contract asks ("error return counts as false").

<!-- RESULTS -->
