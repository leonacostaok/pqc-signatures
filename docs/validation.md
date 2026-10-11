# Validation

Three layers, all run on every library by `common/run-all.sh`, summarized in [../results/MATCH.md](../results/MATCH.md).

## 1. Byte match against the shared reference

Seeded keygen + deterministic signing on [common/vectors.json](../common/vectors.json) must reproduce
[common/reference.json](../common/reference.json) exactly (pk, sk and signature SHA-256) for all 15 ML-DSA/SLH-DSA
sets. Every benchmark line repeats this check for the variant it measures, so a variant that changes the output
cannot produce a number.

## 2. Cross-verification

Each library exports its keys and signatures (`run.sh vectors`), and every library verifies every other library's
signatures (`run.sh crossverify`), plus a bit-flipped copy that must be rejected. Falcon is not byte-matchable
(no standard seed format, randomized salt), so it is checked only here, between noble, liboqs and Bouncy Castle.

## 3. Validation suite: NIST ACVP + negative tests, through every variant

[common/validation/validation.json.gz](../common/validation/validation.json.gz), built by
[common/gen-validation.mjs](../common/gen-validation.mjs), has 651 cases:

| source | kind | cases | what |
|---|---|---|---|
| NIST ACVP (usnistgov/ACVP-Server) | keyGen | 195 | all FIPS 204 (75) and FIPS 205 (120) key generation vectors: pk and sk must match |
| NIST ACVP | sigGen | 69 | deterministic, pure, external interface **with contexts**, imported FIPS-encoded sk; signature must match |
| NIST ACVP | sigVer | 129 | pure/external; every NIST failure reason: modified message, commitment, z, hint (ML-DSA); modified message, R, SIG_FORS, SIG_HT, too large, too small (SLH-DSA); plus valid ones |
| negative suite | sigVer | 258 | per parameter set: positive controls (empty and non-empty context), wrong message, empty message, wrong context in both directions, other key, pk bit flip, sig truncated/extended by one byte, all-zero sig, bit flips at start/middle/end; ML-DSA: z coefficient = gamma1 (norm check), hint count > omega, non-increasing hint indices, nonzero hint padding; SLH-DSA: flips in R, FORS and the last hypertree layer |

Every case runs through **every variant of the matching process** (keygen.v0–v5, sign.v0–v5, verify.v0–v5) and,
for sigVer, through the end-to-end verify pipelines assembled from stages (`total`, `total_best`, and in OpenSSL's
case every single-stage swap). That matters most for caching, fused-decoding and parallel variants: a shortcut that
skipped a check would show up here. An exception or error return counts as "reject"; a crash fails.

One generator bug was caught on the way: the first draft mis-computed the ML-DSA hint offset (z packs into 18/20
bits, not 19/21), so the hint mutations landed past the end of the signature. noble's baseline flagged it, and the
generator now asserts the signature layout against the real lengths.

Per-library details and any findings: `docs/<lib>/validation.md`.
