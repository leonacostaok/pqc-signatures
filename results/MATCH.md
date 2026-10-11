# Signature match report

Every library derives keys from the same seeds in `common/vectors.json` and signs the same message deterministically. `match` = public key, secret key and signature are byte-identical to `common/reference.json`. Falcon is not byte-matchable across libraries (no standard seed format, randomized salt), so it is checked by self-verify and cross-verification only.

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | match | match | match | match | match | match |
| ML-DSA-65 | match | match | match | match | match | match |
| ML-DSA-87 | match | match | match | match | match | match |
| SLH-DSA-SHA2-128s | match | match | match | match | match | match |
| SLH-DSA-SHA2-128f | match | match | match | match | match | match |
| SLH-DSA-SHA2-192s | match | match | match | match | match | match |
| SLH-DSA-SHA2-192f | match | match | match | match | match | match |
| SLH-DSA-SHA2-256s | match | match | match | match | match | match |
| SLH-DSA-SHA2-256f | match | match | match | match | match | match |
| SLH-DSA-SHAKE-128s | match | match | match | match | match | match |
| SLH-DSA-SHAKE-128f | match | match | match | match | match | match |
| SLH-DSA-SHAKE-192s | match | match | match | match | match | match |
| SLH-DSA-SHAKE-192f | match | match | match | match | match | match |
| SLH-DSA-SHAKE-256s | match | match | match | match | match | match |
| SLH-DSA-SHAKE-256f | match | match | match | match | match | match |
| Falcon-512 | self-verify | self-verify | — | — | — | self-verify |
| Falcon-1024 | self-verify | self-verify | — | — | — | self-verify |

## Cross-verification (rows verify signatures produced by columns)

| verifier \ signer | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| **noble** | 17/17 ok, 17 tamper rejected | 17/17 ok, 17 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 17/17 ok, 17 tamper rejected |
| **liboqs** | 17/17 ok, 17 tamper rejected | 17/17 ok, 17 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 17/17 ok, 17 tamper rejected |
| **openssl** | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected |
| **circl** | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected |
| **rustcrypto** | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected |
| **bouncycastle** | 17/17 ok, 17 tamper rejected | 17/17 ok, 17 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 15/15 ok, 15 tamper rejected | 17/17 ok, 17 tamper rejected |

## Benchmark variants matching the reference

| lib | rows | matching |
|---|---|---|
| noble | 298 | 298 |
| liboqs | 306 | 306 |
| openssl | 246 | 246 |
| circl | 270 | 270 |
| rustcrypto | 270 | 270 |
| bouncycastle | 270 | 270 |

## Validation suite (NIST ACVP FIPS 204/205 + negative tests), every case through every variant

| lib | cases run | variants | failures |
|---|---|---|---|
| noble | 4680 | 20 | 0 |
| liboqs | 4680 | 20 | 0 |
| openssl | 12363 | 65 | 0 |
| circl | 4680 | 20 | 0 |
| rustcrypto | 4680 | 20 | 0 |
| bouncycastle | 4680 | 20 | 0 |

## Verify stages: canonical intermediate outputs agree across libraries

93 (param, stage) pairs compared, 0 disagreements.

| lib | stage rows | alternatives not matching v0 |
|---|---|---|
| noble | 285 | 0 |
| liboqs | 408 | 0 |
| openssl | 339 | 0 |
| circl | 396 | 0 |
| rustcrypto | 408 | 0 |
| bouncycastle | 279 | 0 |

**Problems found: 0**
