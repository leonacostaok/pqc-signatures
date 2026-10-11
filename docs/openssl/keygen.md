# OpenSSL - keygen

Process: 32-byte xi (ML-DSA) or 3n-byte `SK.seed||SK.prf||PK.seed` (SLH-DSA) -> (pk, sk).
The timed region covers creating the key object from the seed **and** exporting `pub`/`priv` as octet strings
(the two `EVP_PKEY_get_octet_string_param` calls are part of every variant, since a benchmark that never
materialises the key bytes would not be comparable with the other libraries).
Match = SHA-256(pk) and SHA-256(sk) equal `common/reference.json`.

In OpenSSL the keygen cost is dominated by the algorithm itself: for ML-DSA the SHAKE-based expansion of
the matrix A (k*l polynomials of rejection-sampled SHAKE128 output) plus k+l NTTs; for SLH-DSA the
computation of `PK.root`, i.e. one full XMSS tree of height h' = h/d at the top layer (2^(h') WOTS+ keypairs,
each 2n+3 chains of w=16 hashes). The EVP layer overhead (fetching, ctx allocation) is a few microseconds.

## Variants

| id | name | build | what / why |
|---|---|---|---|
| keygen.v0 | evp-baseline | default | The documented way: `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL)`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_params("seed")`, `EVP_PKEY_keygen`, free. The keymgmt is fetched implicitly on every call (property-cache lookup under the global libctx lock). |
| keygen.v1 | prefetch-reuse-ctx | default | `EVP_KEYMGMT_fetch` once, one `EVP_PKEY_CTX` initialised once (keygen_init + seed param) and reused: per call only `EVP_PKEY_keygen`. Removes the fetch, the ctx malloc/free and the param-translation round trip. |
| keygen.v2 | fromdata-seed-import | default | Instead of the keygen operation, the key is *imported*: `EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, {"seed"})` on a reused fromdata ctx. Internally this goes through `ml_dsa_import -> ossl_ml_dsa_set_prekey + ossl_ml_dsa_generate_key`, so the same expansion happens but through the import path (no gen ctx, no DRBG involvement, no provider-flag handling). ML-DSA only: the SLH-DSA keymgmt only imports `pub`/`priv`. |
| keygen.v3 | no-asm-build | noasm | libcrypto configured with `no-asm`: Keccak-1600 and SHA-256/512 are the generic C versions and the CPUID dispatch is gone. Expected to be slower; included to quantify how much the hash assembly matters (it is the only assembly on the ML-DSA/SLH-DSA path). |
| keygen.v4 | native-lto-build | native | libcrypto and the driver compiled with `-O3 -march=native -flto`: allows AVX/BMI code generation for the C NTT/polynomial loops and cross-translation-unit inlining of the small `ml_dsa_*`/`slh_*` helpers (poly ops, ADRS updates, hash wrappers) that live in separate files. |
| keygen.v5 | pthread-x4 | default | 4 worker threads, each with its own prefetched, reused keygen ctx (the v1 path), generating the same key from the same seed; throughput over a batch (reported as wall per batch / batch size, `threads: 4`). Shows whether the provider/EVP layer scales (no shared state except the libctx property cache). |

## What to expect

* v1/v2 can only shave the EVP overhead (a few us), i.e. visible for ML-DSA-44 (~100 us) and negligible for
  SLH-DSA (ms range).
* v3 vs v0 isolates the Keccak/SHA-2 assembly: SHAKE-heavy ML-DSA keygen and the SHAKE SLH-DSA sets should
  lose most; SHA2 SLH-DSA sets use SHA-256 (SHA-NI capable asm) and lose too.
* v4: gains depend on how much the compiler can do for the portable NTT; LTO mostly helps the many tiny
  helper calls in SLH-DSA (ADRS, `PRF`, `F`, `T_l`).
* v5: ideal is 4x throughput; on the shared box expect ~1.7-2x (other agents use the remaining cores).

## Conclusion (preliminary, noisy box)

See the tables below. The API-level variants (v1, v2) are within noise of the baseline: OpenSSL's EVP
overhead is irrelevant next to the lattice/hash work. `no-asm` costs ~10 % for ML-DSA keygen; `-march=native -flto`
is roughly neutral for ML-DSA and a few percent better for SLH-DSA; threads give the only large win (throughput).

<!-- RESULTS -->
