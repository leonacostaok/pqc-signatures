# OpenSSL - verify

Process: (pk, msg, sig) -> bool. The public key is an `EVP_PKEY` imported from the raw `pub` bytes
with `EVP_PKEY_fromdata` outside the timed region; the signature is the reference signature produced by
`sign.v0`. Every variant must return true for it and false for a one-bit-flipped copy (checked before
the loop and again after the loop on the same, possibly reused, context). `output_sha256` is `"true"`/`"false"`.

ML-DSA verification = SHAKE256(tr || M') to get mu, expand A from rho (SHAKE128), one NTT multiply and
the hint/commitment hash; it is cheaper than signing but still SHAKE dominated. SLH-DSA verification
recomputes the FORS root and d WOTS+ public keys / XMSS auth paths: ms range, hash bound.

## Variants

| id | name | build | what / why |
|---|---|---|---|
| verify.v0 | evp-baseline | default | Documented way, per call: `EVP_PKEY_CTX_new_from_pkey`, `EVP_PKEY_verify_message_init(ctx, NULL, NULL)` (implicit `EVP_SIGNATURE` fetch), `EVP_PKEY_verify`, free. |
| verify.v1 | prefetch-reuse-ctx | default | `EVP_SIGNATURE_fetch` once, one verify ctx initialised once and reused for every call: per call only `EVP_PKEY_verify`. Saves fetch, allocation and the init-time digest fetches. |
| verify.v2 | external-mu | default | OpenSSL's ML-DSA signature implementation accepts the FIPS 204 mu instead of the message (`"mu"=1`, `OSSL_SIGNATURE_PARAM_MU`). The driver caches `tr = SHAKE256(pk, 64)` per key and per call computes `mu = SHAKE256(tr || 0x00 || 0x00 || msg, 64)` with a reused `EVP_MD_CTX`, then verifies mu on a reused ctx. This is the "external mu" flow used by HSM/TLS offload designs; it moves the message hashing out of the provider and lets a caller skip the `tr` recomputation that the provider would otherwise do from the encoded public key. ML-DSA only (no such interface for SLH-DSA). |
| verify.v3 | no-asm-build | noasm | `no-asm` libcrypto, baseline API path. |
| verify.v4 | native-lto-build | native | `-O3 -march=native -flto` libcrypto + driver, baseline API path. |
| verify.v5 | pthread-x4 | default | 4 worker threads, each with its own prefetched reused verify ctx on the shared public key, throughput over a batch, `threads: 4`. |

## What to expect

* ML-DSA-44 verify ~130 us: the EVP setup is ~5 %, so v1 should show a small gain; v2 adds one short
  SHAKE256 call in the driver but saves the same work inside the provider, so it should be within noise
  of v1 (OpenSSL stores `tr` in the key object already, the saving is only the message encoding copy).
* v3/v4 as for sign.
* v5 near-linear throughput scaling; verification has no shared mutable state at all.

## Conclusion (preliminary, noisy box)

See below. Reusing the context is the only API-level change that is consistently (slightly) positive;
external mu is neutral for ML-DSA. The native/LTO build gives a few percent on verify (hash-wrapper
inlining in SLH-DSA, vectorised loops in ML-DSA), `no-asm` costs a few percent, threads scale throughput.

<!-- RESULTS -->
