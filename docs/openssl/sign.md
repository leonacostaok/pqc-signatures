# OpenSSL - sign

Process: (sk, 64-byte msg) -> sig. Pure mode, empty context, deterministic (`"deterministic"=1`:
ML-DSA rnd = 0^32, SLH-DSA opt_rand = PK.seed). The `EVP_PKEY` holding the private key is prepared
outside the timed region (that is the "sk" input); the timed region is one signature.
Match = SHA-256(sig) equals `common/reference.json`.

ML-DSA signing in OpenSSL is the FIPS 204 rejection-sampling loop (each attempt: SHAKE256 expand mask
for l polynomials, NTT, matrix multiply, hint computation), so the wall time has a long tail - the median
and p95 differ noticeably even on a quiet machine. SLH-DSA signing is one FORS signature plus d XMSS
signatures with full tree re-computation: tens of ms (`f`) to seconds (`s`), entirely hash bound.

## Variants

| id | name | build | what / why |
|---|---|---|---|
| sign.v0 | evp-baseline | default | The documented way, per call: `EVP_PKEY_CTX_new_from_pkey`, `EVP_PKEY_sign_message_init(ctx, NULL, {deterministic=1})` (NULL algorithm = implicit `EVP_SIGNATURE` fetch by key type), a size query `EVP_PKEY_sign(ctx, NULL, &len, ...)`, then `EVP_PKEY_sign` into the buffer, `EVP_PKEY_CTX_free`. |
| sign.v1 | prefetch-reuse-ctx | default | `EVP_SIGNATURE_fetch` once; one ctx initialised once with the deterministic param and reused: per call just `EVP_PKEY_sign` with a pre-sized buffer. Removes fetch, ctx alloc, sign-init (which for ML-DSA/SLH-DSA also fetches SHAKE/SHA digests into the provider ctx) and the size query. |
| sign.v2 | ctx-dup-template | default | A fully initialised template ctx is `EVP_PKEY_CTX_dup`'ed for every call and freed afterwards. Gives the "fresh context per signature" semantics many applications need (thread safety, no shared mutable ctx) while skipping fetch/init; measures whether dup is cheaper than init. |
| sign.v3 | no-asm-build | noasm | `no-asm` libcrypto, baseline API path: pure-C Keccak-1600 (ML-DSA, SLH-DSA-SHAKE) and SHA-256/512 without SHA-NI/AVX (SLH-DSA-SHA2). |
| sign.v4 | native-lto-build | native | `-O3 -march=native -flto` libcrypto + driver, baseline API path: vectorised polynomial loops, inlined helpers. |
| sign.v5 | pthread-x4 | default | 4 worker threads sharing the same `EVP_PKEY` (keys are immutable after creation in OpenSSL 3) and each owning a prefetched reused sign ctx; throughput over a batch, `threads: 4`. |

## What to expect

* ML-DSA-44 signing is ~250 us, so the ~5-10 us of EVP ctx setup saved by v1/v2 should be a measurable
  2-4 %; for SLH-DSA it vanishes.
* v3 should hurt most for the SHAKE parameter sets and ML-DSA (everything is SHAKE there).
* v4: potential for the rejection loop (NTT, `vector_*` ops are simple C loops that auto-vectorise with AVX2).
* v5: close to linear on an idle box; the shared key is read-only so there is no contention.

## Conclusion (preliminary, noisy box)

See below. Context reuse / dup gives a few percent on ML-DSA, nothing on SLH-DSA. The build-flag variants
matter less than one would expect because OpenSSL's Keccak assembly is scalar (no AVX2 4-way Keccak), so
`no-asm` costs only ~3-10 % and `-march=native` recovers roughly that much. Threads scale the throughput.

<!-- RESULTS -->
