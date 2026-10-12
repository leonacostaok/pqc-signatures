# OpenSSL SLH-DSA prefix resource audit

The published [PR #33196](https://github.com/openssl/openssl/pull/33196) deliberately trades memory for repeated SHA-512 prefix hashing: **one extra 216-byte allocation plus an 8-byte context pointer, or 224 requested bytes per live SHA2-192/256 hash context** on the tested arm64 build. Unaffected SHA2-128 and SHAKE contexts grow by the 8-byte pointer without another allocation. Deep duplication incurs the same respective cost.

| Focused hash-context lifecycle, new or duplicate | Original allocations / requested bytes | Candidate allocations / requested bytes | Increase |
|---|---:|---:|---:|
| SHA2-128 | 3 / 392 B | 3 / 400 B | 8 B |
| SHA2-192/256 | 3 / 392 B | 4 / 616 B | 1 allocation, 224 B |
| SHAKE-128/192/256 | 4 / 1,360 B | 4 / 1,368 B | 8 B |

The [raw evidence](../../../../results/openssl/resource-audit/) contains 112 lifecycle rows: 24 successful create/use/free or duplicate/use-after-source-free cases and 88 individual allocation-failure injections across both versions. All tracked allocations were freed, all final tracked live-byte counts were zero, and baseline/candidate H/T/PRF outputs match. Successful paths checked that cached states and scratch buffers were zeroed before their allocator free callback. The failure-injection paths check leak freedom, not byte-by-byte zeroization of partial contexts; those prefixes are public and secret-bearing scratch has not been used yet.

## Ownership, cleanup and compatibility

At signed head `857cb293518745277fcf2594e8042fcc6eda549c`, `crypto/slh_dsa/slh_dsa_local.h:56` adds a raw SHA-512 context pointer, not an EVP digest context. `slh_hash.c:494–502` initializes the extra allocation only when `n > 16`, hashing public `PK.seed` and fixed zero padding. H and T copy that immutable prefix into the existing scratch context (`slh_hash.c:389` and `416`). The allocation is deep-copied at `slh_hash.c:520–524`; it is cleared and freed at `slh_dsa_hash_ctx.c:105`. The existing scratch context, which may contain secret-derived PRF state, is cleared at line 106.

The cache belongs to `SLH_DSA_HASH_CTX` and its owning provider EVP context. A caller can reuse an initialized EVP context, so its lifetime is not necessarily one signing or verification operation. There is no new global or key-object cache. A context's mutable scratch already precludes concurrent use of that same context; the independent duplicate owns different scratch and cached-prefix storage. Public EVP reinitialization first frees old operation state (`crypto/evp/signature.c:607`, `crypto/evp/pmeth_lib.c:206–211`), reaching provider cleanup at `providers/implementations/signature/slh_dsa_sig.c:82`; the direct assignment of a new hash context at line 184 does not establish a new public reinitialization leak.

New/duplicate allocation failures reach existing cleanup (`slh_dsa_hash_ctx.c:30–52` and `59–79`). This introduces one more possible allocation-failure point for SHA2-192/256; all added and existing allocation positions in the focused lifecycle were exercised. Buffer sizes remain fixed for supported `n = 16, 24, 32`; the changed code adds no variable-size arithmetic or new externally supplied bounds. Internal deprecated-header handling is present at `slh_dsa_hash_ctx.c:9`; this patch already used low-level SHA contexts in its base. The retained no-deprecated compile check passed. FIPS deployment, other architectures, alternative configurations, full provider clone matrices and sanitizer coverage beyond previously retained tests are not claimed here.

## Probe and reproduction

`ctx-lifecycle.c` installs OpenSSL allocator callbacks and isolates each context creation or duplication through final free. It uses a synthetic key with `key.hmac == NULL`, so totals are **focused hash-context totals, not full EVP key/sign/verify allocation totals**. During duplication, the existing source context is outside the accounting window; it is freed before the duplicate is used. H/T/PRF perform no additional tracked allocation once initialized. Six representative parameter sets cover each SHA2/SHAKE `n` branch; both fast and small algorithm variants were not separately executed in this resource probe.

`run.py` rebuilds and validates both probes against existing sealed static libraries; it rejects missing, reordered, duplicate, leaking or incomplete failure cases and requires exact baseline/candidate output equality. It accepts additional allocation attempts after a failed attempt because an existing SHAKE path checks two allocation results together. `test_runner.py` mutates saved observations to check rejection without another crypto run.

```sh
python3 libs/openssl/experiments/resource-audit/run.py \
  --baseline-source /path/to/openssl/base-122db7 \
  --candidate-source /path/to/openssl/head-857cb2 \
  --sealed-build /path/to/provider-performance/libs/openssl/build/sha512-prefix \
  --out libs/openssl/build/resource-audit/reproduction
python3 libs/openssl/experiments/resource-audit/test_runner.py
```

The evidence's `*-build.json` records the actual build arguments and `provenance.json` binds the signed source tree to the measured candidate and the linked static libraries. Run `python3 libs/openssl/experiments/resource-audit/record.py` to recheck these bindings and both providers' saved resource observations using the original local build paths. The probe measures requested bytes, not allocator size classes or RSS; no speed conclusions come from this instrumented run. No new leak, aliasing or concurrency defect was established by this bounded review. The extra allocation and retained memory are real costs, and full EVP allocation totals remain unmeasured.

## Retained latency losses

The [latency review](../../../../results/openssl/resource-audit/latency-review.json) recomputes the earlier balanced experiment without removing losses. SHA2-192/256 has **12/720 losing wall pairs and 11/720 losing CPU pairs**; its worst individual ratio is 0.840× for both clocks. All affected case-level fork medians remain above 1, and the parameter summaries remain 1.094–1.195× for signing and 1.073–1.172× for verification. Controls have **285/540 losing wall pairs and 300/540 losing CPU pairs**, with minima of 0.384× wall and 0.906× CPU. Control parameter medians remain close to 1; three cells have small aggregate wall losses: SHA2-128f signing (0.997593×), SHA2-128s verification (0.999408×), and SHAKE-128f verification (0.999888×). These controls do not establish a speed benefit from their extra context pointer.

The candidate-first ten-key pass retains **39/210 wall and 39/210 CPU individual losses**. SHA2-192f key generation has a total-wall ratio of 0.986277× and total-CPU ratio of 0.994430×; SHA2-128s signing has a total-wall ratio of 0.999074×; SHAKE-128f verification has a total-CPU ratio of 0.998707×. Affected signing has no individual loss in that pass, while affected verification has one. The single-pass order is confounded with elapsed-time drift and is not a balanced repeated latency estimate. `python3 libs/openssl/experiments/resource-audit/review-latency.py` reproduces these counts from retained results; source-bound original acceptance records remain unchanged.
