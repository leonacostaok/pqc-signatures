# Validated provider improvements

These are comparisons of narrow production patches against each provider's own pinned upstream baseline. They are not a ranking of providers: versions, APIs, algorithms and operation boundaries differ. Measurements use one Apple M1 Pro host; other coordinated builds and tests were stopped, but ordinary desktop processes remained active. Ratios above 1 mean faster execution. Every report retains its controls, losing samples and limitations.

| Provider and scope | Supported result | Report | Review draft |
| --- | --- | --- | --- |
| noble ML-DSA | Signing 1.091–1.189×; verification 1.101–1.189× across two library and two Node versions | [Fresh-input/version study](https://github.com/leonacostaok/pqc-signatures/blob/9288288f2fd95fa53a9320b90e513577d94323e0/docs/noble/robustness.md) | [noble #56](https://github.com/paulmillr/noble-post-quantum/pull/56) |
| liboqs SLH-DSA SHA2 | Signing 4.269–5.276×; verification 4.411–5.288× | [Compression backend](../libs/liboqs/experiments/sha2-openssl/README.md) | [Personal-fork #1](https://github.com/leonacostaok/liboqs/pull/1) |
| CIRCL SLH-DSA SHA2 | Signing 1.322–1.369×; verification 1.323–1.425×; key generation 1.329–1.346× | [Public-prefix reuse](performance/circl/README.md) | [CIRCL #708](https://github.com/cloudflare/circl/pull/708) |
| RustCrypto ML-DSA | Key construction 1.173–1.177×; fresh-key signing 1.038–1.067×; warmed signing/verification near parity | [Constructor reuse](rustcrypto/keygen-reuse.md) | [RustCrypto #1461](https://github.com/RustCrypto/signatures/pull/1461) |
| OpenSSL SLH-DSA SHA2-192/256 | Signing 1.094–1.195×; verification 1.073–1.172×; unchanged controls near parity | [SHA-512 prefix](openssl/sha512-prefix.md) | [Personal-fork #1](https://github.com/leonacostaok/openssl/pull/1) |
| Bouncy Castle SLH-DSA | Complete verification allocates 2.8–7.3% fewer bytes; a whole-verification latency gain is not established | [FORS bit extraction](bouncycastle/fors-base2b.md) | [Personal-fork #1](https://github.com/leonacostaok/bc-java/pull/1) |

## What is reused

Noble removes temporary NTT products and reduces once per coefficient; it adds no cross-call cache and keeps the official hash implementations and cleanup paths. Its robustness study creates fresh input buffers and options for each API call, alternates execution order, and separately measures the first cryptographic operation in a fresh process. Warmed calls cycle distinct fixture values; they do not generate a new random key for every iteration. First-operation gains are smaller and process-startup measurements are mixed, so the warmed result is not a startup claim. Canonical coefficient bounds keep the new integer sums below 2^49 and exactly representable by JavaScript numbers.

Liboqs replaces portable SHA2 compression with the configured OpenSSL backend and adds no cache. Its upstream algorithm already retains public prefix state. The new temporary SHA contexts are explicitly cleansed. Fallback configurations preserve portable compression.

CIRCL and OpenSSL prepare public hash prefixes within each operation. Timings include that preparation and cleanup; neither patch retains key-dependent state across API operations. They trade small additional operation-local storage for less repeated hashing. Native-library reports specify which key import or decoding work lies outside their timed API calls.

RustCrypto avoids deriving a public key twice during construction. It fills the same pre-existing public-key cache with already computed values; its warmed signing and verification paths remain unchanged. Bouncy Castle replaces a bounded BigInteger bit buffer with integer arithmetic, without introducing a cache. The original shared-JVM protocol showed systematic SHAKE verification losses; separate-JVM parameter medians ranged from 0.990× to 1.005× with substantial fork variation. Both runs remain in the evidence. The draft claims reduced allocation, not faster complete verification.

## Evidence and review scope

Each experiment records pinned sources, the patch, runtime/compiler information, correctness gates and raw measurements. Tests cover exact outputs with matched entropy, valid and invalid verification, parameter boundaries, and relevant cleanup or state ownership. Byte equality requires identical key material, messages, contexts and signing entropy; independently randomized signatures need not be equal. These tests and source reviews do not constitute formal side-channel proof or FIPS module certification.

Noble's arithmetic oracle and two-version/runtime study, liboqs's executed-case checks, CIRCL's baseline-failing resource test, RustCrypto's independent verification-key derivation, and OpenSSL's actual-source digest oracle guard against measuring an unchanged or incorrectly built candidate. Invalid attempts remain labeled in the evidence. Independent summary checks are saved alongside the provider results.

The [original harness audit](https://github.com/leonacostaok/pqc-signatures/pull/3) documents separate remaining cache, bounds, acceptance and measurement defects. These production experiments use their own gates; their success does not repair the original harness or establish a general fastest-provider ranking.

All drafts are authored from `leonacostaok`. Noble, CIRCL and RustCrypto drafts target upstream. Liboqs, OpenSSL and Bouncy Castle review drafts target personal forks because their upstream submission policies require disclosure or submitter attestations that need resolution before a later upstream submission. Evidence links target this private repository and require access.

The [independent BC follow-up check](../results/bouncycastle/independent-isolated-check.json) matches every saved process output, exit status and pair against the final summaries. Reproduce it with `python3 libs/bouncycastle/experiments/audit-isolated.py results/bouncycastle/experiments/fors-isolated-jdk25-arm64.json /path/to/new-check.json`.

## Fresh ten-key follow-up

The [candidate-first follow-up](ten-key-order.md) generates ten new keys per parameter, runs all changed providers before any original, and preserves exact-output checks, raw per-key wall/CPU timings and every loss. It reproduces the large liboqs gain and the affected noble/CIRCL/OpenSSL and Rust construction gains; Bouncy Castle latency remains mixed.
