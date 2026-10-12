# Resource audit of the published performance patches

This audit checks the five production patches against their original measured upstream bases. [The live PR snapshot](../../results/resource-regressions/pr-heads.json) records the exact revisions. Noble #56 is now closed; its reviewed code is unchanged. The other four PRs remain open. No production patch is modified by this audit.

The question is whether faster operations cost more allocation, retained memory, temporary working storage, cleanup complexity, or latency elsewhere. These are separate properties: fewer allocated bytes do not establish a smaller peak heap, and a passing digest test does not establish safe failure cleanup. Original cross-provider harness memory results are not used as evidence for these production patches.

## Existing evidence and boundaries

The prior narrow experiments checked exact outputs with matched entropy, invalid-input rejection, ownership, and the affected operation timing. CIRCL's previous allocation regression covered F/H/T primitives only after setup. OpenSSL's prior report disclosed an additional 216-byte prefix context but did not measure complete allocator activity. Rust's existing cache is unchanged by its constructor optimization. Noble's product-buffer elimination does not establish lower peak live memory because row evaluation keeps several public polynomials live at once.

The new probes count allocations around declared API boundaries and inspect destruction and failure paths. Instrumented resource runs make no speed claim. Allocation counts, requested payload bytes, runtime-accounted bytes, object layout, and post-GC diagnostics must be identified separately. Key import and caller-buffer preparation outside a counter interval are not silently included in the result. Synthetic fixture keys are public test data.

## Timing regressions retained from the earlier experiments

Noble's reported gains describe warmed operations. Three of 960 warmed raw pairs lose, including a retained 0.1881× verification outlier for ML-DSA-87 on library 0.7.0/Node 24; the raw first-operation and startup-inclusive studies contain 192/1,440 and 591/1,440 losses respectively. The positive warmed medians do not establish better tails or startup behavior. No cause is assigned to the outlier.

Rust's reported gain concerns construction; existing-key signing and verification remain near parity, with a retained ML-DSA-44 signing fork at 0.9224×. Every constructor/fresh-key-sign fork median improved, but raw repeated pairs include one constructor loss and two fresh-key-sign losses; the ten-key pass includes two ML-DSA-44 fresh-key-sign losses, one at 0.6646×. These observations remain in the provider report and are not silently discarded.

CIRCL's affected SHA-2 cells improved in every recorded fork and all 360 affected raw pairs, while unchanged SHAKE controls lose 27/60 pairs. OpenSSL retained 12 losing affected individual pairs despite positive medians in all affected case/fork cells; its ten-key check retained one affected verification loss and mixed key-generation results. Liboqs's retained balanced affected signing/verification comparisons consistently improved on the tested host.

These earlier measurements do not establish tail-latency behavior, universal cross-platform gains, or performance under memory pressure. The resource audit does not replace them with timings from an instrumented allocator.

## Results

### OpenSSL

The focused hash-context probe measures one extra allocation and 224 additional requested bytes for SHA2-192/256: a 216-byte `SHA512_CTX` plus an 8-byte pointer in the surrounding hash context. Requested retained bytes for a new or duplicated hash context rise from 392 to 616. SHA2-128 grows from 392 to 400 and SHAKE from 1,360 to 1,368 because their hash-context structure also contains the pointer. These are allocator-requested payload bytes, not allocator metadata, RSS, or complete EVP operation totals.

All 112 baseline/candidate lifecycle rows passed, including every one of 88 injected new/dup allocation failures. Allocations and frees balance, net live bytes return to zero, outputs match, and a duplicate remains usable after its source is freed. Successful-use paths inspect cached/scratch bytes immediately before free and require them to be zero. Failure paths establish leak-free cleanup; they do not inspect zeroization of every partially constructed object. The synthetic keys deliberately omit an HMAC context so this is an isolated hash-context measurement. Public EVP reinitialization frees the old provider operation context before creating a replacement; source review found no new reinitialization leak.

The prefix belongs to the hash/EVP context. A caller can retain or reuse that context; the earlier timing experiment creates and destroys an operation context for each measured API operation and includes the added setup/cleanup cost.

### liboqs

The focused private-hash probe observes zero OpenSSL allocator calls across 52 varied and padding-boundary cases per variant, including the first hash. All 104 hash outputs per variant match Python's independent SHA-256/SHA-512 oracle. This is not a process-wide libc allocation or RSS measurement. The production adapter adds no explicit heap allocation, and its temporary OpenSSL context is cleansed.

There is a compiler-specific stack cost: Apple clang 21 with `-O3` on arm64 reports SHA-256 compression's local frame changing from 160 to 144 bytes and SHA-512's from 192 to 256 bytes. The latter adds 64 bytes. Inlining also changes callers: SHA-256 update/final frames grow by 112 bytes and its one-shot frame by 128 bytes; SHA-512 update/final frames grow by 224–240 bytes and its one-shot frame by 224 bytes. These local frames exclude backend callees, cannot simply be added together, and do not measure whole-operation peak stack. Existing exported private hash-state sizes remain unchanged.

### CIRCL

Complete SHA-2 operations add approximately 1,088 allocated bytes for category 1 or 1,376 for categories 3/5, and normally 12 allocation objects. A few samples contain an additional small runtime allocation; all are retained. SHAKE controls are unchanged. The counter run includes operation-owned prefix setup and cleanup; caller-buffer creation and key decoding are outside its declared API interval. Automatic GC is disabled and no measured call reports a collection. Allocation counters are runtime-accounted bytes, not peak memory.

The source retains no new global/key-owned cache. Cleanup checks verify that digest state returns to a public-only prefix, saved state and scratch/arena bytes are cleared, references are dropped, and double `Clear` is harmless. This supports a bounded operation-local allocation tradeoff for the earlier measured speed gains, rather than an allocation improvement.

### Noble

Noble removes 16/30/56 temporary 1,024-byte polynomial buffers from key generation, public-key derivation, and verification for ML-DSA-44/65/87. Signing savings depend on retry count. The instrumented constructor checks observed numeric-length allocations and no ArrayBuffer-backed view constructors. These are logical Int32Array payload savings, not total JS heap allocation. Key generation and verification now keep 4/5/7 public row polynomials live concurrently, so lower allocation volume does not establish lower peak live memory.

In the separate unmodified-runtime post-GC diagnostic, candidate final heap-used medians are 1,728–9,832 bytes higher across the twelve parameter/operation cells. Final ArrayBuffer balances match and stay constant after the first measured batch in all 96 processes. These snapshots include harness, JIT, and potentially last-call references; they neither establish a growing leak nor prove lower peak memory. All 27,648 measured calls passed output checks. The incomplete initial observer-delivery attempt is retained separately from the successful collection.

### RustCrypto

Rust's four feature configurations, three parameters, and four cases show exactly equal baseline/candidate allocation counts, allocated bytes, observed live peaks, retained bytes, and drop accounting. Allocating construction uses four allocations and requests 65,760/108,768/178,400 bytes; existing-key signing uses two and requests 5,120/6,656/9,216 bytes; verification allocates zero. No-alloc operations allocate zero in both versions. These existing allocations are not introduced by the patch. The separately cloned caller verification key is outside the operation counters.

The existing optional zeroization behavior is unchanged: an allocated seed is observed cleared before deallocation when `zeroize` is enabled and uncleared in both default builds; no heap-seed observation applies without `alloc`. This observation does not establish complete secret-stack erasure. In the original uninstrumented benchmark binaries, constructor-local frames shrink from 182,384/214,736/398,704 to 142,352/176,800/343,328 bytes for the three parameter sets. These are compiler-specific individual frames, not total call-stack peaks.

## Assessment and evidence

No new correctness, ownership, or cleanup defect was established in the tested paths. This is not a claim of zero regressions: CIRCL adds allocation pressure, OpenSSL adds a bounded allocation and another failure point, liboqs raises some stack frames, and noble trades lower polynomial allocation traffic for greater public-row liveness. Rust shows unchanged heap costs and smaller measured constructor frames. Complete peak memory, prolonged concurrent load, and behavior on other architectures remain open measurements.

CIRCL is the clearest next target for reducing allocation overhead without losing its hashing savings. Application-level GC and memory-pressure testing would be needed before claiming that its speed improvement holds under those conditions. Existing-key Rust signing/verification and noble startup should not be promoted as demonstrated speedups.

Provider reports include source identities, probe boundaries, raw results, retained timing losses, and reproduction commands:

- [CIRCL](../circl/resource-audit.md)
- [OpenSSL](../../libs/openssl/experiments/resource-audit/README.md)
- [liboqs](../../libs/liboqs/experiments/resource-audit/README.md)
- [Noble](../noble/resource-audit.md)
- [RustCrypto](../rustcrypto/resource-audit.md)

Integration checks recomputed noble and CIRCL summaries from sealed raw files, independently checked CIRCL aggregate arithmetic, checked all Rust feature-case allocation/sizing/drop comparisons, independently checked OpenSSL lifecycle and failure grids, and ran the C probe checkers and their corrupted-output rejection tests. No new production timing run was made during integration.
