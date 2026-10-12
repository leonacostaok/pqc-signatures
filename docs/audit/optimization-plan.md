# Experiments that can establish faster signing and verification

This is a prioritized experiment plan, not a claim that an unimplemented optimization is faster. The audited snapshot contains promising signals, but the correctness and measurement findings must be addressed before ranking providers. Do not optimize away input validation, domain separation, rejection checks, or cryptographic work that depends on a new message/signature.

This plan records opportunities identified at historical snapshot `80c832da`. The [current-main addendum](current-main-status.md) distinguishes unresolved harness issues from the later Falcon adapter fix, updated saved results, and separately validated production performance patches.

## First make the objective precise

Publish separate winners for cold single-request latency, warm repeated-key latency, sustained independent-request throughput, CPU cost, and memory-constrained operation. A four-worker batch divides elapsed time by four for throughput accounting; it does not make an individual signature complete four times sooner. A cached public matrix is a legitimate repeated-key optimization whose construction, storage, eviction, and first-use cost must be visible.

Keep fixed-vector deterministic signing as the differential test mode. Add a separate production-mode workload for hedged signing where supported, checking validity and interoperability instead of byte identity. Never promote a deterministic RNG hook or benchmark seed into production. Any comparisons between deterministic and hedged modes must name the mode and entropy costs explicitly.

## Priority 0 — establish trustworthy measurements

Repair the common checker and run manifest, preserve the later Falcon adapter fix, add defensive context-bound validation, validate the exact optimized/concurrent entry points, standardize timing boundaries, and remove serialization/checksum work from stage timings unless the stage contract explicitly requires it. Keep raw results from the existing run as historical evidence and write a new run bundle. Resolve different stage boundaries before selecting stage winners.

Use one timed-region abstraction: prepare inputs before timing; record operation wall time; consume actual returned output; validate outside operation timing; separately account for harness overhead. CPU/op and throughput must cover the same declared interval across providers. Report batch completion latency and batch size in addition to normalized throughput. Record compiler, flags, CPU features, kernel, runtime, source commit, upstream commit/package integrity, corpus hash, selected fast path, warm-up policy, and cache policy.

## Priority 1 — highest-value algorithm work

| Experiment | Providers to start with | Why it is promising | What proves the gain |
|---|---|---|---|
| Reuse decoded ML-DSA key state, ExpandA, secret polynomial NTTs, public t1 NTT, and tr | CIRCL, noble, RustCrypto; then C implementations | Removes repeated key-dependent computation; existing warm-key verify rows show large signals | End-to-end latency for 1, 2, 4, 16, 256 uses per key; alternating-key correctness; setup time and bytes per key |
| SIMD Keccak across independent polynomials or WOTS/FORS work | liboqs native backends; RustCrypto custom SIMD; then CIRCL | Hashing dominates many workloads; SIMD can lower single-core work without per-request thread dispatch | Same corpus and CPU; scalar/SIMD differential outputs; actual CPU-feature dispatch; fallback validation; held-out sign and verify workloads |
| SHA-2 prefix midstate reuse and specialized short-block compression | liboqs fasthash, noble fastjs, BC FastHash, OpenSSL stage alternatives | Repeated fixed-size tweakable hashes can avoid generic hash API overhead | Full sign/verify tests with changing keys/addresses, context boundaries, SHA2 128/192/256 sets, and independent native baselines |
| Eliminate duplicate SLH hypertree passes in stage pipelines | liboqs first, then audit every total pipeline | Recomputing all layer inputs and then timing the layers again overstates real verification cost | Trace each layer once in end-to-end verification; 387 sigver cases, fuzzing, and stage-vs-baseline differential checks |
| Integrate compatible fast paths into one real pipeline | Each provider independently | Several individually fast stages may share allocations or transform formats; fusion may eliminate work | Compare actual assembled verifier with its upstream API, both cold and warm, including parsing and rejection |

For caching, estimate break-even reuse count as `ceil(setup_cost / (uncached_cost - cached_cost))` when the denominator is positive, with the setup scope defined consistently. Measure it rather than using the theoretical estimate alone. Public matrix storage is approximately `k*l*256*4` bytes before runtime overhead if stored as 32-bit coefficients: 16 KiB for ML-DSA-44, 30 KiB for 65, and 56 KiB for 87. Secret-state caches require appropriate lifetime and zeroization policies; a long-lived cache has costs that a per-operation allocation counter will miss.

## Priority 2 — investigate signing directly

The repository decomposes verification in detail but does not give signing the same diagnostic treatment. Add signing profiles before inventing another five variants:

1. ML-DSA: key decoding/expansion, matrix expansion, message hashing, mask sampling, NTT/matrix product, rejection checks, hint generation, and signature encoding. Record rejection count alongside latency over many keys and messages. Reuse only key-dependent state across requests; do not cache a fixed signature, mask, challenge, or rejection outcome as a signing optimization.
2. SLH-DSA: message randomization/hash, FORS signing/tree work, WOTS signing, XMSS authentication paths, and layer traversal. Identify repeated tree work and evaluate bounded per-key tree caches with realistic changing message indices. Account for construction, hit rate, retained memory, eviction, and concurrency. An indefinitely hot fixed-message benchmark is insufficient evidence for a general signing cache.
3. Falcon: use an explicit compressed/padded wire-format contract first. Compare ordinary and supported expanded-key signing paths while measuring key expansion cost and persistent memory. Require interoperability in both directions, strict malformed-encoding rejection, and review of floating-point/platform assumptions before comparing custom rewrites.

Profiles and work counters are diagnostic instrumentation; disable them for final timing after confirming the measured path is equivalent.

## Priority 3 — engineering and platform experiments

Reuse algorithm/context objects and preallocate scratch buffers where ownership permits. Measure request sizes for which FFI overhead outweighs native hashing gains. Test thread pools with independent jobs rather than spawning threads per tiny stage. Compare compiler/LTO/PGO configurations on held-out workloads, treating a few-percent change as inconclusive without replicated runs. Test available CPU backends separately: the source data's x86 VM has no SHA-NI, so its SHA-2 conclusions do not establish winners on SHA-NI-capable x86 or ARM SHA hardware.

Do not force exactly five alternatives when only two are substantive. Give each variant metadata for implementation identity, optimization mechanism, input/cache assumptions, runtime/backend, thread count, and supported parameters. Runtime/build toggles and aliases are useful controls, but are not five new cryptographic techniques.

## Suggested run matrix and decision rule

Start with ML-DSA-65 and SHA2/SHAKE SLH-DSA-128f for quick diagnosis, then all supported sets including slow `s` variants. Use fixed corpus seeds so every provider receives identical inputs. Include valid signatures, cheap malformed inputs, and full-cost invalid inputs as separate distributions. Sweep messages from empty through 64 B, 1 KiB, and 64 KiB, and contexts at 0/255 bytes plus rejected 256-byte controls. Separate single-key, alternating-key, and cache-exceeding key populations.

Run independent randomized-order repetitions with thermal/CPU conditions recorded. Select candidates using training runs, then measure the selected candidate on held-out runs. Report median and tail latency, throughput, CPU/op, confidence intervals across runs, allocation rate, peak/retained memory, and setup cost. Promote only an end-to-end implementation that preserves all outputs and rejection behavior, has no unexplained sanitizer/differential failures, and improves the chosen objective outside measurement noise.

The historical data suggests where to investigate: noble ML-DSA-65 fastjs signing is recorded at 2.06× its baseline throughput, noble pkcache verification at 2.59×, CIRCL preunpacked verification at 3.88×, and liboqs SHAKE-128f fasthash verification at 2.18×. These are ratios from saved rows, not fresh benchmark claims; provider timing findings and cache assumptions limit interpretation. RustCrypto and Bouncy Castle were provisional in that snapshot; their later saved rows do not remove the unresolved comparability and evidence-gating issues.
