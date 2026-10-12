# Bouncy Castle alternatives

We tested 11 implementation alternatives in three independently prepared campaigns against bc-java `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. The strongest speed candidate is **ML-DSA companion constants alone**: signing time fell about 5–6% across the three parameter sets on Java 25, with about 6.3% improvements for ML-DSA-44 and -65 on Java 17 using a new key corpus. ML-DSA-87 did not meet the confirmation rule on Java 17. These are measured results on one shared host, not universal performance guarantees.

| Alternative | Observed benefit | Cost or counterexample | Assessment |
|---|---|---|---|
| NTT public companion constants | Java 25 signing −4.99% to −6.03%; Java 17 signing −6.26%/−6.33% for 44/65, with lower thread CPU and all four rounds faster | 1,024 bytes of static array payload plus header; Java 17 87 signing −2.19% with one losing round; no consistent allocation benefit | Best small candidate for upstream review |
| Fuse final inverse scaling | Fewer arithmetic reductions | Did not meet the first screen's speed rule; changes intermediate modular representatives | Do not promote alone |
| Combine NTT changes | Some signing cases improve more | Java 17 44 keygen +20.54% time and 65 signing +12.45%; large round variation despite lower CPU in some cells | Prefer the smaller companion-only patch |
| Reduce once per matrix dot product | Fewer Montgomery reductions | Signing about 3.6–4.4% slower across all sets; combined streaming/reduction also regressed | Reject as a speed optimization |
| Stream matrix rows | Keygen allocation −18.2% to −29.6%; verification −22.0% to −33.0% | Small/mixed timing changes; unchanged signing control moved; seven allocation processes had unusually long durations | Memory candidate requiring confirmation |
| Hoist one WOTS address / use two addresses | Lower keygen/signing allocation | Mixed timing; unchanged verification controls shifted substantially in the followup | Allocation benefit; no general speed claim |
| Remove redundant WOTS field clears | A few faster signing cells | No meaningful allocation saving; repeatable 128f keygen loss and mixed higher-size results | Do not promote as a general speedup |
| Reuse WOTS chain buffers | Large allocation reductions across keygen, signing and verification | Some operations slower, including SHA2-256f verification +15.85% time/+15.73% CPU | Explicit allocation/latency tradeoff |
| Peel the buffer loop's first hash | Some gains against the existing buffer candidate | Direct comparison with stock regressed in 128f keygen; failed the frozen followup rule | Rejected; all results retained |

The [complete colored table](alternative-measurements.md) retains all 156 candidate/action comparisons, including original and changed times, CPU changes and allocated bytes. Green/red marks direction, not statistical confidence. Group reports preserve round/pair variation and selection rules: [NTT](ntt-alternatives.md), [matrix](matrix-alternatives.md), [WOTS](wots-alternatives.md). The [independent NTT review](alternative-review.md) explains why companion-only has the smallest review burden.

## Correctness and memory boundaries

The changes retain algorithm parameters and encoded key/signature sizes. They introduce no persistent key cache. Public constant tables and temporary buffers reused inside one operation work with unique keys. Exact-output, malformed-input, ownership and arithmetic gates passed for the tested variants; this does not establish a formal constant-time proof or independent cryptographic certification.

Every one of the eight initial ML-DSA builds passed the complete pinned `MLDSATest` and `MLDSAWycheproofTest` (14 and 3 methods, including 631 Wycheproof cases per build). All six WOTS builds passed four selected native `SLHDSATest` methods with full verification-vector sampling, plus exact-output checks across all 12 parameter sets. The full native SLH-DSA signing-vector suite was not repeated. Java 17 NTT preparation repeated native tests and added direct checks of production companion constants and helper arithmetic.

Allocation is calling-thread bytes allocated per operation, measured in separate JVMs. It is not peak/live heap, RSS, stack size or GC pause time. Reducing allocation can reduce GC pressure; no GC-pause percentage is inferred here. The NTT static table is excluded from per-operation counters and stated separately. No stack reduction or increase is claimed.

## Measurement limits and evidence

The campaigns used 1,464 serial fresh JVM processes. ML-DSA measured 128 distinct keys once per process after 1,000 warmup calls on separate keys; SLH-DSA used 10 distinct keys once after 20 warmup calls. Process order was balanced/reversed. Fresh operation setup is included; key import and output checks are outside the measured call. Repeated processes use the same paired corpus; the Java 17 NTT confirmation uses a disjoint corpus. Different heaps, runtimes and warmup limits prevent absolute speed rankings across campaigns.

The host was not isolated. All controlled builds, tests and other agent benchmarks stopped during each measurement window, but OS/user activity remained. Seven matrix allocation processes lasted 61–4,071 seconds; their cause is unknown and all counts remain. Matrix timing collection finished before those long durations. Unchanged WOTS verification controls moved by as much as +12.19% in the followup, limiting causal speed claims. No result was selectively dropped or rerun.

[Native records](../../results/bouncycastle/alternative-comparison/native/), [independent audits and chronology](../../results/bouncycastle/alternative-comparison/), and [reproduction scripts](../../libs/bouncycastle/experiments/alternative-comparison/) preserve the evidence. Saved-evidence audits check records and identities; they do not rerun cryptography. Source, vector and runtime pins are in each campaign. This is AI-assisted supporting engineering and test work, with three Astra agents and coordinating review; it is not independent cryptographic certification.
