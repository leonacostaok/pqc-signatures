# Complete signature performance and resource comparison

Every library appears for every parameter in the original project scope. NM means no measurement in the coordinated production-patch experiment; it does not mean unsupported or zero gain. The older x86 harness has separate known audit defects and is not substituted into missing cells. This is a complete evidence matrix, not a newly executed complete benchmark.

🟢 = observed favorable direction; 🔴 = observed unfavorable direction; 🟡 = mixed, provisional, or an inference; ⚪ = unchanged, unmeasured, or no evaluated patch. Colors apply to each metric independently and do not imply statistical significance, security approval, or universal performance.

## Timing basis

All times below are milliseconds per operation: original → changed, arithmetic means over ten matched distinct keys. Percentage time saved = 100 × (1 − changed/original). The changed providers ran before originals, so order drift is a limitation. APIs, fixtures, builds and runtimes differ between providers: compare within a row, not as a language or library ranking. Small control differences must not be called optimization gains. The Rust keygen column measures construction from a seed; sign/verify use existing keys. Bouncy Castle here is the earlier FORS candidate, not the newer sampling/WOTS experiments.

Source: [independent calculation](../../results/ten-key-order/independent-check.json), SHA256 `28ef8c23e372d7a9161c297bc522b545d374a14921786db525f067a6120b31c5`. [Protocol and boundaries](../ten-key-order.md). [Resource audit](published-resource-regressions.md). Original raw hashes were rechecked when preparing this comparison.

## Memory and GC interpretation

Allocation traffic is the sum of bytes requested over an operation; live memory is what is still reachable; peak memory is the maximum simultaneously occupied; stack frames are function-local storage. These are not interchangeable. Lower allocation traffic can coexist with a higher live heap or slower code. Local stack frames cannot be added indiscriminately when inlining and call paths differ.

Noble runs under a JavaScript GC: unreachable objects can be reclaimed, while live objects remain. V8 has generational collection; eliminating short-lived arrays may reduce collection work, but greater row liveness and runtime/JIT storage can increase observed memory. Typed-array backing stores and ordinary JS heap are separate counters. Our post-GC snapshots do not measure operation peaks or prove leak absence. [V8 explanation](https://v8.dev/blog/trash-talk).

CIRCL runs under Go GC. Higher allocation rate can make collection more frequent and consume CPU, while live heap and the configured memory budget affect the collection target. Our allocation probe disabled automatic GC to count operation allocations; it did not measure added pauses or throughput under normal GC. +1,376 B per call at a hypothetical 10,000 calls/s is 13.76 MB/s additional allocation traffic, not retained heap growth and not an achieved throughput claim. [Go GC guide](https://go.dev/doc/gc-guide).

Bouncy Castle runs under JVM GC. Allocations and reclamation consume resources, but the selected collector, JIT and object lifetimes affect outcomes. Lower allocated bytes do not guarantee faster operations or fewer pauses; our newer BC candidates demonstrate this directly. No GC-pause improvement is established. [HotSpot GC guide](https://docs.oracle.com/en/java/javase/21/gctuning/index.html).

liboqs and OpenSSL use C allocation/free and stack lifetimes; RustCrypto uses ownership/drop rather than a tracing GC. They can still incur allocation costs, fragmentation, large stack frames, or retained storage. Freeing memory does not guarantee immediate reduction of OS resident memory. Rust zeroization remains feature-dependent; unchanged allocation accounting is not a complete secret-erasure guarantee.

## ML-DSA-44

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | 1.63 → 1.31; 🟢 19.63% less time | 9.06 → 7.75; 🟢 14.45% less time | 2.02 → 1.76; 🟢 12.88% less time | 🟢 16 KiB fewer polynomial payload bytes in keygen/verify; signing depends on retries. 🔴 More simultaneous public-row storage; post-GC heap medians +1.7–9.8 KB across cells. ⚪ Peak/stack unmeasured. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| RustCrypto | Rust | 0.121 → 0.106; 🟢 12.57% less time | 0.199 → 0.190; 🟢 4.57% less time | 0.037 → 0.037; 🟢 0.15% less time | ⚪ Heap counts/bytes/retention unchanged in tested cases. 🟢 Constructor local frame 182,384 → 142,352 B. No tracing GC; total stack peak unmeasured. |
| Bouncy Castle | Java | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |

## ML-DSA-65

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | 2.43 → 2.05; 🟢 15.75% less time | 23.26 → 20.31; 🟢 12.69% less time | 3.00 → 2.63; 🟢 12.58% less time | 🟢 30 KiB fewer polynomial payload bytes in keygen/verify; signing depends on retries. 🔴 More simultaneous public-row storage; post-GC heap medians +1.7–9.8 KB across cells. ⚪ Peak/stack unmeasured. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| RustCrypto | Rust | 0.231 → 0.194; 🟢 16.04% less time | 0.761 → 0.754; 🟢 0.95% less time | 0.053 → 0.053; 🔴 0.19% more time | ⚪ Heap counts/bytes/retention unchanged in tested cases. 🟢 Constructor local frame 214,736 → 176,800 B. No tracing GC; total stack peak unmeasured. |
| Bouncy Castle | Java | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |

## ML-DSA-87

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | 3.81 → 3.11; 🟢 18.44% less time | 22.51 → 18.72; 🟢 16.84% less time | 4.61 → 3.88; 🟢 15.73% less time | 🟢 56 KiB fewer polynomial payload bytes in keygen/verify; signing depends on retries. 🔴 More simultaneous public-row storage; post-GC heap medians +1.7–9.8 KB across cells. ⚪ Peak/stack unmeasured. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| RustCrypto | Rust | 0.313 → 0.264; 🟢 15.79% less time | 0.709 → 0.700; 🟢 1.21% less time | 0.086 → 0.078; 🟢 9.13% less time | ⚪ Heap counts/bytes/retention unchanged in tested cases. 🟢 Constructor local frame 398,704 → 343,328 B. No tracing GC; total stack peak unmeasured. |
| Bouncy Castle | Java | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |

## SLH-DSA-SHA2-128f

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | 1.15 → 0.211; 🟢 81.61% less time | 26.86 → 5.08; 🟢 81.09% less time | 1.64 → 0.309; 🟢 81.14% less time | ⚪ No OpenSSL allocator calls in focused hashes. SHA256 local frames: 🟢 compression −16 B; 🔴 update/final +112 B, one-shot +128 B. No tracing GC; total stack peak unmeasured. |
| OpenSSL | C | 0.245 → 0.245; 🟢 0.04% less time | 5.71 → 5.69; 🟢 0.26% less time | 0.361 → 0.357; 🟢 1.22% less time | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | 0.443 → 0.330; 🟢 25.59% less time | 10.13 → 7.69; 🟢 24.12% less time | 0.619 → 0.460; 🟢 25.69% less time | 🔴 Normally +12 objects / +1,088 allocated B per operation. Potential extra GC pressure, not measured GC latency. Setup local frames unchanged; argument/result areas +24/+32 B; peak unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 1.93 → 1.90; 🟢 1.62% less time | 44.21 → 43.93; 🟢 0.62% less time | 2.82 → 2.82; 🔴 0.12% more time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHA2-128s

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | 73.43 → 13.58; 🟢 81.51% less time | 562.00 → 107.11; 🟢 80.94% less time | 0.569 → 0.110; 🟢 80.72% less time | ⚪ No OpenSSL allocator calls in focused hashes. SHA256 local frames: 🟢 compression −16 B; 🔴 update/final +112 B, one-shot +128 B. No tracing GC; total stack peak unmeasured. |
| OpenSSL | C | 15.50 → 15.39; 🟢 0.67% less time | 119.06 → 119.17; 🔴 0.09% more time | 0.135 → 0.132; 🟢 1.93% less time | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | 28.08 → 20.94; 🟢 25.43% less time | 213.28 → 162.46; 🟢 23.83% less time | 0.225 → 0.173; 🟢 22.92% less time | 🔴 Normally +12 objects / +1,088 allocated B per operation. Potential extra GC pressure, not measured GC latency. Setup local frames unchanged; argument/result areas +24/+32 B; peak unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 105.14 → 104.83; 🟢 0.30% less time | 805.44 → 802.94; 🟢 0.31% less time | 1.04 → 0.972; 🟢 6.37% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHA2-192f

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | 1.66 → 0.316; 🟢 80.98% less time | 43.91 → 9.32; 🟢 78.78% less time | 2.38 → 0.499; 🟢 79.04% less time | ⚪ No OpenSSL allocator calls in focused hash probes. 🔴 Some local stack frames +112–240 B; SHA256 compression −16 B. No tracing GC; total stack peak unmeasured. |
| OpenSSL | C | 0.338 → 0.343; 🔴 1.39% more time | 10.37 → 9.37; 🟢 9.73% less time | 0.567 → 0.532; 🟢 6.04% less time | 🔴 +1 allocation and +224 requested B per hash context; clone has same cost. 🟢 Tested failure cleanup passes. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | 0.650 → 0.496; 🟢 23.64% less time | 18.62 → 13.70; 🟢 26.40% less time | 1.01 → 0.723; 🟢 28.24% less time | 🔴 Normally +12 objects / +1,376 allocated B per operation. Potential extra GC pressure, not measured GC latency. Setup local frames unchanged; argument/result areas +24/+32 B; peak unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 2.69 → 2.70; 🔴 0.49% more time | 70.26 → 70.64; 🔴 0.55% more time | 3.99 → 4.01; 🔴 0.45% more time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHA2-192s

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | 106.88 → 20.27; 🟢 81.03% less time | 988.63 → 218.17; 🟢 77.93% less time | 0.825 → 0.194; 🟢 76.48% less time | ⚪ No OpenSSL allocator calls in focused hash probes. 🔴 Some local stack frames +112–240 B; SHA256 compression −16 B. No tracing GC; total stack peak unmeasured. |
| OpenSSL | C | 30.53 → 21.09; 🟢 30.91% less time | 252.95 → 219.68; 🟢 13.15% less time | 0.243 → 0.203; 🟢 16.69% less time | 🔴 +1 allocation and +224 requested B per hash context; clone has same cost. 🟢 Tested failure cleanup passes. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | 41.81 → 31.10; 🟢 25.61% less time | 437.67 → 318.27; 🟢 27.28% less time | 0.394 → 0.279; 🟢 29.16% less time | 🔴 Normally +12 objects / +1,376 allocated B per operation. Potential extra GC pressure, not measured GC latency. Setup local frames unchanged; argument/result areas +24/+32 B; peak unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 153.18 → 154.55; 🔴 0.90% more time | 1446.80 → 1454.58; 🔴 0.54% more time | 1.42 → 1.38; 🟢 2.32% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHA2-256f

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | 4.49 → 0.842; 🟢 81.24% less time | 90.41 → 19.18; 🟢 78.78% less time | 2.41 → 0.513; 🟢 78.74% less time | ⚪ No OpenSSL allocator calls in focused hash probes. 🔴 Some local stack frames +112–240 B; SHA256 compression −16 B. No tracing GC; total stack peak unmeasured. |
| OpenSSL | C | 0.933 → 0.891; 🟢 4.53% less time | 22.22 → 19.56; 🟢 11.99% less time | 0.596 → 0.540; 🟢 9.35% less time | 🔴 +1 allocation and +224 requested B per hash context; clone has same cost. 🟢 Tested failure cleanup passes. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | 1.74 → 1.28; 🟢 26.23% less time | 38.67 → 28.06; 🟢 27.43% less time | 1.04 → 0.748; 🟢 28.01% less time | 🔴 Normally +12 objects / +1,376 allocated B per operation. Potential extra GC pressure, not measured GC latency. Setup local frames unchanged; argument/result areas +24/+32 B; peak unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 7.12 → 7.16; 🔴 0.54% more time | 145.30 → 146.15; 🔴 0.58% more time | 4.31 → 4.10; 🟢 4.93% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHA2-256s

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | 72.06 → 13.42; 🟢 81.37% less time | 876.18 → 209.26; 🟢 76.12% less time | 1.21 → 0.278; 🟢 76.97% less time | ⚪ No OpenSSL allocator calls in focused hash probes. 🔴 Some local stack frames +112–240 B; SHA256 compression −16 B. No tracing GC; total stack peak unmeasured. |
| OpenSSL | C | 14.45 → 14.20; 🟢 1.68% less time | 242.23 → 202.85; 🟢 16.25% less time | 0.341 → 0.290; 🟢 15.07% less time | 🔴 +1 allocation and +224 requested B per hash context; clone has same cost. 🟢 Tested failure cleanup passes. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | 28.31 → 20.43; 🟢 27.84% less time | 410.09 → 295.10; 🟢 28.04% less time | 0.559 → 0.391; 🟢 30.01% less time | 🔴 Normally +12 objects / +1,376 allocated B per operation. Potential extra GC pressure, not measured GC latency. Setup local frames unchanged; argument/result areas +24/+32 B; peak unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 102.45 → 102.03; 🟢 0.41% less time | 1316.26 → 1308.80; 🟢 0.57% less time | 2.02 → 1.97; 🟢 2.42% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHAKE-128f

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | 1.38 → 1.37; 🟢 0.98% less time | 31.97 → 31.86; 🟢 0.33% less time | 1.94 → 1.93; 🟢 0.02% less time | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | 2.35 → 2.33; 🟢 0.57% less time | 54.93 → 54.68; 🟢 0.45% less time | 3.30 → 3.30; 🔴 0.06% more time | ⚪ Control: allocation counters unchanged for 128f; other SHAKE sets not newly measured. Peak/GC latency unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 1.60 → 1.60; 🔴 0.49% more time | 37.68 → 37.31; 🟢 0.98% less time | 2.42 → 2.35; 🟢 2.92% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHAKE-128s

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ Control: allocation counters unchanged for 128f; other SHAKE sets not newly measured. Peak/GC latency unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 98.08 → 97.80; 🟢 0.28% less time | 753.82 → 752.99; 🟢 0.11% less time | 0.934 → 0.889; 🟢 4.89% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHAKE-192f

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ Control: allocation counters unchanged for 128f; other SHAKE sets not newly measured. Peak/GC latency unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 2.31 → 2.51; 🔴 8.91% more time | 60.28 → 64.70; 🔴 7.34% more time | 3.39 → 3.86; 🔴 13.93% more time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHAKE-192s

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ Control: allocation counters unchanged for 128f; other SHAKE sets not newly measured. Peak/GC latency unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 147.49 → 144.97; 🟢 1.71% less time | 1313.54 → 1339.85; 🔴 2.00% more time | 1.30 → 1.29; 🟢 1.29% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHAKE-256f

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ Control: allocation counters unchanged for 128f; other SHAKE sets not newly measured. Peak/GC latency unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 6.12 → 6.20; 🔴 1.36% more time | 124.28 → 125.14; 🔴 0.69% more time | 3.55 → 3.52; 🟢 0.89% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## SLH-DSA-SHAKE-256s

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | 🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ Control: allocation counters unchanged for 128f; other SHAKE sets not newly measured. Peak/GC latency unknown. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | 96.79 → 98.74; 🔴 2.01% more time | 1169.30 → 1170.61; 🔴 0.11% more time | 1.87 → 1.85; 🟢 0.94% less time | 🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate. |

## Falcon-512

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |

## Falcon-1024

| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |
|---|---|---|---|---|---|
| Noble | TypeScript / JavaScript | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| liboqs | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| OpenSSL | C | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| CIRCL | Go | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| RustCrypto | Rust | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |
| Bouncy Castle | Java | ⚪ NM | ⚪ NM | ⚪ NM | ⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement. |

## Rust construction plus signing

| Parameter | Original → changed (ms), time saved |
|---|---|
| ML-DSA-44 | 0.316 → 0.307; 🟢 2.66% less time |
| ML-DSA-65 | 0.995 → 0.944; 🟢 5.19% less time |
| ML-DSA-87 | 1.03 → 0.974; 🟢 5.82% less time |

## Newer Bouncy Castle alternatives: separate experiments

These results must not be combined with the earlier FORS times above. They compare separate patches to their own upstream baseline. ML sampling is a six-round confirmation; WOTS is a two-pair pilot limited to the two listed sets. Neither establishes lower peak heap, less stack usage, or fewer GC pauses. Time change below is candidate/original minus one; positive is slower.

| Candidate | Parameter / action | Time change | Allocated bytes change | Interpretation |
|---|---|---|---|---|
| ML sampling buffers | 44 sign | 🟢 −0.91% | 🟢 −24.26% | Mixed rounds |
| ML sampling buffers | 44 verify | 🔴 +3.22% | 🟢 −21.36% | All six rounds slower |
| ML sampling buffers | 65 sign | 🔴 +2.06% | 🟢 −28.45% | All six rounds slower |
| ML sampling buffers | 65 verify | 🟢 −1.70% | 🟢 −25.82% | Mixed rounds |
| ML sampling buffers | 87 sign | 🔴 +0.26% | 🟢 −30.30% | Mixed rounds |
| ML sampling buffers | 87 verify | 🟢 −5.18% | 🟢 −30.15% | All six rounds faster |
| WOTS buffer | SHA2-128f keygen | 🔴 +4.10% | 🟢 −73.23% | Both pairs slower |
| WOTS buffer | SHA2-128f sign | 🔴 +2.60% | 🟢 −66.67% | Both pairs slower |
| WOTS buffer | SHA2-128f verify | 🟢 −0.66% | 🟢 −61.64% | Mixed pairs |
| WOTS buffer | SHAKE-128f keygen | 🔴 +1.24% | 🟢 −73.45% | Both pairs slower |
| WOTS buffer | SHAKE-128f sign | 🟢 −4.82% | 🟢 −66.83% | Mixed pairs; weak CPU corroboration |
| WOTS buffer | SHAKE-128f verify | 🔴 +0.79% | 🟢 −62.19% | Mixed pairs |

Evidence is retained in local sibling worktrees: ML report `bc-ml-deep/docs/bouncycastle/ml-deep/confirmation.md`, commit `ecf5f803a2df24bd93abb0cfae0300a4b2cdfeb3`; WOTS report `bc-slh-deep/docs/bouncycastle/slh-deep.md`, commit `cfafbb4641bbf1dac5acc496b99b881303933136`. These experimental branches have not been integrated into the published audit branch. Key generation for ML sampling and other WOTS parameter sets were not measured in these follow-ups.


## Interpretation limits

OpenSSL SHA2-128 and SHAKE are controls. Its 192s key-generation wall improvement is not corroborated by a comparable CPU improvement. Rust existing-key signing/verification are unchanged code. Noble warmed operation benefits are not a startup or tail-latency guarantee. Falcon has no validated production-patch comparison in this exercise; NM does not assert library support. No new cryptographic implementation or timing run is introduced by this report.
