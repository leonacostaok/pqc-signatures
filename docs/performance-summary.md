# Are the optimizations worth it?

The measured tradeoffs are favorable for liboqs and RustCrypto, and remain promising for OpenSSL, CIRCL and noble. Bouncy Castle is not yet a general speed win. These are engineering recommendations for the measured workloads, not universal claims or upstream acceptance decisions.

| Change | Time benefit in repeated experiments | Measured memory cost or saving | Assessment |
|---|---|---|---|
| liboqs SLH-DSA SHA2 | 🟢 Signing uses 76.6–81.0% less time; verification 77.3–81.1% less | Full-call tracked allocation stays 88 B (0% change). Observed touched thread-stack extent changes −8 to +312 B (−0.19% to +7.69%); this diagnostic is not exact stack consumption. | 🟢 Worthwhile with the supported OpenSSL backend and sufficient stack; deprecated API compatibility remains a maintenance cost. |
| RustCrypto ML-DSA construction | 🟢 14.8–15.1% less construction time; 3.6–6.2% less time for construction plus signing | Heap accounting unchanged. Constructor-local frames shrink 13.9–21.9%; new whole-process RSS medians change −1.61% / +1.51% / −3.32% for 44/65/87. Existing-key sign/verify code is unchanged. | 🟢 Worthwhile when constructing keys from seeds (including seed imports); not a speed optimization for an already constructed key. |
| OpenSSL SLH-DSA SHA2-192/256 | 🟢 Signing uses 8.6–16.3% less time; verification 6.8–14.7% less | Full-call sign/verify requested bytes +4.9–6.8%; tracked heap peak +6.25–7.82% (+224 B). Keygen tracked peak +14.29%. The earlier +57.1% referred only to the small hash context. | 🟢 Usually worthwhile for tested signing/verification: bounded added memory and tested failure cleanup. Keygen remains mixed; check the target build. |
| CIRCL SLH-DSA SHA2 | 🟢 Signing uses 24.4–27.0% less time; verification 24.4–29.8% less | Isolated allocation +1,088–1,376 B/call: sign +1.9–6.7%, verify +11.0–16.8%, keygen +83.8–125.9%. New checked workloads have more GC cycles in 8/18 default and 9/18 constrained cells. | 🟢 Favorable in both tested GC settings: checked throughput still rises 24.9–39.5%. Allow for additional allocation/GC work; this is not every workload. |
| noble ML-DSA | 🟢 Warm signing uses 8.3–15.9% less time; verification 9.2–15.9% less | New checked-workload RSS medians fall 0.03–10.13%; observed GC event counts fall 0–14.29%. Some GC durations rise up to 6.69%, and heap snapshots can increase. Exact total JS allocation remains unavailable. | 🟡 Useful in sustained workloads if complexity is acceptable. Not a startup guarantee; upstream closed the PR over complexity versus benefit. |
| Bouncy Castle experiments | 🟡 Mixed: some operations improve and others slow down | Allocation reductions are real but not sufficient: new WOTS SHA2-128f signing allocates ~67% less and records 70% fewer GC events, yet takes ~2% longer and process RSS rises 8.58%. | 🔴 Not ready as a general speed optimization. Potential allocation-focused work, but repeated regressions must be addressed or accepted for a specific workload. |

The time column uses earlier repeated timing experiments; the new resource/GC workloads include instrumentation and have separate boundaries. Their throughput results support the workload-specific assessments, not a universal speed or memory claim.

Time saved is `100 × (1 − changed/original)`; resource change is `100 × (changed/original − 1)`. Percentages with different denominators cannot be added. A zero baseline has no defined percentage: report the absolute change. Green/red describes an observed metric, not statistical significance or an overall security verdict.

## What GC and memory mean here

- **Allocated bytes** measure traffic through the allocator, not bytes permanently retained. More traffic can increase GC work; less traffic does not guarantee lower latency.
- **Live/sampled heap and process peak RSS** include different things. RSS includes runtime/code/stacks and is not an operation heap measurement. A sampled maximum can miss a short-lived peak.
- **Stack frames, reserved runtime stacks and overwritten stack extent** are distinct measurements. None can silently substitute for total per-operation stack use.
- C and Rust do not use a tracing GC in these paths. Go, Node and Java reclaim unreachable heap objects through their runtime collectors. GC is not secret-memory zeroization.

## Evidence

[Actual times between libraries](library-times.md) · [Complete timing table](audit/complete-performance-comparison.md) · [New memory and GC measurements](audit/completed-resource-measurements.md) · [Earlier resource percentages](audit/resource-percentages.md) · [Resource audit and limits](audit/published-resource-regressions.md) · [Individual production experiments](provider-improvements.md).

This supporting testing and analysis work is AI-assisted. Recorded sources, scripts, raw outputs and checks support independent reproduction; they do not replace cryptographic review or certify the implementations.
