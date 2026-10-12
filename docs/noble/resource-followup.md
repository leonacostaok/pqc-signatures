# Noble resource follow-up

The row-dot patch improved checked-workload throughput in all 12 ML-DSA parameter/action cells under both heap settings, and in every matched round. It is still a CPU optimization with some memory and GC tradeoffs: sampled/ending heap sometimes increased, and observed GC duration increased in four setting/action cells. These measurements do not establish a universal memory improvement or resolve the maintainer's separate complexity objection to the closed PR.

| Indicator: candidate change | Default V8 | Constrained V8 |
| --- | ---: | ---: |
| Checked throughput | +8.39% to +23.98% | +9.05% to +24.64% |
| Observed GC events | −14.29% to 0% | −12.50% to 0% |
| Observed GC duration | −22.77% to +6.64% | −21.24% to +6.69% |
| Sampled maximum heapUsed | −12.94% to +0.40% | −2.22% to +1.00% |
| Ending heapUsed | −18.83% to +11.49% | −5.49% to +3.12% |
| Process-lifetime high-water RSS | −10.13% to −0.45% | −9.85% to −0.03% |

Ranges cover every cell; workload indicators use the mean of four equal-count process observations and memory indicators use their median. The largest default GC-duration increase was public-key derivation for ML-DSA-87, from 1.392 to 1.485 ms over 192 calls. Under constrained V8, ML-DSA-44 key generation increased from 1.098 to 1.171 ms. These are observed GC event durations over the checked pipeline, not measured GC CPU or a complete stop-the-world pause accounting.

The workload uses fresh caller arrays/options and ordinary one-shot APIs, 24 warmup calls on two disjoint fixture values, then 192 calls cycling three measured fixture values. It includes caller copies, output checks/digests, memory sampling and event-loop yields; the copies include the whole fixture even when an action does not consume every buffer. This common harness traffic makes the results pipeline diagnostics, distinct from earlier clean API latency and logical polynomial allocation counts. No key, signer or matrix cache persists across calls. Node 22.23.2 runs pinned noble 0.7.1 sources at baseline `48e4933` and candidate `39d56d1`; constrained V8 uses 32 MiB old-space and 1 MiB semi-space flags, with a reported 36,700,160-byte heap limit.

Post-operation samples can miss internal peaks. Ending heapUsed is not post-GC live heap. RSS includes imports, fixture parsing and warmup. Exact whole-process JS allocation traffic, allocation rate, GC CPU and consumed-stack high-water remain unavailable; no heap-balance subtraction is substituted for them. The recorded default V8 stack-size setting is 864 kBytes, a configured limit rather than consumed stack.

For this bounded CPU workload, the measured throughput gains outweighed the observed GC-duration increases under both tested heap settings. Applications whose decision depends on exact peak memory or another runtime still need target-specific measurements. Prior noisy/cold-start losses remain in the [earlier audit](resource-audit.md); this follow-up does not erase them. Supporting test construction and analysis are AI-assisted.

The baseline-only module additionally measures all twelve SLH-DSA sets and detached Falcon-512/1024, with three fresh processes, two capped disjoint warmups and three measured keys per action. These unchanged paths receive no candidate gain. Full per-cell figures, all rounds, undefined/unavailable fields, source bindings and raw references are in the [summary](../../results/noble/resource-followup/summary.json); reproduction and exact boundaries are in the [protocol](resource-followup/protocol.md).
