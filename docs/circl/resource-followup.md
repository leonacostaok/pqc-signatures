# CIRCL resource follow-up

SHA2 prefix reuse improved checked-workload throughput in all 18 affected parameter/action cells under both GC settings, and in every matched round. It also allocated more bytes per call and sometimes incurred more GC work. It is a CPU-for-allocation tradeoff, not a memory optimization.

| Indicator: candidate change | GOGC=100, limit off | GOGC=100, 8 MiB soft limit |
| --- | ---: | ---: |
| Checked throughput | +24.86% to +38.78% | +26.94% to +39.52% |
| Checked allocated bytes/call | +1.04% to +9.04% | +1.04% to +9.05% |
| Checked allocated bytes/second | +33.02% to +46.05% | +34.61% to +45.86% |
| GC cycles, where percentage defined | 0% to +16.67% | −20.00% to +24.62% |
| GC pause time, where percentage defined | −39.61% to +54.33% | −57.50% to +29.51% |
| GC CPU time, where percentage defined | −6.74% to +23.75% | −30.95% to +28.69% |
| Sampled maximum HeapAlloc | −0.69% to +4.46% | −8.79% to +6.97% |
| Process-lifetime high-water RSS | −0.97% to +3.48% | −3.21% to +2.44% |

The pipeline allocated about 1,088–1,380 additional bytes per call. Its percentage increase is diluted by common fixture copying and validation; the earlier [isolated allocation audit](resource-audit.md) remains the source for production API allocation counts. Faster processing also raises bytes allocated per second, so that rate must not be mistaken for a per-call increase of the same size. Default SHA2-192f verification's mean cumulative GC pauses increased from 0.237 to 0.366 ms per workload; constrained SHA2-192s verification increased from 1.060 to 1.373 ms. GC CPU has both increases and decreases, retained in the summary.

All six small-signature keygen/sign cells observed zero GC cycles during their bounded workloads in both variants/settings. Their GC-change percentages are null, not a claim of zero GC cost generally. Last-GC heap values are null if no collection ever completed; otherwise they can still refer to warmup. Ending HeapAlloc varied from −48.95% to +45.84% under default GC and −35.81% to +29.67% under the soft limit, illustrating why a single ending balance is not a peak or leak test.

Four balanced fresh-process rounds cover all six SHA2 sets with fixed per-action counts, two disjoint warmup fixture values and three repeated measured values, using fresh caller buffers and freshly decoded keys. Whole-workload allocation/GC/throughput includes copying the entire fixture, key import, output checking/digests and sampling; individual API clocks exclude those steps. Baseline-only ML-DSA import can prepare key data outside its API clock and is explicitly separate from key generation. The pinned sources are `91db3e7` and `1c31496`, compiled with Go 1.27.0 on darwin/arm64, with GOMAXPROCS=1. The 8 MiB Go memory limit is soft and is not an RSS cap.

For these checked workloads, the CPU gains survived the additional allocation and GC costs under both settings. The extra per-call traffic and sometimes higher RSS/heap remain relevant to memory-sensitive deployments. Post-operation samples miss internal peaks; process RSS includes startup/warmup; StackInuse is runtime-reserved stack storage, not consumed-stack high-water. The result is not a universal peak-memory guarantee. Supporting test construction and analysis are AI-assisted.

Baseline-only coverage adds ML-DSA-44/65/87 and all six SHAKE SLH sets without assigning fake patch gains. Falcon is unsupported by the selected [pinned signature registry](https://github.com/cloudflare/circl/blob/91db3e785ba2635b4f24a023e1ad76d2780e2865/sign/schemes/schemes.go#L32-L56). The [summary](../../results/circl/resource-followup/summary.json) retains all cells/rounds and explicit unavailable values; the [protocol](resource-followup/protocol.md) gives counts, reproduction and normalization details.
