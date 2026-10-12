# OpenSSL completion measurements

The published SHA2-192/256 prefix cache remains a reasonable speed/memory tradeoff for this tested host when a small additional context allocation is acceptable. Earlier [balanced timings](../resource-audit/README.md#retained-latency-losses) report signing ratios of 1.094–1.195× and verification ratios of 1.073–1.172×, about 8.6–16.3% and 6.8–14.7% less elapsed time. The new full-operation probe measures **224 additional requested bytes for each affected sign/verify call**, with one additional allocation, and no tracked leak. SHA2-128 controls pay a smaller pointer cost without an established speed benefit. Key generation is separate: its retained one-pass 192f result includes a slowdown, so the optimization is not a blanket improvement for every operation.

The [summary](../../../../results/openssl/complete-indicators/summary.json) adds 24 baseline timing cells: ML-DSA-44/65/87 and five previously unmeasured SHAKE sets, each with keygen/sign/verify. SHAKE-128f was already measured. Each new cell is the mean of 30 checked calls over ten distinct keys repeated in three fresh processes, with one disjoint warmup per process. No candidate is supplied for unchanged algorithm paths. Native capability probes establish that Falcon-512/1024 are unavailable in this pinned stock default-provider build; third-party providers were not loaded. This is not a claim about all possible OpenSSL provider installations.

| SHA2 set | Operation | Requested heap bytes, original → candidate | Change | Peak tracked live-byte change |
|---|---|---:|---:|---:|
| 128f | keygen | 1,941 → 1,943 | +0.10% | +8 B / +0.51% |
| 128f | sign | 4,152.25 → 4,160.25 | +0.19% | +8 B / +0.25% |
| 128f | verify | 3,800.25 → 3,808.25 | +0.21% | +8 B / +0.29% |
| 128s | keygen | 1,941 → 1,943 | +0.10% | +8 B / +0.51% |
| 128s | sign | 3,552.25 → 3,560.25 | +0.23% | +8 B / +0.25% |
| 128s | verify | 3,200.25 → 3,208.25 | +0.25% | +8 B / +0.29% |
| 192f | keygen | 1,941 → 2,159 | +11.23% | +224 B / +14.29% |
| 192f | sign | 4,576.25 → 4,800.25 | +4.89% | +224 B / +6.26% |
| 192f | verify | 3,904.25 → 4,128.25 | +5.74% | +224 B / +7.82% |
| 192s | keygen | 1,941 → 2,159 | +11.23% | +224 B / +14.29% |
| 192s | sign | 3,976.25 → 4,200.25 | +5.63% | +224 B / +6.26% |
| 192s | verify | 3,304.25 → 3,528.25 | +6.78% | +224 B / +7.82% |
| 256f | keygen | 1,941 → 2,159 | +11.23% | +224 B / +14.29% |
| 256f | sign | 4,384.25 → 4,608.25 | +5.11% | +224 B / +6.25% |
| 256f | verify | 3,704.25 → 3,928.25 | +6.05% | +224 B / +7.82% |
| 256s | keygen | 1,941 → 2,159 | +11.23% | +224 B / +14.29% |
| 256s | sign | 4,024.25 → 4,248.25 | +5.57% | +224 B / +6.25% |
| 256s | verify | 3,344.25 → 3,568.25 | +6.70% | +224 B / +7.82% |

Heap entries are arithmetic means over four matched keys with varied messages/contexts; fractional bytes represent averaging integer per-call counts. Percentages divide the candidate-minus-original mean by the original mean. EVP operation-context creation, initialization, the operation and context free are included; key import, caller buffers and output export/checking are excluded. Newly generated keys retain 544 tracked bytes on both sides at return and are then freed. All final tracked live-byte counts are zero. These allocator-hook totals exclude arbitrary system allocations and allocator metadata. Full keygen requested-byte deltas are +218 affected/+2 control, while its peak-live deltas are +224/+8; the observed cumulative totals are retained without replacing them with the separately proven focused hash-context sizes.

Observed overwritten stack medians are unchanged for every keygen and sign cell. Verification medians change by 0–276 bytes (0–5.91%), with all four observations retained. This diagnostic includes thread startup/exit and detects overwritten paint, not exact reserved depth or a proven operation maximum. The 272-byte no-op floor matches both patterns and variants and is not subtracted. The representative 256s signing second-pattern check agrees; 128f candidate verification differs by 8 bytes between separate process observations, illustrating the diagnostic's limits rather than establishing exact byte precision.

Separate cold-process post-operation peak-RSS median changes range from −0.71% to +1.58%, including increases in affected signing/verification cells. All pre/post absolute bytes, per-key observations and percentages are retained in the summary. This is a process/runtime measure with page-level and desktop noise; it cannot resolve the exact 224-byte context increase or prove its absence. Stack painting runs in different processes and cannot inflate these RSS observations.

All 72 baseline timing and 440 resource processes completed successfully. Correct outputs and input integrity were checked after measurement boundaries; both variants rejected selected tampered signatures in preparation. The [independent local check](../../../../results/openssl/complete-indicators/independent-local-check.json) rechecks source/build/input hashes and raw outputs and independently recomputes every timing/resource cell and percentage. The existing [focused lifecycle/OOM audit](../resource-audit/README.md) covers context create/duplicate/free failures and successful clearing; these new full-operation counters complement it and do not repeat that failure-injection scope.

The [ready manifest](../../../../results/openssl/complete-indicators/ready.json) binds upstream `122db7e`, signed published `857cb29` and its tree-identical measured candidate `cb72255`. The [protocol](README.md) records reproduction and boundaries. The initial missing-source-header compilation failure is retained separately; the corrected preparation and every final collection passed. Original frozen evidence and production sources are unchanged. The prior balanced study retains 12/720 affected wall losses and 11/720 CPU losses, and the separate candidate-first pass retains its order-confounded losses; no new speed claim comes from these resource diagnostics.

For a checkout without the original local builds, run `python3 libs/openssl/experiments/complete-indicators/independent-check.py --provider openssl --out /path/to/check.json`. The default checks committed source/configuration snapshots, fixture bytes, raw outputs and summary arithmetic through the [artifact inventory](../../../../results/openssl/complete-indicators/artifact-inventory.json); it explicitly lists unverified compiled artifacts. Add `--local-builds` to require the original absolute paths and rehash their binary bytes as well. The original local checker execution and its versioned source are retained separately; replaying saved evidence is not a fresh benchmark or build.

Both the [saved-only replay](../../../../results/openssl/complete-indicators/independent-saved-check.json) and the local mode passed. The [saved-reader tests](../../../../results/openssl/complete-indicators/saved-reader-tests.json) pass with external/build-directory reads denied and reject malformed evidence. An initial inventory omitted the Perl build configuration files; the [rejection](../../../../results/openssl/complete-indicators/pre-configdata-inventory-rejection.json) and provisional inventory are preserved, and the completed archive includes both configurations. This was an evidence-packaging failure, not a failed cryptographic operation or discarded measurement.
