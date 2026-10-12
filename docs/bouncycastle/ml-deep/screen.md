# ML-DSA sampling-buffer screen

Operation-local scratch sharing reduced allocated bytes in this two-round screen. It did not produce a broad latency improvement. The combined candidate saved 24–30% of signing allocations and 22–30% of verification allocations; its wall-time ratios were 0.983–1.057x. A separate six-round baseline-versus-combined resource confirmation was predeclared after inspecting this screen. These measurements describe allocated bytes, not peak or retained memory.

All variants use official bc-java `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. The [patch](../../../libs/bouncycastle/patches/ml-deep/sampling-buffers.patch) only shares byte buffers within one matrix expansion or one gamma1 vector sample. It changes neither SHAKE streams nor polynomial arithmetic, nonces, rejection conditions or encoding. The [source analysis](plan.md) identifies the call boundaries and remaining candidates.

## Whole-operation results

The table reports means over 256 calls per cell (128 distinct keys in each of two fresh-process rounds). Wall and calling-thread CPU ratios are sums of original times divided by sums of changed times on matched keys. A ratio below one is slower. The last column counts slower changed-key samples out of256. Every round, key, output digest and loss is retained in the [summary](../../../results/bouncycastle/ml-deep/screen/summary.json) and [execution record](../../../results/bouncycastle/ml-deep/screen/execution.json).

| Set / operation | Variant | Original bytes/call | Changed bytes/call | Reduction | Wall ratio | Thread CPU ratio | Slower keys |
|---|---|---:|---:|---:|---:|---:|---:|
| 44 / sign | matrix | 90714.6 | 77754.6 | 14.29% | 1.001x | 1.001x | 109 |
| 44 / sign | gamma | 90714.6 | 81661.1 | 9.98% | 1.001x | 1.001x | 97 |
| 44 / sign | combined | 90714.6 | 68701.1 | 24.27% | 1.015x | 1.015x | 66 |
| 44 / verify | matrix | 59913.4 | 46740.2 | 21.99% | 0.986x | 0.986x | 141 |
| 44 / verify | gamma | 59913.4 | 59721.4 | 0.32% | 0.999x | 1.007x | 121 |
| 44 / verify | combined | 59913.4 | 46742.7 | 21.98% | 0.983x | 0.984x | 154 |
| 65 / sign | matrix | 142098.7 | 117402.7 | 17.38% | 1.008x | 1.006x | 125 |
| 65 / sign | gamma | 142098.7 | 126982.4 | 10.64% | 1.005x | 1.005x | 103 |
| 65 / sign | combined | 142098.7 | 102286.4 | 28.02% | 1.000x | 0.999x | 144 |
| 65 / verify | matrix | 96737.4 | 71989.4 | 25.58% | 1.001x | 1.001x | 107 |
| 65 / verify | gamma | 96737.4 | 96545.4 | 0.20% | 1.001x | 1.001x | 132 |
| 65 / verify | combined | 96737.4 | 71668.4 | 25.91% | 0.985x | 0.991x | 120 |
| 87 / sign | matrix | 211088.7 | 163568.7 | 22.51% | 0.980x | 0.990x | 134 |
| 87 / sign | gamma | 211088.7 | 195330.8 | 7.47% | 1.007x | 1.006x | 110 |
| 87 / sign | combined | 211088.7 | 147138.8 | 30.30% | 0.991x | 0.998x | 95 |
| 87 / verify | matrix | 158444.9 | 111599.1 | 29.57% | 1.072x | 1.071x | 13 |
| 87 / verify | gamma | 158444.9 | 159109.2 | -0.42% | 1.018x | 1.015x | 94 |
| 87 / verify | combined | 158444.9 | 110891.4 | 30.01% | 1.057x | 1.054x | 16 |

Matrix-only ML-DSA-87 verification was 1.072x overall (rounds1.079x and1.065x); the combined variant was1.057x (1.075x and1.040x). The unchanged gamma-only verification control moved1.018x overall at87, and other cells varied across rounds. This is a candidate for confirmation, not evidence of a general speedup. Small allocation changes in unchanged controls also show JIT/escape-analysis effects; source buffer counts and measured whole-call allocations are reported separately.

## Stage diagnostics

The following baseline percentages are from separate instrumented builds, not the performance binaries. Each column is the fraction of summed stage intervals over128 valid operations; timer/map bookkeeping perturbs intervals. The profiles warm on the same fixture values rather than the disjoint warmup corpus. They are diagnostic attribution, cannot be substituted for uninstrumented latency, and are not independently composable performance estimates. The complete baseline and combined counters are in [profile evidence](../../../results/bouncycastle/ml-deep/profile-screen/execution.json).

| Signing stage | 44 | 65 | 87 |
|---|---:|---:|---:|
| public setup message hash | 1.5% | 1.0% | 0.9% |
| secret decode setup | 3.2% | 1.7% | 2.1% |
| rhoPrime hash | 0.2% | 0.2% | 0.1% |
| matrix sample | 9.6% | 10.6% | 17.4% |
| secret ntt | 7.8% | 6.8% | 8.2% |
| gamma sample | 10.2% | 9.3% | 8.0% |
| y copy ntt | 11.6% | 11.0% | 9.5% |
| matrix product | 5.8% | 8.2% | 9.5% |
| matrix reduce inverse | 12.4% | 14.1% | 11.5% |
| decomposition challenge | 8.8% | 7.4% | 5.5% |
| response rejection | 21.6% | 23.7% | 20.4% |
| hint rejection | 5.0% | 4.4% | 5.2% |
| signature encode | 2.3% | 1.5% | 1.6% |

| Verification stage | 44 | 65 | 87 |
|---|---:|---:|---:|
| public setup message hash | 7.7% | 7.0% | 5.2% |
| signature decode norm | 5.0% | 5.3% | 7.3% |
| public key decode | 0.8% | 0.9% | 0.7% |
| challenge sample | 2.1% | 0.9% | 0.4% |
| matrix sample | 39.5% | 41.4% | 48.2% |
| z ntt | 8.7% | 7.9% | 6.7% |
| matrix product | 4.3% | 5.9% | 7.0% |
| challenge t1 ntt | 10.7% | 11.0% | 8.7% |
| challenge product subtract | 1.3% | 1.4% | 1.1% |
| inverse canonicalize | 9.2% | 10.1% | 8.1% |
| hint encode | 3.5% | 3.1% | 2.4% |
| challenge hash compare | 7.0% | 5.0% | 4.2% |

Signing made555/695/483 gamma samples and matrix products for44/65/87 respectively, averaging4.34/5.43/3.77 attempts per signature. The combined candidate had exactly the same counts. Response checks let129/128/128 attempts reach the hint stage and128 signatures were encoded in every set. The earlier rejected attempts remain included in the totals. Verification matrix sampling accounts for40–48% of instrumented work; removing byte allocations does not remove SHAKE permutations.

The [sampler screen](../../../results/bouncycastle/ml-deep/sampler-screen/summary.json) separately records128 unique-key calls per variant/set/probe in one process per cell. It includes fresh matrix/vector construction, and the gamma probe also creates its64-byte seed. It confirms byte-allocation savings but has only one ordering, so its latency ratios are exploratory. Source payload savings exclude object headers: matrix12,630/24,418/46,310 bytes per expansion and gamma2,040/2,720/4,080 bytes per attempted vector for44/65/87.

## Protocol and correctness

The uninstrumented screen runs48 fresh JVMs with reversed variant order in round2. Every process executes exactly1,000 warmup calls on32 fixture keys disjoint from the128 measured keys. Each measured key is used once in its batch. Caller array copies and expanded-key construction/import are outside the clock; a fresh signer/verifier, initialization, message update and final operation are inside. There is no persistent key or matrix cache. OS caches are not flushed. Untimed signing validation performs an additional verification and key/input encoding checks before the next sample, which can affect GC and JIT. Separate checked-driver process CPU, GC and compilation diagnostics retain that context. Per-operation CPU is calling-thread CPU only.

The strict gate passed432 exact-output operation checks and288 negative checks in each of the four uninstrumented and two instrumented variants. It covers all three pure and prehash sets, repeated deterministic or fixed-entropy calls, message lengths0–4096, contexts0/1/255, full key/signature equality with unchanged upstream, ownership and negative outcomes. The sampler gate checks every coefficient, retained outputs and scratch buffer identities, including poisoned buffers and a forced167-byte stream that exercises refill/carry. The unchanged baseline fails each reduced-buffer resource requirement. The existing upstream native ACVP/Wycheproof suites have not yet been rerun for this prototype; that remains a publication gate.

All84 measured processes exited successfully. An independent reviewer reconstructed all source variants from the upstream pin, checked source/class/runtime/corpus seals and raw stdout/argument/order records, recomputed all summary fields, independently derived3,072 sampler digests using Python SHAKE and bit decoding, and verified profile stage/count invariants. Review artifacts are maintained separately in `results/bouncycastle/deep-independent/ml-{preparation,screen,sampler,profile}.json` for integration with this evidence.

The screen manifest SHA256 is `5ec5e4e10eba45cf77729f1960f1ea2bdd5806a58ff110ca5f6d3148fafb6bf7`. Its parent manifest `4c71600f35c8db31beaef84e6145aa3ca17419c6d57404d3c9d4a0b76e15ea08` was resealed only to bind Python guard changes; Java, production source, class trees, runtime, corpora and correctness gates stayed unchanged. Both Python entry points reject optimized mode, because it disables assertions used by the fail-closed checks. The collector verifies provenance before and after timing and preserves unmodified process stdout separately from enriched metadata. Failed earlier preparation snapshots remain local and are not correctness results.

## Confirmation decision

The [predeclared confirmation](../../../results/bouncycastle/ml-deep/confirmation-plan/protocol.json) compares only baseline and combined across six rounds,72 fresh JVMs and the same explicit core-operation boundaries. Its resource target is at least20% allocation reduction in every set/operation cell. A latency review is triggered if a cell has aggregate wall ratio below0.97 and at least four of six round ratios below0.97; all smaller losses are still reported. No broad latency claim is planned. No lazy-row arithmetic build or timing has been run.
