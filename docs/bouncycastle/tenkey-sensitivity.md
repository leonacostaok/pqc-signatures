# Ten-new-key sensitivity check

Latency remains mixed in the ten-key pass: key-generation totals span 0.9182–1.0174×, signing 0.9316–1.0099×, and verification 0.8777–1.0680×. The results do not establish a general signing or verification speedup. The supported production benefit remains the allocation reduction measured separately in the sealed experiment.

This is a one-pass sensitivity check requested after the repeated performance experiments. It preserves their sealed sources, production patches and results. Each affected parameter uses ten distinct new deterministic seeds, with matched messages, contexts and signing entropy across original and changed implementations. Two additional disjoint seeds warm each fresh process before the ten recorded keys; this bounded warmup is not a steady-state guarantee.

Each key contributes exactly one measured key-generation, ordinary-signing and verification call. Input decoding, entropy derivation, key/signature encoding, exact output comparisons and tamper checks occur outside their clocks. Every measured result is checked against the exact outputs established during untimed preparation. All output bytes, per-key wall/process CPU times, commands, process statuses and timestamps are retained. Each parameter and variant runs in a fresh process. Output paths cannot be reused, and a baseline batch requires its completed candidate batch.

The coordinated final order is all candidate batches across the six providers, followed by all baseline batches in the same provider order. This order is deliberately fixed for the requested sensitivity check, so time drift and order effects cannot be separated from implementation effects. The primary statistic is the sum of original wall time for the ten keys divided by the sum of changed wall time for the matching ten keys. Reports also retain every key ratio, median, range, losses and CPU totals; there are no exclusions or control normalization. This check does not replace the earlier repeated paired measurements.

The twelve pure SLH-DSA parameter sets cover both SHA2 and SHAKE families. Seeds contain all three key-generation seed components, and each key has explicit matched signing entropy. Private/public key decoding and `FixedRandom` construction are outside signing/verification clocks; signer/verifier creation and initialization are inside. Each JVM has exactly one frozen implementation tree on its application classpath, and its reported `Fors` class location must match that tree. The two complete warmup pipelines per parameter bound the cost of slow signing sets; residual JIT compilation and GC effects remain possible. JVM flags are `-Xmx512m -XX:ActiveProcessorCount=2`. Process CPU may quantize to zero for individual calls, so precise current-thread CPU is also retained; these clocks have different scopes.

The final batches completed successfully. Preparation results and frozen manifests are retained under `results/bouncycastle/experiments/tenkey-*`.

The first preparation completed compilation, all 288 cryptographic case checks and corrupt-warmup rejection, then failed before launching the intentionally invalid-side test because its collector attempted an `invalid` classpath lookup. That test-command construction was corrected. The final preparation reuses byte-identical compiled classes, corpus and fixtures after revalidating every saved check command, exit status and exact output, then runs the corrected rejection test. The original collector snapshot, failure receipt and recovery receipt are retained. No measured call occurred in either preparation. The final manifest is `libs/bouncycastle/build/fors-base2b/tenkey-1ea29159f5844818/manifest.json`.

```sh
python3 libs/bouncycastle/experiments/tenkey.py batch --manifest libs/bouncycastle/build/fors-base2b/tenkey-1ea29159f5844818/manifest.json --variant candidate --out results/bouncycastle/experiments/tenkey-candidate.json
python3 libs/bouncycastle/experiments/tenkey.py batch --manifest libs/bouncycastle/build/fors-base2b/tenkey-1ea29159f5844818/manifest.json --variant baseline --out results/bouncycastle/experiments/tenkey-baseline.json --candidate results/bouncycastle/experiments/tenkey-candidate.json
python3 libs/bouncycastle/experiments/tenkey.py compare --candidate results/bouncycastle/experiments/tenkey-candidate.json --baseline results/bouncycastle/experiments/tenkey-baseline.json --out results/bouncycastle/experiments/tenkey-comparison.json
```

The recorded run completed all six providers' candidate batches before starting any baseline batch. Reproductions should preserve that requested ordering and run without competing benchmark or build workloads.

## Completed measurements

Candidate batch: `2026-10-12T02:02:04.926043+00:00` to `2026-10-12T02:03:46.784636+00:00`. Baseline batch: `2026-10-12T02:04:53.322439+00:00` to `2026-10-12T02:06:34.377857+00:00`. These are batch timestamps; per-process command and completion timestamps are retained in the raw directories.

The [comparison](../../results/bouncycastle/experiments/tenkey-comparison.json) retains every key ratio and all wall/CPU totals. The [independent review](../../results/bouncycastle/experiments/tenkey-independent-review.json) verifies each saved command, process status and stdout record, exact keys/signatures against prepared fixtures and the other variant, ten distinct measured keys per parameter, summary arithmetic, and frozen source/class/binary/corpus hashes. Every process exited successfully with empty stderr. No sample was excluded. No zero process-CPU samples occurred in this run; individual-call CPU quantization remains a clock limitation.

Wall totals below sum all ten calls. The primary ratio is original total divided by changed total; values below one are losses. The per-key median and range describe the ten matching keys and are not confidence intervals.

| Parameter / operation | Original ms | Changed ms | Total ratio | Median key ratio | Key range | Losing keys / 10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| sha2_128f / keygen | 19.2885 | 18.9757 | 1.0165× | 1.0133× | 0.9755–1.0858× | 3 |
| sha2_128f / sign | 442.0629 | 439.3438 | 1.0062× | 1.0042× | 0.9926–1.0451× | 3 |
| sha2_128f / verify | 28.2108 | 28.2437 | 0.9988× | 1.0001× | 0.9736–1.0135× | 5 |
| sha2_128s / keygen | 1051.3939 | 1048.2763 | 1.0030× | 1.0031× | 0.9928–1.0158× | 4 |
| sha2_128s / sign | 8054.4397 | 8029.4212 | 1.0031× | 1.0040× | 0.9667–1.0339× | 4 |
| sha2_128s / verify | 10.3840 | 9.7225 | 1.0680× | 1.0552× | 1.0111–1.1480× | 0 |
| sha2_192f / keygen | 26.8698 | 27.0025 | 0.9951× | 0.9947× | 0.9827–1.0063× | 6 |
| sha2_192f / sign | 702.5660 | 706.3957 | 0.9946× | 0.9952× | 0.9765–1.0025× | 7 |
| sha2_192f / verify | 39.9348 | 40.1144 | 0.9955× | 0.9932× | 0.9777–1.0179× | 7 |
| sha2_192s / keygen | 1531.7771 | 1545.4926 | 0.9911× | 0.9929× | 0.9740–0.9999× | 10 |
| sha2_192s / sign | 14468.0490 | 14545.7500 | 0.9947× | 0.9958× | 0.9802–1.0127× | 9 |
| sha2_192s / verify | 14.1772 | 13.8487 | 1.0237× | 1.0308× | 0.9740–1.0696× | 3 |
| sha2_256f / keygen | 71.1994 | 71.5820 | 0.9947× | 0.9954× | 0.9766–1.0085× | 7 |
| sha2_256f / sign | 1452.9679 | 1461.4670 | 0.9942× | 0.9993× | 0.9324–1.0168× | 6 |
| sha2_256f / verify | 43.0735 | 40.9507 | 1.0518× | 1.0213× | 0.9916–1.3334× | 1 |
| sha2_256s / keygen | 1024.5117 | 1020.3419 | 1.0041× | 1.0049× | 0.9929–1.0134× | 2 |
| sha2_256s / sign | 13162.6050 | 13087.9563 | 1.0057× | 1.0032× | 0.9969–1.0317× | 3 |
| sha2_256s / verify | 20.2177 | 19.7290 | 1.0248× | 1.0265× | 0.9792–1.0909× | 2 |
| shake_128f / keygen | 15.9608 | 16.0394 | 0.9951× | 0.9941× | 0.9667–1.0156× | 7 |
| shake_128f / sign | 376.8258 | 373.1459 | 1.0099× | 1.0064× | 0.9954–1.0626× | 2 |
| shake_128f / verify | 24.2255 | 23.5181 | 1.0301× | 1.0264× | 0.9812–1.0778× | 1 |
| shake_128s / keygen | 980.7901 | 978.0016 | 1.0029× | 1.0054× | 0.9925–1.0077× | 3 |
| shake_128s / sign | 7538.1824 | 7529.8660 | 1.0011× | 1.0065× | 0.9403–1.0356× | 4 |
| shake_128s / verify | 9.3427 | 8.8858 | 1.0514× | 1.0535× | 1.0104–1.0893× | 0 |
| shake_192f / keygen | 23.0841 | 25.1420 | 0.9181× | 0.9751× | 0.6876–1.0097× | 8 |
| shake_192f / sign | 602.7855 | 647.0338 | 0.9316× | 0.9585× | 0.7396–1.0128× | 9 |
| shake_192f / verify | 33.8891 | 38.6097 | 0.8777× | 0.9545× | 0.5407–1.0327× | 8 |
| shake_192s / keygen | 1474.9087 | 1449.7188 | 1.0174× | 1.0017× | 0.9916–1.1781× | 3 |
| shake_192s / sign | 13135.3964 | 13398.4922 | 0.9804× | 0.9968× | 0.8511–1.0049× | 7 |
| shake_192s / verify | 13.0361 | 12.8673 | 1.0131× | 1.0214× | 0.8996–1.0732× | 2 |
| shake_256f / keygen | 61.2140 | 62.0478 | 0.9866× | 0.9908× | 0.9592–1.0076× | 8 |
| shake_256f / sign | 1242.8468 | 1251.3803 | 0.9932× | 0.9933× | 0.9881–0.9998× | 10 |
| shake_256f / verify | 35.4733 | 35.1572 | 1.0090× | 1.0136× | 0.9643–1.0266× | 1 |
| shake_256s / keygen | 967.8810 | 987.3612 | 0.9803× | 0.9985× | 0.8478–1.0097× | 6 |
| shake_256s / sign | 11692.9736 | 11706.1203 | 0.9989× | 0.9973× | 0.9934–1.0092× | 6 |
| shake_256s / verify | 18.6862 | 18.5096 | 1.0095× | 1.0232× | 0.9199–1.0760× | 4 |

SHAKE-192f loses in all three totals: 0.9182× key generation (eight losing keys), 0.9316× signing (nine), and 0.8777× verification (eight). Its verification key ratios extend down to 0.5407×. Key generation does not call the changed FORS helper, but this observation does not identify or remove the causes of the measured losses. SHA2-128s verification shows 1.0680× with no losing keys here; that magnitude was not stable across the earlier repeated protocols. No new general latency claim follows. The original shared-JVM systematic SHAKE loss, the separate-process follow-up, and this pass all remain preserved. The prior direct whole-verification allocation reduction of 2.8–7.3% is unchanged; allocation was not remeasured in this pass.

Process CPU totals are retained separately from wall time in every summary cell. BC also retains current-thread CPU totals; process CPU includes JVM compilation and garbage collection work on other threads. None of these totals normalize or remove wall-time losses.
