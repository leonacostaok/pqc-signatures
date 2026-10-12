# Independent review of Bouncy Castle deep screens

The independent checker accepted the pinned-source and patch reconstruction, retained class and corpus seals, process commands/exits/order, every retained full-operation and sampler output, and every summary claim for the initial completed screens. The ML sampler check derives its canonical coefficient output separately using Python SHAKE, rejection sampling, and gamma bit decoding. This is artifact and calculation verification, not an independent rebuild or a claim of statistical significance.

| Initial evidence | Processes | Measured calls | Result |
|---|---:|---:|---|
| SLH whole-operation pilot | 24 | 1,704 | All six cells and both paired ratios per cell match |
| SLH recovered stage screen | 144 | 116,052 | All 36 cells match; zero CPU samples and recovery chronology retained |
| SLH allocation screen | 24 | 192 | All six cells and complete four-key cycles match |
| ML whole-operation screen | 48 | 6,144 | Every original/enriched raw output and all 18 summary cells match |
| ML sampler screen | 24 | 3,072 | All output digests independently derived; all 18 summary cells match |
| ML instrumented profile | 12 | 1,536 | Source transformation, raw processes, stage coverage and entry counts match |

For the combined ML candidate, the initial ratios of total original time to changed time are:

| Parameter | Sign wall | Verify wall | Sign calling-thread CPU | Verify calling-thread CPU | Sign allocation reduction | Verify allocation reduction |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | 1.01478× | 0.98275× | 1.01484× | 0.98377× | 24.27% | 21.98% |
| ML-DSA-65 | 0.99967× | 0.98454× | 0.99939× | 0.99057× | 28.02% | 25.91% |
| ML-DSA-87 | 0.99056× | 1.05720× | 0.99838× | 1.05447× | 30.30% | 30.01% |

Values below 1 indicate slower execution. The initial screen supports a substantial reduction in allocated bytes, with mixed latency results; it does not support a broad CPU speedup. All per-key losses and paired-round totals remain in the JSON reports. The full SLH pilot also has mixed results and several losses in both forks. Its stage kernels are nested diagnostics and cannot be added to estimate total cost.

The profile measurements use instrumented source and warm up on their measured corpus; they have no per-call output digest in the raw profile format. Their source-bound driver checks and preparation gates are distinct from the uninstrumented whole-operation checks. ML whole-operation and sampler measurements use 128 distinct measured keys per process, a reproducible shuffled order, and 1,000 disjoint-key warmup calls. SLH whole-operation measurements reuse four distinct keys in complete cycles. CPU means the calling thread for ML; separately retained SLH process CPU is explicitly identified.

`slh-preparation.json` is the initial preparation-only report. Its 0.619-second read/hash check overlapped the exploratory SLH stage window; `preparation-check-interval.json` preserves the estimated interval and its limits. This overlap is retained when interpreting that screen. The whole-operation pilot had already finished. Later verification ran in a separate coordinated correctness window after ML timing ended.

The checker and synthetic acceptance/rejection tests are in [the experiment directory](../../../libs/bouncycastle/experiments/deep-independent-review.md). Reports bind exact checker hashes and inputs where recorded. Retained compiled artifacts are verified by hash rather than rebuilt; a Java executable hash does not seal every file in the JDK installation. ML preparation logs are textual and do not contain standalone exit-status records, whereas every measured process has a checked structured exit status.

The six-round ML confirmation preparation also passed: the additive manifest preserves all original source/class/corpus fields and declares exactly 72 fresh processes using baseline and combined variants. Its completed measurements are separate from the initial screens above. The latest checker passed all 11 synthetic acceptance/rejection tests; `unit-tests.txt` preserves the output.

The completed six-round ML confirmation passes independent review of all 72 fresh processes, 9,216 measured outputs, original and wrapper execution bindings, exact balanced orders, and every summary field. The encoded inputs, Java driver, production sources, and class trees remain the same as in the initial screen. The independent report is `ml-confirmation.json`.

| Parameter | Sign wall ratio | Verify wall ratio | Sign allocation reduction | Verify allocation reduction |
|---|---:|---:|---:|---:|
| ML-DSA-44 | 1.00917× | 0.96878× | 24.26% | 21.36% |
| ML-DSA-65 | 0.97979× | 1.01733× | 28.45% | 25.82% |
| ML-DSA-87 | 0.99745× | 1.05459× | 30.30% | 30.15% |

All six allocation reductions meet the predeclared 20% resource target. ML-DSA-44 verification nevertheless loses all six rounds and is 3.22% slower overall; three round ratios fall below 0.97. The chosen latency review rule requires at least four such rounds as well as an aggregate ratio below 0.97, so it does not trigger. That rule is a screening choice, not evidence of no regression. ML-DSA-65 signing also loses all six rounds and is 2.06% slower overall. ML-DSA-87 verification improves in every round. The result supports allocation savings with an explicit latency tradeoff.

`slh-stage-summary.md` contains the requested 18-stage tables for both selected SLH parameter sets, including original/changed microseconds and both paired ratios. The full-operation allocation screen shows sign allocation reductions of 66.67%/66.83% and verification reductions of 61.64%/62.19% for SHA2/SHAKE-128f, while the separate whole-operation latency pilot remains mixed.
