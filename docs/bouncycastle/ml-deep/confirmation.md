# ML-DSA scratch allocation confirmation

The combined sampling-buffer candidate reduced allocated bytes by21.36–30.30% across every measured parameter/operation cell. Latency was mixed: ML-DSA-44 verification and ML-DSA-65 signing were slower in all six rounds, while ML-DSA-87 verification improved in all six. This is a resource-versus-latency tradeoff, not a broad speed improvement. No production pull request has been prepared from these results.

The [predeclared protocol](../../../results/bouncycastle/ml-deep/confirmation-plan/protocol.json) fixed six paired rounds,72 fresh JVMs,1,000 disjoint-corpus warmup calls per JVM, and128 distinct measured keys per batch. It selected baseline and combined from the original four-variant source seal. Each cell therefore contains768 paired key observations across six rounds; the same128 fixture values are reused across rounds in separate JVMs. Paired order reverses exactly in each consecutive round pair.

| Set / operation | Original bytes/call | Changed bytes/call | Allocation reduction | Wall ratio | Thread CPU ratio | Slower keys /768 | Wall ratios by round |
|---|---:|---:|---:|---:|---:|---:|---|
| 44 / sign | 90959.9 | 68893.1 | 24.26% | 1.0092x | 1.0091x | 260 | 1.0398, 1.0030, 1.0197, 1.0035, 0.9912, 0.9987 |
| 44 / verify | 59731.1 | 46974.5 | 21.36% | 0.9688x | 0.9668x | 587 | 0.9846, 0.9188, 0.9644, 0.9622, 0.9946, 0.9888 |
| 65 / sign | 142458.7 | 101926.4 | 28.45% | 0.9798x | 0.9839x | 563 | 0.9922, 0.9552, 0.9953, 0.9871, 0.9751, 0.9750 |
| 65 / verify | 96747.4 | 71763.0 | 25.82% | 1.0173x | 1.0178x | 261 | 0.9757, 1.0765, 1.0131, 1.0127, 1.0095, 1.0181 |
| 87 / sign | 211088.7 | 147138.8 | 30.30% | 0.9974x | 1.0001x | 379 | 1.0017, 0.9894, 1.0015, 1.0181, 0.9829, 0.9914 |
| 87 / verify | 158642.8 | 110805.1 | 30.15% | 1.0546x | 1.0558x | 86 | 1.0260, 1.0598, 1.0331, 1.0813, 1.0747, 1.0546 |

Ratios divide the sum of original times by the sum of changed times on identical keys/rounds. Values below one mean the candidate is slower. ML-DSA-44 verification used3.22% more wall time overall, with all six round ratios below one and three below0.97. ML-DSA-65 signing used2.06% more wall time overall, also with all six rounds slower. The predeclared latency review trigger required both aggregate ratio below0.97 and at least four rounds below0.97, so it did not fire; that does not establish absence of regression. All per-key losses and ranges remain in the [full summary](../../../results/bouncycastle/ml-deep/confirmation/summary.json).

The measured scope includes fresh signer/verifier construction, initialization, message update and the final operation. Expanded-key construction/import and fresh caller copies are excluded; no persistent key/matrix cache is used. Output equality, input ownership and negative validation happen after timing, with every measured output checked. Per-operation CPU measures only the calling thread; separate process CPU, GC and compilation diagnostics include the checked driver work. These are allocated-byte counters, not peak memory measurements. The [screen report](screen.md) describes the independent sampling gates, finer stages and remaining limitations.

All72 processes exited successfully, producing9,216 checked output rows. The wrapper retained the original collector execution JSON and all untouched stdout, compared the actual order with the predeclared72-job plan, and the frozen collector verified source/class/runtime/corpus/environment bindings before and after timing. The [execution record](../../../results/bouncycastle/ml-deep/confirmation/execution.json) records all arguments, timestamps and hashes. The confirmation manifest SHA256 is `bd2846a0a790bf2a19c4f4877a225a3241d234c33d12395fb77ff882b83a81e2`; the unchanged parent source seal is `5ec5e4e10eba45cf77729f1960f1ea2bdd5806a58ff110ca5f6d3148fafb6bf7`.

An independent checker passed all72 process records,9,216 output digests, source reconstruction, class/runtime/corpus seals, the declared schedule, all summary fields, allocation targets and the latency-trigger calculation. Its report is maintained at `results/bouncycastle/deep-independent/ml-confirmation.json` for integration with this evidence. The unchanged four-variant screen, sampler probes and stage profiles also passed independent review.

The source change remains a small operation-local allocation candidate. Before any submission it needs a decision on the observed latency tradeoff, repository-native regression tests and fresh native ACVP/Wycheproof execution. The existing private correctness corpus and source-bound sampler gates pass; they do not replace the native suite. The lazy-row alternative is an unbuilt plan only and has no performance claim.
