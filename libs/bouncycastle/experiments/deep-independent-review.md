# Independent deep-experiment evidence review

`deep-independent-review.py` reads saved artifacts without launching Java. Run it from an evidence worktree with the retained source/class trees and the pinned upstream Bouncy Castle Git object available:

```sh
python3 libs/bouncycastle/experiments/deep-independent-review.py \
  --result /absolute/path/to/results.json \
  --workspace /absolute/path/to/experiment-worktree \
  --upstream /absolute/path/to/bc-java \
  --out /absolute/path/to/new-review.json
```

SLH accepts a preparation manifest or completed `bc-slh-deep-results-v1` result, including the separately sealed recovery collector. ML accepts a preparation manifest or completed `execution.json`; normal and sampler modes also require the corresponding `summary.json`. Output creation is exclusive. Missing files, failed processes, duplicate identities/JSON keys, nonfinite or wrongly typed counters, incomplete corpus coverage, wrong output digests, source drift, changed command order, and incorrect summary claims cause failure.

The review independently matches baseline Java bytes against the pinned Git blobs and reconstructs candidate source from the production patch. ML ablations restore complete relevant methods from the baseline; instrumented profile builds must reduce to the exact production sources after removing diagnostic mark statements and the separately bound helper. All retained class trees, Java executable, source/driver files, and corpora are checked against their manifests. This binds retained artifacts; it does not independently recompile them or prove an entire JDK installation unchanged. ML preparation text logs do not retain standalone process exit records; measurement execution records do.

Whole-operation output digests are recomputed from encoded fixture bytes. ML sampler digests use a separate Python SHAKE implementation interface, 23-bit rejection sampling, and packed-bit gamma decoding followed by signed 32-bit big-endian serialization. SLH stage outputs are checked against the sealed baseline/candidate preparation results. Profile-mode ML output has no per-call digest; it relies on source-bound per-call checks and prior correctness gates and is reported as diagnostic evidence only.

The SLH summary recomputes complete-cycle round means, process medians, paired ratios, ranges, and losses. It preserves zero CPU readings under the recovery protocol and uses null ratios for zero candidate denominators. The ML summary recomputes ratios of summed times over matching keys and rounds, per-round and per-key ratios, CPU totals, allocated-byte totals, and every reported loss. Main ML measurements use 128 unique keys per process with an independently reproduced Java shuffle and 1,000 fixed warmup calls on disjoint keys. SLH measurements reuse four distinct keys in complete cycles; its nested stage probes cannot be summed. ML instrumented profile warmup uses its measured corpus and is distinct from main timing.

The synthetic acceptance/rejection suite is `python3 libs/bouncycastle/experiments/deep-independent-review-test.py`; it never launches a JVM. These are descriptive screening measurements, not evidence of statistical equivalence or guaranteed JVM steady state.
