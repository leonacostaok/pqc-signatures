# Bouncy Castle WOTS alternatives

The initial 128f screen found lower per-operation allocated bytes from address-object reuse and the existing chain buffer, without establishing a broad latency improvement. Replacing redundant address clearing improved SHA2 signing but consistently slowed SHA2 key generation. Peeling the first chain hash improved some comparisons against the old buffer, yet failed the direct-stock selection rule because SHA2 key generation regressed. These losses remain part of the result.

All six isolated implementations start from Bouncy Castle `c314b9cdffa3958a0eff5344f8fdcdb0181ed830` and add no persistent cache across keys or calls. They separate the object-only address hoist, a same-allocation field/type rewrite, their previous two-address comparator, the existing chain buffer, and its peeled-loop alternative. [Variant definitions and reproduction](../../libs/bouncycastle/experiments/wots-alternatives/README.md) describe exact source changes and boundaries.

Each implementation passed 24 dirty-address transcript cases across n=16/24/32, 2,514 real SHA2/SHAKE chain cases, and 234 whole-operation checks. The latter comprise all twelve fixture keys for each of six fast parameter sets and one distinct key for each of six slow sets, each through key generation, signing and verification. Exact outputs, caller ownership, explicit entropy consumption, retained outputs and tampered-signature rejection are checked. The transcript engine is a test double; these gates do not replace independent conformance or maintainer review. Root separately ran the pinned native SLH verification methods with `test.full=true`, component-length checks, and uninitialized-signer checks against every sealed variant; the additional evidence belongs to the coordinated alternative-comparison report.

The completed first screen contains 288 fresh JVMs: six independent reference/candidate comparisons, SHA2/SHAKE-128f, three operations, separate latency/allocation modes, and two balanced AB/BA pairs. Every process warms on two disjoint keys for twenty calls, then measures ten other distinct keys exactly once. Key decoding is outside timing and operation initialization is inside. Measurements therefore describe fresh calls with unique measured keys after this bounded warmup. Twenty warmup calls and two pairs do not establish steady state or general JVM behavior.

The table retains every screen comparison and operation, including unchanged verification controls for address variants. Values are percentage changes, candidate versus the stated reference; negative means lower. Each percentage divides the arithmetic mean of two candidate process means by the corresponding reference mean, then subtracts one. Each process mean covers ten distinct keys. Wall time and thread CPU come from timing processes; allocated bytes come from separate processes. Raw pair values and absolute process means are retained in [summary.json](../../results/bouncycastle/wots-alternatives/summary.json).

| Parameter | Reference → candidate | Operation | Wall time % | Thread CPU % | Allocated bytes % |
| --- | --- | --- | ---: | ---: | ---: |
| sha2-128f | baseline → object_hoist | keygen | +1.33 | +1.49 | -10.16 |
| sha2-128f | baseline → field_rewrite | keygen | +6.11 | +5.84 | +0.00 |
| sha2-128f | baseline → two_addresses | keygen | -5.23 | -5.31 | -9.86 |
| sha2-128f | baseline → buffer | keygen | +2.84 | +2.89 | -73.21 |
| sha2-128f | buffer → buffer_peeled | keygen | -0.69 | -0.73 | +0.00 |
| sha2-128f | baseline → buffer_peeled | keygen | +4.76 | +4.88 | -73.23 |
| sha2-128f | baseline → object_hoist | sign | -0.67 | -0.37 | -8.23 |
| sha2-128f | baseline → field_rewrite | sign | -3.83 | -3.55 | -0.07 |
| sha2-128f | baseline → two_addresses | sign | -2.44 | -2.25 | -7.94 |
| sha2-128f | baseline → buffer | sign | +0.75 | +0.90 | -66.60 |
| sha2-128f | buffer → buffer_peeled | sign | -8.23 | -7.26 | -0.18 |
| sha2-128f | baseline → buffer_peeled | sign | +2.29 | -5.17 | -66.52 |
| sha2-128f | baseline → object_hoist | verify | -0.61 | -1.00 | +0.00 |
| sha2-128f | baseline → field_rewrite | verify | -0.59 | -0.64 | +0.00 |
| sha2-128f | baseline → two_addresses | verify | +0.98 | +1.01 | +0.00 |
| sha2-128f | baseline → buffer | verify | +3.07 | +2.98 | -61.08 |
| sha2-128f | buffer → buffer_peeled | verify | -14.24 | -14.04 | -0.03 |
| sha2-128f | baseline → buffer_peeled | verify | -1.74 | -1.70 | -61.07 |
| shake-128f | baseline → object_hoist | keygen | +0.09 | +0.06 | -10.19 |
| shake-128f | baseline → field_rewrite | keygen | -0.02 | +0.01 | +0.00 |
| shake-128f | baseline → two_addresses | keygen | -1.43 | -1.42 | -9.89 |
| shake-128f | baseline → buffer | keygen | +0.72 | +0.66 | -73.45 |
| shake-128f | buffer → buffer_peeled | keygen | -4.44 | -4.33 | +0.00 |
| shake-128f | baseline → buffer_peeled | keygen | -1.97 | -2.06 | -73.45 |
| shake-128f | baseline → object_hoist | sign | -0.30 | +0.03 | -8.18 |
| shake-128f | baseline → field_rewrite | sign | -0.28 | -0.33 | -0.00 |
| shake-128f | baseline → two_addresses | sign | +0.48 | +0.58 | -7.97 |
| shake-128f | baseline → buffer | sign | -1.18 | -0.99 | -66.66 |
| shake-128f | buffer → buffer_peeled | sign | -0.83 | -0.79 | +0.00 |
| shake-128f | baseline → buffer_peeled | sign | -0.52 | -0.37 | -66.66 |
| shake-128f | baseline → object_hoist | verify | +0.30 | +0.31 | +0.00 |
| shake-128f | baseline → field_rewrite | verify | +1.01 | +0.94 | +0.02 |
| shake-128f | baseline → two_addresses | verify | +0.18 | +0.15 | +0.00 |
| shake-128f | baseline → buffer | verify | +0.85 | +0.87 | -61.17 |
| shake-128f | buffer → buffer_peeled | verify | -1.57 | -1.66 | +0.00 |
| shake-128f | baseline → buffer_peeled | verify | -1.73 | -1.76 | -61.14 |

The object-only hoist reduced allocated bytes about 10.2% in key generation and 8.2% in signing for both 128f hash families. Its aggregate wall-time changes ranged from −0.7% to +1.3%; neither address mechanism has demonstrated a repeatable general speedup. The old buffer reduced allocated bytes about 61–73%, while some latency cells worsened. These are allocation-traffic findings: peak live heap, resident memory, stack use, retained heap, and GC pauses were not measured.

The field rewrite's SHA2 signing improvement repeated across both pairs (wall −4.29%/−3.36%, thread CPU −3.81%/−3.29%). Its SHA2 key-generation regression also repeated (wall +6.08%/+6.15%, thread CPU +5.60%/+6.07%). It advanced under the prespecified improvement branch of the rule despite that loss. Peeling failed the direct-stock screen: SHA2 key-generation wall time rose +4.23%/+5.30% and CPU rose +4.43%/+5.35%, with no direct-stock targeted cell meeting the rule's repeatable-improvement threshold. The attractive old-buffer comparison alone is insufficient evidence of a stock improvement.

[selection.json](../../results/bouncycastle/wots-alternatives/selection.json) applies the rule frozen in the initial [plan](../../results/bouncycastle/wots-alternatives/plan.json). It advances `object_hoist`, `field_rewrite`, `two_addresses`, and `buffer`, and rejects `buffer_peeled`. The selected higher-size followup is sealed for all four SHA2/SHAKE-192f/256f configurations, all three operations, separate counters, and two balanced pairs: 384 fresh processes with the same twenty-call warmup and ten distinct measured keys. It has not been collected yet. Selection is conditional on this small screen, not a significance test; mechanisms are not combined and screen losses are not discarded.

The local source/class/runtime/raw-data audit passed for all 288 processes, 2,880 measured rows, and 72 mode/parameter/operation/comparison cells. The saved-data portable checker independently recomputes the same coverage and arithmetic while explicitly reporting skipped or unavailable local runtime/class-tree checks. A source or fixture seal establishes what was run, not the independence of the cryptographic oracle. [Correctness gates](../../results/bouncycastle/wots-alternatives/gates.json), [manifest](../../results/bouncycastle/wots-alternatives/manifest.json), [execution](../../results/bouncycastle/wots-alternatives/execution.json), and [portable audit](../../results/bouncycastle/wots-alternatives/portable-audit.json) retain the evidence.

The coordinator excluded other agents' benchmark/build work during collection, but the host was not isolated. Earlier OS snapshots showed substantial `fseventsd` CPU use; they do not establish its activity throughout this window. Pair reversal reduces a simple order bias without eliminating JIT, thermal, GC, scheduling, or other background effects. Apparent changes in untouched verification controls and unequal wall/CPU changes are reasons to keep these limits visible. No process was killed to create a quieter host.
