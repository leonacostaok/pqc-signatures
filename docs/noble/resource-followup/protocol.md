# Noble missing-cell and GC follow-up protocol

This new evidence keeps the published ML-DSA row-dot implementation and all previous measurements unchanged. The baseline-only module covers all twelve SLH-DSA sets and detached Falcon-512/1024; no candidate gain is assigned to unchanged algorithms. A separate resource workload covers ML-DSA-44/65/87 keygen, getPublicKey, sign and verify. Testing and supporting analysis are AI-assisted.

Preparation copies the previously sealed noble 0.7.1 dependency trees and verifies their complete contents. New fixtures contain two disjoint warmup seeds and three measured seeds per parameter, deterministic entropy, messages of 0/64/1024 bytes and contexts of 0/31/255 bytes (Falcon has no context). Full keys/signatures are retained as an oracle. Every worker checks complete output bytes, fresh caller-array preservation and three tampered signatures; collectors independently recompute each aggregate output digest. Parameter values repeat across calls but caller arrays/options are fresh; no signer/key/matrix cache persists between calls.

Baseline-only collection has three fresh processes per parameter. Every keygen/sign/verify phase performs two warmup calls and one operation on each measured case. Warmup is deliberately capped because small-signature SLH-DSA sets are expensive; these are baseline observations, not a claim of steady-state throughput. Copying and checks are outside each API clock. Process maxRSS includes module loading, fixture parsing, warmup and all phases; it is not per-operation peak memory.

The resource plan has four fresh-process rounds, both variants, all three ML-DSA sets and four actions under default V8 settings and `--max-old-space-size=32 --max-semi-space-size=1`. Every cell has equal AB/BA order exposure. Each process has one action, 24 disjoint warmup calls and 192 checked measured calls. There are 192 resource processes, plus 42 baseline-only processes. No explicit GC is requested. The constrained configuration limits V8 old-space and semi-space, not whole-process RSS, and its actual heap limit is recorded. Any process failure stops collection and remains in raw evidence.

Resource workload wall/CPU totals include caller copying, key handling, checks, digest consumption, memory sampling and event-loop yields. Individual API clocks are retained but are explicitly instrumented-run observations; they are not substituted for earlier clean latency evidence. GC counts/durations are observed PerformanceObserver events whose start lies in the checked-workload interval, after a bounded delivery drain. They include the harness and JIT, and zero observed events does not prove no collection. Event duration is not assumed to be a complete stop-the-world pause measurement or CPU time.

`process.memoryUsage()` samples occur after every synchronous operation, and therefore miss intra-operation peaks. The report separates sampled maximum heapUsed/external/ArrayBuffer balances, ending balances, actual V8 heap limit and process-lifetime OS maxRSS (Node reports KiB). None is an exact cryptographic peak. The prior numeric polynomial constructor probe remains a logical payload measure; Node's public runtime counters do not expose exact whole-process allocation traffic, so total JS allocated bytes/rate remain unavailable rather than inferred from heap deltas. No consumed-stack high-water is claimed; V8 stack settings describe limits, not usage.

The pinned Node executable reports a default V8 `--stack-size=864` in kBytes; the full option output is retained in preparation evidence. Successful API checks with that default establish only that this configuration runs the cases, not how much native or JavaScript stack they consume. The constrained heap flag check reports an actual V8 heap limit of 36,700,160 bytes.

```sh
python3 libs/noble/experiments/resource-followup/run.py prepare
python3 libs/noble/experiments/resource-followup/run.py check
# Exclusive measurement window only:
python3 libs/noble/experiments/resource-followup/run.py collect --profile baseline --out results/noble/resource-followup/baseline
python3 libs/noble/experiments/resource-followup/run.py collect --profile resource --out results/noble/resource-followup/resource
python3 libs/noble/experiments/resource-followup/summarize.py results/noble/resource-followup/baseline results/noble/resource-followup/resource results/noble/resource-followup/summary.json
```

Fresh output directories are mandatory. Source/dependency/runtime/fixture/script hashes and correctness logs are checked before and after collection; complete stdout/stderr, order and timestamped process status are retained. Comparisons use paired per-process totals and report all four rounds, percent changes and losses. Baseline-only summary entries contain no candidate or improvement field.

The selected dependency/source trees are archived with deterministic metadata under `preparation/sources.tar.gz`, accompanied by a checksum. `python3 libs/noble/experiments/resource-followup-evidence.py verify` checks that archive, committed collector inputs, every raw stdout/stderr hash, complete case coverage, balanced order, exact command/runtime bindings and every output digest using only committed files. It passed again in a relocated copy without the original ignored build directories. This is evidence integrity verification, not a new runtime rebuild or independent cryptographic implementation.
