# CIRCL missing-cell and normal-GC follow-up protocol

This follow-up keeps the published SHA2 prefix implementation and previous evidence unchanged. Baseline-only cells cover ML-DSA-44/65/87 and all six SHAKE SLH-DSA sets, with no fake candidate gain for unchanged paths. A separate four-round paired resource experiment covers all six affected SHA2 sets and keygen/sign/verify. Testing and supporting analysis are AI-assisted.

Production trees come directly from the measured official and signed Git refs and receive only a separate driver. Each tree, Go executable, new binary, script and corpus is hashed. The driver uses the same new FIPS ML/SLH fixtures produced by the pinned noble baseline, so exact key/signature comparisons provide an independent implementation oracle. Each set has two disjoint warmup seeds and three measured seeds; messages and contexts vary. Public operations use fresh buffers and freshly decoded keys. API clocks exclude those copies/imports and checking, while the resource workload includes them. CIRCL ML-DSA import can prepare key data, and that setup remains visible in workload resource totals.

Baseline-only collection performs two warmup calls and three measured cases per action in three fresh processes per set (27 processes). Slow-operation warmup is capped, not labeled steady-state. SHA2 resources use four balanced AB/BA rounds under `GOGC=100,GOMEMLIMIT=off` and `GOGC=100,GOMEMLIMIT=8MiB`, always `GOMAXPROCS=1`, with no explicit GC calls. There are 288 resource processes. The soft Go memory limit is not an RSS cap. Fixed call counts vary by public parameter/action to keep slow signatures bounded; both variants use identical counts, repeated complete three-case cycles, and two disjoint warmup calls. Counts are visible in the driver and raw output.

Every output matches the complete fixture, every caller input is preserved, and every process rejects three tampered signatures. Whole-workload wall/CPU totals include fresh key decoding, copies, output checks/digests and instrumentation. Individual API clocks are retained as instrumented-workload observations, separate from earlier clean latency. `TotalAlloc`/`Mallocs` deltas and allocation rate are real process-runtime counters over the checked workload, not only cryptographic function allocations. GC cycle, cumulative pause and GC CPU deltas are reported with that same broad scope; they do not attribute individual pauses to the production patch.

Memory snapshots after each operation provide sampled heap maxima and last-GC live-heap observations. They can miss intra-operation peaks. `StackInuse` is runtime-reserved goroutine stack storage, not consumed stack high-water; prior compiler local-frame evidence remains separate. OS maxRSS is process-lifetime high-water including loading/warmup (Darwin bytes, normalized explicitly). No exact cryptographic stack/heap peak or leak-absence claim is made. Zero observed GC cycles or pauses is an observation for this bounded workload, not inferred zero cost.

The final summary sets last-GC heap observations to null when no GC has completed since startup, and sets their four-round aggregate to null unless every round is available. A non-null counter may still refer to warmup when no measured GC occurred. The preserved `counter-summary.json` contains the runtime's raw counter values; `summary.json` adds the explicit availability information. The normalization script is separate from the frozen collector and records its own hash.

| SHA2 variant | keygen calls | sign calls | verify calls |
| --- | ---: | ---: | ---: |
| 128f | 1,536 | 60 | 1,536 |
| 192f | 768 | 36 | 1,536 |
| 256f | 384 | 18 | 1,536 |
| 128s, 192s, 256s | 24 | 3 | 3,072 |

```sh
python3 libs/circl/experiments/resource-followup/run.py prepare
python3 libs/circl/experiments/resource-followup/run.py check
# Exclusive measurement window only:
python3 libs/circl/experiments/resource-followup/run.py collect --profile baseline --out results/circl/resource-followup/baseline
python3 libs/circl/experiments/resource-followup/run.py collect --profile resource --out results/circl/resource-followup/resource
python3 libs/circl/experiments/resource-followup-summary.py results/circl/resource-followup/baseline results/circl/resource-followup/resource results/circl/resource-followup/summary.json
```

Preparation requires the newly generated noble fixture manifest. Existing output paths are refused. Source/runtime/binary/corpus/script hashes and gates are checked before and after collection, with every raw stdout/stderr, command, order, status and timestamp retained. The report gives all repeats and percent deltas where denominators exist; observed zeros retain a defined null percentage instead of division-by-zero or an invented improvement.

The recorded Go source trees and exact benchmark binaries are archived with deterministic metadata under `preparation/sources.tar.gz`, accompanied by a checksum and source/binary notices. `python3 libs/circl/experiments/resource-followup-evidence.py verify` checks the archive, committed driver/collector inputs, every raw stdout/stderr hash, complete case coverage, balanced order, exact command/runtime/environment bindings and every output digest using only committed files. It passed in a relocated copy without the original build directories. This checks evidence integrity and selected source/binary bindings; it does not rebuild the compiler/runtime or independently implement cryptography.
