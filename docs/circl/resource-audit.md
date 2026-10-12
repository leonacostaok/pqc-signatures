# CIRCL #708 resource and side-effect audit

The exact published patch speeds up SHA2 operations but increases whole-operation heap allocation. It is a time-versus-memory tradeoff, not an allocation reduction. No new shared-state, caller-ownership, cleanup or correctness defect was found in this review. Peak live memory and peak stack use remain unmeasured.

The reviewed production head is `1c31496b567c27e672979358befd2505cb735fa9`, against official `91db3e785ba2635b4f24a023e1ad76d2780e2865`. Its `sign/slhdsa/state.go` bytes exactly match the earlier measured candidate, and the baseline matches too; the only other PR file is the native regression test. [Source identity](../../results/circl/resource-audit/source-identity.json), [raw operations](../../results/circl/resource-audit/whole-operations/execution.json) and [recomputed summary](../../results/circl/resource-audit/summary.json) bind the versions, Go executable, sources, driver, corpus and outputs. This audit changes no production source or prior evidence.

## Measured allocation cost

On Go 1.27.0 / darwin-arm64, complete SHA2 keygen, deterministic sign and valid verify calls usually add 12 objects and 1,088 bytes at category 1 or 1,376 bytes at categories 3/5. Each cell has nine paired observations: three distinct measured keys, repeated in three fresh-process rounds. Some samples contain one additional 16- or 48-byte process-local allocation; every observation is retained. SHAKE-128f's allocation counts are unchanged.

The counter-only driver uses `runtime.MemStats.TotalAlloc` and `Mallocs`, explicit GC before each measured call, `GOGC=off`, `GOMEMLIMIT=off` and `GOMAXPROCS=1`. All 378 measured operations had zero collections during their counter interval. Caller copies, ordinary key import and output validation are outside the interval; ordinary prefix setup and cleanup remain inside it. One disjoint seed warms each process. Exact keys/signatures, input preservation and tamper rejection are checked outside counters, and both variants match. No wall/CPU timing or RSS claim is made. Process-local runtime allocations can appear in these deltas; they are not a count of only source-level `make` calls.

The table reports mean allocated bytes over the nine calls and the full paired increase range. Object deltas and every pair are in the summary.

| Parameter | Operation | Original bytes/call | Changed bytes/call | Paired byte increase |
| --- | --- | ---: | ---: | ---: |
| SHA2-128f | keygen | 864.0 | 1,952.0 | 1,088–1,088 |
| SHA2-128f | sign | 28,506.7 | 29,605.3 | 1,088–1,136 |
| SHA2-128f | verify | 9,130.7 | 10,218.7 | 1,088–1,088 |
| SHA2-128s | keygen | 1,152.0 | 2,240.0 | 1,088–1,088 |
| SHA2-128s | sign | 16,192.0 | 17,280.0 | 1,088–1,088 |
| SHA2-128s | verify | 6,474.7 | 7,562.7 | 1,088–1,088 |
| SHA2-192f | keygen | 1,216.0 | 2,592.0 | 1,376–1,376 |
| SHA2-192f | sign | 53,558.2 | 54,936.0 | 1,360–1,424 |
| SHA2-192f | verify | 11,154.7 | 12,530.7 | 1,376–1,376 |
| SHA2-192s | keygen | 1,552.0 | 2,928.0 | 1,376–1,376 |
| SHA2-192s | sign | 27,608.0 | 28,989.3 | 1,376–1,424 |
| SHA2-192s | verify | 9,106.7 | 10,482.7 | 1,376–1,376 |
| SHA2-256f | keygen | 1,392.0 | 2,773.3 | 1,376–1,424 |
| SHA2-256f | sign | 71,488.0 | 72,869.3 | 1,376–1,424 |
| SHA2-256f | verify | 12,506.7 | 13,882.7 | 1,376–1,376 |
| SHA2-256s | keygen | 1,648.0 | 3,029.3 | 1,376–1,424 |
| SHA2-256s | sign | 46,224.0 | 47,600.0 | 1,376–1,376 |
| SHA2-256s | verify | 11,242.7 | 12,618.7 | 1,376–1,376 |
| SHAKE-128f | keygen | 976.0 | 976.0 | 0–0 |
| SHAKE-128f | sign | 27,936.0 | 27,936.0 | 0–0 |
| SHAKE-128f | verify | 9,082.7 | 9,082.7 | 0–0 |

Separate setup tests measure `NewStatePub` and `NewStatePriv` plus `Clear`: SHA2 increases from 3 to 15 allocations; SHAKE stays at 2. Zero allocations in the existing F/H/T hot-loop test means only after setup. On this compiler, `unsafe.Sizeof(state)` increases 352→376 bytes and `statePriv` 440→472; `baseHasher` and `stateT` each gain 8 bytes. These struct sizes exclude pointed-to heap objects. The generated `NewStatePub`/`NewStatePriv` frame-local sizes stay 96/128 bytes while their argument/result areas grow by 24/32 bytes; some generated value-wrapper frames grow too. [Layout/setup logs](../../results/circl/resource-audit/candidate-checks.jsonl) and [compiler frames](../../results/circl/resource-audit/candidate-frames.txt) are observations for this compiler, not additive peak-stack estimates.

## Ownership, cleanup and API review

The additional allocations come from three operation-owned SHA prefix wrappers, serialized states and closures: [`state.go:315–354`](https://github.com/cloudflare/circl/blob/1c31496b567c27e672979358befd2505cb735fa9/sign/slhdsa/state.go#L315), with the T instance at lines 242–253. Prefix data contains only the public seed and zeros. Keygen/sign/verify still create their own states and defer `Clear` (`internal.go:12–13,84–85,112–113`); no state is stored on a key or shared across calls. Source review found no added caller-buffer alias or cross-call cache. Existing valid/invalid-signature branches and public APIs are unchanged.

`sha2Prefix.Clear` restores the public-only digest state before zeroing the saved bytes and digest scratch (`state.go:338–343`). The F/H closure additionally clears the original prefix slice even though the active input now starts after it (`345–354`); T does the same (`249–253`). Parent clear methods zero the remaining arena slices and drop both closure/hash references (`84–92,259–269`). New audit tests retain references deliberately and verify the full digest serializes to its public-only state, saved/sum/arena bytes clear, and parent clear is idempotent. All five named candidate audit tests passed. This establishes visible buffer clearing; it does not prove erasure of compiler register copies or every transient standard-library copy.

The `encoding.BinaryMarshaler`/`BinaryUnmarshaler` assertions use the documented interfaces returned by `crypto/sha256.New` and `crypto/sha512.New`. In the pinned Go 1.27 sources, both the configured internal FIPS SHA backend and BoringCrypto implementations implement those interfaces; unmarshal overwrites all chaining words, the entire message buffer and length/cursor fields. The immutable saved state is generated by the same digest instance. The pinned implementations therefore support these assertions and resets; BoringCrypto was inspected, not executed on this macOS host. [Standard-library file hashes](../../results/circl/resource-audit/stdlib-source.json) identify that review. No claim is made for an untested future or alternate Go implementation. CIRCL declares Go 1.25; this new allocation/cleanup experiment ran only Go 1.27. Earlier native/emulated amd64 correctness and race logs remain separate from performance portability.

## Retained performance losses and limits

The prior balanced five-fork/four-round experiment improved all 18 affected SHA2 cells and all 90 affected fork medians: keygen 1.329–1.346×, sign 1.322–1.369×, verify 1.323–1.425×. All raw observations remain in the [original report](../../results/circl/experiments/sha2-prefix-go127-arm64.json). All 360 affected raw paired observations also improve. The unchanged SHAKE control loses 27/60 raw pairs and 5/15 fork summaries and has a 0.9999× signing median; [every loss is inventoried](../../results/circl/resource-audit/prior-performance-losses.json). The [changed-first ten-key check](../performance/circl/tenkeys.md) improved all 180 SHA2 key/operation pairs; SHAKE lost 6/10 keygen, 1/10 sign and 3/10 verify pairs, with verification total 0.9994×. These controls do not establish improvement. The ten-key run is an unbalanced one-pass sensitivity check, not a replacement for repeated measurement.

All speed evidence is from one Apple M1 Pro/macOS host and Go 1.27. It does not establish gains on other architectures, Go versions, concurrent applications or memory-constrained workloads. This audit demonstrates a bounded allocation increase even though existing latency results improve. It does not establish peak heap/stack or long-run application GC cost.

## Reproduce

Preparation requires the exact local upstream refs and earlier sealed ten-key corpus identified by the runner. It copies sources into new ignored build paths and refuses an existing preparation/output directory. The checked-in corpus and raw manifests preserve the original fixture independently of those paths.

```sh
python3 libs/circl/experiments/published-memory/run.py prepare
python3 libs/circl/experiments/published-memory/run.py collect --out results/circl/resource-audit/new-whole-operations
python3 libs/circl/experiments/published-memory-review.py results/circl/resource-audit/whole-operations
```

Python optimization is rejected because provenance guards use assertions. The final collector preserves unmodified stdout and checks source/runtime/corpus hashes both before and after collection. No old production patches or benchmark files were edited.
