# Noble #56 resource and side-effect audit

The row-dot patch reduces temporary polynomial allocation, but it does not establish lower peak memory. Keygen, public-key derivation and verification retain a complete public matrix row while calculating its product; signing already retained its matrix within each call. No new correctness, caller-ownership, cleanup or cross-call-cache defect was found in this review. The maintainer [closed PR #56](https://github.com/paulmillr/noble-post-quantum/pull/56#issuecomment-6117136956) over the complexity-versus-speed tradeoff; that is separate from a memory or correctness finding.

The reviewed signed head is `39d56d145aa0127f3117f191aec0522aeb76397f`, against official `48e493397e69fa3e377bd454ff5261b1a7e22651`. Its `src/ml-dsa.ts` bytes exactly match the earlier measured 0.7.1 candidate; the baseline matches too. The only other PR change is the native public-API regression in `test/basic.test.ts`. [Source identity](../../results/noble/resource-audit/source-identity.json) records those checks. The new probe copies the sealed dependencies into separate directories, requires equality except for production TS/compiled JS, and uses Node 22.23.2. It explicitly omits an old, unused arithmetic-test module. No production source or previous evidence is changed.

## Allocation inventory

Across twelve varied deterministic keys per parameter, keygen/getPublicKey/verify each avoid 16/30/56 numeric-length `Int32Array(256)` constructions for ML-DSA-44/65/87. That is 16/30/56 KiB less logical polynomial payload per call. Signing savings vary with rejection attempts; all outputs and caller inputs matched the baseline.

| Set | Keygen arrays, original→changed | getPublicKey / verify arrays, original→changed | Signing arrays, original range→changed range | Signing payload saved per matched key |
| --- | ---: | ---: | ---: | ---: |
| ML-DSA-44 | 53→37 | 57→41 | 81–471→65–295 | 16–176 KiB |
| ML-DSA-65 | 89→59 | 95→65 | 129–1,829→99–1,019 | 30–810 KiB |
| ML-DSA-87 | 151→95 | 159→103 | 205–1,463→149–735 | 56–728 KiB |

These are constructor-instrumented logical payload counts, not total V8 allocations, object overhead, retained heap or peak memory. The probe separately counts ArrayBuffer-backed views; every observed counted constructor used a numeric length and every view count was zero. It excludes ordinary JS row arrays, closures, other typed arrays and runtime/JIT allocations. Input copies and checks are outside the constructor counter interval. Twelve short-signature rejections per parameter retain identical counts (4/6/8 polynomial arrays) and return false. [All 360 checked outputs](../../results/noble/resource-audit/constructors/execution.json) and the recomputed summary preserve the complete key-by-key counts.

The source-level tradeoff is at [`ml-dsa.ts:515–525,550–561,733–742`](https://github.com/paulmillr/noble-post-quantum/blob/39d56d145aa0127f3117f191aec0522aeb76397f/src/ml-dsa.ts#L515): instead of sampling and multiplying one matrix polynomial at a time, the loop creates a small ordinary row array holding L=4/5/7 public polynomials before calling `DotNTTs`. That increases the simultaneously referenced public-row inventory by 3/4/6 KiB relative to one sampled polynomial. The removed product scratch is another 1 KiB, so those public-row bytes alone are not a net live-memory estimate. Garbage collection, compiler liveness and backing-store behavior prevent converting these counts into physical peak memory. Signing at lines 599–605/637–641 uses the existing operation-local matrix and adds no new row array.

## Post-GC diagnostics

All 96 processes passed 27,648 measured-call correctness checks after separate warmup. Final post-GC ArrayBuffer balances were identical across variants and operations for each set (68,727 / 80,731 / 92,019 bytes for ML-DSA-44/65/87), and ArrayBuffer/external totals were constant across the last three checkpoints in every process. Both variants increased from their pre-batch baseline by 21,350 / 27,352 / 32,996 ArrayBuffer bytes, so these snapshots include retained harness/last-call state and must not be read as cryptographic-only memory.

Candidate final post-GC heap-used medians were **1,728–9,832 bytes higher** across the twelve cells. This small residual is retained here as a negative observation, not interpreted as a proven leak: it includes the larger code/JIT footprint, harness and runtime variation. Neither the unchanged buffer balances nor this small heap difference proves long-run absence/presence of a leak. Total allocation traffic and operation peaks are not measured by post-GC snapshots.

| Set | Operation | Original final heap median | Changed final heap median | Difference |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-44 | keygen | 7,167,000 | 7,169,148 | +2,148 |
| ML-DSA-44 | getPublicKey | 7,130,648 | 7,132,716 | +2,068 |
| ML-DSA-44 | sign | 7,253,384 | 7,257,532 | +4,148 |
| ML-DSA-44 | verify | 7,211,916 | 7,215,480 | +3,564 |
| ML-DSA-65 | keygen | 7,164,224 | 7,174,056 | +9,832 |
| ML-DSA-65 | getPublicKey | 7,133,368 | 7,135,096 | +1,728 |
| ML-DSA-65 | sign | 7,252,596 | 7,259,236 | +6,640 |
| ML-DSA-65 | verify | 7,218,928 | 7,222,448 | +3,520 |
| ML-DSA-87 | keygen | 7,165,632 | 7,169,352 | +3,720 |
| ML-DSA-87 | getPublicKey | 7,123,824 | 7,128,168 | +4,344 |
| ML-DSA-87 | sign | 7,256,272 | 7,265,232 | +8,960 |
| ML-DSA-87 | verify | 7,210,976 | 7,216,936 | +5,960 |

[Raw post-GC output](../../results/noble/resource-audit/post-gc/execution.json) and [recomputed summary](../../results/noble/resource-audit/summary.json) retain every checkpoint, fork, automatic/forced GC observation and order. Automatic GC event counts were equal in most cells and lower in three candidate cells; their delivery and runtime behavior make these descriptive diagnostics, not a performance or total-allocation claim.

The unmodified-module diagnostic uses four fresh-process rounds with equal AB/BA exposure per cell, all three sets and keygen/getPublicKey/sign/verify. Each process first performs 48 checked calls on twelve disjoint warmup values, then three batches of 96 calls cycling twelve measured fixture values with fresh caller buffers/options. No result, signer, verifier or matrix is deliberately retained across calls. Twice-forced GC precedes each of four memory checkpoints; snapshots include the harness, decoded fixture, JIT and possibly last lexical temporaries. GC event counts are diagnostic only. No latency, RSS, exact JS allocation volume or operation-peak claim is made. Small residual heap differences cannot by themselves establish leaks.

The first post-GC attempt stopped after one worker because deferred PerformanceObserver delivery had exposed seven of eight completed forced collections. Its stdout/stderr, sources and manifest are retained under `observer-delivery-incomplete`; it is excluded from final diagnostics. A bounded event-delivery flush was added before disconnecting the observer without changing the memory snapshots. The earlier constructor probe that did not distinguish views is also preserved under `pre-review-probes`, and was replaced by the explicit numeric/view gate above.

## Arithmetic, ownership and cleanup

[`DotNTTs` at lines 230–239](https://github.com/paulmillr/noble-post-quantum/blob/39d56d145aa0127f3117f191aec0522aeb76397f/src/ml-dsa.ts#L230) sums at most seven canonical products. With q=8,380,417, the maximum is `7*(q-1)^2 = 491,619,606,331,392 < 2^49 < 2^53`, so each integer product and partial sum is exact in JavaScript. `crystals.mod` applies `%` before its int32 conversion. Sampled matrix entries are canonical; the forward NTT canonicalizes centered/noncanonical decoded-vector coefficients before the product. All four call sites supply distinct outputs and preserve inputs. No wider public helper accepts arbitrary noncanonical vectors.

`RejNTTPoly` owns each returned Int32Array; sampled rows do not alias the XOF buffer. Public row sampling depends on the public seed, and loop bounds remain fixed by public parameters. The patch changes no validation, entropy handling, comparisons, rejection decisions or public API. JavaScript does not offer a portable constant-time execution guarantee; this patch does not establish one.

Keygen/getPublicKey cleanup remains at lines 537/561 and signing cleanup at 661/672/677/687/693. The removed intermediate product arrays could contain secret-derived values and previously were not explicitly cleared individually. Eliminating them creates fewer such temporary copies. Newly retained row arrays contain public matrix data. Existing secret scratch clearing and caller-owned external-mu handling remain unchanged, as do JavaScript's limits on erasing compiler/register copies. No cache, static mutable state or asynchronous concurrency path is added.

## Retained performance losses and portability

The earlier two-release/two-Node matrix improved all 48 warmed cells and all 240 warmed fork medians: signing 1.091–1.189× and verification 1.101–1.189×. First-operation cell medians also improved, but five individual forks lost: 0.7.1/Node22 ML44 getPublicKey 0.998×; 0.7.0/Node22 ML44 and ML87 signing 0.991×; 0.7.1/Node24 ML44 getPublicKey 0.991× and signing 0.992×. Startup-included cell medians span 0.990–1.032× with 13/48 below one. There is no general startup improvement claim. At the individual-pair level, 3/960 warmed pairs lose: ML87 verification on 0.7.0/Node24 has a retained 0.1881× outlier, and two keygen pairs are 0.9922×/0.9942×. First-operation raw pairs lose 192/1,440 times; startup-included pairs lose 591/1,440. These observations are not hidden by the improving medians, and their cause was not established. [The full loss inventory](../../results/noble/resource-audit/prior-performance-losses.json) identifies every losing pair/fork and hashes its original report. All original samples remain in the [robustness evidence](https://github.com/leonacostaok/pqc-signatures/blob/e331f0054ce7a6410547a15a79b3ad670fe5f6dd/docs/noble/robustness.md).

The original two-runtime row-dot experiment also retains two losing raw pairs among 720: ML44 sign/Node22 0.9988× and ML65 verify/Node24 0.9940×, despite improved cell medians. The later changed-first ten-key check improved all 90 key/operation pairs, with signing totals 1.145–1.202× and verification 1.144–1.187×. It is an unbalanced one-pass sensitivity check, not steady-state confirmation or evidence that noisy/regressing forks disappeared. All timing evidence is from one Apple M1 Pro/macOS host on Node 22/24; no SpiderMonkey, JavaScriptCore, browser, other architecture or application-GC speedup is established. The native regression test and prior shared/ACVP tests support correctness, not runtime portability or a security proof.

## Reproduce

Preparation requires the earlier sealed 0.7.1 dependency trees and exact upstream Git refs recorded by the runner. It copies them into new ignored directories and refuses existing output paths. The fixture and full raw source manifests are retained with this audit.

```sh
python3 libs/noble/experiments/published-memory/run.py prepare
python3 libs/noble/experiments/published-memory/run.py constructors --out results/noble/resource-audit/new-constructors
python3 libs/noble/experiments/published-memory/run.py retained --out results/noble/resource-audit/new-post-gc
python3 libs/noble/experiments/published-memory-review.py results/noble/resource-audit
```

Use a quiet diagnostic window for post-GC runs. Python optimization is rejected, raw stdout is preserved, and source/runtime/fixture hashes are checked before and after collection. These commands do not alter the published patch.
