# SLH-DSA stage and allocation investigation

This bounded follow-up starts at Bouncy Castle `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`, independently of the earlier FORS `base2B` allocation patch. Existing evidence and the earlier personal-fork draft are unchanged. The initial screen covers pure SHA2-128f and SHAKE-128f only; native WOTS tests cover SHA2/SHAKE at all three supported hash-output sizes. The first whole-operation pilot does not establish a reliable latency improvement from the buffer candidate.

## Source findings and candidates

`WotsPlus.chain` previously returned a new `n`-byte hash result on every step. A full public-key chain has 15 steps, and a WOTS public key has 35, 51 or 67 chains for `n=16,24,32`. Those chains execute for every XMSS leaf constructed by key generation and signing and for the remaining chain steps during verification. The buffer candidate keeps the first `F` result allocation, then writes later steps into that owned array. Each hash absorbs all input before writing output. Zero-step chains still clone their input, invalid ranges preserve the existing result, and no caller input or retained result is used as scratch. No key cache, cross-operation engine, algorithm, digest backend or entropy policy is added to production.

SHA2 already absorbs compressed address fields directly and caches the public-seed hash prefix in upstream code. The hypertree public root is already generated only during key generation. These are existing baseline improvements, not new candidates. A JDK/JCA SHA2 backend is outside the buffer patch and has not been introduced; provider recursion, backend portability and validation implications would need separate treatment.

A separate unmeasured treehash-stack patch replaces `LinkedList` and `NodeEntry` allocations in FORS and XMSS treehash with bounded local arrays of at most `height+1` entries. It is retained as a proposed second experiment and is excluded from the initial original-versus-buffer preparation. It has no whole-operation performance claim or completed post-edit validation yet.

## Correctness and source binding

The new native WOTS test compares every valid start/step combination against independent SHA-256/SHAKE input assembly for all supported hash sizes, checking edge patterns, address evolution, input/seed immutability, zero-step ownership, invalid ranges and independence of retained outputs from successive calls. It passes on original and buffer implementations. A recursive treehash oracle also passes on the original treehash implementation; it is not evidence for the unmeasured array-stack edit.

The production source and native tests are saved in commit `70ceae9a93b17b5a1af590e3208855b4df25f728` on `perf/slhdsa-deep`. The committed implementation files and test files exactly match their sealed preparation copies. The separate `Fors.java`/`HT.java` array-stack edits are excluded from that commit and all reported measurements.

The preparation script extracts original source into its own initialized Git repository, checks/applies/reverse-checks the buffer patch, verifies that exactly the intended two source files changed and match the production worktree, and requires different source and compiled-class hashes before differential checks. Source, test, driver, fixture, patch, runtime and class hashes are bound in the preparation manifest and checked again before collection. Earlier interrupted preparation attempts remain in the build directory and do not count as completed evidence.

The full-operation corpus reuses the sealed ten-key fixtures: two disjoint warmup keys and ten measured keys per parameter, with matched seeds, messages, contexts and explicit signing entropy. Preparation checks all twelve keys through public key generation, signing and verification, byte-identical keys/signatures, exact entropy consumption, valid/tampered verification, raw-input integrity and encoded key-object integrity. Timed workloads select measured indices 0, 3, 6 and 9 and reuse these four distinct keys in complete cycles. These are repeated-key latency samples, not newly generated unique keys on every call.

## Diagnostic stages

Stage setup parses a valid signature and precomputes the correct message and address for each hypertree layer. It verifies the FORS public key, each WOTS public key, each authentication-path root, and the final public root. Every stage output is checked against the original implementation and, where encoded in the fixture, the exact signature bytes. Prepared diagnostic inputs are also checked for mutation after each call.

| Stage | Work measured | Output checked |
| --- | --- | --- |
| `verify.decode` | Parse the complete signature into upstream objects | Re-encoded signature |
| `sign.prf_msg` | Derive the signing randomizer with the matched explicit entropy | Signature `R` |
| `hmsg` | Hash message/context and extract FORS digest/tree/leaf indices | Digest plus indices |
| `fors.indices` | Convert the FORS digest to indices | Big-endian index words |
| `verify.fors_leaves` | Hash the selected FORS secret values from the signature | All leaf nodes |
| `verify.fors_auth` | Walk FORS authentication paths from prepared leaves | All FORS roots |
| `verify.fors_compress` | Concatenate/compress the prepared FORS roots | FORS public key |
| `verify.fors` | Complete upstream FORS public-key recovery | FORS public key |
| `verify.wots_chains` | Decode digits/checksum and run remaining chains at every layer | All chain endpoints |
| `verify.wots_compress` | Concatenate/compress prepared endpoints at every layer | All WOTS public keys |
| `verify.wots` | Complete upstream WOTS public-key recovery at every layer | All WOTS public keys |
| `verify.xmss_auth` | Walk each XMSS authentication path from prepared WOTS keys | All layer roots |
| `verify.hypertree` | Complete upstream hypertree verification | Final valid result |
| `sign.fors` | Complete FORS signing, including selected PRFs and treehash authentication paths | Encoded FORS signature |
| `sign.wots` | Sign the correct message at every hypertree layer | Encoded WOTS signatures |
| `sign.xmss_auth` | Construct all XMSS authentication paths through upstream treehash | Encoded authentication paths |
| `sign.hypertree` | Complete upstream hypertree signing | Encoded hypertree signature |
| `sign.serialize` | Reproduce nested upstream concatenations of signature components | Complete signature |

Stages are diagnostic measurements with prepared inputs and a reused operation-local engine. Parent and child stages overlap; their timings must not be added or presented as an exact partition of total time. The chain-only driver reproduces the digit conversion and chain loop through upstream helpers, while the inclusive WOTS/FORS/hypertree stages call upstream methods. Complete operation measurements use uninstrumented production classes and fresh generator/signer/verifier initialization for every call, with encoded-key decoding outside the clock.

## Measurement protocol

Each pair launches one fresh JVM per implementation, parameter and operation, with exactly one implementation on its classpath. Even fork counts balance original-first and changed-first order. Warmup uses fixed work on two disjoint keys, identically for both variants; exploratory warmup lengths and any caps will be recorded rather than described as steady-state proof. Each round executes whole four-key cycles until the sum of timed calls reaches its budget. Wall, process CPU and current-thread CPU endpoints are read before canonical-output, entropy, valid/tampered verification and input/key-integrity checks. Every output is consumed and checked. Process CPU can quantize to zero for short calls.

Round means divide the sum of per-call times by calls; a process is summarized by its median round mean, a paired ratio divides original by changed, and the reported cell statistic is the median across process-pair ratios. Every raw call, process order, stdout/stderr, command, status and loss is retained. Ranges are descriptive, not confidence intervals. Allocation is a separate mode using current-thread allocated bytes, without timing claims or peak/live-heap interpretation. Untimed correctness checks and JVM compilation/GC still affect the surrounding process; small wall-time differences require caution and corroboration.

## Initial whole-operation pilot

The sealed preparation is `prepared-c8eeabbff5cec835`, manifest SHA256 `afe0512047ceb707a9316ebc20a34462d6683127342f6ea0a453930cfbee16bd`. The whole-operation pilot ran from 03:13:37 to 03:15:40 UTC on 2026-10-12, with two balanced process pairs per cell, two rounds per process, a 100 ms timed-call budget per round, and 100 warmup cycles (200 calls) per process. The [compact result](../../results/bouncycastle/slh-deep/pilot-totals-summary.json) retains every paired statistic; the evidence archive retains all underlying observations. Ratios above one favor the changed implementation.

| Parameter | Operation | Wall ratio | Fork range | Losing forks | Thread CPU ratio |
| --- | --- | ---: | ---: | ---: | ---: |
| SHA2-128f | Key generation | 0.9606 | 0.9388–0.9825 | 2/2 | 0.9631 |
| SHA2-128f | Sign | 0.9747 | 0.9647–0.9846 | 2/2 | 0.9779 |
| SHA2-128f | Verify | 1.0066 | 0.9699–1.0432 | 1/2 | 1.0038 |
| SHAKE-128f | Key generation | 0.9878 | 0.9854–0.9902 | 2/2 | 0.9858 |
| SHAKE-128f | Sign | 1.0506 | 0.9921–1.1092 | 1/2 | 1.0097 |
| SHAKE-128f | Verify | 0.9922 | 0.9830–1.0015 | 1/2 | 0.9836 |

SHA2 key generation/signing and SHAKE key generation lose in both process pairs. The SHAKE signing wall median is driven by a single favorable pair and has much weaker thread-CPU corroboration. This small screen supports neither a general speedup nor a steady-state claim. The compilation traces contain tier transitions and deoptimizations, but the protocol has no warmup-end trace anchor or GC trace; these logs do not identify the cause of any loss or outlier.

The separate eighteen-stage pilot uses 20 warmup calls and 5 ms round budgets and is exploratory. Its original collector rejected a valid sub-microsecond `sign.prf_msg` observation whose current-thread CPU interval quantized to zero. The Java process exited successfully and all output checks passed. The separately versioned `run_v2.py` accepts nonnegative CPU intervals, retains zero observations, validates and reuses every completed process, and records its own hash and the original plan in the recovery plan. Frozen production sources, preparation manifest and original collector are unchanged. All 72 process pairs subsequently completed; no completed sample was discarded or rerun. Collection was paused between Java processes while another experiment used the machine, and the recovery plan and per-process timestamps retain that chronology.

## Whole-operation allocation pilot

The separate allocation screen completed from 03:24:05 to 03:25:55 UTC with two balanced pairs per cell, two rounds, one complete four-key cycle per round and 200 warmup calls per process. It observes current-thread allocated bytes around the same complete operation boundaries; output encoding and correctness checks remain outside those boundaries. The table shows median process summaries and their percentage difference, with exact per-fork values preserved in the result.

| Parameter | Operation | Original bytes/call | Changed bytes/call | Reduction |
| --- | --- | ---: | ---: | ---: |
| SHA2-128f | Key generation | 171,288 | 45,848 | 73.23% |
| SHA2-128f | Sign | 4,096,472 | 1,365,155.5 | 66.67% |
| SHA2-128f | Verify | 273,026 | 104,746 | 61.64% |
| SHAKE-128f | Key generation | 170,792 | 45,352 | 73.45% |
| SHAKE-128f | Sign | 4,086,648 | 1,355,432 | 66.83% |
| SHAKE-128f | Verify | 266,290 | 100,692 | 62.19% |

Allocation decreases substantially in both process pairs for every cell. This is a resource result for these two parameter sets and this runtime, with fresh operation objects and decoded keys; it does not establish peak-heap savings, all-parameter coverage or a latency improvement. The buffer patch remains exploratory because the whole-operation timing screen includes repeatable losses.

## Evidence and reproduction

Compact views retain all per-pair medians, ranges and sample counts: [whole operations](../../results/bouncycastle/slh-deep/pilot-totals-summary.json), [diagnostic stages](../../results/bouncycastle/slh-deep/pilot-stages-summary.json), and [allocated bytes](../../results/bouncycastle/slh-deep/pilot-allocation-summary.json). The [compressed evidence](../../results/bouncycastle/slh-deep/pilot-evidence.tar.gz) preserves exact result JSON, stdout, stderr, commands, statuses, pair records, compilation traces, preparation checks, fixture/source archives and compiled implementation/driver/test classes. Its [inventory](../../results/bouncycastle/slh-deep/pilot-evidence.tar.gz.inventory.json) records a SHA256 and size for every member and the archive itself. Archive member order and metadata are deterministic; original local files are retained unchanged.

The [packaging check](../../results/bouncycastle/slh-deep/packaging-check.json) verified all 6,410 archived files byte-for-byte against local originals, unchanged preparation provenance, and exact production/test commit binding. The 20,071,004-byte archive contains 358,570,476 uncompressed bytes and has SHA256 `eea9e70b7ef95ffffa850ae9cbb80b96f3ade6cfdf89dc8941fce34be0d1d5c9`.

Extract the archive into an empty evidence checkout to recover the original repository-relative paths. The recorded commands and manifests contain absolute paths from the original machine. Replaying those sealed commands requires that path layout and the recorded JDK; a different layout must create a new preparation manifest rather than edit the historical one. The JDK binary and external dependencies are not redistributed. Original source is recoverable from the archived source tar and tracked buffer patch; the compiled snapshots also allow direct verification of the recorded class hashes. Independent verification can use the reconstructed original result/raw paths.

```sh
tar -xzf results/bouncycastle/slh-deep/pilot-evidence.tar.gz
python3 libs/bouncycastle/experiments/slh-deep/run.py \
  --manifest libs/bouncycastle/build/slh-deep/prepared-c8eeabbff5cec835/manifest.json \
  --out results/bouncycastle/slh-deep/reproduced-totals.json \
  --parameters sha2_128f,shake_128f \
  --operations keygen.total,sign.total,verify.total \
  --forks 2 --rounds 2 --budget-ms 100 --warmup-cycles 100 --jit-trace
```

The historical stage recovery uses `run_v2.py`; a fresh stage run should use that collector with the eighteen operation names above, `--budget-ms 5 --warmup-cycles 10`, and a new output path. Allocation uses the original collector with `--mode allocation` and the whole-operation arguments. Never run these workloads concurrently. This two-fork screen is a bounded exploration; wider parameter coverage, the full affected upstream suite and a stronger warmed latency confirmation remain necessary before proposing the buffer implementation upstream.

## Diagnostic stage observations

These stage timings locate expensive regions under the diagnostic protocol; they do not decompose the warmed public-API time. The initial warmup is only 20 calls, stages reuse prepared engine/input state, and unchanged small controls also show large differences. Each ratio is the median of the two original/changed process-pair ratios; every pair and loss remains in the compact result and raw archive.

| Stage | SHA2 original µs | SHA2 ratio | SHAKE original µs | SHAKE ratio |
| --- | ---: | ---: | ---: | ---: |
| `verify.decode` | 40.708 | 0.9968 | 40.714 | 1.0200 |
| `sign.prf_msg` | 5.602 | 0.9992 | 1.764 | 1.0025 |
| `hmsg` | 8.201 | 1.3003 | 2.050 | 0.9945 |
| `fors.indices` | 14.770 | 0.8560 | 26.105 | 1.5222 |
| `verify.fors_leaves` | 14.373 | 0.8479 | 18.626 | 0.6305 |
| `verify.fors_auth` | 110.511 | 0.9642 | 102.817 | 0.9584 |
| `verify.fors_compress` | 4.136 | 0.9554 | 2.466 | 0.9659 |
| `verify.fors` | 166.515 | 0.9919 | 149.451 | 0.9681 |
| `verify.wots_chains` | 2789.474 | 1.0061 | 2095.854 | 1.0023 |
| `verify.wots_compress` | 93.042 | 1.0032 | 50.653 | 0.9871 |
| `verify.wots` | 2611.526 | 0.8893 | 2126.305 | 0.9881 |
| `verify.xmss_auth` | 31.685 | 0.9182 | 28.311 | 0.9611 |
| `verify.hypertree` | 2751.609 | 0.9600 | 2161.599 | 0.9838 |
| `sign.fors` | 2661.453 | 0.9719 | 2358.222 | 0.9661 |
| `sign.wots` | 2777.917 | 0.9010 | 2269.526 | 0.9662 |
| `sign.xmss_auth` | 36409.008 | 1.0183 | 30589.648 | 0.9872 |
| `sign.hypertree` | 40935.479 | 0.9913 | 34902.726 | 0.9868 |
| `sign.serialize` | 10.050 | 1.4180 | 8.152 | 0.6456 |

XMSS authentication-path construction and its nested WOTS leaf generation dominate the large signing regions in this diagnostic screen. Remaining WOTS chains are the large verification region. SHA2 WOTS public-key recovery loses both process pairs (0.8574 and 0.9212), as does SHAKE (0.9830 and 0.9931). WOTS signing also loses both pairs for both hashes. These observations do not support a CPU speedup from the buffer patch. The isolated chain kernel differs in setup and compilation from its inclusive parent; its near-one ratio does not override the parent losses.

A narrowly separated follow-up could place the first allocating hash before the loop and leave only in-place hashes inside it. That would test loop/control-flow overhead while retaining zero-step ownership and existing invalid/negative-length behavior. It is unimplemented and unmeasured here. The separately retained array-stack proposal could reduce treehash allocation, but its post-edit correctness and end-to-end effect remain unverified. Digest/backend changes require a separate portability and provider-architecture review and are excluded from these resource results.
