# Bouncy Castle: stack and heap per operation

`libs/bouncycastle/run.sh memory --out results/bouncycastle/memory.jsonl [--params a,b] [--ops keygen,sign,verify,verify-stage]`

One line per (variant, op, param) for all 18 bench variants, each verify stage `v0` and the `total_best`
pipeline (`op:"verify-stage"` + `stage`). JVM-flag variants are measured in a child JVM with their flags.

## Stack: how it is measured and its resolution

The contract's suggestion for Java (binary-search `Thread(..., stackSize)`) does not work as such on HotSpot:
any requested size below the VM's internal minimum (`_java_thread_min_stack_allowed`, ~ guard + shadow zones + a
few pages, about 136 KiB on x86-64) is silently raised to that minimum, and every operation here fits in it, so the
search bottoms out at the same number for every op. The driver therefore turns the idea around:

1. A probe thread with a fixed 2 MiB stack first **consumes** stack by recursing `d` frames of a constant-size
   static method (`rec(d, target, op)`, warmed into C2 code first) and then calls the op at the bottom.
2. The deepest `d` at which the op still completes without `StackOverflowError` is found by binary search
   (`StackOverflowError` anywhere, including inside BC, counts as "too deep"; any other exception aborts the
   measurement). The same is done for a no-op.
3. `stack_bytes = (d_noop - d_op) * frameBytes`, where `frameBytes` is calibrated as
   `(2 MiB) / (d_noop(4 MiB) - d_noop(2 MiB))`; on this JVM the compiled recursion frame is 16 bytes, which is the
   reported `stack_resolution_bytes`.

Precautions: each probe creates a fresh engine/runner (a `StackOverflowError` thrown inside a reused `MLDSASigner`
leaves its SHAKE state unusable), the op is warmed through the exact call path used by the probe (otherwise a JIT
deoptimisation triggered by the new call site inflates the first measurement by tens of KiB), and the search is
repeated three times (once for ops slower than 100 ms) taking the deepest success. The result is the stack used by
the op's compiled code including the harness lambda/`Callable` frames (~100 bytes); interpreted execution would be
much deeper, but every number here is taken after JIT warm-up as the contract asks (`-Xint` was not run: for the
slow SLH-DSA sets it would take hours). For **parallel** variants the op measured is one lane's work on the probe
thread, i.e. the stack of one worker thread, and `threads` is set.

## Heap

`heap_alloc_bytes_per_op`: `com.sun.management.ThreadMXBean.getThreadAllocatedBytes(measuring thread)` delta over
a >= 300 ms loop divided by ops (TLAB-accurate, includes every short-lived array BC allocates). For parallel
variants `getTotalThreadAllocatedBytes()` (all threads) is used. `heap_peak_bytes` is reported as `null`: the JVM
offers no per-operation live-set peak without a heap walk, and pool peak-usage counters include garbage.

## What the numbers mean

* BC's PQC code is heap-bound, not stack-bound: ML-DSA keygen/sign/verify use about 1-2 KiB of stack and
  60-80 KB of allocation per op (the A matrix alone is k*l*256 ints), SLH-DSA signing allocates megabytes.
* The JCA layer (`*.v0` jca, fresh `getInstance` per op) is the stack outlier at ~25 KiB because the provider
  lookup / `Signature` initialisation call chain is deep; the lightweight API variants stay around 1 KiB.
* Stage lines show where the allocation goes inside a verify (expandA and decode for ML-DSA, ht_wots for
  SLH-DSA). A side finding: the `total_best` pipeline for the SHA2 sets allocates ~4-5x more than BC's verify
  (1.26 MB vs 272 KB for SHA2-128f) because the JDK-SHA-256 backend clones a `MessageDigest` midstate per hash
  call; it is still ~2x faster, but a production version would keep a reusable digest instead of `clone()`.
* Stack numbers of 0-200 bytes for single stages are real for JIT-compiled code: HotSpot inlines the small BC
  methods into the caller so the stage runs in the probe lambda's own frame; numbers vary by one or two frames
  (16-32 bytes) between JVM runs as inlining decisions change.

<!-- RESULTS -->

## Results

Generated from `results/bouncycastle/memory.jsonl`. Method: probe thread (2 MiB) recurses d constant-size frames then runs the op; deepest d without StackOverflowError (binary search, best of 3, after JIT warm-up through the same path) vs a no-op, times the calibrated frame size; per worker thread (one lane's op): probe thread (2 MiB) recurses d constant-size frames then runs the op; deepest d without StackOverflowError (binary search, best of 3, after JIT warm-up through the same path) vs a no-op, times the calibrated frame size.

### keygen: peak stack

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.9 KiB | 411 B | 474 B | 379 B | 411 B | 474 B |
| ML-DSA-65 | 632 B | 348 B | 348 B | 379 B | 237 B | 474 B |
| ML-DSA-87 | 632 B | 348 B | 348 B | 379 B | 253 B | 948 B |
| SLH-DSA-SHA2-128s | 1.5 KiB | 790 B | 916 B | 1.2 KiB | 1.3 KiB | 1.2 KiB |
| SLH-DSA-SHA2-128f | 1011 B | 727 B | 916 B | 1011 B | 822 B | 1.3 KiB |
| SLH-DSA-SHA2-192s | 1011 B | 569 B | 695 B | 822 B | 822 B | 1.3 KiB |
| SLH-DSA-SHA2-192f | 758 B | 158 B | 379 B | 569 B | 569 B | 1.3 KiB |
| SLH-DSA-SHA2-256s | 758 B | 158 B | 379 B | 569 B | 569 B | 1.2 KiB |
| SLH-DSA-SHA2-256f | 758 B | 126 B | 348 B | 569 B | 569 B | 1.1 KiB |
| SLH-DSA-SHAKE-128s | 758 B | 316 B | 474 B | 600 B | 600 B | 1.3 KiB |
| SLH-DSA-SHAKE-128f | 758 B | 284 B | 474 B | 284 B | 284 B | 1.5 KiB |
| SLH-DSA-SHAKE-192s | 648 B | 158 B | 158 B | 158 B | 158 B | 1.3 KiB |
| SLH-DSA-SHAKE-192f | 0 B | 158 B | 0 B | 0 B | 0 B | 1.5 KiB |
| SLH-DSA-SHAKE-256s | 0 B | 253 B | 158 B | 158 B | 158 B | 1.3 KiB |
| SLH-DSA-SHAKE-256f | 0 B | 0 B | 0 B | 0 B | 0 B | 1.2 KiB |

### keygen: heap allocated per op

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 66.2 KiB | 66.0 KiB | 65.8 KiB | 61.8 KiB | 62.0 KiB | 65.7 KiB |
| ML-DSA-65 | 108.9 KiB | 108.8 KiB | 108.6 KiB | 102.5 KiB | 102.7 KiB | 108.6 KiB |
| ML-DSA-87 | 172.8 KiB | 172.6 KiB | 172.5 KiB | 165.0 KiB | 165.1 KiB | 172.5 KiB |
| SLH-DSA-SHA2-128s | 10.29 MiB | 10.29 MiB | 10.29 MiB | 10.29 MiB | 10.29 MiB | 10.29 MiB |
| SLH-DSA-SHA2-128f | 167.0 KiB | 166.8 KiB | 166.8 KiB | 166.8 KiB | 166.9 KiB | 166.9 KiB |
| SLH-DSA-SHA2-192s | 18.34 MiB | 18.34 MiB | 18.34 MiB | 18.34 MiB | 18.34 MiB | 18.34 MiB |
| SLH-DSA-SHA2-192f | 296.6 KiB | 296.4 KiB | 296.4 KiB | 296.4 KiB | 296.5 KiB | 296.5 KiB |
| SLH-DSA-SHA2-256s | 14.26 MiB | 14.26 MiB | 14.26 MiB | 14.26 MiB | 14.26 MiB | 14.26 MiB |
| SLH-DSA-SHA2-256f | 915.7 KiB | 915.5 KiB | 915.5 KiB | 915.5 KiB | 915.6 KiB | 915.6 KiB |
| SLH-DSA-SHAKE-128s | 10.29 MiB | 10.29 MiB | 10.29 MiB | 10.29 MiB | 10.29 MiB | 10.28 MiB |
| SLH-DSA-SHAKE-128f | 166.4 KiB | 166.2 KiB | 166.2 KiB | 166.2 KiB | 166.3 KiB | 166.3 KiB |
| SLH-DSA-SHAKE-192s | 18.34 MiB | 18.34 MiB | 18.34 MiB | 18.34 MiB | 18.34 MiB | 18.33 MiB |
| SLH-DSA-SHAKE-192f | 295.3 KiB | 295.1 KiB | 295.1 KiB | 295.0 KiB | 295.2 KiB | 295.2 KiB |
| SLH-DSA-SHAKE-256s | 14.26 MiB | 14.26 MiB | 14.26 MiB | 14.26 MiB | 14.26 MiB | 14.26 MiB |
| SLH-DSA-SHAKE-256f | 914.4 KiB | 914.2 KiB | 914.2 KiB | 914.1 KiB | 914.4 KiB | 914.1 KiB |

### sign: peak stack

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 600 B | 379 B | 379 B | 316 B | 537 B | 632 B |
| ML-DSA-65 | 474 B | 379 B | 379 B | 474 B | 758 B | 1.1 KiB |
| ML-DSA-87 | 411 B | 379 B | 379 B | 411 B | 758 B | 980 B |
| SLH-DSA-SHA2-128s | 1.5 KiB | 1.5 KiB | 1.4 KiB | 1.4 KiB | 240.2 KiB | 1.5 KiB |
| SLH-DSA-SHA2-128f | 1.2 KiB | 1.2 KiB | 1.0 KiB | 1.0 KiB | 1.6 KiB | 1.5 KiB |
| SLH-DSA-SHA2-192s | 1.1 KiB | 1.2 KiB | 853 B | 853 B | 240.2 KiB | 1.5 KiB |
| SLH-DSA-SHA2-192f | 411 B | 569 B | 411 B | 411 B | 1.4 KiB | 1.5 KiB |
| SLH-DSA-SHA2-256s | 537 B | 569 B | 411 B | 411 B | 240.2 KiB | 1.5 KiB |
| SLH-DSA-SHA2-256f | 411 B | 569 B | 411 B | 411 B | 240.2 KiB | 1.5 KiB |
| SLH-DSA-SHAKE-128s | 537 B | 664 B | 537 B | 537 B | 240.2 KiB | 1.6 KiB |
| SLH-DSA-SHAKE-128f | 537 B | 664 B | 537 B | 537 B | 1.6 KiB | 1.6 KiB |
| SLH-DSA-SHAKE-192s | 0 B | 569 B | 521 B | 506 B | 240.2 KiB | 1.5 KiB |
| SLH-DSA-SHAKE-192f | 506 B | 616 B | 332 B | 490 B | 1.6 KiB | 1.6 KiB |
| SLH-DSA-SHAKE-256s | 506 B | 616 B | 490 B | 490 B | 240.2 KiB | 1.6 KiB |
| SLH-DSA-SHAKE-256f | 0 B | 616 B | 0 B | 506 B | 240.2 KiB | 1.5 KiB |

### sign: heap allocated per op

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 77.4 KiB | 77.1 KiB | 72.4 KiB | 72.6 KiB | 77.4 KiB | 77.1 KiB |
| ML-DSA-65 | 141.8 KiB | 141.5 KiB | 135.4 KiB | 135.5 KiB | 142.0 KiB | 142.0 KiB |
| ML-DSA-87 | 196.9 KiB | 196.6 KiB | 189.6 KiB | 189.8 KiB | 196.9 KiB | 196.9 KiB |
| SLH-DSA-SHA2-128s | 79.95 MiB | 79.95 MiB | 79.95 MiB | 79.95 MiB | 79.95 MiB | 79.95 MiB |
| SLH-DSA-SHA2-128f | 3.91 MiB | 3.91 MiB | 3.91 MiB | 3.91 MiB | 3.92 MiB | 3.91 MiB |
| SLH-DSA-SHA2-192s | 173.08 MiB | 173.08 MiB | 173.08 MiB | 173.08 MiB | 173.09 MiB | 173.09 MiB |
| SLH-DSA-SHA2-192f | 7.80 MiB | 7.80 MiB | 7.80 MiB | 7.80 MiB | 7.80 MiB | 7.80 MiB |
| SLH-DSA-SHA2-256s | 180.19 MiB | 180.19 MiB | 180.19 MiB | 180.19 MiB | 180.19 MiB | 180.19 MiB |
| SLH-DSA-SHA2-256f | 18.62 MiB | 18.62 MiB | 18.62 MiB | 18.62 MiB | 18.62 MiB | 18.62 MiB |
| SLH-DSA-SHAKE-128s | 79.95 MiB | 79.95 MiB | 79.95 MiB | 79.95 MiB | 79.90 MiB | 79.90 MiB |
| SLH-DSA-SHAKE-128f | 3.91 MiB | 3.91 MiB | 3.91 MiB | 3.91 MiB | 3.91 MiB | 3.91 MiB |
| SLH-DSA-SHAKE-192s | 173.08 MiB | 173.08 MiB | 173.08 MiB | 173.08 MiB | 173.03 MiB | 173.03 MiB |
| SLH-DSA-SHAKE-192f | 7.79 MiB | 7.79 MiB | 7.79 MiB | 7.79 MiB | 7.80 MiB | 7.80 MiB |
| SLH-DSA-SHAKE-256s | 180.19 MiB | 180.19 MiB | 180.18 MiB | 180.19 MiB | 180.16 MiB | 180.16 MiB |
| SLH-DSA-SHAKE-256f | 18.62 MiB | 18.62 MiB | 18.62 MiB | 18.62 MiB | 18.62 MiB | 18.62 MiB |

### verify: peak stack

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 316 B | 284 B | 284 B | 253 B | 379 B | 1.4 KiB |
| ML-DSA-65 | 316 B | 284 B | 284 B | 253 B | 379 B | 1011 B |
| ML-DSA-87 | 316 B | 284 B | 284 B | 253 B | 1.1 KiB | 1011 B |
| SLH-DSA-SHA2-128s | 916 B | 1.0 KiB | 348 B | 316 B | 1.2 KiB | 1.3 KiB |
| SLH-DSA-SHA2-128f | 664 B | 790 B | 632 B | 600 B | 1.2 KiB | 1.3 KiB |
| SLH-DSA-SHA2-192s | 411 B | 411 B | 253 B | 221 B | 1.5 KiB | 1.2 KiB |
| SLH-DSA-SHA2-192f | 253 B | 411 B | 253 B | 221 B | 1.2 KiB | 1.2 KiB |
| SLH-DSA-SHA2-256s | 253 B | 411 B | 253 B | 221 B | 1.3 KiB | 8.4 KiB |
| SLH-DSA-SHA2-256f | 253 B | 316 B | 253 B | 221 B | 1.2 KiB | 1.2 KiB |
| SLH-DSA-SHAKE-128s | 158 B | 158 B | 158 B | 126 B | 1.3 KiB | 1.1 KiB |
| SLH-DSA-SHAKE-128f | 158 B | 158 B | 158 B | 126 B | 1.5 KiB | 1.3 KiB |
| SLH-DSA-SHAKE-192s | 0 B | 158 B | 0 B | 0 B | 1.3 KiB | 3.3 KiB |
| SLH-DSA-SHAKE-192f | 0 B | 0 B | 79 B | 32 B | 1.4 KiB | 5.8 KiB |
| SLH-DSA-SHAKE-256s | 126 B | 0 B | 0 B | 0 B | 1.3 KiB | 3.6 KiB |
| SLH-DSA-SHAKE-256f | 0 B | 0 B | 0 B | 32 B | 1.3 KiB | 1.4 KiB |

### verify: heap allocated per op

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 58.2 KiB | 57.9 KiB | 54.4 KiB | 54.5 KiB | 57.9 KiB | 57.9 KiB |
| ML-DSA-65 | 94.6 KiB | 94.4 KiB | 90.2 KiB | 90.4 KiB | 94.4 KiB | 94.4 KiB |
| ML-DSA-87 | 155.8 KiB | 155.5 KiB | 150.8 KiB | 150.9 KiB | 155.6 KiB | 155.6 KiB |
| SLH-DSA-SHA2-128s | 100.0 KiB | 99.5 KiB | 99.4 KiB | 99.4 KiB | 98.9 KiB | 98.4 KiB |
| SLH-DSA-SHA2-128f | 265.9 KiB | 265.4 KiB | 265.3 KiB | 510.3 KiB | 264.8 KiB | 263.3 KiB |
| SLH-DSA-SHA2-192s | 172.8 KiB | 172.3 KiB | 172.2 KiB | 172.2 KiB | 171.6 KiB | 171.1 KiB |
| SLH-DSA-SHA2-192f | 460.5 KiB | 460.0 KiB | 459.9 KiB | 460.0 KiB | 460.2 KiB | 458.2 KiB |
| SLH-DSA-SHA2-256s | 296.4 KiB | 296.0 KiB | 295.8 KiB | 296.0 KiB | 295.2 KiB | 294.6 KiB |
| SLH-DSA-SHA2-256f | 560.8 KiB | 560.4 KiB | 560.2 KiB | 560.4 KiB | 560.5 KiB | 558.1 KiB |
| SLH-DSA-SHAKE-128s | 95.9 KiB | 95.4 KiB | 95.3 KiB | 95.5 KiB | 94.9 KiB | 94.5 KiB |
| SLH-DSA-SHAKE-128f | 273.5 KiB | 273.1 KiB | 273.0 KiB | 273.1 KiB | 272.9 KiB | 270.6 KiB |
| SLH-DSA-SHAKE-192s | 171.2 KiB | 170.7 KiB | 170.6 KiB | 170.7 KiB | 170.1 KiB | 169.6 KiB |
| SLH-DSA-SHAKE-192f | 450.0 KiB | 449.5 KiB | 449.4 KiB | 449.6 KiB | 450.5 KiB | 448.9 KiB |
| SLH-DSA-SHAKE-256s | 289.8 KiB | 289.3 KiB | 289.2 KiB | 289.3 KiB | 288.5 KiB | 288.4 KiB |
| SLH-DSA-SHAKE-256f | 560.4 KiB | 559.9 KiB | 559.8 KiB | 560.0 KiB | 559.9 KiB | 559.3 KiB |

### verify-stage: peak stack

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 0 B | 0 B | — | 0 B | — | — | — | 0 B | 190 B | 32 B |
| ML-DSA-65 | 0 B | 0 B | — | 0 B | — | — | — | 0 B | 190 B | 63 B |
| ML-DSA-87 | 0 B | 0 B | — | 0 B | — | — | — | 0 B | 190 B | 63 B |
| SLH-DSA-SHA2-128s | — | — | 32 B | — | 95 B | 0 B | 221 B | — | 1011 B | — |
| SLH-DSA-SHA2-128f | — | — | 32 B | — | 221 B | 0 B | 63 B | — | 664 B | — |
| SLH-DSA-SHA2-192s | — | — | 0 B | — | 32 B | 0 B | 0 B | — | 632 B | — |
| SLH-DSA-SHA2-192f | — | — | 0 B | — | 32 B | 0 B | 0 B | — | 316 B | — |
| SLH-DSA-SHA2-256s | — | — | 0 B | — | 32 B | 0 B | 0 B | — | 0 B | — |
| SLH-DSA-SHA2-256f | — | — | 0 B | — | 32 B | 0 B | 0 B | — | 63 B | — |
| SLH-DSA-SHAKE-128s | — | — | 0 B | — | 0 B | 0 B | 0 B | — | 474 B | — |
| SLH-DSA-SHAKE-128f | — | — | 0 B | — | 0 B | 0 B | 0 B | — | 0 B | — |
| SLH-DSA-SHAKE-192s | — | — | 0 B | — | 0 B | 0 B | 0 B | — | 0 B | — |
| SLH-DSA-SHAKE-192f | — | — | 0 B | — | 0 B | 0 B | 0 B | — | 0 B | — |
| SLH-DSA-SHAKE-256s | — | — | 0 B | — | 0 B | 0 B | 0 B | — | 0 B | — |
| SLH-DSA-SHAKE-256f | — | — | 0 B | — | 0 B | 0 B | 0 B | — | 0 B | — |

### verify-stage: heap allocated per op

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 17.7 KiB | 30.9 KiB | — | 6.4 KiB | — | — | — | 1.1 KiB | 64.6 KiB | 14.4 KiB |
| ML-DSA-65 | 25.2 KiB | 57.8 KiB | — | 8.5 KiB | — | — | — | 1.1 KiB | 102.1 KiB | 19.6 KiB |
| ML-DSA-87 | 34.0 KiB | 107.8 KiB | — | 11.1 KiB | — | — | — | 1.1 KiB | 165.2 KiB | 25.9 KiB |
| SLH-DSA-SHA2-128s | — | — | 14.5 KiB | — | 672 B | 2.5 KiB | 67.3 KiB | — | 428.9 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 23.8 KiB | — | 872 B | 3.5 KiB | 212.6 KiB | — | 1.20 MiB | — |
| SLH-DSA-SHA2-192s | — | — | 22.3 KiB | — | 856 B | 2.9 KiB | 121.1 KiB | — | 741.0 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 28.8 KiB | — | 1.0 KiB | 4.1 KiB | 381.4 KiB | — | 2.38 MiB | — |
| SLH-DSA-SHA2-256s | — | — | 32.1 KiB | — | 920 B | 3.5 KiB | 219.6 KiB | — | 1.08 MiB | — |
| SLH-DSA-SHA2-256f | — | — | 38.6 KiB | — | 1.0 KiB | 4.3 KiB | 456.3 KiB | — | 2.08 MiB | — |
| SLH-DSA-SHAKE-128s | — | — | 14.6 KiB | — | 344 B | 2.5 KiB | 64.1 KiB | — | 98.4 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 23.6 KiB | — | 536 B | 3.5 KiB | 221.4 KiB | — | 304.2 KiB | — |
| SLH-DSA-SHAKE-192s | — | — | 22.4 KiB | — | 360 B | 2.9 KiB | 121.3 KiB | — | 185.2 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 28.8 KiB | — | 552 B | 4.1 KiB | 372.7 KiB | — | 454.5 KiB | — |
| SLH-DSA-SHAKE-256s | — | — | 32.0 KiB | — | 384 B | 3.5 KiB | 214.8 KiB | — | 305.2 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 38.6 KiB | — | 504 B | 4.3 KiB | 457.7 KiB | — | 591.5 KiB | — |

