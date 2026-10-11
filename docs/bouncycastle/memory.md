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
* Stage lines show where the allocation goes inside a verify (expandA and decode for ML-DSA).

<!-- RESULTS -->
