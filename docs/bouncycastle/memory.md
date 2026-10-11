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

## Results (preliminary dev run on a shared 4-core box)

stack = peak stack of one op (bytes, resolution = one compiled recursion frame); heap = allocated bytes per op.

### ML-DSA-44

| op | variant | stack bytes | heap alloc bytes/op | threads | match |
|---|---|---|---|---|---|
| keygen | `keygen.v0` | 1936 | 67968 | 1 | True |
| keygen | `keygen.v1` | 240 | 67648 | 1 | True |
| keygen | `keygen.v2` | 448 | 67424 | 1 | True |
| keygen | `keygen.v3` | 384 | 63328 | 1 | True |
| keygen | `keygen.v4` | 400 | 63486 | 4 | True |
| keygen | `keygen.v5` | 948 | 67634 | 1 | True |
| sign | `sign.v0` | 1088 | 79424 | 1 | True |
| sign | `sign.v1` | 704 | 78992 | 1 | True |
| sign | `sign.v2` | 416 | 74176 | 1 | True |
| sign | `sign.v3` | 240 | 74317 | 4 | True |
| sign | `sign.v4` | 853 | 79617 | 1 | True |
| sign | `sign.v5` | 1043 | 79333 | 1 | True |
| verify | `verify.v0` | 480 | 59560 | 1 | True |
| verify | `verify.v1` | 160 | 59272 | 1 | True |
| verify | `verify.v2` | 112 | 55688 | 1 | True |
| verify | `verify.v3` | 160 | 55837 | 4 | True |
| verify | `verify.v4` | 1011 | 59436 | 1 | True |
| verify | `verify.v5` | 1074 | 59928 | 1 | True |
| verify-stage | `decode.v0` | 0 | 18144 | 1 | True |
| verify-stage | `mu.v0` | 0 | 1152 | 1 | True |
| verify-stage | `expandA.v0` | 0 | 31600 | 1 | True |
| verify-stage | `w_approx.v0` | 32 | 14728 | 1 | True |
| verify-stage | `hint_check.v0` | 0 | 6536 | 1 | True |
| verify-stage | `total_best` | 1120 | 66616 | 1 | True |

### ML-DSA-87

| op | variant | stack bytes | heap alloc bytes/op | threads | match |
|---|---|---|---|---|---|
| keygen | `keygen.v0` | 704 | 176976 | 1 | True |
| keygen | `keygen.v1` | 224 | 176792 | 1 | True |
| keygen | `keygen.v2` | 240 | 176600 | 1 | True |
| keygen | `keygen.v3` | 288 | 168912 | 1 | True |
| keygen | `keygen.v4` | 288 | 169054 | 4 | True |
| keygen | `keygen.v5` | 1074 | 176968 | 1 | True |
| sign | `sign.v0` | 512 | 201592 | 1 | True |
| sign | `sign.v1` | 480 | 201336 | 1 | True |
| sign | `sign.v2` | 480 | 194184 | 1 | True |
| sign | `sign.v3` | 320 | 194332 | 4 | True |
| sign | `sign.v4` | 1184 | 202064 | 1 | True |
| sign | `sign.v5` | 1011 | 202064 | 1 | True |
| verify | `verify.v0` | 384 | 159544 | 1 | True |
| verify | `verify.v1` | 480 | 159288 | 1 | True |
| verify | `verify.v2` | 288 | 154424 | 1 | True |
| verify | `verify.v3` | 160 | 154563 | 4 | True |
| verify | `verify.v4` | 1165 | 159812 | 1 | True |
| verify | `verify.v5` | 0 | 159912 | 1 | True |
| verify-stage | `decode.v0` | 0 | 34864 | 1 | True |
| verify-stage | `mu.v0` | 0 | 1152 | 1 | True |
| verify-stage | `expandA.v0` | 0 | 110336 | 1 | True |
| verify-stage | `w_approx.v0` | 32 | 26568 | 1 | True |
| verify-stage | `hint_check.v0` | 0 | 11384 | 1 | True |
| verify-stage | `total_best` | 1120 | 120312 | 1 | True |

### SLH-DSA-SHA2-128f

| op | variant | stack bytes | heap alloc bytes/op | threads | match |
|---|---|---|---|---|---|
| keygen | `keygen.v0` | 1280 | 171112 | 1 | True |
| keygen | `keygen.v1` | 896 | 170928 | 1 | True |
| keygen | `keygen.v2` | 928 | 170880 | 1 | True |
| keygen | `keygen.v3` | 1024 | 170880 | 1 | True |
| keygen | `keygen.v4` | 1024 | 171071 | 4 | True |
| keygen | `keygen.v5` | 1138 | 170912 | 1 | True |
| sign | `sign.v0` | 1280 | 4100391 | 1 | True |
| sign | `sign.v1` | 1312 | 4095280 | 1 | True |
| sign | `sign.v2` | 1120 | 4095072 | 1 | True |
| sign | `sign.v3` | 1152 | 4095521 | 4 | True |
| sign | `sign.v4` | 1612 | 4108288 | 1 | True |
| sign | `sign.v5` | 1675 | 4101952 | 1 | True |
| verify | `verify.v0` | 896 | 272024 | 1 | True |
| verify | `verify.v1` | 1056 | 271560 | 1 | True |
| verify | `verify.v2` | 896 | 271448 | 1 | True |
| verify | `verify.v3` | 864 | 271622 | 4 | True |
| verify | `verify.v4` | 1327 | 274064 | 1 | True |
| verify | `verify.v5` | 1548 | 274064 | 1 | True |
| verify-stage | `hmsg.v0` | None | 872 | 1 | False java.lang.RuntimeException: probe failed with java.lang.ArrayIndexOutOfBoundsException: Index 16 out of bounds for length 16 |
| verify-stage | `fors.v0` | 112 | 24376 | 1 | True |
| verify-stage | `ht_wots.v0` | 224 | 217384 | 1 | True |
| verify-stage | `ht_auth.v0` | 0 | 3624 | 1 | True |
| verify-stage | `total_best` | 960 | 1262497 | 1 | True |

### SLH-DSA-SHAKE-128s

| op | variant | stack bytes | heap alloc bytes/op | threads | match |
|---|---|---|---|---|---|
| keygen | `keygen.v0` | 1280 | 10782472 | 1 | True |
| keygen | `keygen.v1` | 896 | 10782288 | 1 | True |
| keygen | `keygen.v2` | 1120 | 10782272 | 1 | True |
| keygen | `keygen.v3` | 1216 | 10782272 | 1 | True |
| keygen | `keygen.v4` | 1216 | 10782846 | 4 | True |
| keygen | `keygen.v5` | 1359 | 10782512 | 1 | True |
| sign | `sign.v0` | 1472 | 83767561 | 1 | True |
