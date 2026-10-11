# noble — stack and heap per operation

`libs/noble/run.sh memory --out results/noble/memory.jsonl [--params a,b] [--variants id,id] [--no-stages] [--no-heap]`

One line per (variant, op, param) for all 18 bench variants, plus `op:"verify-stage"` lines for every
stage `v0` and for `total.v0` / `total_best.v0`.

## Stack — how it is measured

JavaScript gives no access to the stack pointer, and the process-level approach (`node --stack-size=N`
binary search) turned out too coarse for this library: Node needs ≈ 50–64 KiB of V8 stack just to
load the ES modules, and every noble operation fits in the slack left over at 64 KiB, so the
subprocess search cannot resolve the op at all. The harness therefore measures *inside* the process
(`src/mem-one.mjs`):

1. A probe function recurses to a chosen depth and then calls the operation. The largest depth at
   which the op still completes (`dOp`, binary search catching `RangeError: Maximum call stack size
   exceeded`) is compared with the largest depth at which an empty call completes (`dNoop`).
   `stack_bytes = (dNoop − dOp) × frame_bytes`.
2. `frame_bytes` of the probe is calibrated per runtime by running the probe to overflow at two
   known stack sizes (`node --stack-size=512/1024`; for Bun `ulimit -s 1024/2048`, since JSC derives
   its limit from the thread's stack): 104 B on V8, 112 B on JSC.
3. JIT tiers change frame sizes, so the op is warmed up (25 ops) and the probe is warmed before
   measuring, and `(dNoop, dOp, dNoop)` is re-measured until two consecutive rounds agree within one
   search step. The search step is 4 frames → `stack_resolution_bytes` ≈ 416–448 B.
4. Worker variants (`*.v5`) run the whole measurement inside one `worker_thread`
   (`--in-worker`), so the number is per worker. Bun variants run under Bun.

The result is the stack *of the operation on top of the caller*, as seen by the JS engine (JS
frames + the native frames V8/JSC push for builtins such as typed-array `set`/`slice`). Noble's
code is iterative everywhere (no recursion in NTT, Keccak or the hash trees), so the numbers are a
few KiB and nearly independent of the parameter set.

## Heap

Node only (`--expose-gc`, V8 inspector): `heap_alloc_bytes_per_op` is the allocation volume of one
op from the V8 sampling heap profiler (256-byte sampling interval, 10 ops, including objects already
collected) — a statistical estimate, accurate to a few percent for ops that allocate ≥ 100 KB;
`heap_peak_bytes` is `heapUsed` right after one op (after a forced `gc()` before it) minus the value
before, i.e. live objects plus not-yet-collected garbage at the end of the op — an upper bound of
the live peak unless a GC ran during the op (large SLH-DSA signatures). Bun exposes neither API,
so its lines carry `null` (documented limitation).

## What to expect

* Stack: ≈ 1.5–2.5 KiB for all keygen/sign/verify variants (call depth ≈ 6–10 JS frames); the
  fast rewrites are a little lower (fewer nested helper calls); Bun frames differ slightly from V8.
* Heap: the baseline allocates generously (new polynomial per `MultiplyNTTs`, per-hash output
  arrays, `setAddr` option objects): ≈ 150 KB per ML-DSA-44 signature, several MB per SLH-DSA "f"
  signature. The fast rewrites and the cache variants allocate less (fused accumulators, in-place
  hashing, cached expanded keys).

<!-- RESULTS -->

## Results

Generated from `results/noble/memory.jsonl`. Method: in-process recursion probe: max probe depth with vs. without the op (binary search, JIT-warmed), times the calibrated frame size (104 B from two known stack sizes); in-process recursion probe: max probe depth with vs. without the op (binary search, JIT-warmed), times the calibrated frame size (83 B from two known stack sizes); in-process recursion probe: max probe depth with vs. without the op (binary search, JIT-warmed), times the calibrated frame size (104 B from two known stack sizes); measured inside one worker_thread; in-process recursion probe: max probe depth with vs. without the op (binary search, JIT-warmed), times the calibrated frame size (112 B from two known stack sizes).

### keygen: peak stack

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.9 KiB | 1.9 KiB | 1.9 KiB | 1.9 KiB | 1.1 KiB | 1.9 KiB |
| ML-DSA-65 | 1.9 KiB | 1.9 KiB | 1.9 KiB | 1.9 KiB | 1.2 KiB | 1.9 KiB |
| ML-DSA-87 | 1.9 KiB | 1.9 KiB | 1.9 KiB | 1.9 KiB | 1.1 KiB | 1.9 KiB |
| SLH-DSA-SHA2-128s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHA2-128f | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 1.2 KiB | 2.2 KiB |
| SLH-DSA-SHA2-192s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHA2-192f | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 1.5 KiB | 2.2 KiB |
| SLH-DSA-SHA2-256s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHA2-256f | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 1.5 KiB | 2.2 KiB |
| SLH-DSA-SHAKE-128s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-128f | 2.2 KiB | 2.4 KiB | 2.4 KiB | 2.4 KiB | 1.1 KiB | 2.2 KiB |
| SLH-DSA-SHAKE-192s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-192f | 2.4 KiB | 2.4 KiB | 2.4 KiB | 2.4 KiB | 1.1 KiB | 2.2 KiB |
| SLH-DSA-SHAKE-256s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-256f | 2.2 KiB | 2.2 KiB | 2.4 KiB | 2.4 KiB | 1.1 KiB | 2.2 KiB |
| Falcon-512 | 4.2 KiB | 4.2 KiB | — | — | 3.2 KiB | 4.2 KiB |
| Falcon-1024 | 4.4 KiB | 4.2 KiB | — | — | 3.2 KiB | 4.4 KiB |

### keygen: heap allocated per op

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 53.2 KiB | 54.3 KiB | 63.2 KiB | 66.4 KiB | — | 56.5 KiB |
| ML-DSA-65 | 80.7 KiB | 82.7 KiB | 93.5 KiB | 92.7 KiB | — | 79.9 KiB |
| ML-DSA-87 | 126.8 KiB | 125.3 KiB | 129.0 KiB | 132.5 KiB | — | 124.5 KiB |
| SLH-DSA-SHA2-128s | 67.99 MiB | — | — | — | — | — |
| SLH-DSA-SHA2-128f | 1.07 MiB | 1.09 MiB | 398.8 KiB | 396.6 KiB | — | 1.08 MiB |
| SLH-DSA-SHA2-192s | 101.84 MiB | — | — | — | — | — |
| SLH-DSA-SHA2-192f | 1.61 MiB | 1.61 MiB | 621.4 KiB | 642.4 KiB | — | 1.62 MiB |
| SLH-DSA-SHA2-256s | 67.31 MiB | — | — | — | — | — |
| SLH-DSA-SHA2-256f | 4.23 MiB | 4.21 MiB | 1.57 MiB | 1.58 MiB | — | 4.23 MiB |
| SLH-DSA-SHAKE-128s | 36.74 MiB | — | — | — | — | — |
| SLH-DSA-SHAKE-128f | 600.4 KiB | 618.2 KiB | 12.2 KiB | 12.0 KiB | — | 601.4 KiB |
| SLH-DSA-SHAKE-192s | 53.41 MiB | — | — | — | — | — |
| SLH-DSA-SHAKE-192f | 865.1 KiB | 868.4 KiB | 11.4 KiB | 12.9 KiB | — | 870.3 KiB |
| SLH-DSA-SHAKE-256s | 35.05 MiB | — | — | — | — | — |
| SLH-DSA-SHAKE-256f | 2.21 MiB | 2.21 MiB | 12.7 KiB | 12.4 KiB | — | 2.20 MiB |
| Falcon-512 | 178.37 MiB | 178.33 MiB | — | — | — | 178.86 MiB |
| Falcon-1024 | — | — | — | — | — | — |

### sign: peak stack

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.3 KiB | 2.2 KiB |
| ML-DSA-65 | 1.9 KiB | 1.9 KiB | 1.9 KiB | 1.9 KiB | 2.0 KiB | 1.9 KiB |
| ML-DSA-87 | 2.2 KiB | 2.2 KiB | 1.9 KiB | 1.9 KiB | 1.5 KiB | 2.2 KiB |
| SLH-DSA-SHA2-128f | 2.4 KiB | 2.7 KiB | 2.7 KiB | 2.4 KiB | 2.0 KiB | 2.4 KiB |
| SLH-DSA-SHA2-192f | 2.4 KiB | 2.7 KiB | 2.7 KiB | 2.7 KiB | 3.0 KiB | 2.4 KiB |
| SLH-DSA-SHA2-256f | 2.4 KiB | 2.7 KiB | 2.7 KiB | 2.7 KiB | 2.0 KiB | 2.4 KiB |
| SLH-DSA-SHAKE-128f | 2.7 KiB | 2.7 KiB | 2.4 KiB | 2.2 KiB | 2.0 KiB | 2.7 KiB |
| SLH-DSA-SHAKE-192f | 2.7 KiB | 2.7 KiB | 2.4 KiB | 2.2 KiB | 2.0 KiB | 2.7 KiB |
| SLH-DSA-SHAKE-256f | 2.7 KiB | 2.7 KiB | 2.4 KiB | 2.2 KiB | 2.0 KiB | 2.7 KiB |
| Falcon-512 | 4.9 KiB | 4.7 KiB | — | 4.9 KiB | 7.5 KiB | 4.7 KiB |
| Falcon-1024 | 5.2 KiB | 4.9 KiB | — | 5.2 KiB | 7.2 KiB | 5.2 KiB |

### sign: heap allocated per op

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 145.3 KiB | 146.4 KiB | 39.7 KiB | 116.5 KiB | — | 143.2 KiB |
| ML-DSA-65 | 650.9 KiB | 662.4 KiB | 99.8 KiB | 616.1 KiB | — | 657.7 KiB |
| ML-DSA-87 | 416.7 KiB | 414.0 KiB | 91.7 KiB | 325.8 KiB | — | 417.5 KiB |
| SLH-DSA-SHA2-128f | 25.41 MiB | 22.49 MiB | 8.85 MiB | 21.60 MiB | — | 22.44 MiB |
| SLH-DSA-SHA2-192f | 47.24 MiB | 47.21 MiB | 18.32 MiB | 45.70 MiB | — | 64.86 MiB |
| SLH-DSA-SHA2-256f | 97.09 MiB | 97.16 MiB | 38.01 MiB | 93.04 MiB | — | 97.06 MiB |
| SLH-DSA-SHAKE-128f | 14.18 MiB | 14.21 MiB | 146.7 KiB | 13.64 MiB | — | 14.19 MiB |
| SLH-DSA-SHAKE-192f | 23.87 MiB | 23.94 MiB | 142.6 KiB | 23.08 MiB | — | 23.91 MiB |
| SLH-DSA-SHAKE-256f | 48.62 MiB | 48.73 MiB | 145.9 KiB | 46.53 MiB | — | 48.66 MiB |
| Falcon-512 | 6.65 MiB | 6.64 MiB | — | 5.43 MiB | — | 6.65 MiB |
| Falcon-1024 | 14.31 MiB | 14.05 MiB | — | 11.60 MiB | — | 14.29 MiB |

### verify: peak stack

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 1.6 KiB | 2.2 KiB |
| ML-DSA-65 | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 1008 B | 2.2 KiB |
| ML-DSA-87 | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 1.6 KiB | 2.2 KiB |
| SLH-DSA-SHA2-128s | 2.4 KiB | — | — | — | — | — |
| SLH-DSA-SHA2-128f | 2.4 KiB | 2.7 KiB | 2.4 KiB | 2.7 KiB | 2.0 KiB | 2.4 KiB |
| SLH-DSA-SHA2-192s | 2.7 KiB | — | — | — | — | — |
| SLH-DSA-SHA2-192f | 2.7 KiB | 2.7 KiB | 2.4 KiB | 2.7 KiB | 2.6 KiB | 2.4 KiB |
| SLH-DSA-SHA2-256s | 2.7 KiB | — | — | — | — | — |
| SLH-DSA-SHA2-256f | 2.4 KiB | 2.7 KiB | 2.4 KiB | 2.7 KiB | 2.3 KiB | 2.4 KiB |
| SLH-DSA-SHAKE-128s | 1.9 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-128f | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.0 KiB | 2.2 KiB |
| SLH-DSA-SHAKE-192s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-192f | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.0 KiB | 2.2 KiB |
| SLH-DSA-SHAKE-256s | 2.2 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-256f | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.0 KiB | 2.2 KiB |
| Falcon-512 | 1.3 KiB | 1.3 KiB | — | 1.3 KiB | 1008 B | 1.3 KiB |
| Falcon-1024 | 1.3 KiB | 1.3 KiB | — | 1.3 KiB | 560 B | 1.3 KiB |

### verify: heap allocated per op

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 93.1 KiB | 95.4 KiB | 153.5 KiB | 63.2 KiB | — | 92.2 KiB |
| ML-DSA-65 | 135.0 KiB | 129.9 KiB | 221.5 KiB | 89.3 KiB | — | 140.4 KiB |
| ML-DSA-87 | 192.3 KiB | 194.3 KiB | 240.5 KiB | 115.9 KiB | — | 193.7 KiB |
| SLH-DSA-SHA2-128s | 764.7 KiB | — | — | — | — | — |
| SLH-DSA-SHA2-128f | 2.14 MiB | 2.13 MiB | 665.6 KiB | 2.04 MiB | — | 2.13 MiB |
| SLH-DSA-SHA2-192s | 1.66 MiB | — | — | — | — | — |
| SLH-DSA-SHA2-192f | 3.61 MiB | 3.49 MiB | 1.12 MiB | 3.42 MiB | — | 4.58 MiB |
| SLH-DSA-SHA2-256s | 1.99 MiB | — | — | — | — | — |
| SLH-DSA-SHA2-256f | 3.53 MiB | 3.53 MiB | 1.15 MiB | 3.47 MiB | — | 3.62 MiB |
| SLH-DSA-SHAKE-128s | 569.1 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-128f | 1.63 MiB | 1.63 MiB | 112.3 KiB | 1.61 MiB | — | 1.61 MiB |
| SLH-DSA-SHAKE-192s | 790.1 KiB | — | — | — | — | — |
| SLH-DSA-SHAKE-192f | 2.16 MiB | 2.16 MiB | 112.7 KiB | 2.11 MiB | — | 2.15 MiB |
| SLH-DSA-SHAKE-256s | 1.11 MiB | — | — | — | — | — |
| SLH-DSA-SHAKE-256f | 2.20 MiB | 2.21 MiB | 99.5 KiB | 2.18 MiB | — | 2.20 MiB |
| Falcon-512 | 266.3 KiB | 270.2 KiB | — | 267.4 KiB | — | 263.2 KiB |
| Falcon-1024 | 519.7 KiB | 524.7 KiB | — | 519.6 KiB | — | 520.3 KiB |

### verify-stage: peak stack

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total.v0` | `total_best.v0` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.3 KiB | 1.5 KiB | — | 1.5 KiB | — | — | — | 1.5 KiB | 1.9 KiB | 1.9 KiB | 1.3 KiB |
| ML-DSA-65 | 1.3 KiB | 1.3 KiB | — | 1.5 KiB | — | — | — | 1.5 KiB | 1.9 KiB | 1.9 KiB | 1.5 KiB |
| ML-DSA-87 | 1.3 KiB | 1.3 KiB | — | 1.5 KiB | — | — | — | 1.5 KiB | 1.9 KiB | 1.9 KiB | 1.3 KiB |
| SLH-DSA-SHA2-128f | — | — | 1.9 KiB | — | 1.9 KiB | 1.5 KiB | 1.9 KiB | — | 2.2 KiB | 2.2 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 1.9 KiB | — | 2.2 KiB | 1.9 KiB | 1.9 KiB | — | 2.2 KiB | 2.2 KiB | — |
| SLH-DSA-SHA2-256f | — | — | 1.9 KiB | — | 2.2 KiB | 1.9 KiB | 1.9 KiB | — | 2.2 KiB | 2.2 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 1.9 KiB | — | 1.5 KiB | 1.9 KiB | 1.9 KiB | — | 1.9 KiB | 1.9 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 1.9 KiB | — | 1.5 KiB | 1.9 KiB | 1.9 KiB | — | 1.9 KiB | 1.9 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 1.9 KiB | — | 1.5 KiB | 1.9 KiB | 1.9 KiB | — | 1.9 KiB | 1.9 KiB | — |

### verify-stage: heap allocated per op

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total.v0` | `total_best.v0` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 9.9 KiB | 27.2 KiB | — | 49.6 KiB | — | — | — | 11.6 KiB | 87.8 KiB | 26.8 KiB | 10.5 KiB |
| ML-DSA-65 | 9.1 KiB | 46.8 KiB | — | 72.3 KiB | — | — | — | 13.0 KiB | 135.2 KiB | 42.8 KiB | 13.2 KiB |
| ML-DSA-87 | 11.6 KiB | 84.4 KiB | — | 95.7 KiB | — | — | — | 16.3 KiB | 199.5 KiB | 61.6 KiB | 19.8 KiB |
| SLH-DSA-SHA2-128f | — | — | 93.8 KiB | — | 49.6 KiB | 53.0 KiB | 1.91 MiB | — | 2.08 MiB | 683.3 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 259.4 KiB | — | 51.9 KiB | 83.6 KiB | 3.09 MiB | — | 3.46 MiB | 1.14 MiB | — |
| SLH-DSA-SHA2-256f | — | — | 302.8 KiB | — | 49.7 KiB | 80.1 KiB | 3.11 MiB | — | 3.53 MiB | 1.18 MiB | — |
| SLH-DSA-SHAKE-128f | — | — | 77.7 KiB | — | 45.6 KiB | 49.8 KiB | 1.49 MiB | — | 1.64 MiB | 145.9 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 96.8 KiB | — | 46.6 KiB | 47.4 KiB | 2.00 MiB | — | 2.18 MiB | 146.1 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 110.6 KiB | — | 43.9 KiB | 42.6 KiB | 2.04 MiB | — | 2.21 MiB | 126.0 KiB | — |

