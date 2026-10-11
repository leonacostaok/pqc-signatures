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
