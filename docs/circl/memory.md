# CIRCL: stack and heap per operation (Phase 2 C)

`libs/circl/run.sh memory --out results/circl/memory.jsonl [--params a,b]`

## How it is measured

**Stack (goroutine stack high-water mark, "paint and scan").** Go stacks are growable and relocated by
copying, so the op is run on a dedicated goroutine whose stack is first grown to ~4 MiB by a recursion with
1 KiB frames (`growStack`), which returns the address of its deepest frame. Back at the top, a tiny probe
function returns an address just below the measuring frame; the region between the two addresses is the
free stack the op will use. It is painted with `0xA5` through `unsafe.Slice`, the op is called, and the region
is scanned for the lowest overwritten byte; `stack_bytes` = painted top - lowest overwritten address, minimum
of three runs, minus the empty-op baseline (0 bytes: the call itself fits in the dead probe frame).
Preconditions: GC is disabled for the whole `memory` run (no stack shrinking, no GC-triggered copies),
`run.sh` sets `GODEBUG=asyncpreemptoff=1` so no `asyncPreempt` register-save frame is pushed onto the
painted region, and the probe address is re-checked after the op: if the stack had been copied (op needed
more than 4 MiB) the value is reported as `null` (never happened). `stack_resolution_bytes` = 64: the
granularity of the scan is one byte, but writes inside the probe's own ~64-byte dead frame directly below
the measuring frame are not visible, and the figure includes the frames of the harness closure (`singleOp`)
and of the library's public wrapper, i.e. a few tens of bytes of harness overhead.

For the parallel variants (`*.v5`) the per-worker closure (one op, pre-unpacked key) is measured and
`threads` = 4. `gc-off` is measured like the baseline (GC is off for everyone here). Verify stages are
measured for each `<stage>.v0` and for `total_best` (`op: "verify-stage"`, `stage` set).

**Heap.** `heap_alloc_bytes_per_op` = `runtime.MemStats.TotalAlloc` delta over n ops (n = 5, or 1 for the
multi-second SLH-DSA "s" signatures) divided by n; `heap_peak_bytes` = `HeapAlloc` growth over a single op
with GC disabled, which equals the op's total allocation and is therefore an upper bound of the peak live
heap (Go cannot report peak live heap without a GC cycle). Both exclude the untimed setup (key unpacking
for `v1`/`v5`, the per-key caches of `total_best`).

Every line's `match` is re-checked against `common/reference.json` (or the stage's v0 canonical output,
or for `total_best` "true on the reference and false on a flipped bit").

## Findings (development run: ML-DSA-44/87, SLH-DSA-SHA2-128f, SHAKE-128f)

- **ML-DSA stack** is dominated by the vectors the functions keep as locals: `SignTo` needs 45 KB (44) / 84 KB
  (87) (y, w, w0, w1, ct0 ... are `VecK`/`VecL` locals of 1 KB per polynomial); `Verify` 29 KB / 52 KB; keygen
  8.5 KB / 14 KB (the `PrivateKey` with its 16-56 KB matrix is heap-allocated by `NewKeyFromSeed`). The build
  flavor changes nothing meaningful (purego is ~1 KB lower: fewer AVX2 call frames).
- **ML-DSA heap**: the baseline sign/verify allocate 52-112 KB / 23-69 KB per op, all of it the unpacked
  `PrivateKey`/`PublicKey` (expanded matrix A, NTT copies). With a pre-unpacked key (`v1`, `v5`) sign and verify
  allocate **451 bytes** per op (the message closure and a SHAKE state), i.e. the caching variants are also
  the allocation-free ones. The stage pipeline (`decode`..`hint_check`, `total_best`) allocates 0 bytes.
- **SLH-DSA stack** is tiny (2.9-4.3 KB): everything lives in the heap-allocated hasher `state`. Heap per op:
  keygen 1.4 KB, sign 46 KB (the hasher state plus the signature, 17 KB for 128f), verify 8.7 KB (state +
  parsed signature). `hmsg.v0` allocates 8 KB of which almost all is the structure parse (slice headers),
  which is what the `lazy-parse` alternative avoids.
- **A real PGO finding**: in the `-pgo` build the compiler inlines `sha256.Sum256` into CIRCL's
  `sha256sum` helper (`slhdsa/state.go:69`) and then reports `moved to heap: sha256.sum`, so every F/H call of
  the SHA2 parameter sets allocates a 32-byte digest on the heap: sign allocates **13.9 MB** per op instead of
  47 KB, verify 831 KB instead of 8.7 KB, keygen 585 KB instead of 1.4 KB (`go build -gcflags=-m` confirms it;
  the default build keeps the sum on the stack). This is the reason the PGO variants of Phase 1 were 20-30%
  *slower* on SLH-DSA-SHA2 (`sign.v4`, `verify.v4`, `keygen.v3`): profile-guided inlining changed the escape
  analysis result of a hot helper. SHAKE sets are unaffected.
- `total_best` for ML-DSA uses more stack (59 KB / 134 KB) than `verify.v0` (29 KB / 52 KB) because the
  harness pipeline keeps the decoded signature, w, mu and w1 as locals of one frame on top of the
  `WApproxCachedT1` temporaries; it allocates nothing on the heap.

<!-- RESULTS -->

## Results

Generated from `results/circl/memory.jsonl`. Method: pre-grown goroutine stack (~4 MiB) painted with 0xA5 via unsafe below the measuring frame, GC off, asyncpreempt off; high-water mark = lowest overwritten byte, minimum of 3 runs; empty-op baseline subtracted; writes inside the ~64-byte probe frame directly below the measuring frame are not visible.

### keygen: peak stack

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 8.3 KiB | 7.2 KiB | 8.3 KiB | 8.3 KiB | 8.3 KiB | 8.3 KiB |
| ML-DSA-65 | 10.9 KiB | 9.9 KiB | 10.9 KiB | 10.9 KiB | 10.9 KiB | 10.9 KiB |
| ML-DSA-87 | 13.6 KiB | 12.5 KiB | 13.6 KiB | 13.6 KiB | 13.6 KiB | 13.6 KiB |
| SLH-DSA-SHA2-128s | 4.2 KiB | 3.9 KiB | 4.1 KiB | 3.9 KiB | 4.2 KiB | 4.2 KiB |
| SLH-DSA-SHA2-128f | 4.2 KiB | 3.9 KiB | 4.1 KiB | 3.9 KiB | 4.2 KiB | 4.2 KiB |
| SLH-DSA-SHA2-192s | 4.2 KiB | 4.6 KiB | 4.1 KiB | 3.9 KiB | 4.2 KiB | 4.2 KiB |
| SLH-DSA-SHA2-192f | 4.2 KiB | 4.6 KiB | 4.1 KiB | 3.9 KiB | 4.2 KiB | 4.2 KiB |
| SLH-DSA-SHA2-256s | 4.2 KiB | 4.6 KiB | 4.1 KiB | 3.9 KiB | 4.2 KiB | 4.2 KiB |
| SLH-DSA-SHA2-256f | 4.2 KiB | 4.6 KiB | 4.1 KiB | 3.9 KiB | 4.2 KiB | 4.2 KiB |
| SLH-DSA-SHAKE-128s | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB |
| SLH-DSA-SHAKE-128f | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB |
| SLH-DSA-SHAKE-192s | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB |
| SLH-DSA-SHAKE-192f | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB |
| SLH-DSA-SHAKE-256s | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB |
| SLH-DSA-SHAKE-256f | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB | 3.5 KiB |

### keygen: heap allocated per op

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 58.0 KiB | 58.0 KiB | 58.0 KiB | 58.0 KiB | 58.0 KiB | 58.0 KiB |
| ML-DSA-65 | 86.0 KiB | 86.0 KiB | 86.0 KiB | 86.0 KiB | 86.0 KiB | 86.0 KiB |
| ML-DSA-87 | 122.5 KiB | 122.5 KiB | 122.5 KiB | 122.5 KiB | 122.5 KiB | 122.5 KiB |
| SLH-DSA-SHA2-128s | 1.7 KiB | 1.7 KiB | 1.7 KiB | 35.61 MiB | 1.7 KiB | 1.7 KiB |
| SLH-DSA-SHA2-128f | 1.4 KiB | 1.4 KiB | 1.4 KiB | 571.0 KiB | 1.4 KiB | 1.4 KiB |
| SLH-DSA-SHA2-192s | 2.2 KiB | 2.2 KiB | 2.2 KiB | 51.80 MiB | 2.2 KiB | 2.2 KiB |
| SLH-DSA-SHA2-192f | 1.9 KiB | 1.9 KiB | 1.9 KiB | 830.7 KiB | 1.9 KiB | 1.9 KiB |
| SLH-DSA-SHA2-256s | 2.3 KiB | 2.3 KiB | 2.3 KiB | 34.03 MiB | 2.3 KiB | 2.3 KiB |
| SLH-DSA-SHA2-256f | 2.1 KiB | 2.1 KiB | 2.1 KiB | 2.13 MiB | 2.1 KiB | 2.1 KiB |
| SLH-DSA-SHAKE-128s | 1.8 KiB | 1.8 KiB | 1.8 KiB | 1.8 KiB | 1.8 KiB | 1.8 KiB |
| SLH-DSA-SHAKE-128f | 1.5 KiB | 1.5 KiB | 1.5 KiB | 1.5 KiB | 1.5 KiB | 1.5 KiB |
| SLH-DSA-SHAKE-192s | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB | 2.2 KiB |
| SLH-DSA-SHAKE-192f | 1.8 KiB | 1.8 KiB | 1.8 KiB | 1.8 KiB | 1.8 KiB | 1.8 KiB |
| SLH-DSA-SHAKE-256s | 2.3 KiB | 2.3 KiB | 2.3 KiB | 2.3 KiB | 2.3 KiB | 2.3 KiB |
| SLH-DSA-SHAKE-256f | 2.0 KiB | 2.0 KiB | 2.0 KiB | 2.0 KiB | 2.0 KiB | 2.0 KiB |

### sign: peak stack

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 44.6 KiB | 44.5 KiB | 43.8 KiB | 44.6 KiB | 44.6 KiB | 44.5 KiB |
| ML-DSA-65 | 61.6 KiB | 61.6 KiB | 60.9 KiB | 61.6 KiB | 61.6 KiB | 61.6 KiB |
| ML-DSA-87 | 81.8 KiB | 81.8 KiB | 81.2 KiB | 81.8 KiB | 81.8 KiB | 81.8 KiB |
| SLH-DSA-SHA2-128s | 3.9 KiB | 3.8 KiB | 3.6 KiB | 3.9 KiB | 3.7 KiB | 3.8 KiB |
| SLH-DSA-SHA2-128f | 3.9 KiB | 3.8 KiB | 3.6 KiB | 3.9 KiB | 3.7 KiB | 3.8 KiB |
| SLH-DSA-SHA2-192s | 3.9 KiB | 3.8 KiB | 4.5 KiB | 3.9 KiB | 3.7 KiB | 3.8 KiB |
| SLH-DSA-SHA2-192f | 3.9 KiB | 3.8 KiB | 4.5 KiB | 3.9 KiB | 3.7 KiB | 3.8 KiB |
| SLH-DSA-SHA2-256s | 3.9 KiB | 3.8 KiB | 4.5 KiB | 3.9 KiB | 3.7 KiB | 3.8 KiB |
| SLH-DSA-SHA2-256f | 3.9 KiB | 3.8 KiB | 4.5 KiB | 3.9 KiB | 3.7 KiB | 3.8 KiB |
| SLH-DSA-SHAKE-128s | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.3 KiB | 3.2 KiB |
| SLH-DSA-SHAKE-128f | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.3 KiB | 3.2 KiB |
| SLH-DSA-SHAKE-192s | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.3 KiB | 3.2 KiB |
| SLH-DSA-SHAKE-192f | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.3 KiB | 3.2 KiB |
| SLH-DSA-SHAKE-256s | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.3 KiB | 3.2 KiB |
| SLH-DSA-SHAKE-256f | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.2 KiB | 3.3 KiB | 3.2 KiB |

### sign: heap allocated per op

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 51.1 KiB | 451 B | 51.1 KiB | 51.1 KiB | 51.1 KiB | 451 B |
| ML-DSA-65 | 75.8 KiB | 451 B | 75.8 KiB | 75.8 KiB | 75.8 KiB | 451 B |
| ML-DSA-87 | 109.2 KiB | 451 B | 109.2 KiB | 109.2 KiB | 109.2 KiB | 451 B |
| SLH-DSA-SHA2-128s | 23.5 KiB | 15.3 KiB | 23.5 KiB | 23.5 KiB | 272.05 MiB | 15.3 KiB |
| SLH-DSA-SHA2-128f | 45.5 KiB | 27.3 KiB | 45.5 KiB | 45.5 KiB | 13.27 MiB | 27.3 KiB |
| SLH-DSA-SHA2-192s | 42.7 KiB | 26.4 KiB | 42.7 KiB | 42.7 KiB | 430.65 MiB | 26.4 KiB |
| SLH-DSA-SHA2-192f | 92.0 KiB | 51.8 KiB | 92.0 KiB | 92.0 KiB | 20.18 MiB | 51.8 KiB |
| SLH-DSA-SHA2-256s | 76.9 KiB | 44.6 KiB | 76.9 KiB | 76.9 KiB | 360.32 MiB | 44.6 KiB |
| SLH-DSA-SHA2-256f | 125.5 KiB | 69.3 KiB | 125.5 KiB | 125.5 KiB | 40.85 MiB | 69.3 KiB |
| SLH-DSA-SHAKE-128s | 23.0 KiB | 14.8 KiB | 23.0 KiB | 23.0 KiB | 23.0 KiB | 14.8 KiB |
| SLH-DSA-SHAKE-128f | 44.9 KiB | 26.7 KiB | 44.9 KiB | 44.9 KiB | 44.9 KiB | 26.7 KiB |
| SLH-DSA-SHAKE-192s | 41.5 KiB | 25.2 KiB | 41.5 KiB | 41.5 KiB | 41.5 KiB | 25.2 KiB |
| SLH-DSA-SHAKE-192f | 90.8 KiB | 50.6 KiB | 90.8 KiB | 90.8 KiB | 90.8 KiB | 50.6 KiB |
| SLH-DSA-SHAKE-256s | 75.7 KiB | 43.4 KiB | 75.7 KiB | 75.7 KiB | 75.7 KiB | 43.4 KiB |
| SLH-DSA-SHAKE-256f | 124.4 KiB | 68.1 KiB | 124.4 KiB | 124.4 KiB | 124.4 KiB | 68.1 KiB |

### verify: peak stack

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 28.4 KiB | 28.4 KiB | 27.3 KiB | 28.4 KiB | 28.4 KiB | 28.4 KiB |
| ML-DSA-65 | 38.4 KiB | 38.4 KiB | 37.4 KiB | 38.4 KiB | 38.4 KiB | 38.4 KiB |
| ML-DSA-87 | 50.7 KiB | 50.7 KiB | 49.6 KiB | 50.7 KiB | 50.7 KiB | 50.7 KiB |
| SLH-DSA-SHA2-128s | 3.6 KiB | 3.6 KiB | 3.4 KiB | 3.6 KiB | 4.0 KiB | 3.6 KiB |
| SLH-DSA-SHA2-128f | 3.6 KiB | 3.6 KiB | 3.4 KiB | 3.6 KiB | 4.0 KiB | 3.6 KiB |
| SLH-DSA-SHA2-192s | 3.6 KiB | 3.6 KiB | 4.2 KiB | 3.6 KiB | 4.0 KiB | 3.6 KiB |
| SLH-DSA-SHA2-192f | 3.6 KiB | 3.6 KiB | 4.2 KiB | 3.6 KiB | 4.0 KiB | 3.6 KiB |
| SLH-DSA-SHA2-256s | 3.6 KiB | 3.6 KiB | 4.2 KiB | 3.6 KiB | 4.0 KiB | 3.6 KiB |
| SLH-DSA-SHA2-256f | 3.6 KiB | 3.6 KiB | 4.2 KiB | 3.6 KiB | 4.0 KiB | 3.6 KiB |
| SLH-DSA-SHAKE-128s | 2.8 KiB | 2.8 KiB | 2.8 KiB | 2.8 KiB | 3.6 KiB | 2.8 KiB |
| SLH-DSA-SHAKE-128f | 2.8 KiB | 2.8 KiB | 2.8 KiB | 2.8 KiB | 3.6 KiB | 2.8 KiB |
| SLH-DSA-SHAKE-192s | 2.8 KiB | 2.8 KiB | 2.8 KiB | 2.8 KiB | 3.6 KiB | 2.8 KiB |
| SLH-DSA-SHAKE-192f | 2.8 KiB | 2.8 KiB | 2.8 KiB | 2.8 KiB | 3.6 KiB | 2.8 KiB |
| SLH-DSA-SHAKE-256s | 2.8 KiB | 2.8 KiB | 2.8 KiB | 2.8 KiB | 3.6 KiB | 2.8 KiB |
| SLH-DSA-SHAKE-256f | 2.8 KiB | 2.8 KiB | 2.8 KiB | 2.8 KiB | 3.6 KiB | 2.8 KiB |

### verify: heap allocated per op

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 22.5 KiB | 451 B | 22.5 KiB | 22.5 KiB | 22.5 KiB | 451 B |
| ML-DSA-65 | 40.5 KiB | 451 B | 40.5 KiB | 40.5 KiB | 40.5 KiB | 451 B |
| ML-DSA-87 | 67.1 KiB | 451 B | 67.1 KiB | 67.1 KiB | 67.1 KiB | 451 B |
| SLH-DSA-SHA2-128s | 5.9 KiB | 5.8 KiB | 6.0 KiB | 5.9 KiB | 280.0 KiB | 5.8 KiB |
| SLH-DSA-SHA2-128f | 8.5 KiB | 8.4 KiB | 8.5 KiB | 8.5 KiB | 811.4 KiB | 8.4 KiB |
| SLH-DSA-SHA2-192s | 8.5 KiB | 8.4 KiB | 8.5 KiB | 8.5 KiB | 358.1 KiB | 8.4 KiB |
| SLH-DSA-SHA2-192f | 10.5 KiB | 10.4 KiB | 10.5 KiB | 10.5 KiB | 1.09 MiB | 10.4 KiB |
| SLH-DSA-SHA2-256s | 10.6 KiB | 10.4 KiB | 10.6 KiB | 10.6 KiB | 539.7 KiB | 10.4 KiB |
| SLH-DSA-SHA2-256f | 11.8 KiB | 11.7 KiB | 11.8 KiB | 11.8 KiB | 1.08 MiB | 11.7 KiB |
| SLH-DSA-SHAKE-128s | 5.9 KiB | 5.8 KiB | 5.9 KiB | 5.9 KiB | 5.9 KiB | 5.8 KiB |
| SLH-DSA-SHAKE-128f | 8.5 KiB | 8.3 KiB | 8.5 KiB | 8.5 KiB | 8.5 KiB | 8.3 KiB |
| SLH-DSA-SHAKE-192s | 8.1 KiB | 8.0 KiB | 8.1 KiB | 8.1 KiB | 8.1 KiB | 8.0 KiB |
| SLH-DSA-SHAKE-192f | 10.1 KiB | 10.0 KiB | 10.1 KiB | 10.1 KiB | 10.1 KiB | 10.0 KiB |
| SLH-DSA-SHAKE-256s | 10.2 KiB | 10.0 KiB | 10.2 KiB | 10.2 KiB | 10.2 KiB | 10.0 KiB |
| SLH-DSA-SHAKE-256f | 11.4 KiB | 11.3 KiB | 11.4 KiB | 11.4 KiB | 11.4 KiB | 11.3 KiB |

### verify-stage: peak stack

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 16.3 KiB | 1.1 KiB | — | 5.6 KiB | — | — | — | 824 B | 57.2 KiB | 15.3 KiB |
| ML-DSA-65 | 22.3 KiB | 1.1 KiB | — | 7.6 KiB | — | — | — | 824 B | 86.3 KiB | 20.3 KiB |
| ML-DSA-87 | 30.3 KiB | 1.1 KiB | — | 9.7 KiB | — | — | — | 824 B | 130.8 KiB | 26.3 KiB |
| SLH-DSA-SHA2-128s | — | — | 1.7 KiB | — | 2.4 KiB | 1.7 KiB | 1.9 KiB | — | 2.9 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 1.7 KiB | — | 2.4 KiB | 1.7 KiB | 1.9 KiB | — | 2.9 KiB | — |
| SLH-DSA-SHA2-192s | — | — | 1.7 KiB | — | 2.4 KiB | 1.7 KiB | 1.9 KiB | — | 2.9 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 1.7 KiB | — | 2.4 KiB | 1.7 KiB | 1.9 KiB | — | 2.9 KiB | — |
| SLH-DSA-SHA2-256s | — | — | 1.7 KiB | — | 2.4 KiB | 1.7 KiB | 1.9 KiB | — | 2.9 KiB | — |
| SLH-DSA-SHA2-256f | — | — | 1.7 KiB | — | 2.4 KiB | 1.7 KiB | 1.9 KiB | — | 2.9 KiB | — |
| SLH-DSA-SHAKE-128s | — | — | 1.0 KiB | — | 1.3 KiB | 1.1 KiB | 1.2 KiB | — | 1.8 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 1.0 KiB | — | 1.3 KiB | 1.1 KiB | 1.2 KiB | — | 1.8 KiB | — |
| SLH-DSA-SHAKE-192s | — | — | 1.0 KiB | — | 1.3 KiB | 1.1 KiB | 1.2 KiB | — | 1.8 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 1.0 KiB | — | 1.3 KiB | 1.1 KiB | 1.2 KiB | — | 1.8 KiB | — |
| SLH-DSA-SHAKE-256s | — | — | 1.0 KiB | — | 1.3 KiB | 1.1 KiB | 1.2 KiB | — | 1.8 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 1.0 KiB | — | 1.3 KiB | 1.1 KiB | 1.2 KiB | — | 1.8 KiB | — |

### verify-stage: heap allocated per op

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 0 B | 0 B | — | 0 B | — | — | — | 0 B | 0 B | 0 B |
| ML-DSA-65 | 0 B | 0 B | — | 0 B | — | — | — | 0 B | 0 B | 0 B |
| ML-DSA-87 | 0 B | 0 B | — | 0 B | — | — | — | 0 B | 0 B | 0 B |
| SLH-DSA-SHA2-128s | — | — | 48 B | — | 5.3 KiB | 224 B | 224 B | — | 6.1 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 48 B | — | 7.8 KiB | 704 B | 704 B | — | 10.4 KiB | — |
| SLH-DSA-SHA2-192s | — | — | 56 B | — | 7.5 KiB | 224 B | 224 B | — | 8.4 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 56 B | — | 9.5 KiB | 704 B | 704 B | — | 12.1 KiB | — |
| SLH-DSA-SHA2-256s | — | — | 64 B | — | 9.5 KiB | 256 B | 256 B | — | 10.5 KiB | — |
| SLH-DSA-SHA2-256f | — | — | 64 B | — | 10.7 KiB | 544 B | 544 B | — | 13.0 KiB | — |
| SLH-DSA-SHAKE-128s | — | — | 48 B | — | 5.1 KiB | 224 B | 224 B | — | 5.9 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 48 B | — | 7.6 KiB | 704 B | 704 B | — | 10.2 KiB | — |
| SLH-DSA-SHAKE-192s | — | — | 56 B | — | 7.2 KiB | 224 B | 224 B | — | 8.0 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 56 B | — | 9.2 KiB | 704 B | 704 B | — | 11.7 KiB | — |
| SLH-DSA-SHAKE-256s | — | — | 64 B | — | 9.2 KiB | 256 B | 256 B | — | 10.1 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 64 B | — | 10.4 KiB | 544 B | 544 B | — | 12.7 KiB | — |

