# rustcrypto: stack and heap per operation

`run.sh memory --out results/rustcrypto/memory.jsonl [--params a,b]`

## Method

**Stack** (`stack_method` in every line): the operation runs on a thread whose stack the harness
allocates itself — 32 MiB from `mmap`, filled with the byte pattern `0xA5`, handed to
`pthread_attr_setstack`, thread created with `pthread_create` (`src/memory.rs`). After `pthread_join`
the region is scanned upwards (8-byte words, then bytes) for the lowest address that no longer holds
the pattern; `32 MiB − offset` is the high-water mark of that thread. glibc places the thread's TLS
block and start frames at the top of a user-supplied stack, so an empty closure is measured the same
way (minimum of three runs, ≈ 6.4 KB) and subtracted. Reported `stack_bytes` is therefore the extra
stack the operation itself touched; `stack_resolution_bytes` is 16: the compiler may reserve frame
space it never writes (a `[u8; N]` that is only partially filled), and the red zone / alignment make
single bytes meaningless. Ops that touch less than the baseline show 0.

Each line measures **one** operation on prepared inputs (the same closures as the benchmark, outputs
checked against the reference: `match`). For the rayon `par` variants the per-item closure is run on
the painted stack, which is what one worker executes; `threads` is set to the pool size (4). rayon's
own frames on the worker (job dispatch, a few hundred bytes) are not included.

**Heap**: the binary's global allocator is a counting wrapper (`heap` module in `src/main.rs`) around
`std::alloc::System` — or `mimalloc` in the `keygen.v4` binary — that, while enabled, adds every
allocation to `heap_alloc_bytes_per_op` and tracks live bytes to report `heap_peak_bytes` (peak live
above the level at op start). Counting is switched on inside the measurement thread right before the
op and off right after it, so thread set-up is excluded. The same wrapper is linked into the
benchmark binaries; disabled it costs one relaxed atomic load per allocation.

Verify stages: the `verify-stage` lines measure the v0 implementation of each stage on its prepared
inputs (`stage` field) plus the `total` and `total_best` pipelines on raw bytes. These come from the
`base` binary only.

## What to expect / reading the numbers

* ML-DSA keygen is the stack-hungriest op in these crates: the crate works on `Vector`/`NttMatrix`
  values by move (`hybrid_array` arrays of 256 × u32 per polynomial; A^ for ML-DSA-87 is 8·7·1 KiB)
  and only boxes the final key structures (`MaybeBox`, the `alloc` feature), so intermediate matrices
  live on the stack: ~270 KB for ML-DSA-44. Signing and verifying are around 50–110 KB. The
  `keycache` variants are smaller because `ExpandedSigningKey::from_expanded` / `VerifyingKey::decode`
  (which build A^ on the stack) happen outside the op.
* Heap: ML-DSA keygen allocates the boxed expanded key + verifying key (~90 KB for ML-DSA-44);
  verify allocates the boxed `VerifyingKey` precomputations (~28 KB) that `keycache` avoids; SLH-DSA
  allocates almost nothing (the harness's output `Vec` is the only heap traffic for keygen/sign).
* SLH-DSA signing uses ~110 KB of stack (recursive `xmss_node`/`fors_node` tree builds plus the
  signature arrays by value); verify ~87 KB (the parsed `Signature` of up to 50 KB lives on the stack
  in `Signature::try_from`).
* `total_best` (SLH-DSA) runs on a few KB of stack because it never materialises the parsed signature
  (zero-copy slices) and keeps its chain/tree state in small heap buffers instead.

<!-- RESULTS -->

## Results

Generated from `results/rustcrypto/memory.jsonl`. Method: painted mmap stack (pthread_attr_setstack, 0xA5 fill), lowest overwritten byte, minus empty-closure baseline on the same kind of thread; peak of one op.

### keygen: peak stack

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 196.9 KiB | 197.0 KiB | 193.8 KiB | 217.4 KiB | 196.9 KiB | 196.9 KiB |
| ML-DSA-65 | 272.5 KiB | 272.7 KiB | 300.1 KiB | 344.3 KiB | 272.5 KiB | 272.5 KiB |
| ML-DSA-87 | 428.4 KiB | 428.6 KiB | 432.6 KiB | 422.4 KiB | 428.4 KiB | 428.4 KiB |
| SLH-DSA-SHA2-128s | 7.0 KiB | 6.9 KiB | 6.9 KiB | 7.0 KiB | 7.0 KiB | 7.0 KiB |
| SLH-DSA-SHA2-128f | 2.5 KiB | 2.4 KiB | 2.4 KiB | 2.5 KiB | 2.5 KiB | 2.5 KiB |
| SLH-DSA-SHA2-192s | 3.5 KiB | 3.5 KiB | 3.3 KiB | 3.1 KiB | 3.5 KiB | 3.5 KiB |
| SLH-DSA-SHA2-192f | 2.7 KiB | 2.7 KiB | 2.4 KiB | 2.2 KiB | 2.7 KiB | 2.7 KiB |
| SLH-DSA-SHA2-256s | 4.5 KiB | 4.5 KiB | 4.3 KiB | 4.3 KiB | 4.5 KiB | 4.5 KiB |
| SLH-DSA-SHA2-256f | 3.9 KiB | 3.9 KiB | 3.6 KiB | 3.7 KiB | 3.9 KiB | 3.9 KiB |
| SLH-DSA-SHAKE-128s | 8.2 KiB | 8.2 KiB | 8.1 KiB | 8.1 KiB | 8.2 KiB | 8.2 KiB |
| SLH-DSA-SHAKE-128f | 3.7 KiB | 3.7 KiB | 3.6 KiB | 3.0 KiB | 3.7 KiB | 3.7 KiB |
| SLH-DSA-SHAKE-192s | 3.7 KiB | 3.7 KiB | 3.5 KiB | 3.6 KiB | 3.7 KiB | 3.7 KiB |
| SLH-DSA-SHAKE-192f | 2.8 KiB | 2.8 KiB | 2.7 KiB | 3.8 KiB | 2.8 KiB | 2.8 KiB |
| SLH-DSA-SHAKE-256s | 4.7 KiB | 4.7 KiB | 4.5 KiB | 5.3 KiB | 4.7 KiB | 4.7 KiB |
| SLH-DSA-SHAKE-256f | 4.1 KiB | 4.0 KiB | 3.9 KiB | 5.1 KiB | 4.1 KiB | 4.1 KiB |

### keygen: heap allocated per op

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 92.1 KiB | 92.1 KiB | 92.1 KiB | 92.1 KiB | 92.1 KiB | 92.1 KiB |
| ML-DSA-65 | 154.1 KiB | 154.1 KiB | 154.1 KiB | 154.1 KiB | 154.1 KiB | 154.1 KiB |
| ML-DSA-87 | 253.6 KiB | 253.6 KiB | 253.6 KiB | 253.6 KiB | 253.6 KiB | 253.6 KiB |
| SLH-DSA-SHA2-128s | 96 B | 96 B | 96 B | 96 B | 96 B | 96 B |
| SLH-DSA-SHA2-128f | 96 B | 96 B | 96 B | 96 B | 96 B | 96 B |
| SLH-DSA-SHA2-192s | 144 B | 144 B | 144 B | 144 B | 144 B | 144 B |
| SLH-DSA-SHA2-192f | 144 B | 144 B | 144 B | 144 B | 144 B | 144 B |
| SLH-DSA-SHA2-256s | 192 B | 192 B | 192 B | 192 B | 192 B | 192 B |
| SLH-DSA-SHA2-256f | 192 B | 192 B | 192 B | 192 B | 192 B | 192 B |
| SLH-DSA-SHAKE-128s | 96 B | 96 B | 96 B | 96 B | 96 B | 96 B |
| SLH-DSA-SHAKE-128f | 96 B | 96 B | 96 B | 96 B | 96 B | 96 B |
| SLH-DSA-SHAKE-192s | 144 B | 144 B | 144 B | 144 B | 144 B | 144 B |
| SLH-DSA-SHAKE-192f | 144 B | 144 B | 144 B | 144 B | 144 B | 144 B |
| SLH-DSA-SHAKE-256s | 192 B | 192 B | 192 B | 192 B | 192 B | 192 B |
| SLH-DSA-SHAKE-256f | 192 B | 192 B | 192 B | 192 B | 192 B | 192 B |

### sign: peak stack

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 105.1 KiB | 103.2 KiB | 105.2 KiB | 115.8 KiB | 64.9 KiB | 105.1 KiB |
| ML-DSA-65 | 158.2 KiB | 158.2 KiB | 160.3 KiB | 165.9 KiB | 89.8 KiB | 158.2 KiB |
| ML-DSA-87 | 269.0 KiB | 269.0 KiB | 262.1 KiB | 262.9 KiB | 127.4 KiB | 269.0 KiB |
| SLH-DSA-SHA2-128s | 43.2 KiB | 43.2 KiB | 51.3 KiB | 43.6 KiB | 43.2 KiB | 43.2 KiB |
| SLH-DSA-SHA2-128f | 93.6 KiB | 93.6 KiB | 83.3 KiB | 83.3 KiB | 93.5 KiB | 93.6 KiB |
| SLH-DSA-SHA2-192s | 89.3 KiB | 89.3 KiB | 95.7 KiB | 79.6 KiB | 89.2 KiB | 89.3 KiB |
| SLH-DSA-SHA2-192f | 200.5 KiB | 200.5 KiB | 172.7 KiB | 172.5 KiB | 200.4 KiB | 200.5 KiB |
| SLH-DSA-SHA2-256s | 163.0 KiB | 163.0 KiB | 173.8 KiB | 145.0 KiB | 162.9 KiB | 163.0 KiB |
| SLH-DSA-SHA2-256f | 276.2 KiB | 276.2 KiB | 289.8 KiB | 241.5 KiB | 276.1 KiB | 276.2 KiB |
| SLH-DSA-SHAKE-128s | 43.6 KiB | 43.6 KiB | 52.9 KiB | 44.8 KiB | 43.6 KiB | 43.6 KiB |
| SLH-DSA-SHAKE-128f | 93.8 KiB | 93.8 KiB | 84.9 KiB | 85.5 KiB | 93.7 KiB | 93.8 KiB |
| SLH-DSA-SHAKE-192s | 89.3 KiB | 89.3 KiB | 96.4 KiB | 82.2 KiB | 89.2 KiB | 89.3 KiB |
| SLH-DSA-SHAKE-192f | 200.5 KiB | 200.5 KiB | 173.3 KiB | 175.0 KiB | 200.4 KiB | 200.5 KiB |
| SLH-DSA-SHAKE-256s | 163.1 KiB | 163.1 KiB | 174.5 KiB | 146.8 KiB | 162.9 KiB | 163.1 KiB |
| SLH-DSA-SHAKE-256f | 276.3 KiB | 276.3 KiB | 290.5 KiB | 243.3 KiB | 276.1 KiB | 276.3 KiB |

### sign: heap allocated per op

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 6.4 KiB | 6.4 KiB | 6.4 KiB | 6.4 KiB | 6.4 KiB | 6.4 KiB |
| ML-DSA-65 | 8.2 KiB | 8.2 KiB | 8.2 KiB | 8.2 KiB | 8.2 KiB | 8.2 KiB |
| ML-DSA-87 | 11.5 KiB | 11.5 KiB | 11.5 KiB | 11.5 KiB | 11.5 KiB | 11.5 KiB |
| SLH-DSA-SHA2-128s | 7.7 KiB | 7.7 KiB | 7.7 KiB | 7.7 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-128f | 16.7 KiB | 16.7 KiB | 16.7 KiB | 16.7 KiB | 16.7 KiB | 16.7 KiB |
| SLH-DSA-SHA2-192s | 15.8 KiB | 15.8 KiB | 15.8 KiB | 15.8 KiB | 15.8 KiB | 15.8 KiB |
| SLH-DSA-SHA2-192f | 34.8 KiB | 34.8 KiB | 34.8 KiB | 34.8 KiB | 34.8 KiB | 34.8 KiB |
| SLH-DSA-SHA2-256s | 29.1 KiB | 29.1 KiB | 29.1 KiB | 29.1 KiB | 29.1 KiB | 29.1 KiB |
| SLH-DSA-SHA2-256f | 48.7 KiB | 48.7 KiB | 48.7 KiB | 48.7 KiB | 48.7 KiB | 48.7 KiB |
| SLH-DSA-SHAKE-128s | 7.7 KiB | 7.7 KiB | 7.7 KiB | 7.7 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHAKE-128f | 16.7 KiB | 16.7 KiB | 16.7 KiB | 16.7 KiB | 16.7 KiB | 16.7 KiB |
| SLH-DSA-SHAKE-192s | 15.8 KiB | 15.8 KiB | 15.8 KiB | 15.8 KiB | 15.8 KiB | 15.8 KiB |
| SLH-DSA-SHAKE-192f | 34.8 KiB | 34.8 KiB | 34.8 KiB | 34.8 KiB | 34.8 KiB | 34.8 KiB |
| SLH-DSA-SHAKE-256s | 29.1 KiB | 29.1 KiB | 29.1 KiB | 29.1 KiB | 29.1 KiB | 29.1 KiB |
| SLH-DSA-SHAKE-256f | 48.7 KiB | 48.7 KiB | 48.7 KiB | 48.7 KiB | 48.7 KiB | 48.7 KiB |

### verify: peak stack

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 66.7 KiB | 64.8 KiB | 57.1 KiB | 65.9 KiB | 47.3 KiB | 66.7 KiB |
| ML-DSA-65 | 100.9 KiB | 101.0 KiB | 92.3 KiB | 103.2 KiB | 53.1 KiB | 100.9 KiB |
| ML-DSA-87 | 166.2 KiB | 166.3 KiB | 150.8 KiB | 154.2 KiB | 68.4 KiB | 166.2 KiB |
| SLH-DSA-SHA2-128s | 33.9 KiB | 33.9 KiB | 18.5 KiB | 26.7 KiB | 33.8 KiB | 33.9 KiB |
| SLH-DSA-SHA2-128f | 84.7 KiB | 84.7 KiB | 60.6 KiB | 62.1 KiB | 84.7 KiB | 84.7 KiB |
| SLH-DSA-SHA2-192s | 71.1 KiB | 71.1 KiB | 45.1 KiB | 60.3 KiB | 71.1 KiB | 71.1 KiB |
| SLH-DSA-SHA2-192f | 180.8 KiB | 180.8 KiB | 128.7 KiB | 132.0 KiB | 180.8 KiB | 180.8 KiB |
| SLH-DSA-SHA2-256s | 134.3 KiB | 134.3 KiB | 82.3 KiB | 112.4 KiB | 134.2 KiB | 134.3 KiB |
| SLH-DSA-SHA2-256f | 249.1 KiB | 249.1 KiB | 178.0 KiB | 184.4 KiB | 249.0 KiB | 249.1 KiB |
| SLH-DSA-SHAKE-128s | 33.9 KiB | 33.9 KiB | 18.5 KiB | 26.7 KiB | 33.8 KiB | 33.9 KiB |
| SLH-DSA-SHAKE-128f | 84.7 KiB | 84.7 KiB | 61.8 KiB | 62.1 KiB | 84.7 KiB | 84.7 KiB |
| SLH-DSA-SHAKE-192s | 71.1 KiB | 71.1 KiB | 45.1 KiB | 60.3 KiB | 71.1 KiB | 71.1 KiB |
| SLH-DSA-SHAKE-192f | 180.8 KiB | 180.8 KiB | 128.9 KiB | 132.0 KiB | 180.8 KiB | 180.8 KiB |
| SLH-DSA-SHAKE-256s | 134.3 KiB | 134.3 KiB | 82.3 KiB | 112.4 KiB | 134.2 KiB | 134.3 KiB |
| SLH-DSA-SHAKE-256f | 249.1 KiB | 249.1 KiB | 178.3 KiB | 184.4 KiB | 249.0 KiB | 249.1 KiB |

### verify: heap allocated per op

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 28.1 KiB | 28.1 KiB | 28.1 KiB | 28.1 KiB | 4.0 KiB | 28.1 KiB |
| ML-DSA-65 | 47.1 KiB | 47.1 KiB | 47.1 KiB | 47.1 KiB | 5.0 KiB | 47.1 KiB |
| ML-DSA-87 | 79.1 KiB | 79.1 KiB | 79.1 KiB | 79.1 KiB | 7.0 KiB | 79.1 KiB |
| SLH-DSA-SHA2-128s | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHA2-128f | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHA2-192s | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHA2-192f | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHA2-256s | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHA2-256f | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHAKE-128s | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHAKE-128f | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHAKE-192s | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHAKE-192f | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHAKE-256s | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |
| SLH-DSA-SHAKE-256f | 0 B | 0 B | 0 B | 0 B | 0 B | 0 B |

### verify-stage: peak stack

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total.v0` | `total_best.v0` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 43.5 KiB | 42.1 KiB | — | 12.8 KiB | — | — | — | 0 B | 78.7 KiB | 70.2 KiB | 53.5 KiB |
| ML-DSA-65 | 61.6 KiB | 72.1 KiB | — | 18.8 KiB | — | — | — | 0 B | 97.3 KiB | 119.8 KiB | 54.5 KiB |
| ML-DSA-87 | 83.6 KiB | 128.1 KiB | — | 25.1 KiB | — | — | — | 0 B | 153.4 KiB | 208.3 KiB | 70.5 KiB |
| SLH-DSA-SHA2-128s | — | — | 0 B | — | 41.7 KiB | 0 B | 672 B | — | 49.8 KiB | 1.5 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 0 B | — | 101.6 KiB | 0 B | 672 B | — | 118.7 KiB | 1.5 KiB | — |
| SLH-DSA-SHA2-192s | — | — | 576 B | — | 87.1 KiB | 368 B | 2.8 KiB | — | 103.6 KiB | 2.1 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 1.0 KiB | — | 215.8 KiB | 352 B | 2.8 KiB | — | 251.3 KiB | 2.2 KiB | — |
| SLH-DSA-SHA2-256s | — | — | 928 B | — | 163.5 KiB | 368 B | 4.7 KiB | — | 193.3 KiB | 2.1 KiB | — |
| SLH-DSA-SHA2-256f | — | — | 1.4 KiB | — | 297.9 KiB | 368 B | 4.7 KiB | — | 347.3 KiB | 2.2 KiB | — |
| SLH-DSA-SHAKE-128s | — | — | 1.3 KiB | — | 41.7 KiB | 328 B | 1.5 KiB | — | 50.9 KiB | 3.7 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 1.7 KiB | — | 101.6 KiB | 312 B | 1.5 KiB | — | 119.8 KiB | 3.7 KiB | — |
| SLH-DSA-SHAKE-192s | — | — | 1.5 KiB | — | 87.1 KiB | 344 B | 2.8 KiB | — | 104.5 KiB | 3.8 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 1.9 KiB | — | 215.8 KiB | 328 B | 2.8 KiB | — | 252.2 KiB | 3.8 KiB | — |
| SLH-DSA-SHAKE-256s | — | — | 1.9 KiB | — | 163.5 KiB | 360 B | 4.7 KiB | — | 194.2 KiB | 3.8 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 2.3 KiB | — | 297.9 KiB | 344 B | 4.7 KiB | — | 348.2 KiB | 3.8 KiB | — |

### verify-stage: heap allocated per op

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total.v0` | `total_best.v0` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 32.0 KiB | 0 B | — | 768 B | — | — | — | 0 B | 768 B | 28.9 KiB | 0 B |
| ML-DSA-65 | 48.0 KiB | 0 B | — | 768 B | — | — | — | 0 B | 768 B | 47.9 KiB | 0 B |
| ML-DSA-87 | 64.0 KiB | 0 B | — | 1.0 KiB | — | — | — | 0 B | 1.0 KiB | 80.3 KiB | 0 B |
| SLH-DSA-SHA2-128s | — | — | 16 B | — | 51 B | 392 B | 392 B | — | 179 B | 8.6 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 16 B | — | 59 B | 1.2 KiB | 1.2 KiB | — | 427 B | 26.7 KiB | — |
| SLH-DSA-SHA2-192s | — | — | 24 B | — | 69 B | 448 B | 448 B | — | 205 B | 17.4 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 24 B | — | 75 B | 1.4 KiB | 1.4 KiB | — | 451 B | 53.5 KiB | — |
| SLH-DSA-SHA2-256s | — | — | 32 B | — | 86 B | 576 B | 576 B | — | 246 B | 34.9 KiB | — |
| SLH-DSA-SHA2-256f | — | — | 32 B | — | 89 B | 1.2 KiB | 1.2 KiB | — | 393 B | 73.3 KiB | — |
| SLH-DSA-SHAKE-128s | — | — | 16 B | — | 51 B | 392 B | 392 B | — | 179 B | 24.4 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 16 B | — | 59 B | 1.2 KiB | 1.2 KiB | — | 427 B | 76.1 KiB | — |
| SLH-DSA-SHAKE-192s | — | — | 24 B | — | 69 B | 448 B | 448 B | — | 205 B | 40.9 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 24 B | — | 75 B | 1.4 KiB | 1.4 KiB | — | 451 B | 127.6 KiB | — |
| SLH-DSA-SHAKE-256s | — | — | 32 B | — | 86 B | 576 B | 576 B | — | 246 B | 69.6 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 32 B | — | 89 B | 1.2 KiB | 1.2 KiB | — | 393 B | 147.3 KiB | — |

