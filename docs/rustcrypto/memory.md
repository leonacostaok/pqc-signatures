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
