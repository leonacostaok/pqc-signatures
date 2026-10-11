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

## Results (PRELIMINARY: dev run on a loaded shared box, short budgets; the orchestrator overwrites this section)

| param | op | variant | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| ML-DSA-44 | keygen | `keygen.v0` | 201664 | 94272 | 90400 | 1 | ✓ |
| ML-DSA-44 | keygen | `keygen.v1` | 201744 | 94272 | 90400 | 1 | ✓ |
| ML-DSA-44 | keygen | `keygen.v2` | 198464 | 94272 | 90400 | 1 | ✓ |
| ML-DSA-44 | keygen | `keygen.v3` | 189344 | 94272 | 90400 | 1 | ✓ |
| ML-DSA-44 | keygen | `keygen.v4` | 201664 | 94272 | 90400 | 1 | ✓ |
| ML-DSA-44 | keygen | `keygen.v5` | 201664 | 94272 | 90400 | 4 | ✓ |
| ML-DSA-44 | sign | `sign.v0` | 107600 | 6516 | 6516 | 1 | ✓ |
| ML-DSA-44 | sign | `sign.v1` | 105680 | 6516 | 6516 | 1 | ✓ |
| ML-DSA-44 | sign | `sign.v2` | 107696 | 6516 | 6516 | 1 | ✓ |
| ML-DSA-44 | sign | `sign.v3` | 118576 | 6516 | 6516 | 1 | ✓ |
| ML-DSA-44 | sign | `sign.v4` | 66480 | 6516 | 6516 | 1 | ✓ |
| ML-DSA-44 | sign | `sign.v5` | 107600 | 6516 | 6516 | 4 | ✓ |
| ML-DSA-44 | verify | `verify.v0` | 68272 | 28736 | 28736 | 1 | ✓ |
| ML-DSA-44 | verify | `verify.v1` | 66384 | 28736 | 28736 | 1 | ✓ |
| ML-DSA-44 | verify | `verify.v2` | 58464 | 28736 | 28736 | 1 | ✓ |
| ML-DSA-44 | verify | `verify.v3` | 59968 | 28736 | 28736 | 1 | ✓ |
| ML-DSA-44 | verify | `verify.v4` | 48464 | 4096 | 4096 | 1 | ✓ |
| ML-DSA-44 | verify | `verify.v5` | 68272 | 28736 | 28736 | 4 | ✓ |
| ML-DSA-44 | verify-stage decode | `decode.v0` | 44592 | 32768 | 32768 | 1 | ✓ |
| ML-DSA-44 | verify-stage expandA | `expandA.v0` | 43096 | 0 | 0 | 1 | ✓ |
| ML-DSA-44 | verify-stage hint_check | `hint_check.v0` | 13078 | 768 | 768 | 1 | ✓ |
| ML-DSA-44 | verify-stage mu | `mu.v0` | 0 | 0 | 0 | 1 | ✓ |
| ML-DSA-44 | verify-stage total | `total.v0` | 80608 | 768 | 768 | 1 | ✓ |
| ML-DSA-44 | verify-stage total_best | `total_best.v0` | 71920 | 29568 | 16384 | 1 | ✓ |
| ML-DSA-44 | verify-stage w_approx | `w_approx.v0` | 54768 | 0 | 0 | 1 | ✓ |
| ML-DSA-87 | keygen | `keygen.v0` | 438688 | 259680 | 252192 | 1 | ✓ |
| ML-DSA-87 | keygen | `keygen.v1` | 438848 | 259680 | 252192 | 1 | ✓ |
| ML-DSA-87 | keygen | `keygen.v2` | 442976 | 259680 | 252192 | 1 | ✓ |
| ML-DSA-87 | keygen | `keygen.v3` | 432560 | 259680 | 252192 | 1 | ✓ |
| ML-DSA-87 | keygen | `keygen.v4` | 438688 | 259680 | 252192 | 1 | ✓ |
| ML-DSA-87 | keygen | `keygen.v5` | 438688 | 259680 | 252192 | 4 | ✓ |
| ML-DSA-87 | sign | `sign.v0` | 275432 | 11795 | 11795 | 1 | ✓ |
| ML-DSA-87 | sign | `sign.v1` | 275488 | 11795 | 11795 | 1 | ✓ |
| ML-DSA-87 | sign | `sign.v2` | 268432 | 11795 | 11795 | 1 | ✓ |
| ML-DSA-87 | sign | `sign.v3` | 269240 | 11795 | 11795 | 1 | ✓ |
| ML-DSA-87 | sign | `sign.v4` | 130432 | 11795 | 11795 | 1 | ✓ |
| ML-DSA-87 | sign | `sign.v5` | 275432 | 11795 | 11795 | 4 | ✓ |
| ML-DSA-87 | verify | `verify.v0` | 170144 | 80960 | 80960 | 1 | ✓ |
| ML-DSA-87 | verify | `verify.v1` | 170288 | 80960 | 80960 | 1 | ✓ |
| ML-DSA-87 | verify | `verify.v2` | 154464 | 80960 | 80960 | 1 | ✓ |
| ML-DSA-87 | verify | `verify.v3` | 157824 | 80960 | 80960 | 1 | ✓ |
| ML-DSA-87 | verify | `verify.v4` | 70032 | 7168 | 7168 | 1 | ✓ |
| ML-DSA-87 | verify | `verify.v5` | 170144 | 80960 | 80960 | 4 | ✓ |
| ML-DSA-87 | verify-stage decode | `decode.v0` | 85648 | 65536 | 65536 | 1 | ✓ |
| ML-DSA-87 | verify-stage expandA | `expandA.v0` | 131208 | 0 | 0 | 1 | ✓ |
| ML-DSA-87 | verify-stage hint_check | `hint_check.v0` | 25654 | 1024 | 1024 | 1 | ✓ |
| ML-DSA-87 | verify-stage mu | `mu.v0` | 0 | 0 | 0 | 1 | ✓ |
| ML-DSA-87 | verify-stage total | `total.v0` | 157048 | 1024 | 1024 | 1 | ✓ |
| ML-DSA-87 | verify-stage total_best | `total_best.v0` | 213312 | 82176 | 57344 | 1 | ✓ |
| ML-DSA-87 | verify-stage w_approx | `w_approx.v0` | 72192 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHA2-256s | keygen | `keygen.v0` | 4624 | 192 | 192 | 1 | ✓ |
| SLH-DSA-SHA2-256s | keygen | `keygen.v1` | 4608 | 192 | 192 | 1 | ✓ |
| SLH-DSA-SHA2-256s | keygen | `keygen.v2` | 4352 | 192 | 192 | 1 | ✓ |
| SLH-DSA-SHA2-256s | keygen | `keygen.v3` | 4440 | 192 | 192 | 1 | ✓ |
| SLH-DSA-SHA2-256s | keygen | `keygen.v4` | 4624 | 192 | 192 | 1 | ✓ |
| SLH-DSA-SHA2-256s | keygen | `keygen.v5` | 4624 | 192 | 192 | 4 | ✓ |
| SLH-DSA-SHA2-256s | sign | `sign.v0` | 166960 | 29792 | 29792 | 1 | ✓ |
| SLH-DSA-SHA2-256s | sign | `sign.v1` | 166944 | 29792 | 29792 | 1 | ✓ |
| SLH-DSA-SHA2-256s | sign | `sign.v2` | 177968 | 29792 | 29792 | 1 | ✓ |
| SLH-DSA-SHA2-256s | sign | `sign.v3` | 148520 | 29792 | 29792 | 1 | ✓ |
| SLH-DSA-SHA2-256s | sign | `sign.v4` | 166784 | 29792 | 29792 | 1 | ✓ |
| SLH-DSA-SHA2-256s | sign | `sign.v5` | 166960 | 29792 | 29792 | 4 | ✓ |
| SLH-DSA-SHA2-256s | verify | `verify.v0` | 137488 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify | `verify.v1` | 137504 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify | `verify.v2` | 84320 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify | `verify.v3` | 115120 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify | `verify.v4` | 137408 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify | `verify.v5` | 137488 | 0 | 0 | 4 | ✓ |
| SLH-DSA-SHA2-256s | verify-stage fors | `fors.v0` | 928 | 32 | 32 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify-stage hmsg | `hmsg.v0` | 167440 | 86 | 86 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify-stage ht_auth | `ht_auth.v0` | 368 | 576 | 576 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify-stage ht_wots | `ht_wots.v0` | 4768 | 576 | 576 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify-stage total | `total.v0` | 197952 | 246 | 246 | 1 | ✓ |
| SLH-DSA-SHA2-256s | verify-stage total_best | `total_best.v0` | 2160 | 35718 | 4505 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | keygen | `keygen.v0` | 3832 | 96 | 96 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | keygen | `keygen.v1` | 3720 | 96 | 96 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | keygen | `keygen.v2` | 3712 | 96 | 96 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | keygen | `keygen.v3` | 3064 | 96 | 96 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | keygen | `keygen.v4` | 3840 | 96 | 96 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | keygen | `keygen.v5` | 3832 | 96 | 96 | 4 | ✓ |
| SLH-DSA-SHAKE-128f | sign | `sign.v0` | 96048 | 17088 | 17088 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | sign | `sign.v1` | 96048 | 17088 | 17088 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | sign | `sign.v2` | 86928 | 17088 | 17088 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | sign | `sign.v3` | 87576 | 17088 | 17088 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | sign | `sign.v4` | 95984 | 17088 | 17088 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | sign | `sign.v5` | 96048 | 17088 | 17088 | 4 | ✓ |
| SLH-DSA-SHAKE-128f | verify | `verify.v0` | 86768 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify | `verify.v1` | 86768 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify | `verify.v2` | 63296 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify | `verify.v3` | 63600 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify | `verify.v4` | 86720 | 0 | 0 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify | `verify.v5` | 86768 | 0 | 0 | 4 | ✓ |
| SLH-DSA-SHAKE-128f | verify-stage fors | `fors.v0` | 1720 | 16 | 16 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify-stage hmsg | `hmsg.v0` | 104032 | 59 | 59 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify-stage ht_auth | `ht_auth.v0` | 312 | 1232 | 1232 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify-stage ht_wots | `ht_wots.v0` | 1512 | 1232 | 1232 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify-stage total | `total.v0` | 122640 | 427 | 427 | 1 | ✓ |
| SLH-DSA-SHAKE-128f | verify-stage total_best | `total_best.v0` | 3808 | 77969 | 3838 | 1 | ✓ |
