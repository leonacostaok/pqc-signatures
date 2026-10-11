# liboqs: stack and heap per operation

`run.sh memory --out results/liboqs/memory.jsonl [--params a,b]`

## Method

**Stack.** Every variant's operation (and every verify stage `v0` plus `total_best`) is executed once on a thread
whose stack the driver allocates itself: a 16 MiB `mmap` region passed through `pthread_attr_setstack`, filled
with the byte 0xA5 before the run. After `pthread_join` the region is scanned from the bottom for the first byte
that is not 0xA5; `stack_bytes` is the distance from that address to the top of the region, minus the high-water
mark of an empty function run the same way (glibc puts the thread descriptor / TLS at the top of a user-supplied
stack and the start routine has its own frames; that baseline is ~2-3 KiB and is reported in `stack_method`).
Resolution: the scan is byte-exact, but glibc's thread start code dirties the stack just below the start
routine before calling it, so the trampoline re-paints everything below its own frame except a 256-byte safety
margin and the high-water mark is taken from that frame; usage inside the margin is not resolvable (a stage that
needs less than ~256 B, e.g. ML-DSA `decode`, reads 0), hence `stack_resolution_bytes: 256`. The trampoline's own
call overhead (measured with an empty function) is subtracted. The measured op is a warm second call (the first
call of a liboqs binary performs one-time initialisation such as the SHA-3 dispatch and the `OQS_SIG` object
creation, which is not part of an operation). Inputs (keys, message, signature, the stage state) live outside the
measured stack.

**Heap.** The driver is linked statically with an allocator interposer (`libs/liboqs/src/memhook.c`) that
replaces `malloc/calloc/realloc/free/memalign/posix_memalign/aligned_alloc/valloc` and forwards to glibc's
`__libc_*`; every allocation made by liboqs, OpenSSL or the stage code during the operation is counted with
`malloc_usable_size`. `heap_alloc_bytes_per_op` is the total allocated during one op, `heap_peak_bytes` the peak
live heap during it (counters reset right before the op, after warm-up).

**Threads.** The four-thread variants execute the identical code on each worker, so their line reports the
per-worker stack of one worker and `threads: 4`.

**What to expect from liboqs.** mldsa-native allocates all working memory on the stack (`MLD_ALLOC` is a stack
array in the liboqs configuration): verify needs the whole A^ matrix (k x l KiB: 16 / 30 / 56 KiB) plus a few
polynomials, keygen and sign more (s1, s2, t0, y, w ...). The only heap traffic in ML-DSA comes from liboqs's
SHA-3 layer, which allocates the Keccak state of every incremental SHAKE context (and the 4-way contexts) with
`OQS_MEM_aligned_alloc` and frees it again; the OpenSSL-SHAKE alternatives allocate an `EVP_MD_CTX` instead.
slhdsa-c keeps everything on the stack too (ADRS, the `slh_var_t` with SHA-2 midstates, the FORS root buffer
`k*n`, the WOTS temporary `len*n`) and does no heap allocation; its only heap bytes are the OpenSSL `SHA256_CTX`
lookups in the `fasthash` flavour (none: `SHA256_Transform` is stateless) and liboqs's `OQS_SIG` wrapper (none per
op). Falcon (PQClean) uses a stack `tmp` buffer of a few KiB for verify and tens of KiB for keygen/sign.

## Conclusions (preliminary dev run, all 17 params, all variants; `results/liboqs/memory.jsonl`)

- **ML-DSA (mldsa-native, all on the stack):** keygen 31 / 54 / 79 KiB, sign 50 / 85 / 113 KiB, verify 30 / 50 / 74 KiB
  for ML-DSA-44 / 65 / 87; the A^ matrix (k x l KiB) plus a few polynomial vectors. Heap: 5.7-17.6 KB allocated per
  op with a 1.1 KB peak, all of it liboqs's SHA-3 layer allocating and freeing Keccak states (`OQS_SHA3_*_inc_init`
  uses `OQS_MEM_aligned_alloc`; the 4-way contexts are the largest). The direct-API variants are ~0.5 KiB smaller
  (no `OQS_SIG` wrapper frames); build flavours differ by a few hundred bytes (inlining); the threaded variant has
  the same per-worker footprint.
- **SLH-DSA (slhdsa-c):** 3.7-4.8 KiB stack for every op and every parameter set (ADRS, `slh_var_t` with the SHA-2
  midstates, FORS roots `k*n`, WOTS temporary `len*n`), no heap of its own; the constant 280 B heap is one
  `OQS_randombytes` / wrapper allocation. Per stage: ht_wots ~3 KiB, fors ~1.9 KiB, hmsg 0.5-0.7 KiB, ht_auth 0.5 KiB.
- **Falcon (PQClean):** keygen 36 KiB, sign 86 KiB (the FFT temporaries), verify 9 KiB.
- **Verify stages (ML-DSA):** w_approx 6.7-9.7 KiB (NTT(z) copy, two polynomials), expandA 4.3 KiB (4-way Keccak
  state), hint_check 1.4 KiB, mu 0.4 KiB, decode below the 256 B resolution. `total_best` runs in 6.4-9.5 KiB
  because A^ lives in the per-key cache instead of the stack, versus 30-74 KiB for the library's verify.

<!-- RESULTS -->

## Results (PRELIMINARY dev run)

### keygen: peak stack per op (heap alloc / peak in parentheses when non-zero)

| variant | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | SHA2-128s | SHA2-128f | SHA2-192s | SHA2-192f | SHA2-256s | SHA2-256f | SHAKE-128s | SHAKE-128f | SHAKE-192s | SHAKE-192f | SHAKE-256s | SHAKE-256f | Falcon-512 | Falcon-1024 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `keygen.v0` | 30.5 KiB (6352/1152) | 47.5 KiB (9528/1152) | 77.5 KiB (15976/1152) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 18.4 KiB (544/544) | 34.9 KiB (544/544) |
| `keygen.v1` | 30.4 KiB (6352/1152) | 47.4 KiB (9528/1152) | 77.4 KiB (15976/1152) | 3.8 KiB (280/280) | 3.8 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 18.4 KiB (544/544) | 34.9 KiB (544/544) |
| `keygen.v2` | 30.6 KiB (6352/1152) | 47.6 KiB (9528/1152) | 77.6 KiB (15976/1152) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 18.5 KiB (544/544) | 35.0 KiB (544/544) |
| `keygen.v3` | 30.4 KiB (6352/1152) | 47.5 KiB (9528/1152) | 77.5 KiB (15976/1152) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 3.7 KiB (280/280) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 20.7 KiB (544/544) | 37.2 KiB (544/544) |
| `keygen.v4` | 30.5 KiB (6352/1152) | 47.5 KiB (9528/1152) | 77.5 KiB (15976/1152) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 3.8 KiB (280/280) | 3.8 KiB (280/280) | 3.8 KiB (280/280) | 3.8 KiB (280/280) | 3.8 KiB (280/280) | 3.8 KiB (280/280) | 17.8 KiB (544/544) | 34.5 KiB (544/544) |
| `keygen.v5` | 30.5 KiB (6352/1152) | 47.5 KiB (9528/1152) | 77.5 KiB (15976/1152) | 3.9 KiB (280/280) | 3.9 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 18.4 KiB (544/544) | 34.9 KiB (544/544) |

### sign: peak stack per op (heap alloc / peak in parentheses when non-zero)

| variant | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | SHA2-128s | SHA2-128f | SHA2-192s | SHA2-192f | SHA2-256s | SHA2-256f | SHAKE-128s | SHAKE-128f | SHAKE-192s | SHAKE-192f | SHAKE-256s | SHAKE-256f | Falcon-512 | Falcon-1024 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `sign.v0` | 48.6 KiB (6536/1152) | 72.6 KiB (17424/1152) | 110.6 KiB (17560/1152) | 4.7 KiB (280/280) | 4.7 KiB (280/280) | 5.1 KiB (280/280) | 5.1 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 44.2 KiB (808/544) | 84.4 KiB (808/544) |
| `sign.v1` | 48.0 KiB (6536/1152) | 72.0 KiB (17424/1152) | 110.0 KiB (17560/1152) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 44.3 KiB (808/544) | 84.4 KiB (808/544) |
| `sign.v2` | 48.5 KiB (6536/1152) | 72.6 KiB (17424/1152) | 110.6 KiB (17560/1152) | 4.7 KiB (280/280) | 4.7 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 43.8 KiB (808/544) | 84.0 KiB (808/544) |
| `sign.v3` | 48.6 KiB (6536/1152) | 72.6 KiB (17424/1152) | 110.6 KiB (17560/1152) | 5.5 KiB (280/280) | 5.5 KiB (280/280) | 7.5 KiB (280/280) | 7.5 KiB (280/280) | 7.5 KiB (280/280) | 7.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 44.2 KiB (808/544) | 84.4 KiB (808/544) |
| `sign.v4` | 48.5 KiB (6536/1152) | 72.5 KiB (17424/1152) | 110.5 KiB (17560/1152) | 4.7 KiB (280/280) | 4.7 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 44.4 KiB (808/544) | 84.6 KiB (808/544) |
| `sign.v5` | 48.6 KiB (6536/1152) | 72.6 KiB (17424/1152) | 110.6 KiB (17560/1152) | 4.7 KiB (280/280) | 4.7 KiB (280/280) | 5.1 KiB (280/280) | 5.1 KiB (280/280) | 5.2 KiB (280/280) | 5.2 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.4 KiB (280/280) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 44.2 KiB (808/544) | 84.4 KiB (808/544) |

### verify: peak stack per op (heap alloc / peak in parentheses when non-zero)

| variant | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | SHA2-128s | SHA2-128f | SHA2-192s | SHA2-192f | SHA2-256s | SHA2-256f | SHAKE-128s | SHAKE-128f | SHAKE-192s | SHAKE-192f | SHAKE-256s | SHAKE-256f | Falcon-512 | Falcon-1024 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `verify.v0` | 29.0 KiB (5664/1152) | 44.1 KiB (7968/1152) | 72.3 KiB (13544/1152) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.6 KiB (544/544) | 8.6 KiB (544/544) |
| `verify.v1` | 28.5 KiB (5664/1152) | 43.6 KiB (7968/1152) | 71.8 KiB (13544/1152) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.7 KiB (544/544) | 8.7 KiB (544/544) |
| `verify.v2` | 29.0 KiB (5664/1152) | 44.0 KiB (7968/1152) | 72.3 KiB (13544/1152) | 4.5 KiB (280/280) | 4.5 KiB (280/280) | 4.9 KiB (280/280) | 4.9 KiB (280/280) | 4.9 KiB (280/280) | 4.9 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.7 KiB (544/544) | 8.7 KiB (544/544) |
| `verify.v3` | 28.8 KiB (5664/1152) | 43.9 KiB (7968/1152) | 72.1 KiB (13544/1152) | 4.1 KiB (280/280) | 4.1 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.2 KiB (280/280) | 4.1 KiB (280/280) | 4.1 KiB (280/280) | 4.1 KiB (280/280) | 4.1 KiB (280/280) | 4.1 KiB (280/280) | 4.1 KiB (280/280) | 4.6 KiB (544/544) | 8.6 KiB (544/544) |
| `verify.v4` | 29.0 KiB (5664/1152) | 44.1 KiB (7968/1152) | 72.3 KiB (13544/1152) | 5.5 KiB (280/280) | 5.5 KiB (280/280) | 7.5 KiB (280/280) | 7.5 KiB (280/280) | 7.5 KiB (280/280) | 7.5 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.6 KiB (544/544) | 8.6 KiB (544/544) |
| `verify.v5` | 29.0 KiB (5664/1152) | 44.1 KiB (7968/1152) | 72.3 KiB (13544/1152) | 4.6 KiB (280/280) | 4.6 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 5.0 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.3 KiB (280/280) | 4.6 KiB (544/544) | 8.6 KiB (544/544) |

### verify-stage: peak stack per op (heap alloc / peak in parentheses when non-zero)

| variant | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | SHA2-128s | SHA2-128f | SHA2-192s | SHA2-192f | SHA2-256s | SHA2-256f | SHAKE-128s | SHAKE-128f | SHAKE-192s | SHAKE-192f | SHAKE-256s | SHAKE-256f |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `decode.v0` | 0 B (1120/280) | 0 B (280/280) | 0 B (280/280) | — | — | — | — | — | — | — | — | — | — | — | — |
| `mu.v0` | 432 B (1648/544) | 368 B (808/544) | 368 B (808/544) | — | — | — | — | — | — | — | — | — | — | — | — |
| `expandA.v0` | 4.2 KiB (4608/1152) | 4.2 KiB (6912/1152) | 4.2 KiB (12488/1152) | — | — | — | — | — | — | — | — | — | — | — | — |
| `w_approx.v0` | 6.5 KiB (1384/544) | 7.5 KiB (544/544) | 9.5 KiB (544/544) | — | — | — | — | — | — | — | — | — | — | — | — |
| `hint_check.v0` | 1.4 KiB (1384/544) | 1.3 KiB (544/544) | 1.3 KiB (544/544) | — | — | — | — | — | — | — | — | — | — | — | — |
| `hmsg.v0` | — | — | — | 740 B (1120/280) | 740 B (280/280) | 1.4 KiB (280/280) | 1.4 KiB (280/280) | 1.4 KiB (280/280) | 1.4 KiB (280/280) | 536 B (280/280) | 536 B (280/280) | 536 B (280/280) | 536 B (280/280) | 536 B (280/280) | 536 B (280/280) |
| `fors.v0` | — | — | — | 1.9 KiB (1120/280) | 1.9 KiB (280/280) | 2.5 KiB (280/280) | 2.5 KiB (280/280) | 2.5 KiB (280/280) | 2.5 KiB (280/280) | 1.7 KiB (280/280) | 1.7 KiB (280/280) | 1.7 KiB (280/280) | 1.7 KiB (280/280) | 1.7 KiB (280/280) | 1.7 KiB (280/280) |
| `ht_wots.v0` | — | — | — | 3.2 KiB (1120/280) | 3.2 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 3.6 KiB (280/280) | 2.9 KiB (280/280) | 2.9 KiB (280/280) | 2.9 KiB (280/280) | 2.9 KiB (280/280) | 2.9 KiB (280/280) | 2.9 KiB (280/280) |
| `ht_auth.v0` | — | — | — | 596 B (1120/280) | 596 B (280/280) | 1.2 KiB (280/280) | 1.2 KiB (280/280) | 1.2 KiB (280/280) | 1.2 KiB (280/280) | 488 B (280/280) | 488 B (280/280) | 488 B (280/280) | 488 B (280/280) | 488 B (280/280) | 488 B (280/280) |
| `total_best` | 6.3 KiB (1912/544) | 7.3 KiB (1072/544) | 9.3 KiB (1072/544) | 4.5 KiB (1120/280) | 4.5 KiB (280/280) | 5.5 KiB (280/280) | 5.5 KiB (280/280) | 5.5 KiB (280/280) | 5.5 KiB (280/280) | 3.1 KiB (280/280) | 3.1 KiB (280/280) | 3.1 KiB (280/280) | 3.1 KiB (280/280) | 3.1 KiB (280/280) | 3.1 KiB (280/280) |

