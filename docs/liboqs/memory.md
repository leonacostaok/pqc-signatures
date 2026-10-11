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

## Results

Generated from `results/liboqs/memory.jsonl`. Method: private pthread stack (16 MiB) re-painted with 0xA5 below the trampoline frame, high-water scan from that frame, minus the trampoline+call overhead of 239 B; private pthread stack (16 MiB) re-painted with 0xA5 below the trampoline frame, high-water scan from that frame, minus the trampoline+call overhead of 247 B.

### keygen: peak stack

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 30.5 KiB | 30.4 KiB | 30.6 KiB | 30.4 KiB | 30.5 KiB | 30.5 KiB |
| ML-DSA-65 | 47.5 KiB | 47.4 KiB | 47.6 KiB | 47.5 KiB | 47.5 KiB | 47.5 KiB |
| ML-DSA-87 | 77.5 KiB | 77.4 KiB | 77.6 KiB | 77.5 KiB | 77.5 KiB | 77.5 KiB |
| SLH-DSA-SHA2-128s | 3.9 KiB | 3.8 KiB | 3.9 KiB | 3.6 KiB | 3.9 KiB | 3.9 KiB |
| SLH-DSA-SHA2-128f | 3.9 KiB | 3.8 KiB | 3.9 KiB | 3.6 KiB | 3.9 KiB | 3.9 KiB |
| SLH-DSA-SHA2-192s | 4.3 KiB | 4.3 KiB | 4.4 KiB | 3.7 KiB | 4.4 KiB | 4.3 KiB |
| SLH-DSA-SHA2-192f | 4.3 KiB | 4.3 KiB | 4.4 KiB | 3.7 KiB | 4.4 KiB | 4.3 KiB |
| SLH-DSA-SHA2-256s | 4.3 KiB | 4.3 KiB | 4.4 KiB | 3.7 KiB | 4.4 KiB | 4.3 KiB |
| SLH-DSA-SHA2-256f | 4.3 KiB | 4.3 KiB | 4.4 KiB | 3.7 KiB | 4.4 KiB | 4.3 KiB |
| SLH-DSA-SHAKE-128s | 3.6 KiB | 3.6 KiB | 3.7 KiB | 3.9 KiB | 3.8 KiB | 3.6 KiB |
| SLH-DSA-SHAKE-128f | 3.6 KiB | 3.6 KiB | 3.7 KiB | 3.9 KiB | 3.8 KiB | 3.6 KiB |
| SLH-DSA-SHAKE-192s | 3.6 KiB | 3.6 KiB | 3.7 KiB | 3.9 KiB | 3.8 KiB | 3.6 KiB |
| SLH-DSA-SHAKE-192f | 3.6 KiB | 3.6 KiB | 3.7 KiB | 3.9 KiB | 3.8 KiB | 3.6 KiB |
| SLH-DSA-SHAKE-256s | 3.6 KiB | 3.6 KiB | 3.7 KiB | 3.9 KiB | 3.8 KiB | 3.6 KiB |
| SLH-DSA-SHAKE-256f | 3.6 KiB | 3.6 KiB | 3.7 KiB | 3.9 KiB | 3.8 KiB | 3.6 KiB |
| Falcon-512 | 18.4 KiB | 18.4 KiB | 18.5 KiB | 20.7 KiB | 17.8 KiB | 18.4 KiB |
| Falcon-1024 | 34.9 KiB | 34.9 KiB | 35.0 KiB | 37.2 KiB | 34.5 KiB | 34.9 KiB |

### keygen: heap allocated per op

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 6.2 KiB | 6.2 KiB | 6.2 KiB | 6.2 KiB | 6.2 KiB | 6.2 KiB |
| ML-DSA-65 | 9.3 KiB | 9.3 KiB | 9.3 KiB | 9.3 KiB | 9.3 KiB | 9.3 KiB |
| ML-DSA-87 | 15.6 KiB | 15.6 KiB | 15.6 KiB | 15.6 KiB | 15.6 KiB | 15.6 KiB |
| SLH-DSA-SHA2-128s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-128f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-192s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-192f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-256s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-256f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-128s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-128f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-192s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-192f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-256s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-256f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| Falcon-512 | 544 B | 544 B | 544 B | 544 B | 544 B | 544 B |
| Falcon-1024 | 544 B | 544 B | 544 B | 544 B | 544 B | 544 B |

### sign: peak stack

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 48.6 KiB | 48.0 KiB | 48.5 KiB | 48.6 KiB | 48.5 KiB | 48.6 KiB |
| ML-DSA-65 | 72.6 KiB | 72.0 KiB | 72.6 KiB | 72.6 KiB | 72.5 KiB | 72.6 KiB |
| ML-DSA-87 | 110.6 KiB | 110.0 KiB | 110.6 KiB | 110.6 KiB | 110.5 KiB | 110.6 KiB |
| SLH-DSA-SHA2-128s | 4.7 KiB | 4.6 KiB | 4.7 KiB | 5.5 KiB | 4.7 KiB | 4.7 KiB |
| SLH-DSA-SHA2-128f | 4.7 KiB | 4.6 KiB | 4.7 KiB | 5.5 KiB | 4.7 KiB | 4.7 KiB |
| SLH-DSA-SHA2-192s | 5.1 KiB | 5.0 KiB | 5.2 KiB | 7.5 KiB | 5.2 KiB | 5.1 KiB |
| SLH-DSA-SHA2-192f | 5.1 KiB | 5.0 KiB | 5.2 KiB | 7.5 KiB | 5.2 KiB | 5.1 KiB |
| SLH-DSA-SHA2-256s | 5.2 KiB | 5.0 KiB | 5.2 KiB | 7.5 KiB | 5.2 KiB | 5.2 KiB |
| SLH-DSA-SHA2-256f | 5.2 KiB | 5.0 KiB | 5.2 KiB | 7.5 KiB | 5.2 KiB | 5.2 KiB |
| SLH-DSA-SHAKE-128s | 4.4 KiB | 4.3 KiB | 4.5 KiB | 4.5 KiB | 4.6 KiB | 4.4 KiB |
| SLH-DSA-SHAKE-128f | 4.4 KiB | 4.3 KiB | 4.5 KiB | 4.5 KiB | 4.6 KiB | 4.4 KiB |
| SLH-DSA-SHAKE-192s | 4.4 KiB | 4.3 KiB | 4.5 KiB | 4.5 KiB | 4.6 KiB | 4.4 KiB |
| SLH-DSA-SHAKE-192f | 4.4 KiB | 4.3 KiB | 4.5 KiB | 4.5 KiB | 4.6 KiB | 4.4 KiB |
| SLH-DSA-SHAKE-256s | 4.5 KiB | 4.3 KiB | 4.5 KiB | 4.5 KiB | 4.6 KiB | 4.5 KiB |
| SLH-DSA-SHAKE-256f | 4.5 KiB | 4.3 KiB | 4.5 KiB | 4.5 KiB | 4.6 KiB | 4.5 KiB |
| Falcon-512 | 44.2 KiB | 44.3 KiB | 43.8 KiB | 44.2 KiB | 44.4 KiB | 44.2 KiB |
| Falcon-1024 | 84.4 KiB | 84.4 KiB | 84.0 KiB | 84.4 KiB | 84.6 KiB | 84.4 KiB |

### sign: heap allocated per op

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 6.4 KiB | 6.4 KiB | 6.4 KiB | 6.4 KiB | 6.4 KiB | 6.4 KiB |
| ML-DSA-65 | 17.0 KiB | 17.0 KiB | 17.0 KiB | 17.0 KiB | 17.0 KiB | 17.0 KiB |
| ML-DSA-87 | 17.1 KiB | 17.1 KiB | 17.1 KiB | 17.1 KiB | 17.1 KiB | 17.1 KiB |
| SLH-DSA-SHA2-128s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-128f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-192s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-192f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-256s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-256f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-128s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-128f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-192s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-192f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-256s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-256f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| Falcon-512 | 808 B | 808 B | 808 B | 808 B | 808 B | 808 B |
| Falcon-1024 | 808 B | 808 B | 808 B | 808 B | 808 B | 808 B |

### verify: peak stack

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 29.0 KiB | 28.5 KiB | 29.0 KiB | 28.8 KiB | 29.0 KiB | 29.0 KiB |
| ML-DSA-65 | 44.1 KiB | 43.6 KiB | 44.0 KiB | 43.9 KiB | 44.1 KiB | 44.1 KiB |
| ML-DSA-87 | 72.3 KiB | 71.8 KiB | 72.3 KiB | 72.1 KiB | 72.3 KiB | 72.3 KiB |
| SLH-DSA-SHA2-128s | 4.6 KiB | 4.6 KiB | 4.5 KiB | 4.1 KiB | 5.5 KiB | 4.6 KiB |
| SLH-DSA-SHA2-128f | 4.6 KiB | 4.6 KiB | 4.5 KiB | 4.1 KiB | 5.5 KiB | 4.6 KiB |
| SLH-DSA-SHA2-192s | 5.0 KiB | 5.0 KiB | 4.9 KiB | 4.2 KiB | 7.5 KiB | 5.0 KiB |
| SLH-DSA-SHA2-192f | 5.0 KiB | 5.0 KiB | 4.9 KiB | 4.2 KiB | 7.5 KiB | 5.0 KiB |
| SLH-DSA-SHA2-256s | 5.0 KiB | 5.0 KiB | 4.9 KiB | 4.2 KiB | 7.5 KiB | 5.0 KiB |
| SLH-DSA-SHA2-256f | 5.0 KiB | 5.0 KiB | 4.9 KiB | 4.2 KiB | 7.5 KiB | 5.0 KiB |
| SLH-DSA-SHAKE-128s | 4.3 KiB | 4.3 KiB | 4.2 KiB | 4.1 KiB | 4.3 KiB | 4.3 KiB |
| SLH-DSA-SHAKE-128f | 4.3 KiB | 4.3 KiB | 4.2 KiB | 4.1 KiB | 4.3 KiB | 4.3 KiB |
| SLH-DSA-SHAKE-192s | 4.3 KiB | 4.3 KiB | 4.2 KiB | 4.1 KiB | 4.3 KiB | 4.3 KiB |
| SLH-DSA-SHAKE-192f | 4.3 KiB | 4.3 KiB | 4.2 KiB | 4.1 KiB | 4.3 KiB | 4.3 KiB |
| SLH-DSA-SHAKE-256s | 4.3 KiB | 4.3 KiB | 4.2 KiB | 4.1 KiB | 4.3 KiB | 4.3 KiB |
| SLH-DSA-SHAKE-256f | 4.3 KiB | 4.3 KiB | 4.2 KiB | 4.1 KiB | 4.3 KiB | 4.3 KiB |
| Falcon-512 | 4.6 KiB | 4.7 KiB | 4.7 KiB | 4.6 KiB | 4.6 KiB | 4.6 KiB |
| Falcon-1024 | 8.6 KiB | 8.7 KiB | 8.7 KiB | 8.6 KiB | 8.6 KiB | 8.6 KiB |

### verify: heap allocated per op

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 5.5 KiB | 5.5 KiB | 5.5 KiB | 5.5 KiB | 5.5 KiB | 5.5 KiB |
| ML-DSA-65 | 7.8 KiB | 7.8 KiB | 7.8 KiB | 7.8 KiB | 7.8 KiB | 7.8 KiB |
| ML-DSA-87 | 13.2 KiB | 13.2 KiB | 13.2 KiB | 13.2 KiB | 13.2 KiB | 13.2 KiB |
| SLH-DSA-SHA2-128s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-128f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-192s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-192f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-256s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHA2-256f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-128s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-128f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-192s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-192f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-256s | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| SLH-DSA-SHAKE-256f | 280 B | 280 B | 280 B | 280 B | 280 B | 280 B |
| Falcon-512 | 544 B | 544 B | 544 B | 544 B | 544 B | 544 B |
| Falcon-1024 | 544 B | 544 B | 544 B | 544 B | 544 B | 544 B |

### verify-stage: peak stack

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 0 B | 4.2 KiB | — | 1.4 KiB | — | — | — | 432 B | 6.3 KiB | 6.5 KiB |
| ML-DSA-65 | 0 B | 4.2 KiB | — | 1.3 KiB | — | — | — | 368 B | 7.3 KiB | 7.5 KiB |
| ML-DSA-87 | 0 B | 4.2 KiB | — | 1.3 KiB | — | — | — | 368 B | 9.3 KiB | 9.5 KiB |
| SLH-DSA-SHA2-128s | — | — | 1.9 KiB | — | 740 B | 596 B | 3.2 KiB | — | 4.5 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 1.9 KiB | — | 740 B | 596 B | 3.2 KiB | — | 4.5 KiB | — |
| SLH-DSA-SHA2-192s | — | — | 2.5 KiB | — | 1.4 KiB | 1.2 KiB | 3.6 KiB | — | 5.5 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 2.5 KiB | — | 1.4 KiB | 1.2 KiB | 3.6 KiB | — | 5.5 KiB | — |
| SLH-DSA-SHA2-256s | — | — | 2.5 KiB | — | 1.4 KiB | 1.2 KiB | 3.6 KiB | — | 5.5 KiB | — |
| SLH-DSA-SHA2-256f | — | — | 2.5 KiB | — | 1.4 KiB | 1.2 KiB | 3.6 KiB | — | 5.5 KiB | — |
| SLH-DSA-SHAKE-128s | — | — | 1.7 KiB | — | 536 B | 488 B | 2.9 KiB | — | 3.1 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 1.7 KiB | — | 536 B | 488 B | 2.9 KiB | — | 3.1 KiB | — |
| SLH-DSA-SHAKE-192s | — | — | 1.7 KiB | — | 536 B | 488 B | 2.9 KiB | — | 3.1 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 1.7 KiB | — | 536 B | 488 B | 2.9 KiB | — | 3.1 KiB | — |
| SLH-DSA-SHAKE-256s | — | — | 1.7 KiB | — | 536 B | 488 B | 2.9 KiB | — | 3.1 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 1.7 KiB | — | 536 B | 488 B | 2.9 KiB | — | 3.1 KiB | — |

### verify-stage: heap allocated per op

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.1 KiB | 4.5 KiB | — | 1.4 KiB | — | — | — | 1.6 KiB | 1.9 KiB | 1.4 KiB |
| ML-DSA-65 | 280 B | 6.8 KiB | — | 544 B | — | — | — | 808 B | 1.0 KiB | 544 B |
| ML-DSA-87 | 280 B | 12.2 KiB | — | 544 B | — | — | — | 808 B | 1.0 KiB | 544 B |
| SLH-DSA-SHA2-128s | — | — | 1.1 KiB | — | 1.1 KiB | 1.1 KiB | 1.1 KiB | — | 1.1 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHA2-192s | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHA2-192f | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHA2-256s | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHA2-256f | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHAKE-128s | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHAKE-128f | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHAKE-192s | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHAKE-192f | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHAKE-256s | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |
| SLH-DSA-SHAKE-256f | — | — | 280 B | — | 280 B | 280 B | 280 B | — | 280 B | — |

