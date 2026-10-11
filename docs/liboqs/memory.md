# liboqs: stack and heap per operation

`run.sh memory --out results/liboqs/memory.jsonl [--params a,b]`

## Method

**Stack.** Every variant's operation (and every verify stage `v0` plus `total_best`) is executed once on a thread
whose stack the driver allocates itself: a 16 MiB `mmap` region passed through `pthread_attr_setstack`, filled
with the byte 0xA5 before the run. After `pthread_join` the region is scanned from the bottom for the first byte
that is not 0xA5; `stack_bytes` is the distance from that address to the top of the region, minus the high-water
mark of an empty function run the same way (glibc puts the thread descriptor / TLS at the top of a user-supplied
stack and the start routine has its own frames; that baseline is ~2-3 KiB and is reported in `stack_method`).
Resolution: the scan is byte-exact, but the baseline and the trampoline differ by a few words between runs, so
`stack_resolution_bytes` is reported as 16. The measured op is a warm second call (the first call of a liboqs
binary performs one-time initialisation such as the SHA-3 dispatch and the `OQS_SIG` object creation, which is
not part of an operation). Inputs (keys, message, signature, the stage state) live outside the measured stack.

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

## Conclusions (preliminary)

Dev numbers: ML-DSA-44 verify ~28 KiB stack (the A^ matrix dominates), ML-DSA-87 sign ~110 KiB; SLH-DSA
verify ~3 KiB and sign/keygen a few KiB regardless of parameter set (slhdsa-c is written for small stacks);
Falcon-512 verify ~3 KiB. Heap per op: ML-DSA verify ~5.7 KB allocated / 1.1 KB peak (SHAKE contexts),
SLH-DSA 280 B (a single `OQS_SIG`-level buffer), stages allocate only when they hash. The `cached` pipeline
(`total_best`) needs the least stack of the ML-DSA verifiers (4.8 KiB) because the matrix lives in the
per-key cache rather than on the stack. The threaded variants have the same per-worker footprint as `v0`.

<!-- RESULTS -->
