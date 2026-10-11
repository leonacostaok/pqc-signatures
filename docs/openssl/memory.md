# OpenSSL - stack and heap per operation

`libs/openssl/run.sh memory --out results/openssl/memory.jsonl [--params a,b]`

## Method

* **Stack** (`libs/openssl/src/pqc_memory.c`): one operation is executed on a pthread whose 16 MiB stack the
  driver allocates itself (`pthread_attr_setstack`) after painting it with `0xA5`. After the join, the lowest
  address whose byte is no longer `0xA5` gives the high-water mark. The same measurement with an empty thread
  function (glibc puts the thread descriptor / static TLS and the start frame at the top of a user-supplied
  stack) is taken three times and its maximum subtracted, so `stack_bytes` is what the operation itself
  touched. Resolution: the scan is byte exact; reported as 16 bytes (stack alignment granularity).
  Every op is warmed up once on the main thread before the measurement so one-time lazy initialisations
  (property cache entries, error strings, ...) are not attributed to the op.
* **Heap**: `CRYPTO_set_mem_functions` is called as the very first thing in `main()`, installing a counting
  `malloc/realloc/free` (16-byte size header). `heap_alloc_bytes_per_op` is the total number of bytes OpenSSL
  requested during the op, `heap_peak_bytes` the peak of live bytes above the level before the op. Only
  OpenSSL's allocations are counted (the driver's own buffers are allocated with libc malloc), which is what
  one wants: the library's footprint. Thread-safe atomics, so the numbers are valid for threaded variants too.
* Every phase-1 variant of keygen/sign/verify is measured (the `pthread-x4` variants are measured as one worker,
  i.e. per-thread stack, `threads: 4` is reported), plus v0 of every verify stage (`op: "verify-stage"`) and the
  `total` / `total_best` pipelines. Each measured op is checked against the reference afterwards (`match`).
* The three build flavours are measured by their own binaries (`build` field); the stage numbers come from the
  default build.

## What to expect / observations

* OpenSSL keeps the big ML-DSA objects on the heap: `ml_dsa_verify_internal` allocates one blob for the
  matrix A^, the signature vectors and w1 (`k*l + k + l + 2k + 1` polynomials of 1 KiB), and signing a larger
  one (the full set of s1/s2/t0/y/w vectors plus A^); keygen allocates the key (t1, t0, s1, s2) and the encoded
  keys. The stack use of the EVP path is therefore modest (a few KiB: the EVP layers, the PACKET/WPACKET
  encoders, the SHAKE block buffers, `c_tilde`, `mu`).
* SLH-DSA in OpenSSL is almost allocation free per op (the hash ctx and key are created once, the FORS roots
  and WOTS chain buffers are stack arrays sized for n = 32), so the stack is where everything lives: the
  `ossl_slh_wots_pk_from_sig` temporary (`(2n+3)*n` bytes, up to 2 KiB), the FORS roots (`k*n`), ADRS copies,
  EVP digest contexts, and for signing the XMSS tree recursion (`ossl_slh_xmss_node` recurses hm levels).
* The staged pipeline keeps its matrices in context buffers allocated once per key (they are inputs of the
  measurement, not part of it), so `total_best` shows mainly the own NTT's stack (`cn[256]` plus the SHAKE
  contexts) and no heap, while `total` (v0 stages) still allocates the EVP contexts OpenSSL's code creates per call.

<!-- RESULTS -->
