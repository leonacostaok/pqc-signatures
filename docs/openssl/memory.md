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

## Results

Generated from `results/openssl/memory.jsonl`. Method: painted 16 MiB pthread stack (pthread_attr_setstack), re-painted below the measuring frame's rsp after an in-thread warm-up, high-water mark of the op.

### keygen: peak stack

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 2.1 KiB | 1.9 KiB | 1.9 KiB | 2.1 KiB | 2.4 KiB | 1.9 KiB |
| ML-DSA-65 | 2.1 KiB | 1.9 KiB | 1.9 KiB | 2.1 KiB | 2.4 KiB | 1.9 KiB |
| ML-DSA-87 | 2.1 KiB | 1.9 KiB | 1.9 KiB | 2.1 KiB | 2.4 KiB | 1.9 KiB |
| SLH-DSA-SHA2-128s | 6.7 KiB | 6.7 KiB | — | 5.9 KiB | 6.7 KiB | 6.7 KiB |
| SLH-DSA-SHA2-128f | 5.7 KiB | 5.7 KiB | — | 4.7 KiB | 5.7 KiB | 5.7 KiB |
| SLH-DSA-SHA2-192s | 7.7 KiB | 7.7 KiB | — | 6.0 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-192f | 7.7 KiB | 7.7 KiB | — | 4.8 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-256s | 7.7 KiB | 7.7 KiB | — | 5.8 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-256f | 7.7 KiB | 7.7 KiB | — | 5.0 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHAKE-128s | 6.0 KiB | 5.8 KiB | — | 6.1 KiB | 5.8 KiB | 5.8 KiB |
| SLH-DSA-SHAKE-128f | 4.8 KiB | 4.6 KiB | — | 4.9 KiB | 4.6 KiB | 4.6 KiB |
| SLH-DSA-SHAKE-192s | 6.0 KiB | 5.8 KiB | — | 6.1 KiB | 5.8 KiB | 5.8 KiB |
| SLH-DSA-SHAKE-192f | 4.8 KiB | 4.6 KiB | — | 4.9 KiB | 4.6 KiB | 4.6 KiB |
| SLH-DSA-SHAKE-256s | 5.8 KiB | 5.6 KiB | — | 5.9 KiB | 5.6 KiB | 5.6 KiB |
| SLH-DSA-SHAKE-256f | 5.0 KiB | 4.8 KiB | — | 5.1 KiB | 4.8 KiB | 4.8 KiB |

### keygen: heap allocated per op

| param | `keygen.v0` | `keygen.v1` | `keygen.v2` | `keygen.v3` | `keygen.v4` | `keygen.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 46.2 KiB | 45.9 KiB | 46.0 KiB | 46.2 KiB | 46.2 KiB | 45.9 KiB |
| ML-DSA-65 | 72.2 KiB | 72.0 KiB | 72.1 KiB | 72.2 KiB | 72.2 KiB | 72.0 KiB |
| ML-DSA-87 | 111.7 KiB | 111.5 KiB | 111.5 KiB | 111.7 KiB | 111.7 KiB | 111.5 KiB |
| SLH-DSA-SHA2-128s | 21.7 KiB | 21.4 KiB | — | 21.7 KiB | 21.7 KiB | 21.4 KiB |
| SLH-DSA-SHA2-128f | 2.0 KiB | 1.7 KiB | — | 2.0 KiB | 2.0 KiB | 1.7 KiB |
| SLH-DSA-SHA2-192s | 22.0 KiB | 21.7 KiB | — | 22.0 KiB | 22.0 KiB | 21.7 KiB |
| SLH-DSA-SHA2-192f | 2.3 KiB | 2.0 KiB | — | 2.3 KiB | 2.3 KiB | 2.0 KiB |
| SLH-DSA-SHA2-256s | 12.0 KiB | 11.7 KiB | — | 12.0 KiB | 12.0 KiB | 11.7 KiB |
| SLH-DSA-SHA2-256f | 2.6 KiB | 2.3 KiB | — | 2.6 KiB | 2.6 KiB | 2.3 KiB |
| SLH-DSA-SHAKE-128s | 21.6 KiB | 21.3 KiB | — | 21.6 KiB | 21.6 KiB | 21.3 KiB |
| SLH-DSA-SHAKE-128f | 1.9 KiB | 1.6 KiB | — | 1.9 KiB | 1.9 KiB | 1.6 KiB |
| SLH-DSA-SHAKE-192s | 21.6 KiB | 21.3 KiB | — | 21.6 KiB | 21.6 KiB | 21.3 KiB |
| SLH-DSA-SHAKE-192f | 1.9 KiB | 1.6 KiB | — | 1.9 KiB | 1.9 KiB | 1.6 KiB |
| SLH-DSA-SHAKE-256s | 11.6 KiB | 11.3 KiB | — | 11.6 KiB | 11.6 KiB | 11.3 KiB |
| SLH-DSA-SHAKE-256f | 2.2 KiB | 1.9 KiB | — | 2.2 KiB | 2.2 KiB | 1.9 KiB |

### sign: peak stack

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 3.6 KiB | 3.3 KiB | 3.3 KiB | 3.7 KiB | 4.2 KiB | 3.3 KiB |
| ML-DSA-65 | 3.6 KiB | 3.3 KiB | 3.3 KiB | 3.7 KiB | 4.2 KiB | 3.3 KiB |
| ML-DSA-87 | 3.6 KiB | 3.3 KiB | 3.3 KiB | 3.7 KiB | 4.2 KiB | 3.3 KiB |
| SLH-DSA-SHA2-128s | 8.7 KiB | 7.7 KiB | 7.7 KiB | 7.4 KiB | 8.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-128f | 6.7 KiB | 6.7 KiB | 6.7 KiB | 6.2 KiB | 7.7 KiB | 6.7 KiB |
| SLH-DSA-SHA2-192s | 9.7 KiB | 9.7 KiB | 9.7 KiB | 7.5 KiB | 9.7 KiB | 9.7 KiB |
| SLH-DSA-SHA2-192f | 7.7 KiB | 7.7 KiB | 7.7 KiB | 6.3 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-256s | 9.7 KiB | 9.7 KiB | 9.7 KiB | 7.3 KiB | 9.7 KiB | 9.7 KiB |
| SLH-DSA-SHA2-256f | 7.7 KiB | 7.7 KiB | 7.7 KiB | 6.5 KiB | 9.7 KiB | 7.7 KiB |
| SLH-DSA-SHAKE-128s | 7.5 KiB | 7.3 KiB | 7.3 KiB | 7.6 KiB | 7.5 KiB | 7.3 KiB |
| SLH-DSA-SHAKE-128f | 6.3 KiB | 6.0 KiB | 6.0 KiB | 6.4 KiB | 6.3 KiB | 6.0 KiB |
| SLH-DSA-SHAKE-192s | 7.5 KiB | 7.3 KiB | 7.3 KiB | 7.6 KiB | 7.5 KiB | 7.3 KiB |
| SLH-DSA-SHAKE-192f | 6.3 KiB | 6.0 KiB | 6.0 KiB | 6.4 KiB | 6.3 KiB | 6.0 KiB |
| SLH-DSA-SHAKE-256s | 7.3 KiB | 7.1 KiB | 7.1 KiB | 7.4 KiB | 7.3 KiB | 7.1 KiB |
| SLH-DSA-SHAKE-256f | 6.5 KiB | 6.2 KiB | 6.2 KiB | 6.6 KiB | 6.5 KiB | 6.2 KiB |

### sign: heap allocated per op

| param | `sign.v0` | `sign.v1` | `sign.v2` | `sign.v3` | `sign.v4` | `sign.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 59.6 KiB | 58.7 KiB | 59.5 KiB | 59.6 KiB | 59.6 KiB | 58.7 KiB |
| ML-DSA-65 | 90.8 KiB | 89.9 KiB | 90.7 KiB | 90.8 KiB | 90.8 KiB | 89.9 KiB |
| ML-DSA-87 | 136.9 KiB | 136.0 KiB | 136.8 KiB | 136.9 KiB | 136.9 KiB | 136.0 KiB |
| SLH-DSA-SHA2-128s | 142.2 KiB | 140.3 KiB | 142.1 KiB | 142.2 KiB | 142.2 KiB | 140.3 KiB |
| SLH-DSA-SHA2-128f | 9.1 KiB | 7.1 KiB | 9.0 KiB | 9.1 KiB | 9.1 KiB | 7.1 KiB |
| SLH-DSA-SHA2-192s | 142.9 KiB | 140.4 KiB | 142.8 KiB | 142.9 KiB | 142.9 KiB | 140.4 KiB |
| SLH-DSA-SHA2-192f | 9.8 KiB | 7.3 KiB | 9.7 KiB | 9.8 KiB | 9.8 KiB | 7.3 KiB |
| SLH-DSA-SHA2-256s | 82.9 KiB | 80.4 KiB | 82.8 KiB | 82.9 KiB | 82.9 KiB | 80.4 KiB |
| SLH-DSA-SHA2-256f | 13.5 KiB | 11.0 KiB | 13.5 KiB | 13.5 KiB | 13.5 KiB | 11.0 KiB |
| SLH-DSA-SHAKE-128s | 141.6 KiB | 140.1 KiB | 141.5 KiB | 141.6 KiB | 141.6 KiB | 140.1 KiB |
| SLH-DSA-SHAKE-128f | 8.5 KiB | 7.0 KiB | 8.4 KiB | 8.5 KiB | 8.5 KiB | 7.0 KiB |
| SLH-DSA-SHAKE-192s | 141.6 KiB | 140.1 KiB | 141.5 KiB | 141.6 KiB | 141.6 KiB | 140.1 KiB |
| SLH-DSA-SHAKE-192f | 8.5 KiB | 7.0 KiB | 8.4 KiB | 8.5 KiB | 8.5 KiB | 7.0 KiB |
| SLH-DSA-SHAKE-256s | 81.6 KiB | 80.1 KiB | 81.5 KiB | 81.6 KiB | 81.6 KiB | 80.1 KiB |
| SLH-DSA-SHAKE-256f | 12.2 KiB | 10.7 KiB | 12.1 KiB | 12.2 KiB | 12.2 KiB | 10.7 KiB |

### verify: peak stack

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 3.3 KiB | 3.1 KiB | 3.1 KiB | 3.4 KiB | 3.3 KiB | 3.1 KiB |
| ML-DSA-65 | 3.3 KiB | 3.1 KiB | 3.1 KiB | 3.4 KiB | 3.3 KiB | 3.1 KiB |
| ML-DSA-87 | 3.3 KiB | 3.1 KiB | 3.1 KiB | 3.4 KiB | 3.3 KiB | 3.1 KiB |
| SLH-DSA-SHA2-128s | 6.7 KiB | 5.7 KiB | — | 5.6 KiB | 6.7 KiB | 5.7 KiB |
| SLH-DSA-SHA2-128f | 6.7 KiB | 5.7 KiB | — | 5.6 KiB | 6.7 KiB | 5.7 KiB |
| SLH-DSA-SHA2-192s | 7.7 KiB | 7.7 KiB | — | 5.6 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-192f | 7.7 KiB | 7.7 KiB | — | 5.6 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-256s | 7.7 KiB | 7.7 KiB | — | 5.6 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHA2-256f | 7.7 KiB | 7.7 KiB | — | 5.6 KiB | 7.7 KiB | 7.7 KiB |
| SLH-DSA-SHAKE-128s | 5.7 KiB | 5.4 KiB | — | 5.7 KiB | 5.4 KiB | 5.4 KiB |
| SLH-DSA-SHAKE-128f | 5.7 KiB | 5.4 KiB | — | 5.7 KiB | 5.4 KiB | 5.4 KiB |
| SLH-DSA-SHAKE-192s | 5.7 KiB | 5.4 KiB | — | 5.7 KiB | 5.4 KiB | 5.4 KiB |
| SLH-DSA-SHAKE-192f | 5.7 KiB | 5.4 KiB | — | 5.7 KiB | 5.4 KiB | 5.4 KiB |
| SLH-DSA-SHAKE-256s | 5.7 KiB | 5.4 KiB | — | 5.7 KiB | 5.4 KiB | 5.4 KiB |
| SLH-DSA-SHAKE-256f | 5.7 KiB | 5.4 KiB | — | 5.7 KiB | 5.4 KiB | 5.4 KiB |

### verify: heap allocated per op

| param | `verify.v0` | `verify.v1` | `verify.v2` | `verify.v3` | `verify.v4` | `verify.v5` |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 39.5 KiB | 38.7 KiB | 38.7 KiB | 39.5 KiB | 39.5 KiB | 38.7 KiB |
| ML-DSA-65 | 61.5 KiB | 60.7 KiB | 60.7 KiB | 61.5 KiB | 61.5 KiB | 60.7 KiB |
| ML-DSA-87 | 97.8 KiB | 97.0 KiB | 97.0 KiB | 97.8 KiB | 97.8 KiB | 97.0 KiB |
| SLH-DSA-SHA2-128s | 2.1 KiB | 544 B | — | 2.1 KiB | 2.1 KiB | 544 B |
| SLH-DSA-SHA2-128f | 2.7 KiB | 1.1 KiB | — | 2.7 KiB | 2.7 KiB | 1.1 KiB |
| SLH-DSA-SHA2-192s | 2.5 KiB | 648 B | — | 2.5 KiB | 2.5 KiB | 648 B |
| SLH-DSA-SHA2-192f | 3.1 KiB | 1.2 KiB | — | 3.1 KiB | 3.1 KiB | 1.2 KiB |
| SLH-DSA-SHA2-256s | 2.6 KiB | 688 B | — | 2.6 KiB | 2.6 KiB | 688 B |
| SLH-DSA-SHA2-256f | 2.9 KiB | 1.0 KiB | — | 2.9 KiB | 2.9 KiB | 1.0 KiB |
| SLH-DSA-SHAKE-128s | 1.9 KiB | 360 B | — | 1.9 KiB | 1.9 KiB | 360 B |
| SLH-DSA-SHAKE-128f | 2.4 KiB | 960 B | — | 2.4 KiB | 2.4 KiB | 960 B |
| SLH-DSA-SHAKE-192s | 1.9 KiB | 360 B | — | 1.9 KiB | 1.9 KiB | 360 B |
| SLH-DSA-SHAKE-192f | 2.4 KiB | 960 B | — | 2.4 KiB | 2.4 KiB | 960 B |
| SLH-DSA-SHAKE-256s | 1.9 KiB | 400 B | — | 1.9 KiB | 1.9 KiB | 400 B |
| SLH-DSA-SHAKE-256f | 2.3 KiB | 760 B | — | 2.3 KiB | 2.3 KiB | 760 B |

### verify-stage: peak stack

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 136 B | 856 B | — | 824 B | — | — | — | 600 B | 3.5 KiB | 3.0 KiB | 3.3 KiB |
| ML-DSA-65 | 136 B | 856 B | — | 824 B | — | — | — | 600 B | 3.5 KiB | 3.0 KiB | 3.3 KiB |
| ML-DSA-87 | 136 B | 856 B | — | 824 B | — | — | — | 600 B | 3.5 KiB | 3.0 KiB | 3.3 KiB |
| SLH-DSA-SHA2-128s | — | — | 3.7 KiB | — | 2.7 KiB | 1.7 KiB | 6.7 KiB | — | 6.7 KiB | 3.7 KiB | — |
| SLH-DSA-SHA2-128f | — | — | 3.7 KiB | — | 2.7 KiB | 1.7 KiB | 6.7 KiB | — | 6.7 KiB | 3.7 KiB | — |
| SLH-DSA-SHA2-192s | — | — | 3.7 KiB | — | 3.7 KiB | 3.7 KiB | 7.7 KiB | — | 7.7 KiB | 5.7 KiB | — |
| SLH-DSA-SHA2-192f | — | — | 3.7 KiB | — | 3.7 KiB | 3.7 KiB | 7.7 KiB | — | 7.7 KiB | 5.7 KiB | — |
| SLH-DSA-SHA2-256s | — | — | 3.7 KiB | — | 3.7 KiB | 3.7 KiB | 7.7 KiB | — | 7.7 KiB | 5.7 KiB | — |
| SLH-DSA-SHA2-256f | — | — | 3.7 KiB | — | 3.7 KiB | 3.7 KiB | 7.7 KiB | — | 7.7 KiB | 5.7 KiB | — |
| SLH-DSA-SHAKE-128s | — | — | 2.4 KiB | — | 1.7 KiB | 1.0 KiB | 5.8 KiB | — | 5.8 KiB | 3.9 KiB | — |
| SLH-DSA-SHAKE-128f | — | — | 2.4 KiB | — | 1.7 KiB | 1.0 KiB | 5.8 KiB | — | 5.8 KiB | 3.9 KiB | — |
| SLH-DSA-SHAKE-192s | — | — | 2.4 KiB | — | 1.7 KiB | 1.0 KiB | 5.8 KiB | — | 5.8 KiB | 3.9 KiB | — |
| SLH-DSA-SHAKE-192f | — | — | 2.4 KiB | — | 1.7 KiB | 1.0 KiB | 5.8 KiB | — | 5.8 KiB | 3.9 KiB | — |
| SLH-DSA-SHAKE-256s | — | — | 2.4 KiB | — | 1.7 KiB | 1.0 KiB | 5.8 KiB | — | 5.8 KiB | 3.9 KiB | — |
| SLH-DSA-SHAKE-256f | — | — | 2.4 KiB | — | 1.7 KiB | 1.0 KiB | 5.8 KiB | — | 5.8 KiB | 3.9 KiB | — |

### verify-stage: heap allocated per op

| param | `decode.v0` | `expandA.v0` | `fors.v0` | `hint_check.v0` | `hmsg.v0` | `ht_auth.v0` | `ht_wots.v0` | `mu.v0` | `total` | `total_best` | `w_approx.v0` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 0 B | 504 B | — | 544 B | — | — | — | 504 B | 2.0 KiB | 504 B | 504 B |
| ML-DSA-65 | 0 B | 504 B | — | 544 B | — | — | — | 504 B | 2.0 KiB | 504 B | 504 B |
| ML-DSA-87 | 0 B | 504 B | — | 544 B | — | — | — | 504 B | 2.0 KiB | 504 B | 504 B |
| SLH-DSA-SHA2-128s | — | — | 40 B | — | 184 B | 0 B | 280 B | — | 504 B | 0 B | — |
| SLH-DSA-SHA2-128f | — | — | 40 B | — | 184 B | 0 B | 880 B | — | 1.1 KiB | 0 B | — |
| SLH-DSA-SHA2-192s | — | — | 40 B | — | 288 B | 0 B | 280 B | — | 608 B | 0 B | — |
| SLH-DSA-SHA2-192f | — | — | 40 B | — | 288 B | 0 B | 880 B | — | 1.2 KiB | 0 B | — |
| SLH-DSA-SHA2-256s | — | — | 40 B | — | 288 B | 0 B | 320 B | — | 648 B | 0 B | — |
| SLH-DSA-SHA2-256f | — | — | 40 B | — | 288 B | 0 B | 680 B | — | 1008 B | 0 B | — |
| SLH-DSA-SHAKE-128s | — | — | 40 B | — | 0 B | 0 B | 280 B | — | 320 B | 0 B | — |
| SLH-DSA-SHAKE-128f | — | — | 40 B | — | 0 B | 0 B | 880 B | — | 920 B | 0 B | — |
| SLH-DSA-SHAKE-192s | — | — | 40 B | — | 0 B | 0 B | 280 B | — | 320 B | 0 B | — |
| SLH-DSA-SHAKE-192f | — | — | 40 B | — | 0 B | 0 B | 880 B | — | 920 B | 0 B | — |
| SLH-DSA-SHAKE-256s | — | — | 40 B | — | 0 B | 0 B | 320 B | — | 360 B | 0 B | — |
| SLH-DSA-SHAKE-256f | — | — | 40 B | — | 0 B | 0 B | 680 B | — | 720 B | 0 B | — |

