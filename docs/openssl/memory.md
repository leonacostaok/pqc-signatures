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

## Results (development run; stack/heap are deterministic, so these are not noisy)

### ML-DSA-44

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 2,152 | 47,280 | 42,192 | 1 | ✓ |
| `keygen.v1` | keygen | default | 1,944 | 47,048 | 41,960 | 1 | ✓ |
| `keygen.v2` | keygen | default | 1,960 | 47,100 | 41,960 | 1 | ✓ |
| `keygen.v5` | keygen | default | 1,944 | 47,048 | 41,960 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 2,192 | 47,280 | 42,192 | 1 | ✓ |
| `keygen.v4` | keygen | native | 2,440 | 47,280 | 42,192 | 1 | ✓ |
| `sign.v0` | sign | default | 3,672 | 61,016 | 60,464 | 1 | ✓ |
| `sign.v1` | sign | default | 3,416 | 60,152 | 59,680 | 1 | ✓ |
| `sign.v2` | sign | default | 3,416 | 60,936 | 60,464 | 1 | ✓ |
| `sign.v5` | sign | default | 3,416 | 60,152 | 59,680 | 4 | ✓ |
| `sign.v3` | sign | noasm | 3,824 | 61,016 | 60,464 | 1 | ✓ |
| `sign.v4` | sign | native | 4,344 | 61,016 | 60,464 | 1 | ✓ |
| `verify.v0` | verify | default | 3,416 | 40,496 | 39,984 | 1 | ✓ |
| `verify.v1` | verify | default | 3,128 | 39,632 | 39,200 | 1 | ✓ |
| `verify.v2` | verify | default | 3,128 | 39,632 | 39,200 | 1 | ✓ |
| `verify.v5` | verify | default | 3,128 | 39,632 | 39,200 | 4 | ✓ |
| `verify.v3` | verify | noasm | 3,488 | 40,496 | 39,984 | 1 | ✓ |
| `verify.v4` | verify | native | 3,352 | 40,496 | 39,984 | 1 | ✓ |
| `decode.v0` | verify-stage | default | 136 | 0 | 0 | 1 | ✓ |
| `expandA.v0` | verify-stage | default | 856 | 504 | 504 | 1 | ✓ |
| `hint_check.v0` | verify-stage | default | 824 | 544 | 504 | 1 | ✓ |
| `mu.v0` | verify-stage | default | 600 | 504 | 504 | 1 | ✓ |
| `total` | verify-stage | default | 3,544 | 2,056 | 504 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,080 | 504 | 504 | 1 | ✓ |
| `w_approx.v0` | verify-stage | default | 3,368 | 504 | 504 | 1 | ✓ |

### ML-DSA-65

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 2,152 | 73,968 | 66,768 | 1 | ✓ |
| `keygen.v1` | keygen | default | 1,944 | 73,736 | 66,536 | 1 | ✓ |
| `keygen.v2` | keygen | default | 1,960 | 73,788 | 66,536 | 1 | ✓ |
| `keygen.v5` | keygen | default | 1,944 | 73,736 | 66,536 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 2,192 | 73,968 | 66,768 | 1 | ✓ |
| `keygen.v4` | keygen | native | 2,440 | 73,968 | 66,768 | 1 | ✓ |
| `sign.v0` | sign | default | 3,672 | 92,960 | 92,208 | 1 | ✓ |
| `sign.v1` | sign | default | 3,416 | 92,096 | 91,424 | 1 | ✓ |
| `sign.v2` | sign | default | 3,416 | 92,880 | 92,208 | 1 | ✓ |
| `sign.v5` | sign | default | 3,416 | 92,096 | 91,424 | 4 | ✓ |
| `sign.v3` | sign | noasm | 3,824 | 92,960 | 92,208 | 1 | ✓ |
| `sign.v4` | sign | native | 4,344 | 92,960 | 92,208 | 1 | ✓ |
| `verify.v0` | verify | default | 3,416 | 63,024 | 62,512 | 1 | ✓ |
| `verify.v1` | verify | default | 3,128 | 62,160 | 61,728 | 1 | ✓ |
| `verify.v2` | verify | default | 3,128 | 62,160 | 61,728 | 1 | ✓ |
| `verify.v5` | verify | default | 3,128 | 62,160 | 61,728 | 4 | ✓ |
| `verify.v3` | verify | noasm | 3,488 | 63,024 | 62,512 | 1 | ✓ |
| `verify.v4` | verify | native | 3,352 | 63,024 | 62,512 | 1 | ✓ |
| `decode.v0` | verify-stage | default | 136 | 0 | 0 | 1 | ✓ |
| `expandA.v0` | verify-stage | default | 856 | 504 | 504 | 1 | ✓ |
| `hint_check.v0` | verify-stage | default | 824 | 544 | 504 | 1 | ✓ |
| `mu.v0` | verify-stage | default | 600 | 504 | 504 | 1 | ✓ |
| `total` | verify-stage | default | 3,544 | 2,056 | 504 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,080 | 504 | 504 | 1 | ✓ |
| `w_approx.v0` | verify-stage | default | 3,368 | 504 | 504 | 1 | ✓ |

### ML-DSA-87

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 2,152 | 114,384 | 105,680 | 1 | ✓ |
| `keygen.v1` | keygen | default | 1,944 | 114,152 | 105,448 | 1 | ✓ |
| `keygen.v2` | keygen | default | 1,960 | 114,204 | 105,448 | 1 | ✓ |
| `keygen.v5` | keygen | default | 1,944 | 114,152 | 105,448 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 2,192 | 114,384 | 105,680 | 1 | ✓ |
| `keygen.v4` | keygen | native | 2,440 | 114,384 | 105,680 | 1 | ✓ |
| `sign.v0` | sign | default | 3,672 | 140,160 | 139,568 | 1 | ✓ |
| `sign.v1` | sign | default | 3,416 | 139,296 | 138,784 | 1 | ✓ |
| `sign.v2` | sign | default | 3,416 | 140,080 | 139,568 | 1 | ✓ |
| `sign.v5` | sign | default | 3,416 | 139,296 | 138,784 | 4 | ✓ |
| `sign.v3` | sign | noasm | 3,824 | 140,160 | 139,568 | 1 | ✓ |
| `sign.v4` | sign | native | 4,344 | 140,160 | 139,568 | 1 | ✓ |
| `verify.v0` | verify | default | 3,416 | 100,144 | 99,632 | 1 | ✓ |
| `verify.v1` | verify | default | 3,128 | 99,280 | 98,848 | 1 | ✓ |
| `verify.v2` | verify | default | 3,128 | 99,280 | 98,848 | 1 | ✓ |
| `verify.v5` | verify | default | 3,128 | 99,280 | 98,848 | 4 | ✓ |
| `verify.v3` | verify | noasm | 3,488 | 100,144 | 99,632 | 1 | ✓ |
| `verify.v4` | verify | native | 3,352 | 100,144 | 99,632 | 1 | ✓ |
| `decode.v0` | verify-stage | default | 136 | 0 | 0 | 1 | ✓ |
| `expandA.v0` | verify-stage | default | 856 | 504 | 504 | 1 | ✓ |
| `hint_check.v0` | verify-stage | default | 824 | 544 | 504 | 1 | ✓ |
| `mu.v0` | verify-stage | default | 600 | 504 | 504 | 1 | ✓ |
| `total` | verify-stage | default | 3,544 | 2,056 | 504 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,080 | 504 | 504 | 1 | ✓ |
| `w_approx.v0` | verify-stage | default | 3,368 | 504 | 504 | 1 | ✓ |

### SLH-DSA-SHA2-128s

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 6,840 | 22,204 | 1,544 | 1 | ✓ |
| `keygen.v1` | keygen | default | 6,840 | 21,900 | 1,240 | 1 | ✓ |
| `keygen.v5` | keygen | default | 6,840 | 21,900 | 1,240 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 6,088 | 22,204 | 1,544 | 1 | ✓ |
| `keygen.v4` | keygen | native | 6,840 | 22,204 | 1,544 | 1 | ✓ |
| `sign.v0` | sign | default | 8,888 | 145,632 | 2,152 | 1 | ✓ |
| `sign.v1` | sign | default | 7,864 | 143,640 | 224 | 1 | ✓ |
| `sign.v2` | sign | default | 7,864 | 145,552 | 2,152 | 1 | ✓ |
| `sign.v5` | sign | default | 7,864 | 143,640 | 224 | 4 | ✓ |
| `sign.v3` | sign | noasm | 7,624 | 145,632 | 2,152 | 1 | ✓ |
| `sign.v4` | sign | native | 8,888 | 145,632 | 2,152 | 1 | ✓ |
| `verify.v0` | verify | default | 6,840 | 2,200 | 1,760 | 1 | ✓ |
| `verify.v1` | verify | default | 5,816 | 544 | 184 | 1 | ✓ |
| `verify.v5` | verify | default | 5,816 | 544 | 184 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,720 | 2,200 | 1,760 | 1 | ✓ |
| `verify.v4` | verify | native | 6,840 | 2,200 | 1,760 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 3,768 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 2,744 | 184 | 184 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,720 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 6,840 | 280 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 6,840 | 504 | 184 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,768 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHA2-128f

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 5,816 | 2,044 | 1,544 | 1 | ✓ |
| `keygen.v1` | keygen | default | 5,816 | 1,740 | 1,240 | 1 | ✓ |
| `keygen.v5` | keygen | default | 5,816 | 1,740 | 1,240 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 4,840 | 2,044 | 1,544 | 1 | ✓ |
| `keygen.v4` | keygen | native | 5,816 | 2,044 | 1,544 | 1 | ✓ |
| `sign.v0` | sign | default | 6,840 | 9,312 | 2,152 | 1 | ✓ |
| `sign.v1` | sign | default | 6,840 | 7,320 | 224 | 1 | ✓ |
| `sign.v2` | sign | default | 6,840 | 9,232 | 2,152 | 1 | ✓ |
| `sign.v5` | sign | default | 6,840 | 7,320 | 224 | 4 | ✓ |
| `sign.v3` | sign | noasm | 6,376 | 9,312 | 2,152 | 1 | ✓ |
| `sign.v4` | sign | native | 7,864 | 9,312 | 2,152 | 1 | ✓ |
| `verify.v0` | verify | default | 6,840 | 2,800 | 1,760 | 1 | ✓ |
| `verify.v1` | verify | default | 5,816 | 1,144 | 184 | 1 | ✓ |
| `verify.v5` | verify | default | 5,816 | 1,144 | 184 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,720 | 2,800 | 1,760 | 1 | ✓ |
| `verify.v4` | verify | native | 6,840 | 2,800 | 1,760 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 3,768 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 2,744 | 184 | 184 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,720 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 6,840 | 880 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 6,840 | 1,104 | 184 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,768 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHA2-192s

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 7,864 | 22,492 | 1,832 | 1 | ✓ |
| `keygen.v1` | keygen | default | 7,864 | 22,188 | 1,528 | 1 | ✓ |
| `keygen.v5` | keygen | default | 7,864 | 22,188 | 1,528 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 6,152 | 22,492 | 1,832 | 1 | ✓ |
| `keygen.v4` | keygen | native | 7,864 | 22,492 | 1,832 | 1 | ✓ |
| `sign.v0` | sign | default | 9,912 | 146,344 | 2,864 | 1 | ✓ |
| `sign.v1` | sign | default | 9,912 | 143,752 | 328 | 1 | ✓ |
| `sign.v2` | sign | default | 9,912 | 146,264 | 2,864 | 1 | ✓ |
| `sign.v5` | sign | default | 9,912 | 143,752 | 328 | 4 | ✓ |
| `sign.v3` | sign | noasm | 7,688 | 146,344 | 2,864 | 1 | ✓ |
| `sign.v4` | sign | native | 9,912 | 146,344 | 2,864 | 1 | ✓ |
| `verify.v0` | verify | default | 7,864 | 2,592 | 2,152 | 1 | ✓ |
| `verify.v1` | verify | default | 7,864 | 648 | 288 | 1 | ✓ |
| `verify.v5` | verify | default | 7,864 | 648 | 288 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,720 | 2,592 | 2,152 | 1 | ✓ |
| `verify.v4` | verify | native | 7,864 | 2,592 | 2,152 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 3,768 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 3,768 | 288 | 288 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 3,768 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 7,864 | 280 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 7,864 | 608 | 288 | 1 | ✓ |
| `total_best` | verify-stage | default | 5,816 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHA2-192f

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 7,864 | 2,332 | 1,832 | 1 | ✓ |
| `keygen.v1` | keygen | default | 7,864 | 2,028 | 1,528 | 1 | ✓ |
| `keygen.v5` | keygen | default | 7,864 | 2,028 | 1,528 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 4,904 | 2,332 | 1,832 | 1 | ✓ |
| `keygen.v4` | keygen | native | 7,864 | 2,332 | 1,832 | 1 | ✓ |
| `sign.v0` | sign | default | 7,864 | 10,024 | 2,864 | 1 | ✓ |
| `sign.v1` | sign | default | 7,864 | 7,432 | 328 | 1 | ✓ |
| `sign.v2` | sign | default | 7,864 | 9,944 | 2,864 | 1 | ✓ |
| `sign.v5` | sign | default | 7,864 | 7,432 | 328 | 4 | ✓ |
| `sign.v3` | sign | noasm | 6,440 | 10,024 | 2,864 | 1 | ✓ |
| `sign.v4` | sign | native | 7,864 | 10,024 | 2,864 | 1 | ✓ |
| `verify.v0` | verify | default | 7,864 | 3,192 | 2,152 | 1 | ✓ |
| `verify.v1` | verify | default | 7,864 | 1,248 | 288 | 1 | ✓ |
| `verify.v5` | verify | default | 7,864 | 1,248 | 288 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,720 | 3,192 | 2,152 | 1 | ✓ |
| `verify.v4` | verify | native | 7,864 | 3,192 | 2,152 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 3,768 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 3,768 | 288 | 288 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 3,768 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 7,864 | 880 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 7,864 | 1,208 | 288 | 1 | ✓ |
| `total_best` | verify-stage | default | 5,816 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHA2-256s

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 7,864 | 12,252 | 1,832 | 1 | ✓ |
| `keygen.v1` | keygen | default | 7,864 | 11,948 | 1,528 | 1 | ✓ |
| `keygen.v5` | keygen | default | 7,864 | 11,948 | 1,528 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 5,944 | 12,252 | 1,832 | 1 | ✓ |
| `keygen.v4` | keygen | native | 7,864 | 12,252 | 1,832 | 1 | ✓ |
| `sign.v0` | sign | default | 9,912 | 84,912 | 2,872 | 1 | ✓ |
| `sign.v1` | sign | default | 9,912 | 82,320 | 328 | 1 | ✓ |
| `sign.v2` | sign | default | 9,912 | 84,832 | 2,872 | 1 | ✓ |
| `sign.v5` | sign | default | 9,912 | 82,320 | 328 | 4 | ✓ |
| `sign.v3` | sign | noasm | 7,480 | 84,912 | 2,872 | 1 | ✓ |
| `sign.v4` | sign | native | 9,912 | 84,912 | 2,872 | 1 | ✓ |
| `verify.v0` | verify | default | 7,864 | 2,632 | 2,152 | 1 | ✓ |
| `verify.v1` | verify | default | 7,864 | 688 | 288 | 1 | ✓ |
| `verify.v5` | verify | default | 7,864 | 688 | 288 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,720 | 2,632 | 2,152 | 1 | ✓ |
| `verify.v4` | verify | native | 7,864 | 2,632 | 2,152 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 3,768 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 3,768 | 288 | 288 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 3,768 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 7,864 | 320 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 7,864 | 648 | 288 | 1 | ✓ |
| `total_best` | verify-stage | default | 5,816 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHA2-256f

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 7,864 | 2,652 | 1,832 | 1 | ✓ |
| `keygen.v1` | keygen | default | 7,864 | 2,348 | 1,528 | 1 | ✓ |
| `keygen.v5` | keygen | default | 7,864 | 2,348 | 1,528 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 5,112 | 2,652 | 1,832 | 1 | ✓ |
| `keygen.v4` | keygen | native | 7,864 | 2,652 | 1,832 | 1 | ✓ |
| `sign.v0` | sign | default | 7,864 | 13,872 | 2,872 | 1 | ✓ |
| `sign.v1` | sign | default | 7,864 | 11,280 | 328 | 1 | ✓ |
| `sign.v2` | sign | default | 7,864 | 13,792 | 2,872 | 1 | ✓ |
| `sign.v5` | sign | default | 7,864 | 11,280 | 328 | 4 | ✓ |
| `sign.v3` | sign | noasm | 6,648 | 13,872 | 2,872 | 1 | ✓ |
| `sign.v4` | sign | native | 9,912 | 13,872 | 2,872 | 1 | ✓ |
| `verify.v0` | verify | default | 7,864 | 2,992 | 2,152 | 1 | ✓ |
| `verify.v1` | verify | default | 7,864 | 1,048 | 288 | 1 | ✓ |
| `verify.v5` | verify | default | 7,864 | 1,048 | 288 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,720 | 2,992 | 2,152 | 1 | ✓ |
| `verify.v4` | verify | native | 7,864 | 2,992 | 2,152 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 3,768 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 3,768 | 288 | 288 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 3,768 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 7,864 | 680 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 7,864 | 1,008 | 288 | 1 | ✓ |
| `total_best` | verify-stage | default | 5,816 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHAKE-128s

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 6,152 | 22,092 | 1,432 | 1 | ✓ |
| `keygen.v1` | keygen | default | 5,944 | 21,788 | 1,128 | 1 | ✓ |
| `keygen.v5` | keygen | default | 5,944 | 21,788 | 1,128 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 6,224 | 22,092 | 1,432 | 1 | ✓ |
| `keygen.v4` | keygen | native | 5,944 | 22,092 | 1,432 | 1 | ✓ |
| `sign.v0` | sign | default | 7,688 | 144,984 | 1,544 | 1 | ✓ |
| `sign.v1` | sign | default | 7,432 | 143,440 | 80 | 1 | ✓ |
| `sign.v2` | sign | default | 7,432 | 144,904 | 1,544 | 1 | ✓ |
| `sign.v5` | sign | default | 7,432 | 143,440 | 80 | 4 | ✓ |
| `sign.v3` | sign | noasm | 7,760 | 144,984 | 1,544 | 1 | ✓ |
| `sign.v4` | sign | native | 7,672 | 144,984 | 1,544 | 1 | ✓ |
| `verify.v0` | verify | default | 5,800 | 1,904 | 1,544 | 1 | ✓ |
| `verify.v1` | verify | default | 5,512 | 360 | 40 | 1 | ✓ |
| `verify.v5` | verify | default | 5,512 | 360 | 40 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,872 | 1,904 | 1,544 | 1 | ✓ |
| `verify.v4` | verify | native | 5,496 | 1,904 | 1,544 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 2,504 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 1,752 | 0 | 0 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,032 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 5,928 | 280 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 5,960 | 320 | 40 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,944 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHAKE-128f

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 4,904 | 1,932 | 1,432 | 1 | ✓ |
| `keygen.v1` | keygen | default | 4,696 | 1,628 | 1,128 | 1 | ✓ |
| `keygen.v5` | keygen | default | 4,696 | 1,628 | 1,128 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 4,976 | 1,932 | 1,432 | 1 | ✓ |
| `keygen.v4` | keygen | native | 4,696 | 1,932 | 1,432 | 1 | ✓ |
| `sign.v0` | sign | default | 6,440 | 8,664 | 1,544 | 1 | ✓ |
| `sign.v1` | sign | default | 6,184 | 7,120 | 80 | 1 | ✓ |
| `sign.v2` | sign | default | 6,184 | 8,584 | 1,544 | 1 | ✓ |
| `sign.v5` | sign | default | 6,184 | 7,120 | 80 | 4 | ✓ |
| `sign.v3` | sign | noasm | 6,512 | 8,664 | 1,544 | 1 | ✓ |
| `sign.v4` | sign | native | 6,424 | 8,664 | 1,544 | 1 | ✓ |
| `verify.v0` | verify | default | 5,800 | 2,504 | 1,544 | 1 | ✓ |
| `verify.v1` | verify | default | 5,512 | 960 | 40 | 1 | ✓ |
| `verify.v5` | verify | default | 5,512 | 960 | 40 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,872 | 2,504 | 1,544 | 1 | ✓ |
| `verify.v4` | verify | native | 5,496 | 2,504 | 1,544 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 2,504 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 1,752 | 0 | 0 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,032 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 5,928 | 880 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 5,960 | 920 | 40 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,944 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHAKE-192s

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 6,152 | 22,092 | 1,432 | 1 | ✓ |
| `keygen.v1` | keygen | default | 5,944 | 21,788 | 1,128 | 1 | ✓ |
| `keygen.v5` | keygen | default | 5,944 | 21,788 | 1,128 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 6,224 | 22,092 | 1,432 | 1 | ✓ |
| `keygen.v4` | keygen | native | 5,944 | 22,092 | 1,432 | 1 | ✓ |
| `sign.v0` | sign | default | 7,688 | 144,984 | 1,544 | 1 | ✓ |
| `sign.v1` | sign | default | 7,432 | 143,440 | 80 | 1 | ✓ |
| `sign.v2` | sign | default | 7,432 | 144,904 | 1,544 | 1 | ✓ |
| `sign.v5` | sign | default | 7,432 | 143,440 | 80 | 4 | ✓ |
| `sign.v3` | sign | noasm | 7,760 | 144,984 | 1,544 | 1 | ✓ |
| `sign.v4` | sign | native | 7,672 | 144,984 | 1,544 | 1 | ✓ |
| `verify.v0` | verify | default | 5,800 | 1,904 | 1,544 | 1 | ✓ |
| `verify.v1` | verify | default | 5,512 | 360 | 40 | 1 | ✓ |
| `verify.v5` | verify | default | 5,512 | 360 | 40 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,872 | 1,904 | 1,544 | 1 | ✓ |
| `verify.v4` | verify | native | 5,496 | 1,904 | 1,544 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 2,504 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 1,752 | 0 | 0 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,032 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 5,928 | 280 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 5,960 | 320 | 40 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,944 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHAKE-192f

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 4,904 | 1,932 | 1,432 | 1 | ✓ |
| `keygen.v1` | keygen | default | 4,696 | 1,628 | 1,128 | 1 | ✓ |
| `keygen.v5` | keygen | default | 4,696 | 1,628 | 1,128 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 4,976 | 1,932 | 1,432 | 1 | ✓ |
| `keygen.v4` | keygen | native | 4,696 | 1,932 | 1,432 | 1 | ✓ |
| `sign.v0` | sign | default | 6,440 | 8,664 | 1,544 | 1 | ✓ |
| `sign.v1` | sign | default | 6,184 | 7,120 | 80 | 1 | ✓ |
| `sign.v2` | sign | default | 6,184 | 8,584 | 1,544 | 1 | ✓ |
| `sign.v5` | sign | default | 6,184 | 7,120 | 80 | 4 | ✓ |
| `sign.v3` | sign | noasm | 6,512 | 8,664 | 1,544 | 1 | ✓ |
| `sign.v4` | sign | native | 6,424 | 8,664 | 1,544 | 1 | ✓ |
| `verify.v0` | verify | default | 5,800 | 2,504 | 1,544 | 1 | ✓ |
| `verify.v1` | verify | default | 5,512 | 960 | 40 | 1 | ✓ |
| `verify.v5` | verify | default | 5,512 | 960 | 40 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,872 | 2,504 | 1,544 | 1 | ✓ |
| `verify.v4` | verify | native | 5,496 | 2,504 | 1,544 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 2,504 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 1,752 | 0 | 0 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,032 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 5,928 | 880 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 5,960 | 920 | 40 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,944 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHAKE-256s

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 5,944 | 11,852 | 1,432 | 1 | ✓ |
| `keygen.v1` | keygen | default | 5,736 | 11,548 | 1,128 | 1 | ✓ |
| `keygen.v5` | keygen | default | 5,736 | 11,548 | 1,128 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 6,016 | 11,852 | 1,432 | 1 | ✓ |
| `keygen.v4` | keygen | native | 5,736 | 11,852 | 1,432 | 1 | ✓ |
| `sign.v0` | sign | default | 7,480 | 83,544 | 1,544 | 1 | ✓ |
| `sign.v1` | sign | default | 7,224 | 82,000 | 80 | 1 | ✓ |
| `sign.v2` | sign | default | 7,224 | 83,464 | 1,544 | 1 | ✓ |
| `sign.v5` | sign | default | 7,224 | 82,000 | 80 | 4 | ✓ |
| `sign.v3` | sign | noasm | 7,552 | 83,544 | 1,544 | 1 | ✓ |
| `sign.v4` | sign | native | 7,464 | 83,544 | 1,544 | 1 | ✓ |
| `verify.v0` | verify | default | 5,800 | 1,944 | 1,544 | 1 | ✓ |
| `verify.v1` | verify | default | 5,512 | 400 | 40 | 1 | ✓ |
| `verify.v5` | verify | default | 5,512 | 400 | 40 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,872 | 1,944 | 1,544 | 1 | ✓ |
| `verify.v4` | verify | native | 5,496 | 1,944 | 1,544 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 2,504 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 1,752 | 0 | 0 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,032 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 5,928 | 320 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 5,960 | 360 | 40 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,944 | 0 | 0 | 1 | ✓ |

### SLH-DSA-SHAKE-256f

| variant | op | build | stack bytes | heap alloc/op | heap peak | threads | match |
|---|---|---|---|---|---|---|---|
| `keygen.v0` | keygen | default | 5,112 | 2,252 | 1,432 | 1 | ✓ |
| `keygen.v1` | keygen | default | 4,904 | 1,948 | 1,128 | 1 | ✓ |
| `keygen.v5` | keygen | default | 4,904 | 1,948 | 1,128 | 4 | ✓ |
| `keygen.v3` | keygen | noasm | 5,184 | 2,252 | 1,432 | 1 | ✓ |
| `keygen.v4` | keygen | native | 4,904 | 2,252 | 1,432 | 1 | ✓ |
| `sign.v0` | sign | default | 6,648 | 12,504 | 1,544 | 1 | ✓ |
| `sign.v1` | sign | default | 6,392 | 10,960 | 80 | 1 | ✓ |
| `sign.v2` | sign | default | 6,392 | 12,424 | 1,544 | 1 | ✓ |
| `sign.v5` | sign | default | 6,392 | 10,960 | 80 | 4 | ✓ |
| `sign.v3` | sign | noasm | 6,720 | 12,504 | 1,544 | 1 | ✓ |
| `sign.v4` | sign | native | 6,632 | 12,504 | 1,544 | 1 | ✓ |
| `verify.v0` | verify | default | 5,800 | 2,304 | 1,544 | 1 | ✓ |
| `verify.v1` | verify | default | 5,512 | 760 | 40 | 1 | ✓ |
| `verify.v5` | verify | default | 5,512 | 760 | 40 | 4 | ✓ |
| `verify.v3` | verify | noasm | 5,872 | 2,304 | 1,544 | 1 | ✓ |
| `verify.v4` | verify | native | 5,496 | 2,304 | 1,544 | 1 | ✓ |
| `fors.v0` | verify-stage | default | 2,504 | 40 | 40 | 1 | ✓ |
| `hmsg.v0` | verify-stage | default | 1,752 | 0 | 0 | 1 | ✓ |
| `ht_auth.v0` | verify-stage | default | 1,032 | 0 | 0 | 1 | ✓ |
| `ht_wots.v0` | verify-stage | default | 5,928 | 680 | 40 | 1 | ✓ |
| `total` | verify-stage | default | 5,960 | 720 | 40 | 1 | ✓ |
| `total_best` | verify-stage | default | 3,944 | 0 | 0 | 1 | ✓ |

