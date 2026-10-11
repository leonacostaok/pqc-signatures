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

_Preliminary numbers (development run, 4 params). stack_bytes: paint-and-scan high-water mark (resolution 64 B); heap/op: TotalAlloc delta per op; peak: HeapAlloc growth of one op with GC off._


**ML-DSA-44**

| variant | op | stage | threads | stack (B) | heap alloc / op (B) | heap peak (B) | match |
|---|---|---|---:|---:|---:|---:|---|
| keygen.v0 | keygen |  | 1 | 8,512 | 59,392 | 59,392 | True |
| keygen.v1 | keygen |  | 1 | 7,416 | 59,392 | 59,392 | True |
| keygen.v2 | keygen |  | 1 | 8,512 | 59,392 | 59,392 | True |
| keygen.v3 | keygen |  | 1 | 8,512 | 59,392 | 59,392 | True |
| keygen.v4 | keygen |  | 1 | 8,512 | 59,392 | 59,392 | True |
| keygen.v5 | keygen |  | 4 | 8,512 | 59,392 | 59,392 | True |
| sign.v0 | sign |  | 1 | 45,632 | 52,307 | 52,320 | True |
| sign.v1 | sign |  | 1 | 45,600 | 451 | 464 | True |
| sign.v2 | sign |  | 1 | 44,872 | 52,307 | 52,320 | True |
| sign.v3 | sign |  | 1 | 45,632 | 52,307 | 52,320 | True |
| sign.v4 | sign |  | 1 | 45,632 | 52,307 | 52,320 | True |
| sign.v5 | sign |  | 4 | 45,600 | 451 | 464 | True |
| verify.v0 | verify |  | 1 | 29,056 | 22,995 | 23,008 | True |
| verify.v1 | verify |  | 1 | 29,056 | 451 | 464 | True |
| verify.v2 | verify |  | 1 | 27,992 | 22,995 | 23,008 | True |
| verify.v3 | verify |  | 1 | 29,056 | 22,995 | 23,008 | True |
| verify.v4 | verify |  | 1 | 29,056 | 22,995 | 23,008 | True |
| verify.v5 | verify |  | 4 | 29,056 | 451 | 464 | True |
| decode.v0 | verify-stage | decode | 1 | 16,664 | 0 | 0 | True |
| expandA.v0 | verify-stage | expandA | 1 | 1,128 | 0 | 0 | True |
| hint_check.v0 | verify-stage | hint_check | 1 | 5,768 | 0 | 0 | True |
| mu.v0 | verify-stage | mu | 1 | 824 | 0 | 0 | True |
| total_best | verify-stage | total_best | 1 | 58,592 | 0 | 0 | True |
| w_approx.v0 | verify-stage | w_approx | 1 | 15,648 | 0 | 0 | True |

**ML-DSA-87**

| variant | op | stage | threads | stack (B) | heap alloc / op (B) | heap peak (B) | match |
|---|---|---|---:|---:|---:|---:|---|
| keygen.v0 | keygen |  | 1 | 13,888 | 125,440 | 125,440 | True |
| keygen.v1 | keygen |  | 1 | 12,792 | 125,440 | 125,440 | True |
| keygen.v2 | keygen |  | 1 | 13,888 | 125,440 | 125,440 | True |
| keygen.v3 | keygen |  | 1 | 13,888 | 125,440 | 125,440 | True |
| keygen.v4 | keygen |  | 1 | 13,888 | 125,440 | 125,440 | True |
| keygen.v5 | keygen |  | 4 | 13,888 | 125,440 | 125,440 | True |
| sign.v0 | sign |  | 1 | 83,808 | 111,827 | 111,840 | True |
| sign.v1 | sign |  | 1 | 83,776 | 451 | 464 | True |
| sign.v2 | sign |  | 1 | 83,112 | 111,827 | 111,840 | True |
| sign.v3 | sign |  | 1 | 83,808 | 111,827 | 111,840 | True |
| sign.v4 | sign |  | 1 | 83,808 | 111,827 | 111,840 | True |
| sign.v5 | sign |  | 4 | 83,776 | 451 | 464 | True |
| verify.v0 | verify |  | 1 | 51,904 | 68,691 | 68,704 | True |
| verify.v1 | verify |  | 1 | 51,904 | 451 | 464 | True |
| verify.v2 | verify |  | 1 | 50,840 | 68,691 | 68,704 | True |
| verify.v3 | verify |  | 1 | 51,904 | 68,691 | 68,704 | True |
| verify.v4 | verify |  | 1 | 51,904 | 68,691 | 68,704 | True |
| verify.v5 | verify |  | 4 | 51,904 | 451 | 464 | True |
| decode.v0 | verify-stage | decode | 1 | 31,032 | 0 | 0 | True |
| expandA.v0 | verify-stage | expandA | 1 | 1,128 | 0 | 0 | True |
| hint_check.v0 | verify-stage | hint_check | 1 | 9,896 | 0 | 0 | True |
| mu.v0 | verify-stage | mu | 1 | 824 | 0 | 0 | True |
| total_best | verify-stage | total_best | 1 | 133,920 | 0 | 0 | True |
| w_approx.v0 | verify-stage | w_approx | 1 | 26,912 | 0 | 0 | True |

**SLH-DSA-SHA2-128f**

| variant | op | stage | threads | stack (B) | heap alloc / op (B) | heap peak (B) | match |
|---|---|---|---:|---:|---:|---:|---|
| keygen.v0 | keygen |  | 1 | 4,256 | 1,408 | 1,408 | True |
| keygen.v1 | keygen |  | 1 | 4,024 | 1,408 | 1,408 | True |
| keygen.v2 | keygen |  | 1 | 4,248 | 1,408 | 1,408 | True |
| keygen.v3 | keygen |  | 1 | 4,024 | 584,704 | 584,704 | True |
| keygen.v4 | keygen |  | 1 | 4,256 | 1,408 | 1,408 | True |
| keygen.v5 | keygen |  | 4 | 4,256 | 1,408 | 1,408 | True |
| sign.v0 | sign |  | 1 | 3,960 | 46,606 | 46,616 | True |
| sign.v1 | sign |  | 1 | 3,936 | 27,958 | 27,968 | True |
| sign.v2 | sign |  | 1 | 3,728 | 46,606 | 46,616 | True |
| sign.v3 | sign |  | 1 | 3,952 | 46,606 | 46,616 | True |
| sign.v4 | sign |  | 1 | 3,784 | 13,913,742 | 13,913,752 | True |
| sign.v5 | sign |  | 4 | 3,936 | 27,955 | 27,968 | True |
| verify.v0 | verify |  | 1 | 3,672 | 8,718 | 8,728 | True |
| verify.v1 | verify |  | 1 | 3,664 | 8,582 | 8,592 | True |
| verify.v2 | verify |  | 1 | 3,440 | 8,718 | 8,728 | True |
| verify.v3 | verify |  | 1 | 3,672 | 8,718 | 8,728 | True |
| verify.v4 | verify |  | 1 | 4,064 | 830,865 | 830,872 | True |
| verify.v5 | verify |  | 4 | 3,664 | 8,579 | 8,592 | True |
| fors.v0 | verify-stage | fors | 1 | 1,696 | 48 | 48 | True |
| hmsg.v0 | verify-stage | hmsg | 1 | 2,496 | 8,000 | 8,000 | True |
| ht_auth.v0 | verify-stage | ht_auth | 1 | 1,728 | 704 | 704 | True |
| ht_wots.v0 | verify-stage | ht_wots | 1 | 1,896 | 704 | 704 | True |
| total_best | verify-stage | total_best | 1 | 3,008 | 10,616 | 10,616 | True |

**SLH-DSA-SHAKE-128f**

| variant | op | stage | threads | stack (B) | heap alloc / op (B) | heap peak (B) | match |
|---|---|---|---:|---:|---:|---:|---|
| keygen.v0 | keygen |  | 1 | 3,616 | 1,520 | 1,520 | True |
| keygen.v1 | keygen |  | 1 | 3,616 | 1,520 | 1,520 | True |
| keygen.v2 | keygen |  | 1 | 3,600 | 1,520 | 1,520 | True |
| keygen.v3 | keygen |  | 1 | 3,632 | 1,520 | 1,520 | True |
| keygen.v4 | keygen |  | 1 | 3,616 | 1,520 | 1,520 | True |
| keygen.v5 | keygen |  | 4 | 3,616 | 1,520 | 1,520 | True |
| sign.v0 | sign |  | 1 | 3,320 | 46,030 | 46,040 | True |
| sign.v1 | sign |  | 1 | 3,296 | 27,382 | 27,392 | True |
| sign.v2 | sign |  | 1 | 3,320 | 46,027 | 46,040 | True |
| sign.v3 | sign |  | 1 | 3,304 | 46,030 | 46,040 | True |
| sign.v4 | sign |  | 1 | 3,392 | 46,030 | 46,040 | True |
| sign.v5 | sign |  | 4 | 3,296 | 27,382 | 27,392 | True |
| verify.v0 | verify |  | 1 | 2,864 | 8,670 | 8,680 | True |
| verify.v1 | verify |  | 1 | 2,856 | 8,534 | 8,544 | True |
| verify.v2 | verify |  | 1 | 2,864 | 8,670 | 8,680 | True |
| verify.v3 | verify |  | 1 | 2,856 | 8,670 | 8,680 | True |
| verify.v4 | verify |  | 1 | 3,672 | 8,670 | 8,680 | True |
| verify.v5 | verify |  | 4 | 2,856 | 8,534 | 8,544 | True |
| fors.v0 | verify-stage | fors | 1 | 1,056 | 48 | 48 | True |
| hmsg.v0 | verify-stage | hmsg | 1 | 1,288 | 7,792 | 7,792 | True |
| ht_auth.v0 | verify-stage | ht_auth | 1 | 1,088 | 704 | 704 | True |
| ht_wots.v0 | verify-stage | ht_wots | 1 | 1,256 | 704 | 704 | True |
| total_best | verify-stage | total_best | 1 | 1,800 | 10,408 | 10,408 | True |
