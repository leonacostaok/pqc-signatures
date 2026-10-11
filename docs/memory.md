# Memory: stack and heap per operation

Measured for keygen, sign and verify, for every variant, and for each verify stage, by `run.sh memory`.

| runtime | stack method | resolution | heap method |
|---|---|---|---|
| C (liboqs, OpenSSL) | run the op on a self-allocated pthread stack painted with a pattern; scan for the deepest overwritten byte | 16 B | interposed allocator / `CRYPTO_set_mem_functions` counting bytes allocated and peak live |
| Rust | same painting on an mmap'd stack via `pthread_attr_setstack`, empty-closure baseline subtracted | 16 B | counting `GlobalAlloc` around the op (allocated + peak live) |
| Go | pre-grow a goroutine stack (~4 MiB), paint the unused part via `unsafe`, GC and async preemption off, scan; null if the stack was moved | 64 B | `runtime.MemStats` TotalAlloc / HeapAlloc deltas with GC off |
| JavaScript (V8, JSC) | in-process recursion probe: how deep a calibrated frame can recurse before and after the op leaves room, JIT-warmed (`--stack-size` subprocess search was too coarse: module loading alone needs more than any op) | ≈ 0.4 KiB | V8 sampling heap profiler allocation per op; Bun: n/a |
| Java (HotSpot) | recursion probe in a 2 MiB thread: deepest constant-size recursion that still completes the op without StackOverflowError, binary-searched, after JIT warm-up (plain `Thread(stackSize)` search fails: HotSpot silently raises small sizes) | 16 B | `ThreadMXBean.getThreadAllocatedBytes` per op |

What to read from it:
- **Stack** is what matters on embedded targets and in small-stack threads. Pure iterative implementations (noble,
  Bouncy Castle, OpenSSL) stay at a few KiB. Implementations that keep whole matrices or parsed signatures in local
  variables (RustCrypto, circl for ML-DSA) need tens to hundreds of KiB.
- **Heap allocated per op** is what drives GC pressure in managed runtimes (JS, Java, Go), and it varies by orders of
  magnitude between variants (caching variants allocate almost nothing).
- Methods differ by runtime, so compare within a language more than across.

Results: [../RESULTS.md](../RESULTS.md) (Memory section) and `docs/<lib>/memory.md`.
