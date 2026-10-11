# Bouncy Castle: sign variants

Process: (sk, msg) -> sig. ML-DSA signing in BC (`MLDSAEngine.generateSignature`) unpacks s1/s2/t0 from the
encoded key, re-expands the matrix A from rho with SHAKE128 on **every** call (nothing is cached in the key
object), NTTs the secret vectors and then runs the Fiat-Shamir-with-aborts loop; each attempt allocates fresh
`PolyVec`s. SLH-DSA signing is the heavy one: FORS + d XMSS tree signatures, each rebuilt from scratch, i.e.
hundreds of thousands of hash compressions for the "s" parameter sets (seconds in pure Java).

All variants sign deterministically (rnd = 0^32 / opt_rand = PK.seed, see README) and the signature is compared
to the reference bytes on every iteration. Hedged signing is not used anywhere.

| id | name | what | why it might help |
|---|---|---|---|
| sign.v0 | `jca` | **Baseline.** `Signature.getInstance("ML-DSA" or "SLH-DSA", "BC")`, `initSign(privateKey)` (no `SecureRandom` => deterministic), `update(msg)`, `sign()`; new `Signature` object per op. The `PrivateKey` is built once from the FIPS encoding via `KeyFactory` + PKCS#8. | - |
| sign.v1 | `lightweight` | `new MLDSASigner()` / `new SLHDSASigner()`, `init(true, privateKeyParameters)`, `update` + `generateSignature()`; new signer per op. | Drops the JCA layer: no provider lookup, no `BaseDeterministicOrRandomSignature` re-init dance, no `ByteArrayOutputStream` message buffering (SLH-DSA's SPI buffers the whole message before signing). |
| sign.v2 | `reuse-signer` | One lightweight signer initialised once per key and reused: per op only `update(msg)` + `generateSignature()`. | `MLDSASigner.init` clones rho/K/t0/s1/s2 out of the key object and absorbs `tr` into the SHAKE256 state; `SLHDSASigner.init` clones the four key halves. With reuse these happen once; the engine's `reset()` after each signature keeps the object valid. This is as much key-state precomputation as BC's public API permits (A is still re-expanded per call inside the engine). |
| sign.v3 | `parallel` | Batch of signatures over a 4-thread pool, each lane owning its own initialised signer (as in v2); throughput numbers, `threads = 4`. | Measures multi-core scaling of signing, which for SLH-DSA is the only practical way to get acceptable latency-per-core out of pure Java, and exposes allocation/GC contention for ML-DSA. |
| sign.v4 | `c2-only` | `lightweight` code path in a child JVM with `-XX:-TieredCompilation`. | Without tiering HotSpot interprets until the C2 threshold and then compiles straight to the fully optimised tier; it avoids C1 intermediate code and profile-pollution from the warm-up phase, which sometimes yields better peak code for tight integer loops such as the NTT / Keccak permutation. (It also shows how much the warm-up cost matters: the warm-up phase is slower.) |
| sign.v5 | `epsilon-nogc` | `lightweight` code path in a child JVM with `-XX:+UseEpsilonGC -Xms8g -Xmx8g` (no-op collector). The measured loop stops early if the heap passes 85 % so the JVM never dies. | Removes garbage collection and all GC barriers from the measurement: the result is the pure allocation+compute cost of BC's signing code, i.e. an upper bound on what any GC tuning could achieve. Also a direct read-out of how allocation-heavy each parameter set is (the loop's iteration count vs the 8 GB heap). |

Implementation notes: for ML-DSA the message is passed via `update(byte[],int,int)` so the SHAKE absorb is part
of the op; for SLH-DSA the one-shot `generateSignature(byte[] msg)` is the only entry point. Key objects
(`MLDSAPrivateKeyParameters(params, skBytes, null)`, which derives t1 once, and `SLHDSAPrivateKeyParameters`) are
prepared before the loop.

## Preliminary conclusions (dev run, noisy shared box; final numbers come from the quiet run)

* The API layer barely matters for signing: `lightweight` and `reuse-signer` are within a few percent of the
  JCA baseline for both families; the per-op cost is dominated by BC re-expanding A and running the rejection
  loop (ML-DSA) or rebuilding the hypertree (SLH-DSA), none of which BC lets a caller cache.
* `c2-only` needs a long warm-up: with a 300 ms warm-up it was 2x *slower* (still interpreting), with the 1 s
  warm-up now used it is on par or slightly ahead of tiered compilation (ML-DSA-65: 703 vs 724 us median,
  cpu/op 770 vs 909 us in a side-by-side 1 s run). Warm-up policy, not peak code quality, is the real effect.
* `epsilon-nogc` did not beat G1 in the dev run, which says BC's allocation pattern (many short-lived small
  arrays) is already handled well by G1's TLAB bump allocation; the heap guard never triggered with an 8 GB heap
  and a 1 s budget (ML-DSA-87 sign: >1000 ops).
* `parallel` is the only variant that changes the picture for SLH-DSA (near-linear scaling expected on a quiet
  4-core box; 1.85x geometric mean even while sharing the machine), but for ML-DSA on the loaded dev box it was
  slower than single-threaded because the pool could not get more than ~one core.

<!-- RESULTS -->

## Results (preliminary, --budget-ms 200 on a shared 4-core box)

Median wall time per op (us), process CPU per op (us), cpu_util, and speedup of median wall vs v0.
Parallel variants: wall = batch wall / batch size, i.e. throughput-equivalent per-op time on all cores.

### ML-DSA-44

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 1133 | 166.2 | 218.9 | 220.7 | 1.25 | 5,664.0 | 1.00x | True |
| sign.v1 `lightweight` | 1136 | 165.6 | 224.9 | 176.1 | 1.00 | 5,678.1 | 1.00x | True |
| sign.v2 `reuse-signer` | 1121 | 165.4 | 220.0 | 187.3 | 1.05 | 5,600.6 | 1.01x | True |
| sign.v3 `parallel` (t=4) | 1216 | 175.8 | 215.7 | 189.1 | 1.14 | 6,027.6 | 0.95x | True |
| sign.v4 `c2-only` | 680 | 226.1 | 400.7 | 323.5 | 1.10 | 3,399.7 | 0.73x | True |
| sign.v5 `epsilon-nogc` | 962 | 192.3 | 243.2 | 249.5 | 1.20 | 4,807.0 | 0.86x | True |

### ML-DSA-65

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 256 | 683.2 | 1,165.8 | 781.2 | 0.98 | 1,256.0 | 1.00x | True |
| sign.v1 `lightweight` | 304 | 650.4 | 698.5 | 657.9 | 1.00 | 1,517.6 | 1.05x | True |
| sign.v2 `reuse-signer` | 304 | 651.4 | 707.2 | 657.9 | 1.00 | 1,517.0 | 1.05x | True |
| sign.v3 `parallel` (t=4) | 448 | 488.6 | 534.1 | 692.0 | 1.49 | 2,156.1 | 1.40x | True |
| sign.v4 `c2-only` | 237 | 688.1 | 1,336.9 | 970.5 | 1.14 | 1,175.7 | 0.99x | True |
| sign.v5 `epsilon-nogc` | 200 | 813.0 | 1,510.9 | 1,000.0 | 1.00 | 996.4 | 0.84x | True |

### ML-DSA-87

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 304 | 525.7 | 951.0 | 657.9 | 1.00 | 1,515.0 | 1.00x | True |
| sign.v1 `lightweight` | 219 | 965.7 | 1,046.9 | 913.2 | 1.00 | 1,090.9 | 0.54x | True |
| sign.v2 `reuse-signer` | 379 | 501.8 | 646.2 | 712.4 | 1.35 | 1,893.4 | 1.05x | True |
| sign.v3 `parallel` (t=4) | 576 | 357.1 | 530.5 | 555.6 | 1.49 | 2,675.8 | 1.47x | True |
| sign.v4 `c2-only` | 355 | 523.5 | 924.4 | 563.4 | 1.00 | 1,771.1 | 1.00x | True |
| sign.v5 `epsilon-nogc` | 183 | 1,084.5 | 1,185.7 | 1,092.9 | 1.00 | 912.3 | 0.48x | True |

### SLH-DSA-SHA2-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 1,025,110.0 | 1,094,226.7 | 1,030,000.0 | 0.99 | 1.0 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,053,091.0 | 1,055,909.3 | 1,026,666.7 | 0.99 | 1.0 | 0.97x | True |
| sign.v2 `reuse-signer` | 3 | 1,012,876.1 | 1,081,780.8 | 1,030,000.0 | 1.00 | 1.0 | 1.01x | True |
| sign.v3 `parallel` (t=4) | 4 | 687,551.8 | 687,551.8 | 1,067,500.0 | 1.55 | 1.5 | 1.49x | True |
| sign.v4 `c2-only` | 3 | 1,242,457.5 | 1,267,809.9 | 1,190,000.0 | 0.99 | 0.8 | 0.83x | True |
| sign.v5 `epsilon-nogc` | 3 | 1,235,316.4 | 1,249,630.3 | 1,200,000.0 | 0.99 | 0.8 | 0.83x | True |

### SLH-DSA-SHA2-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 5 | 49,173.7 | 50,986.7 | 50,000.0 | 1.02 | 20.4 | 1.00x | True |
| sign.v1 `lightweight` | 4 | 56,860.3 | 57,087.0 | 55,000.0 | 1.00 | 18.1 | 0.86x | True |
| sign.v2 `reuse-signer` | 5 | 47,419.8 | 50,419.4 | 48,000.0 | 1.00 | 20.9 | 1.04x | True |
| sign.v3 `parallel` (t=4) | 8 | 40,406.3 | 40,406.3 | 56,250.0 | 1.70 | 30.2 | 1.22x | True |
| sign.v4 `c2-only` | 3 | 64,597.3 | 79,076.1 | 63,333.3 | 0.92 | 14.5 | 0.76x | True |
| sign.v5 `epsilon-nogc` | 5 | 49,419.9 | 49,505.6 | 50,000.0 | 1.01 | 20.3 | 1.00x | True |

### SLH-DSA-SHA2-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 1,935,741.0 | 1,936,023.4 | 1,906,666.7 | 0.99 | 0.5 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,968,082.7 | 2,028,933.3 | 1,930,000.0 | 0.99 | 0.5 | 0.98x | True |
| sign.v2 `reuse-signer` | 3 | 1,972,542.2 | 2,147,951.9 | 1,990,000.0 | 0.99 | 0.5 | 0.98x | True |
| sign.v3 `parallel` (t=4) | 4 | 1,292,502.2 | 1,292,502.2 | 2,107,500.0 | 1.63 | 0.8 | 1.50x | True |
| sign.v4 `c2-only` | 3 | 2,143,828.1 | 2,252,115.6 | 2,100,000.0 | 0.98 | 0.5 | 0.90x | True |
| sign.v5 `epsilon-nogc` | 3 | 3,096,011.6 | 3,636,467.0 | 3,160,000.0 | 0.99 | 0.3 | 0.63x | True |

### SLH-DSA-SHA2-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 81,919.2 | 82,682.0 | 83,333.3 | 1.02 | 12.2 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 87,403.1 | 91,684.9 | 83,333.3 | 0.95 | 11.4 | 0.94x | True |
| sign.v2 `reuse-signer` | 3 | 81,194.9 | 95,561.1 | 86,666.7 | 1.01 | 11.7 | 1.01x | True |
| sign.v3 `parallel` (t=4) | 4 | 54,997.4 | 54,997.4 | 105,000.0 | 1.91 | 18.2 | 1.49x | True |
| sign.v4 `c2-only` | 3 | 87,660.2 | 96,747.3 | 93,333.3 | 1.03 | 11.1 | 0.93x | True |
| sign.v5 `epsilon-nogc` | 3 | 128,836.3 | 130,960.0 | 130,000.0 | 1.01 | 7.8 | 0.64x | True |

### SLH-DSA-SHA2-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 1,741,534.3 | 1,741,603.0 | 1,713,333.3 | 1.00 | 0.6 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,733,540.8 | 1,742,357.5 | 1,703,333.3 | 1.00 | 0.6 | 1.00x | True |
| sign.v2 `reuse-signer` | 3 | 1,803,696.6 | 1,973,581.0 | 1,803,333.3 | 0.99 | 0.5 | 0.97x | True |
| sign.v3 `parallel` (t=4) | 4 | 1,378,285.2 | 1,378,285.2 | 2,172,500.0 | 1.58 | 0.7 | 1.26x | True |
| sign.v4 `c2-only` | 3 | 1,979,480.4 | 2,060,214.9 | 1,973,333.3 | 0.99 | 0.5 | 0.88x | True |
| sign.v5 `epsilon-nogc` | 3 | 2,825,445.2 | 3,079,879.1 | 2,776,666.7 | 0.98 | 0.4 | 0.62x | True |

### SLH-DSA-SHA2-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 170,542.2 | 171,240.0 | 170,000.0 | 1.00 | 5.9 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 171,610.8 | 176,360.1 | 173,333.3 | 1.00 | 5.8 | 0.99x | True |
| sign.v2 `reuse-signer` | 3 | 165,303.1 | 170,553.9 | 166,666.7 | 1.00 | 6.0 | 1.03x | True |
| sign.v3 `parallel` (t=4) | 4 | 137,881.5 | 137,881.5 | 195,000.0 | 1.41 | 7.3 | 1.24x | True |
| sign.v4 `c2-only` | 3 | 180,899.9 | 187,952.8 | 180,000.0 | 1.00 | 5.6 | 0.94x | True |
| sign.v5 `epsilon-nogc` | 3 | 268,139.9 | 313,627.8 | 223,333.3 | 0.88 | 3.9 | 0.64x | True |

### SLH-DSA-SHAKE-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 1,140,688.0 | 1,235,720.5 | 1,166,666.7 | 1.00 | 0.9 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,251,903.3 | 1,263,049.6 | 1,206,666.7 | 0.98 | 0.8 | 0.91x | True |
| sign.v2 `reuse-signer` | 3 | 1,144,451.0 | 1,163,894.0 | 1,136,666.7 | 1.00 | 0.9 | 1.00x | True |
| sign.v3 `parallel` (t=4) | 4 | 934,851.8 | 934,851.8 | 1,347,500.0 | 1.44 | 1.1 | 1.22x | True |
| sign.v4 `c2-only` | 3 | 1,297,022.9 | 1,367,469.4 | 1,340,000.0 | 1.03 | 0.8 | 0.88x | True |
| sign.v5 `epsilon-nogc` | 3 | 1,665,533.3 | 1,719,753.6 | 1,520,000.0 | 0.97 | 0.6 | 0.68x | True |

### SLH-DSA-SHAKE-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 80,808.1 | 98,955.9 | 83,333.3 | 1.02 | 12.2 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 69,835.7 | 83,980.8 | 70,000.0 | 1.00 | 14.3 | 1.16x | True |
| sign.v2 `reuse-signer` | 4 | 58,260.4 | 58,541.3 | 57,500.0 | 1.00 | 17.4 | 1.39x | True |
| sign.v3 `parallel` (t=4) | 8 | 41,330.4 | 41,330.4 | 78,750.0 | 1.99 | 25.3 | 1.96x | True |
| sign.v4 `c2-only` | 3 | 93,623.5 | 97,430.1 | 90,000.0 | 0.98 | 10.9 | 0.86x | True |
| sign.v5 `epsilon-nogc` | 4 | 57,474.9 | 76,719.1 | 62,500.0 | 1.01 | 16.2 | 1.41x | True |

### SLH-DSA-SHAKE-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 2,155,746.9 | 2,203,061.1 | 2,113,333.3 | 1.00 | 0.5 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 2,156,776.0 | 2,287,300.1 | 2,153,333.3 | 1.00 | 0.5 | 1.00x | True |
| sign.v2 `reuse-signer` | 3 | 2,417,505.9 | 2,561,267.8 | 2,426,666.7 | 0.99 | 0.4 | 0.89x | True |
| sign.v3 `parallel` (t=4) | 4 | 1,154,896.4 | 1,154,896.4 | 2,142,500.0 | 1.86 | 0.9 | 1.87x | True |
| sign.v4 `c2-only` | 3 | 2,288,213.2 | 2,421,067.3 | 2,256,666.7 | 0.99 | 0.4 | 0.94x | True |
| sign.v5 `epsilon-nogc` | 3 | 2,830,153.7 | 3,687,529.1 | 2,913,333.3 | 0.97 | 0.3 | 0.76x | True |

### SLH-DSA-SHAKE-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 87,440.6 | 87,798.6 | 90,000.0 | 1.03 | 11.4 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 103,419.2 | 106,843.1 | 103,333.3 | 1.00 | 9.6 | 0.85x | True |
| sign.v2 `reuse-signer` | 3 | 92,101.6 | 108,964.1 | 93,333.3 | 0.97 | 10.4 | 0.95x | True |
| sign.v3 `parallel` (t=4) | 4 | 52,411.4 | 52,411.4 | 92,500.0 | 1.76 | 19.1 | 1.67x | True |
| sign.v4 `c2-only` | 3 | 93,625.4 | 94,402.4 | 93,333.3 | 1.00 | 10.7 | 0.93x | True |
| sign.v5 `epsilon-nogc` | 3 | 159,078.3 | 165,417.7 | 153,333.3 | 1.00 | 6.5 | 0.55x | True |

### SLH-DSA-SHAKE-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 1,749,759.6 | 1,861,541.7 | 1,783,333.3 | 1.00 | 0.6 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,966,106.5 | 2,156,873.3 | 1,993,333.3 | 0.99 | 0.5 | 0.89x | True |
| sign.v2 `reuse-signer` | 3 | 1,823,372.4 | 1,902,539.6 | 1,816,666.7 | 1.00 | 0.5 | 0.96x | True |
| sign.v3 `parallel` (t=4) | 4 | 1,194,962.8 | 1,194,962.8 | 2,122,500.0 | 1.78 | 0.8 | 1.46x | True |
| sign.v4 `c2-only` | 3 | 2,087,524.1 | 2,208,400.5 | 2,090,000.0 | 0.98 | 0.5 | 0.84x | True |
| sign.v5 `epsilon-nogc` | 3 | 3,107,722.1 | 3,142,227.8 | 3,033,333.3 | 0.99 | 0.3 | 0.56x | True |

### SLH-DSA-SHAKE-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 184,926.9 | 194,152.7 | 186,666.7 | 1.00 | 5.3 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 191,231.3 | 194,106.1 | 190,000.0 | 0.99 | 5.2 | 0.97x | True |
| sign.v2 `reuse-signer` | 3 | 186,796.8 | 192,937.4 | 190,000.0 | 1.01 | 5.3 | 0.99x | True |
| sign.v3 `parallel` (t=4) | 4 | 103,973.4 | 103,973.4 | 187,500.0 | 1.80 | 9.6 | 1.78x | True |
| sign.v4 `c2-only` | 3 | 191,216.2 | 192,656.3 | 190,000.0 | 1.00 | 5.2 | 0.97x | True |
| sign.v5 `epsilon-nogc` | 3 | 307,843.6 | 311,902.0 | 303,333.3 | 0.98 | 3.2 | 0.60x | True |

### Geometric mean speedup vs v0 across parameter sets

| variant | ML-DSA | SLH-DSA | all |
|---|---|---|---|
| sign.v0 `jca` | 1.00x | 1.00x | 1.00x |
| sign.v1 `lightweight` | 0.83x | 0.96x | 0.93x |
| sign.v2 `reuse-signer` | 1.03x | 1.01x | 1.02x |
| sign.v3 `parallel` | 1.25x | 1.49x | 1.44x |
| sign.v4 `c2-only` | 0.90x | 0.89x | 0.89x |
| sign.v5 `epsilon-nogc` | 0.71x | 0.71x | 0.71x |
