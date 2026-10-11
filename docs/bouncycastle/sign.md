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
| sign.v0 `jca` | 583 | 184.4 | 492.8 | 394.5 | 1.13 | 2,857.4 | 1.00x | True |
| sign.v1 `lightweight` | 745 | 211.8 | 432.1 | 241.6 | 0.90 | 3,722.1 | 0.87x | True |
| sign.v2 `reuse-signer` | 1112 | 162.8 | 223.7 | 179.9 | 1.00 | 5,556.6 | 1.13x | True |
| sign.v3 `parallel` (t=4) | 704 | 309.3 | 392.1 | 284.1 | 0.96 | 3,382.8 | 0.60x | True |
| sign.v4 `c2-only` | 498 | 384.5 | 505.4 | 522.1 | 1.30 | 2,485.6 | 0.48x | True |
| sign.v5 `epsilon-nogc` | 961 | 194.5 | 257.9 | 260.1 | 1.25 | 4,801.4 | 0.95x | True |

### ML-DSA-65

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 259 | 677.9 | 1,078.9 | 849.4 | 1.10 | 1,291.1 | 1.00x | True |
| sign.v1 `lightweight` | 290 | 657.4 | 870.7 | 1,241.4 | 1.80 | 1,447.0 | 1.03x | True |
| sign.v2 `reuse-signer` | 280 | 659.3 | 935.3 | 678.6 | 0.95 | 1,395.5 | 1.03x | True |
| sign.v3 `parallel` (t=4) | 264 | 771.0 | 1,058.7 | 719.7 | 0.90 | 1,243.6 | 0.88x | True |
| sign.v4 `c2-only` | 152 | 1,330.4 | 1,918.0 | 1,315.8 | 1.00 | 757.8 | 0.51x | True |
| sign.v5 `epsilon-nogc` | 272 | 710.5 | 862.5 | 772.1 | 1.05 | 1,357.1 | 0.95x | True |

### ML-DSA-87

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 354 | 500.8 | 572.2 | 565.0 | 1.00 | 1,767.5 | 1.00x | True |
| sign.v1 `lightweight` | 310 | 538.2 | 936.0 | 677.4 | 1.05 | 1,546.3 | 0.93x | True |
| sign.v2 `reuse-signer` | 329 | 513.8 | 975.9 | 607.9 | 1.00 | 1,641.3 | 0.97x | True |
| sign.v3 `parallel` (t=4) | 280 | 854.6 | 1,215.3 | 607.1 | 0.75 | 1,228.8 | 0.59x | True |
| sign.v4 `c2-only` | 315 | 570.1 | 758.9 | 666.7 | 1.04 | 1,560.8 | 0.88x | True |
| sign.v5 `epsilon-nogc` | 325 | 586.6 | 756.2 | 707.7 | 1.15 | 1,623.7 | 0.85x | True |

### SLH-DSA-SHA2-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 1,185,153.6 | 1,382,750.3 | 1,046,666.7 | 0.85 | 0.8 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,102,389.9 | 1,126,179.5 | 1,073,333.3 | 0.99 | 0.9 | 1.08x | True |
| sign.v2 `reuse-signer` | 3 | 1,061,178.1 | 1,454,465.8 | 1,113,333.3 | 0.93 | 0.8 | 1.12x | True |
| sign.v3 `parallel` (t=4) | 4 | 933,416.9 | 933,416.9 | 1,095,000.0 | 1.17 | 1.1 | 1.27x | True |
| sign.v4 `c2-only` | 3 | 1,073,431.6 | 1,082,442.9 | 1,066,666.7 | 1.00 | 0.9 | 1.10x | True |
| sign.v5 `epsilon-nogc` | 3 | 1,180,490.3 | 1,285,782.3 | 1,170,000.0 | 1.01 | 0.9 | 1.00x | True |

### SLH-DSA-SHA2-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 5 | 49,881.1 | 68,717.0 | 52,000.0 | 0.98 | 18.8 | 1.00x | True |
| sign.v1 `lightweight` | 4 | 51,030.3 | 53,434.4 | 80,000.0 | 1.57 | 19.6 | 0.98x | True |
| sign.v2 `reuse-signer` | 4 | 54,243.6 | 60,282.9 | 52,500.0 | 1.00 | 19.0 | 0.92x | True |
| sign.v3 `parallel` (t=4) | 8 | 52,477.6 | 52,477.6 | 65,000.0 | 1.29 | 19.8 | 0.95x | True |
| sign.v4 `c2-only` | 4 | 50,810.1 | 51,256.1 | 50,000.0 | 0.99 | 19.7 | 0.98x | True |
| sign.v5 `epsilon-nogc` | 5 | 48,050.6 | 48,671.0 | 48,000.0 | 1.00 | 20.8 | 1.04x | True |

### SLH-DSA-SHA2-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 2,112,524.5 | 2,188,637.5 | 1,870,000.0 | 0.88 | 0.5 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 2,024,976.5 | 2,190,909.7 | 1,943,333.3 | 0.95 | 0.5 | 1.04x | True |
| sign.v2 `reuse-signer` | 3 | 2,147,635.6 | 2,192,929.7 | 1,936,666.7 | 0.90 | 0.5 | 0.98x | True |
| sign.v3 `parallel` (t=4) | 4 | 1,102,879.7 | 1,102,879.7 | 1,927,500.0 | 1.75 | 0.9 | 1.92x | True |
| sign.v4 `c2-only` | 3 | 2,130,098.9 | 2,474,890.6 | 2,183,333.3 | 0.99 | 0.5 | 0.99x | True |
| sign.v5 `epsilon-nogc` | 3 | 3,029,135.3 | 3,170,575.6 | 2,903,333.3 | 0.99 | 0.3 | 0.70x | True |

### SLH-DSA-SHA2-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 106,140.2 | 126,376.4 | 86,666.7 | 0.80 | 9.2 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 86,827.7 | 87,009.0 | 83,333.3 | 0.97 | 11.6 | 1.22x | True |
| sign.v2 `reuse-signer` | 3 | 82,333.8 | 86,777.7 | 80,000.0 | 0.97 | 12.1 | 1.29x | True |
| sign.v3 `parallel` (t=4) | 4 | 77,553.0 | 77,553.0 | 90,000.0 | 1.16 | 12.9 | 1.37x | True |
| sign.v4 `c2-only` | 3 | 82,873.5 | 82,957.6 | 86,666.7 | 1.05 | 12.1 | 1.28x | True |
| sign.v5 `epsilon-nogc` | 3 | 156,052.0 | 188,008.4 | 143,333.3 | 0.98 | 6.8 | 0.68x | True |

### SLH-DSA-SHA2-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 2,121,985.9 | 2,224,343.1 | 1,733,333.3 | 0.81 | 0.5 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,773,213.8 | 1,874,970.8 | 1,750,000.0 | 0.98 | 0.6 | 1.20x | True |
| sign.v2 `reuse-signer` | 3 | 1,909,320.7 | 2,073,592.7 | 1,763,333.3 | 0.90 | 0.5 | 1.11x | True |
| sign.v3 `parallel` (t=4) | 4 | 1,464,484.1 | 1,464,484.1 | 1,810,000.0 | 1.24 | 0.7 | 1.45x | True |
| sign.v4 `c2-only` | 3 | 1,936,399.7 | 2,029,270.0 | 1,910,000.0 | 0.99 | 0.5 | 1.10x | True |
| sign.v5 `epsilon-nogc` | 3 | 2,609,987.0 | 2,900,205.9 | 2,653,333.3 | 0.99 | 0.4 | 0.81x | True |

### SLH-DSA-SHA2-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 246,023.4 | 256,504.3 | 170,000.0 | 0.70 | 4.1 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 202,634.4 | 206,666.6 | 193,333.3 | 0.99 | 5.1 | 1.21x | True |
| sign.v2 `reuse-signer` | 3 | 205,516.6 | 206,795.7 | 163,333.3 | 0.79 | 4.9 | 1.20x | True |
| sign.v3 `parallel` (t=4) | 4 | 176,156.5 | 176,156.5 | 187,500.0 | 1.06 | 5.7 | 1.40x | True |
| sign.v4 `c2-only` | 3 | 179,391.3 | 238,513.6 | 196,666.7 | 0.99 | 5.0 | 1.37x | True |
| sign.v5 `epsilon-nogc` | 3 | 183,441.1 | 296,727.6 | 223,333.3 | 1.02 | 4.6 | 1.34x | True |

### SLH-DSA-SHAKE-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 1,230,318.9 | 1,241,105.7 | 1,196,666.7 | 0.99 | 0.8 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 1,389,368.8 | 1,396,867.2 | 1,330,000.0 | 0.98 | 0.7 | 0.89x | True |
| sign.v2 `reuse-signer` | 3 | 1,481,101.6 | 1,548,032.6 | 1,200,000.0 | 0.86 | 0.7 | 0.83x | True |
| sign.v3 `parallel` (t=4) | 4 | 348,133.1 | 348,133.1 | 1,160,000.0 | 3.33 | 2.9 | 3.53x | True |
| sign.v4 `c2-only` | 3 | 1,452,067.9 | 1,479,573.7 | 1,410,000.0 | 1.02 | 0.7 | 0.85x | True |
| sign.v5 `epsilon-nogc` | 3 | 1,683,496.4 | 1,979,557.5 | 1,746,666.7 | 0.99 | 0.6 | 0.73x | True |

### SLH-DSA-SHAKE-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 4 | 55,329.8 | 55,594.1 | 55,000.0 | 1.00 | 18.2 | 1.00x | True |
| sign.v1 `lightweight` | 4 | 57,166.5 | 60,186.4 | 55,000.0 | 0.98 | 17.7 | 0.97x | True |
| sign.v2 `reuse-signer` | 4 | 55,647.8 | 66,518.6 | 55,000.0 | 0.94 | 17.2 | 0.99x | True |
| sign.v3 `parallel` (t=4) | 16 | 14,291.6 | 14,630.9 | 54,375.0 | 3.82 | 70.3 | 3.87x | True |
| sign.v4 `c2-only` | 4 | 55,675.7 | 56,541.3 | 57,500.0 | 1.04 | 18.0 | 0.99x | True |
| sign.v5 `epsilon-nogc` | 3 | 62,534.8 | 95,139.3 | 70,000.0 | 0.98 | 14.0 | 0.88x | True |

### SLH-DSA-SHAKE-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 2,211,295.0 | 2,249,283.8 | 2,096,666.7 | 0.98 | 0.5 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 2,446,219.8 | 2,669,950.1 | 2,120,000.0 | 0.85 | 0.4 | 0.90x | True |
| sign.v2 `reuse-signer` | 3 | 2,650,181.5 | 2,898,083.4 | 2,340,000.0 | 0.90 | 0.4 | 0.83x | True |
| sign.v3 `parallel` (t=4) | 4 | 758,418.6 | 758,418.6 | 2,155,000.0 | 2.84 | 1.3 | 2.92x | True |
| sign.v4 `c2-only` | 3 | 2,120,792.5 | 2,195,161.5 | 2,116,666.7 | 1.00 | 0.5 | 1.04x | True |
| sign.v5 `epsilon-nogc` | 3 | 3,316,808.7 | 3,503,214.3 | 3,340,000.0 | 0.99 | 0.3 | 0.67x | True |

### SLH-DSA-SHAKE-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 93,958.7 | 95,532.8 | 93,333.3 | 1.00 | 10.7 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 105,797.5 | 127,400.3 | 103,333.3 | 0.95 | 9.2 | 0.89x | True |
| sign.v2 `reuse-signer` | 3 | 106,085.2 | 108,867.1 | 90,000.0 | 0.89 | 9.9 | 0.89x | True |
| sign.v3 `parallel` (t=4) | 8 | 46,029.9 | 46,029.9 | 96,250.0 | 2.34 | 24.3 | 2.04x | True |
| sign.v4 `c2-only` | 3 | 90,230.9 | 97,085.7 | 93,333.3 | 1.01 | 10.8 | 1.04x | True |
| sign.v5 `epsilon-nogc` | 3 | 145,813.9 | 148,747.9 | 153,333.3 | 1.05 | 6.8 | 0.64x | True |

### SLH-DSA-SHAKE-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 2,039,444.7 | 2,119,022.3 | 2,016,666.7 | 0.99 | 0.5 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 2,034,346.7 | 2,255,600.6 | 1,963,333.3 | 0.94 | 0.5 | 1.00x | True |
| sign.v2 `reuse-signer` | 3 | 2,399,544.7 | 2,700,309.4 | 2,006,666.7 | 0.84 | 0.4 | 0.85x | True |
| sign.v3 `parallel` (t=4) | 4 | 1,160,591.4 | 1,160,591.4 | 2,180,000.0 | 1.88 | 0.9 | 1.76x | True |
| sign.v4 `c2-only` | 3 | 2,468,423.3 | 2,733,687.6 | 2,476,666.7 | 0.99 | 0.4 | 0.83x | True |
| sign.v5 `epsilon-nogc` | 3 | 3,170,311.9 | 3,284,779.1 | 3,176,666.7 | 0.99 | 0.3 | 0.64x | True |

### SLH-DSA-SHAKE-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| sign.v0 `jca` | 3 | 202,740.3 | 222,243.0 | 203,333.3 | 1.00 | 4.9 | 1.00x | True |
| sign.v1 `lightweight` | 3 | 212,801.1 | 221,446.1 | 196,666.7 | 0.94 | 4.8 | 0.95x | True |
| sign.v2 `reuse-signer` | 3 | 204,926.5 | 208,663.5 | 186,666.7 | 0.93 | 5.0 | 0.99x | True |
| sign.v3 `parallel` (t=4) | 4 | 112,642.6 | 112,642.6 | 210,000.0 | 1.86 | 8.9 | 1.80x | True |
| sign.v4 `c2-only` | 3 | 191,439.6 | 319,582.1 | 233,333.3 | 1.00 | 4.3 | 1.06x | True |
| sign.v5 `epsilon-nogc` | 3 | 337,688.0 | 340,890.2 | 326,666.7 | 0.98 | 3.0 | 0.60x | True |

### Geometric mean speedup vs v0 across parameter sets

| variant | ML-DSA | SLH-DSA | all |
|---|---|---|---|
| sign.v0 `jca` | 1.00x | 1.00x | 1.00x |
| sign.v1 `lightweight` | 0.94x | 1.02x | 1.00x |
| sign.v2 `reuse-signer` | 1.04x | 0.99x | 1.00x |
| sign.v3 `parallel` | 0.67x | 1.85x | 1.51x |
| sign.v4 `c2-only` | 0.60x | 1.04x | 0.93x |
| sign.v5 `epsilon-nogc` | 0.92x | 0.79x | 0.81x |
