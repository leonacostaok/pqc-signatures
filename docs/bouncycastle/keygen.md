# Bouncy Castle: keygen variants

Process: seed -> (pk, sk). ML-DSA: 32-byte xi expanded by `ML-DSA.KeyGen_internal` (SHAKE256 expansion of
rho/rho'/K, matrix A expansion with SHAKE128, rejection sampling of s1/s2, NTT, t = A s1 + s2, power2round,
tr = H(pk)). SLH-DSA: `slh_keygen_internal` computes `PK.root` by building the whole top XMSS tree
(2^h' WOTS+ key generations), which is why SLH-DSA keygen is far more expensive than ML-DSA keygen and is
dominated by hashing (SHA-256 or SHAKE256 compression calls).

Every variant feeds the same seed, so every op produces the reference pk/sk; both are compared to the
expected bytes on every iteration.

| id | name | what | why it might help |
|---|---|---|---|
| keygen.v0 | `jca` | **Baseline.** `KeyPairGenerator.getInstance("ML-DSA" or "SLH-DSA", "BC")`, `initialize(MLDSAParameterSpec/SLHDSAParameterSpec, seedRandom)`, `generateKeyPair()`; a fresh generator per op, exactly as the BC documentation shows. | - |
| keygen.v1 | `jca-reuse` | One JCA `KeyPairGenerator` created and initialised once, `generateKeyPair()` called repeatedly (the seed RNG is rewound before each call). | Skips the provider lookup (`Security` service map, reflection, `MLDSAKeyGenerationParameters` construction) per op. For ML-DSA keygen (~100 us) that overhead is a measurable fraction. |
| keygen.v2 | `lightweight` | BC lightweight API: `new MLDSAKeyPairGenerator()` / `new SLHDSAKeyPairGenerator()`, `init(new *KeyGenerationParameters(seedRandom, params))`, `generateKeyPair()`; returns `AsymmetricCipherKeyPair` with raw parameter objects. | No JCA layer at all: no `BCMLDSAPrivateKey`/`BCMLDSAPublicKey` wrapper allocation, no `KeyPair`, no `SecureRandom` default-DRBG lookup. |
| keygen.v3 | `internal-seed` | Seed expansion without any `SecureRandom`: ML-DSA `new MLDSAPrivateKeyParameters(params, seed32, null)` (BC recognises the 32-byte form and runs `generateKeyPairInternal`) then `getPublicKeyParameters()`; SLH-DSA `SLHDSAKeyPairGenerator.internalGenerateKeyPair(skSeed, skPrf, pkSeed)`. | Removes the RNG indirection and the generator object; it is also the cleanest expression of the FIPS `KeyGen_internal` entry point and the path the parallel variant uses. |
| keygen.v4 | `parallel` | Batch of `internal-seed` keygens spread over a fixed pool of `availableProcessors()` threads (4 here); the batch size is tuned so a batch lasts >= 40 ms. Reported numbers are throughput (wall per batch / batch size) and `threads = 4`. | Keygen is embarrassingly parallel and BC's engines are per-call objects with no shared mutable state, so a server generating many keys should scale with cores; this measures how well, including GC/alloc contention. |
| keygen.v5 | `parallelgc` | Same code as `lightweight` (v2) but in a child JVM started with `-XX:+UseParallelGC -Xms2g -Xmx2g -Xmn1200m -XX:+AlwaysPreTouch`. | ML-DSA keygen allocates several `PolyVec`/`int[256]` arrays per op (A matrix: k*l polynomials), SLH-DSA allocates many small `byte[]` per hash call. ParallelGC has cheaper allocation and no G1 write/read barriers, and a pre-touched 1.2 GB young generation makes minor collections rare during the measured loop. |

Implementation notes: `SeedRandom` (`Alg.java`) returns the seed bytes sequentially and is reset before each op
(v0-v2); v3/v4 slice the seed themselves. The JCA variants obtain the raw bytes for the match check via
`MLDSAPublicKey.getPublicData()`/`MLDSAPrivateKey.getPrivateData()`; the SLH-DSA JCA private key has no raw
accessor, so its PKCS#8 encoding is compared to a precomputed expected encoding (cheap, and outside the timed region).

## Preliminary conclusions (dev run, noisy shared box; final numbers come from the quiet run)

* ML-DSA keygen is ~100 us in BC, so the fixed per-call overhead of the JCA layer is visible: `internal-seed`, `jca-reuse`,
  `lightweight` and `parallelgc` all came out 3-20 % ahead of a fresh `KeyPairGenerator.getInstance` per op in
  different dev runs (the ordering between them flips from run to run, i.e. it is within the noise of the shared
  box); the quiet run has to decide which of provider lookup, SecureRandom indirection and allocation cost matters.
* SLH-DSA keygen (2-160 ms, pure hashing) is insensitive to all of this: every single-threaded variant is within
  noise of the baseline; only more cores help (`parallel`), and on the shared box that variant could not get its
  4 cores so its dev numbers are meaningless.

<!-- RESULTS -->

## Results (preliminary, --budget-ms 200 on a shared 4-core box)

Median wall time per op (us), process CPU per op (us), cpu_util, and speedup of median wall vs v0.
Parallel variants: wall = batch wall / batch size, i.e. throughput-equivalent per-op time on all cores.

### ML-DSA-44

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 1576 | 99.4 | 229.4 | 177.7 | 1.40 | 7,876.8 | 1.00x | True |
| keygen.v1 `jca-reuse` | 1735 | 97.0 | 200.0 | 115.3 | 1.00 | 8,672.9 | 1.03x | True |
| keygen.v2 `lightweight` | 1527 | 96.0 | 233.8 | 124.4 | 0.95 | 7,628.4 | 1.04x | True |
| keygen.v3 `internal-seed` | 1639 | 97.6 | 197.0 | 122.0 | 1.00 | 8,192.2 | 1.02x | True |
| keygen.v4 `parallel` (t=4) | 2496 | 77.2 | 133.9 | 132.2 | 1.61 | 12,193.8 | 1.29x | True |
| keygen.v5 `parallelgc` | 1297 | 153.2 | 210.4 | 285.3 | 1.85 | 6,482.7 | 0.65x | True |

### ML-DSA-65

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 571 | 191.1 | 481.2 | 385.3 | 1.09 | 2,822.8 | 1.00x | True |
| keygen.v1 `jca-reuse` | 1019 | 164.3 | 368.9 | 206.1 | 1.05 | 5,091.6 | 1.16x | True |
| keygen.v2 `lightweight` | 1123 | 161.8 | 229.6 | 178.1 | 1.00 | 5,610.4 | 1.18x | True |
| keygen.v3 `internal-seed` | 1067 | 160.2 | 233.5 | 187.4 | 1.00 | 5,333.1 | 1.19x | True |
| keygen.v4 `parallel` (t=4) | 1408 | 139.5 | 184.6 | 227.3 | 1.55 | 6,834.6 | 1.37x | True |
| keygen.v5 `parallelgc` | 1113 | 157.3 | 251.2 | 170.7 | 0.95 | 5,562.9 | 1.21x | True |

### ML-DSA-87

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 604 | 281.3 | 555.4 | 314.6 | 0.95 | 3,016.5 | 1.00x | True |
| keygen.v1 `jca-reuse` | 680 | 276.3 | 327.0 | 294.1 | 1.00 | 3,398.8 | 1.02x | True |
| keygen.v2 `lightweight` | 691 | 278.4 | 320.4 | 289.4 | 1.00 | 3,450.4 | 1.01x | True |
| keygen.v3 `internal-seed` | 512 | 314.2 | 587.6 | 390.6 | 1.00 | 2,558.6 | 0.90x | True |
| keygen.v4 `parallel` (t=4) | 768 | 276.3 | 326.9 | 468.8 | 1.75 | 3,735.4 | 1.02x | True |
| keygen.v5 `parallelgc` | 703 | 268.5 | 342.9 | 284.5 | 1.00 | 3,513.9 | 1.05x | True |

### SLH-DSA-SHA2-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 142,530.3 | 145,407.0 | 140,000.0 | 1.01 | 7.2 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 124,765.7 | 125,283.1 | 126,666.7 | 1.01 | 8.0 | 1.14x | True |
| keygen.v2 `lightweight` | 3 | 161,617.5 | 173,798.5 | 143,333.3 | 0.92 | 6.4 | 0.88x | True |
| keygen.v3 `internal-seed` | 3 | 146,283.1 | 146,752.4 | 133,333.3 | 0.96 | 7.2 | 0.97x | True |
| keygen.v4 `parallel` (t=4) | 4 | 92,392.9 | 92,392.9 | 175,000.0 | 1.89 | 10.8 | 1.54x | True |
| keygen.v5 `parallelgc` | 3 | 125,248.7 | 131,684.8 | 126,666.7 | 1.00 | 7.9 | 1.14x | True |

### SLH-DSA-SHA2-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 97 | 1,995.8 | 2,381.6 | 2,061.9 | 1.00 | 483.9 | 1.00x | True |
| keygen.v1 `jca-reuse` | 64 | 3,278.9 | 3,873.5 | 3,125.0 | 1.00 | 318.6 | 0.61x | True |
| keygen.v2 `lightweight` | 91 | 2,131.9 | 2,864.8 | 2,087.9 | 0.94 | 451.9 | 0.94x | True |
| keygen.v3 `internal-seed` | 100 | 1,960.2 | 2,278.4 | 2,000.0 | 1.00 | 498.6 | 1.02x | True |
| keygen.v4 `parallel` (t=4) | 160 | 1,438.7 | 1,465.1 | 2,250.0 | 1.74 | 775.4 | 1.39x | True |
| keygen.v5 `parallelgc` | 98 | 1,997.7 | 2,281.1 | 2,040.8 | 1.00 | 487.7 | 1.00x | True |

### SLH-DSA-SHA2-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 206,640.5 | 255,094.6 | 216,666.7 | 1.00 | 4.6 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 198,164.5 | 275,768.3 | 220,000.0 | 0.99 | 4.5 | 1.04x | True |
| keygen.v2 `lightweight` | 3 | 240,806.3 | 274,045.6 | 236,666.7 | 1.00 | 4.2 | 0.86x | True |
| keygen.v3 `internal-seed` | 3 | 189,899.3 | 193,934.8 | 190,000.0 | 1.00 | 5.2 | 1.09x | True |
| keygen.v4 `parallel` (t=4) | 4 | 107,495.1 | 107,495.1 | 227,500.0 | 2.12 | 9.3 | 1.92x | True |
| keygen.v5 `parallelgc` | 3 | 201,879.5 | 205,937.1 | 200,000.0 | 0.99 | 4.9 | 1.02x | True |

### SLH-DSA-SHA2-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 64 | 2,999.1 | 3,783.4 | 3,125.0 | 1.00 | 318.7 | 1.00x | True |
| keygen.v1 `jca-reuse` | 68 | 2,914.5 | 3,169.9 | 2,941.2 | 0.99 | 336.9 | 1.03x | True |
| keygen.v2 `lightweight` | 63 | 2,972.1 | 4,039.7 | 3,015.9 | 0.94 | 310.3 | 1.01x | True |
| keygen.v3 `internal-seed` | 41 | 3,431.6 | 7,254.3 | 7,317.1 | 1.45 | 198.5 | 0.87x | True |
| keygen.v4 `parallel` (t=4) | 128 | 1,950.2 | 2,428.9 | 3,437.5 | 1.87 | 542.6 | 1.54x | True |
| keygen.v5 `parallelgc` | 66 | 2,894.9 | 3,818.1 | 3,030.3 | 1.00 | 329.0 | 1.04x | True |

### SLH-DSA-SHA2-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 130,648.4 | 134,496.6 | 130,000.0 | 0.99 | 7.6 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 151,885.6 | 182,724.5 | 156,666.7 | 0.99 | 6.3 | 0.86x | True |
| keygen.v2 `lightweight` | 3 | 199,083.1 | 206,139.3 | 180,000.0 | 1.01 | 5.6 | 0.66x | True |
| keygen.v3 `internal-seed` | 3 | 130,264.2 | 131,264.3 | 130,000.0 | 1.00 | 7.7 | 1.00x | True |
| keygen.v4 `parallel` (t=4) | 4 | 68,647.0 | 68,647.0 | 147,500.0 | 2.15 | 14.6 | 1.90x | True |
| keygen.v5 `parallelgc` | 3 | 125,067.7 | 128,103.2 | 123,333.3 | 0.98 | 8.0 | 1.04x | True |

### SLH-DSA-SHA2-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 24 | 8,094.1 | 9,299.0 | 8,333.3 | 1.00 | 119.6 | 1.00x | True |
| keygen.v1 `jca-reuse` | 16 | 12,829.6 | 13,189.8 | 13,125.0 | 1.02 | 77.7 | 0.63x | True |
| keygen.v2 `lightweight` | 24 | 8,243.5 | 10,456.4 | 8,750.0 | 1.03 | 117.6 | 0.98x | True |
| keygen.v3 `internal-seed` | 24 | 8,272.3 | 10,518.4 | 8,750.0 | 1.00 | 114.8 | 0.98x | True |
| keygen.v4 `parallel` (t=4) | 48 | 4,304.8 | 5,636.7 | 8,958.3 | 1.97 | 220.3 | 1.88x | True |
| keygen.v5 `parallelgc` | 27 | 7,481.2 | 7,621.1 | 7,407.4 | 0.99 | 133.2 | 1.08x | True |

### SLH-DSA-SHAKE-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 143,911.8 | 144,368.4 | 143,333.3 | 1.00 | 6.9 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 146,061.9 | 147,112.5 | 146,666.7 | 1.00 | 6.8 | 0.99x | True |
| keygen.v2 `lightweight` | 3 | 161,843.5 | 189,650.5 | 160,000.0 | 0.95 | 6.0 | 0.89x | True |
| keygen.v3 `internal-seed` | 3 | 151,163.2 | 233,411.1 | 176,666.7 | 1.00 | 5.6 | 0.95x | True |
| keygen.v4 `parallel` (t=4) | 4 | 79,519.6 | 79,519.6 | 177,500.0 | 2.23 | 12.6 | 1.81x | True |
| keygen.v5 `parallelgc` | 3 | 147,158.1 | 147,646.6 | 146,666.7 | 1.00 | 6.8 | 0.98x | True |

### SLH-DSA-SHAKE-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 71 | 2,334.4 | 6,187.3 | 2,816.9 | 1.00 | 354.0 | 1.00x | True |
| keygen.v1 `jca-reuse` | 88 | 2,252.5 | 2,314.9 | 2,272.7 | 0.99 | 435.7 | 1.04x | True |
| keygen.v2 `lightweight` | 88 | 2,264.4 | 2,496.2 | 2,272.7 | 0.99 | 437.4 | 1.03x | True |
| keygen.v3 `internal-seed` | 79 | 2,307.1 | 3,902.0 | 2,658.2 | 1.04 | 390.7 | 1.01x | True |
| keygen.v4 `parallel` (t=4) | 160 | 1,235.3 | 2,046.2 | 2,500.0 | 1.99 | 796.7 | 1.89x | True |
| keygen.v5 `parallelgc` | 71 | 2,576.2 | 4,125.5 | 2,676.1 | 0.94 | 352.1 | 0.91x | True |

### SLH-DSA-SHAKE-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 217,829.2 | 311,267.1 | 246,666.7 | 0.99 | 4.0 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 247,963.7 | 264,831.4 | 246,666.7 | 1.00 | 4.0 | 0.88x | True |
| keygen.v2 `lightweight` | 3 | 228,921.1 | 242,715.4 | 230,000.0 | 0.99 | 4.3 | 0.95x | True |
| keygen.v3 `internal-seed` | 3 | 215,270.1 | 216,036.9 | 213,333.3 | 0.99 | 4.7 | 1.01x | True |
| keygen.v4 `parallel` (t=4) | 4 | 109,700.9 | 109,700.9 | 260,000.0 | 2.37 | 9.1 | 1.99x | True |
| keygen.v5 `parallelgc` | 3 | 246,082.3 | 311,730.2 | 256,666.7 | 0.98 | 3.8 | 0.89x | True |

### SLH-DSA-SHAKE-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 58 | 3,339.7 | 5,388.0 | 3,448.3 | 0.99 | 288.1 | 1.00x | True |
| keygen.v1 `jca-reuse` | 30 | 6,688.7 | 7,034.9 | 6,666.7 | 0.99 | 147.9 | 0.50x | True |
| keygen.v2 `lightweight` | 45 | 3,792.2 | 6,057.9 | 4,444.4 | 0.99 | 222.3 | 0.88x | True |
| keygen.v3 `internal-seed` | 60 | 3,329.7 | 3,481.4 | 3,333.3 | 1.00 | 298.8 | 1.00x | True |
| keygen.v4 `parallel` (t=4) | 112 | 2,005.0 | 2,299.1 | 4,285.7 | 2.10 | 490.1 | 1.67x | True |
| keygen.v5 `parallelgc` | 54 | 3,698.3 | 4,461.3 | 3,703.7 | 0.98 | 265.9 | 0.90x | True |

### SLH-DSA-SHAKE-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 146,622.6 | 150,115.7 | 146,666.7 | 1.00 | 6.8 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 145,472.3 | 150,384.3 | 146,666.7 | 1.00 | 6.8 | 1.01x | True |
| keygen.v2 `lightweight` | 3 | 160,264.0 | 170,900.6 | 160,000.0 | 0.99 | 6.2 | 0.91x | True |
| keygen.v3 `internal-seed` | 3 | 156,725.8 | 180,516.1 | 160,000.0 | 0.99 | 6.2 | 0.94x | True |
| keygen.v4 `parallel` (t=4) | 4 | 59,763.0 | 59,763.0 | 155,000.0 | 2.59 | 16.7 | 2.45x | True |
| keygen.v5 `parallelgc` | 3 | 172,754.8 | 209,892.3 | 176,666.7 | 0.98 | 5.5 | 0.85x | True |

### SLH-DSA-SHAKE-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 23 | 8,924.0 | 9,031.3 | 13,043.5 | 1.45 | 111.4 | 1.00x | True |
| keygen.v1 `jca-reuse` | 19 | 9,573.2 | 15,945.5 | 11,052.6 | 1.01 | 91.6 | 0.93x | True |
| keygen.v2 `lightweight` | 21 | 9,365.3 | 10,688.7 | 9,523.8 | 0.98 | 103.2 | 0.95x | True |
| keygen.v3 `internal-seed` | 22 | 9,089.1 | 9,705.1 | 9,090.9 | 0.99 | 109.4 | 0.98x | True |
| keygen.v4 `parallel` (t=4) | 32 | 7,077.5 | 7,570.0 | 12,187.5 | 1.86 | 152.6 | 1.26x | True |
| keygen.v5 `parallelgc` | 20 | 9,290.4 | 12,747.4 | 10,500.0 | 1.03 | 97.8 | 0.96x | True |

### Geometric mean speedup vs v0 across parameter sets

| variant | ML-DSA | SLH-DSA | all |
|---|---|---|---|
| keygen.v0 `jca` | 1.00x | 1.00x | 1.00x |
| keygen.v1 `jca-reuse` | 1.07x | 0.86x | 0.90x |
| keygen.v2 `lightweight` | 1.07x | 0.91x | 0.94x |
| keygen.v3 `internal-seed` | 1.03x | 0.98x | 0.99x |
| keygen.v4 `parallel` | 1.22x | 1.74x | 1.62x |
| keygen.v5 `parallelgc` | 0.94x | 0.98x | 0.97x |
