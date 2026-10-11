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

* ML-DSA keygen is ~100 us in BC, so the fixed per-call overhead of the JCA layer is visible: `internal-seed` and
  `jca-reuse` were ~15-20 % faster than a fresh `KeyPairGenerator.getInstance` per op, and `parallelgc` gained a
  similar amount by making the PolyVec allocations cheaper. `lightweight` with a fresh generator object was no
  better than JCA, i.e. the cost is in the per-op provider lookup/initialisation, not in the key wrapper objects.
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
| keygen.v0 `jca` | 1170 | 120.2 | 255.8 | 196.6 | 1.15 | 5,847.6 | 1.00x | True |
| keygen.v1 `jca-reuse` | 1278 | 102.3 | 197.4 | 125.2 | 0.80 | 6,387.9 | 1.17x | True |
| keygen.v2 `lightweight` | 1695 | 99.7 | 229.7 | 118.0 | 1.00 | 8,467.7 | 1.20x | True |
| keygen.v3 `internal-seed` | 1669 | 95.3 | 145.0 | 107.8 | 0.89 | 8,254.0 | 1.26x | True |
| keygen.v4 `parallel` (t=4) | 1600 | 115.0 | 215.9 | 131.2 | 1.00 | 7,609.8 | 1.05x | True |
| keygen.v5 `parallelgc` | 1039 | 96.6 | 172.5 | 211.7 | 1.10 | 5,193.0 | 1.24x | True |

### ML-DSA-65

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 809 | 209.6 | 386.6 | 234.9 | 0.95 | 4,042.3 | 1.00x | True |
| keygen.v1 `jca-reuse` | 1016 | 161.7 | 273.4 | 187.0 | 0.95 | 5,079.4 | 1.30x | True |
| keygen.v2 `lightweight` | 774 | 262.0 | 335.7 | 245.5 | 0.95 | 3,869.4 | 0.80x | True |
| keygen.v3 `internal-seed` | 659 | 160.5 | 229.2 | 197.3 | 0.65 | 3,293.2 | 1.31x | True |
| keygen.v4 `parallel` (t=4) | 896 | 189.2 | 363.4 | 234.4 | 1.03 | 4,401.3 | 1.11x | True |
| keygen.v5 `parallelgc` | 1103 | 159.0 | 247.7 | 253.9 | 1.40 | 5,511.5 | 1.32x | True |

### ML-DSA-87

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 612 | 281.2 | 499.6 | 408.5 | 1.25 | 3,054.7 | 1.00x | True |
| keygen.v1 `jca-reuse` | 547 | 277.6 | 362.3 | 310.8 | 0.85 | 2,734.8 | 1.01x | True |
| keygen.v2 `lightweight` | 592 | 292.0 | 540.0 | 320.9 | 0.95 | 2,956.8 | 0.96x | True |
| keygen.v3 `internal-seed` | 403 | 283.3 | 544.2 | 347.4 | 0.70 | 2,012.1 | 0.99x | True |
| keygen.v4 `parallel` (t=4) | 720 | 282.7 | 322.1 | 291.7 | 1.00 | 3,416.1 | 0.99x | True |
| keygen.v5 `parallelgc` | 614 | 260.5 | 435.6 | 293.2 | 0.88 | 3,013.2 | 1.08x | True |

### SLH-DSA-SHA2-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 138,848.9 | 141,870.4 | 133,333.3 | 0.97 | 7.3 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 152,283.4 | 152,914.7 | 133,333.3 | 0.92 | 6.9 | 0.91x | True |
| keygen.v2 `lightweight` | 3 | 134,811.3 | 201,621.5 | 153,333.3 | 0.99 | 6.4 | 1.03x | True |
| keygen.v3 `internal-seed` | 3 | 142,009.3 | 146,387.8 | 133,333.3 | 0.94 | 7.1 | 0.98x | True |
| keygen.v4 `parallel` (t=4) | 4 | 162,624.0 | 162,624.0 | 150,000.0 | 0.92 | 6.1 | 0.85x | True |
| keygen.v5 `parallelgc` | 3 | 129,935.6 | 135,189.5 | 130,000.0 | 1.00 | 7.7 | 1.07x | True |

### SLH-DSA-SHA2-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 98 | 1,995.4 | 2,277.1 | 2,142.9 | 1.04 | 486.1 | 1.00x | True |
| keygen.v1 `jca-reuse` | 86 | 2,033.5 | 2,631.9 | 2,209.3 | 0.95 | 428.3 | 0.98x | True |
| keygen.v2 `lightweight` | 70 | 3,034.4 | 3,632.5 | 2,714.3 | 0.95 | 349.2 | 0.66x | True |
| keygen.v3 `internal-seed` | 88 | 2,036.7 | 2,792.8 | 2,272.7 | 1.00 | 438.6 | 0.98x | True |
| keygen.v4 `parallel` (t=4) | 96 | 2,089.1 | 2,792.2 | 2,291.7 | 1.09 | 476.9 | 0.96x | True |
| keygen.v5 `parallelgc` | 90 | 1,974.3 | 3,084.1 | 2,222.2 | 0.98 | 440.7 | 1.01x | True |

### SLH-DSA-SHA2-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 199,370.2 | 219,251.4 | 203,333.3 | 0.99 | 4.9 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 211,700.8 | 250,817.5 | 206,666.7 | 0.94 | 4.5 | 0.94x | True |
| keygen.v2 `lightweight` | 3 | 194,958.2 | 254,513.3 | 213,333.3 | 1.00 | 4.7 | 1.02x | True |
| keygen.v3 `internal-seed` | 3 | 206,682.3 | 273,084.5 | 203,333.3 | 0.89 | 4.4 | 0.96x | True |
| keygen.v4 `parallel` (t=4) | 4 | 158,268.7 | 158,268.7 | 215,000.0 | 1.36 | 6.3 | 1.26x | True |
| keygen.v5 `parallelgc` | 3 | 191,795.5 | 230,549.9 | 190,000.0 | 0.93 | 4.9 | 1.04x | True |

### SLH-DSA-SHA2-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 58 | 3,066.2 | 4,561.4 | 3,448.3 | 0.99 | 287.6 | 1.00x | True |
| keygen.v1 `jca-reuse` | 31 | 6,935.8 | 10,179.4 | 4,193.5 | 0.64 | 153.0 | 0.44x | True |
| keygen.v2 `lightweight` | 50 | 4,127.5 | 5,149.7 | 4,000.0 | 0.99 | 248.0 | 0.74x | True |
| keygen.v3 `internal-seed` | 46 | 3,074.1 | 8,770.9 | 3,478.3 | 0.79 | 227.9 | 1.00x | True |
| keygen.v4 `parallel` (t=4) | 60 | 3,353.5 | 3,456.6 | 3,333.3 | 0.99 | 296.9 | 0.91x | True |
| keygen.v5 `parallelgc` | 60 | 3,040.5 | 5,215.4 | 3,333.3 | 0.98 | 292.7 | 1.01x | True |

### SLH-DSA-SHA2-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 123,882.3 | 124,927.5 | 133,333.3 | 1.07 | 8.1 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 152,228.8 | 173,799.6 | 150,000.0 | 0.94 | 6.3 | 0.81x | True |
| keygen.v2 `lightweight` | 3 | 130,794.4 | 136,874.2 | 130,000.0 | 0.99 | 7.6 | 0.95x | True |
| keygen.v3 `internal-seed` | 3 | 169,754.7 | 173,379.0 | 130,000.0 | 0.77 | 5.9 | 0.73x | True |
| keygen.v4 `parallel` (t=4) | 4 | 133,958.6 | 133,958.6 | 137,500.0 | 1.03 | 7.5 | 0.92x | True |
| keygen.v5 `parallelgc` | 3 | 130,448.3 | 149,203.1 | 133,333.3 | 1.00 | 7.5 | 0.95x | True |

### SLH-DSA-SHA2-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 24 | 7,812.7 | 10,994.5 | 8,750.0 | 1.03 | 117.3 | 1.00x | True |
| keygen.v1 `jca-reuse` | 24 | 8,159.6 | 12,097.9 | 8,333.3 | 0.97 | 116.0 | 0.96x | True |
| keygen.v2 `lightweight` | 26 | 7,782.8 | 8,073.1 | 7,692.3 | 0.98 | 127.8 | 1.00x | True |
| keygen.v3 `internal-seed` | 20 | 10,776.7 | 12,841.0 | 7,500.0 | 0.75 | 100.0 | 0.72x | True |
| keygen.v4 `parallel` (t=4) | 28 | 7,867.7 | 8,144.5 | 7,857.1 | 0.99 | 126.2 | 0.99x | True |
| keygen.v5 `parallelgc` | 26 | 7,570.4 | 8,271.7 | 7,692.3 | 1.00 | 129.8 | 1.03x | True |

### SLH-DSA-SHAKE-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 199,488.0 | 245,184.3 | 196,666.7 | 0.98 | 5.0 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 214,870.6 | 215,051.4 | 173,333.3 | 0.86 | 5.0 | 0.93x | True |
| keygen.v2 `lightweight` | 3 | 164,548.1 | 173,306.4 | 150,000.0 | 0.90 | 6.0 | 1.21x | True |
| keygen.v3 `internal-seed` | 3 | 157,832.1 | 190,676.5 | 150,000.0 | 0.90 | 6.0 | 1.26x | True |
| keygen.v4 `parallel` (t=4) | 4 | 154,683.3 | 154,683.3 | 150,000.0 | 0.97 | 6.4 | 1.29x | True |
| keygen.v5 `parallelgc` | 3 | 159,714.4 | 161,567.0 | 146,666.7 | 0.94 | 6.4 | 1.25x | True |

### SLH-DSA-SHAKE-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 81 | 2,364.9 | 3,025.4 | 2,469.1 | 1.00 | 404.5 | 1.00x | True |
| keygen.v1 `jca-reuse` | 79 | 2,393.3 | 3,362.3 | 2,531.6 | 0.99 | 390.9 | 0.99x | True |
| keygen.v2 `lightweight` | 73 | 2,312.6 | 6,308.2 | 2,328.8 | 0.84 | 359.6 | 1.02x | True |
| keygen.v3 `internal-seed` | 83 | 2,259.0 | 2,560.1 | 2,289.2 | 0.94 | 411.2 | 1.05x | True |
| keygen.v4 `parallel` (t=4) | 96 | 2,331.3 | 2,357.5 | 2,291.7 | 0.99 | 432.0 | 1.01x | True |
| keygen.v5 `parallelgc` | 52 | 4,464.0 | 8,551.7 | 3,461.5 | 0.88 | 255.3 | 0.53x | True |

### SLH-DSA-SHAKE-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 235,770.6 | 275,482.2 | 240,000.0 | 0.99 | 4.1 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 260,603.5 | 265,438.9 | 240,000.0 | 0.93 | 3.9 | 0.90x | True |
| keygen.v2 `lightweight` | 3 | 290,385.6 | 366,555.8 | 236,666.7 | 0.77 | 3.3 | 0.81x | True |
| keygen.v3 `internal-seed` | 3 | 260,252.9 | 262,279.5 | 226,666.7 | 0.92 | 4.1 | 0.91x | True |
| keygen.v4 `parallel` (t=4) | 4 | 243,862.1 | 243,862.1 | 255,000.0 | 1.05 | 4.1 | 0.97x | True |
| keygen.v5 `parallelgc` | 3 | 309,757.1 | 353,680.2 | 240,000.0 | 0.78 | 3.3 | 0.76x | True |

### SLH-DSA-SHAKE-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 45 | 3,717.2 | 7,426.0 | 3,777.8 | 0.83 | 219.6 | 1.00x | True |
| keygen.v1 `jca-reuse` | 60 | 3,335.3 | 3,448.1 | 3,333.3 | 0.99 | 298.2 | 1.11x | True |
| keygen.v2 `lightweight` | 34 | 3,552.8 | 11,835.0 | 3,529.4 | 0.60 | 169.1 | 1.05x | True |
| keygen.v3 `internal-seed` | 46 | 3,414.6 | 7,542.5 | 3,695.7 | 0.83 | 224.9 | 1.09x | True |
| keygen.v4 `parallel` (t=4) | 48 | 4,309.8 | 5,575.1 | 3,958.3 | 0.94 | 236.8 | 0.86x | True |
| keygen.v5 `parallelgc` | 55 | 3,378.8 | 4,882.7 | 3,272.7 | 0.89 | 270.8 | 1.10x | True |

### SLH-DSA-SHAKE-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 3 | 151,529.5 | 168,087.6 | 150,000.0 | 0.96 | 6.4 | 1.00x | True |
| keygen.v1 `jca-reuse` | 3 | 147,855.9 | 148,293.0 | 150,000.0 | 1.02 | 6.8 | 1.02x | True |
| keygen.v2 `lightweight` | 3 | 208,929.0 | 211,033.2 | 166,666.7 | 0.83 | 5.0 | 0.73x | True |
| keygen.v3 `internal-seed` | 3 | 151,529.7 | 154,258.4 | 150,000.0 | 0.99 | 6.6 | 1.00x | True |
| keygen.v4 `parallel` (t=4) | 4 | 142,842.9 | 142,842.9 | 182,500.0 | 1.28 | 7.0 | 1.06x | True |
| keygen.v5 `parallelgc` | 3 | 164,452.7 | 242,940.2 | 166,666.7 | 0.90 | 5.4 | 0.92x | True |

### SLH-DSA-SHAKE-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| keygen.v0 `jca` | 22 | 9,177.1 | 9,393.1 | 9,090.9 | 0.99 | 108.8 | 1.00x | True |
| keygen.v1 `jca-reuse` | 23 | 8,887.4 | 8,970.9 | 9,130.4 | 1.02 | 112.0 | 1.03x | True |
| keygen.v2 `lightweight` | 15 | 12,644.2 | 25,454.0 | 10,666.7 | 0.76 | 71.5 | 0.73x | True |
| keygen.v3 `internal-seed` | 18 | 9,545.6 | 19,418.7 | 10,000.0 | 0.89 | 89.1 | 0.96x | True |
| keygen.v4 `parallel` (t=4) | 20 | 9,595.0 | 15,625.7 | 10,000.0 | 0.93 | 93.1 | 0.96x | True |
| keygen.v5 `parallelgc` | 20 | 9,543.6 | 14,537.4 | 10,500.0 | 1.04 | 98.8 | 0.96x | True |

### Geometric mean speedup vs v0 across parameter sets

| variant | ML-DSA | SLH-DSA | all |
|---|---|---|---|
| keygen.v0 `jca` | 1.00x | 1.00x | 1.00x |
| keygen.v1 `jca-reuse` | 1.16x | 0.90x | 0.95x |
| keygen.v2 `lightweight` | 0.98x | 0.90x | 0.91x |
| keygen.v3 `internal-seed` | 1.18x | 0.96x | 1.00x |
| keygen.v4 `parallel` | 1.05x | 1.00x | 1.01x |
| keygen.v5 `parallelgc` | 1.21x | 0.95x | 1.00x |
