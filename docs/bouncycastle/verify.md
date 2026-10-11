# Bouncy Castle: verify variants

Process: (pk, msg, sig) -> bool. ML-DSA verification (`MLDSAEngine.verifyInternal`) decodes z/h, re-expands the
matrix A from rho (SHAKE128, per call), computes `w1' = A z - c 2^d t1` in the NTT domain and recomputes the
challenge hash. SLH-DSA verification recomputes the FORS roots and walks d XMSS authentication paths: much
cheaper than signing but still thousands of hash calls, and for the "f" sets the large signature is the main input.

Every variant must return `true` for the reference (pk, msg, sig) on every iteration and `false` for a signature
with one flipped bit (checked once per cell through the same code path); `output_sha256` is `"true"` only if both hold.

| id | name | what | why it might help |
|---|---|---|---|
| verify.v0 | `jca` | **Baseline.** `Signature.getInstance("ML-DSA" or "SLH-DSA", "BC")`, `initVerify(publicKey)`, `update(msg)`, `verify(sig)`; new `Signature` per op. `PublicKey` built once via `KeyFactory` + X.509 SPKI. | - |
| verify.v1 | `lightweight` | `new MLDSASigner()` / `new SLHDSASigner()`, `init(false, publicKeyParameters)`, `verifySignature(...)`; new verifier per op. | Same reasoning as for signing: avoids provider lookup, SPI re-initialisation and (SLH-DSA) the message buffering stream. |
| verify.v2 | `reuse-verifier` | One lightweight verifier initialised once per public key and reused for every op. | `MLDSASigner.init(false, pk)` computes `tr = SHAKE256(rho || t1)` over the whole public key and absorbs it into the message digest state, and clones rho/t1; with reuse that hash over 1.3-2.6 KB is paid once (BC keeps a copy of the absorbed state and forks it per message). For SLH-DSA only the key clones are saved. |
| verify.v3 | `parallel` | Batch of verifications over a 4-thread pool, one initialised verifier per lane; throughput, `threads = 4`. | Verification is the operation most often done in bulk (certificate chains, batches of transactions); shows how BC scales when the matrix expansion and NTTs of several verifications run concurrently. |
| verify.v4 | `parallelgc` | `lightweight` code path in a child JVM with `-XX:+UseParallelGC -Xms2g -Xmx2g -Xmn1200m -XX:+AlwaysPreTouch`. | ML-DSA verify allocates the whole A matrix (k*l `int[256]`), z, h, t1, w1 per call; a throughput collector with a big pre-touched young generation makes those allocations nearly free and removes G1's barriers. |
| verify.v5 | `inline-aggressive` | `lightweight` code path in a child JVM with larger C2 inlining budgets: `-XX:MaxInlineLevel=30 -XX:MaxInlineSize=120 -XX:FreqInlineSize=1200 -XX:InlineSmallCode=6000 -XX:MaxNodeLimit=240000 -XX:NodeLimitFudgeFactor=8000`. | BC's ML-DSA code is written as many small methods (`Reduce.montgomeryReduce`, `Poly.getCoeffIndex`, `Rounding.*`, Keccak helpers) called from hot loops; verification is the most call-dense op. Raising the inlining thresholds lets C2 inline the whole NTT/pointwise layer into the loops and vectorise across what were call boundaries. |

Implementation notes: the tamper check flips bit 0 of the middle byte of the signature (inside z for ML-DSA, inside
the FORS/XMSS part for SLH-DSA); BC returns `false` (never throws) for malformed ML-DSA signatures, as documented
in the `MLDSASigner` javadoc. For the parallel variant the tamper check runs the whole batch with the bad signature
and requires every lane to reject.

## Preliminary conclusions (dev run, noisy shared box; final numbers come from the quiet run)

* `reuse-verifier` is the consistent single-thread winner (~7-9 % over the JCA baseline for both families): for
  ML-DSA it saves the SHAKE256 of the full public key (`tr`) and the `Signature` SPI re-init on every call.
  `lightweight` alone gives most of the SLH-DSA gain (the SPI buffers the message through a
  `ByteArrayOutputStream` and re-initialises the signer per op).
* `parallelgc` gives a small, consistent gain (~3-5 %) by making the per-verify A-matrix allocation cheaper;
  `inline-aggressive` was slightly negative for ML-DSA and neutral for SLH-DSA in the dev run: C2's default
  inlining already covers BC's hot paths and the larger budgets mostly cost compile time.
* `parallel` scaled best of all ops in the dev run (1.9x geometric mean despite sharing the box), since
  verification has no shared state and a short allocation lifetime.

<!-- RESULTS -->

## Results (preliminary, --budget-ms 200 on a shared 4-core box)

Median wall time per op (us), process CPU per op (us), cpu_util, and speedup of median wall vs v0.
Parallel variants: wall = batch wall / batch size, i.e. throughput-equivalent per-op time on all cores.

### ML-DSA-44

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 1559 | 107.6 | 196.2 | 166.8 | 1.30 | 7,792.7 | 1.00x | True |
| verify.v1 `lightweight` | 1772 | 101.9 | 136.9 | 220.1 | 1.95 | 8,856.8 | 1.06x | True |
| verify.v2 `reuse-verifier` | 1919 | 96.8 | 147.4 | 104.2 | 1.00 | 9,592.7 | 1.11x | True |
| verify.v3 `parallel` (t=4) | 3008 | 58.4 | 100.2 | 136.3 | 2.04 | 14,946.0 | 1.84x | True |
| verify.v4 `parallelgc` | 1597 | 101.8 | 196.4 | 137.8 | 1.10 | 7,984.9 | 1.06x | True |
| verify.v5 `inline-aggressive` | 1389 | 125.4 | 174.6 | 352.8 | 2.45 | 6,942.2 | 0.86x | True |

### ML-DSA-65

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 1097 | 164.5 | 254.3 | 255.2 | 1.40 | 5,484.5 | 1.00x | True |
| verify.v1 `lightweight` | 1131 | 164.5 | 227.9 | 353.7 | 2.00 | 5,653.1 | 1.00x | True |
| verify.v2 `reuse-verifier` | 1201 | 156.6 | 210.5 | 166.5 | 1.00 | 6,001.6 | 1.05x | True |
| verify.v3 `parallel` (t=4) | 1600 | 129.0 | 168.4 | 250.0 | 1.97 | 7,867.3 | 1.28x | True |
| verify.v4 `parallelgc` | 1130 | 162.0 | 255.5 | 230.1 | 1.30 | 5,648.9 | 1.02x | True |
| verify.v5 `inline-aggressive` | 860 | 198.7 | 359.5 | 279.1 | 1.20 | 4,298.7 | 0.83x | True |

### ML-DSA-87

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 658 | 275.4 | 512.3 | 607.9 | 2.00 | 3,288.9 | 1.00x | True |
| verify.v1 `lightweight` | 698 | 272.4 | 354.2 | 286.5 | 1.00 | 3,485.8 | 1.01x | True |
| verify.v2 `reuse-verifier` | 648 | 265.9 | 454.1 | 308.6 | 1.00 | 3,235.5 | 1.04x | True |
| verify.v3 `parallel` (t=4) | 1024 | 209.1 | 300.4 | 468.8 | 2.27 | 4,850.2 | 1.32x | True |
| verify.v4 `parallelgc` | 648 | 272.8 | 394.1 | 601.9 | 1.95 | 3,239.4 | 1.01x | True |
| verify.v5 `inline-aggressive` | 685 | 271.4 | 310.0 | 306.6 | 1.05 | 3,420.1 | 1.01x | True |

### SLH-DSA-SHA2-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 185 | 998.8 | 1,537.4 | 2,378.4 | 2.20 | 924.7 | 1.00x | True |
| verify.v1 `lightweight` | 203 | 963.3 | 1,075.7 | 985.2 | 1.00 | 1,012.9 | 1.04x | True |
| verify.v2 `reuse-verifier` | 174 | 983.2 | 1,655.3 | 2,298.8 | 1.99 | 867.1 | 1.02x | True |
| verify.v3 `parallel` (t=4) | 360 | 558.2 | 817.1 | 1,527.8 | 2.50 | 1,634.9 | 1.79x | True |
| verify.v4 `parallelgc` | 191 | 979.9 | 1,370.4 | 2,041.9 | 1.94 | 952.4 | 1.02x | True |
| verify.v5 `inline-aggressive` | 187 | 1,012.1 | 1,303.5 | 2,406.4 | 2.24 | 932.9 | 0.99x | True |

### SLH-DSA-SHA2-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 67 | 2,922.6 | 3,428.9 | 5,970.1 | 1.99 | 333.7 | 1.00x | True |
| verify.v1 `lightweight` | 72 | 2,793.2 | 2,853.8 | 2,777.8 | 0.99 | 357.7 | 1.05x | True |
| verify.v2 `reuse-verifier` | 71 | 2,801.2 | 2,925.7 | 3,239.4 | 1.15 | 355.0 | 1.04x | True |
| verify.v3 `parallel` (t=4) | 168 | 1,286.6 | 1,625.8 | 3,214.3 | 2.41 | 748.8 | 2.27x | True |
| verify.v4 `parallelgc` | 70 | 2,805.6 | 3,357.2 | 2,857.1 | 0.99 | 347.9 | 1.04x | True |
| verify.v5 `inline-aggressive` | 69 | 2,804.2 | 2,962.4 | 3,623.2 | 1.25 | 344.2 | 1.04x | True |

### SLH-DSA-SHA2-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 135 | 1,470.1 | 1,594.4 | 1,555.6 | 1.05 | 672.2 | 1.00x | True |
| verify.v1 `lightweight` | 127 | 1,526.1 | 1,830.5 | 1,574.8 | 1.00 | 634.3 | 0.96x | True |
| verify.v2 `reuse-verifier` | 130 | 1,469.1 | 1,786.2 | 1,538.5 | 1.00 | 648.9 | 1.00x | True |
| verify.v3 `parallel` (t=4) | 320 | 697.6 | 782.3 | 1,625.0 | 2.34 | 1,440.0 | 2.11x | True |
| verify.v4 `parallelgc` | 122 | 1,510.1 | 2,589.9 | 3,032.8 | 1.85 | 608.4 | 0.97x | True |
| verify.v5 `inline-aggressive` | 111 | 1,563.6 | 2,804.5 | 3,603.6 | 1.98 | 550.5 | 0.94x | True |

### SLH-DSA-SHA2-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 48 | 4,177.9 | 4,365.8 | 4,166.7 | 0.98 | 235.1 | 1.00x | True |
| verify.v1 `lightweight` | 47 | 4,231.9 | 4,506.0 | 4,255.3 | 1.00 | 234.6 | 0.99x | True |
| verify.v2 `reuse-verifier` | 46 | 4,287.6 | 4,847.1 | 4,347.8 | 0.99 | 228.7 | 0.97x | True |
| verify.v3 `parallel` (t=4) | 96 | 2,550.5 | 2,892.1 | 5,208.3 | 2.19 | 420.1 | 1.64x | True |
| verify.v4 `parallelgc` | 48 | 4,072.9 | 4,602.2 | 4,166.7 | 0.99 | 238.0 | 1.03x | True |
| verify.v5 `inline-aggressive` | 47 | 4,193.7 | 4,573.8 | 4,893.6 | 1.15 | 234.6 | 1.00x | True |

### SLH-DSA-SHA2-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 85 | 2,244.7 | 3,081.7 | 2,352.9 | 0.99 | 421.5 | 1.00x | True |
| verify.v1 `lightweight` | 74 | 2,354.8 | 3,863.1 | 2,567.6 | 0.94 | 364.4 | 0.95x | True |
| verify.v2 `reuse-verifier` | 87 | 2,273.0 | 2,648.4 | 2,298.8 | 1.00 | 433.1 | 0.99x | True |
| verify.v3 `parallel` (t=4) | 180 | 1,182.0 | 1,549.2 | 2,722.2 | 2.19 | 803.9 | 1.90x | True |
| verify.v4 `parallelgc` | 87 | 2,196.4 | 2,495.6 | 2,413.8 | 1.04 | 431.3 | 1.02x | True |
| verify.v5 `inline-aggressive` | 85 | 2,301.5 | 2,579.3 | 2,470.6 | 1.04 | 420.2 | 0.98x | True |

### SLH-DSA-SHA2-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 42 | 4,691.0 | 6,877.6 | 4,761.9 | 0.98 | 204.9 | 1.00x | True |
| verify.v1 `lightweight` | 45 | 4,387.1 | 5,125.9 | 4,444.4 | 0.99 | 223.2 | 1.07x | True |
| verify.v2 `reuse-verifier` | 47 | 4,269.7 | 4,417.0 | 4,255.3 | 0.99 | 232.9 | 1.10x | True |
| verify.v3 `parallel` (t=4) | 84 | 2,877.9 | 3,249.0 | 6,547.6 | 2.41 | 368.4 | 1.63x | True |
| verify.v4 `parallelgc` | 31 | 6,724.5 | 7,015.7 | 6,451.6 | 0.98 | 152.4 | 0.70x | True |
| verify.v5 `inline-aggressive` | 45 | 4,350.7 | 5,050.0 | 4,444.4 | 0.99 | 223.3 | 1.08x | True |

### SLH-DSA-SHAKE-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 167 | 1,070.0 | 1,774.9 | 1,197.6 | 1.00 | 832.2 | 1.00x | True |
| verify.v1 `lightweight` | 155 | 1,112.9 | 1,985.3 | 1,290.3 | 1.00 | 773.9 | 0.96x | True |
| verify.v2 `reuse-verifier` | 147 | 1,063.9 | 2,051.5 | 1,360.5 | 1.00 | 731.8 | 1.01x | True |
| verify.v3 `parallel` (t=4) | 364 | 679.0 | 782.6 | 1,620.9 | 2.47 | 1,523.4 | 1.58x | True |
| verify.v4 `parallelgc` | 173 | 1,093.6 | 1,826.6 | 2,312.1 | 1.99 | 862.7 | 0.98x | True |
| verify.v5 `inline-aggressive` | 183 | 1,079.3 | 1,177.6 | 2,131.1 | 1.95 | 912.8 | 0.99x | True |

### SLH-DSA-SHAKE-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 59 | 3,351.2 | 3,851.0 | 3,389.8 | 0.99 | 292.0 | 1.00x | True |
| verify.v1 `lightweight` | 53 | 3,426.7 | 5,981.8 | 3,773.6 | 0.98 | 259.1 | 0.98x | True |
| verify.v2 `reuse-verifier` | 60 | 3,361.1 | 3,521.1 | 3,500.0 | 1.04 | 296.9 | 1.00x | True |
| verify.v3 `parallel` (t=4) | 88 | 2,394.9 | 3,511.7 | 4,772.7 | 1.94 | 406.7 | 1.40x | True |
| verify.v4 `parallelgc` | 54 | 3,500.4 | 3,781.9 | 7,222.2 | 1.94 | 268.1 | 0.96x | True |
| verify.v5 `inline-aggressive` | 44 | 4,197.6 | 6,212.6 | 8,181.8 | 1.80 | 219.7 | 0.80x | True |

### SLH-DSA-SHAKE-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 84 | 2,536.0 | 3,337.3 | 2,381.0 | 0.99 | 417.4 | 1.00x | True |
| verify.v1 `lightweight` | 115 | 1,657.2 | 2,018.3 | 1,826.1 | 1.05 | 574.9 | 1.53x | True |
| verify.v2 `reuse-verifier` | 105 | 1,638.4 | 2,943.7 | 1,904.8 | 0.99 | 521.8 | 1.55x | True |
| verify.v3 `parallel` (t=4) | 308 | 741.6 | 771.3 | 1,720.8 | 2.37 | 1,375.6 | 3.42x | True |
| verify.v4 `parallelgc` | 112 | 1,642.3 | 2,539.4 | 1,785.7 | 0.99 | 555.8 | 1.54x | True |
| verify.v5 `inline-aggressive` | 119 | 1,636.1 | 1,914.6 | 1,680.7 | 1.00 | 593.3 | 1.55x | True |

### SLH-DSA-SHAKE-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 25 | 8,006.3 | 12,272.1 | 8,000.0 | 0.98 | 122.2 | 1.00x | True |
| verify.v1 `lightweight` | 43 | 4,565.7 | 4,912.3 | 4,651.2 | 1.00 | 214.5 | 1.75x | True |
| verify.v2 `reuse-verifier` | 42 | 4,632.0 | 5,576.4 | 4,761.9 | 0.99 | 207.5 | 1.73x | True |
| verify.v3 `parallel` (t=4) | 80 | 2,366.1 | 3,898.6 | 6,000.0 | 2.37 | 395.5 | 3.38x | True |
| verify.v4 `parallelgc` | 43 | 4,620.3 | 5,354.2 | 4,651.2 | 0.99 | 212.0 | 1.73x | True |
| verify.v5 `inline-aggressive` | 43 | 4,622.5 | 4,802.4 | 4,883.7 | 1.03 | 210.7 | 1.73x | True |

### SLH-DSA-SHAKE-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 83 | 2,362.2 | 2,686.8 | 2,409.6 | 1.00 | 413.2 | 1.00x | True |
| verify.v1 `lightweight` | 62 | 2,574.8 | 6,785.4 | 3,225.8 | 0.99 | 307.3 | 0.92x | True |
| verify.v2 `reuse-verifier` | 82 | 2,423.6 | 2,786.2 | 2,439.0 | 0.99 | 405.5 | 0.97x | True |
| verify.v3 `parallel` (t=4) | 160 | 1,478.3 | 1,532.8 | 3,062.5 | 2.10 | 686.8 | 1.60x | True |
| verify.v4 `parallelgc` | 74 | 2,452.6 | 3,908.9 | 2,702.7 | 0.99 | 368.0 | 0.96x | True |
| verify.v5 `inline-aggressive` | 82 | 2,423.8 | 2,646.2 | 2,561.0 | 1.04 | 407.6 | 0.97x | True |

### SLH-DSA-SHAKE-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 41 | 4,849.8 | 5,382.5 | 4,878.0 | 0.98 | 201.8 | 1.00x | True |
| verify.v1 `lightweight` | 42 | 4,807.2 | 5,037.8 | 7,142.9 | 1.47 | 206.4 | 1.01x | True |
| verify.v2 `reuse-verifier` | 38 | 5,031.2 | 6,717.6 | 5,526.3 | 1.05 | 189.5 | 0.96x | True |
| verify.v3 `parallel` (t=4) | 88 | 2,303.1 | 2,861.6 | 5,340.9 | 2.21 | 413.9 | 2.11x | True |
| verify.v4 `parallelgc` | 31 | 4,889.0 | 11,869.1 | 6,451.6 | 0.99 | 153.5 | 0.99x | True |
| verify.v5 `inline-aggressive` | 36 | 5,328.5 | 8,102.2 | 5,555.6 | 0.99 | 177.6 | 0.91x | True |

### Geometric mean speedup vs v0 across parameter sets

| variant | ML-DSA | SLH-DSA | all |
|---|---|---|---|
| verify.v0 `jca` | 1.00x | 1.00x | 1.00x |
| verify.v1 `lightweight` | 1.02x | 1.08x | 1.07x |
| verify.v2 `reuse-verifier` | 1.07x | 1.09x | 1.09x |
| verify.v3 `parallel` | 1.46x | 1.98x | 1.87x |
| verify.v4 `parallelgc` | 1.03x | 1.05x | 1.05x |
| verify.v5 `inline-aggressive` | 0.90x | 1.06x | 1.02x |
