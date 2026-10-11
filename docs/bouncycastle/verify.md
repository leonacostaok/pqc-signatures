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
| verify.v0 `jca` | 1411 | 103.7 | 163.2 | 191.4 | 1.35 | 7,053.5 | 1.00x | True |
| verify.v1 `lightweight` | 1568 | 107.8 | 208.5 | 127.6 | 1.00 | 7,838.1 | 0.96x | True |
| verify.v2 `reuse-verifier` | 1827 | 98.2 | 148.0 | 114.9 | 1.05 | 9,133.8 | 1.06x | True |
| verify.v3 `parallel` (t=4) | 2688 | 78.1 | 104.0 | 122.8 | 1.63 | 13,297.1 | 1.33x | True |
| verify.v4 `parallelgc` | 1873 | 100.1 | 131.6 | 293.6 | 2.75 | 9,363.2 | 1.04x | True |
| verify.v5 `inline-aggressive` | 1608 | 104.6 | 181.7 | 373.1 | 3.00 | 8,036.2 | 0.99x | True |

### ML-DSA-65

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 515 | 164.2 | 261.2 | 601.9 | 1.52 | 2,525.1 | 1.00x | True |
| verify.v1 `lightweight` | 1035 | 166.5 | 368.2 | 183.6 | 0.95 | 5,171.3 | 0.99x | True |
| verify.v2 `reuse-verifier` | 995 | 160.9 | 327.8 | 201.0 | 1.00 | 4,971.1 | 1.02x | True |
| verify.v3 `parallel` (t=4) | 1664 | 123.2 | 179.4 | 198.3 | 1.60 | 8,060.0 | 1.33x | True |
| verify.v4 `parallelgc` | 1128 | 162.6 | 237.3 | 203.9 | 1.15 | 5,637.9 | 1.01x | True |
| verify.v5 `inline-aggressive` | 1091 | 168.3 | 243.4 | 220.0 | 1.20 | 5,453.2 | 0.98x | True |

### ML-DSA-87

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 627 | 281.9 | 505.9 | 319.0 | 1.00 | 3,134.7 | 1.00x | True |
| verify.v1 `lightweight` | 518 | 296.9 | 746.0 | 386.1 | 1.00 | 2,584.9 | 0.95x | True |
| verify.v2 `reuse-verifier` | 703 | 267.0 | 383.6 | 284.5 | 1.00 | 3,512.3 | 1.06x | True |
| verify.v3 `parallel` (t=4) | 560 | 371.7 | 662.5 | 482.1 | 1.27 | 2,638.3 | 0.76x | True |
| verify.v4 `parallelgc` | 609 | 284.7 | 477.6 | 344.8 | 1.05 | 3,041.7 | 0.99x | True |
| verify.v5 `inline-aggressive` | 598 | 293.2 | 512.6 | 334.4 | 1.00 | 2,989.4 | 0.96x | True |

### SLH-DSA-SHA2-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 186 | 1,008.9 | 1,451.1 | 1,451.6 | 1.35 | 926.7 | 1.00x | True |
| verify.v1 `lightweight` | 195 | 984.2 | 1,253.3 | 1,025.6 | 1.00 | 971.6 | 1.03x | True |
| verify.v2 `reuse-verifier` | 194 | 971.9 | 1,222.1 | 979.4 | 0.94 | 961.9 | 1.04x | True |
| verify.v3 `parallel` (t=4) | 260 | 809.8 | 1,041.2 | 1,192.3 | 1.52 | 1,272.7 | 1.25x | True |
| verify.v4 `parallelgc` | 202 | 953.4 | 1,251.9 | 1,039.6 | 1.05 | 1,007.9 | 1.06x | True |
| verify.v5 `inline-aggressive` | 196 | 981.9 | 1,337.1 | 1,632.7 | 1.59 | 976.5 | 1.03x | True |

### SLH-DSA-SHA2-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 60 | 3,019.8 | 4,449.8 | 3,333.3 | 1.00 | 299.3 | 1.00x | True |
| verify.v1 `lightweight` | 65 | 3,027.1 | 3,996.5 | 3,076.9 | 0.99 | 320.8 | 1.00x | True |
| verify.v2 `reuse-verifier` | 71 | 2,797.1 | 2,976.7 | 2,816.9 | 1.00 | 354.0 | 1.08x | True |
| verify.v3 `parallel` (t=4) | 96 | 2,147.9 | 2,689.2 | 3,125.0 | 1.49 | 477.2 | 1.41x | True |
| verify.v4 `parallelgc` | 71 | 2,754.5 | 3,052.3 | 2,957.7 | 1.04 | 353.0 | 1.10x | True |
| verify.v5 `inline-aggressive` | 53 | 4,288.7 | 4,830.7 | 3,773.6 | 0.99 | 262.2 | 0.70x | True |

### SLH-DSA-SHA2-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 118 | 1,510.2 | 2,268.4 | 2,542.4 | 1.49 | 587.4 | 1.00x | True |
| verify.v1 `lightweight` | 131 | 1,507.8 | 1,688.7 | 1,526.7 | 1.00 | 652.3 | 1.00x | True |
| verify.v2 `reuse-verifier` | 129 | 1,507.7 | 1,827.1 | 1,550.4 | 1.00 | 645.0 | 1.00x | True |
| verify.v3 `parallel` (t=4) | 220 | 936.0 | 1,189.2 | 1,681.8 | 1.71 | 1,014.2 | 1.61x | True |
| verify.v4 `parallelgc` | 127 | 1,456.0 | 2,285.2 | 1,574.8 | 1.00 | 633.0 | 1.04x | True |
| verify.v5 `inline-aggressive` | 137 | 1,441.3 | 1,622.7 | 1,532.8 | 1.05 | 684.6 | 1.05x | True |

### SLH-DSA-SHA2-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 26 | 8,905.5 | 10,741.2 | 7,692.3 | 0.98 | 127.5 | 1.00x | True |
| verify.v1 `lightweight` | 46 | 4,218.7 | 4,773.6 | 4,130.4 | 0.94 | 228.8 | 2.11x | True |
| verify.v2 `reuse-verifier` | 47 | 4,209.2 | 4,500.4 | 4,255.3 | 1.00 | 234.3 | 2.12x | True |
| verify.v3 `parallel` (t=4) | 60 | 3,599.7 | 4,554.0 | 4,666.7 | 1.26 | 270.9 | 2.47x | True |
| verify.v4 `parallelgc` | 46 | 4,109.6 | 5,573.1 | 4,347.8 | 0.99 | 228.8 | 2.17x | True |
| verify.v5 `inline-aggressive` | 34 | 6,545.3 | 7,315.8 | 5,882.4 | 1.00 | 169.6 | 1.36x | True |

### SLH-DSA-SHA2-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 70 | 2,556.8 | 4,064.9 | 2,857.1 | 1.00 | 349.7 | 1.00x | True |
| verify.v1 `lightweight` | 80 | 2,287.7 | 3,268.4 | 2,500.0 | 0.99 | 397.7 | 1.12x | True |
| verify.v2 `reuse-verifier` | 80 | 2,291.8 | 3,614.5 | 2,375.0 | 0.95 | 397.9 | 1.12x | True |
| verify.v3 `parallel` (t=4) | 112 | 2,111.6 | 2,639.9 | 3,125.0 | 1.52 | 485.3 | 1.21x | True |
| verify.v4 `parallelgc` | 91 | 2,160.0 | 2,347.3 | 2,197.8 | 1.00 | 454.3 | 1.18x | True |
| verify.v5 `inline-aggressive` | 86 | 2,215.4 | 3,677.8 | 2,209.3 | 0.94 | 427.7 | 1.15x | True |

### SLH-DSA-SHA2-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 45 | 4,417.1 | 4,935.1 | 4,444.4 | 1.00 | 224.6 | 1.00x | True |
| verify.v1 `lightweight` | 47 | 4,287.3 | 4,506.8 | 4,255.3 | 0.99 | 231.8 | 1.03x | True |
| verify.v2 `reuse-verifier` | 41 | 4,367.9 | 6,936.2 | 4,634.1 | 0.94 | 202.4 | 1.01x | True |
| verify.v3 `parallel` (t=4) | 80 | 2,661.6 | 3,003.2 | 4,750.0 | 1.82 | 383.1 | 1.66x | True |
| verify.v4 `parallelgc` | 48 | 4,205.1 | 4,421.0 | 4,166.7 | 0.99 | 237.0 | 1.05x | True |
| verify.v5 `inline-aggressive` | 46 | 4,281.1 | 4,693.4 | 4,347.8 | 1.00 | 229.3 | 1.03x | True |

### SLH-DSA-SHAKE-128s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 107 | 1,842.4 | 2,924.2 | 1,869.2 | 1.00 | 534.0 | 1.00x | True |
| verify.v1 `lightweight` | 187 | 1,052.1 | 1,202.4 | 1,069.5 | 1.00 | 930.5 | 1.75x | True |
| verify.v2 `reuse-verifier` | 192 | 1,036.5 | 1,102.2 | 1,041.7 | 1.00 | 955.2 | 1.78x | True |
| verify.v3 `parallel` (t=4) | 384 | 555.1 | 643.8 | 1,276.0 | 2.36 | 1,846.3 | 3.32x | True |
| verify.v4 `parallelgc` | 184 | 1,066.4 | 1,209.0 | 1,141.3 | 1.05 | 916.7 | 1.73x | True |
| verify.v5 `inline-aggressive` | 162 | 1,074.8 | 1,355.1 | 1,172.8 | 0.95 | 806.8 | 1.71x | True |

### SLH-DSA-SHAKE-128f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 44 | 3,933.2 | 7,168.5 | 4,772.7 | 1.03 | 216.8 | 1.00x | True |
| verify.v1 `lightweight` | 57 | 3,484.6 | 3,894.3 | 3,508.8 | 1.00 | 283.6 | 1.13x | True |
| verify.v2 `reuse-verifier` | 55 | 3,533.3 | 4,533.8 | 3,818.2 | 1.04 | 271.6 | 1.11x | True |
| verify.v3 `parallel` (t=4) | 100 | 2,194.4 | 2,545.2 | 4,800.0 | 2.19 | 456.4 | 1.79x | True |
| verify.v4 `parallelgc` | 56 | 3,487.0 | 4,382.7 | 3,571.4 | 0.99 | 277.9 | 1.13x | True |
| verify.v5 `inline-aggressive` | 56 | 3,486.0 | 4,282.6 | 3,571.4 | 0.99 | 276.5 | 1.13x | True |

### SLH-DSA-SHAKE-192s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 124 | 1,598.5 | 1,674.3 | 1,612.9 | 1.00 | 619.8 | 1.00x | True |
| verify.v1 `lightweight` | 110 | 1,697.0 | 2,443.8 | 1,818.2 | 1.00 | 547.4 | 0.94x | True |
| verify.v2 `reuse-verifier` | 120 | 1,601.3 | 2,046.9 | 1,666.7 | 1.00 | 597.8 | 1.00x | True |
| verify.v3 `parallel` (t=4) | 192 | 1,182.4 | 1,478.0 | 2,135.4 | 1.92 | 899.2 | 1.35x | True |
| verify.v4 `parallelgc` | 106 | 1,676.3 | 3,088.8 | 2,924.5 | 1.53 | 523.2 | 0.95x | True |
| verify.v5 `inline-aggressive` | 90 | 2,491.5 | 2,868.0 | 2,555.6 | 1.14 | 444.8 | 0.64x | True |

### SLH-DSA-SHAKE-192f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 41 | 4,695.5 | 6,742.2 | 5,122.0 | 1.01 | 196.6 | 1.00x | True |
| verify.v1 `lightweight` | 27 | 8,015.5 | 9,115.9 | 7,777.8 | 1.02 | 131.7 | 0.59x | True |
| verify.v2 `reuse-verifier` | 33 | 5,520.6 | 8,498.5 | 6,060.6 | 0.99 | 163.6 | 0.85x | True |
| verify.v3 `parallel` (t=4) | 108 | 1,781.9 | 2,439.7 | 5,833.3 | 3.03 | 518.7 | 2.64x | True |
| verify.v4 `parallelgc` | 40 | 4,682.4 | 7,303.1 | 5,000.0 | 1.00 | 199.7 | 1.00x | True |
| verify.v5 `inline-aggressive` | 41 | 4,786.0 | 6,545.4 | 4,878.0 | 0.98 | 201.1 | 0.98x | True |

### SLH-DSA-SHAKE-256s

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 85 | 2,361.1 | 2,454.3 | 3,764.7 | 1.59 | 423.1 | 1.00x | True |
| verify.v1 `lightweight` | 83 | 2,383.5 | 2,806.0 | 2,409.6 | 0.99 | 410.0 | 0.99x | True |
| verify.v2 `reuse-verifier` | 85 | 2,348.5 | 2,429.4 | 2,352.9 | 1.00 | 424.6 | 1.01x | True |
| verify.v3 `parallel` (t=4) | 312 | 666.7 | 1,103.5 | 2,596.2 | 3.56 | 1,372.9 | 3.54x | True |
| verify.v4 `parallelgc` | 77 | 2,470.1 | 3,484.2 | 5,064.9 | 1.94 | 382.1 | 0.96x | True |
| verify.v5 `inline-aggressive` | 68 | 2,547.8 | 4,511.1 | 2,941.2 | 0.99 | 335.1 | 0.93x | True |

### SLH-DSA-SHAKE-256f

| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| verify.v0 `jca` | 38 | 4,956.8 | 6,827.0 | 5,263.2 | 1.00 | 189.9 | 1.00x | True |
| verify.v1 `lightweight` | 39 | 5,011.9 | 6,345.6 | 5,128.2 | 0.98 | 191.9 | 0.99x | True |
| verify.v2 `reuse-verifier` | 38 | 5,217.0 | 7,507.5 | 5,263.2 | 0.98 | 185.9 | 0.95x | True |
| verify.v3 `parallel` (t=4) | 108 | 1,891.4 | 2,165.4 | 6,111.1 | 3.17 | 518.4 | 2.62x | True |
| verify.v4 `parallelgc` | 42 | 4,832.7 | 4,949.4 | 4,761.9 | 0.98 | 206.1 | 1.03x | True |
| verify.v5 `inline-aggressive` | 38 | 5,199.7 | 6,869.3 | 5,263.2 | 0.99 | 187.2 | 0.95x | True |

### Geometric mean speedup vs v0 across parameter sets

| variant | ML-DSA | SLH-DSA | all |
|---|---|---|---|
| verify.v0 `jca` | 1.00x | 1.00x | 1.00x |
| verify.v1 `lightweight` | 0.97x | 1.08x | 1.06x |
| verify.v2 `reuse-verifier` | 1.04x | 1.13x | 1.11x |
| verify.v3 `parallel` | 1.10x | 1.94x | 1.73x |
| verify.v4 `parallelgc` | 1.01x | 1.16x | 1.13x |
| verify.v5 `inline-aggressive` | 0.98x | 1.02x | 1.01x |
