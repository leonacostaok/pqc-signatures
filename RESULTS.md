# Results: PQC signatures across 6 libraries

All numbers from one quiet, sequential run on the same 4-core x86-64 VM (see `common/run-all.sh`). Each process (keygen, sign, verify) is measured separately: median wall time per op from individual timings, CPU time per op from process user+sys time. "best" = highest throughput among the 6 variants of that process; single-threaded best excludes parallel batch variants. Every number here comes from a run whose output byte-matched the reference (see `results/MATCH.md`).

## keygen

### Baseline (v0) median time per op

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.63 ms | **16.2 µs** | 117.8 µs | 66.3 µs | 160.4 µs | 99.6 µs |
| ML-DSA-65 | 1.86 ms | **27.3 µs** | 206.7 µs | 109.7 µs | 259.3 µs | 170.9 µs |
| ML-DSA-87 | 3.20 ms | **41.7 µs** | 298.8 µs | 176.1 µs | 447.2 µs | 292.4 µs |
| SLH-DSA-SHA2-128s | 352.83 ms | **72.92 ms** | 122.91 ms | 136.99 ms | 108.27 ms | 153.21 ms |
| SLH-DSA-SHA2-128f | 4.09 ms | **1.15 ms** | 1.93 ms | 3.16 ms | 1.55 ms | 1.98 ms |
| SLH-DSA-SHA2-192s | 525.83 ms | **113.18 ms** | 188.57 ms | 180.26 ms | 151.72 ms | 193.53 ms |
| SLH-DSA-SHA2-192f | 6.57 ms | **1.69 ms** | 3.07 ms | 3.15 ms | 2.27 ms | 2.99 ms |
| SLH-DSA-SHA2-256s | 332.85 ms | **79.09 ms** | 143.25 ms | 136.48 ms | 107.18 ms | 135.63 ms |
| SLH-DSA-SHA2-256f | 27.19 ms | **4.54 ms** | 7.48 ms | 7.48 ms | 6.08 ms | 8.34 ms |
| SLH-DSA-SHAKE-128s | 1.91 s | 180.99 ms | 162.32 ms | 147.17 ms | 359.03 ms | **145.76 ms** |
| SLH-DSA-SHAKE-128f | 28.64 ms | 2.04 ms | **1.99 ms** | 2.30 ms | 3.99 ms | 2.28 ms |
| SLH-DSA-SHAKE-192s | 2.77 s | 199.66 ms | **187.37 ms** | 229.39 ms | 422.55 ms | 221.33 ms |
| SLH-DSA-SHAKE-192f | 39.02 ms | 3.05 ms | **2.87 ms** | 3.32 ms | 5.88 ms | 3.35 ms |
| SLH-DSA-SHAKE-256s | 1.77 s | **125.46 ms** | 130.66 ms | 178.00 ms | 259.49 ms | 151.08 ms |
| SLH-DSA-SHAKE-256f | 148.92 ms | 8.00 ms | **7.98 ms** | 9.04 ms | 22.85 ms | 9.27 ms |
| Falcon-512 | 223.07 ms | **8.02 ms** | — | — | — | — |
| Falcon-1024 | 710.19 ms | **17.61 ms** | — | — | — | — |

### Best single-threaded variant: effective time per op (speedup vs own v0, variant)

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 589.1 µs (3.13×, v3) | 17.1 µs (1.12×, v3) | 128.5 µs (1.04×, v4) | 79.0 µs (1.14×, v2) | 176.1 µs (1.06×, v3) | 111.5 µs (1.16×, v2) |
| ML-DSA-65 | 955.5 µs (2.24×, v3) | 29.3 µs (1.00×, v0) | 209.2 µs (1.14×, v4) | 126.7 µs (1.13×, v3) | 260.9 µs (1.12×, v4) | 187.2 µs (1.16×, v3) |
| ML-DSA-87 | 1.45 ms (2.58×, v3) | 44.4 µs (1.00×, v0) | 316.5 µs (1.00×, v0) | 183.0 µs (1.19×, v2) | 433.1 µs (1.18×, v4) | 318.5 µs (1.06×, v1) |
| SLH-DSA-SHA2-128s | 161.81 ms (2.17×, v2) | 69.99 ms (1.07×, v4) | 124.46 ms (1.00×, v0) | 137.10 ms (1.01×, v2) | 84.80 ms (1.31×, v3) | 129.87 ms (1.24×, v1) |
| SLH-DSA-SHA2-128f | 2.55 ms (1.74×, v2) | 1.12 ms (1.24×, v4) | 2.07 ms (1.00×, v0) | 2.36 ms (1.23×, v2) | 1.19 ms (1.36×, v1) | 2.00 ms (1.12×, v5) |
| SLH-DSA-SHA2-192s | 252.21 ms (1.96×, v2) | 108.97 ms (1.14×, v4) | 172.71 ms (1.14×, v4) | 180.30 ms (1.00×, v0) | 116.83 ms (1.35×, v3) | 191.63 ms (1.02×, v5) |
| SLH-DSA-SHA2-192f | 3.72 ms (1.89×, v2) | 1.71 ms (1.04×, v1) | 2.76 ms (1.25×, v1) | 3.05 ms (1.25×, v4) | 1.80 ms (1.46×, v3) | 2.96 ms (1.07×, v5) |
| SLH-DSA-SHA2-256s | 153.09 ms (1.99×, v2) | 74.78 ms (1.16×, v2) | 114.26 ms (1.32×, v4) | 135.06 ms (1.01×, v4) | 81.46 ms (1.31×, v3) | 131.69 ms (1.06×, v5) |
| SLH-DSA-SHA2-256f | 9.65 ms (2.66×, v2) | 4.54 ms (1.18×, v4) | 7.60 ms (1.19×, v4) | 7.96 ms (1.00×, v4) | 5.43 ms (1.14×, v1) | 7.56 ms (1.25×, v5) |
| SLH-DSA-SHAKE-128s | 933.71 ms (2.02×, v2) | 117.59 ms (1.42×, v2) | 125.28 ms (1.36×, v4) | 144.93 ms (1.02×, v2) | 239.22 ms (1.50×, v1) | 145.93 ms (1.07×, v5) |
| SLH-DSA-SHAKE-128f | 14.54 ms (2.15×, v2) | 1.86 ms (1.39×, v2) | 1.94 ms (1.05×, v4) | 2.15 ms (1.24×, v2) | 3.85 ms (1.11×, v1) | 2.44 ms (1.02×, v3) |
| SLH-DSA-SHAKE-192s | 1.23 s (2.34×, v2) | 156.20 ms (1.32×, v2) | 186.32 ms (1.11×, v4) | 208.67 ms (1.12×, v2) | 367.67 ms (1.14×, v3) | 215.73 ms (1.19×, v5) |
| SLH-DSA-SHAKE-192f | 21.75 ms (1.96×, v3) | 2.55 ms (1.26×, v4) | 3.07 ms (1.00×, v0) | 3.30 ms (1.08×, v2) | 5.91 ms (1.13×, v3) | 3.38 ms (1.06×, v2) |
| SLH-DSA-SHAKE-256s | 710.23 ms (2.56×, v2) | 108.62 ms (1.18×, v2) | 122.44 ms (1.08×, v4) | 134.96 ms (1.38×, v1) | 223.88 ms (1.17×, v1) | 150.20 ms (1.08×, v3) |
| SLH-DSA-SHAKE-256f | 50.03 ms (2.87×, v2) | 6.51 ms (1.44×, v4) | 7.76 ms (1.09×, v1) | 8.11 ms (1.31×, v2) | 14.93 ms (1.49×, v3) | 10.01 ms (1.00×, v2) |
| Falcon-512 | 205.34 ms (1.09×, v4) | 7.48 ms (1.16×, v3) | — | — | — | — |
| Falcon-1024 | 621.50 ms (1.20×, v4) | 15.85 ms (1.11×, v3) | — | — | — | — |

### Variant leaderboard (geomean speedup vs v0 across params)

| lib | v1 | v2 | v3 | v4 | v5 |
|---|---|---|---|---|---|
| noble | native-hash: 0.90× | fastjs: 2.18× | fastjs+native: 1.18× | bun: 1.00× | workers-x4: 3.23× (4 thr) |
| liboqs | internal-seeded: 1.01× | march-native: 1.12× | clang-native: 1.04× | gcc-pgo: 1.07× | pthread-x4: 2.26× (4 thr) |
| openssl | prefetch-reuse-ctx: 1.02× | fromdata-seed-import: 1.00× | no-asm-build: 0.82× | native-lto-build: 1.10× | pthread-x4: 2.74× (4 thr) |
| circl | purego: 0.66× | amd64v3: 1.10× | pgo: 0.99× | gc-off: 0.77× | parallel: 2.22× (4 thr) |
| rustcrypto | native: 1.11× | lto: 1.03× | pgo: 1.19× | mimalloc: 1.08× | par: 3.26× (4 thr) |
| bouncycastle | jca-reuse: 0.95× | lightweight: 1.01× | internal-seed: 1.01× | parallel: 3.08× (4 thr) | parallelgc: 1.01× |

## sign

### Baseline (v0) median time per op

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 2.07 ms | **26.3 µs** | 253.3 µs | 74.9 µs | 175.5 µs | 167.2 µs |
| ML-DSA-65 | 8.72 ms | **101.5 µs** | 1.25 ms | 304.8 µs | 830.5 µs | 659.4 µs |
| ML-DSA-87 | 7.29 ms | **75.4 µs** | 820.1 µs | 272.8 µs | 596.1 µs | 507.5 µs |
| SLH-DSA-SHA2-128s | 2.06 s | **562.99 ms** | 976.91 ms | 1.12 s | 981.22 ms | 1.04 s |
| SLH-DSA-SHA2-128f | 100.83 ms | **27.30 ms** | 46.33 ms | 49.32 ms | 36.07 ms | 47.66 ms |
| SLH-DSA-SHA2-192s | 4.46 s | 1.35 s | 1.88 s | 1.92 s | **1.32 s** | 1.93 s |
| SLH-DSA-SHA2-192f | 185.41 ms | **48.43 ms** | 74.93 ms | 85.82 ms | 58.07 ms | 85.74 ms |
| SLH-DSA-SHA2-256s | 4.26 s | **1.04 s** | 1.53 s | 1.88 s | 1.26 s | 1.85 s |
| SLH-DSA-SHA2-256f | 439.93 ms | **99.14 ms** | 166.74 ms | 169.30 ms | 120.93 ms | 176.78 ms |
| SLH-DSA-SHAKE-128s | 14.20 s | 1.10 s | **988.16 ms** | 1.25 s | 2.29 s | 1.19 s |
| SLH-DSA-SHAKE-128f | 662.01 ms | **47.96 ms** | 48.61 ms | 85.20 ms | 105.54 ms | 64.02 ms |
| SLH-DSA-SHAKE-192s | 26.06 s | 1.90 s | **1.86 s** | 2.35 s | 3.58 s | 2.05 s |
| SLH-DSA-SHAKE-192f | 1.14 s | 84.52 ms | **81.71 ms** | 96.08 ms | 169.58 ms | 107.20 ms |
| SLH-DSA-SHAKE-256s | 21.74 s | 1.79 s | **1.60 s** | 2.00 s | 3.42 s | 1.93 s |
| SLH-DSA-SHAKE-256f | 2.36 s | 181.45 ms | **159.54 ms** | 184.87 ms | 322.79 ms | 200.98 ms |
| Falcon-512 | 4.44 ms | **218.7 µs** | — | — | — | — |
| Falcon-1024 | 10.28 ms | **658.7 µs** | — | — | — | — |

### Best single-threaded variant: effective time per op (speedup vs own v0, variant)

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.23 ms (1.77×, v2) | 28.8 µs (1.00×, v0) | 259.7 µs (1.03×, v4) | 41.1 µs (2.52×, v1) | 118.6 µs (1.66×, v4) | 178.6 µs (1.06×, v2) |
| ML-DSA-65 | 4.34 ms (2.06×, v2) | 109.4 µs (1.04×, v1) | 1.23 ms (1.07×, v4) | 274.1 µs (1.36×, v1) | 813.4 µs (1.09×, v4) | 681.5 µs (1.12×, v4) |
| ML-DSA-87 | 3.23 ms (2.46×, v2) | 80.3 µs (1.18×, v2) | 861.8 µs (1.04×, v2) | 122.1 µs (2.58×, v1) | 498.6 µs (1.41×, v4) | 558.1 µs (1.00×, v0) |
| SLH-DSA-SHA2-128s | 1.28 s (1.62×, v2) | 520.29 ms (1.09×, v3) | 975.61 ms (1.03×, v4) | 1.02 s (1.06×, v3) | 655.35 ms (1.49×, v3) | 1.05 s (1.00×, v0) |
| SLH-DSA-SHA2-128f | 79.45 ms (1.33×, v2) | 25.97 ms (1.19×, v4) | 46.05 ms (1.03×, v4) | 52.24 ms (1.00×, v0) | 30.31 ms (1.20×, v1) | 50.08 ms (1.00×, v0) |
| SLH-DSA-SHA2-192s | 3.18 s (1.43×, v2) | 888.10 ms (1.53×, v3) | 1.77 s (1.06×, v1) | 1.84 s (1.06×, v3) | 1.18 s (1.14×, v3) | 1.97 s (1.00×, v0) |
| SLH-DSA-SHA2-192f | 128.53 ms (1.52×, v2) | 34.68 ms (1.73×, v3) | 77.35 ms (1.00×, v0) | 79.06 ms (1.11×, v1) | 48.41 ms (1.21×, v1) | 86.80 ms (1.01×, v2) |
| SLH-DSA-SHA2-256s | 2.93 s (1.42×, v2) | 777.60 ms (1.39×, v3) | 1.53 s (1.00×, v0) | 1.61 s (1.12×, v3) | 926.38 ms (1.36×, v3) | 1.74 s (1.06×, v2) |
| SLH-DSA-SHA2-256f | 257.14 ms (1.69×, v2) | 69.21 ms (1.47×, v3) | 154.89 ms (1.09×, v1) | 159.44 ms (1.06×, v3) | 101.79 ms (1.21×, v3) | 178.25 ms (1.00×, v0) |
| SLH-DSA-SHAKE-128s | 5.92 s (2.38×, v2) | 890.47 ms (1.27×, v2) | 997.01 ms (1.00×, v0) | 1.12 s (1.12×, v3) | 1.93 s (1.17×, v3) | 1.18 s (1.00×, v0) |
| SLH-DSA-SHAKE-128f | 418.06 ms (1.64×, v2) | 43.16 ms (1.16×, v4) | 44.89 ms (1.10×, v4) | 52.11 ms (1.50×, v3) | 92.69 ms (1.28×, v2) | 59.25 ms (1.11×, v2) |
| SLH-DSA-SHAKE-192s | 11.90 s (2.10×, v2) | 1.52 s (1.27×, v2) | 1.74 s (1.08×, v4) | 2.02 s (1.16×, v3) | 3.43 s (1.06×, v3) | 2.10 s (1.01×, v2) |
| SLH-DSA-SHAKE-192f | 628.54 ms (1.80×, v2) | 68.36 ms (1.67×, v4) | 78.32 ms (1.07×, v1) | 81.37 ms (1.27×, v3) | 156.18 ms (1.10×, v2) | 90.42 ms (1.24×, v4) |
| SLH-DSA-SHAKE-256s | 9.90 s (2.15×, v2) | 1.40 s (1.26×, v3) | 1.57 s (1.01×, v1) | 1.50 s (1.42×, v3) | 2.98 s (1.17×, v1) | 1.86 s (1.10×, v2) |
| SLH-DSA-SHAKE-256f | 1.00 s (2.34×, v2) | 147.36 ms (1.31×, v3) | 149.14 ms (1.08×, v4) | 162.91 ms (1.28×, v3) | 287.20 ms (1.17×, v1) | 197.43 ms (1.00×, v0) |
| Falcon-512 | 3.85 ms (1.19×, v3) | 230.9 µs (1.16×, v2) | — | — | — | — |
| Falcon-1024 | 9.63 ms (1.14×, v3) | 486.8 µs (1.27×, v1) | — | — | — | — |

### Variant leaderboard (geomean speedup vs v0 across params)

| lib | v1 | v2 | v3 | v4 | v5 |
|---|---|---|---|---|---|
| noble | native-hash: 0.77× | fastjs: 1.81× | keycache: 0.98× | bun: 0.83× | workers-x4: 3.00× (4 thr) |
| liboqs | internal-deterministic: 1.05× | march-native: 1.18× | fasthash: 1.16× | gcc-pgo: 1.15× | pthread-x4: 2.87× (4 thr) |
| openssl | prefetch-reuse-ctx: 1.00× | ctx-dup-template: 0.96× | no-asm-build: 0.74× | native-lto-build: 1.04× | pthread-x4: 2.91× (4 thr) |
| circl | preunpacked: 1.14× | purego: 0.63× | amd64v3: 1.13× | pgo: 1.00× | parallel: 3.45× (4 thr) |
| rustcrypto | native: 1.12× | lto: 1.05× | pgo: 1.15× | keycache: 1.09× | par: 3.45× (4 thr) |
| bouncycastle | lightweight: 0.94× | reuse-signer: 0.99× | parallel: 3.03× (4 thr) | c2-only: 0.98× | epsilon-nogc: 0.59× |

## verify

### Baseline (v0) median time per op

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.19 ms | **18.0 µs** | 131.8 µs | 46.4 µs | 102.5 µs | 105.4 µs |
| ML-DSA-65 | 2.21 ms | **28.6 µs** | 202.6 µs | 74.1 µs | 167.1 µs | 210.8 µs |
| ML-DSA-87 | 3.24 ms | **42.5 µs** | 324.2 µs | 132.3 µs | 270.8 µs | 285.9 µs |
| SLH-DSA-SHA2-128s | 2.30 ms | **602.3 µs** | 950.9 µs | 961.4 µs | 756.6 µs | 988.3 µs |
| SLH-DSA-SHA2-128f | 6.61 ms | **1.76 ms** | 2.72 ms | 2.86 ms | 2.19 ms | 2.92 ms |
| SLH-DSA-SHA2-192s | 3.96 ms | **842.8 µs** | 1.36 ms | 1.40 ms | 1.07 ms | 1.56 ms |
| SLH-DSA-SHA2-192f | 11.22 ms | 3.26 ms | 3.92 ms | 4.05 ms | **3.13 ms** | 5.16 ms |
| SLH-DSA-SHA2-256s | 5.62 ms | **1.30 ms** | 1.98 ms | 2.57 ms | 1.61 ms | 2.35 ms |
| SLH-DSA-SHA2-256f | 10.90 ms | **2.48 ms** | 3.87 ms | 4.60 ms | 3.18 ms | 4.66 ms |
| SLH-DSA-SHAKE-128s | 12.39 ms | 1.63 ms | **923.4 µs** | 1.08 ms | 1.89 ms | 1.06 ms |
| SLH-DSA-SHAKE-128f | 40.52 ms | 6.73 ms | **2.98 ms** | 3.49 ms | 6.13 ms | 3.41 ms |
| SLH-DSA-SHAKE-192s | 19.03 ms | 1.43 ms | **1.40 ms** | 1.58 ms | 2.93 ms | 1.68 ms |
| SLH-DSA-SHAKE-192f | 52.37 ms | 4.10 ms | **3.96 ms** | 4.60 ms | 7.90 ms | 4.87 ms |
| SLH-DSA-SHAKE-256s | 27.84 ms | 2.10 ms | **2.01 ms** | 2.30 ms | 4.15 ms | 2.48 ms |
| SLH-DSA-SHAKE-256f | 55.94 ms | 4.24 ms | **4.14 ms** | 4.93 ms | 8.87 ms | 4.94 ms |
| Falcon-512 | 583.4 µs | **39.7 µs** | — | — | — | — |
| Falcon-1024 | 1.11 ms | **78.4 µs** | — | — | — | — |

### Best single-threaded variant: effective time per op (speedup vs own v0, variant)

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 666.4 µs (2.89×, v2) | 19.1 µs (1.17×, v2) | 128.7 µs (1.10×, v4) | 20.4 µs (2.93×, v1) | 56.7 µs (1.93×, v4) | 109.3 µs (1.19×, v4) |
| ML-DSA-65 | 938.6 µs (2.59×, v3) | 31.4 µs (1.04×, v1) | 201.8 µs (1.07×, v4) | 25.9 µs (3.88×, v1) | 72.1 µs (2.94×, v4) | 182.7 µs (1.37×, v4) |
| ML-DSA-87 | 1.33 ms (2.74×, v3) | 46.1 µs (1.05×, v4) | 349.8 µs (1.01×, v2) | 37.7 µs (4.37×, v1) | 107.1 µs (2.94×, v4) | 265.5 µs (1.36×, v2) |
| SLH-DSA-SHA2-128s | 1.37 ms (1.75×, v2) | 434.8 µs (1.70×, v4) | 958.5 µs (1.12×, v1) | 1.02 ms (1.04×, v3) | 636.0 µs (1.27×, v1) | 981.4 µs (1.06×, v4) |
| SLH-DSA-SHA2-128f | 4.53 ms (1.49×, v2) | 1.29 ms (1.53×, v4) | 2.78 ms (1.02×, v4) | 3.09 ms (1.00×, v0) | 1.97 ms (1.16×, v3) | 2.97 ms (1.01×, v4) |
| SLH-DSA-SHA2-192s | 2.33 ms (1.87×, v2) | 655.3 µs (1.40×, v4) | 1.42 ms (1.00×, v0) | 1.45 ms (1.00×, v0) | 1.03 ms (1.12×, v3) | 1.43 ms (1.27×, v4) |
| SLH-DSA-SHA2-192f | 8.23 ms (1.50×, v2) | 1.82 ms (1.94×, v4) | 4.05 ms (1.00×, v0) | 4.24 ms (1.00×, v0) | 2.56 ms (1.45×, v3) | 4.34 ms (1.28×, v4) |
| SLH-DSA-SHA2-256s | 4.29 ms (1.44×, v2) | 960.6 µs (1.63×, v4) | 1.99 ms (1.00×, v0) | 2.22 ms (1.31×, v1) | 1.38 ms (1.30×, v1) | 2.35 ms (1.06×, v4) |
| SLH-DSA-SHA2-256f | 6.60 ms (1.77×, v2) | 1.98 ms (1.27×, v4) | 3.94 ms (1.00×, v0) | 4.37 ms (1.17×, v3) | 3.20 ms (1.02×, v3) | 4.37 ms (1.28×, v1) |
| SLH-DSA-SHAKE-128s | 5.97 ms (2.10×, v2) | 786.6 µs (1.88×, v2) | 911.0 µs (1.08×, v4) | 1.02 ms (1.25×, v3) | 1.96 ms (1.00×, v4) | 1.10 ms (1.09×, v2) |
| SLH-DSA-SHAKE-128f | 16.77 ms (2.55×, v2) | 2.62 ms (2.18×, v4) | 3.09 ms (1.00×, v4) | 3.44 ms (1.11×, v4) | 5.95 ms (1.23×, v2) | 3.48 ms (1.02×, v4) |
| SLH-DSA-SHAKE-192s | 8.56 ms (2.30×, v2) | 1.34 ms (1.19×, v2) | 1.37 ms (1.07×, v4) | 1.57 ms (1.11×, v4) | 2.74 ms (1.34×, v2) | 1.62 ms (1.25×, v2) |
| SLH-DSA-SHAKE-192f | 25.93 ms (2.03×, v2) | 3.67 ms (1.32×, v4) | 4.22 ms (1.00×, v0) | 4.12 ms (1.17×, v3) | 8.08 ms (1.08×, v2) | 5.04 ms (1.18×, v2) |
| SLH-DSA-SHAKE-256s | 11.56 ms (2.65×, v2) | 1.83 ms (1.21×, v4) | 2.06 ms (1.00×, v0) | 2.08 ms (1.21×, v3) | 4.22 ms (1.06×, v1) | 2.60 ms (1.07×, v2) |
| SLH-DSA-SHAKE-256f | 26.40 ms (2.39×, v2) | 3.85 ms (1.21×, v4) | 4.27 ms (1.02×, v4) | 4.66 ms (1.32×, v2) | 8.31 ms (1.28×, v2) | 4.85 ms (1.05×, v2) |
| Falcon-512 | 572.6 µs (1.26×, v3) | 41.4 µs (1.03×, v4) | — | — | — | — |
| Falcon-1024 | 1.04 ms (1.39×, v3) | 81.0 µs (1.01×, v2) | — | — | — | — |

### Variant leaderboard (geomean speedup vs v0 across params)

| lib | v1 | v2 | v3 | v4 | v5 |
|---|---|---|---|---|---|
| noble | native-hash: 0.91× | fastjs: 1.96× | pkcache: 1.12× | bun: 0.82× | workers-x4: 1.35× (4 thr) |
| liboqs | internal-direct: 1.05× | gcc-lto: 1.17× | clang-native: 1.08× | fasthash: 1.32× | pthread-x4: 2.21× (4 thr) |
| openssl | prefetch-reuse-ctx: 0.93× | external-mu: 1.01× | no-asm-build: 0.78× | native-lto-build: 1.01× | pthread-x4: 2.28× (4 thr) |
| circl | preunpacked: 1.32× | purego: 0.64× | amd64v3: 1.09× | pgo: 1.02× | parallel: 2.66× (4 thr) |
| rustcrypto | native: 1.03× | lto: 1.09× | pgo: 1.10× | keycache: 1.23× | par: 3.11× (4 thr) |
| bouncycastle | lightweight: 1.07× | reuse-verifier: 1.09× | parallel: 2.95× (4 thr) | parallelgc: 1.10× | inline-aggressive: 1.03× |


## Verify split into stages

Each stage timed in isolation with the library's own internals (v0) and its alternatives; canonical intermediate outputs are byte-compared across libraries (`results/MATCH.md`). Cells: v0 median → fastest correct single-threaded alternative (variant).

### ml-dsa / decode

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 56.7 µs → 27.6 µs (v1) | 1.0 µs → 0.4 µs (v3) | 2.0 µs → 1.8 µs (v1) | 2.8 µs → 1.9 µs (v1) | 5.6 µs → 4.4 µs (v1) | 5.1 µs → 3.2 µs (v1) | **liboqs decode.v3** 0.4 µs |
| ML-DSA-65 | 107.2 µs → 50.4 µs (v2) | 1.0 µs → 0.6 µs (v3) | 2.7 µs → 2.4 µs (v1) | 3.6 µs → 2.4 µs (v1) | 7.8 µs → 6.5 µs (v1) | 6.5 µs → 4.7 µs (v1) | **liboqs decode.v3** 0.6 µs |
| ML-DSA-87 | 125.2 µs → 64.0 µs (v1) | 1.4 µs → 0.8 µs (v3) | 3.7 µs → 3.2 µs (v1) | 5.1 µs → 3.4 µs (v1) | 10.3 µs → 8.4 µs (v1) | 8.4 µs → 6.3 µs (v1) | **liboqs decode.v3** 0.8 µs |

### ml-dsa / mu

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 59.1 µs → 7.2 µs (v3) | 2.8 µs → 0.4 µs (v2) | 4.0 µs → 0.4 µs (v1) | 4.3 µs → 0.5 µs (v1) | 4.6 µs → 0.6 µs (v1) | 5.3 µs → 0.8 µs (v1) | **liboqs mu.v2** 0.4 µs |
| ML-DSA-65 | 84.2 µs → 7.3 µs (v3) | 4.0 µs → 0.4 µs (v2) | 5.7 µs → 0.4 µs (v1) | 6.2 µs → 0.5 µs (v3) | 6.6 µs → 0.6 µs (v1) | 7.5 µs → 0.6 µs (v1) | **liboqs mu.v2** 0.4 µs |
| ML-DSA-87 | 109.9 µs → 6.9 µs (v3) | 5.2 µs → 0.4 µs (v2) | 7.4 µs → 0.4 µs (v1) | 8.1 µs → 0.5 µs (v3) | 8.6 µs → 0.5 µs (v1) | 9.7 µs → 0.6 µs (v1) | **liboqs mu.v2** 0.4 µs |

### ml-dsa / expandA

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 461.5 µs → 0.1 µs (v3) | 6.6 µs → 0.1 µs (v3) | 33.5 µs → 0.1 µs (v1) | 18.4 µs → 0.0 µs (v4) | 39.9 µs → 1.2 µs (v3) | 46.7 µs → 0.0 µs (v1) | **circl expandA.v4** 0.0 µs |
| ML-DSA-65 | 898.2 µs → 0.2 µs (v3) | 14.0 µs → 0.7 µs (v3) | 62.6 µs → 0.6 µs (v1) | 35.6 µs → 0.0 µs (v4) | 76.2 µs → 2.6 µs (v3) | 86.2 µs → 0.0 µs (v1) | **circl expandA.v4** 0.0 µs |
| ML-DSA-87 | 1.67 ms → 0.5 µs (v3) | 22.5 µs → 1.3 µs (v3) | 117.8 µs → 1.3 µs (v1) | 64.1 µs → 0.0 µs (v4) | 158.0 µs → 3.5 µs (v3) | 164.6 µs → 0.1 µs (v1) | **circl expandA.v4** 0.0 µs |

### ml-dsa / w_approx

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 808.1 µs → 174.0 µs (v1) | 4.6 µs → 3.6 µs (v2) | 80.6 µs → 24.8 µs (v4) | 9.1 µs → 7.4 µs (v2) | 39.1 µs → 24.0 µs (v1) | 40.5 µs → 31.4 µs (v1) | **liboqs w_approx.v2** 3.6 µs |
| ML-DSA-65 | 1.04 ms → 214.6 µs (v1) | 6.4 µs → 4.9 µs (v2) | 120.2 µs → 34.5 µs (v4) | 13.0 µs → 10.6 µs (v2) | 58.6 µs → 34.2 µs (v1) | 59.5 µs → 43.6 µs (v1) | **liboqs w_approx.v2** 4.9 µs |
| ML-DSA-87 | 1.42 ms → 345.4 µs (v1) | 8.7 µs → 6.7 µs (v2) | 171.5 µs → 48.4 µs (v4) | 18.9 µs → 15.5 µs (v2) | 84.9 µs → 46.7 µs (v1) | 81.9 µs → 63.0 µs (v1) | **liboqs w_approx.v2** 6.7 µs |

### ml-dsa / hint_check

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 69.6 µs → 33.3 µs (v2) | 2.9 µs → 2.5 µs (v5) | 12.3 µs → 9.1 µs (v4) | 6.5 µs → 6.0 µs (v1) | 14.4 µs → 8.2 µs (v1) | 7.8 µs → 6.1 µs (v1) | **liboqs hint_check.v5** 2.5 µs |
| ML-DSA-65 | 78.1 µs → 44.5 µs (v2) | 2.6 µs → 2.3 µs (v5) | 14.3 µs → 10.9 µs (v4) | 7.0 µs → 6.3 µs (v1) | 16.8 µs → 10.6 µs (v1) | 8.7 µs → 6.1 µs (v1) | **liboqs hint_check.v5** 2.3 µs |
| ML-DSA-87 | 104.2 µs → 59.6 µs (v2) | 3.4 µs → 3.0 µs (v5) | 19.4 µs → 14.5 µs (v4) | 8.6 µs → 8.1 µs (v1) | 22.4 µs → 14.2 µs (v1) | 11.5 µs → 8.0 µs (v1) | **liboqs hint_check.v5** 3.0 µs |

### slh-dsa / hmsg

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 18.6 µs → 15.4 µs (v3) | 1.4 µs → 1.0 µs (v1) | 0.9 µs → 0.8 µs (v3) | 3.2 µs → 1.0 µs (v2) | 3.0 µs → 1.3 µs (v1) | 1.7 µs → 1.0 µs (v1) | **openssl hmsg.v3** 0.8 µs |
| SLH-DSA-SHA2-128f | 30.4 µs → 23.4 µs (v3) | 1.9 µs → 1.4 µs (v1) | 1.3 µs → 1.0 µs (v4) | 4.2 µs → 1.4 µs (v2) | 5.0 µs → 1.7 µs (v2) | 2.5 µs → 1.4 µs (v1) | **openssl hmsg.v4** 1.0 µs |
| SLH-DSA-SHA2-192s | 29.6 µs → 25.3 µs (v3) | 2.1 µs → 1.5 µs (v1) | 1.3 µs → 1.1 µs (v3) | 5.2 µs → 1.2 µs (v2) | 4.5 µs → 1.1 µs (v1) | 2.4 µs → 1.3 µs (v1) | **openssl hmsg.v3** 1.1 µs |
| SLH-DSA-SHA2-192f | 36.1 µs → 28.0 µs (v1) | 2.2 µs → 1.5 µs (v1) | 1.3 µs → 1.1 µs (v3) | 4.5 µs → 1.3 µs (v2) | 10.0 µs → 1.2 µs (v2) | 2.4 µs → 1.3 µs (v1) | **openssl hmsg.v3** 1.1 µs |
| SLH-DSA-SHA2-256s | 33.6 µs → 24.2 µs (v1) | 2.2 µs → 1.5 µs (v1) | 1.2 µs → 1.0 µs (v3) | 6.0 µs → 1.2 µs (v2) | 7.1 µs → 1.2 µs (v1) | 2.4 µs → 1.3 µs (v1) | **openssl hmsg.v3** 1.0 µs |
| SLH-DSA-SHA2-256f | 54.9 µs → 28.3 µs (v1) | 3.6 µs → 1.5 µs (v1) | 1.2 µs → 1.0 µs (v3) | 6.8 µs → 1.2 µs (v2) | 12.8 µs → 1.1 µs (v1) | 2.4 µs → 1.3 µs (v1) | **openssl hmsg.v3** 1.0 µs |
| SLH-DSA-SHAKE-128s | 16.3 µs → 12.0 µs (v2) | 0.5 µs → 0.5 µs (v5) | 0.5 µs → 0.4 µs (v3) | 3.4 µs → 0.6 µs (v2) | 2.6 µs → 0.6 µs (v2) | 0.6 µs → 0.6 µs (v0) | **openssl hmsg.v3** 0.4 µs |
| SLH-DSA-SHAKE-128f | 26.8 µs → 19.8 µs (v2) | 0.5 µs → 0.5 µs (v5) | 0.5 µs → 0.4 µs (v3) | 3.9 µs → 0.6 µs (v2) | 4.0 µs → 0.5 µs (v2) | 0.6 µs → 0.6 µs (v0) | **openssl hmsg.v3** 0.4 µs |
| SLH-DSA-SHAKE-192s | 22.0 µs → 13.5 µs (v1) | 1.0 µs → 0.8 µs (v2) | 0.8 µs → 0.8 µs (v3) | 3.4 µs → 1.0 µs (v2) | 4.7 µs → 1.0 µs (v2) | 1.0 µs → 1.0 µs (v0) | **openssl hmsg.v3** 0.8 µs |
| SLH-DSA-SHAKE-192f | 29.9 µs → 20.2 µs (v1) | 1.0 µs → 0.8 µs (v2) | 0.8 µs → 0.8 µs (v3) | 4.0 µs → 2.1 µs (v2) | 10.1 µs → 1.0 µs (v2) | 2.0 µs → 1.1 µs (v2) | **openssl hmsg.v3** 0.8 µs |
| SLH-DSA-SHAKE-256s | 24.3 µs → 15.1 µs (v1) | 1.0 µs → 0.8 µs (v2) | 0.8 µs → 0.8 µs (v2) | 4.1 µs → 1.0 µs (v2) | 7.3 µs → 1.0 µs (v2) | 1.1 µs → 1.1 µs (v0) | **openssl hmsg.v2** 0.8 µs |
| SLH-DSA-SHAKE-256f | 27.8 µs → 20.8 µs (v1) | 1.0 µs → 0.8 µs (v2) | 0.8 µs → 0.8 µs (v3) | 5.1 µs → 1.0 µs (v2) | 13.1 µs → 1.0 µs (v2) | 1.1 µs → 1.1 µs (v0) | **openssl hmsg.v3** 0.8 µs |

### slh-dsa / fors

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 178.6 µs → 96.5 µs (v1) | 52.1 µs → 38.8 µs (v1) | 75.2 µs → 37.5 µs (v3) | 79.0 µs → 44.3 µs (v3) | 63.6 µs → 48.4 µs (v5) | 85.4 µs → 46.3 µs (v3) | **openssl fors.v3** 37.5 µs |
| SLH-DSA-SHA2-128f | 236.9 µs → 129.4 µs (v1) | 67.0 µs → 50.1 µs (v1) | 97.0 µs → 76.4 µs (v3) | 104.1 µs → 57.3 µs (v3) | 81.1 µs → 62.1 µs (v5) | 113.7 µs → 60.0 µs (v3) | **liboqs fors.v1** 50.1 µs |
| SLH-DSA-SHA2-192s | 870.5 µs → 480.5 µs (v1) | 95.5 µs → 68.1 µs (v1) | 146.8 µs → 71.6 µs (v3) | 217.8 µs → 80.7 µs (v3) | 82.0 µs → 69.6 µs (v5) | 188.5 µs → 86.8 µs (v3) | **liboqs fors.v1** 68.1 µs |
| SLH-DSA-SHA2-192f | 957.4 µs → 554.2 µs (v1) | 111.8 µs → 95.6 µs (v4) | 169.3 µs → 83.1 µs (v3) | 234.7 µs → 92.1 µs (v3) | 95.7 µs → 82.4 µs (v5) | 218.1 µs → 101.6 µs (v3) | **rustcrypto fors.v5** 82.4 µs |
| SLH-DSA-SHA2-256s | 882.0 µs → 657.2 µs (v1) | 123.6 µs → 88.4 µs (v1) | 188.7 µs → 94.5 µs (v3) | 288.0 µs → 126.3 µs (v3) | 106.1 µs → 89.5 µs (v5) | 246.0 µs → 116.8 µs (v3) | **liboqs fors.v1** 88.4 µs |
| SLH-DSA-SHA2-256f | 881.7 µs → 687.8 µs (v1) | 132.3 µs → 93.9 µs (v1) | 199.4 µs → 98.4 µs (v3) | 302.9 µs → 112.5 µs (v3) | 117.9 µs → 95.7 µs (v5) | 268.0 µs → 121.9 µs (v3) | **liboqs fors.v1** 93.9 µs |
| SLH-DSA-SHAKE-128s | 1.11 ms → 466.9 µs (v1) | 89.4 µs → 75.8 µs (v4) | 155.5 µs → 74.8 µs (v3) | 85.8 µs → 78.7 µs (v4) | 169.3 µs → 33.5 µs (v2) | 95.8 µs → 95.8 µs (v0) | **rustcrypto fors.v2** 33.5 µs |
| SLH-DSA-SHAKE-128f | 2.35 ms → 597.5 µs (v1) | 114.6 µs → 96.9 µs (v4) | 105.7 µs → 93.7 µs (v3) | 110.0 µs → 101.0 µs (v4) | 208.3 µs → 41.7 µs (v2) | 123.9 µs → 123.9 µs (v0) | **rustcrypto fors.v2** 41.7 µs |
| SLH-DSA-SHAKE-192s | 1.60 ms → 635.8 µs (v1) | 129.4 µs → 112.1 µs (v5) | 111.9 µs → 102.7 µs (v3) | 117.7 µs → 106.9 µs (v4) | 230.6 µs → 49.7 µs (v2) | 135.7 µs → 135.7 µs (v0) | **rustcrypto fors.v2** 49.7 µs |
| SLH-DSA-SHAKE-192f | 1.98 ms → 801.7 µs (v1) | 153.2 µs → 131.6 µs (v5) | 131.4 µs → 120.6 µs (v3) | 138.0 µs → 125.3 µs (v4) | 280.0 µs → 54.9 µs (v2) | 162.1 µs → 162.1 µs (v0) | **rustcrypto fors.v2** 54.9 µs |
| SLH-DSA-SHAKE-256s | 2.19 ms → 833.5 µs (v1) | 176.1 µs → 150.8 µs (v2) | 148.4 µs → 136.3 µs (v3) | 150.8 µs → 134.2 µs (v4) | 296.6 µs → 59.5 µs (v2) | 180.1 µs → 180.1 µs (v0) | **rustcrypto fors.v2** 59.5 µs |
| SLH-DSA-SHAKE-256f | 2.40 ms → 900.6 µs (v1) | 188.4 µs → 162.8 µs (v5) | 180.4 µs → 142.1 µs (v3) | 161.0 µs → 143.3 µs (v4) | 314.4 µs → 60.9 µs (v2) | 197.1 µs → 197.1 µs (v0) | **rustcrypto fors.v2** 60.9 µs |

### slh-dsa / ht_wots

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 1.86 ms → 978.7 µs (v1) | 496.2 µs → 370.4 µs (v1) | 813.0 µs → 395.4 µs (v3) | 832.5 µs → 515.1 µs (v3) | 659.2 µs → 552.1 µs (v5) | 861.5 µs → 488.6 µs (v4) | **liboqs ht_wots.v1** 370.4 µs |
| SLH-DSA-SHA2-128f | 6.13 ms → 2.93 ms (v1) | 1.57 ms → 1.16 ms (v1) | 2.84 ms → 1.24 ms (v3) | 2.78 ms → 1.61 ms (v3) | 2.08 ms → 1.71 ms (v4) | 2.65 ms → 1.57 ms (v4) | **liboqs ht_wots.v1** 1.16 ms |
| SLH-DSA-SHA2-192s | 3.03 ms → 1.47 ms (v1) | 746.3 µs → 533.9 µs (v1) | 1.15 ms → 562.6 µs (v3) | 1.22 ms → 730.2 µs (v3) | 964.1 µs → 769.1 µs (v5) | 1.23 ms → 808.5 µs (v4) | **liboqs ht_wots.v1** 533.9 µs |
| SLH-DSA-SHA2-192f | 9.56 ms → 4.90 ms (v1) | 2.61 ms → 1.69 ms (v1) | 3.71 ms → 1.80 ms (v3) | 4.00 ms → 2.47 ms (v3) | 3.03 ms → 2.46 ms (v5) | 4.05 ms → 2.57 ms (v1) | **liboqs ht_wots.v1** 1.69 ms |
| SLH-DSA-SHA2-256s | 4.78 ms → 2.55 ms (v1) | 2.38 ms → 813.5 µs (v1) | 1.75 ms → 868.4 µs (v3) | 2.93 ms → 1.17 ms (v3) | 1.48 ms → 1.22 ms (v4) | 1.88 ms → 1.24 ms (v4) | **liboqs ht_wots.v1** 813.5 µs |
| SLH-DSA-SHA2-256f | 9.40 ms → 5.10 ms (v1) | 2.57 ms → 1.69 ms (v1) | 3.75 ms → 1.82 ms (v3) | 3.81 ms → 2.33 ms (v3) | 3.04 ms → 2.53 ms (v5) | 3.94 ms → 2.56 ms (v4) | **liboqs ht_wots.v1** 1.69 ms |
| SLH-DSA-SHAKE-128s | 10.77 ms → 4.21 ms (v1) | 816.3 µs → 666.6 µs (v5) | 809.1 µs → 738.0 µs (v3) | 880.9 µs → 816.2 µs (v4) | 1.63 ms → 319.1 µs (v2) | 903.3 µs → 903.3 µs (v0) | **rustcrypto ht_wots.v2** 319.1 µs |
| SLH-DSA-SHAKE-128f | 37.62 ms → 15.56 ms (v1) | 5.91 ms → 2.36 ms (v5) | 2.77 ms → 2.58 ms (v3) | 3.05 ms → 2.83 ms (v4) | 5.61 ms → 1.08 ms (v2) | 3.21 ms → 3.21 ms (v0) | **rustcrypto ht_wots.v2** 1.08 ms |
| SLH-DSA-SHAKE-192s | 16.97 ms → 7.02 ms (v1) | 1.31 ms → 1.03 ms (v4) | 1.26 ms → 1.18 ms (v2) | 1.43 ms → 1.22 ms (v4) | 2.49 ms → 514.0 µs (v2) | 1.44 ms → 1.44 ms (v0) | **rustcrypto ht_wots.v2** 514.0 µs |
| SLH-DSA-SHAKE-192f | 50.48 ms → 20.98 ms (v1) | 4.02 ms → 3.19 ms (v4) | 3.89 ms → 3.60 ms (v3) | 4.09 ms → 3.78 ms (v4) | 7.58 ms → 1.55 ms (v2) | 4.53 ms → 4.53 ms (v0) | **rustcrypto ht_wots.v2** 1.55 ms |
| SLH-DSA-SHAKE-256s | 26.02 ms → 9.95 ms (v1) | 1.88 ms → 1.54 ms (v2) | 1.83 ms → 1.69 ms (v3) | 2.24 ms → 1.80 ms (v4) | 3.70 ms → 763.4 µs (v2) | 2.16 ms → 2.16 ms (v0) | **rustcrypto ht_wots.v2** 763.4 µs |
| SLH-DSA-SHAKE-256f | 53.21 ms → 21.57 ms (v1) | 4.30 ms → 3.29 ms (v5) | 3.89 ms → 3.61 ms (v3) | 4.13 ms → 3.86 ms (v4) | 8.10 ms → 1.64 ms (v2) | 4.86 ms → 4.86 ms (v0) | **rustcrypto ht_wots.v2** 1.64 ms |

### slh-dsa / ht_auth

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle | best overall |
|---|---|---|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 66.1 µs → 35.2 µs (v1) | 17.3 µs → 13.1 µs (v1) | 25.8 µs → 12.8 µs (v3) | 27.2 µs → 15.6 µs (v3) | 22.0 µs → 16.8 µs (v5) | 28.3 µs → 15.8 µs (v3) | **openssl ht_auth.v3** 12.8 µs |
| SLH-DSA-SHA2-128f | 90.6 µs → 46.5 µs (v1) | 18.1 µs → 13.9 µs (v1) | 27.4 µs → 13.6 µs (v3) | 31.0 µs → 17.1 µs (v3) | 23.1 µs → 17.7 µs (v5) | 31.8 µs → 16.8 µs (v3) | **openssl ht_auth.v3** 13.6 µs |
| SLH-DSA-SHA2-192s | 190.2 µs → 120.6 µs (v1) | 23.4 µs → 16.9 µs (v1) | 35.5 µs → 17.6 µs (v3) | 34.6 µs → 19.7 µs (v3) | 20.0 µs → 17.3 µs (v5) | 45.0 µs → 21.2 µs (v3) | **liboqs ht_auth.v1** 16.9 µs |
| SLH-DSA-SHA2-192f | 213.6 µs → 155.4 µs (v1) | 24.7 µs → 17.8 µs (v1) | 57.8 µs → 18.6 µs (v3) | 37.0 µs → 21.4 µs (v3) | 21.0 µs → 18.1 µs (v5) | 47.7 µs → 22.6 µs (v3) | **liboqs ht_auth.v1** 17.8 µs |
| SLH-DSA-SHA2-256s | 163.1 µs → 127.6 µs (v1) | 23.8 µs → 17.2 µs (v1) | 36.0 µs → 17.9 µs (v3) | 35.3 µs → 20.0 µs (v3) | 20.2 µs → 17.1 µs (v5) | 46.3 µs → 21.6 µs (v3) | **rustcrypto ht_auth.v5** 17.1 µs |
| SLH-DSA-SHA2-256f | 193.5 µs → 141.8 µs (v1) | 25.2 µs → 18.2 µs (v1) | 38.5 µs → 19.0 µs (v3) | 37.8 µs → 21.5 µs (v3) | 21.6 µs → 18.4 µs (v5) | 49.6 µs → 23.5 µs (v3) | **liboqs ht_auth.v1** 18.2 µs |
| SLH-DSA-SHAKE-128s | 380.2 µs → 153.1 µs (v1) | 30.7 µs → 25.8 µs (v5) | 27.2 µs → 25.0 µs (v3) | 29.9 µs → 27.8 µs (v4) | 56.7 µs → 11.2 µs (v2) | 31.9 µs → 31.9 µs (v0) | **rustcrypto ht_auth.v2** 11.2 µs |
| SLH-DSA-SHAKE-128f | 435.7 µs → 184.1 µs (v1) | 32.3 µs → 27.3 µs (v5) | 28.8 µs → 26.5 µs (v3) | 47.5 µs → 30.1 µs (v4) | 58.7 µs → 11.6 µs (v2) | 33.5 µs → 33.5 µs (v0) | **rustcrypto ht_auth.v2** 11.6 µs |
| SLH-DSA-SHAKE-192s | 385.0 µs → 156.1 µs (v1) | 31.7 µs → 27.0 µs (v5) | 27.2 µs → 25.1 µs (v3) | 29.2 µs → 26.6 µs (v4) | 56.5 µs → 11.5 µs (v2) | 32.4 µs → 32.4 µs (v0) | **rustcrypto ht_auth.v2** 11.5 µs |
| SLH-DSA-SHAKE-192f | 415.9 µs → 182.4 µs (v1) | 33.5 µs → 28.6 µs (v5) | 29.1 µs → 26.6 µs (v3) | 32.5 µs → 28.8 µs (v4) | 58.7 µs → 12.1 µs (v2) | 34.3 µs → 34.3 µs (v0) | **rustcrypto ht_auth.v2** 12.1 µs |
| SLH-DSA-SHAKE-256s | 392.6 µs → 162.0 µs (v1) | 33.4 µs → 28.6 µs (v2) | 27.6 µs → 25.3 µs (v3) | 29.1 µs → 26.1 µs (v4) | 56.4 µs → 10.3 µs (v2) | 33.6 µs → 33.6 µs (v0) | **rustcrypto ht_auth.v2** 10.3 µs |
| SLH-DSA-SHAKE-256f | 435.0 µs → 180.7 µs (v1) | 35.6 µs → 30.6 µs (v5) | 29.5 µs → 27.1 µs (v3) | 32.0 µs → 28.3 µs (v4) | 60.0 µs → 13.0 µs (v2) | 35.8 µs → 35.8 µs (v0) | **rustcrypto ht_auth.v2** 13.0 µs |

### Best possible verify: stage-wise best of all libraries vs best real implementations

"best-of-breed" sums the fastest correct implementation of every stage across all libraries (a lower bound if one implementation combined them all). It is compared with the fastest assembled pipeline per library (`total_best`) and the fastest end-to-end verify variant from the main benchmark.

| param | best-of-breed (sum of stage minima) | stage winners | best `total_best` (lib) | best end-to-end verify variant (lib) |
|---|---|---|---|---|
| ML-DSA-44 | 6.9 µs | decode: liboqs, mu: liboqs, expandA: circl, w_approx: liboqs, hint_check: liboqs | 8.2 µs (liboqs) | 17.4 µs (liboqs verify.v3) |
| ML-DSA-65 | 8.1 µs | decode: liboqs, mu: liboqs, expandA: circl, w_approx: liboqs, hint_check: liboqs | 9.8 µs (liboqs) | 22.7 µs (circl verify.v1) |
| ML-DSA-87 | 10.8 µs | decode: liboqs, mu: liboqs, expandA: circl, w_approx: liboqs, hint_check: liboqs | 13.4 µs (liboqs) | 31.4 µs (circl verify.v1) |
| SLH-DSA-SHA2-128s | 421.6 µs | hmsg: openssl, fors: openssl, ht_wots: liboqs, ht_auth: openssl | 453.7 µs (openssl) | 425.6 µs (liboqs verify.v4) |
| SLH-DSA-SHA2-128f | 1.22 ms | hmsg: openssl, fors: liboqs, ht_wots: liboqs, ht_auth: openssl | 1.33 ms (openssl) | 1.24 ms (liboqs verify.v4) |
| SLH-DSA-SHA2-192s | 619.9 µs | hmsg: openssl, fors: liboqs, ht_wots: liboqs, ht_auth: liboqs | 657.7 µs (openssl) | 625.3 µs (liboqs verify.v4) |
| SLH-DSA-SHA2-192f | 1.79 ms | hmsg: openssl, fors: rustcrypto, ht_wots: liboqs, ht_auth: liboqs | 2.01 ms (openssl) | 1.77 ms (liboqs verify.v4) |
| SLH-DSA-SHA2-256s | 920.1 µs | hmsg: openssl, fors: liboqs, ht_wots: liboqs, ht_auth: rustcrypto | 994.7 µs (openssl) | 926.3 µs (liboqs verify.v4) |
| SLH-DSA-SHA2-256f | 1.80 ms | hmsg: openssl, fors: liboqs, ht_wots: liboqs, ht_auth: liboqs | 1.92 ms (openssl) | 1.83 ms (liboqs verify.v4) |
| SLH-DSA-SHAKE-128s | 364.2 µs | hmsg: openssl, fors: rustcrypto, ht_wots: rustcrypto, ht_auth: rustcrypto | 414.4 µs (rustcrypto) | 769.1 µs (liboqs verify.v2) |
| SLH-DSA-SHAKE-128f | 1.14 ms | hmsg: openssl, fors: rustcrypto, ht_wots: rustcrypto, ht_auth: rustcrypto | 1.28 ms (rustcrypto) | 2.48 ms (liboqs verify.v2) |
| SLH-DSA-SHAKE-192s | 576.0 µs | hmsg: openssl, fors: rustcrypto, ht_wots: rustcrypto, ht_auth: rustcrypto | 609.9 µs (rustcrypto) | 1.20 ms (liboqs verify.v2) |
| SLH-DSA-SHAKE-192f | 1.62 ms | hmsg: openssl, fors: rustcrypto, ht_wots: rustcrypto, ht_auth: rustcrypto | 1.73 ms (rustcrypto) | 3.44 ms (liboqs verify.v2) |
| SLH-DSA-SHAKE-256s | 834.0 µs | hmsg: openssl, fors: rustcrypto, ht_wots: rustcrypto, ht_auth: rustcrypto | 879.8 µs (rustcrypto) | 1.80 ms (liboqs verify.v4) |
| SLH-DSA-SHAKE-256f | 1.72 ms | hmsg: openssl, fors: rustcrypto, ht_wots: rustcrypto, ht_auth: rustcrypto | 1.99 ms (rustcrypto) | 3.59 ms (liboqs verify.v2) |

## Memory: peak stack per operation

v0 = baseline variant; "min" = smallest stack among that process's variants (single-threaded or per worker). Methods differ by runtime (see each `docs/<lib>/memory.md`), so compare within a language more than across.

### keygen

| param | noble v0 / min | liboqs v0 / min | openssl v0 / min | circl v0 / min | rustcrypto v0 / min | bouncycastle v0 / min |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 1.9 KiB / 1.1 KiB (v4) | 30.5 KiB / 30.4 KiB (v1) | 2.1 KiB / 1.9 KiB (v1) | 8.3 KiB / 7.2 KiB (v1) | 196.9 KiB / 193.8 KiB (v2) | 1.9 KiB / 379 B (v3) |
| ML-DSA-65 | 1.9 KiB / 1.2 KiB (v4) | 47.5 KiB / 47.4 KiB (v1) | 2.1 KiB / 1.9 KiB (v1) | 10.9 KiB / 9.9 KiB (v1) | 272.5 KiB / 272.5 KiB | 632 B / 237 B (v4) |
| ML-DSA-87 | 1.9 KiB / 1.1 KiB (v4) | 77.5 KiB / 77.4 KiB (v1) | 2.1 KiB / 1.9 KiB (v1) | 13.6 KiB / 12.5 KiB (v1) | 428.4 KiB / 422.4 KiB (v3) | 632 B / 253 B (v4) |
| SLH-DSA-SHA2-128s | 2.2 KiB / 2.2 KiB | 3.9 KiB / 3.6 KiB (v3) | 6.7 KiB / 5.9 KiB (v3) | 4.2 KiB / 3.9 KiB (v1) | 7.0 KiB / 6.9 KiB (v1) | 1.5 KiB / 790 B (v1) |
| SLH-DSA-SHA2-128f | 2.2 KiB / 1.2 KiB (v4) | 3.9 KiB / 3.6 KiB (v3) | 5.7 KiB / 4.7 KiB (v3) | 4.2 KiB / 3.9 KiB (v1) | 2.5 KiB / 2.4 KiB (v1) | 1011 B / 727 B (v1) |
| SLH-DSA-SHA2-192s | 2.2 KiB / 2.2 KiB | 4.3 KiB / 3.7 KiB (v3) | 7.7 KiB / 6.0 KiB (v3) | 4.2 KiB / 3.9 KiB (v3) | 3.5 KiB / 3.1 KiB (v3) | 1011 B / 569 B (v1) |
| SLH-DSA-SHA2-192f | 2.2 KiB / 1.5 KiB (v4) | 4.3 KiB / 3.7 KiB (v3) | 7.7 KiB / 4.8 KiB (v3) | 4.2 KiB / 3.9 KiB (v3) | 2.7 KiB / 2.2 KiB (v3) | 758 B / 158 B (v1) |
| SLH-DSA-SHA2-256s | 2.2 KiB / 2.2 KiB | 4.3 KiB / 3.7 KiB (v3) | 7.7 KiB / 5.8 KiB (v3) | 4.2 KiB / 3.9 KiB (v3) | 4.5 KiB / 4.3 KiB (v2) | 758 B / 158 B (v1) |
| SLH-DSA-SHA2-256f | 2.2 KiB / 1.5 KiB (v4) | 4.3 KiB / 3.7 KiB (v3) | 7.7 KiB / 5.0 KiB (v3) | 4.2 KiB / 3.9 KiB (v3) | 3.9 KiB / 3.6 KiB (v2) | 758 B / 126 B (v1) |
| SLH-DSA-SHAKE-128s | 2.2 KiB / 2.2 KiB | 3.6 KiB / 3.6 KiB (v1) | 6.0 KiB / 5.8 KiB (v1) | 3.5 KiB / 3.5 KiB (v2) | 8.2 KiB / 8.1 KiB (v2) | 758 B / 316 B (v1) |
| SLH-DSA-SHAKE-128f | 2.2 KiB / 1.1 KiB (v4) | 3.6 KiB / 3.6 KiB (v1) | 4.8 KiB / 4.6 KiB (v1) | 3.5 KiB / 3.5 KiB (v2) | 3.7 KiB / 3.0 KiB (v3) | 758 B / 284 B (v1) |
| SLH-DSA-SHAKE-192s | 2.2 KiB / 2.2 KiB | 3.6 KiB / 3.6 KiB (v1) | 6.0 KiB / 5.8 KiB (v1) | 3.5 KiB / 3.5 KiB (v2) | 3.7 KiB / 3.5 KiB (v2) | 648 B / 158 B (v1) |
| SLH-DSA-SHAKE-192f | 2.4 KiB / 1.1 KiB (v4) | 3.6 KiB / 3.6 KiB (v1) | 4.8 KiB / 4.6 KiB (v1) | 3.5 KiB / 3.5 KiB (v2) | 2.8 KiB / 2.7 KiB (v2) | 0 B / 0 B |
| SLH-DSA-SHAKE-256s | 2.2 KiB / 2.2 KiB | 3.6 KiB / 3.6 KiB (v1) | 5.8 KiB / 5.6 KiB (v1) | 3.5 KiB / 3.5 KiB (v2) | 4.7 KiB / 4.5 KiB (v2) | 0 B / 0 B |
| SLH-DSA-SHAKE-256f | 2.2 KiB / 1.1 KiB (v4) | 3.6 KiB / 3.6 KiB (v1) | 5.0 KiB / 4.8 KiB (v1) | 3.5 KiB / 3.5 KiB (v2) | 4.1 KiB / 3.9 KiB (v2) | 0 B / 0 B |
| Falcon-512 | 4.2 KiB / 3.2 KiB (v4) | 18.4 KiB / 17.8 KiB (v4) | — | — | — | — |
| Falcon-1024 | 4.4 KiB / 3.2 KiB (v4) | 34.9 KiB / 34.5 KiB (v4) | — | — | — | — |

keygen, heap allocated per op (v0):

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 53.2 KiB | 6.2 KiB | 46.2 KiB | 58.0 KiB | 92.1 KiB | 66.2 KiB |
| ML-DSA-65 | 80.7 KiB | 9.3 KiB | 72.2 KiB | 86.0 KiB | 154.1 KiB | 108.9 KiB |
| ML-DSA-87 | 126.8 KiB | 15.6 KiB | 111.7 KiB | 122.5 KiB | 253.6 KiB | 172.8 KiB |
| SLH-DSA-SHA2-128s | 67.99 MiB | 280 B | 21.7 KiB | 1.7 KiB | 96 B | 10.29 MiB |
| SLH-DSA-SHA2-128f | 1.07 MiB | 280 B | 2.0 KiB | 1.4 KiB | 96 B | 167.0 KiB |
| SLH-DSA-SHA2-192s | 101.84 MiB | 280 B | 22.0 KiB | 2.2 KiB | 144 B | 18.34 MiB |
| SLH-DSA-SHA2-192f | 1.61 MiB | 280 B | 2.3 KiB | 1.9 KiB | 144 B | 296.6 KiB |
| SLH-DSA-SHA2-256s | 67.31 MiB | 280 B | 12.0 KiB | 2.3 KiB | 192 B | 14.26 MiB |
| SLH-DSA-SHA2-256f | 4.23 MiB | 280 B | 2.6 KiB | 2.1 KiB | 192 B | 915.7 KiB |
| SLH-DSA-SHAKE-128s | 36.74 MiB | 280 B | 21.6 KiB | 1.8 KiB | 96 B | 10.29 MiB |
| SLH-DSA-SHAKE-128f | 600.4 KiB | 280 B | 1.9 KiB | 1.5 KiB | 96 B | 166.4 KiB |
| SLH-DSA-SHAKE-192s | 53.41 MiB | 280 B | 21.6 KiB | 2.2 KiB | 144 B | 18.34 MiB |
| SLH-DSA-SHAKE-192f | 865.1 KiB | 280 B | 1.9 KiB | 1.8 KiB | 144 B | 295.3 KiB |
| SLH-DSA-SHAKE-256s | 35.05 MiB | 280 B | 11.6 KiB | 2.3 KiB | 192 B | 14.26 MiB |
| SLH-DSA-SHAKE-256f | 2.21 MiB | 280 B | 2.2 KiB | 2.0 KiB | 192 B | 914.4 KiB |
| Falcon-512 | 178.37 MiB | 544 B | — | — | — | — |
| Falcon-1024 | — | 544 B | — | — | — | — |

### sign

| param | noble v0 / min | liboqs v0 / min | openssl v0 / min | circl v0 / min | rustcrypto v0 / min | bouncycastle v0 / min |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 2.2 KiB / 2.2 KiB | 48.6 KiB / 48.0 KiB (v1) | 3.6 KiB / 3.3 KiB (v1) | 44.6 KiB / 43.8 KiB (v2) | 105.1 KiB / 64.9 KiB (v4) | 600 B / 316 B (v3) |
| ML-DSA-65 | 1.9 KiB / 1.9 KiB | 72.6 KiB / 72.0 KiB (v1) | 3.6 KiB / 3.3 KiB (v1) | 61.6 KiB / 60.9 KiB (v2) | 158.2 KiB / 89.8 KiB (v4) | 474 B / 379 B (v1) |
| ML-DSA-87 | 2.2 KiB / 1.5 KiB (v4) | 110.6 KiB / 110.0 KiB (v1) | 3.6 KiB / 3.3 KiB (v1) | 81.8 KiB / 81.2 KiB (v2) | 269.0 KiB / 127.4 KiB (v4) | 411 B / 379 B (v1) |
| SLH-DSA-SHA2-128s | — | 4.7 KiB / 4.6 KiB (v1) | 8.7 KiB / 7.4 KiB (v3) | 3.9 KiB / 3.6 KiB (v2) | 43.2 KiB / 43.2 KiB (v4) | 1.5 KiB / 1.4 KiB (v3) |
| SLH-DSA-SHA2-128f | 2.4 KiB / 2.0 KiB (v4) | 4.7 KiB / 4.6 KiB (v1) | 6.7 KiB / 6.2 KiB (v3) | 3.9 KiB / 3.6 KiB (v2) | 93.6 KiB / 83.3 KiB (v2) | 1.2 KiB / 1.0 KiB (v2) |
| SLH-DSA-SHA2-192s | — | 5.1 KiB / 5.0 KiB (v1) | 9.7 KiB / 7.5 KiB (v3) | 3.9 KiB / 3.7 KiB (v4) | 89.3 KiB / 79.6 KiB (v3) | 1.1 KiB / 853 B (v2) |
| SLH-DSA-SHA2-192f | 2.4 KiB / 2.4 KiB | 5.1 KiB / 5.0 KiB (v1) | 7.7 KiB / 6.3 KiB (v3) | 3.9 KiB / 3.7 KiB (v4) | 200.5 KiB / 172.5 KiB (v3) | 411 B / 411 B |
| SLH-DSA-SHA2-256s | — | 5.2 KiB / 5.0 KiB (v1) | 9.7 KiB / 7.3 KiB (v3) | 3.9 KiB / 3.7 KiB (v4) | 163.0 KiB / 145.0 KiB (v3) | 537 B / 411 B (v2) |
| SLH-DSA-SHA2-256f | 2.4 KiB / 2.0 KiB (v4) | 5.2 KiB / 5.0 KiB (v1) | 7.7 KiB / 6.5 KiB (v3) | 3.9 KiB / 3.7 KiB (v4) | 276.2 KiB / 241.5 KiB (v3) | 411 B / 411 B |
| SLH-DSA-SHAKE-128s | — | 4.4 KiB / 4.3 KiB (v1) | 7.5 KiB / 7.3 KiB (v1) | 3.2 KiB / 3.2 KiB (v1) | 43.6 KiB / 43.6 KiB (v4) | 537 B / 537 B |
| SLH-DSA-SHAKE-128f | 2.7 KiB / 2.0 KiB (v4) | 4.4 KiB / 4.3 KiB (v1) | 6.3 KiB / 6.0 KiB (v1) | 3.2 KiB / 3.2 KiB (v1) | 93.8 KiB / 84.9 KiB (v2) | 537 B / 537 B |
| SLH-DSA-SHAKE-192s | — | 4.4 KiB / 4.3 KiB (v1) | 7.5 KiB / 7.3 KiB (v1) | 3.2 KiB / 3.2 KiB (v1) | 89.3 KiB / 82.2 KiB (v3) | 0 B / 0 B |
| SLH-DSA-SHAKE-192f | 2.7 KiB / 2.0 KiB (v4) | 4.4 KiB / 4.3 KiB (v1) | 6.3 KiB / 6.0 KiB (v1) | 3.2 KiB / 3.2 KiB (v1) | 200.5 KiB / 173.3 KiB (v2) | 506 B / 332 B (v2) |
| SLH-DSA-SHAKE-256s | — | 4.5 KiB / 4.3 KiB (v1) | 7.3 KiB / 7.1 KiB (v1) | 3.2 KiB / 3.2 KiB (v1) | 163.1 KiB / 146.8 KiB (v3) | 506 B / 490 B (v2) |
| SLH-DSA-SHAKE-256f | 2.7 KiB / 2.0 KiB (v4) | 4.5 KiB / 4.3 KiB (v1) | 6.5 KiB / 6.2 KiB (v1) | 3.2 KiB / 3.2 KiB (v1) | 276.3 KiB / 243.3 KiB (v3) | 0 B / 0 B |
| Falcon-512 | 4.9 KiB / 4.7 KiB (v1) | 44.2 KiB / 43.8 KiB (v2) | — | — | — | — |
| Falcon-1024 | 5.2 KiB / 4.9 KiB (v1) | 84.4 KiB / 84.0 KiB (v2) | — | — | — | — |

sign, heap allocated per op (v0):

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 145.3 KiB | 6.4 KiB | 59.6 KiB | 51.1 KiB | 6.4 KiB | 77.4 KiB |
| ML-DSA-65 | 650.9 KiB | 17.0 KiB | 90.8 KiB | 75.8 KiB | 8.2 KiB | 141.8 KiB |
| ML-DSA-87 | 416.7 KiB | 17.1 KiB | 136.9 KiB | 109.2 KiB | 11.5 KiB | 196.9 KiB |
| SLH-DSA-SHA2-128s | — | 280 B | 142.2 KiB | 23.5 KiB | 7.7 KiB | 79.95 MiB |
| SLH-DSA-SHA2-128f | 25.41 MiB | 280 B | 9.1 KiB | 45.5 KiB | 16.7 KiB | 3.91 MiB |
| SLH-DSA-SHA2-192s | — | 280 B | 142.9 KiB | 42.7 KiB | 15.8 KiB | 173.08 MiB |
| SLH-DSA-SHA2-192f | 47.24 MiB | 280 B | 9.8 KiB | 92.0 KiB | 34.8 KiB | 7.80 MiB |
| SLH-DSA-SHA2-256s | — | 280 B | 82.9 KiB | 76.9 KiB | 29.1 KiB | 180.19 MiB |
| SLH-DSA-SHA2-256f | 97.09 MiB | 280 B | 13.5 KiB | 125.5 KiB | 48.7 KiB | 18.62 MiB |
| SLH-DSA-SHAKE-128s | — | 280 B | 141.6 KiB | 23.0 KiB | 7.7 KiB | 79.95 MiB |
| SLH-DSA-SHAKE-128f | 14.18 MiB | 280 B | 8.5 KiB | 44.9 KiB | 16.7 KiB | 3.91 MiB |
| SLH-DSA-SHAKE-192s | — | 280 B | 141.6 KiB | 41.5 KiB | 15.8 KiB | 173.08 MiB |
| SLH-DSA-SHAKE-192f | 23.87 MiB | 280 B | 8.5 KiB | 90.8 KiB | 34.8 KiB | 7.79 MiB |
| SLH-DSA-SHAKE-256s | — | 280 B | 81.6 KiB | 75.7 KiB | 29.1 KiB | 180.19 MiB |
| SLH-DSA-SHAKE-256f | 48.62 MiB | 280 B | 12.2 KiB | 124.4 KiB | 48.7 KiB | 18.62 MiB |
| Falcon-512 | 6.65 MiB | 808 B | — | — | — | — |
| Falcon-1024 | 14.31 MiB | 808 B | — | — | — | — |

### verify

| param | noble v0 / min | liboqs v0 / min | openssl v0 / min | circl v0 / min | rustcrypto v0 / min | bouncycastle v0 / min |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 2.2 KiB / 1.6 KiB (v4) | 29.0 KiB / 28.5 KiB (v1) | 3.3 KiB / 3.1 KiB (v1) | 28.4 KiB / 27.3 KiB (v2) | 66.7 KiB / 47.3 KiB (v4) | 316 B / 253 B (v3) |
| ML-DSA-65 | 2.2 KiB / 1008 B (v4) | 44.1 KiB / 43.6 KiB (v1) | 3.3 KiB / 3.1 KiB (v1) | 38.4 KiB / 37.4 KiB (v2) | 100.9 KiB / 53.1 KiB (v4) | 316 B / 253 B (v3) |
| ML-DSA-87 | 2.2 KiB / 1.6 KiB (v4) | 72.3 KiB / 71.8 KiB (v1) | 3.3 KiB / 3.1 KiB (v1) | 50.7 KiB / 49.6 KiB (v2) | 166.2 KiB / 68.4 KiB (v4) | 316 B / 253 B (v3) |
| SLH-DSA-SHA2-128s | 2.4 KiB / 2.4 KiB | 4.6 KiB / 4.1 KiB (v3) | 6.7 KiB / 5.6 KiB (v3) | 3.6 KiB / 3.4 KiB (v2) | 33.9 KiB / 18.5 KiB (v2) | 916 B / 316 B (v3) |
| SLH-DSA-SHA2-128f | 2.4 KiB / 2.0 KiB (v4) | 4.6 KiB / 4.1 KiB (v3) | 6.7 KiB / 5.6 KiB (v3) | 3.6 KiB / 3.4 KiB (v2) | 84.7 KiB / 60.6 KiB (v2) | 664 B / 600 B (v3) |
| SLH-DSA-SHA2-192s | 2.7 KiB / 2.7 KiB | 5.0 KiB / 4.2 KiB (v3) | 7.7 KiB / 5.6 KiB (v3) | 3.6 KiB / 3.6 KiB (v1) | 71.1 KiB / 45.1 KiB (v2) | 411 B / 221 B (v3) |
| SLH-DSA-SHA2-192f | 2.7 KiB / 2.4 KiB (v2) | 5.0 KiB / 4.2 KiB (v3) | 7.7 KiB / 5.6 KiB (v3) | 3.6 KiB / 3.6 KiB (v1) | 180.8 KiB / 128.7 KiB (v2) | 253 B / 221 B (v3) |
| SLH-DSA-SHA2-256s | 2.7 KiB / 2.7 KiB | 5.0 KiB / 4.2 KiB (v3) | 7.7 KiB / 5.6 KiB (v3) | 3.6 KiB / 3.6 KiB (v1) | 134.3 KiB / 82.3 KiB (v2) | 253 B / 221 B (v3) |
| SLH-DSA-SHA2-256f | 2.4 KiB / 2.3 KiB (v4) | 5.0 KiB / 4.2 KiB (v3) | 7.7 KiB / 5.6 KiB (v3) | 3.6 KiB / 3.6 KiB (v1) | 249.1 KiB / 178.0 KiB (v2) | 253 B / 221 B (v3) |
| SLH-DSA-SHAKE-128s | 1.9 KiB / 1.9 KiB | 4.3 KiB / 4.1 KiB (v3) | 5.7 KiB / 5.4 KiB (v4) | 2.8 KiB / 2.8 KiB (v1) | 33.9 KiB / 18.5 KiB (v2) | 158 B / 126 B (v3) |
| SLH-DSA-SHAKE-128f | 2.2 KiB / 2.0 KiB (v4) | 4.3 KiB / 4.1 KiB (v3) | 5.7 KiB / 5.4 KiB (v4) | 2.8 KiB / 2.8 KiB (v1) | 84.7 KiB / 61.8 KiB (v2) | 158 B / 126 B (v3) |
| SLH-DSA-SHAKE-192s | 2.2 KiB / 2.2 KiB | 4.3 KiB / 4.1 KiB (v3) | 5.7 KiB / 5.4 KiB (v4) | 2.8 KiB / 2.8 KiB (v1) | 71.1 KiB / 45.1 KiB (v2) | 0 B / 0 B |
| SLH-DSA-SHAKE-192f | 2.2 KiB / 2.0 KiB (v4) | 4.3 KiB / 4.1 KiB (v3) | 5.7 KiB / 5.4 KiB (v4) | 2.8 KiB / 2.8 KiB (v1) | 180.8 KiB / 128.9 KiB (v2) | 0 B / 0 B |
| SLH-DSA-SHAKE-256s | 2.2 KiB / 2.2 KiB | 4.3 KiB / 4.1 KiB (v3) | 5.7 KiB / 5.4 KiB (v4) | 2.8 KiB / 2.8 KiB (v1) | 134.3 KiB / 82.3 KiB (v2) | 126 B / 0 B (v1) |
| SLH-DSA-SHAKE-256f | 2.2 KiB / 2.0 KiB (v4) | 4.3 KiB / 4.1 KiB (v3) | 5.7 KiB / 5.4 KiB (v4) | 2.8 KiB / 2.8 KiB (v1) | 249.1 KiB / 178.3 KiB (v2) | 0 B / 0 B |
| Falcon-512 | 1.3 KiB / 1008 B (v4) | 4.6 KiB / 4.6 KiB (v3) | — | — | — | — |
| Falcon-1024 | 1.3 KiB / 560 B (v4) | 8.6 KiB / 8.6 KiB (v3) | — | — | — | — |

verify, heap allocated per op (v0):

| param | noble | liboqs | openssl | circl | rustcrypto | bouncycastle |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 93.1 KiB | 5.5 KiB | 39.5 KiB | 22.5 KiB | 28.1 KiB | 58.2 KiB |
| ML-DSA-65 | 135.0 KiB | 7.8 KiB | 61.5 KiB | 40.5 KiB | 47.1 KiB | 94.6 KiB |
| ML-DSA-87 | 192.3 KiB | 13.2 KiB | 97.8 KiB | 67.1 KiB | 79.1 KiB | 155.8 KiB |
| SLH-DSA-SHA2-128s | 764.7 KiB | 280 B | 2.1 KiB | 5.9 KiB | 0 B | 100.0 KiB |
| SLH-DSA-SHA2-128f | 2.14 MiB | 280 B | 2.7 KiB | 8.5 KiB | 0 B | 265.9 KiB |
| SLH-DSA-SHA2-192s | 1.66 MiB | 280 B | 2.5 KiB | 8.5 KiB | 0 B | 172.8 KiB |
| SLH-DSA-SHA2-192f | 3.61 MiB | 280 B | 3.1 KiB | 10.5 KiB | 0 B | 460.5 KiB |
| SLH-DSA-SHA2-256s | 1.99 MiB | 280 B | 2.6 KiB | 10.6 KiB | 0 B | 296.4 KiB |
| SLH-DSA-SHA2-256f | 3.53 MiB | 280 B | 2.9 KiB | 11.8 KiB | 0 B | 560.8 KiB |
| SLH-DSA-SHAKE-128s | 569.1 KiB | 280 B | 1.9 KiB | 5.9 KiB | 0 B | 95.9 KiB |
| SLH-DSA-SHAKE-128f | 1.63 MiB | 280 B | 2.4 KiB | 8.5 KiB | 0 B | 273.5 KiB |
| SLH-DSA-SHAKE-192s | 790.1 KiB | 280 B | 1.9 KiB | 8.1 KiB | 0 B | 171.2 KiB |
| SLH-DSA-SHAKE-192f | 2.16 MiB | 280 B | 2.4 KiB | 10.1 KiB | 0 B | 450.0 KiB |
| SLH-DSA-SHAKE-256s | 1.11 MiB | 280 B | 1.9 KiB | 10.2 KiB | 0 B | 289.8 KiB |
| SLH-DSA-SHAKE-256f | 2.20 MiB | 280 B | 2.3 KiB | 11.4 KiB | 0 B | 560.4 KiB |
| Falcon-512 | 266.3 KiB | 544 B | — | — | — | — |
| Falcon-1024 | 519.7 KiB | 544 B | — | — | — | — |

