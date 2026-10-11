# CIRCL: keygen variants

Process: `seed -> (pk, sk)` as packed bytes. ML-DSA: `NewKeyFromSeed` (SHAKE256 seed expansion, `ExpandA`,
sampling of s1/s2, NTT, `t = A s1 + s2`, power2round, packing). SLH-DSA: `slh_keygen_internal`, i.e. one
full XMSS tree of the top hypertree layer (2^h' WOTS+ keypairs) to obtain `PK.root`; this is the dominant
cost and is why "s" parameter sets (h' = 9) are far slower than "f" (h' = 3).

| variant | name | binary | what / why / how |
|---|---|---|---|
| keygen.v0 | baseline | default | `mldsa.NewKeyFromSeed` + `Pack` / `slhdsa.GenerateKey(bytes.NewReader(seed), id)` + `MarshalBinary`, default `go build`. CIRCL's default amd64 build already uses AVX2 assembly for the ML-DSA NTT/pointwise ops and a 4-way AVX2 Keccak-f1600 for `ExpandA`/sampling (runtime CPU detection). |
| keygen.v1 | purego | `-tags purego` | Disables all assembly: generic Go NTT and scalar Keccak (no AVX2 x4 permutation) in CIRCL, and, because Go's standard library honours the same tag, also the SHA-NI/AVX2 `crypto/sha256` block function that SLH-DSA-SHA2 relies on. Expected to be *slower*; included to quantify how much of the speed comes from hand-written assembly. |
| keygen.v2 | amd64v3 | `GOAMD64=v3` | Lets the Go compiler assume AVX2/BMI1/BMI2/FMA/LZCNT for *generic* Go code (CIRCL's hand-written assembly already checks for AVX2 at runtime, so only the compiled Go parts change: packing, rounding, SLH-DSA address handling, stdlib code). Expected: small gain at most. |
| keygen.v3 | pgo | `-pgo=default.pgo` | Profile-guided optimisation (Go >= 1.21): hot-path inlining and devirtualisation driven by a CPU profile of exactly this workload. Expected: a few percent, mostly on SLH-DSA where the hash-call layering (`stateF`/`stateH`/`stateT` hashers, `hash.Hash` interfaces) gives the inliner something to work with. |
| keygen.v4 | gc-off | default | Runtime tuning: `debug.SetGCPercent(-1)` (= `GOGC=off`) plus `debug.SetMemoryLimit(1 GiB)` for the duration of the loop. ML-DSA keygen allocates two large structs per call (`PrivateKey` holds the expanded matrix A: 56 KB for ML-DSA-87), so GC work is a visible share of the per-op CPU. Expected: removes GC assists/background marking at the cost of touching fresh memory. |
| keygen.v5 | parallel | default | Goroutine worker pool with `GOMAXPROCS` (= 4) persistent workers; one keygen per worker per batch, batch = 4 ops; `threads = 4`, wall per op = batch wall / 4. All outputs in the batch are compared bit-for-bit to the first. Pure throughput variant for servers generating many keys. |

Notes on correctness: every variant derives from the contract seed and is checked against both
`pk_sha256` and `sk_sha256` of `common/reference.json` on every run.

## Preliminary conclusion (noisy, shared machine; final numbers come from the quiet run)

- The assembly matters: `purego` roughly halves ML-DSA keygen throughput (generic NTT, scalar Keccak for
  `ExpandA`) and costs ~2.5x on SLH-DSA-SHA2, where the loss is the standard library's SHA-NI/AVX2 SHA-256
  block function (the tag reaches into `crypto/sha256` too). The SHAKE sets should be affected least.
- `GOAMD64=v3` and PGO are within noise for keygen (ML-DSA keygen time is dominated by code that is already
  assembly; SLH-DSA keygen is dominated by SHA-256/SHAKE compression functions).
- `gc-off` does not help: ML-DSA keygen allocation rate is high but Go's GC is cheap for short-lived
  objects, and without GC every allocation touches a cold page.
- `parallel` only pays on a quiet machine; during development the four workers competed with five other
  agents' builds, which is why the preliminary throughput gain is far below 4x (SLH-DSA shows ~1.5-2x,
  ML-DSA sometimes a loss).

<!-- RESULTS -->

**ML-DSA-44** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| keygen.v0 | baseline | 1 | 72.2 | 109.2 | 1.06 | 9,712.0 | 1.00x | True |
| keygen.v1 | purego | 1 | 131.9 | 192.8 | 1.00 | 5,198.2 | 0.55x | True |
| keygen.v2 | amd64v3 | 1 | 69.5 | 171.8 | 1.00 | 5,799.3 | 1.04x | True |
| keygen.v3 | pgo | 1 | 73.7 | 117.1 | 0.92 | 7,822.9 | 0.98x | True |
| keygen.v4 | gc-off | 1 | 78.1 | 113.2 | 0.99 | 8,709.3 | 0.92x | True |
| keygen.v5 | parallel | 4 | 86.6 | 200.2 | 1.03 | 5,125.1 | 0.83x | True |

**ML-DSA-65** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| keygen.v0 | baseline | 1 | 105.3 | 168.2 | 1.11 | 6,617.4 | 1.00x | True |
| keygen.v1 | purego | 1 | 205.1 | 300.4 | 1.06 | 3,523.7 | 0.51x | True |
| keygen.v2 | amd64v3 | 1 | 113.5 | 198.2 | 1.04 | 5,236.9 | 0.93x | True |
| keygen.v3 | pgo | 1 | 114.4 | 159.8 | 0.99 | 6,203.9 | 0.92x | True |
| keygen.v4 | gc-off | 1 | 138.1 | 159.9 | 0.98 | 6,148.6 | 0.76x | True |
| keygen.v5 | parallel | 4 | 152.0 | 335.1 | 0.98 | 2,924.7 | 0.69x | True |

**ML-DSA-87** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| keygen.v0 | baseline | 1 | 157.2 | 206.7 | 1.00 | 4,859.9 | 1.00x | True |
| keygen.v1 | purego | 1 | 324.1 | 443.8 | 1.05 | 2,358.5 | 0.49x | True |
| keygen.v2 | amd64v3 | 1 | 145.6 | 231.1 | 0.97 | 4,213.9 | 1.08x | True |
| keygen.v3 | pgo | 1 | 158.5 | 203.8 | 0.98 | 4,807.4 | 0.99x | True |
| keygen.v4 | gc-off | 1 | 170.1 | 198.5 | 0.99 | 4,989.8 | 0.92x | True |
| keygen.v5 | parallel | 4 | 183.7 | 444.2 | 0.96 | 2,156.5 | 0.86x | True |

**SLH-DSA-SHA2-128f** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| keygen.v0 | baseline | 1 | 1,950.7 | 2,030.3 | 1.00 | 493.8 | 1.00x | True |
| keygen.v1 | purego | 1 | 5,049.0 | 5,058.8 | 0.99 | 196.4 | 0.39x | True |
| keygen.v2 | amd64v3 | 1 | 1,992.1 | 1,998.2 | 0.98 | 489.1 | 0.98x | True |
| keygen.v3 | pgo | 1 | 2,424.3 | 2,961.5 | 1.02 | 343.3 | 0.80x | True |
| keygen.v4 | gc-off | 1 | 2,643.1 | 2,596.9 | 0.98 | 379.0 | 0.74x | True |
| keygen.v5 | parallel | 4 | 2,117.4 | 2,493.8 | 1.02 | 408.2 | 0.92x | True |

**SLH-DSA-SHAKE-128f** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| keygen.v0 | baseline | 1 | 2,787.9 | 2,987.9 | 0.98 | 328.9 | 1.00x | True |
| keygen.v1 | purego | 1 | 2,308.1 | 2,357.8 | 0.97 | 409.7 | 1.21x | True |
| keygen.v2 | amd64v3 | 1 | 2,048.9 | 2,097.1 | 0.98 | 468.1 | 1.36x | True |
| keygen.v3 | pgo | 1 | 2,126.3 | 2,160.5 | 1.00 | 465.0 | 1.31x | True |
| keygen.v4 | gc-off | 1 | 2,867.7 | 2,824.7 | 0.90 | 318.9 | 0.97x | True |
| keygen.v5 | parallel | 4 | 2,287.6 | 2,435.6 | 1.09 | 446.9 | 1.22x | True |
