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

## Results

Generated by `common/report.mjs` from `results/bouncycastle/bench.jsonl` (bouncycastle 1.86, openjdk 21.0.12.1 (OpenJDK 64-Bit Server VM)). Speedup = throughput vs `sign.v0`.

### Summary (geometric mean speedup over all params)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all outputs match |
|---|---|---|---|---|
| `sign.v0` | jca | 1.00× | 1.00× | yes |
| `sign.v1` | lightweight | 0.94× | 1.03× | yes |
| `sign.v2` | reuse-signer | 0.99× | 0.97× | yes |
| `sign.v3` | parallel | 3.03× | 1.08× | yes |
| `sign.v4` | c2-only | 0.98× | 1.02× | yes |
| `sign.v5` | epsilon-nogc | 0.59× | 1.71× | yes |

### Per parameter set

#### ML-DSA-44

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 167.2 µs | 316.7 µs | 295.0 µs | 1.56 | 1 | 5286 | 1.00× | ✓ |
| `sign.v1` lightweight | 166.7 µs | 340.4 µs | 202.2 µs | 1.00 | 1 | 4945 | 0.94× | ✓ |
| `sign.v2` reuse-signer | 163.5 µs | 243.1 µs | 178.6 µs | 1.00 | 1 | 5598 | 1.06× | ✓ |
| `sign.v3` parallel | 61.7 µs | 108.2 µs | 205.0 µs | 2.84 | 4 | 13875 | 2.62× | ✓ |
| `sign.v4` c2-only | 173.7 µs | 309.2 µs | 241.8 µs | 1.23 | 1 | 5085 | 0.96× | ✓ |
| `sign.v5` epsilon-nogc | 226.4 µs | 782.1 µs | 593.7 µs | 1.61 | 1 | 2711 | 0.51× | ✓ |

#### ML-DSA-65

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 659.4 µs | 1.35 ms | 770.4 µs | 1.01 | 1 | 1311 | 1.00× | ✓ |
| `sign.v1` lightweight | 657.8 µs | 1.11 ms | 716.8 µs | 1.00 | 1 | 1394 | 1.06× | ✓ |
| `sign.v2` reuse-signer | 673.8 µs | 1.27 ms | 761.5 µs | 0.99 | 1 | 1299 | 0.99× | ✓ |
| `sign.v3` parallel | 356.2 µs | 404.4 µs | 1.12 ms | 3.08 | 4 | 2754 | 2.10× | ✓ |
| `sign.v4` c2-only | 666.0 µs | 724.1 µs | 810.6 µs | 1.19 | 1 | 1467 | 1.12× | ✓ |
| `sign.v5` epsilon-nogc | 1.57 ms | 2.04 ms | 1.66 ms | 1.01 | 1 | 609 | 0.46× | ✓ |

#### ML-DSA-87

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 507.5 µs | 823.1 µs | 563.6 µs | 1.01 | 1 | 1792 | 1.00× | ✓ |
| `sign.v1` lightweight | 522.1 µs | 1.03 ms | 607.7 µs | 0.99 | 1 | 1629 | 0.91× | ✓ |
| `sign.v2` reuse-signer | 834.6 µs | 1.04 ms | 788.4 µs | 1.01 | 1 | 1281 | 0.71× | ✓ |
| `sign.v3` parallel | 265.9 µs | 395.1 µs | 896.4 µs | 3.25 | 4 | 3627 | 2.02× | ✓ |
| `sign.v4` c2-only | 526.8 µs | 946.0 µs | 591.3 µs | 1.01 | 1 | 1708 | 0.95× | ✓ |
| `sign.v5` epsilon-nogc | 1.71 ms | 2.48 ms | 1.84 ms | 1.01 | 1 | 549 | 0.31× | ✓ |

#### SLH-DSA-SHA2-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 1.04 s | 1.10 s | 1.05 s | 0.99 | 1 | 0.95 | 1.00× | ✓ |
| `sign.v1` lightweight | 1.26 s | 1.44 s | 1.25 s | 0.98 | 1 | 0.79 | 0.83× | ✓ |
| `sign.v2` reuse-signer | 1.07 s | 1.13 s | 1.07 s | 0.99 | 1 | 0.93 | 0.98× | ✓ |
| `sign.v3` parallel | 279.44 ms | 279.44 ms | 1.06 s | 3.81 | 4 | 3.58 | 3.77× | ✓ |
| `sign.v4` c2-only | 1.07 s | 1.24 s | 1.11 s | 0.99 | 1 | 0.90 | 0.95× | ✓ |
| `sign.v5` epsilon-nogc | 1.61 s | 1.89 s | 1.67 s | 0.99 | 1 | 0.59 | 0.63× | ✓ |

#### SLH-DSA-SHA2-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 47.66 ms | 55.25 ms | 53.50 ms | 1.07 | 1 | 20 | 1.00× | ✓ |
| `sign.v1` lightweight | 52.51 ms | 72.69 ms | 54.74 ms | 0.99 | 1 | 18 | 0.91× | ✓ |
| `sign.v2` reuse-signer | 46.86 ms | 56.74 ms | 50.50 ms | 1.01 | 1 | 20 | 1.00× | ✓ |
| `sign.v3` parallel | 18.77 ms | 22.23 ms | 57.33 ms | 3.25 | 4 | 57 | 2.84× | ✓ |
| `sign.v4` c2-only | 53.03 ms | 61.41 ms | 54.21 ms | 1.01 | 1 | 19 | 0.93× | ✓ |
| `sign.v5` epsilon-nogc | 76.34 ms | 110.96 ms | 90.00 ms | 1.11 | 1 | 12 | 0.62× | ✓ |

#### SLH-DSA-SHA2-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 1.93 s | 2.05 s | 1.97 s | 1.00 | 1 | 0.51 | 1.00× | ✓ |
| `sign.v1` lightweight | 2.56 s | 2.61 s | 2.52 s | 0.99 | 1 | 0.39 | 0.78× | ✓ |
| `sign.v2` reuse-signer | 1.94 s | 2.25 s | 2.02 s | 1.00 | 1 | 0.49 | 0.97× | ✓ |
| `sign.v3` parallel | 518.66 ms | 518.66 ms | 2.01 s | 3.88 | 4 | 1.93 | 3.79× | ✓ |
| `sign.v4` c2-only | 1.99 s | 2.10 s | 2.00 s | 0.99 | 1 | 0.50 | 0.97× | ✓ |
| `sign.v5` epsilon-nogc | 3.28 s | 3.28 s | 3.21 s | 0.99 | 1 | 0.31 | 0.61× | ✓ |

#### SLH-DSA-SHA2-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 85.74 ms | 105.32 ms | 88.33 ms | 1.00 | 1 | 11 | 1.00× | ✓ |
| `sign.v1` lightweight | 88.38 ms | 151.39 ms | 99.00 ms | 0.98 | 1 | 9.91 | 0.87× | ✓ |
| `sign.v2` reuse-signer | 85.94 ms | 93.87 ms | 85.83 ms | 0.99 | 1 | 12 | 1.01× | ✓ |
| `sign.v3` parallel | 29.79 ms | 38.18 ms | 95.00 ms | 3.39 | 4 | 36 | 3.14× | ✓ |
| `sign.v4` c2-only | 84.82 ms | 120.40 ms | 101.67 ms | 1.15 | 1 | 11 | 0.99× | ✓ |
| `sign.v5` epsilon-nogc | 137.34 ms | 142.17 ms | 136.25 ms | 1.00 | 1 | 7.33 | 0.65× | ✓ |

#### SLH-DSA-SHA2-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 1.85 s | 1.85 s | 1.84 s | 1.00 | 1 | 0.54 | 1.00× | ✓ |
| `sign.v1` lightweight | 1.90 s | 2.16 s | 1.92 s | 0.99 | 1 | 0.51 | 0.95× | ✓ |
| `sign.v2` reuse-signer | 1.74 s | 1.75 s | 1.73 s | 0.99 | 1 | 0.57 | 1.06× | ✓ |
| `sign.v3` parallel | 572.00 ms | 572.00 ms | 2.02 s | 3.53 | 4 | 1.75 | 3.22× | ✓ |
| `sign.v4` c2-only | 2.03 s | 2.07 s | 1.95 s | 0.99 | 1 | 0.51 | 0.93× | ✓ |
| `sign.v5` epsilon-nogc | 2.87 s | 3.09 s | 2.93 s | 1.00 | 1 | 0.34 | 0.63× | ✓ |

#### SLH-DSA-SHA2-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 176.78 ms | 192.42 ms | 175.00 ms | 0.98 | 1 | 5.61 | 1.00× | ✓ |
| `sign.v1` lightweight | 183.67 ms | 232.83 ms | 186.67 ms | 1.00 | 1 | 5.36 | 0.96× | ✓ |
| `sign.v2` reuse-signer | 175.90 ms | 234.82 ms | 185.00 ms | 1.00 | 1 | 5.42 | 0.97× | ✓ |
| `sign.v3` parallel | 58.61 ms | 68.55 ms | 200.50 ms | 3.37 | 4 | 17 | 3.00× | ✓ |
| `sign.v4` c2-only | 199.07 ms | 217.05 ms | 193.33 ms | 0.99 | 1 | 5.11 | 0.91× | ✓ |
| `sign.v5` epsilon-nogc | 328.44 ms | 339.72 ms | 315.00 ms | 1.01 | 1 | 3.19 | 0.57× | ✓ |

#### SLH-DSA-SHAKE-128s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 1.19 s | 1.19 s | 1.18 s | 1.00 | 1 | 0.85 | 1.00× | ✓ |
| `sign.v1` lightweight | 1.23 s | 1.29 s | 1.23 s | 0.99 | 1 | 0.81 | 0.95× | ✓ |
| `sign.v2` reuse-signer | 1.21 s | 1.28 s | 1.23 s | 1.00 | 1 | 0.81 | 0.96× | ✓ |
| `sign.v3` parallel | 386.91 ms | 386.91 ms | 1.35 s | 3.50 | 4 | 2.58 | 3.04× | ✓ |
| `sign.v4` c2-only | 1.25 s | 1.45 s | 1.32 s | 1.02 | 1 | 0.77 | 0.91× | ✓ |
| `sign.v5` epsilon-nogc | 1.74 s | 1.76 s | 1.72 s | 1.00 | 1 | 0.58 | 0.68× | ✓ |

#### SLH-DSA-SHAKE-128f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 64.02 ms | 88.31 ms | 65.63 ms | 1.00 | 1 | 15 | 1.00× | ✓ |
| `sign.v1` lightweight | 59.41 ms | 86.99 ms | 64.38 ms | 1.00 | 1 | 16 | 1.02× | ✓ |
| `sign.v2` reuse-signer | 54.55 ms | 97.93 ms | 58.82 ms | 0.99 | 1 | 17 | 1.11× | ✓ |
| `sign.v3` parallel | 23.88 ms | 26.04 ms | 69.09 ms | 2.99 | 4 | 43 | 2.83× | ✓ |
| `sign.v4` c2-only | 65.53 ms | 87.81 ms | 68.00 ms | 1.01 | 1 | 15 | 0.98× | ✓ |
| `sign.v5` epsilon-nogc | 83.74 ms | 92.09 ms | 85.00 ms | 1.01 | 1 | 12 | 0.78× | ✓ |

#### SLH-DSA-SHAKE-192s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 2.05 s | 2.28 s | 2.11 s | 1.00 | 1 | 0.47 | 1.00× | ✓ |
| `sign.v1` lightweight | 2.67 s | 2.85 s | 2.62 s | 0.99 | 1 | 0.38 | 0.80× | ✓ |
| `sign.v2` reuse-signer | 2.10 s | 2.16 s | 2.09 s | 1.00 | 1 | 0.48 | 1.01× | ✓ |
| `sign.v3` parallel | 626.45 ms | 626.45 ms | 2.26 s | 3.60 | 4 | 1.60 | 3.38× | ✓ |
| `sign.v4` c2-only | 2.17 s | 2.21 s | 2.15 s | 1.00 | 1 | 0.46 | 0.98× | ✓ |
| `sign.v5` epsilon-nogc | 3.43 s | 3.65 s | 3.47 s | 0.99 | 1 | 0.29 | 0.61× | ✓ |

#### SLH-DSA-SHAKE-192f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 107.20 ms | 169.66 ms | 112.22 ms | 1.00 | 1 | 8.90 | 1.00× | ✓ |
| `sign.v1` lightweight | 92.42 ms | 102.79 ms | 92.73 ms | 0.99 | 1 | 11 | 1.19× | ✓ |
| `sign.v2` reuse-signer | 93.06 ms | 124.48 ms | 93.64 ms | 0.98 | 1 | 10 | 1.17× | ✓ |
| `sign.v3` parallel | 29.75 ms | 37.09 ms | 99.25 ms | 3.47 | 4 | 35 | 3.93× | ✓ |
| `sign.v4` c2-only | 89.66 ms | 95.72 ms | 90.00 ms | 1.00 | 1 | 11 | 1.24× | ✓ |
| `sign.v5` epsilon-nogc | 148.77 ms | 152.89 ms | 150.00 ms | 1.01 | 1 | 6.73 | 0.76× | ✓ |

#### SLH-DSA-SHAKE-256s

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 1.93 s | 2.32 s | 2.02 s | 0.99 | 1 | 0.49 | 1.00× | ✓ |
| `sign.v1` lightweight | 2.00 s | 2.08 s | 1.97 s | 0.99 | 1 | 0.50 | 1.02× | ✓ |
| `sign.v2` reuse-signer | 1.84 s | 1.93 s | 1.85 s | 1.00 | 1 | 0.54 | 1.10× | ✓ |
| `sign.v3` parallel | 603.83 ms | 603.83 ms | 2.17 s | 3.59 | 4 | 1.66 | 3.37× | ✓ |
| `sign.v4` c2-only | 1.95 s | 2.17 s | 2.01 s | 0.99 | 1 | 0.49 | 1.01× | ✓ |
| `sign.v5` epsilon-nogc | 3.39 s | 3.71 s | 3.42 s | 0.99 | 1 | 0.29 | 0.59× | ✓ |

#### SLH-DSA-SHAKE-256f

| variant | median | p95 | CPU/op | CPU util | threads | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| `sign.v0` jca | 200.98 ms | 212.09 ms | 195.00 ms | 0.99 | 1 | 5.07 | 1.00× | ✓ |
| `sign.v1` lightweight | 200.21 ms | 264.17 ms | 210.00 ms | 0.99 | 1 | 4.70 | 0.93× | ✓ |
| `sign.v2` reuse-signer | 205.96 ms | 268.41 ms | 216.00 ms | 0.98 | 1 | 4.52 | 0.89× | ✓ |
| `sign.v3` parallel | 66.37 ms | 67.11 ms | 215.00 ms | 3.36 | 4 | 16 | 3.08× | ✓ |
| `sign.v4` c2-only | 213.75 ms | 280.11 ms | 222.00 ms | 1.00 | 1 | 4.51 | 0.89× | ✓ |
| `sign.v5` epsilon-nogc | 313.43 ms | 319.02 ms | 316.67 ms | 1.01 | 1 | 3.18 | 0.63× | ✓ |

