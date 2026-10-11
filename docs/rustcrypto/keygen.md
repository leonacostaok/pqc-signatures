# rustcrypto: keygen

Process: seed → (pk, sk) in FIPS encodings. ML-DSA: `SigningKey::<P>::from_seed(ξ)` then
`verifying_key().encode()` and `expanded_key().to_expanded()`. SLH-DSA:
`SigningKey::<P>::slh_keygen_internal(sk_seed, sk_prf, pk_seed)` then `to_bytes()` for both keys.
Allocation of the two output `Vec`s is inside the timed region for every variant.

What keygen costs in these crates: ML-DSA keygen is dominated by `ExpandA` (K·L SHAKE-128 squeezes of
rejection-sampled polynomials), one NTT matrix-vector product and the encodings; `ml-dsa` 0.1 also
computes the `VerifyingKey` (a second A·s1 product, pkEncode and a SHAKE-256 of pk for `tr`) inside
`from_seed` because the `alloc` feature precomputes it. SLH-DSA keygen is one full XMSS tree at the top
layer (2^h' WOTS+ public keys, i.e. thousands of SHA-256 / SHAKE-256 calls); for the `s` sets h' = 9,
for the `f` sets h' = 3, so keygen cost is hash-bound and 60× apart between them.

## Variants

| id | name | what / why / how |
|---|---|---|
| `keygen.v0` | default | Baseline: `cargo build --release` (opt-level 3, 16 codegen units, thin local LTO off, panic=unwind), the API calls above, one op per call, single thread. |
| `keygen.v1` | native | Same binary built with `RUSTFLAGS="-C target-cpu=native"` (AVX2 + AVX-512 on the benchmark VM). Lets LLVM auto-vectorise the NTT butterflies, polynomial add/sub/power2round loops and the bit-packing encoders; the Keccak and SHA-2 compression functions are scalar so hash-bound work gains little. Separate target dir `target/native`. |
| `keygen.v2` | lto | `[profile.lto]`: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`. The hot path crosses crate boundaries constantly (`hybrid-array` → `digest` → `shake`/`sha2` → `keccak`; `module-lattice` for the NTT), so whole-program inlining and single-unit codegen give LLVM the whole loop nests; `panic=abort` removes unwinding landing pads around every `Vec`/`Box`. |
| `keygen.v3` | pgo | Profile-guided optimisation on top of native + fat LTO: an instrumented binary (`-C profile-generate`) runs the keygen workload of all 15 parameter sets, `llvm-profdata merge` (rustup `llvm-tools`) produces `keygen.profdata`, and the final binary is built with `-C profile-use`. The profile is specific to keygen so branch layout / inlining decisions are made for `ExpandA` rejection sampling and the XMSS tree walk rather than for sign or verify. |
| `keygen.v4` | mimalloc | Default build plus `mimalloc` as `#[global_allocator]`. `ml-dsa` boxes the expanded key, the verifying key and its precomputed values (`MaybeBox`), and the harness returns `Vec` outputs, so keygen does a handful of multi-KB allocations per call; mimalloc's thread-local free lists are cheaper than glibc malloc for that pattern. Tests whether the allocator is visible at all at this granularity. |
| `keygen.v5` | par | Throughput variant: a batch of 16 independent keygens is distributed over a 4-thread `rayon` pool (`into_par_iter().map(keygen).reduce(..)`). Reported wall per op = wall per batch / 16, `threads = 4`, and `cpu_ns_per_op` shows the real CPU cost (rayon overhead + cache contention). All 16 outputs are checked against the reference. |

Every variant's pk and sk are hashed after the measured loop and compared with `pk_sha256` /
`sk_sha256` from `common/reference.json`; `match` is set from that comparison.

## Conclusion (preliminary, noisy shared machine; final numbers below the marker are regenerated)

See the preliminary table below. Expectations: `native` and `lto` should each give a modest
single-digit-to-low-double-digit percent gain on ML-DSA (NTT-heavy) and less on SLH-DSA (hash-bound);
`pgo` stacks on both; `mimalloc` is noise-level; `par` scales close to the number of cores when the box
is quiet.

<!-- RESULTS -->

## Results (PRELIMINARY: dev run with --budget-ms 200 on a loaded 4-core box; the orchestrator overwrites this section)

| variant | name | geomean speedup | geomean CPU/op vs v0 | all outputs match |
|---|---|---|---|---|
| `keygen.v0` | default | 1.00× | 1.00× | yes |
| `keygen.v1` | native | 0.67× | 1.08× | yes |
| `keygen.v2` | lto | 1.01× | 0.95× | yes |
| `keygen.v3` | pgo | 1.02× | 0.92× | yes |
| `keygen.v4` | mimalloc | 0.88× | 0.96× | yes |
| `keygen.v5` | par | 1.26× | 1.08× | yes |

| param | variant | median | CPU/op | CPU util | thr | ops/s | speedup | match |
|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | `keygen.v0` default | 181.6 µs | 206.8 µs | 0.86 | 1 | 4154.5 | 1.00× | ✓ |
| ML-DSA-44 | `keygen.v1` native | 171.8 µs | 186.9 µs | 0.30 | 1 | 1609.8 | 0.39× | ✓ |
| ML-DSA-44 | `keygen.v2` lto | 151.1 µs | 160.6 µs | 0.95 | 1 | 5934.0 | 1.43× | ✓ |
| ML-DSA-44 | `keygen.v3` pgo | 162.1 µs | 174.6 µs | 0.91 | 1 | 5186.8 | 1.25× | ✓ |
| ML-DSA-44 | `keygen.v4` mimalloc | 157.8 µs | 167.6 µs | 0.79 | 1 | 4708.4 | 1.13× | ✓ |
| ML-DSA-44 | `keygen.v5` par | 188.4 µs | 227.6 µs | 1.09 | 4 | 4768.9 | 1.15× | ✓ |
| ML-DSA-87 | `keygen.v0` default | 512.6 µs | 529.6 µs | 1.00 | 1 | 1885.5 | 1.00× | ✓ |
| ML-DSA-87 | `keygen.v1` native | 531.5 µs | 553.6 µs | 0.87 | 1 | 1570.8 | 0.83× | ✓ |
| ML-DSA-87 | `keygen.v2` lto | 446.8 µs | 462.4 µs | 0.82 | 1 | 1776.8 | 0.94× | ✓ |
| ML-DSA-87 | `keygen.v3` pgo | 661.3 µs | 624.3 µs | 0.95 | 1 | 1518.3 | 0.81× | ✓ |
| ML-DSA-87 | `keygen.v4` mimalloc | 451.8 µs | 497.5 µs | 0.68 | 1 | 1372.9 | 0.73× | ✓ |
| ML-DSA-87 | `keygen.v5` par | 498.1 µs | 520.0 µs | 1.01 | 4 | 1949.3 | 1.03× | ✓ |
| SLH-DSA-SHA2-128f | `keygen.v0` default | 1.54 ms | 1.57 ms | 0.98 | 1 | 626.2 | 1.00× | ✓ |
| SLH-DSA-SHA2-128f | `keygen.v1` native | 1.19 ms | 1.25 ms | 0.93 | 1 | 743.0 | 1.19× | ✓ |
| SLH-DSA-SHA2-128f | `keygen.v2` lto | 1.78 ms | 1.98 ms | 0.95 | 1 | 479.0 | 0.76× | ✓ |
| SLH-DSA-SHA2-128f | `keygen.v3` pgo | 1.23 ms | 1.29 ms | 0.90 | 1 | 694.4 | 1.11× | ✓ |
| SLH-DSA-SHA2-128f | `keygen.v4` mimalloc | 1.54 ms | 1.57 ms | 0.94 | 1 | 601.2 | 0.96× | ✓ |
| SLH-DSA-SHA2-128f | `keygen.v5` par | 1.42 ms | 1.91 ms | 1.27 | 4 | 665.9 | 1.06× | ✓ |
| SLH-DSA-SHAKE-128s | `keygen.v0` default | 287.10 ms | 278.73 ms | 0.95 | 1 | 3.4 | 1.00× | ✓ |
| SLH-DSA-SHAKE-128s | `keygen.v1` native | 559.92 ms | 507.00 ms | 0.91 | 1 | 1.8 | 0.53× | ✓ |
| SLH-DSA-SHAKE-128s | `keygen.v2` lto | 279.80 ms | 264.20 ms | 0.93 | 1 | 3.5 | 1.03× | ✓ |
| SLH-DSA-SHAKE-128s | `keygen.v3` pgo | 304.49 ms | 246.28 ms | 0.82 | 1 | 3.3 | 0.97× | ✓ |
| SLH-DSA-SHAKE-128s | `keygen.v4` mimalloc | 339.49 ms | 312.10 ms | 0.82 | 1 | 2.6 | 0.77× | ✓ |
| SLH-DSA-SHAKE-128s | `keygen.v5` par | 151.35 ms | 291.86 ms | 1.96 | 4 | 6.7 | 1.97× | ✓ |
