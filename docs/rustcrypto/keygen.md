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
