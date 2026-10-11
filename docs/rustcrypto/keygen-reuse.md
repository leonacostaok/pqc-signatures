# Reusing the public key during ML-DSA key construction

The proposed change targets `SigningKey::from_seed` in current upstream `RustCrypto/signatures` revision `a84081789729c96dabb35f96cd000e434b247e02`. With `alloc` enabled, the signing key stores a cached verification key. Key generation already computes `t = A*s1 + s2`, rounds it into `(t1,t0)`, and encodes `(rho,t1)` to produce the public-key hash. Upstream then calls `ExpandedSigningKey::verifying_key` to reconstruct those public values for the cache. The [patch](../../libs/rustcrypto/patches/mldsa-keygen-reuse.patch) passes the existing `t1`, encoding and matrix to the existing crate-private `VerifyingKey::new` constructor instead.

This removes a second matrix-vector multiplication, inverse NTT, vector addition, rounding pass and public-key encoding from the allocating construction path. It does not remove matrix expansion or all repeated hashing. The no-alloc path keeps its existing computation; the public API and zeroizing drop implementations are unchanged. Construction still caches the same public values, as checked by full-key equality against independent derivation and decoding. No new secret-dependent branch, lookup or arithmetic primitive is introduced. This is a source-level argument, not a formal side-channel proof or a heap-usage measurement.

Production commit: `fcbaba75e2f265f0b944e4c28beceddf95910ff5`. The saved patch and frozen executable predate this commit but contain exactly the committed source and regression test.

## Correctness gates

The unchanged baseline passed the complete upstream ML-DSA all-features suite on the installed Rust toolchain, including 75 ACVP key-generation vectors, 60 ACVP signing vectors, 45 ACVP verification vectors, property tests, PKCS#8, Wycheproof and documentation tests. The Wycheproof files match the exact upstream submodule revision `0fd0ec1cf2114f456f5c3e7c61ba807fb1311b45`; [file hashes](../../results/rustcrypto/experiments/wycheproof-data.json) are preserved. Logs are in [the evidence directory](../../results/rustcrypto/experiments).

Before the production edit, new regression tests passed on baseline for all three parameter sets. They compare the cached key to independently derived and decoded verification keys, check clone/drop lifetime behavior and seed preservation, and exercise valid and invalid verification with empty and maximum-length contexts. The candidate complete all-features, default and no-default-features release suites passed, including the new tests; the alloc-only release library suite also passed. These runs use the installed native Rust 1.93 toolchain. The upstream MSRV and cross-target no-std CI matrices were not run locally and are not claimed.

## Experiment design

The standalone [runner](../../libs/rustcrypto/experiments/keygen.py) builds baseline and patched copies from the same pinned revision and lockfile. The experiment copies rename their package identities so both implementations can coexist in one process; production algorithm sources otherwise differ only by the reviewed patch. Builds use the release profile with default features and `zeroize`. Compiler version, flags, source trees, patch, corpus, Cargo manifests and lockfile, driver and executable hashes are recorded before timing and checked afterward.

The fixed corpus has 16 distinct SHA256-derived seeds and randomness values, crosses message sizes `0,1,32,1024` with context sizes `0,1,31,255`, and covers ML-DSA-44/65/87. The [fresh differential gate](../../results/rustcrypto/experiments/keygen-differential.txt) passed: 48 cases, 96 byte-identical signatures per variant, and 240 negative checks per variant. It checks exact public and private keys, complete cached-key equality against independent derivation and decoding, deterministic and explicit-randomness signing, cross verification, invalid messages/contexts/signatures, oversized-context behavior and clone/drop lifetime. The first experiment build found a Cargo workspace-layout error; explicitly assigning the isolated packages to their workspace roots fixed the harness without changing production code. The successful [build log](../../results/rustcrypto/experiments/keygen-build.txt) is retained.

Four operations are deliberately separate: `keygen` constructs from a seed; `keygen_sign` constructs a fresh key and signs; `sign` signs with an existing key; `verify` uses an existing verification key. Only the first two are expected to benefit. Faster construction must not be reported as faster warmed signing or verification.

Each operation uses five fresh processes, paired AB/BA order balanced by fork and round, and at least six rounds. Both variants warm for 300 ms. Samples run whole 16-item corpus cycles and check their final output after the timer. Timing uses monotonic wall time and retains process CPU time; destruction of prior outputs occurs inside the loop, while validation and destruction of the final output occur afterward for both variants. Prepared keys, decoded signatures and input parsing are outside the timer. Reported ratios summarize medians within each fork and then across forks; observed fork ranges are descriptive, not confidence intervals.

## Final measurements

The [final raw results](../../results/rustcrypto/experiments/keygen-rust193-arm64.json) contain all 360 paired samples from five fresh processes per operation and six rounds per parameter. An [independent recomputation](../../results/rustcrypto/experiments/keygen-review.json) checked every summary, count, order and prepared-input hash. The run used an Apple M1 Pro with 16 GiB RAM, arm64 macOS/Darwin 25.2.0 and Rust 1.93.0, with other coordinated build/test/benchmark jobs stopped.

| Operation | Parameter | Baseline µs | Candidate µs | Paired speedup | Fork range |
| --- | --- | ---: | ---: | ---: | ---: |
| keygen | ML-DSA-44 | 126.439 | 107.486 | 1.1738× | 1.1708–1.1774× |
| keygen | ML-DSA-65 | 229.706 | 195.639 | 1.1733× | 1.1709–1.1782× |
| keygen | ML-DSA-87 | 319.749 | 271.655 | 1.1775× | 1.1747–1.1801× |
| keygen_sign | ML-DSA-44 | 498.461 | 479.474 | 1.0376× | 1.0363–1.0418× |
| keygen_sign | ML-DSA-65 | 808.199 | 777.162 | 1.0380× | 1.0318–1.0425× |
| keygen_sign | ML-DSA-87 | 816.192 | 768.331 | 1.0666× | 1.0610–1.0717× |
| sign | ML-DSA-44 | 372.709 | 371.496 | 1.0014× | 0.9224–1.0065× |
| sign | ML-DSA-65 | 575.848 | 575.323 | 1.0005× | 0.9988–1.0040× |
| sign | ML-DSA-87 | 493.467 | 494.548 | 1.0000× | 0.9977–1.0021× |
| verify | ML-DSA-44 | 36.012 | 36.113 | 1.0002× | 0.9969–1.0021× |
| verify | ML-DSA-65 | 51.564 | 51.566 | 0.9999× | 0.9985–1.0013× |
| verify | ML-DSA-87 | 74.646 | 74.650 | 1.0001× | 0.9969–1.0052× |

Latency columns are medians of fork median times; speedup uses paired ratios, so it need not equal the ratio of those two columns. Ranges describe the five observed fork medians, not confidence intervals.

Seed construction improves by 1.1733–1.1775× across the parameter sets, and every constructor fork improves. Constructing a fresh key and signing improves by 1.0376–1.0666×. Warmed signing and verification medians remain near 1.000×, as expected from unchanged operation paths. A retained ML-DSA-44 signing control fork has a 0.9224× median: its initial samples have low CPU/wall ratios (down to 0.793), consistent with off-CPU interruption without establishing its cause. No samples or losses were removed. These results support constructor and fresh-key workflow savings on this host; they do not establish faster warmed signing or verification or performance on other platforms.

The [frozen prepared manifest](../../results/rustcrypto/experiments/keygen-prepared.json) records the verified inputs. No exploratory timing pilot preceded this final run. All final measurements passed output checks and frozen-provenance validation.

Run from this worktree only after the shared machine is released for timing:

```sh
python3 libs/rustcrypto/experiments/keygen.py run --manifest libs/rustcrypto/build/keygen-reuse/prepared-4b0bcedd916d66de/manifest.json --out results/rustcrypto/experiments/keygen-rust193-arm64.json --forks 5 --start 10 --rounds 6 --budget-ms 200 --operations keygen,keygen_sign,sign,verify
```

To reproduce preparation from the exact upstream revision, run `python3 libs/rustcrypto/experiments/keygen.py prepare --upstream /path/to/RustCrypto/signatures`. The saved experiment lockfile pins dependencies; the script creates separate baseline and patched source copies and refuses to overwrite an existing preparation. Its generated manifest supplies the paths for a new timing run.
