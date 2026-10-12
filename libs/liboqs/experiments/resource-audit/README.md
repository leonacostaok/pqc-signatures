# liboqs SHA-2 resource audit

The published [PR #2625](https://github.com/open-quantum-safe/liboqs/pull/2625) adds no explicit heap allocation or persistent key cache, but increases several local stack frames on the tested Apple arm64 build. SHA-512 compression grows **192 → 256 bytes (+64 bytes)** and the one-shot hash grows **320 → 544 bytes (+224 bytes)**. SHA-256 compression falls from 160 to 144 bytes while its one-shot hash grows **176 → 304 bytes (+128 bytes)**. These compiler reports describe individual frames, including the compiler's inlining choices; neither the OpenSSL callees nor complete SLH-DSA peak stack was measured.

| Measured item | Original | Published change |
|---|---:|---:|
| SHA-256 compression local stack frame, clang `-O3 -fstack-usage` | 160 B | 144 B |
| SHA-512 compression local stack frame, same flags | 192 B | 256 B |
| SHA-256 update / one-shot local frames | 64 / 176 B | 176 / 304 B |
| SHA-512 update / one-shot local frames | 64 / 320 B | 304 / 544 B |
| OpenSSL allocation-hook calls during 52 two-hash cases | 0 | 0 |
| SHA-256/SHA-512 outputs checked against Python hashlib | 104 | 104 |

Finalization frames also grow by 112 bytes for SHA-256 and 224–240 bytes for SHA-512. The largest measured local-frame increase is **240 bytes**. All emitted function-frame observations, including unchanged functions and SHA-224/384 variants, are retained in the [complete table](../../../../results/liboqs/resource-audit/STACK.md), four `*-stack.txt` files and parsed provenance table. Frame values cannot be summed blindly: inlining and call relationships determine actual peak usage. Applications with tight stack budgets should assess their complete target build before adopting the faster backend.

The [raw observations and command records](../../../../results/liboqs/resource-audit/) use the signed PR head `94b42a7232057236dcb3dd56310df3d9d0a1cbd7` and upstream base `fd44469daeffe6b28f031f54f9bb66cbae69a572`. The signed tree equals the tested trim commit `dd039f5`; both SHA implementation files equal the original measured `b14f1b6` version. Source, binary and backend bindings are in `provenance.json` in that evidence directory.

## Source review

At the signed head, `src/sig/slh_dsa/slh_dsa_c/sha2_256.c:48–66` and `sha2_512.c:50–68` copy eight chaining-state words into an automatic OpenSSL context, transform one block, copy the state back, and call `OPENSSL_cleanse` on the entire context. The contexts can hold secret-derived states in PRF paths. The retained assembly checks confirm that the transform and cleanse calls remain in optimized output. The caller state layout, block traversal, and public function signatures do not change. There is no new shared mutable state or lifetime beyond the compression call.

The new dependency is OpenSSL's deprecated public low-level `SHA256_Transform`/`SHA512_Transform` API. Guards at lines 11–22 in both files select the portable implementation when the OpenSSL SHA-2 backend is disabled, dynamic OpenSSL loading is enabled, or deprecated declarations are unavailable. Existing fallback/hash checks cover these configurations; this audit does not claim measured speedups there, on another architecture, or with another OpenSSL backend. The existing experimental instrumentation counter is unchanged and is not evidence of a new production race.

## Probe and limits

`hash-resources.c` installs OpenSSL allocation hooks before the first tested hash, then hashes four distinct fixed byte patterns at 13 lengths covering both SHA-2 padding and block boundaries. Counters surround only the private hash calls. All returned digests are checked independently with `hashlib` by `check.py`. The probe does not intercept arbitrary libc allocation, measure full SLH API allocation, RSS, or total peak stack; zero hook calls must not be described as a universal zero-allocation proof.

Run `python3 libs/liboqs/experiments/resource-audit/check.py` from this repository to validate the retained observations. Each `*-commands.json` preserves the exact four compile/link/run argument arrays for reproduction against the recorded source and Homebrew OpenSSL paths; the final command's stdout is the corresponding `*.jsonl`. Keep generated objects, `.su` files and binaries under `libs/liboqs/build/resource-audit/`. No performance measurement was made with allocation hooks.

The retained [latency review](../../../../results/liboqs/resource-audit/latency-review.json) contains no observed slowdown for the published runtime: 0/288 individual case pairs and 0/72 aggregated parameter/operation/round pairs in the first balanced run; 0/180 wall and CPU pairs in the candidate-first ten-key pass; and 0/1,080 wall and CPU individual pairs in the later full-versus-original ablation. Minimum individual wall ratios differ substantially across these experiments: **4.140×, 3.314×, and 1.848×**, respectively. Thus a universal 4× improvement floor would be unsupported even though all observed ratios exceed 1. The one-pass experiment confounds variant order with elapsed-time drift. Reduced SHA256-only/SHA512-only ablation variants and earlier pre-cleanse pilots are not the published runtime and are not pooled into this result.

`python3 libs/openssl/experiments/resource-audit/record.py` rechecks both providers' saved observations, compiler frames, linked libraries, and signed/measured source identity using the original local build paths. `python3 libs/openssl/experiments/resource-audit/review-latency.py` recomputes the retained ratios/loss counts without running benchmarks. Original corpus/binary acceptance checks remain in the frozen experiment evidence. These results apply to one Apple M1 Pro host, not other platforms or worst-case latency. No new leak, aliasing or concurrency defect was established by this bounded review; complete peak-stack and full-operation heap measurements remain gaps.
