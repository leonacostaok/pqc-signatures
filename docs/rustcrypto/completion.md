# Rust baseline completion and runtime memory

The constructor change remains worthwhile for workloads that create ML-DSA keys: the earlier repeated experiment showed 17.33–17.75% more constructions per second without added operation allocations. This follow-up finds a small whole-process RSS increase for ML-DSA-65 and decreases for 44/87; it does not establish a universal memory reduction or faster existing-key operations. SLH results below are baseline-only, with no evaluated patch or invented before/after percentage.

The [complete results](../../results/rustcrypto/completion/result.json) retain every sample. Sources remain official `a84081789729c96dabb35f96cd000e434b247e02` and published ML head `43cad14d86b36607a3c4b47c59c30d91145f64c1`, built with Rust 1.93.0, library defaults plus `zeroize`. All output hashes reproduce a sealed untimed preparation, valid signatures verify, and tampered signatures fail. These supportive checks used AI assistance and do not replace independent maintainer review or conformance testing.

## Baseline timings

Milliseconds per operation are arithmetic means over ten distinct synthetic keys per process. ML uses four fresh processes; SLH uses one. Two disjoint keys warm each process. Key construction returns the key; encoding and public-key extraction/cloning are outside its clock. Signing uses an existing key with deterministic entropy; verification uses a decoded signature and existing verification key. Per-operation process CPU uses microsecond-resolution `getrusage`; zero/quantized samples remain in the raw results. These bounded passes are not steady-state or tail-latency guarantees.

| Parameter | Key construction (ms) | Sign (ms) | Verify (ms) |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 0.121829 | 0.288353 | 0.036059 |
| ML-DSA-65 | 0.222101 | 0.622773 | 0.052210 |
| ML-DSA-87 | 0.317809 | 0.507294 | 0.078842 |
| SLH-DSA-SHA2-128f | 0.247796 | 5.687771 | 0.353750 |
| SLH-DSA-SHA2-128s | 15.501100 | 118.164246 | 0.121104 |
| SLH-DSA-SHA2-192f | 0.363592 | 10.184108 | 0.569521 |
| SLH-DSA-SHA2-192s | 22.991908 | 237.030471 | 0.209884 |
| SLH-DSA-SHA2-256f | 0.966438 | 21.110263 | 0.595604 |
| SLH-DSA-SHA2-256s | 15.479821 | 222.778496 | 0.303783 |
| SLH-DSA-SHAKE-128f | 1.047225 | 23.776800 | 1.432354 |
| SLH-DSA-SHAKE-128s | 64.718871 | 493.989233 | 0.488175 |
| SLH-DSA-SHAKE-192f | 1.506229 | 39.135396 | 2.118700 |
| SLH-DSA-SHAKE-192s | 96.667579 | 876.853842 | 0.743608 |
| SLH-DSA-SHAKE-256f | 4.021992 | 81.075750 | 2.161725 |
| SLH-DSA-SHAKE-256s | 64.337875 | 771.561371 | 1.076529 |

Falcon is not implemented by the pinned RustCrypto/signatures source tree; those cells remain unsupported for this provider, not zero time.

## Memory observations

Peak RSS is `/usr/bin/time -l` maximum resident memory for the complete normal executable, including runtime startup, both warmup keys, all three operations, encoding, checks and teardown. The binary contains both ML variants but each fresh process selects only one. Four process pairs use AB/BA/AB/BA order. Medians and percentage change use measured RSS values; this is not exact operation peak heap or consumed stack.

| Parameter | Original median RSS | Changed median RSS | Change |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 2,547,712 B | 2,506,752 B | -1.61% |
| ML-DSA-65 | 2,719,744 B | 2,760,704 B | +1.51% |
| ML-DSA-87 | 3,211,264 B | 3,104,768 B | -3.32% |

The ML-DSA-65 increase is retained: all four changed samples exceed their matched originals. ML-DSA-44 and 87 have lower RSS in all four pairs, but page granularity, runtime layout and this small process sample limit generalization. Lower constructor-local frames did not guarantee lower measured whole-process RSS for every parameter.

The separately built global-allocator probe reports identical ML operation counts, requested bytes, returned live bytes and peak above entry for all ten keys per parameter. It forwards `alloc`, `alloc_zeroed`, `realloc` and `dealloc` to `System`; no reallocations occurred. All twelve SLH sets report zero scoped heap allocations for keygen, sign and verify: their returned values and intermediate storage are substantially stack-based, and serialization remains outside accounting. Zero scoped heap allocation does not imply zero process memory or small stack use.

This default-plus-zeroize configuration does not replace the [earlier four-feature audit](resource-audit.md), which separately tested default, default+zeroize, alloc-only+zeroize and no-alloc+zeroize. The default library without `zeroize` retains its preexisting seed-clearing limitation. Allocator hooks can alter code generation, so the accounting executable is not used for timing or RSS comparisons.

True total consumed stack is still unmeasured. The earlier constructor-frame disassembly is compiler-specific and excludes callers/callees; a successful configured thread-stack limit would not establish consumption, while painting active Rust/runtime stacks would require unsafe assumptions about runtime ownership and overwritten regions. This audit therefore does not claim a total-stack peak from either approach. RSS cannot separate stack from other resident pages.

Reproduce with `libs/rustcrypto/experiments/completion/prepare.py`, then the printed manifest and `collect.py --manifest PATH --out results/rustcrypto/completion/new-result.json` in an exclusive machine window. Raw commands, stdout, stderr, exit status and timestamps are retained beside the result. All prior losing timing observations remain in the earlier audit; unchanged signing/verification controls are not credited to the constructor patch.

The [prepared manifest](../../results/rustcrypto/completion/prepared.json), preparation logs and [source archive](../../results/rustcrypto/completion/sources.tar.gz) retain the exact snapshots, adapted manifests, Cargo lockfile and original Git archives. [sources.json](../../results/rustcrypto/completion/sources.json) inventories every archived member by SHA256; extract with `tar -xzf` into a new directory to inspect the complete `baseline/`, `candidate/` and `harness/` trees. Saved-data recomputation is available through `python3 libs/rustcrypto/experiments/completion/audit.py`.
