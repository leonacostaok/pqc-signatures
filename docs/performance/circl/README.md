# Production CIRCL SHA-2 prefix experiment

This candidate avoids repeatedly compressing the public-seed block in SLH-DSA's F/H/T SHA-2 hashes. It creates the prefix state inside each normal operation, restores it for subsequent primitive calls, and discards it when the operation ends. It introduces no public API and no cross-operation key cache. The production patch is based on official CIRCL main `91db3e785ba2635b4f24a023e1ad76d2780e2865`; its production commit is `d3f651b7e088a33a3e697761d67f8b2e408e33e0`.

The patches and fail-closed runner live in `libs/circl/experiments/sha2-prefix/`. The current verified correctness gate and logs are in `evidence/validated-*`. The implementation passed independent F/H/T digest checks, an expected-failure baseline resource regression, a candidate zero-allocation hot-loop regression, the race detector, all 432 shared SLH-DSA vectors, varied complete operations with negative/ownership cases, and upstream suites on native arm64 and emulated amd64. These are regression evidence, not a security proof.

Prefix setup adds per-operation state allocations; the zero-allocation test applies only to primitive calls after setup. Overall allocation counts and peak memory remain unmeasured.

The final five-fork, four-round experiment improved every SHA2 keygen/sign/verify cell: key generation 1.329–1.346×, signing 1.322–1.369×, and verification 1.323–1.425×. All 90 affected fork medians exceeded one. The unchanged SHAKE-128f control stayed near parity, including losing observations. Direct-worktree pilot logs remain explicitly exploratory and are excluded from these results. Earlier copied-source snapshots are preserved under `evidence/invalid-snapshot-2e10305f7c29470c/` because their patch did not apply; they must not be used as candidate evidence. The corrected runner verifies distinct sources/binaries and named tests before accepting a gate or starting timing.

Required `make lint` passed using the isolated Go 1.26.2 toolchain compatible with the pinned golangci-lint binary; shadow vet passed on Go 1.27. The toolchain compatibility failure on Go 1.27 remains recorded separately from code results. See `evidence/validated-tooling.json` and the corresponding logs.

Production and evidence commits are handed off separately; the public draft links this private evidence report.

## Reproduce

From this benchmark repository, preparation archives the pinned official CIRCL commit into isolated baseline/candidate copies under ignored build paths and applies the checked-in patches. It never edits the upstream clone. A fresh checkout can use:

```sh
python3 libs/circl/experiments/sha2-prefix/run.py prepare
python3 libs/circl/experiments/sha2-prefix/run.py check
python3 libs/circl/experiments/sha2-prefix/run.py bench --out results/circl/experiments/new-prefix-run.json --forks 5 --rounds 4 --start 10 --budget-ms 250
```

Preparation and checks must finish before the timing window. The gate requires distinct baseline/candidate source and binary hashes, all three named resource/digest/allocation tests, the expected baseline failure, the complete shared vector corpus, and the upstream candidate suite. The collector rejects stale source/runtime/script hashes, modified gate logs, existing output files, and concurrent preparation/check/timing commands in the same worktree. Run one performance workload at a time on the host.

Each of five forks creates a new three-case corpus for six SHA2 parameter sets and an unchanged SHAKE-128f control. Both variants validate the complete corpus before that fork. Each parameter/operation has four paired rounds, with two AB and two BA orders per fork. Every variant/operation/round uses a new process, with 25 ms warmup and at least 250 ms measured time, rounded up to complete three-case cycles. Seed, message and context values vary between cases and forks. Parsed ordinary key objects and input values repeat inside a process; no new signer, verifier or cross-operation cryptographic cache is introduced. Key parsing happens outside timing; the prefix setup remains inside every ordinary keygen, deterministic signing or valid-verification operation. Signing excludes external randomness acquisition.

The report retains every paired operation latency, iteration count, measurement order and corpus hash. Ratios are the median of each fork's median paired baseline/candidate ratios; observed fork min/max are descriptive ranges, not confidence intervals. The independent `libs/circl/experiments/audit-prefix.py` checker recomputes all 420 pairs and summaries, verifies complete case coverage and balanced order, and checks the retained corpus bytes against those hashes.

## Final results

Measured 2026-10-11 23:58:55 to 2026-10-12 00:07:25 UTC on Apple M1 Pro / macOS 26.2 arm64 with Go 1.27.0, GOMAXPROCS=1 and PGO disabled. No other scheduled build, test or benchmark workload ran during this exclusive window. This is one host and one runtime; the result does not establish gains on other architectures, operating systems, Go releases or application workloads. Native and emulated amd64 correctness runs do not establish amd64 performance.

Ratios below are the median speedup followed by minimum–maximum fork medians. A 1.34× ratio means approximately 25% less operation time, not 34% less. Every affected cell and every affected fork improved. SHAKE-128f is an unchanged-path control; its signing median was 0.9999× and its keygen/sign fork ranges include regressions. All such samples remain in the report.

| Parameter set | Key generation | Signing | Verification |
| --- | ---: | ---: | ---: |
| SLH-DSA-SHA2-128f | 1.336× [1.325–1.343] | 1.322× [1.316–1.327] | 1.334× [1.332–1.337] |
| SLH-DSA-SHA2-128s | 1.341× [1.338–1.343] | 1.331× [1.326–1.342] | 1.323× [1.307–1.330] |
| SLH-DSA-SHA2-192f | 1.339× [1.326–1.340] | 1.357× [1.356–1.360] | 1.388× [1.386–1.393] |
| SLH-DSA-SHA2-192s | 1.346× [1.345–1.349] | 1.360× [1.357–1.387] | 1.425× [1.410–1.436] |
| SLH-DSA-SHA2-256f | 1.329× [1.324–1.334] | 1.351× [1.351–1.370] | 1.388× [1.384–1.392] |
| SLH-DSA-SHA2-256s | 1.333× [1.330–1.341] | 1.369× [1.367–1.372] | 1.415× [1.405–1.426] |
| SLH-DSA-SHAKE-128f | 1.0021× [0.9972–1.0034] | 0.9999× [0.9978–1.0032] | 1.0021× [1.0010–1.0058] |

[The complete report](../../../results/circl/experiments/sha2-prefix-go127-arm64.json) embeds all 420 pairs, 840 individual timed results, exact correctness gate and source/binary/runtime hashes. The five exact [corpora and manifest](../../../results/circl/experiments/sha2-prefix-go127-arm64.corpora/manifest.json) retain 105 cases; their bytes match every recorded corpus hash. [The independent audit](../../../results/circl/experiments/sha2-prefix-independent-check.json) recomputes every pair and all 105 fork summaries, checks both AB/BA orders, and confirms complete case coverage. No noisy or losing observation was removed.

```sh
python3 libs/circl/experiments/audit-prefix.py results/circl/experiments/sha2-prefix-go127-arm64.json results/circl/experiments/sha2-prefix-go127-arm64.corpora
```

The prefix cache is recreated within every operation. These are warmed complete-operation timings using parsed ordinary key objects and repeated values from three varied cases, not fresh-input-identity or first-operation timings. Normal CPU/OS caches remain. Setup allocations and whole-operation peak memory have not been measured; the resource regression only establishes zero F/H/T hot-loop allocations after setup.
