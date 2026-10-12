# SHA-2 ablation results

SHA256-only preserves the observed full gain for the narrow SHA2-128f/s scope, passing the predeclared 3% median slowdown screen. It does not preserve the full signing/verification gain across all six sets: for SHA2-192/256, removing the SHA-512 backend increases median signing latency by 20.70–36.94% and verification latency by 22.34–38.91%. Process CPU results agree in magnitude. Of the 24 larger-set paired rounds per operation, 23 signing rounds and all 24 verification rounds exceed the 3% penalty; the minimum signing ratio is 1.004884, so the threshold is not exceeded in every signing round. SHA512-only provides only 1.039–1.093× signing and 1.048–1.094× verification speedups over the original on those larger sets; its 128f/s cases are unused-backend controls near 1×.

The full patch remains 4.268–5.295× faster for signing and 4.345–5.279× faster for verification than the original in this experiment. Its runtime part is already 64 added lines. [The three-file, 67-addition runtime-only artifact](minimal-runtime.patch) contains identical runtime/CMake diff sections, with a [mechanical comparison](evidence/minimal-runtime-proof.json); it is not a fifth measured variant. The maintained patch additionally needs tests and regeneration support, as explained in [PATCH_SCOPE.md](PATCH_SCOPE.md). A [separate test-build cleanup](../../../../results/liboqs/sha2-trim/README.md) commit, `dd039f5f899aefb24b86b94c4b5cba1b2ec39f2f`, removes three redundant test include-directory lines and reduces the original 257 additions to 254 without changing SLH runtime sources; the measured full variant remains `b14f1b616f938698ebc0bf8b75b3736c30e1502c`.

Each value below is the median of six paired-round ratios after summing the ten matched-key times within each parameter/operation. “Gain” is original time divided by variant time; “penalty” is `(reduced time / full time - 1) × 100`, with wall/CPU percentages shown separately. The median of paired ratios is not generally the quotient of separately reported medians.

| Parameter | Operation | Full wall gain | SHA256-only wall gain | SHA256-only latency penalty wall / CPU | SHA512-only wall gain | SHA512-only latency penalty wall / CPU |
|---|---|---:|---:|---:|---:|---:|
| 128f | sign | 5.295× | 5.300× | +0.01% / +0.02% | 1.002× | +428.97% / +428.57% |
| 128s | sign | 5.257× | 5.274× | -0.36% / -0.18% | 1.005× | +426.00% / +424.79% |
| 192f | sign | 4.749× | 3.922× | +20.70% / +20.62% | 1.039× | +356.42% / +354.17% |
| 192s | sign | 4.515× | 3.557× | +27.24% / +27.15% | 1.060× | +323.24% / +325.35% |
| 256f | sign | 4.687× | 3.861× | +21.20% / +21.98% | 1.051× | +346.03% / +347.62% |
| 256s | sign | 4.268× | 3.104× | +36.94% / +36.61% | 1.093× | +289.68% / +289.44% |
| 128f | verify | 5.279× | 5.300× | +0.20% / -0.28% | 0.998× | +428.80% / +426.36% |
| 128s | verify | 5.177× | 5.183× | -0.67% / -0.63% | 1.008× | +407.20% / +406.65% |
| 192f | verify | 4.872× | 4.006× | +22.34% / +21.73% | 1.048× | +365.27% / +363.40% |
| 192s | verify | 4.345× | 3.135× | +38.91% / +38.71% | 1.088× | +297.49% / +295.97% |
| 256f | verify | 4.756× | 3.766× | +25.88% / +26.19% | 1.061× | +347.13% / +347.27% |
| 256s | verify | 4.483× | 3.237× | +37.78% / +37.83% | 1.094× | +309.05% / +308.71% |
| 128f | keygen | 5.447× | 5.420× | -0.02% / -0.12% | 0.997× | +444.30% / +440.75% |
| 128s | keygen | 5.420× | 5.424× | -0.01% / +0.14% | 1.001× | +439.92% / +438.85% |
| 192f | keygen | 5.292× | 5.031× | +5.68% / +5.41% | 1.005× | +425.47% / +423.05% |
| 192s | keygen | 5.192× | 5.041× | +3.31% / +4.33% | 1.010× | +414.48% / +420.31% |
| 256f | keygen | 5.243× | 4.926× | +6.36% / +6.27% | 1.013× | +420.30% / +419.55% |
| 256s | keygen | 5.265× | 4.940× | +6.51% / +6.58% | 1.017× | +417.79% / +418.30% |

For the larger sets, SHA256-only retains 73.02–82.85% of the full signing speedup and 71.99–81.74% of the full verification speedup, defined per round as `full time / reduced time`. This is the ratio of the two original-relative speedups, not the fraction of execution time saved. Key generation is separate: SHA256-only has median penalties of 3.31–6.51% wall and 4.33–6.58% CPU for the larger sets, while its 128f/s medians remain within the screen.

The [complete metrics table](RESULTS.csv) contains all 54 variant/parameter/operation cells, both clocks, round-ratio ranges, direct penalties, speedup fractions, and losses. [The exact summary](evidence/final/summary.json) additionally preserves all six paired-round totals and ratios and all sixty individual-key original-relative ratios in every cell. No observations were removed. Across 1080 original-relative operation pairs per variant, the full patch has zero wall/CPU losses; SHA256-only has one wall loss and zero CPU losses (the wall outlier is 256f key generation); SHA512-only has 225 wall and 188 CPU losses, including its unchanged 128f/s controls. At the round-total level those counts are 0/0, 0/0, and 19/15 respectively.

The 3% screen applies to the median only and is not a statistical equivalence result. Some individual rounds remain noisy: SHA256-only 128s signing ranges from 6.20% faster to 11.75% slower than full despite its median being 0.36% faster; the unchanged SHA512-only 128 cases also fluctuate around the original. The one-minute host-load samples are not an isolation guarantee: they range from 2.75 to 8.43, with a median of 4.34 on the eight-core host. All coordinated builds and other benchmarks were paused, but ordinary desktop activity remained. These results apply to this Apple M1 Pro arm64 host and OpenSSL 3.6.4, not all hardware or compiler configurations.

The final run completed all 24 fresh processes in six rounds between `2026-10-12T02:21:02.842924+00:00` and `2026-10-12T02:29:07.489704+00:00`. Three different orders and their reverses balance every pair of variants in temporal order. Each process uses the same sixty matched keys recreated from fresh buffers/objects after disjoint warmups; the corpus contains ten distinct seeds per parameter, newly derived in an ablation-specific domain. The ten keys in a process are not independent process replicates. The native operations use fixed test-process entropy, excluding OS RNG acquisition and excluding allocation, object setup, and validation from timing. CPU intervals include the two wall-clock reads.

All 1440 recorded keygen/sign/verify pipelines passed native verification plus the selected signature-bit mutation rejection outside timing; public-key, secret-key, and signature bytes for each corresponding key matched exactly across all variants and rounds. Every variant passed four configurations of 5710 hash/compression differential checks, including padding/truncation edges, and a backend/cleanse probe; the two reduced builds also passed the upstream private incremental/copy hash test. These focused checks do not claim a fresh complete NIST-vector or entire upstream-suite run for the reduced variants. The full candidate retains its earlier separately documented conformance evidence.

The final [ready manifest](evidence/ready.json) binds sources, input bytes and metadata, archives, drivers, reused-driver provenance, backend, configuration, and correctness reports. [Compiled-object checks](evidence/compiled-backend.json) distinguish the intended backend/cleanup paths. A further [archive and linkage check](evidence/archive-link-check.json) proves the sealed archives contain exactly those checked compression objects and that all drivers link the recorded OpenSSL path. Command/status hashes and exact expected arguments bind every final batch; the final [completion record](evidence/final/complete.json) binds all 24 results and host diagnostics. The provisional `ready-pre-binding.json` predates the strengthened invocation/metadata gates and is not the final measurement seal. The source/driver/binary files were unchanged throughout final timing.

The [independent audit](../../../../results/liboqs/ablation-independent.json) reparses all raw records and artifacts and recomputes every summary cell. The experiment runner itself reproduces the saved summary with `python3 libs/liboqs/experiments/sha2-ablation/run.py analyze`; the four fail-closed acceptance tests pass.
