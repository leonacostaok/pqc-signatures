# Bouncy Castle baseline completion and runtime resources

Lower allocation traffic did not consistently improve latency or process memory. WOTS reduced signing allocation about 67% and measured checked-batch collection counts 70%, yet SHA2-128f signing RSS rose 8.58% and its scoped wall/CPU times rose about 2%. The FORS and combined sampling alternatives reduced process RSS in the measured cells, but retain parameter-specific latency losses. These are separate alternatives; no patches or timings are combined.

The [complete results](../../results/bouncycastle/completion/result.json) preserve all samples, timestamps, commands and exit status. Production sources start from official `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`; the FORS, combined ML sampling and WOTS classes are bound to their earlier sealed manifests. No production or PR change was made. AI-assisted supportive checks compare complete outputs with prepared baselines, reject tampered signatures and confirm caller-input integrity; they do not replace independent maintainer or conformance review.

## Missing baseline timings

Milliseconds per operation are arithmetic means over ten distinct synthetic keys, one fresh JVM per parameter. ML has 200 disjoint-key warmup calls per operation. Falcon warmup is capped at four calls; it uses deterministic expanding test entropy and native BC encodings, so this is bounded baseline sensitivity evidence rather than a cross-provider interoperability or steady-state claim. Keygen includes generator setup and encoding; signing/verification include fresh key decoding and fresh operation objects. No candidate is invented for Falcon or the baseline rows.

| Parameter | Keygen (ms) | Sign (ms) | Verify (ms) |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 0.124200 | 0.363471 | 0.103575 |
| ML-DSA-65 | 0.185142 | 0.554017 | 0.145692 |
| ML-DSA-87 | 0.250738 | 0.794392 | 0.215842 |
| Falcon-512 | 10.426612 | 1.369850 | 0.247617 |
| Falcon-1024 | 29.738283 | 2.437125 | 0.474350 |

The earlier ten-key report already supplies all twelve SLH baseline sets; it remains a separate protocol. New sampling key-generation resource cells appear below, independently of these baseline-only timing rows.

## Resource protocol

Each patch/parameter/operation uses two balanced AB/BA pairs of fresh JVMs, one variant per JVM, fixed G1 collector, `-Xms64m -Xmx512m -XX:ActiveProcessorCount=2`, and Temurin 25.0.4.1. Each process has 200 warmup calls on two disjoint keys, then ten cycles over ten measured keys. Every measured output is checked outside its API clock. Caller seed/message/context/entropy/key/signature hashes are compared before warmup and after the resource interval.

Peak RSS is the complete process maximum from `/usr/bin/time -l`, including initialization, fixtures, warmup, checks and teardown. Allocated bytes and thread CPU are scoped to the operation; GC count/time and heap snapshots cover the checked batch, including untimed validation and small recording arrays. Verification batches also execute one negative check per measured valid verification. JSON formatting and caller-integrity hashing are outside the GC interval. `System.gc()` plus 30 ms precedes the final heap snapshot: the label is requested-GC heap, not guaranteed completed collection, exact live heap or operation peak. Collection time is a millisecond-resolution MXBean counter, not a pause distribution. No consumed stack or exact peak heap is established.

Changes below are `100 × (changed/original − 1)` from mean per-process measurements; positive means more bytes/time. GC entries are mean collection counts per checked batch. Each table keeps all cells, including losses. Diagnostic API clocks are from this resource protocol and must not replace the earlier latency experiments.

### Earlier FORS bit extraction

| Parameter / operation | Allocated bytes | Process RSS | Requested-GC heap | GC count original → changed | API wall | Thread CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SLH-DSA-SHA2-128f / verify | -5.07% | -2.85% | +0.03% | 1 → 1 | +2.42% | +2.07% |
| SLH-DSA-SHA2-128s / verify | -7.74% | -2.91% | +0.03% | 0 → 0 | +7.06% | +7.01% |
| SLH-DSA-SHA2-192f / verify | -3.70% | -1.53% | +0.03% | 2 → 2 | -0.81% | -0.66% |
| SLH-DSA-SHA2-192s / verify | -7.12% | -2.21% | +0.02% | 0 → 0 | -0.70% | -0.56% |
| SLH-DSA-SHA2-256f / verify | -3.61% | -7.48% | +0.03% | 3 → 2 | +1.63% | -0.32% |
| SLH-DSA-SHA2-256s / verify | -4.70% | -6.11% | +0.02% | 1 → 1 | -0.89% | -0.74% |
| SLH-DSA-SHAKE-128f / verify | -6.38% | -7.06% | +0.04% | 1 → 1 | -0.11% | -0.03% |
| SLH-DSA-SHAKE-128s / verify | -9.20% | -6.56% | +0.03% | 0 → 0 | +0.01% | -0.04% |
| SLH-DSA-SHAKE-192f / verify | -2.80% | -6.43% | +0.03% | 2 → 2 | -0.58% | -0.65% |
| SLH-DSA-SHAKE-192s / verify | -7.40% | -6.47% | +0.04% | 0 → 0 | -0.84% | -0.82% |
| SLH-DSA-SHAKE-256f / verify | -3.11% | -7.22% | +0.04% | 3 → 2 | -0.25% | -0.59% |
| SLH-DSA-SHAKE-256s / verify | -5.24% | -6.84% | +0.03% | 1 → 1 | -0.82% | -0.80% |

### Combined ML sampling buffers

| Parameter / operation | Allocated bytes | Process RSS | Requested-GC heap | GC count original → changed | API wall | Thread CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ML-DSA-44 / keygen | -15.64% | -0.78% | +0.06% | 0 → 0 | +0.16% | +1.11% |
| ML-DSA-44 / sign | -21.07% | -8.28% | +0.09% | 0 → 0 | -1.69% | -1.61% |
| ML-DSA-44 / verify | -20.38% | -4.56% | +0.06% | 0 → 0 | -5.33% | -5.10% |
| ML-DSA-65 / keygen | -18.95% | -7.40% | +0.05% | 0 → 0 | -8.69% | -7.86% |
| ML-DSA-65 / sign | -24.95% | -1.47% | +0.05% | 0 → 0 | -3.44% | -2.77% |
| ML-DSA-65 / verify | -24.67% | -9.12% | +0.05% | 0 → 0 | +0.92% | +0.25% |
| ML-DSA-87 / keygen | -23.48% | -0.97% | +0.03% | 0 → 0 | +0.44% | +0.45% |
| ML-DSA-87 / sign | -28.92% | -8.71% | +0.05% | 0 → 0 | -2.04% | -1.96% |
| ML-DSA-87 / verify | -28.83% | -9.17% | +0.05% | 0 → 0 | -7.24% | -2.20% |

### WOTS output buffer

| Parameter / operation | Allocated bytes | Process RSS | Requested-GC heap | GC count original → changed | API wall | Thread CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SLH-DSA-SHA2-128f / keygen | -73.03% | +0.20% | +0.07% | 0 → 0 | -3.29% | -3.34% |
| SLH-DSA-SHA2-128f / sign | -66.67% | +8.58% | +0.03% | 10 → 3 | +1.98% | +2.04% |
| SLH-DSA-SHA2-128f / verify | -61.06% | -0.57% | +0.05% | 1 → 0 | +4.51% | +4.44% |
| SLH-DSA-SHAKE-128f / keygen | -73.29% | +1.76% | +0.08% | 0 → 0 | +2.99% | +2.98% |
| SLH-DSA-SHAKE-128f / sign | -66.82% | -4.83% | +0.07% | 10 → 3 | +0.57% | +0.61% |
| SLH-DSA-SHAKE-128f / verify | -61.77% | -1.36% | +0.05% | 1 → 0 | -8.43% | +1.00% |

## Are the tradeoffs worthwhile?

**FORS: conditional allocation/RSS improvement, not an unconditional latency optimization.** Allocation falls 2.80–9.20% and process RSS 1.53–7.48% in this boundary and corpus. SHA2-128s verification nevertheless takes 7.06% more wall time and 7.01% more thread CPU, with both process pairs slower. SHA2-128f is also slower in aggregate. Most checked batches show unchanged collection counts; the 256f sets fall from three to two. The small change can be useful where allocation or process footprint matters, but these retained losses warrant workload-specific evaluation before claiming a general performance benefit. Earlier shared-JVM SHAKE losses and later mixed isolated-JVM results remain in the original report.

**ML sampling: promising resource reduction, with parameter-specific CPU tradeoffs still unresolved.** New keygen allocation falls 15.64–23.48%; sign/verify fall 20.38–28.92%, and RSS falls 0.78–9.17%. No measured batch collects, so there is no new GC-count gain to claim. ML-DSA-65 keygen has favorable wall/CPU directions here, but ML-DSA-44/87 keygen and ML-DSA-65 verification have aggregate CPU losses. The earlier six-round confirmation included all six ML-DSA-44 verification rounds slower; this resource protocol shows the opposite direction with different boundaries/corpus, so the newer result does not erase it. Worth pursuing for allocation-sensitive workloads; a universal speed claim remains unsupported.

**WOTS: substantial allocation/collection-count reduction, with material counterexamples for latency and RSS.** Both signing batches fall from ten collections to three (−70%); verification falls from one to zero in these finite batches. The collection-time counter falls from 3.0→0.5 ms for SHA2 signing (−83.33%) and 2.5→1.0 ms for SHAKE signing (−60%), but these small quantized totals do not establish tail-pause or sustained-throughput gains. SHA2 signing RSS rises from 106,987,520→116,170,752 B (+8.58%), and SHA2 verification wall/CPU increase 4.51%/4.44% in both pairs. SHAKE keygen is also slower in both pairs. SHAKE verification wall improves 8.43% while thread CPU worsens 1.00%; that is not evidence of faster cryptographic work. Worth considering when allocation traffic is the overriding constraint, but these measurements do not justify presenting it as an overall latency or memory improvement.

Requested-GC heap snapshots are slightly higher for every candidate cell (roughly 0.02–0.09%), despite lower allocation traffic. They include fixtures, runtime state and recording arrays, have only two samples per side, and do not isolate retained algorithm memory or establish a leak. All original/changed values and paired samples are present in the JSON; zero-denominator GC percentages are null.

## Reproduction and source evidence

Use `libs/bouncycastle/experiments/completion/prepare.py` with the earlier pinned preparations available, then `collect.py --manifest PATH --out results/bouncycastle/completion/new-result.json` during a coordinated quiet window. The new collector refuses altered source/class/driver/fixture seals. The [prepared manifest](../../results/bouncycastle/completion/prepared.json) and preparation logs preserve exact local paths and commands. The [source archive](../../results/bouncycastle/completion/sources.tar.gz) is byte-inventoried in [sources.json](../../results/bouncycastle/completion/sources.json): extract `baseline/`, then overlay exactly one selected variant directory; never combine overlays. FORS also retains its native regression source files. Compiled classes are host build artifacts, not portable evidence binaries.

Run `python3 libs/rustcrypto/experiments/completion/audit.py` to independently recheck saved raw hashes, sample counts, sums/means, percentage formulas and paired order for both providers without running cryptographic workloads. The [audit result](../../results/rustcrypto/completion/independent-check.json) passes all 54 Rust and 113 BC processes. Source snapshots and current raw data remain distinct from the earlier experiments.
