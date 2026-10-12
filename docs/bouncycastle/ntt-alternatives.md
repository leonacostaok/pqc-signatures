# Bouncy Castle ML-DSA NTT alternatives

Three isolated arithmetic alternatives are prepared against official bc-java `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`: folded final inverse scaling, fixed-twiddle Montgomery companions, and their combination. Each changes only `core/src/main/java/org/bouncycastle/crypto/signers/mldsa/Ntt.java`; each compiled production tree differs from baseline only in `Ntt.class`. A Java 25 screen and a separate Java 17 held-out-key confirmation support narrower signing gains: companion-only repeated gains on ML-DSA-44/65; combined repeated gains on ML-DSA-44/87 but retained substantial losses elsewhere. Companion-only is the smallest credible patch to take forward. The folded-only alternative did not qualify for confirmation. These results are limited to the recorded machine, runtimes, inputs, and operation boundary.

The [prepared manifest](../../results/bouncycastle/ntt-alternatives/prepared-v1/manifest.json) binds copied source trees, complete class trees, drivers, runtime files, fixtures, and correctness results. The portable baseline archive and three overlays are in the same directory. Its SHA256 is `bb280c8513f09283317d29b91d46f42d3edb0d729b308943e3208e5b36e5c797`. The [preparation audit](../../results/bouncycastle/ntt-alternatives/preparation-audit-v2.json) reconstructs the source inventories from that archive and overlays, checks fixture hashes and correctness stdout, and checks local classes/runtime when available. Compiled classes and the Java runtime remain local build artifacts; an audit on a machine without them explicitly reports those checks unavailable.

## Alternatives

| Variant | Change | Source-derived effect |
| --- | --- | --- |
| `fused` | Fold the final inverse twiddle into the final Montgomery scale. | Removes 128 of 1,280 Montgomery reductions and one full array pass per inverse transform. No additional allocation. |
| `companion` | Precompute the low-word product of every public twiddle with QINV; use independent products in the reduction helper. | Shortens a multiplication dependency, retaining exactly the original signed result. Adds 1,024 bytes of static constant-array payload plus its header. No key-dependent cache. |
| `both` | Apply both changes. | Combines those arithmetic changes without altering sampling or operation state. |

The upstream implementation already uses in-place NTTs and pointwise accumulation without product arrays. These alternatives do not claim to remove allocations that the current production implementation has already removed. JVM optimization can change the consequences of a source-level arithmetic count, so fewer reductions or a shorter dependency does not establish lower latency.

## Arithmetic proof and caller audit

Write `M(x)` for signed Montgomery reduction, with `q=8380417`, `R=2^32`, and `QINV=58728449`. The last inverse butterfly uses `z=-25847`, then scales both outputs with `f=41978`. Its outputs are `M(f*(a+b))` and `M(f*M(z*(a-b)))`. Since `M(f*z)=3975713`, the second output can be replaced by `M(3975713*(a-b))`. Both are congruent modulo q. The generic inverse loop stops before `len=128`, and a single final loop performs both scaled outputs.

This is a known arithmetic technique rather than a new cryptographic construction: the [pq-crystals AVX2 inverse](https://raw.githubusercontent.com/pq-crystals/dilithium/master/avx2/invntt.S) folds its last twiddle and scale. Its [constant table](https://raw.githubusercontent.com/pq-crystals/dilithium/master/avx2/consts.c) contains `-3975713` for the opposite subtraction order. The Java candidate adds no secret-dependent branch, index, division, or sampling change.

All current forward NTT inputs have magnitude below q: decoded eta fields are bounded even for noncanonical encodings (`[-5,2]` or `[-11,4]`), decoded t0 lies in `[-4095,4096]`, and `t1<<13` is at most `1023*8192=q-1`. The centered twiddles have magnitude below q/2. Each forward butterfly adds a Montgomery result of magnitude below q, so every forward output has magnitude below 9q. A pointwise product is therefore bounded by `81*q^2`, and its reduced magnitude is at most 5,514,722, below q.

A matrix row contains at most seven reduced products; verification additionally subtracts a reduced challenge product. Before `reduce32`, the magnitude is below 8q. Writing its quotient as `t=floor((a+2^22)/2^23)` gives `|t|<=8` and reduced magnitude at most `2^22+8*8191=4,259,832`, below q. All inverse callers consequently supply inputs of magnitude below q.

The candidate source comment `Inputs satisfy |x| < q` refers to inverse-method entry, not the final butterfly stage. After the first seven inverse layers, every coefficient has magnitude below 128q. The last sum and difference have magnitude at most `256*(q-1)=2,145,386,496`, which is below signed-int maximum; the slightly looser `256q` envelope used below remains conservative. The folded right output has magnitude at most 6,176,124; the left output at most 4,211,177. Both lie in `(-q,q)`. These bounds follow from `|M(x)|<=|x|/R+q/2`. All long products and the subtraction inside Montgomery reduction fit in signed long. Java overflow in the low-word `a*QINV` computation is intentional and preserves the required low 32 bits; casting the upper word after `>>>32` has the same signed-int result as casting after `>>32`.

| Engine call at pinned source | Following operations | Required representative argument |
| --- | --- | --- |
| `285`, key generation | Add s2, conditional-add-q, power2Round | Adding s2 of magnitude at most 11 still leaves a value in `(-q,q)`, so canonical inputs to rounding are identical. |
| `333`, deriveT1 | Add s2, conditional-add-q, power2Round | The same bound covers noncanonical decoded eta values. |
| `433`, signing matrix product | Conditional-add-q, decomposition | Canonical coefficients are identical before decomposition. |
| `450`, c*s1 | Add y, reduce, norm check | Exact small integer product is preserved. |
| `459`, c*s2 | Subtract from w0, reduce, norm check | Exact small integer product is preserved. |
| `468`, c*t0 | Reduce, norm check, hints | Exact small integer product is preserved. |
| `562`, verification | Conditional-add-q, useHint | Canonical coefficients are identical before useHint. |

A challenge has at most 60 coefficients equal to +1 or -1. Each coefficient of the integer negacyclic products c*s1 and c*s2 therefore has magnitude at most 660, including noncanonical eta encodings; c*t0 has magnitude at most `60*4096=245760`. A different modular representative would have magnitude at least `q-245760=8,134,657`, exceeding the folded output bound. Thus these products are equal as integers, preserving subsequent rejection and hint decisions rather than merely modular residues.

Raw inverse-array equality is intentionally not a requirement for arbitrary inputs. As an algebraic illustration only, taking `a-b=2,145,386,737` gives original right result `-3,959,542` and folded result `4,420,875`, differing by q. That scalar is outside the tightened caller-domain endpoint `256*(q-1)` and is not claimed reachable at a current caller. Current callers either canonicalize safely or use products proved exactly equal. The Java gate found 38 such representative differences for fused and combined across its 516 inverse vectors, and zero for the companion-only variant; canonical results always matched.

For a fixed twiddle z, the companion is `zq=(int)(z*QINV)`. Evaluating `t=x*zq`, followed by the upper word of `(long)x*z-(long)t*q`, preserves the exact original signed reduction because its low-word t is identical. Forward and inverse twiddle companions are public constants; final scale companions are `-8395782` for 41978 and `151046689` for 3975713. This is also used in the [pq-crystals AVX2 forward butterfly](https://raw.githubusercontent.com/pq-crystals/dilithium/master/avx2/ntt.S). It trades a small static table and extra loads against a shorter dependency chain.

## Correctness evidence

Each variant passes 2,313 signed reduction/companion checks, 516 raw-equality forward transforms, 516 canonical-equality inverse transforms, and 108 exact sparse products compared with independent schoolbook negacyclic convolution. The arithmetic oracle includes maximal decoded eta/t0 values, both signs, zero, random inputs, and signed-domain endpoints. The [Python oracle](../../libs/bouncycastle/experiments/ntt-alternatives/arithmetic_oracle.py) independently checks a second bounded corpus. Bounded numerical checking supplements the range proof; it is not an exhaustive proof of every integer input.

The unchanged MLDeep correctness corpus supplies 432 operation checks and 288 negative checks per variant, covering all three pure and prehash sets, deterministic/fixed-entropy signing, message lengths 0–4096, contexts 0/1/255, repeated calls, exact key/signature bytes, and caller/key ownership. The decoder-specific gate adds 936 checks across 72 cases: cumulative hint overflow/decrease, duplicate hint indices, nonzero unused tail, positive/negative norm equality with adjacent accepted-interior controls, short/long signatures, wrong message/context, and valid verification after negatives. The malformed gate was copied unchanged from the parallel matrix experiment and is sealed with the other driver sources.

The separate integration task reports the upstream MLDSATest suite (14 test methods) and MLDSAWycheproofTest suite (3 methods, including 631 Wycheproof cases per variant) passing against these exact four production class directories, with class origins checked. Its source/test-data pins and stdout are retained in the [native comparison evidence](../../results/bouncycastle/alternative-comparison/native/). Those native records remain separate from this preparation manifest.

## Predeclared measurement plan

The [frozen plan](../../results/bouncycastle/ntt-alternatives/screen-plan-v2/protocol.json), SHA256 `2407ed7f9c9454bf803d86b74340f6846c4921ebaefc74543b1d2396d396e424`, covers all three parameter sets and keygen/sign/verify. Four rounds form two reversed-order pairs for all four variants: 144 fresh JVMs for timing and 144 separate fresh JVMs for allocation. Within each pair every candidate is on the opposite side of baseline in the second round. The first plan is retained as preparation history; version 2 only binds the strengthened portable checker, before any measurement, without changing production sources, drivers, fixtures, or job order.

Each process warms with 1,000 calls on two keys disjoint from the measured corpus, then consumes 128 distinct measured keys once each in a fixed shuffled order. The same fixture values recur across separate rounds; no measured batch cycles over a key. Timing records wall time and calling-thread CPU without allocated-byte reads; the allocation cohort records allocated bytes without operation clocks. Every output and caller/key ownership check is outside those counters; each measured verification also receives an untimed tamper check.

The operation boundary includes fresh lightweight operation setup, initialization, message update, and the final operation. Expanded-key import, caller copies, keygen encoding, and checks are excluded. No persistent key or matrix cache is introduced. Both cohorts use Temurin 25.0.4.1+1 with `-Xms64m -Xmx512m -XX:ActiveProcessorCount=2 -XX:+UseG1GC`. Whole-operation figures will not be inferred from the arithmetic oracle.

A cell can nominate a candidate for later confirmation only if aggregate wall time and calling-thread CPU improve by at least 3%, all four wall rounds improve, and no other cell has both an aggregate wall regression above 3% and four slower rounds. All smaller losses and allocation changes remain reported. This exploratory rule establishes neither statistical significance nor a general performance improvement.

Python entry points reject both optimization mode and PYTHONOPTIMIZE. Eight retained negative guard checks confirm that behavior. The collector validates source, class, driver, fixture, runtime, environment, and schedule bindings before and after collection, requires an explicit exclusive-window grant, and preserves stdout/stderr and process status before validating each result. The read-only auditor checks every output digest against portable fixtures, reconstructs paired totals and per-round ratios from untouched stdout, and preserves slower-key counts.

## Reproduction

Run `prepare.py --upstream PATH --old-manifest PATH --out NEW_DIRECTORY` in `libs/bouncycastle/experiments/ntt-alternatives`; it requires the pinned existing MLDeep fixtures. Then run `protocol.py plan --manifest PREPARED/manifest.json --out NEW_PLAN_DIRECTORY`. Preparation performs builds and correctness checks only. The existing portable source archive and fixture files allow an independent reconstruction without a working upstream checkout, although the preparation entry point currently obtains the source archive from Git.

After an exclusive measurement window has been granted, run `protocol.py collect --plan PLAN/protocol.json --mode timing --out NEW_TIMING_DIRECTORY --exclusive-window-grant DESCRIPTION`, followed by the separately granted allocation collection with `--mode allocation`. Run `audit.py --plan PLAN/protocol.json --timing TIMING_DIRECTORY --allocation ALLOCATION_DIRECTORY --out NEW_AUDIT_JSON` to recompute results. Each output directory/file must be new, preserving failed and superseded evidence.

## Java 25 screen results

The [raw-result audit](../../results/bouncycastle/ntt-alternatives/screen-audit.json) passed for 288 fresh JVMs and 36,864 output rows. The [relocated audit](../../results/bouncycastle/ntt-alternatives/portable-audit.json) independently reconstructed the portable source inventories, fixture outputs, paired totals, and round ratios. Local production/driver classes and runtime files were still available and were checked; this does not claim a binary audit on a machine without those files. The controlled collection window is recorded in [exclusive-window.json](../../results/bouncycastle/ntt-alternatives/exclusive-window.json); uncontrolled OS activity remains a limitation.

Each percentage below is `(changed/original−1)*100`; negative means lower time or allocation. Each cell contains 512 paired observations from 128 keys over four fresh-JVM rounds, with each measured key used once inside a process. The complete audit retains totals, means, slower-key counts, and every round ratio.

| Parameter | Operation | Variant | Wall change | CPU change | Allocated-byte change | Faster wall rounds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 44 | keygen | fused | +0.04% | +0.07% | -0.15% | 2/4 |
| 44 | keygen | companion | +0.83% | +0.84% | +0.42% | 2/4 |
| 44 | keygen | both | -1.43% | -1.31% | +0.42% | 4/4 |
| 44 | sign | fused | -2.72% | -2.73% | +0.00% | 4/4 |
| 44 | sign | companion | -6.03% | -6.00% | +0.20% | 4/4 |
| 44 | sign | both | -7.32% | -7.36% | +0.11% | 4/4 |
| 44 | verify | fused | -5.92% | -2.79% | -0.21% | 4/4 |
| 44 | verify | companion | -8.50% | -5.63% | -0.17% | 4/4 |
| 44 | verify | both | -4.70% | -4.89% | +0.01% | 3/4 |
| 65 | keygen | fused | +0.35% | +0.24% | -0.22% | 3/4 |
| 65 | keygen | companion | -0.40% | -0.40% | -0.16% | 2/4 |
| 65 | keygen | both | -5.08% | -2.18% | -0.16% | 4/4 |
| 65 | sign | fused | -2.81% | -2.29% | -0.13% | 4/4 |
| 65 | sign | companion | -5.35% | -5.11% | -0.13% | 4/4 |
| 65 | sign | both | -6.45% | -6.47% | +0.25% | 4/4 |
| 65 | verify | fused | +0.76% | +0.96% | +0.12% | 1/4 |
| 65 | verify | companion | -0.05% | -1.27% | -0.00% | 2/4 |
| 65 | verify | both | -0.68% | -1.87% | +0.56% | 2/4 |
| 87 | keygen | fused | +1.70% | +1.70% | +0.06% | 0/4 |
| 87 | keygen | companion | -0.52% | -0.68% | +0.06% | 3/4 |
| 87 | keygen | both | -0.90% | -0.83% | -0.00% | 2/4 |
| 87 | sign | fused | -2.73% | -2.51% | +0.20% | 4/4 |
| 87 | sign | companion | -4.99% | -4.83% | +0.00% | 4/4 |
| 87 | sign | both | -5.51% | -5.73% | +0.16% | 4/4 |
| 87 | verify | fused | -0.89% | -0.54% | -0.17% | 3/4 |
| 87 | verify | companion | -1.96% | -1.34% | -0.43% | 3/4 |
| 87 | verify | both | -2.30% | -2.25% | -0.21% | 4/4 |

The companion alternative qualified on ML-DSA-44 signing and verification and ML-DSA-65/87 signing. The combined alternative qualified on signing for all three sets. No variant had the frozen blocking condition of a wall regression above 3% with all four rounds slower. The folded-only variant qualified on no cell; its ML-DSA-87 key generation was 1.70% slower with four slower rounds, a retained loss. ML-DSA-44 verification for folded-only and ML-DSA-65 key generation for combined have larger wall than CPU changes and fail the CPU threshold. Combined ML-DSA-44 verification fails the all-round condition.

Allocated-byte changes range from −0.43% to +0.56%, with inconsistent signs. They provide no convincing memory improvement; the companion variants also add 1,024 bytes of static table payload plus an array header. The signing signals justify bounded confirmation, not a universal provider-wide gain or statistical-significance claim.

## Java 17 held-out confirmation

The [confirmation plan](../../results/bouncycastle/ntt-alternatives/confirmation-plan-v1/protocol.json), SHA256 `3eae6929ce3d80a789169ff66fe8cd3a8b3abf822a2031365f6ee8ce8aa8ebc9`, was frozen before any confirmation measurement. It contains 216 fresh JVMs: baseline, companion, and combined, all nine parameter/operation cells, four rounds arranged as two reversed-order pairs, and separate timing/allocation cohorts. Each process keeps 1,000 warmup calls on two disjoint keys and 128 distinct measured keys used once. Results on Oracle Java 17.0.11 are evaluated separately from the Java 25 screen.

The [confirmation manifest](../../results/bouncycastle/ntt-alternatives/confirmation-prepared-v1/manifest.json), SHA256 `6b0e78983a109d51e39f83453dc5820076b41de0355c8a83065f430b8613dfa7`, reuses the exact production class trees compiled with `--release 8`. Separate driver source copies change only `threadId()` to `getId()` and compile with `--release 17`. Fresh correctness/warmup/measured domains contain 462 distinct seeds, with zero overlap against all 552 earlier seeds. Per variant, the full new measured corpus passed 2,304 exact operation checks and 1,536 negative checks; the correctness corpus passed 432/288 checks, the malformed gate passed 936, and native MLDSA/Wycheproof suites passed 14+3 methods including 631 Wycheproof cases.

A separate supplemental gate reflects into the actual production companion variants. It checks every stored companion (256 entries), both final-scale constants, and 78,128 private-helper results against an independent BigInteger signed Montgomery oracle across 152 inputs including signed-int endpoints, current caller bounds, and fixed random values. Both companion and combined passed with production class origins verified. The original arithmetic gates remain unchanged. The [supplement audit](../../results/bouncycastle/ntt-alternatives/confirmation-supplement-audit.json) and [preparation audit](../../results/bouncycastle/ntt-alternatives/confirmation-preparation-audit.json) retain those bindings.

A cell replicates only if it qualified in the screen and independently improves both Java 17 aggregate wall and CPU time by at least 3%, with all four Java 17 wall rounds improving. A candidate is supported only if at least one cell replicates and no other Java 17 cell has an aggregate wall regression above 3% with all four rounds slower. Every smaller loss and every allocation result remains reported. Java 17 and Java 25 measurements are never pooled. Confirmation collection completed exactly once under its [recorded exclusive grant](../../results/bouncycastle/ntt-alternatives/confirmation-exclusive-window.json); no result was discarded and no process was rerun.

The [confirmation audit](../../results/bouncycastle/ntt-alternatives/confirmation-audit.json) passed 216 fresh JVMs and 27,648 checked output rows. The [relocated confirmation audit](../../results/bouncycastle/ntt-alternatives/confirmation-portable-audit.json) and [relocated supplemental gate audit](../../results/bouncycastle/ntt-alternatives/confirmation-supplement-portable-audit.json) also passed. They checked the original pinned local binary/runtime/native assets, which remained available, alongside relocated portable sources and fixtures. The integration task independently reran the confirmation audit successfully.

| Parameter | Operation | Variant | Wall change | CPU change | Allocated-byte change | Faster wall rounds | Replicates screen |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 44 | keygen | companion | -2.02% | -1.29% | +0.35% | 3/4 | no |
| 44 | keygen | both | +20.54% | +2.74% | +0.20% | 2/4 | no |
| 44 | sign | companion | -6.26% | -5.34% | +0.00% | 4/4 | yes |
| 44 | sign | both | -7.93% | -6.95% | +0.21% | 4/4 | yes |
| 44 | verify | companion | -0.64% | -0.05% | -0.16% | 2/4 | no |
| 44 | verify | both | -1.42% | +0.16% | -0.15% | 2/4 | no |
| 65 | keygen | companion | -1.65% | -2.34% | -0.31% | 3/4 | no |
| 65 | keygen | both | +3.92% | -0.93% | +0.00% | 2/4 | no |
| 65 | sign | companion | -6.33% | -5.73% | -0.17% | 4/4 | yes |
| 65 | sign | both | +12.45% | -5.77% | -0.13% | 3/4 | no |
| 65 | verify | companion | +1.43% | -0.53% | -0.38% | 2/4 | no |
| 65 | verify | both | +0.44% | -2.24% | -0.38% | 1/4 | no |
| 87 | keygen | companion | -1.22% | -1.76% | +0.00% | 2/4 | no |
| 87 | keygen | both | +0.52% | -1.11% | -0.37% | 1/4 | no |
| 87 | sign | companion | -2.18% | -3.40% | -0.31% | 3/4 | no |
| 87 | sign | both | -5.42% | -5.55% | +0.16% | 4/4 | yes |
| 87 | verify | companion | -3.82% | -1.75% | -0.00% | 3/4 | no |
| 87 | verify | both | -3.06% | -1.88% | -0.00% | 2/4 | no |

The [frozen-rule decision](../../results/bouncycastle/ntt-alternatives/confirmation-selection-recomputed.json) supports companion via ML-DSA-44/65 signing and combined via ML-DSA-44/87 signing. Companion ML-DSA-87 signing did not meet the Java 17 wall threshold or all-round condition; its earlier ML-DSA-44 verification signal did not replicate. No general key-generation or verification speed claim follows. Java 17 allocation differences range from −0.38% to +0.35%, remain inconsistent, and establish no memory gain.

Combined ML-DSA-44 key generation regressed 20.54% in wall time and 2.74% in CPU; ML-DSA-65 key generation regressed 3.92% in wall time despite 0.93% lower CPU; ML-DSA-65 signing regressed 12.45% in wall time despite 5.77% lower CPU. These losses do not trigger the predeclared blocker because none had four slower wall rounds, but they materially limit the practical conclusion. The [largest wall/CPU gaps](../../results/bouncycastle/ntt-alternatives/confirmation-largest-wall-cpu-gaps.json) are retained for inspection, including a combined ML-DSA-65 signing sample of 14.96 ms wall versus 1.43 ms CPU. Such gaps do not identify their cause. Every row stays in the aggregates, with no outlier removal or replacement run.

Independent source review found no blocker and preferred companion-only as the minimum scope: its loop structure and exact signed representatives stay unchanged, while combined additionally relies on the seven-caller range proof above. The direct production table/helper supplement addresses the distinction between testing a reconstructed arithmetic formula and testing the compiled private helper. The companion table costs 1 KiB of static payload plus an array header; no cross-call cache or algorithm/security/output change is introduced. The evidence supports a focused signing optimization candidate on this machine across two runtimes, with parameter-specific limits, not an upstream-ready universal improvement.

To independently recompute Java 17 evidence, run `confirmation_audit.py --plan PLAN/protocol.json --timing CONFIRMATION_TIMING --allocation CONFIRMATION_ALLOCATION --out NEW_AUDIT_JSON`, followed by `confirmation_supplement.py audit --manifest CONFIRMATION_PREPARED/manifest.json --out NEW_SUPPLEMENT_JSON`. Recompute selection with `select_confirmation.py --plan PLAN/protocol.json --audit NEW_AUDIT_JSON --out NEW_SELECTION_JSON`. All paths refer to the owned experiment/results directories. `confirmation_prepare.py` prepares fresh Java 17 driver/fixture/native gates from the sealed screen manifest; `confirmation_supplement.py prepare` adds the direct production gate while retaining the pre-supplement manifest; then `confirmation_protocol.py plan` seals the collection schedule. Original production and screen-driver artifacts remain unchanged.
