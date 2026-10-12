# Noble and CIRCL audit

Audit target: `80c832da6ce81ca8def12b319da9f4c19d589111`. Scope: the noble and CIRCL harnesses, noble patches and rewritten cryptographic paths, CIRCL vendored sources and added stages, validation, timing, memory, and signing/verifying opportunities. This is a read-only audit of the implementation. No existing benchmark results were replaced.

This is the historical snapshot report. See the [current-main addendum](current-main-status.md) for unchanged cache defects and the later Falcon adapter/result updates at `45076e0`.

## Outcome and evidence

The arithmetic and encoding probes passed for the exercised noble paths, but two newly reproduced CIRCL stage-cache bugs make the cached experimental verifiers unsafe to reuse as currently written. There are also timing and memory defects that prevent treating all reported speedups and resource numbers as directly comparable. These findings concern the added harness/experimental paths; they do not establish flaws in upstream CIRCL.

Noble's three patches apply with zero fuzz to the exact [official npm 0.7.1 package](https://registry.npmjs.org/@noble/post-quantum/-/post-quantum-0.7.1.tgz). SHA-512 integrity was verified against the committed lockfile for post-quantum 0.7.1 and hashes/curves/ciphers 2.4.0. All 62 CIRCL non-stage vendored source files matched the [official v1.6.5 Go module archive](https://proxy.golang.org/github.com/cloudflare/circl/@v/v1.6.5.zip) after the documented import-path and package-name substitutions. There were no other source deltas. The four `stages.go` files are harness additions. See [upstream comparison evidence](evidence/js-go-upstream.txt).

Fresh noble probes ran all 387 verification cases and 45 ML-DSA signature-generation cases from the supplied validation suite against both the patched and fast implementations. Each implementation passed 432/432 with the JS hash selection and 432/432 with native hashes. These are 1,728 case/backend executions, not a new full-suite claim. Evidence: [JS hash results](evidence/js-go-noble-differential.json), [native hash results](evidence/js-go-noble-native-differential.json), and [reproduction script](evidence/js-go-noble-probes.mjs). The script does not exercise the separate cached-key APIs or the stage pipelines.

Fresh Go probes compiled copied harness files against the official v1.6.5 source and reproduced the two cache defects below. Evidence: [test source](evidence/js-go-circl-probes.go.txt) and [output](evidence/js-go-circl-probes.txt). The failed tests are intentional reproductions of defects; they are not passing validation. Runtime: Go 1.27.0 darwin/arm64, Node 22.23.2. No full performance run, Bun run, amd64/AVX2 run, PGO regeneration, or exhaustive side-channel analysis was performed.

## Findings

### JG-1 — P2: ML-DSA prepared cache accepts a signature under a mutated public-key input

**Locations:** `libs/circl/cmd/pqcbench/stages_ml44.go:57`, `:167`; the generated `stages_ml65.go` and `stages_ml87.go` have the same lines. **Status: reproduced.**

`prepare` stores `m.cpk, m.cctx = pk, ctx` without copying. The best pipeline checks `bytes.Equal(pk, m.cpk)` to decide whether the decoded key, matrix, transformed t1, and message prefix are still valid. If the caller mutates the input slice, the saved comparison slice mutates too, while the derived cache remains tied to the old bytes. For all three ML-DSA levels, `prepare(valid)` followed by `pk[0] ^= 1` made `verifyPipeline(true, changedPk, originalMessage, originalContext, originalSignature)` return **true**, while the uncached pipeline returned **false**. The same aliasing mechanism applies to a mutable context.

This is an acceptance under the wrong requested public key in the reusable prepared-stage helper. Current fixed, unmodified benchmark inputs do not trigger it, and the upstream public-key API is unaffected. Copy both pk and context when installing the cache, just as the rebuild path already does at line 176, or bind the prepared verifier to an immutable key object with no per-call key argument. Add prepare → input-mutation → verification tests at each parameter set and include context mutation. Do not use this helper as an application verifier until fixed.

### JG-2 — P2: a failed SLH-DSA key import poisons both stage pipelines

**Locations:** `libs/circl/cmd/pqcbench/stages_slh.go:40-45`, `:226-230`. **Status: reproduced.**

`setKey` overwrites `m.pub` before `UnmarshalBinary` succeeds. The existing `m.v` retains `&m.pub`, but `m.cpk` remains the old successful key when import fails. A subsequent verification using that old key skips rebuilding and uses the damaged public-key object. A valid SHA2-128f verification, a verification with its truncated public key, then the original valid verification produced **true, false, false** for both `total` and `total_best`.

The consequence is persistent false rejection until another key forces a rebuild; adversarial malformed requests can disrupt later valid verification in this experimental cached verifier. Build the new public key, verifier, and hash states in temporaries, then install them atomically after import succeeds. Alternatively invalidate the entire cache on failure. Test valid A → malformed key → valid A and valid A → valid B → valid A for all SLH parameter sets. The ordered single-case validation suite did not establish these state transitions.

### JG-3 — P2: noble fast/native paths drop the upstream secret-erasure behavior

**Locations:** `libs/noble/src/native-hash.mjs:85-86`, `:161`; `libs/noble/src/fast-shake.mjs:80-81`, `:113`; `libs/noble/src/fast-ml-dsa.mjs:367-368`, `:433-435`, `:552`; `libs/noble/src/fast-slh-dsa.mjs:538-549`, `:606`. **Status: code-confirmed and hash-state behavior reproduced.**

The replacement hash `destroy()` only sets a flag, and both XOF `clean()` functions do nothing. Fast ML-DSA returns with expanded secret polynomials, mask-generation seed/state, and other secret temporaries unwiped; fast SLH-DSA similarly has no lane cleanup. This exceeds the introductory claim that only rejected intermediate buffers are not wiped: the fast implementation has no final secret cleanup either. In a fresh probe, the official SHAKE object's state contained zero nonzero bytes after `destroy()`, whereas each replacement retained the entire 32-byte synthetic input. See [probe output](evidence/js-go-hash-memory-probes.json).

This is a defense-in-depth regression under a heap-disclosure or post-use memory-inspection threat model, not evidence that ordinary signature outputs expose keys. It also changes the work being compared. Restore best-effort wiping of owned secret buffers on success and exceptional exits, with explicit destroy methods for long-lived expanded secret keys; do not wipe caller-owned key arrays. Rebenchmark the cleanup-preserving implementation. JS cannot promise perfect erasure or constant-time execution, but that does not justify silently removing the concrete cleanup upstream performs.

### JG-4 — P2: noble worker verification times extra negative verifications without counting them

**Locations:** `libs/noble/src/worker.mjs:35-37`; `libs/noble/src/bench-one.mjs:168-174`. **Status: code-confirmed.**

Every worker request executes `count` valid verifications followed by a full tampered-signature verification before sending its response. The parent times the full response interval and divides by `count * threads`. For the slow parameter sets where `count` is one, the timed request contains two cryptographic verifications per counted operation, in addition to messaging. Single-threaded tamper checks occur outside the timed call. This depresses worker throughput and inflates the reported per-operation time, so apparent poor scaling is partly a measurement artifact.

Validate the negative signature during setup or in a separate untimed request; retain correct-output checks without including a hidden additional operation. Continue reporting batch throughput separately from single-operation latency, and avoid treating repeated copies of one batch mean as independent latency samples.

### JG-5 — P2: CIRCL throughput and CPU-utilization denominators omit loop/check time

**Locations:** `libs/circl/cmd/pqcbench/bench.go:257-290`. **Status: code-confirmed; synthetic timing probe reproduced the accounting mismatch.**

CPU time covers the full measured loop, while `ops_per_sec` and `cpu_util` divide by `wallTotal`, the sum of only the timed calls. The excluded output comparisons, sample collection, and loop bookkeeping still consume CPU. This violates the contract's throughput denominator and differs from noble's whole-loop denominator. A targeted empty-operation plus 1 ms checker probe produced infinite throughput/utilization on this machine because the empty call durations rounded to zero while the loop consumed real wall/CPU time. That probe illustrates the defect; it is not a claim that the stored cryptographic rows are infinite.

Record `loopWall := time.Since(loopStart)` immediately after the measured loop and use it for throughput and CPU utilization; retain isolated per-call samples for latency percentiles. Reject non-finite metrics and check JSON marshal errors. This matters particularly for near-empty cached stages and for comparisons of CPU efficiency.

### JG-6 — P2: noble memory rows do not select the declared hash backend

**Locations:** `libs/noble/src/memory.mjs:24-25`, `:54-68`; `libs/noble/src/hashlayer.mjs:9-10`; compare `libs/noble/src/bench.mjs:49-50`. **Status: code-confirmed.**

Memory subprocesses inherit `process.env` and never set `NOBLE_PQ_HASH` from `v.hash`. With the normal unset environment, `keygen.v1`, `sign.v1`, and `verify.v1` measure patched noble with JS hashing, and `keygen.v3` measures fast JS rather than fast+native. If the environment is manually set to native, other declared JS variants can instead measure native hashing. Successful output hashes do not reveal the substitution because both backends are byte-compatible.

Pass `{ ...process.env, NOBLE_PQ_HASH: v.hash }` for every memory child, matching bench/stages/validate, and emit the selected backend with each row. Regenerate affected memory rows after the fix.

### JG-7 — P2: noble `heap_peak_bytes` is neither a peak nor the operation's total heap footprint

**Locations:** `libs/noble/src/mem-one.mjs:78-86`, `:94-102`. **Status: code-confirmed; omitted backing-store behavior reproduced.**

The field is `max(0, heapUsed_after - heapUsed_before)`. `--expose-gc` enables explicit GC but does not prevent GC during the operation, so a transient peak can disappear before the final sample. V8's `heapUsed` also excludes ArrayBuffer backing-store accounting, which is material for the typed polynomial arrays and signatures here. An 8 MiB typed-array allocation raised `arrayBuffers` by 8,388,608 bytes while this measurement's `heapUsed` delta was only 3,488 bytes; see the [probe output](evidence/js-go-hash-memory-probes.json). The sampling profiler is an allocation estimate and does not repair the separate peak field.

Label the current observation as an end-of-operation V8-heap delta, add separate external/ArrayBuffer measurements, and return null for an unmeasured peak. A production footprint comparison also needs the retained expanded-key/cache size and setup allocation, currently prepared before measurement. CIRCL honestly labels its GC-disabled HeapAlloc delta as an upper bound; that is not numerically the same quantity as noble's current field.

### JG-8 — P2: CIRCL stage `match` omits negative verification and ignores all timed results

**Locations:** `libs/circl/cmd/pqcbench/stages.go:211-216`; `libs/circl/cmd/pqcbench/bench.go:319-321`; `libs/circl/cmd/pqcbench/validate.go:240-242`. **Status: code-confirmed.**

The stage timing loop discards `r.run()`'s bool and supplies an empty checker. Only one fresh call after measurement determines `match`; `total` and `total_best` require only a true result on the positive signature. They never include a negative check in the stage command. Ordinary benchmark verification reuses `st.tamperRejected` from the baseline instead of checking the measured variant. Separate validation is useful, but it does not satisfy the contract that every measured variant must establish the positive and negative predicates on every run. Additionally, CIRCL validate prints a warning and exits successfully when cases fail, so callers must parse its results to detect failure.

Capture and validate each measured result outside its timed call, perform a negative check through the exact selected pipeline/variant before emitting a true match, and exit nonzero on any mismatch or validation failure. Add transition cases from JG-1/JG-2; one independent case per key is insufficient coverage for cache reuse.

### JG-9 — P3: CIRCL ML-DSA stage partition performs the norm check twice

**Locations:** `libs/circl/vendorcircl/mldsa44i/stages.go:47-52`, `:309-311`, `:368-370`; upstream-copy `libs/circl/vendorcircl/mldsa44i/dilithium.go:90-101`; identical issue in 65/87. **Status: code-confirmed.**

`DecodeSig` delegates to upstream `Unpack`, which already checks `||z||inf < gamma1-beta`; fused decode also performs that check. All hint-check alternatives repeat it. The canonical contract assigns the norm check to `hint_check`, and the upstream verifier checks it once. Thus CIRCL decode has extra work relative to that partition, while the assembled total has duplicate work relative to upstream. This is not an acceptance bug, but stage attribution and the claim of exactly the same end-to-end work are inaccurate.

Either expose a pure unpack-and-hint-validation decode for the canonical partition and keep the norm check in hint_check, or explicitly report a fused partition and remove the duplicate only in a pipeline where decode's successful norm check is guaranteed. Never remove both checks.

## Stage mathematics and optimization assessment

The reviewed ML-DSA reconstruction follows `InvNTT(A * NTT(z) - NTT(c) * NTT(t1 * 2^d))`; the CIRCL canonical serializers normalize coefficients to `[0,q)` and emit little-endian words. The rewritten noble arithmetic uses exact integer-valued doubles below `2^53`, with canonicalization after transforms and a fused sum bounded by `L * (q-1)^2` for `L <= 7`. Those bounds make the design plausible and the targeted functional probes found no arithmetic mismatch; they are not a formal arithmetic or side-channel proof. Preserve the full hint ordering/padding rules, challenge equality, z norm bound, and external `0 || len(ctx) || ctx || M` domain separation in subsequent changes.

For SLH-DSA, direct SHA-2 compression in noble retains the required public-seed padded block and length padding; 192/256-bit H/T use SHA-512 while F/PRF use SHA-256. The SHAKE fast lane fits the fixed F/H/PRF inputs within one rate block. CIRCL's alternative SHA-2 hash states restore a precompressed public prefix and hash the remaining address/message. These are real computations with meaningful optimization potential. All tree, layer, keypair, chain, height, and index address fields must remain part of the hash input. Per-worker hash state must remain independent.

CIRCL's parallel `ht_wots`/`ht_auth` stage microbenchmarks receive each layer's correct message/leaf precomputed outside timing. The layers of a real signature are dependent: layer j+1's WOTS input is the root produced at layer j. Their stage speedups cannot simply be added or transplanted into whole verification. Parallel FORS trees are independent; parallel WOTS chains within the current layer and batches of independent signatures are realistic next targets. The shipped total_best correctly keeps the hypertree layer progression sequential.

The following figures are from the committed results, not fresh performance measurements. [Selected original rows with source line numbers](evidence/js-go-selected-existing-results.json) preserve provenance. Latencies are microseconds; cached-key comparisons exclude setup.

| Existing path | Baseline → alternative | Observed ratio | Interpretation |
|---|---:|---:|---|
| CIRCL ML-DSA-44 sign, preunpacked | 74.89 → 34.45 | 2.17x | Reuse the upstream private-key object and signature buffer; no cryptographic rewrite required. |
| CIRCL ML-DSA-87 sign, preunpacked | 272.79 → 108.83 | 2.51x | Matrix and secret NTT setup is amortized across signatures. |
| CIRCL ML-DSA-44 verify, preunpacked | 46.45 → 18.18 | 2.55x | Existing documented object API already caches matrix and tr. |
| CIRCL ML-DSA-87 verify, preunpacked | 132.34 → 31.40 | 4.21x | Strong same-key opportunity; include memory and first-use costs. |
| Noble ML-DSA-44 sign, fast JS | 2072.15 → 1077.70 | 1.92x | Promising arithmetic/hash optimization, currently confounded by removed cleanup. |
| Noble ML-DSA-44 verify, fast JS | 1194.50 → 559.11 | 2.14x | No signing-secret cleanup benefit; substantial verification-only rewrite gain. |
| Noble ML-DSA-87 verify, cached pk | 3240.68 → 1218.15 | 2.66x | Key-dependent cache, distinct from uncached verification. |
| CIRCL SHA2-128f verify stages, total_best | 2901.43 → 1768.73 | 1.64x | SHA-2 prefix reuse is the meaningful algorithmic change; cache defects still need repair. |
| Noble SHAKE-128f verify, fast JS | 40520.00 → 16372.30 | 2.47x | Specialized Keccak/address/buffer path is promising. |

### Prioritized next experiments

1. **Use CIRCL's existing expanded-key objects for repeated-key workloads.** This is the lowest-risk improvement with the strongest stored evidence. Treat deserialization/expansion as setup and publish both cold and steady-state cost, retained memory, and break-even operation count. The extra staged verifier should beat this preunpacked baseline, not only repeated `UnmarshalBinary`. Per-worker signing buffers remain separate.
2. **Combine noble's fast ML-DSA arithmetic with its already implemented `expandSk`/`expandPk`.** `fast-ml-dsa.mjs:558-561` exports the cache APIs, but `variants.mjs:31-32` chooses only the slower vendor backend for caching. A cleanup-preserving fast+cache variant and a fast+native+cache experiment are unmeasured combinations. Choose native SHAKE based on parameter-specific end-to-end evidence; native hashes are not universally faster, especially for tiny SHA-2 calls. Copy/bind cache inputs, test key changes, and provide explicit disposal of secret state.
3. **Bring the CIRCL SLH SHA-2 public-prefix midstate path into signing.** The current addition accelerates verification F/H/T. Signing repeatedly uses the same public prefix too, so the same transformation is a justified experiment, not a measured signing gain. Adapt it inside a separate upstream-based signing fork, preserve PRF/HMAC distinctions and all address bytes, and validate deterministic signatures against official vectors before timing.
4. **Combine noble's faster SLH hash lanes with the top-tree cache.** The current top-tree cache lives in the vendor path while the fast hash/ADRS path is separate. The top XMSS tree is key-dependent and its public nodes are reusable; lower tree selection varies with the message digest. Measure setup, retained nodes, and changing-message signing to establish break-even. The stored SHA2-128f cache variant is slower than baseline, so caching by itself is not evidence of a win here.
5. **Batch independent hashes/signatures where the dependency graph permits it.** Reuse bounded worker pools and batch sizes large enough to amortize scheduling. For a single signature, consider FORS trees or chains in the current WOTS layer, not all hypertree layers given unavailable future messages. Report throughput and service latency separately; repair JG-4 first.
6. **Measure a varied workload before declaring a signing winner.** Both harnesses repeatedly sign the same key and message deterministically. That replays the same ML-DSA rejection path and the same SLH addresses. Rotate public messages and contexts and several keys, report per-message rejection counts where available, distinguish cold-key/many-key/same-key workloads, and include invalid verification cases for denial-of-service behavior. Caching A/tr/t1 or a key-only top tree is valid across messages; caching signature-derived mu, sampled c, z, layer messages, or final verification outcomes would be a different workload.

The specialized unrolled Keccak, fused arithmetic, public-key expansion, and SHA-2 prefix reuse are real optimizations. Build tags, GOAMD64, PGO, Bun, and worker counts are configuration experiments whose benefit depends on architecture and workload. On the current arm64 audit host, setting GOAMD64 would not establish an AVX2 build comparison; the archived amd64 results require their own environment provenance. Do not interpret passing vectors as proof of constant-time behavior or promote secret-processing rewrites without separate review.

## Falcon interoperability note

`libs/noble/src/algs.mjs:25` selects the unpadded `falcon512`/`falcon1024` APIs. `libs/bouncycastle/src/Alg.java:191-194` pads its exported signatures to 666/1280 bytes. Official noble 0.7.1 explicitly rejects trailing zero tails in unpadded signatures and provides separate padded APIs. This explains the observed noble←BouncyCastle Falcon cross-verification failures as a wire-format adapter mismatch, not a demonstrated cryptographic failure. The BouncyCastle audit independently reproduced successful verification through noble's padded APIs. Make the encoding explicit in artifact metadata and select the corresponding strict verifier; do not fix interoperability by indiscriminately accepting malformed tails.

## Limits

Fresh validation did not regenerate SLH signing/keygen vectors, exercise Bun, rerun all cached APIs, prove constant time, or confirm archived timings on their original machine. Stack painting and JIT recursion probes were inspected but not calibrated across compiler/runtime versions; their numeric outputs should remain method-specific estimates. The original phase-2 validation results are useful evidence of the cases exercised, but the newly failing state-transition tests show why they are not a proof of reusable-cache correctness. No upstream CIRCL arithmetic defect was found in the inspected copy, and no noble arithmetic mismatch was found in the targeted probes.
