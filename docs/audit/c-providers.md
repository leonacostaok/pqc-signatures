# C providers: liboqs and OpenSSL

Audit target: repository commit `80c832da`. Scope: the two C harnesses, their local algorithm alternatives, upstream correspondence, validation, timing, and memory accounting. This report distinguishes source-proven harness issues from measured performance claims and from proposed experiments. No production source or committed result was changed.

This is the historical snapshot report, separate from subsequent upstream production performance patches. See the [current-main addendum](current-main-status.md) for status at `45076e0` and the shared ML-DSA/SLH-DSA scope of the stage context-bound finding.

## Evidence and limits

The audit started with `common/CONTRACT.md` and inspected both build scripts before downloading dependencies. Exact official sources were cloned from [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs/tree/5a1a854b0dc9f2141bdc771c555ee60c37950183) and [openssl/openssl](https://github.com/openssl/openssl/tree/45e844fa2a14ec92d146bd8f5778ac130b6625fb):

| Provider | Requested tag | Resolved commit | Comparison |
|---|---|---|---|
| liboqs | `0.16.0` | `5a1a854b0dc9f2141bdc771c555ee60c37950183` | Clean upstream clone; `git apply --check` accepts the repository's `slh-fasthash.patch`. |
| OpenSSL | `openssl-3.5.9` | `45e844fa2a14ec92d146bd8f5778ac130b6625fb` | Clean upstream clone; no provider patch is applied by this harness. Its custom alternatives live in the driver. |

Source SHA-256 digests and clone status are preserved in [c-providers-provenance.json](evidence/c-providers-provenance.json). Recomputed summaries of the committed measurements are in [c-providers-artifact-summary.json](evidence/c-providers-artifact-summary.json). Those summaries are analysis of existing data, not fresh benchmark runs.

The host is macOS arm64. The repository harnesses assume Linux/glibc and x86: OpenSSL configures `linux-x86_64`, uses an `rsp` instruction in memory measurement, and both harnesses use pthread barriers; liboqs additionally interposes glibc allocator internals and unconditionally compiles x86 stage units. A native ARM OpenSSL archive and a compatibility driver were built under `libs/openssl/build/audit-arm`. No successful fresh provider validation run resulted, and no performance or memory conclusions are drawn from that build. No full benchmark was run. The bounds concern below is a static finding; the complete harness path was not reproduced. This review does not establish absence of cryptographic, side-channel, undefined-behavior, or concurrency defects beyond the inspected paths.

## Findings

### C1 — P1: liboqs SLH totals repeat the hypertree verification work

**Source:** `libs/liboqs/src/bench.c:801–808`, `libs/liboqs/src/bench.c:1084–1091`, `libs/liboqs/src/stages_slh.c:62–87`, `libs/liboqs/src/stages_slh.c:90–136`.

`run_pipeline()` calls `prepare_layers()` immediately after FORS. That helper walks all hypertree layers with upstream `xmss_pk_from_sig()`, which already performs WOTS public-key recovery and authentication-path hashing. The pipeline then calls `ht_wots()` and `ht_auth()`, recomputing those operations. The helper is correctly outside timing for an isolated stage, but it is inside every measured `total` and `total_best` pipeline call. The comment calling it untimed does not describe the total path.

**Consequence:** SLH totals measure a verifier with substantially duplicated work, so they cannot be presented as the cost of one assembled verification or compared directly with OpenSSL's sequential total. The committed SHA2-128f medians illustrate the issue: liboqs total is 3,569,982 ns while the sum of its stage-v0 medians is 1,656,540 ns. This observation supports the source diagnosis, but the source call graph is the decisive evidence; noisy stage sums alone are not proof.

**Fix:** Keep `prepare_layers()` exclusively for isolated stage measurements. Implement the total as `hmsg → fors → (wots(layer), auth(layer))` repeated in layer order, passing the newly computed root into the next layer. The selected hash/backend alternative must be used during that single walk. Preserve final root comparison, address transitions, and rejection of malformed inputs. Do not precompute layer messages for a purported end-to-end verifier. This is the clearest immediate efficiency improvement in the C harnesses, although it removes benchmark duplication rather than improving upstream liboqs verification.

**Status:** Proven by source; no new timing claim.

### C2 — P1: the liboqs stage wrapper lacks the context-length guard before prefix construction

**Source:** `libs/liboqs/src/bench.c:316–319`, `libs/liboqs/src/bench.c:754–766`, `libs/liboqs/src/bench.c:934`; compare the existing guards at `libs/liboqs/src/bench.c:324` and `:340` and OpenSSL's guard at `libs/openssl/src/pqc_stages.c:1153`.

The stage wrapper stores its pure-mode prefix in `pre[2 + 255]` but calls `make_pre()` with unchecked `ctxlen`. That helper copies the entire caller-specified context and truncates its length to one byte. The normal sign/verify wrappers reject `ctxlen > 255` before calling it; the stage constructor does not. Later stage checks are too late to serve as the wrapper's defensive input validation.

**Consequence:** The stage verifier does not safely enforce the FIPS external-interface context bound. The committed suite contains no context longer than 255 bytes, so its passing totals do not cover this case.

**Fix:** Reject oversized context lengths at the stage constructor boundary, before prefix construction or allocation, and return a normal verification failure. Route every pipeline entry through that check and add an overlong-context rejection case to the common validation contract when implementing the fix.

**Status:** Static/unreproduced for the complete harness. No exploitability claim is made.

### C3 — P2: OpenSSL validation substitutes serial operations for advertised threaded variants

**Source:** `libs/openssl/src/pqc_validate.c:31–60`, `libs/openssl/src/pqc_validate.c:158–170`, `libs/openssl/src/pqc_stages.c:1357–1358`; actual threaded layer implementation at `libs/openssl/src/pqc_stages.c:1100–1117`.

Phase-1 validation changes every `IMPL_THREADS` variant into one `IMPL_REUSE` worker. For staged SLH validation, `stage_pipeline()` explicitly maps `X_THREADS` for WOTS/auth into serial `X_LL`. Consequently a result named `sign.v5`, `verify.v5`, `stages.ht_wots.v4`, or `stages.ht_auth.v4` does not establish that the corresponding parallel execution path was checked. FORS and ExpandA thread methods do reach their thread pool; this finding should not be generalized to them.

**Consequence:** The 12,363 recorded OpenSSL passes overstate execution-path coverage. They provide useful algorithmic checks of reused contexts and low-level hashing, but cannot rule out worker sharing, barrier, publication, or task partitioning mistakes in the substituted paths. The layer-parallel stage also assumes already known layer inputs; it is not an end-to-end parallelization of the dependent hypertree.

**Fix:** Validate whole-operation threaded variants with their actual workers and distinct per-worker expected outputs. Validate isolated threaded stages against the upstream stage outputs on prepared inputs, then separately validate a real end-to-end pipeline. Report any method deliberately replaced or unsupported as such rather than retaining its parallel variant label.

**Status:** Proven by source; no concurrent failure demonstrated.

### C4 — P2: liboqs threaded validation writes shared RNG configuration from each worker

**Source:** `libs/liboqs/src/bench.c:168–180`, `libs/liboqs/src/bench.c:913`, `libs/liboqs/src/bench.c:923–924`, `libs/liboqs/src/bench.c:987–988`.

The deterministic callback reads global `g_rng_buf` and `g_rng_len`. `vjob_run()` sets those globals in each keygen/sign validation worker, while other workers can simultaneously set or read them. Identical written values do not remove a C data race. The ordinary benchmark sets the RNG before releasing its workers, so its setup is materially different from the validation implementation.

**Consequence:** Threaded validation uses undefined concurrent access even if all byte comparisons currently pass. This weakens the intended evidence for the threading variants.

**Fix:** Configure an immutable shared RNG descriptor before creating/releasing same-case workers, or use thread-local deterministic RNG input for tests with distinct worker cases. Keep mutable RNG state out of the workers' shared path. Validate with a race detector as a future implementation check.

**Status:** Source-proven unsynchronized shared access; not reproduced with a race detector.

### C5 — P2: memory results omit retained stage state and OpenSSL's driver allocations

**Source:** `libs/liboqs/src/bench.c:766–767`, `libs/liboqs/src/bench.c:1166–1178`, `libs/liboqs/src/stages_mldsa.c:31–58`; `libs/openssl/src/pqc_stages.c:340–351`, `libs/openssl/src/pqc_stages.c:993`, `libs/openssl/src/pqc_memory.c:69`, `libs/openssl/src/pqc_memory.c:100–106`.

Both stage implementations allocate large workspaces and caches before measuring. liboqs retains both a working and a cached matrix, plus polynomial vectors; OpenSSL retains multiple matrix/vector representations. These bytes do not appear in the measured incremental allocation counts or stage stack. OpenSSL's hooks count only `OPENSSL_malloc` traffic: the low-level FORS variant allocates `fors_task_t` with ordinary `calloc()` during the operation, which remains invisible to those hooks. The emitted heap-method string does disclose the OpenSSL-only scope, but the values are not interchangeable with liboqs's wider allocator accounting.

**Consequence:** A lower stage stack, especially liboqs `total_best`, is partly a transfer into persistent heap storage. It is not evidence of a smaller total working set. Direct comparisons of the two `heap_peak_bytes` fields can also compare different allocation scopes.

**Fix:** Report retained per-key bytes, retained per-worker workspace bytes, incremental allocated bytes, and peak live temporary bytes separately. Count ordinary driver allocations as well as OpenSSL allocations, or visibly separate provider and driver memory. Measure cold construction and warm operations independently. Use the same scope when comparing providers.

**Status:** Proven accounting boundary; not a claim that the documented OpenSSL-only counter is incorrectly implemented for its stated scope.

### C6 — P2: liboqs heap measurement includes thread machinery and first-use calibration

**Source:** `libs/liboqs/src/bench.c:859–883`, `libs/liboqs/src/bench.c:1153–1155`, `libs/liboqs/src/bench.c:1170–1178`, `libs/liboqs/src/memhook.c:22–33`.

Heap counting is enabled before `painted_run()`. That function creates and joins the measuring pthread; its first call also executes three empty-thread calibration runs. Allocation/free traffic from this scaffolding is included in the same counters as the cryptographic operation. The warm-up preceding measurement runs on the main thread rather than the newly created measuring thread. The interposer also subtracts frees without tracking whether the allocation was made after the reset, clipping its live counter at zero.

**Consequence:** Some recorded heap activity and peaks belong to startup/calibration or pre-existing allocations rather than the operation. For example, the committed SLH rows commonly report 280 bytes despite the underlying portable slhdsa-c operation requiring no heap of its own; treating that as an algorithm allocation is unsupported. The first reported measurement is especially incomparable because of calibration.

**Fix:** Calibrate before enabling allocation counters. Warm the operation inside the measuring thread, then reset counters immediately around the operation. Track a consistent allocation lifetime model or use a baseline of total live bytes rather than clipping unrelated frees.

**Status:** Proven scope error; exact attribution of every historical byte was not reproduced.

### C7 — P2: build caches do not reliably identify the source or patch being measured

**Source:** `libs/liboqs/run.sh:71–79`, `libs/liboqs/run.sh:120–123`, `libs/openssl/run.sh:40–54`, `libs/openssl/run.sh:62–79`.

liboqs considers its patched source current whenever `slh_fasthash.c` exists, and its build sentinel does not incorporate the patch digest, dependency commit, or relevant headers. OpenSSL accepts any existing `Configure` source checkout and any installed `libcrypto.a`; changing `OPENSSL_TAG`, compiler, or build options need not replace either. An idempotent rerun can therefore leave old code in place after the input configuration changes.

**Consequence:** A new experiment can silently reuse an old binary/source tree, undermining optimization comparisons and version claims. The current audit's clean upstream clones do not prove which tree was used to produce the committed historical results.

**Fix:** Cache using a manifest of resolved commit, patch digest, compiler identity, flags, and driver/header inputs. Verify it before reuse, and record the manifest digest in results. Resolve tags to immutable commits. Rebuild affected targets when the manifest changes.

**Status:** Proven cache invalidation gap, not proof the current committed results used wrong code.

### C8 — P2: fresh OpenSSL result runs append to old output files

**Source:** `libs/openssl/run.sh:110–131`, `libs/openssl/run.sh:133–153`, `libs/openssl/src/pqc_stages.c:1405`, `libs/openssl/src/pqc_memory.c:175`; the operation driver also opens its benchmark output in append mode.

Appending is needed to combine the three flavours, but the wrapper never truncates the requested output once at the start of `bench`, `stages`, or `memory`. Running the same command twice appends a second experiment to the first with identical identities and no run boundary.

**Consequence:** Downstream consumers may silently overwrite one duplicate, average incompatible runs, or select arbitrary data. A repeat run is not guaranteed to replace the requested artifact.

**Fix:** Write each invocation to a fresh temporary artifact, append only the flavours of that invocation, and atomically replace the destination after checks. If intentional accumulation is supported, require a distinct run identifier and explicit append mode.

**Status:** Proven by source; committed-file duplication was not asserted.

### C9 — P2: the fasthash patch has unsynchronized first-use backend selection

**Source:** `libs/liboqs/patches/slh-fasthash.patch:104–119`.

The new Keccak wrapper uses a process-global mutable `use_avx2` initialized lazily without an atomic or one-time initialization primitive. Concurrent first calls can read/write it without synchronization. The current fasthash benchmark variants are single-threaded and normally warm up first, so the stored measurements do not demonstrate a failure.

**Consequence:** The patch is not ready to be treated as a generally thread-safe drop-in hash backend for production use.

**Fix:** Resolve backend selection once under `pthread_once`/the library's initialization facility, or use an existing thread-safe dispatch mechanism. Test cold concurrent initialization and portable fallback separately.

**Status:** Static concurrency finding; not runtime-reproduced.

## Upstream correspondence and mathematical review

The liboqs ML-DSA stages call the exact pinned mldsa-native polynomial, sampling, packing, and hashing routines. The sequence was compared with [the pinned upstream verifier](https://github.com/open-quantum-safe/liboqs/blob/5a1a854b0dc9f2141bdc771c555ee60c37950183/src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/sign.c#L1087). Its challenge generation, `A·NTT(z) − NTT(c)·NTT(t1·2^d)`, reduction before inverse NTT, UseHint, and challenge comparison correspond. The stage version delays the norm check until `hint_check`, whereas upstream rejects excessive z before matrix work. That preserves the positive-input computation but increases work before rejecting some malformed signatures. The harness reconstructs backend coefficient order by applying the library permutation to `0..255`; this is a sensible way to avoid hardcoding a second NTT lane table. Full-key comparisons invalidate the three public-key caches; no message-dependent verification result is intentionally cached.

The liboqs SLH stage code includes the pinned upstream `slh_dsa.c` with renamed exported entry points. The FORS call, WOTS recovery, tree/leaf updates, domain-separated address types, auth-node ordering, and final root comparison align with its upstream helpers on inspection. The duplicated total walk in C1 is an assembly/timing error, not evidence of an incorrect hash-tree formula.

The fasthash patch changes the three compression/permutation implementations, not SLH's address or tree logic. SHA-256/512 chaining words are converted between slhdsa-c's big-endian representation and OpenSSL's host-word context. The AVX2 lane map exactly matches the pinned upstream `mapState` table in `src/common/sha3/xkcp_low/KeccakP-1600/avx2/KeccakP-1600-AVX2.S:1091`. The portable fallbacks remain. This is positive source evidence for representation correctness; it is not a new differential test of every hash state or CPU path. OpenSSL's linked version for this patch is the ambient `-lcrypto` dependency and is not independently pinned by `libs/liboqs/run.sh`.

OpenSSL's default stages include the pinned `ml_dsa_encoders.c` and call its polynomial/hash helpers; the comparison reference is [OpenSSL's pinned verifier](https://github.com/openssl/openssl/blob/45e844fa2a14ec92d146bd8f5778ac130b6625fb/crypto/ml_dsa/ml_dsa_sign.c#L207). The custom decoder retains signature-length, hint-count, strictly increasing hint indices, and zero-padding checks. Its raw `memcpy`-to-integer unpacking assumes little-endian input interpretation, consistent with the supplied x86 build but not a generic architecture-independent decoder. The custom NTT uses signed Montgomery arithmetic, lazy butterflies, one 64-bit product accumulation, and a final canonical reduction. The arithmetic pattern is plausible and committed canonical outputs match, but a bound proof for every intermediate, adversarial-input differential testing, and sanitizer coverage remain prerequisites to promoting that replacement. No integer-overflow defect was established by this review.

The OpenSSL SLH low-level alternatives preserve separate F versus H/T hash choices, compressed versus full addresses, WOTS checksum digits, and MGF1 counter encoding. SHA2 midstates cover the complete `PK.seed || zero padding` block; cloning that state is legitimate when the public seed and parameter set are fixed. Its total pipeline already walks each hypertree layer sequentially without precomputing future layer messages, which is the structure liboqs should adopt.

## Validation and interpretation of measurements

The committed liboqs files contain 306 benchmark rows with `match:true` and 4,680 validation rows with `pass:true`. OpenSSL has 246 benchmark rows with `match:true` and 12,363 passing validation rows. These are historical assertions emitted by the harnesses, not independent fresh validation from this audit. Neither the shared validation corpus nor those results test context lengths above 255. liboqs runs only its total and selected total_best stage pipelines through validation, so its isolated portable-backend, OpenSSL-hash, and one-way-expansion stage alternatives do not receive the same negative-case pipeline coverage. The OpenSSL substitution issues are described in C3.

Both operation loops use monotonic wall clocks, process CPU time, untimed warm-up, a budget plus a minimum iteration count, and output checks before/after measurement. The threaded operation variants measure batch throughput; their wall-per-operation numbers must not be interpreted as one request's latency. OpenSSL additionally changes the threaded worker's implementation from baseline to reused contexts, whereas liboqs uses the baseline API path. Comparing v5 to v0 mixes context reuse and parallelism for OpenSSL; compare it with v1 as well. Neither provider validates every generated byte inside every timed iteration: OpenSSL's comment/README claiming every-op byte comparison is stronger than the loop implementation, which compares initial and final output and checks return codes during the loop.

The ordinary OpenSSL API benchmarks use imported/decoded key objects prepared outside timing, while liboqs APIs consume encoded key buffers. The contract permits inputs prepared outside timing, but cross-provider differences therefore include key representation and cache lifetime. Stage `mu.v0` deliberately rehashes the encoded public key to satisfy the canonical decomposition even though OpenSSL's imported `ML_DSA_KEY` already retains `tr`. A speedup of cached-tr over that stage baseline does not imply the same saving over OpenSSL `verify.v0`. The committed external-mu whole-verify variant is only about 1.009× over v0 across ML-DSA, consistent with this distinction.

liboqs total_best is a warm per-key cached verifier; OpenSSL total_best deliberately excludes caches and threads. Their speedups answer different questions. Report stateless verification, cold per-key setup, warm verification, and batch throughput as distinct workloads. Current one-message/one-key deterministic signing also fixes the ML-DSA rejection-sampling trajectory; meaningful signing comparisons need a corpus of keys/messages and reported dispersion, while preserving deterministic reference outputs.

## Efficiency opportunities supported by this repository

The following numbers are geometric means recomputed from committed per-parameter median ratios. They are descriptive evidence from these artifacts, not hardware-independent guarantees or fresh controlled experiments.

| Mechanism | Recorded observation | Interpretation |
|---|---|---|
| liboqs direct internal API | ML-DSA signing 0.947×, verifying 1.000× v0 | Dispatcher/RNG bypass is not a demonstrated major optimization. |
| liboqs native/PGO for ML-DSA | Signing roughly 1.00–1.01×; verify build variants roughly 1.01–1.02× | Much of this workload is already optimized assembly; generic flags are low priority. |
| liboqs fasthash | SHA2 sign 1.320×, verify 1.452×; SHAKE sign 1.133×, verify 1.448× | Hash backend replacement is materially more promising for SLH than dispatcher changes, but benefits vary by parameter and need controlled confirmation. |
| OpenSSL context reuse | ML sign 1.008×, verify 1.007×; SLH results near or below 1× | Reusing EVP contexts is sensible engineering but not the main cost in this workload. |
| OpenSSL no-asm | SHA2 sign 0.621×, verify 0.635× | Preserve hardware hash implementations. Removing assembly is a control, not an optimization. |
| OpenSSL stateless total_best | ML-DSA 44/65/87: 134.835→81.910, 205.013→130.017, 321.178→210.726 microseconds | Custom arithmetic and stage fusion have a materially larger signal than ordinary API tuning; these are custom driver paths requiring more validation. |
| OpenSSL SLH low-level total_best | SHA2-128f 2.680→1.329 ms; SHAKE-128f 2.941→2.777 ms | SHA2 midstate/context overhead reduction is especially promising; do not transfer its gain to SHAKE without measurement. |
| Four-worker signing | liboqs ML/SHA2/SHAKE 2.02×/3.04×/2.58×; OpenSSL 1.97×/3.43×/3.01× | Useful throughput evidence, with higher CPU demand and no implication of equivalent single-request latency reduction. |

Prioritized next experiments:

1. **Repair SLH total assembly and measurement integrity first.** Remove the duplicate hypertree pass, rerun canonical stage outputs and the negative suite, then collect isolated total timings. Require exact final root comparison and proper message/root propagation at every layer. Repair validation labels, build manifests, and output-file handling before claiming new wins.
2. **Measure realistic per-key reuse for ML-DSA.** Compare uncached, cold-cache, and warm-cache paths over varying key-reuse counts. Cache only key-dependent data: `tr`, expanded A, and transformed public t1 for verification. Publish cache bytes and key-setup time; key identity must include the parameter set and complete encoded key. Report the break-even reuse count, not just the warm endpoint. liboqs's stored total-to-cached ratios are approximately 2.17×/2.90×/3.11× for 44/65/87, but its memory accounting must include retained state.
3. **Profile key-dependent signing setup before adding a signing cache.** Candidate reusable data are A and expanded/transformed secret polynomials, with a distinct per-key object and per-operation scratch. Never reuse message-dependent `mu`, signing randomness/seed derivation, y, rejection outcomes, or one-time ephemeral material across messages. Retained secret material needs explicit lifetime/zeroization and concurrency ownership. This opportunity is not implemented or measured by the existing direct-call variants.
4. **Pursue SLH hash-state reuse and batched chains.** Reuse SHA2 public-seed midstates and reduce EVP allocation/dispatch where the configured provider/security boundary permits. Batch independent FORS trees or WOTS chains within the current layer using SIMD/multi-buffer hashing; retain exact address domain separation and chain start/end indices. Layers themselves remain dependent during a real verification. Benchmark one-thread SIMD separately from four-thread throughput. Do not label a custom low-level path as the same validated OpenSSL provider path.
5. **Evaluate ML-DSA arithmetic/vector backends instead of relying on compiler flags.** liboqs already supplies vectorized polynomial and four-way SHAKE paths. For OpenSSL, compare supported backend/provider choices or a carefully isolated multi-buffer ExpandA implementation before maintaining a broad handwritten crypto fork. Prove signed intermediate bounds and run differential tests against the exact pinned upstream for custom NTT/reduction changes; preserve rejection sampling, norm bounds, hint canonicality, and challenge comparison. Consider rejecting excessive z before expensive matrix work in custom verification pipelines, while retaining canonical stage definitions for instrumentation.
6. **Improve experimental design.** Use a seeded corpus with multiple keys/messages and realistic message lengths, randomized variant order, several isolated process repetitions, explicit CPU feature/compiler provenance, and separate cold/warm measurements. Report wall latency and CPU/op together. Keep deterministic conformance checks, but do not use a single fixed rejection-sampling path to characterize signing distributions.

The strongest existing leads are SLH hash backend/midstate improvements, ML-DSA reusable public-key work, and optimized polynomial/SHAKE backends. The clearest immediate fix is removing duplicated SLH work from the liboqs totals. API dispatch bypass, context duplication, and generic build flags have much weaker evidence here.
