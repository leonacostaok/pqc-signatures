# RustCrypto and BouncyCastle audit at 80c832da

This is the historical snapshot report. See the [current-main addendum](current-main-status.md) for unchanged harness defects, the fixed Falcon adapter, and updated saved Rust/Java results at `45076e0`.

The implementations contain substantial, testable optimization work. The main confirmed defects in this review concern measurement boundaries, validation identity, build freshness, and interoperability, rather than a demonstrated ML-DSA or SLH-DSA forgery. The committed results are development runs and must not be read as final performance rankings. No existing result or production source was changed and no full benchmark was run.

## Evidence and scope

Read `common/CONTRACT.md`, both harnesses, the custom stage math/hash code, vendor changes, and the documentation. Fresh evidence is saved in [rust-java-checks.json](evidence/rust-java-checks.json), with the bounded Java checker source in [RustJavaAuditCheck.java.txt](evidence/RustJavaAuditCheck.java.txt). It was compiled as `AuditCheck.java` in the ignored library build directory. Commands and limitations are in the evidence file.

Downloaded exact published Rust crates [ml-dsa 0.1.1](https://static.crates.io/crates/ml-dsa/ml-dsa-0.1.1.crate), [slh-dsa 0.2.0-rc.5](https://static.crates.io/crates/slh-dsa/slh-dsa-0.2.0-rc.5.crate), and [BouncyCastle 1.86 source](https://repo.maven.apache.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86-sources.jar), plus its `bcprov` and `bcutil` jars from Maven Central. Locally computed SHA-256 hashes and the source-file diff inventory are in the evidence file; a follow-up published-checksum request failed with an SSL EOF, so independent checksum matching is not claimed. These comparisons concern the pinned releases, not an assertion that they are the newest releases.

Both Rust source trees match upstream after removing visibility, `doc(hidden)`, and lint-attribute differences. No changed algorithm statement or constant was found. BouncyCastle ML-DSA sources match after package renaming except public visibility on `PolyVec`/`PolyVecMatrix` and the added matrix `row` accessor. Its SLH-DSA sources match after package renaming except public engine methods, keeping the full H_msg digest in `IndexedDigest`, and removing the engine's upstream top-level static keygen/sign/verify wrappers. `Keccak`, `MlStages`, `SlhStages`, `FastHash`, and `AltEngines` are custom code, not upstream implementations. Removing unused upstream wrappers does not itself change the called primitives.

Java compiled on HotSpot 22.0.1 with `--release 21`. A fresh bounded run substituted each composable non-JVM-flag stage alternative individually into the v0 verification pipeline, against all 387 supplied sigver cases: **5,328 checks, zero failures**. This covers 99 ML-DSA and 288 SLH-DSA cases, including contexts and malformed inputs. It is stronger than checking one reference digest but does not exhaust joint compositions, independent fuzz inputs, keygen/sign, JVM flag variants, or side channels. The existing Java validation file reports 4,680 passes; those historical results were inspected, not freshly rerun in full.

The unmodified Rust harness build was attempted with `cargo build --locked --release` on macOS/rustc 1.93.0. Both vendor crates compiled, but `src/memory.rs:40` failed because this target's `libc` does not expose `pthread_attr_setstack`. Thus no fresh Rust harness correctness, AVX2, or timing claim is made. The published Linux results used a different compiler/runtime. The compile failure is a portability limitation, not evidence of a Rust cryptographic failure.

## Confirmed findings

### RJ-1 — P1: validation can exercise a different Java total_best pipeline from the measured one

**Location:** `libs/bouncycastle/src/Stages.java:392-411`; `libs/bouncycastle/run.sh:59-62`; `libs/bouncycastle/src/Validate.java:107-110`.

`stages --out <arbitrary-file>` chooses and writes a per-parameter composition from the measured alternatives. `validate` and `memory` independently load `results/bouncycastle/stages.jsonl` relative to the caller's current directory and silently select defaults when absent or unreadable. The entry point resolves the shared inputs absolutely but does not resolve or pass the result path. Running the same entry point from outside the repository root therefore validates the default composition, even if `common/run-all.sh` has just produced fresh stage output at its absolute repository path. A standalone stages output path has the same problem. The fresh composition probe in the evidence file demonstrates different selections from the repository root and the library directory.

**Consequence:** a successful `total_best` validation is not necessarily validation of the measured implementation. Results also omit the composition from the validation rows, making this mismatch invisible in those rows. The root-relative orchestration order itself is correct: stages precede validation.

**Fix:** pass the exact fresh stage artifact or an immutable composition manifest explicitly to validation and memory; record its digest, build identity, and per-parameter composition. Fail when a requested manifest is missing instead of silently substituting defaults.

### RJ-2 — P1: validation failures and Java child failures are not process failures

**Location:** `libs/bouncycastle/src/Validate.java:78-83,138-140`; `libs/rustcrypto/src/validate.rs:253-259,269-280`. Equivalent Java child-status handling exists in `Bench.java:239-246`, `Stages.java:533-539`, and `Memory.java:266-272`.

Java prints failed validation counts, writes the report, and exits successfully. A fresh one-case fixture with deliberately inverted expected verification produced `pass=0, fail=1` and **exit code 0**. Rust validation and merge likewise only report counters. Java child runners merely log a nonzero exit and return the rows received so far; a killed/OOM/unsupported-flag child can leave an absent or partial variant rather than an explicit failed result.

**Consequence:** shell success does not establish validation success or coverage. This is particularly important for Epsilon-GC children and automation that relies on `set -e`. The top-level checker must independently reject omissions, and its failure must itself stop the run.

**Fix:** nonzero exit after saving a report with failures; propagate child nonzero exits; compare the received case/variant IDs to the required manifest, rejecting duplicates and omissions. Do not count a crashed child as skipped or unsupported.

### RJ-3 — P2: Java aggregate CPU/throughput includes substantial validation work

**Location:** `libs/bouncycastle/src/Timing.java:48-63`; `libs/bouncycastle/src/Stages.java:459-462`; `libs/bouncycastle/src/Bench.java:301-325`.

Per-op wall samples stop immediately after the operation, but each measured iteration then runs `check.ok` before the loop-wide wall and process CPU timers stop. Stage checking serializes the canonical output, SHA-256 hashes it, formats hex, and compares it; full-process checks compare/encode outputs. Rust checks its final measured output after the timing loop. Consequently cross-library CPU/op and throughput have different measurement boundaries. Java's own wall median and aggregate throughput measure different workloads.

**Evidence:** the development ML-DSA-44 `expandA.v1` row has 51 ns mean operation wall but approximately 88,138 ns elapsed per reported operation (`1e9/ops_per_sec`) and 61,511 ns CPU/op. Noise/JIT may affect the amounts; the code establishes that canonicalization and checking are included. The magnitude is not a fresh speed claim.

**Fix:** retain correctness checks but put them outside all reported timing/CPU intervals, or explicitly separate crypto-only and checked-driver metrics consistently across libraries. A bounded output buffer plus validation after each measured block can retain checked outputs without hashing a matrix on every timed-loop iteration.

### RJ-4 — P2: stage boundaries do not measure the same canonical work

**Location:** `libs/bouncycastle/src/Stages.java:140-143,222-225`; `libs/rustcrypto/src/stages.rs:254-261,312`; `libs/rustcrypto/src/stages_mldsa.rs:110-123,606-609`.

Java SLH-DSA `hmsg` consumes an already parsed signature from its context; the contract assigns signature parsing to `hmsg`. Rust `hmsg.v0` parses the signature inside the operation. Java therefore omits parsing cost from every isolated SLH-DSA stage, although its end-to-end pipeline does parse it.

Rust ML-DSA `decode` performs `Decoded::full_bytes()` inside the timed closure, allocating and serializing rho, all t1/z coefficients, and hint bits. This is validation representation overhead, not decoding. Its memory closure constructs **both** the new and reference serializations inside the measurement. Rust also performs the z norm check in decode and again in hint_check, whereas the contract assigns it to hint_check and Java decode does not do it.

**Consequence:** cross-library stage rankings and the interpretation of stage memory are biased even when canonical digests agree. Canonical equality cannot establish equal measurement boundaries.

**Fix:** return a decoded structure and compare/serialize it after all timing and memory counters stop; include signature parsing in Java hmsg; assign the norm check once to a documented common stage, keeping early rejection in production verification as a separately identified option.

### RJ-5 — P2: Rust freshness logic misses vendor code and can preserve stale PGO binaries

**Location:** `libs/rustcrypto/run.sh:37-57,74`.

The shell freshness test includes only the top-level manifest/lock/build script and `src/*.rs`; neither vendor tree is included. `ensure_built` can therefore run old binaries after an algorithm or visibility edit in a vendor crate. Even an explicit `build` rebuilds the ordinary configurations through Cargo but can skip all PGO rebuilds when their timestamps pass this incomplete check. PGO fallback also labels native+LTO binaries as the `pgo-*` variants when no profile tool is available.

**Consequence:** a run can mix different source revisions and attribute a speed difference to PGO even when no profile was used. This is a source-level defect; no existing cached binary was altered to reproduce it.

**Fix:** delegate freshness to Cargo with `--locked`; key PGO profiles/artifacts on the complete source, lockfile, toolchain, flags, target features, and training corpus. Emit `pgo_applied`, profile hash, and actual flags, and report unsupported/skipped rather than silently substituting the same optimization under a different name. The GNU `stat -c` dependency is an additional macOS entry-point limitation.

### RJ-6 — P2: parallel Java total_best stack measures the coordinator, not the workers

**Location:** `libs/bouncycastle/src/Memory.java:81-91,150-162,203-207`; `libs/bouncycastle/src/Stages.java:353-370`.

The total_best memory path passes the entire verification closure into one stack-constrained probe thread. If the selected composition contains parallel FORS or WOTS-chain work, that closure dispatches to `Stages.POOL`; worker stacks are unconstrained and unmeasured. The row nevertheless reports multiple threads. Ordinary process parallel variants correctly probe one lane (`Memory.java:139-147`), but the composed-stage path does not use that treatment.

**Consequence:** those stack rows are coordinator-stack estimates, not the contract's per-worker stack requirement. They cannot support a per-thread deployment stack budget.

**Fix:** measure coordinator and each distinct worker operation separately, report the maximum worker requirement and the thread count, and identify retained executor state. Also check the result of the actual stack/heap probe rather than relying only on prior warm-up checks; `probe` currently considers any nonthrowing return successful.

### RJ-7 — P2: Falcon cross-library failures are a padded/unpadded API mismatch

**Location:** `libs/bouncycastle/src/Alg.java:190-193`; `libs/bouncycastle/src/Bench.java:81`; `libs/noble/src/algs.mjs:25,43`; `libs/noble/src/crossverify.mjs:19-24`.

BouncyCastle intentionally pads its compressed detached signatures to 666/1280 bytes. Noble selects `falcon512`/`falcon1024`, whose unpadded decoder rejects those trailing bytes. Fresh deterministic-seeded artifacts reproduced both failures: 666 bytes with 653-byte compressed content for Falcon-512; 1280 with 1273 for Falcon-1024. Both verify with the pinned Noble padded APIs, and both verify with its ordinary APIs after removing only the padding. BouncyCastle self-verification passed.

**Consequence:** the stored two crossverify failures do not demonstrate bad signature math; they demonstrate an unspecified wire-format adapter boundary. They still must be resolved before claiming complete interoperability.

**Fix:** define the artifact Falcon encoding, select the corresponding strict padded/unpadded verifier, and test both formats separately. Avoid broad normalization as a substitute for strict parsing: the BC wrapper additionally removes a public-key header based only on length (`Alg.java:170-173`) and accepts arbitrary amounts of trailing zero padding (`181-185`). Validate parameter/header and permitted format lengths explicitly.

## Correctness and security assessment

The ML-DSA stage paths preserve public-key/signature exact lengths, increasing hint indices, cumulative hint limits, zero hint-tail bytes, z-norm rejection, pure/context domain separation, and final challenge comparison. The reviewed Montgomery constants use q=8,380,417, q-inverse 58,728,449 modulo 2^32, and inverse-NTT factor 41,978; transform scaling is reversed by the inverse NTT and outputs are normalized before canonical serialization. Lazy accumulators are real arithmetic changes, not aliases: Rust sums the row products in u64, and Java performs one Montgomery reduction on a signed-long accumulator for the combined row. With at most seven products of canonical values, the Rust u64 sum is below 2^49. Broader NTT intermediate bounds and adversarial differential tests should be retained before moving either rewrite into secret-dependent signing.

The SLH-DSA pipelines use separate address types for FORS tree/roots, WOTS hash/public-key compression, and XMSS authentication, preserve layer/tree/leaf indices, include the pure/context prefix, and compare the final root. SHA2 uses the 22-byte compressed address and correct SHA-256 versus SHA-512 distinction. The fresh Java suite found no violation among its tested substitutions. Both implementations correctly avoid composing independently parallelized hypertree layers into a real verify: each next layer's WOTS input depends on the preceding root. Rust's total_best uses four-way work within each layer, while Java explicitly marks layer parallelism noncomposable.

The custom variable-time decomposition/hint logic is used in verification on public values. This is not, by itself, a secret-key timing finding. Do not copy it into signing without a separate constant-time and rejection-loop review. Rust's imported expanded secret-key API is explicitly deprecated and documented upstream as not validating malformed expanded keys; the harness checks size but does not upgrade that guarantee. This audit does not establish safe handling of attacker-supplied signing keys.

Canonical digest checks are necessary but limited: Java decode compares only c-tilde, so a t1/z/h decoder defect can leave that isolated stage's `match` true. The fresh full-pipeline substitution test addresses the supplied cases, but the permanent suite should validate all composable alternatives this way, plus differential intermediate-state tests. Rust checks richer decoded equality, albeit inside the wrong measurement boundary. A self-test or a single reference signature is not a proof of arbitrary-input correctness.

## Optimization priorities and experiments

| Priority | Work | Concrete reason | Required comparison and invariants |
|---|---|---|---|
| 1 | Reuse Rust ML-DSA expanded signing and verifying objects in real repeated-key workloads | Already implemented by sign.v4/verify.v4. Upstream `ExpandedSigningKey::new` caches A and NTT(s1,s2,t0); `VerifyingKey` caches A, NTT(t1·2^d), tr. This removes defined work, not merely compiler noise. | Separate import/setup time, retained bytes, and steady-state operation cost; use many keys, messages, and contexts, with eviction and concurrency tests. Preserve exact deterministic signatures and all malformed-signature rejection. |
| 2 | Prototype equivalent per-key ML-DSA precomputation in BC | Public signer reuse avoids init overhead but the engine still expands A and transforms secret vectors on each signature. The existing stage cache mechanisms demonstrate the verification-side building blocks. | Start with a reusable verify-key object; then a separate signing-key object with immutable secret precomputation and per-call scratch. Measure allocations and bounded retained memory; review secret zeroization/lifetime and forbid shared mutable digest state across workers. |
| 3 | Combine real Rust verification arithmetic and hash changes under controlled builds | Montgomery w_approx, word unpacking, raw hashing, and four-way Keccak are substantive. total_best currently hardcodes a composition and does not prove it is fastest for every architecture/parameter. | Differential/property tests over many public keys and signature shapes; baseline versus each change versus full composition; record runtime AVX2 availability and fallback. Validate the exact combined artifact and report latency separately from parallel throughput. |
| 4 | Reuse buffers and reduce digest clone churn in Java SLH-DSA verification | FastHash avoids node-output arrays but SHA2 still clones a MessageDigest for every F/H/T (`FastHash.java:57-81`). The documentation itself reports higher allocation in some fast pipelines. | Compare scalar BC, JDK digest backend, buffer-only rewrite, and combined rewrite under the same warmed JVM. A reset/reseed implementation must retain PK.seed padding, address compression and domain separation; clone removal is a hypothesis until measured. |
| 5 | Explore bounded SLH-DSA signing tree/hash reuse | Signing reconstructs FORS/XMSS trees. Merely importing a 64–128-byte key once cannot remove that work. Fixed top-layer data and per-key hash midstates are plausible reuse targets; tree/hash batching can reduce per-hash overhead. | Track key/parameter/layer/tree indices in caches and measure hit rates, construction cost, retained memory and break-even signatures. Do not skip PRF/message binding, alter deterministic entropy, reuse a WOTS key at a different address, or remove mandatory tree nodes. No new signing speedup was established in this audit. |
| 6 | Evaluate compiler/JVM tuning after fixing the measurement protocol | Native/LTO/PGO and C2/inlining/GC variants are real execution configurations, but their gains are workload and warm-up dependent. Epsilon is an allocation experiment, not a sustainable collector for an unbounded service. | Train PGO on varied keys/messages rather than the sole measured deterministic fixture; use disjoint evaluation inputs. Run JVM forks with equivalent warm-up and record compilation/GC state. Count all process CPU, but exclude correctness hashing from reported crypto work. |

Cross-library sign/verify baselines must be labeled by API lifecycle. Java builds `PrivateKey`/`PublicKey` or lightweight key objects outside the timed loop (`Variants.java:207-216` and the corresponding verify constructor); Rust v0 imports byte keys inside every operation (`schemes.rs:111-130`). Both are legitimate workloads, but v0/v0 is not a normalized byte-in comparison. Publish both stateless byte APIs and reused-key APIs, plus one-time setup and retained memory. Similarly, BC's cached-A stage returns a reference while Rust clones a matrix; that pair does not compare the same cache-access cost.

Do not derive production stack limits from the existing small Java estimates: the recursion-depth method is a JIT-dependent differential estimate, and taking the deepest successful probe gives the smallest observed requirement, not a worst-case bound. No fresh memory run was needed for the confirmed path-boundary findings. Rust's paint scan measures overwritten bytes, not all reserved stack space; its 16-byte field is a reporting granularity rather than proof of 16-byte accuracy. Report practical stack headroom separately from these experiments.

## Remaining limitations

No full benchmark, reranking, upstream security certification, exhaustive formal proof, Rust runtime validation, Java signing rewrite, or side-channel measurement was performed. The Java fresh tests reuse the supplied suite, so any suite-generation or oracle issue is outside their independence. Joint Java alternatives and AVX2 Rust paths need additional tests on their intended hardware. Existing results, especially partially overwritten development files, cannot settle final speedups. The strongest next work is to fix measurement/validation identity, then validate the exact built artifacts and run controlled repeated-key versus stateless comparisons.
