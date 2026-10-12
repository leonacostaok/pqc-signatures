# Shared contract, evidence, and reporting audit

Audited commit: `80c832da6ce81ca8def12b319da9f4c19d589111`. Severity describes consequences for this experiment; a harness defect is not automatically a defect in its upstream cryptographic library. Existing result files were left unchanged. Reproduce the common-tool findings with `python3 docs/audit/reproduce-common.py`; the script runs copied tools against disposable fixtures.

This is the historical snapshot report. See the [current-main addendum](current-main-status.md) for unchanged defects and the later Falcon adapter/result updates at `45076e0`.

## Confirmed findings

### C1 — High: missing evidence passes the correctness gate

`common/check-match.mjs:17`, `:31`, `:42`, `:53`, and `:64` skip absent files. There is no expected library/parameter/variant/case coverage manifest. Validation at line 55 counts only literal `pass:false`, so missing `pass` is accepted. Memory is never read. Stage agreement at lines 74–77 treats a single participant as agreement and does not require all supported providers. A completely empty results directory exits zero and prints `Problems found: 0`; adding a failed memory row and a validation row with no verdict still exits zero. Evidence: `evidence/checker-reproduction.json`.

Require a declared coverage matrix, unique rows, strict schemas, explicit justified skips, all required artifacts, validation case membership, memory verdicts, and sufficient stage participants before success. Derive coverage from capabilities, not from whichever files happen to exist. A partial audit may report partial evidence but must not pass a final release gate.

### C2 — High: final-run failures still publish success

`common/run-final.sh:14` converts any failed step into a successful `echo`; lines 32–35 suppress checker failure, generate reports, and print `ALL DONE`. `common/run-all.sh:41` also suppresses checker failure. A fixture whose driver returns 23 for every operation completed build, bench, stages, memory, and validation attempts, generated reports, and exited zero. This can publish stale or incomplete measurements as a completed run.

Propagate failures, prevent dependent steps after failed builds, write output to temporary files, validate completion, atomically rename, and publish only after all gates pass. Keep diagnostic reports for failed runs explicitly labeled failed.

### C3 — High: final resumption can mix code, builds, and old evidence

`common/run-final.sh:12` considers a filename sufficient proof of completion; markers contain no source, dependency, flags, hardware, corpus, or output hashes. The script does not run `vectors` or `crossverify` at all. All six `artifacts.json` files are absent from the checkout because `.gitignore:8` ignores them. Consequently, running the checker on the committed snapshot performs zero baseline artifact comparisons while consuming old cross-verification files. The saved historical run is incomplete: RustCrypto has 108 benchmark rows over 14 parameters, compared with its expected full supported matrix; the log ends during the base-build sweep. Bouncy Castle's results in this snapshot are development evidence.

Use a run ID with a content-addressed manifest; invalidate affected markers when dependencies change. Include vectors and cross-verification in the final dependency graph, store their hashes, and archive a complete immutable bundle. Resume only when both marker metadata and output completeness match.

### C4 — High: reports assert evidence that their inputs do not establish

`common/report.mjs:53–55` unconditionally claims one quiet final run and correct outputs. It does not consume the checker verdict or a run manifest. Baseline tables at lines 58–61 and leaderboards at lines 68–69 do not filter failed rows; the single-threaded best table does. `common/report-phase2.mjs:100` selects minimum stack without checking `match`. A run with a known failure can therefore still produce optimistic ranking prose and tables.

Require a successful manifest, label provisional inputs explicitly, exclude incorrect rows everywhere, distinguish missing from unsupported, and expose the workload/cache class alongside each result. Do not merge provisional Rust/Java numbers into a final ranking.

### C5 — Medium: sums of stage minima are not a demonstrated performance bound

`common/report-phase2.mjs:70–87` selects stage minima across runtimes, cached and uncached variants, and differing measurement boundaries, then calls their sum a lower bound on a combined implementation. It does not require all stages to be present. Median sums are not the median of an actual dependent pipeline; cached work has setup costs, internal representations differ, and SLH-DSA's next-layer WOTS message depends on the preceding root. Fusion can also outperform separate stage measurements, so this is not a mathematical lower bound.

Call this an exploratory stage-cost estimate and enforce complete stages with comparable boundaries and cache policies. Demonstrate any claimed gain in one actual end-to-end implementation with setup and data conversion accounted for. Report independent-signature batching separately from single-request latency.

### C6 — Medium: the workload cannot establish generally fastest signing

`common/gen-vectors.mjs:19–33` supplies one key and one 64-byte message per parameter set; the contract requires deterministic signing of that same pair throughout timing. This is excellent for differential reproducibility but gives one fixed ML-DSA rejection-sampling path and one SLH-DSA hash-chain workload. It also favors indefinitely hot caches. The contract's minimum three samples, one-second windows, fixed variant order, and selection of the best observed result do not provide independent-run confidence intervals. PGO trained on the measured operation needs held-out keys/messages to establish generalization.

Retain these known-answer vectors as the correctness gate. Add deterministic but diverse held-out key/message/context corpora, cold-key and reused-key workloads, key-cardinality/cache-capacity sweeps, realistic message lengths, and repeated randomized-order runs. Report latency and throughput separately, confidence intervals across independent runs, CPU/op, persistent cache bytes, setup latency, and break-even reuse count. Differences of a few percent are hypotheses until replicated.

### C7 — Medium: the validation suite leaves important optimized-path boundaries untested

`common/gen-validation.mjs:72–106` mutates signature lengths but not public-key lengths, includes contexts up to 255 bytes but no oversized context, and does not exercise cache reuse while alternating keys, signatures, messages, and contexts. Its empty-message mutation tests rejection of an old signature, not successful signing and verification of an empty message. Falcon has no ACVP/negative-suite coverage here. Per-case testing cannot alone detect stale cache reuse in a persistent object. This matters because optimized internal entry points bypass upstream wrappers; the C-provider review found an oversized-context bug.

Add empty, truncated, extended, and malformed public keys; contexts of length 0, 1, 255, and 256; positive empty messages; z/hint boundary cases; changing-input sequences on the same optimized state; malformed Falcon encodings; and concurrency tests for the actual batch implementation. Fuzz decoders under sanitizers and differentially check all optimized paths against an untouched upstream baseline. Standard correctness vectors do not establish constant-time behavior or fault resistance of custom arithmetic/hash code.

## What the evidence does support

The gzip contains exactly 651 cases: 195 ACVP keygen, 69 ACVP siggen, 129 ACVP sigver, and 258 generated negative/positive-control cases. All 393 stored ACVP cases were compared field-by-field, including keys, messages, contexts, signatures, seeds, and expected results, with the official NIST ACVP-Server snapshot `975de31eb83d87039ec88934fdc47d8c312b892d`; no differences were found. Source-file SHA-256 hashes are saved in `evidence/acvp-comparison.json`. The generator should record this provenance in the suite itself.

The committed validation files contain 35,763 passing rows and zero explicit failures. That is saved evidence, not a fresh execution or proof that every row uses the advertised implementation. Provider reviews examine that distinction. The checker observes 93 stage/parameter keys with no differing stored canonical digests; coverage varies, and some keys are total rows. It reports two cross-verification failures: noble verifying Bouncy Castle Falcon-512 and Falcon-1024. Therefore the repository's own stored evidence is not fully passing.

Primary references: [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), and [the compared official ACVP snapshot](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files). These standards define the operations and validation boundaries; passing this local sample suite is not certification.
