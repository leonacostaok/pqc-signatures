# pqc-signatures

Performance experiments for post-quantum signatures in noble (TypeScript/JavaScript), liboqs and OpenSSL (C), CIRCL (Go), RustCrypto (Rust), and Bouncy Castle (Java). The project measures key generation, signing, verification, and resource costs for ML-DSA, SLH-DSA, and supported Falcon implementations.

## Results

- **[Are the optimizations worth it?](docs/performance-summary.md)** Short verdicts with time and memory percentages.
- [Time and memory comparison](docs/audit/complete-performance-comparison.md): every library/parameter combination, with paired changes, baseline-only timings and explicit unsupported cases.
- [Memory and GC measurements](docs/audit/completed-resource-measurements.md): allocation, heap, process memory, GC and stack diagnostics with percentages.
- [Resource audit](docs/audit/published-resource-regressions.md): cleanup, local stack frames and the limits of each probe.
- [Production experiments](docs/provider-improvements.md): individual patches, source revisions, protocols and pull requests.
- [Bouncy Castle research](docs/bouncycastle/pattern-research.md): new arithmetic/coding candidates and a preliminary address-hoisting screen.
- [Bouncy Castle alternatives](docs/bouncycastle/alternative-comparison.md): separate NTT, matrix and WOTS experiments with fresh-key comparisons and additional native correctness tests.
- [Raw data](results/) and [measurement contract](common/CONTRACT.md): inputs, checks and reproduction details.

Compare each patch with its own baseline. The reports identify hardware, versions, API boundaries and measurement limitations; they do not establish a universally fastest library. Lower allocation does not necessarily mean lower peak memory or faster execution.

## AI-assisted testing disclosure

This is supporting research and testing work developed with AI assistance, including test harnesses, experiments, analysis and documentation. Source revisions, scripts, raw outputs and checks are retained for independent review and reproduction. AI-assisted results are not an independent cryptographic security audit or certification.

## Historical results

[The original cross-library run](RESULTS.md) is retained with its [harness audit](https://github.com/leonacostaok/pqc-signatures/pull/3). Its known measurement and validation limitations are separate from the later production-patch experiments; historical success counts must not be treated as a blanket correctness guarantee.

## Build and run

Use `libs/<library>/run.sh build` before running that library's original harness. Later production experiments have their own pinned builds and reproduction commands in the linked reports. Keep timing runs serial and preserve their source/runtime identities.

Regenerate the completed comparison from saved evidence with `bash common/update-completion-reports.sh`; this checks coverage, percentages, saved-evidence hashes and collection chronology without rerunning cryptography.
