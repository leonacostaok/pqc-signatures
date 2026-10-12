# Performance comparison handoff

Branch: `docs/performance-comparison`, based on resource audit `929d442`. Publication targets existing evidence [PR2](https://github.com/leonacostaok/pqc-signatures/pull/2), branch `perf/provider-improvements`, by fast-forward push. Canonical main is untouched.

Integrated `fe38ea7` (prior Bouncy Castle evidence), `4d31601` (Rust/BC completion), `5dce831` (C completion), `166d624` (noble completion), and `6362517` (CIRCL completion). All ten measurement batches finished serially; coordination and execution timestamps are retained. No production cryptographic code changed in this completion task.

The generated table covers 309 action cells: 117 earlier paired comparisons, 174 newly filled baseline-only cells, and 18 unsupported Falcon cells in the selected OpenSSL/CIRCL/Rust implementations. New resource tables expose 1,899 paired metric observations and 341 baseline-only observations; unavailable values remain explicit. Baseline-only timings use separate declared protocols, not candidate gains or a cross-language ranking.

Root verification passed: Rust/BC raw checks, both C portable checks and four malformed/missing-evidence tests, both JS/Go portable checks and full summary recomputation, integrated coverage/percentage/hash/chronology checks, and 358 local links across 22 Markdown files. The saved evidence and reproduction commands are linked from the README. One command regenerates aggregate reports: `bash common/update-completion-reports.sh`.

Recommendations and limitations are in `docs/performance-summary.md`. liboqs and seed-based Rust construction are favorable; OpenSSL/CIRCL/noble remain workload-dependent. Bouncy Castle allocation reductions retain latency/RSS regressions. Exact consumed stack, exact intra-operation managed-heap peaks, and Node total allocation/GC CPU are not established. C unchanged-path baseline probes measure timing only. AI-assisted supporting testing is disclosed without claiming an independent cryptographic audit.

Published report commit `b53bd66` to PR2 by fast-forward push and updated its title/body with concise findings and evidence links. The PR is open, not merged. All requested measurement/report work within the stated feasible scope is complete; no background measurements remain.
