# Resource audit handoff

Branch: `audit/resource-regressions`, based on `81393c3`.

The five published patch revisions are recorded in `results/resource-regressions/pr-heads.json`. Provider audit commits are integrated on this branch; `docs/audit/published-resource-regressions.md` links all reports. Allocation, cleanup, source identity, retained timing losses, and measurement limits are documented. No production patches or upstream PRs were changed.

Integration recomputed noble/CIRCL raw summaries and checked Rust metric/drop equality, OpenSSL failure coverage, and liboqs hash outputs. Actual tradeoffs remain: CIRCL allocation traffic, OpenSSL context storage, liboqs local stack frames, and noble live-row/heap observations. Full peak-memory and concurrent memory-pressure measurements remain future work.

Bouncy Castle experiments remain in their separate worktrees and are not integrated here; their prior latency regressions prevent an unconditional speed claim. The provider-performance worktree's existing local correction is untouched.
