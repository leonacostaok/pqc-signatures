# Library time comparison

Worktree: `worktrees/library-time-comparison`; branch: `docs/library-times`; based on `6a9e475`. This task adds an absolute-time view to existing ready PR2, preserving the previous benchmark evidence and upstream patches.

Completed: `common/report-library-times.py` generates `docs/library-times.md` and CSV/JSON evidence for six libraries, 17 exact signature parameter sets and keygen/sign/verify. Original and selected-patch views are separate; unsupported cells stay absent, baseline-only cells are marked, and losing patch results remain. All 612 cells, 102 numerical minima, source hashes, CSV values, local links, deterministic rendering and assertion-disable guards were checked. No new benchmark or cryptographic test ran.

These are descriptive cross-study observations, not a matched cross-provider ranking. Different fixtures, key representations, import/setup boundaries, warmup and statistics prevent a definitive fastest-library claim. The report states that limit prominently and links the underlying protocols. Newer Bouncy Castle NTT/WOTS measurements remain separate. AI-assisted testing disclosure stays in the evidence repository, not upstream commit messages or PR bodies.

Publish this report as a fast-forward update to `perf/provider-improvements` (PR2); do not merge. No pending measurement or background process remains. Keep Leon's DCO signoff and preserve canonical clones.
