# Signature measurement completion implementation plan

> **For agentic workers:** Continue the authorized provider subagents in their isolated worktrees; the root coordinates exclusive measurement windows and integration.

**Goal:** Fill feasible missing baseline and resource measurements, express measured changes as percentages, publish concise recommendations and an accurate AI-assisted testing disclosure.

**Architecture:** Preserve all sealed prior evidence. New provider-specific probes produce raw observations, source/build/runtime identities, correctness outcomes, and compact summaries. The root integrates these into the complete comparison and a short README, without combining distinct patches or incompatible protocols.

**Tech stack:** Existing C/OpenSSL, Go, Node, Rust, and JVM source-bound runners; Python report generation; macOS process accounting.

**Spec:** User request of 2026-10-12: run missing indicators, include memory, explain percentages and whether tradeoffs are worthwhile, and disclose supportive AI-driven testing.

## Global constraints

- Each provider works in its own new worktree. Existing source and measurement snapshots remain intact.
- No production cryptographic edits or upstream PR changes are required for this measurement task.
- Measured jobs run serially after coordinated builds/checks stop. Preparation may run in parallel.
- Record whether a row is an unchanged baseline, a paired patch comparison, unsupported, or unavailable, with a reason.
- Do not infer operation heap/stack peaks from process RSS, post-GC snapshots, allocated bytes, or individual function frames.
- Percent time saved is `100 * (1 - candidate / baseline)`; percent resource change is `100 * (candidate / baseline - 1)`. A zero baseline produces an undefined percentage with an absolute change instead.
- Colors describe observed direction only; verdicts use repeated evidence, tradeoff scope, and retained losses.
- The latest explicit user request authorizes an AI-assisted testing disclosure in this repository. No co-author trailers or claims of human/security certification.

## Review focus

- Incorrect build or unchanged candidate masquerading as an optimization: verify exact source/build identities and expected differences.
- Cheap verification after invalid setup: require valid output checks and tamper rejection outside declared timing boundaries.
- Overlapping runs or background builds: coordinate exclusive windows and preserve run chronology.
- Missing or incomparable metrics misreported as zero/savings: explicit units, null reasons, and scope in every summary.
- Runtime/GC noise or warmup effects promoted as universal gains: retain all samples, orders, and protocol limitations.

## Tasks

- [x] Inspect worktrees, prior reports, coverage table, and harness contract.
- [x] Delegate C, JS/Go, Rust/Java bounded preparation using existing authorized agents.
- [x] C: baseline ML-DSA/SHAKE/Falcon where supported; full-operation allocator/RSS diagnostics for affected paths; source-bound summary and local-frame percent changes.
- [x] JS/Go: fill supported missing baseline types; normal/constrained GC diagnostics and process/runtime memory; scoped stack-limit evidence if feasible.
- [x] Rust/Java: fill Rust SLH and BC missing baseline types; Rust process memory and safe stack evidence; separate JVM diagnostics for distinct BC candidates.
- [x] Accept each prepared protocol and grant serial collection windows; retain all commands/statuses/hashes and failures.
- [x] Independently recompute percentages, check source identities/raw links/completion counts, and review metric boundaries.
- [x] Integrate provider commits and update complete table/CSV without replacing historical observations.
- [x] Rewrite README and concise findings with AI disclosure, percentage costs, conditional worth-it decisions, and remaining measured/unsupported/unavailable coverage.
- [x] Run final report/link/coverage checks, commit with the user's signoff, publish to the existing evidence PR, and report completion and exact residual limitations.
