# Bouncy Castle pattern research

Branch: `research/bc-patterns`, based on `fe4729d`; root owns this worktree. This continues the supporting evidence work in PR2 without modifying earlier source snapshots or production patches. Canonical main is untouched.

Three Astra xhigh agents independently investigated ML algebra, SLH traversal/hash work and JVM code shape. Findings are in `docs/bouncycastle/pattern-research.md`, with a detailed inverse-NTT proof note. These are ranked hypotheses and a bounded screen, not additional upstream-ready performance claims.

Completed: ADRS-hoisting prototype changes WotsPlus only. Twenty-four dirty-address transcript cases and 72 whole-operation checks per variant passed before 48 serial fresh-process measurements. Independent review reproduced 1,724 timing rows, 192 allocation rows, all source/class/runtime bindings and every summary field. Preliminary keygen time fell 4.18%/1.78% for SHA2/SHAKE-128f, allocation about 9.9%; signing allocation fell about 8% but latency is mixed. Unchanged verification controls and all losing pairs remain visible. Timed calls cycle four fixture values; imports are outside the clock.

Completed: inverse-NTT fusion source/caller bound review and oracle (260 inverse vectors, 66,560 coefficients, 108 independent sparse convolutions). A second review found no arithmetic defect for the seven pinned callers. Fixed oracle assertion-disable behavior and distinguished an unreachable scalar illustration from an actual valid-vector representative witness. Added source/constant binding. No Java NTT patch or timing result exists yet.

The historical ADRS collector remains byte-identical to its measurement seal. A guarded entry point and guarded independent audit reject optimized Python. The audit still requires recorded local binary/JDK paths; documentation states that limit. Source snapshots, candidate diff, fixtures, raw commands/results and all summaries are retained. Nineteen local report links and assertion-guard checks pass.

Research/probe work is complete and no background workloads remain. Production follow-ups would separately implement/confirm NTT fusion or ablate address-object hoisting versus field-reset removal, with broader correctness and balanced timing coverage. Publish this evidence by fast-forwarding existing PR2, keeping experimental claims separate from confirmed tables; do not merge or open an upstream production PR from this screen.
