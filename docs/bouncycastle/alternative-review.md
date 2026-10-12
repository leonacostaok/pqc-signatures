# Independent NTT review

A second Astra agent reviewed the sealed NTT source and caller bounds without running concurrent workloads. It found no blocking arithmetic defect in the pinned implementation. This is supporting engineering review, not independent cryptographic certification.

The companion multiply preserves the signed Montgomery result exactly: intentional 32-bit overflow keeps the required low word, while the subtraction uses a safe 64-bit numerator. Negating the inverse twiddle's companion preserves the same low-word identity. Indices depend on the public transform schedule; the change adds no secret-dependent branch, per-call allocation or key cache. Its cost is a 1,024-byte static array payload plus the array header.

Companion-only is the smallest candidate for upstream review: one source file, unchanged transform loops and callers, and identical signed representatives. Combining inverse-stage fusion with it requires the additional caller-range argument in the [fusion proof](pattern-research/invntt.md). The bound `|x| < q` describes coefficients entering the inverse transform, not every later intermediate. Fused intermediate representatives can differ while the tested encoded outputs remain identical.

The original arithmetic gate reconstructed the companion formula locally. Whole-transform tests already exercised the production implementation; the Java 17 preparation adds a direct reflection gate for all 256 stored companion constants and 78,128 production-helper comparisons. That supplements rather than replaces the sealed original checks. Native tests and performance confirmation remain separate evidence.

See the [NTT campaign](ntt-alternatives.md) for source snapshots, test records, both runtime cohorts and all regressions. No formal constant-time proof or independent security audit is claimed.
