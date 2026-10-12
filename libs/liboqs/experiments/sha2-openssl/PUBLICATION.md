# Publication preparation

The [review draft](https://github.com/leonacostaok/liboqs/pull/1) is open in the personal fork, with production commit `b14f1b616f938698ebc0bf8b75b3736c30e1502c` and immutable [benchmark evidence](https://github.com/leonacostaok/pqc-signatures/tree/57229259515d6efa710d235d4e0a0d6ab17b4a1c/libs/liboqs/experiments/sha2-openssl). The evidence repository is private and requires access. The local `upstream-pr-body.md` remains a reusable template with an explicit evidence-commit placeholder; the actual draft body contains the resolved link. This is a personal-fork review draft, not an upstream submission.

The upstream contribution policy must be resolved before any later upstream submission. The pinned [CONTRIBUTING.md line 28](https://github.com/open-quantum-safe/liboqs/blob/fd44469daeffe6b28f031f54f9bb66cbae69a572/CONTRIBUTING.md#L28) says:

> Pull requests containing code, documentation, or text produced with the help of generative AI must declare that in the pull request description and describe the nature of the use. Contributors are expected to have verified and affirm such contributions themselves before submission.

The [pinned PR template](https://github.com/open-quantum-safe/liboqs/blob/fd44469daeffe6b28f031f54f9bb66cbae69a572/.github/PULL_REQUEST_TEMPLATE.md) repeats the disclosure requirement. The initial personal-fork draft allows the user to review the patch while preserving the standing no-attribution instruction. Its prepared body makes no claim that the submitter has personally reviewed or affirmed anything. A later upstream submission remains subject to the upstream disclosure and review rules.

The direct public-API verification adapter and execution checks now pass all 396 NIST and 216 shared cases. The initial NIST exit-zero report contained 312 executed cases and 84 skipped external verification cases; its correction and the complete replacement run are preserved in the evidence. The sealed performance snapshot remains unchanged.

# Existing upstream work

Read-only GitHub API searches on 2026-10-12 found no open PR proposing this exact compression-backend change. Queries covered `SLH OpenSSL`, `SHA2`, `SHA256_Transform`, `SLH performance`, `SLH hash`, `shims`, `2204`, and all open PRs matching `SLH`; the API reported complete results for each search. This is a search result, not proof that no unindexed branch or private work exists.

[Issue #2204, Create SLH-DSA hash shims](https://github.com/open-quantum-safe/liboqs/issues/2204), remains open and requests replacing private SLH hash implementations with liboqs shims. [PR #2245](https://github.com/open-quantum-safe/liboqs/pull/2245) and [PR #2251](https://github.com/open-quantum-safe/liboqs/pull/2251) are closed without merge. Their inspected changes replace single-call hash entry points with common liboqs APIs; they do not replace the private SHA-256/SHA-512 compression functions used by cached SLH hash states. The proposed patch is a narrower backend optimization and only partially addresses the broader issue. A maintainer may still prefer completing common hash shims, so related work should be acknowledged without claiming to close #2204.

The open SLH results were [#2587](https://github.com/open-quantum-safe/liboqs/pull/2587), [#2566](https://github.com/open-quantum-safe/liboqs/pull/2566), [#2476](https://github.com/open-quantum-safe/liboqs/pull/2476), and [#2449](https://github.com/open-quantum-safe/liboqs/pull/2449). These concern short-signature handling, null-message handling, ML-DSA key generation, and constant-time analysis. They do not duplicate the proposed OpenSSL compression path; #2566 touches the same source files and should be watched for rebase conflicts.
