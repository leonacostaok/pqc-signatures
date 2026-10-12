# Signature efficiency audit

**The original benchmark harness still needs correctness and measurement fixes before supporting fastest-provider claims or reuse of its experimental verifiers.** Separately validated production performance patches have their own source, correctness, and measurement evidence; those results neither repair nor depend on accepting the original common gate.

**Read the [current-main status addendum](current-main-status.md) first.** The detailed reports and runtime evidence below concern historical snapshot `80c832da6ce81ca8def12b319da9f4c19d589111`. A later source-only comparison against `origin/main` at `45076e05b67a6792e3bbb5115256e776e790cd1c` confirms that the critical cache, context-bound, validation-identity, and false-success defects remain. The Falcon cross-verification adapter is fixed and the saved Rust/Java results have advanced; the earlier incomplete-run and unresolved-Falcon statements are historical. No fresh runtime tests were performed for that addendum.

## Read first

| Priority | Finding | Evidence and implications |
|---|---|---|
| High | CIRCL's experimental ML-DSA cache retains mutable key/context buffers | Historical runtime tests show the cached path accepting an old signature after its caller's public-key buffer changes, while a fresh baseline rejects it; affects ML-DSA-44/65/87. The source is unchanged on current main. |
| High | liboqs stage setup constructs a context prefix before enforcing its bound | Static review finds an unchecked copy into a fixed 257-byte buffer before the 255-byte context limit is enforced. Validate the bound before construction; this is a harness finding, not an upstream liboqs claim. No full-path runtime reproduction is claimed. |
| High | Correctness gates accept absent evidence and orchestration suppresses failures | Reproduced an empty result set passing and every final-run operation failing while the runner exits zero. The final runner omits fresh artifacts/cross-verification. |
| High | Validation does not always execute the measured implementation | Java total_best selection changes with caller working directory; C parallel paths substitute serial paths in validation. Pass an exact implementation/composition manifest into every check. |
| High | Some optimized signing/hash paths weaken cleanup behavior | Noble replacement hashes retain copied input buffers after destroy, unlike the official implementation. Restore cleanup before treating speed gains as security-equivalent. |
| Medium | Stateful negative sequences are missing | Historical CIRCL SLH tests show valid → malformed key → valid becoming true → false → false. The source is unchanged. Failed key import must not mutate live cached state. |
| Medium | Timing, stage, and memory boundaries differ | Checksum/serialization overhead, duplicate verification work, omitted parsing, and coordinator-only stack measurements distort comparisons. Byte-identical intermediate outputs do not establish equal workloads. |
| Medium | Common final results are not tied to immutable run metadata | Later saved results have advanced, but resume markers still do not bind source, builds, corpus, or outputs. Saved passing rows alone do not establish complete execution-path coverage. |

The detailed provider reports include additional defensive input-validation, build-freshness, memory, and coverage findings. Severity is scoped to the experiment and possible reuse of its custom code; this audit does not assert vulnerabilities in the official upstream providers.

## Reports

- [Current-main status, resolved historical findings, and production-patch scope](current-main-status.md)
- [Common infrastructure, vector provenance, and methodology](common.md)
- [liboqs and OpenSSL](c-providers.md)
- [noble and CIRCL](js-go.md)
- [RustCrypto and Bouncy Castle](rust-java.md)
- [Prioritized optimization experiments](optimization-plan.md)
- [Evidence inventory](evidence/snapshot-inventory.json) and [reproducible common-tool checks](reproduce-common.py)

## What was verified at the historical snapshot

The 651-case suite contains 393 NIST cases and 258 generated cases. All 393 NIST cases match the official ACVP snapshot field-by-field; source commit and file hashes are retained. The historical saved validation files report 35,763 passes, but those labels alone do not prove exact-path coverage. The historical checker found two Falcon cross-verification failures and no differing stored canonical stage digests among the 93 keys it compared. The current saved match report instead records 558/558 successful cross-verifications after the Falcon adapter fix. Neither snapshot tracks the baseline artifact files needed to freshly reproduce all byte comparisons.

Fresh bounded tests include 5,328 Java verification-stage substitutions and 1,728 noble vendor/fast-path case/backend executions with zero failures, the two CIRCL cache failure sequences, Falcon format checks, and common-tool failure fixtures. Exact-version upstream source comparisons were performed for all six providers, with details and hashes in their reports. These are targeted audit tests, not a fresh full six-provider benchmark run.

## Best next performance work

Start with reusable ML-DSA key objects that cache decoding, ExpandA, polynomial transforms, and tr; measure first-use cost, retained memory, and break-even reuse. Then test SIMD Keccak and SHA-2 prefix-midstate/short-block hashing in complete sign/verify pipelines. Remove duplicated SLH verification work before evaluating stage alternatives. Profile signing explicitly, including ML-DSA rejection counts and SLH tree work, rather than assuming verification-stage winners transfer to signing.

Compare cold keys, reused keys, and independent-request batches separately. Use varied held-out keys/messages/contexts and replicated runs. Existing large speed ratios are leads to validate; modest compiler/runtime differences are not dependable wins without uncertainty estimates. The [experiment plan](optimization-plan.md) specifies the work matrix and promotion criteria.

## Scope and limitations

This report changes no production code or existing result files. The evidence distinguishes source inspection, bounded runtime checks, saved historical measurements, and proposed experiments.

The historical audit host is macOS, whereas the recorded six-provider benchmarks target Linux/x86. Rust's original harness could not compile its stack probe unchanged on this host. Historical C review includes source comparison and static findings, without a successful fresh full C validation run. Java and noble tests cover selected paths, not all joint compositions, signing workloads, or hardware backends. This audit does not claim side-channel certification, formal proof, or new production speedups. Subsequent production performance experiments have separate evidence and limitations. A corrected comparable run remains necessary before a general provider ranking.
