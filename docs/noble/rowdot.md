# ML-DSA row-wise NTT accumulation

This experiment reduces modular reductions and temporary polynomial allocations in noble ML-DSA key generation, public-key derivation, signing, and verification. The candidate applies a small patch to the unmodified `@noble/post-quantum` 0.7.1 package, independently of this repository's existing vendor and native-hash variants. Existing benchmark variants and historical measurements retain their original meanings.

The [fresh-input robustness follow-up](robustness.md) adds fresh caller buffers, first operations in new processes, balanced randomized ordering, and separate comparisons for noble 0.7.0/0.7.1 on Node 22/24. The measurements below remain the original experiment.

## Change and arithmetic

The original matrix-vector product constructs `MultiplyNTTs(A[i][j], v[j])` for every column and then adds that temporary polynomial to the row accumulator. `DotNTTs` sums the row's products coefficient by coefficient and reduces once per coefficient. Signing uses its existing matrix; the other operations sample one public matrix row before multiplying it. Sampling order, signature encoding, randomness, validation, domain separation, and explicit cleanup are preserved.

All operands are canonical NTT coefficients in `[0, q)`, where `q = 8380417`. The supported parameter sets have `L = 4, 5, 7`; the largest product sum is `7 * (q - 1)^2 = 491619606331392 < 2^49`. Products and partial sums therefore remain exact JavaScript integers. Reduction happens before assignment to `Int32Array`. This proof depends on those bounds: do not generalize the helper to other moduli, unreduced inputs, or larger rows without a new bound. Output buffers must not alias input polynomials; none of the four callsites does.

The change removes 16, 30, or 56 temporary 1 KiB product arrays per matrix-vector multiplication. Signing may perform multiple such products because of rejection sampling. This is an allocation-volume reduction, not evidence of reduced peak memory: key generation, public-key derivation, and verification now retain a row of 4, 5, or 7 public polynomials at once and create ordinary row arrays.

## Reproduce

Install the repository's locked dependencies, then run the isolated experiment using the chosen Node executable:

```sh
npm ci --ignore-scripts --no-audit --no-fund
ROUNDS=6 BUDGET_MS=250 libs/noble/run.sh rowdot --out results/noble/experiments/rowdot-local.json --forks 5 --start 10
# To use a second installed runtime:
NODE_BIN=/absolute/path/to/node ROUNDS=6 BUDGET_MS=250 libs/noble/run.sh rowdot --out results/noble/experiments/rowdot-second-runtime.json --forks 5 --start 10
```

The output path must be new. The runner verifies the pinned source hashes, applies both checked-in patches to isolated copies, checks arithmetic and correctness, and then runs fresh benchmark processes sequentially. A failure prevents publication of the aggregate report. Do not launch multiple copies of this experiment concurrently: the isolated build directory is shared within a checkout. Use separate worktrees if separate experiments are necessary, and serialize timings on the same machine.

Measurements use the ordinary one-shot APIs on warmed processes. Signing uses `extraEntropy: false`, so these timings exclude operating-system entropy acquisition. Verification timings use valid signatures. Each fork uses 12 different seeds/messages/contexts per parameter set; message lengths are 0, 64, 1024, and 4096 bytes and context lengths are 0, 31, and 255 bytes. Each timed batch completes whole corpus cycles so rejection paths retain equal weights. Both implementations receive the same corpus. Warmup and paired measurement order alternate by fork/round. Signature bytes and key bytes are checked outside timing. Allocation instrumentation runs in a separate process before timing.

The report preserves all paired wall-clock and process-CPU measurements, iteration counts, corpus IDs, runtime/host metadata, and hashes of source, patches, scripts, lockfile, and validation suite. The reported speedup is the median across forks of each fork's median paired baseline/candidate latency ratio. Fork min/max values describe observed variation; they are not confidence intervals. Faster key generation or verification does not imply the same speedup for another provider, architecture, runtime, workload, or short-lived process.

## Correctness and patch provenance

The TypeScript patch is `libs/noble/patches/ml-dsa-rowdot.patch`; the JavaScript patch is `libs/noble/patches/ml-dsa-rowdot-js.patch`. The pinned npm TypeScript source is byte-identical to upstream commit `48e493397e69fa3e377bd454ff5261b1a7e22651`. The JavaScript patch is generated from the compiled TypeScript with the published package's import quote spelling preserved. The preparation script checks both original source hashes before applying either patch.

The patched upstream TypeScript passed the default suite on Node 22.23.2: 230 tests executed successfully and five were skipped (Falcon secret cleanup plus four WebCrypto cases); the upstream runner labels their combined total as “235 tests passed.” Build, test logs, and source-equivalence evidence are in `results/noble/experiments/rowdot-upstream-*`.

The isolated correctness checks include the repository's 219 ML-DSA validation cases, deterministic output comparisons across three parameter sets, supplied-entropy pure/prehash/external-μ comparisons, caller-owned input preservation, malformed-signature behavior parity, and instrumented typed-array allocation regression checks. An independent BigInt oracle checks 204 dot-product cases covering zero, maximum coefficients, random coefficients, allocated destinations, and nonzero reused subarray destinations with canaries. These checks establish concrete regression evidence, not a cryptographic security proof.

## Measured results

Measured on one Apple M1 Pro / Darwin arm64 host, using Node 22.23.2 and Node 24.3.0. Each runtime used five new processes (corpus seeds 10–14), six paired rounds per operation and parameter set, and at least 250 ms per timed batch. The pilots used to select the optimization are excluded. All 24 runtime/operation/parameter cells improved, and every observed fork median exceeded 1. This establishes a repeatable local improvement; x86-64, other engines, cold-start latency, and peak memory remain unmeasured.

Values are median speedup ×, followed by the minimum–maximum fork medians in brackets. A value of 1.20× means approximately 16.7% lower latency.

| Parameter set | Operation | Node 22.23.2 | Node 24.3.0 |
| --- | --- | --- | --- |
| ML-DSA-44 | `keygen` | 1.123× [1.121–1.128] | 1.192× [1.186–1.193] |
| ML-DSA-44 | `getPublicKey` | 1.128× [1.124–1.131] | 1.200× [1.196–1.203] |
| ML-DSA-44 | `sign` | 1.074× [1.071–1.081] | 1.092× [1.079–1.098] |
| ML-DSA-44 | `verify` | 1.085× [1.079–1.087] | 1.085× [1.080–1.089] |
| ML-DSA-65 | `keygen` | 1.145× [1.138–1.147] | 1.241× [1.238–1.246] |
| ML-DSA-65 | `getPublicKey` | 1.154× [1.148–1.158] | 1.262× [1.259–1.270] |
| ML-DSA-65 | `sign` | 1.113× [1.101–1.116] | 1.136× [1.125–1.146] |
| ML-DSA-65 | `verify` | 1.120× [1.116–1.126] | 1.119× [1.117–1.123] |
| ML-DSA-87 | `keygen` | 1.197× [1.195–1.198] | 1.330× [1.320–1.334] |
| ML-DSA-87 | `getPublicKey` | 1.203× [1.200–1.206] | 1.341× [1.340–1.344] |
| ML-DSA-87 | `sign` | 1.155× [1.141–1.163] | 1.190× [1.174–1.197] |
| ML-DSA-87 | `verify` | 1.180× [1.175–1.184] | 1.167× [1.162–1.168] |

Raw paired measurements and correctness evidence: [Node 22](../../results/noble/experiments/rowdot-node22-arm64.json), [Node 24](../../results/noble/experiments/rowdot-node24-arm64.json). Upstream evidence: [build log](../../results/noble/experiments/rowdot-upstream-build.txt), [test log](../../results/noble/experiments/rowdot-upstream-tests-node22.txt), and [source/build provenance](../../results/noble/experiments/rowdot-upstream-validation.json).

## Reproduce the upstream suite

Use a separate checkout under the ignored build directory. The ACVP submodule is large and must be populated before running the upstream tests.

```sh
git clone --no-checkout https://github.com/paulmillr/noble-post-quantum.git libs/noble/build/rowdot-upstream
git -C libs/noble/build/rowdot-upstream checkout 48e493397e69fa3e377bd454ff5261b1a7e22651
git -C libs/noble/build/rowdot-upstream submodule update --init --depth 1
git -C libs/noble/build/rowdot-upstream apply "$PWD/libs/noble/patches/ml-dsa-rowdot.patch"
npm ci --ignore-scripts --prefix libs/noble/build/rowdot-upstream
npm run build --prefix libs/noble/build/rowdot-upstream
npm test --prefix libs/noble/build/rowdot-upstream
```

That upstream commit pins ACVP vectors at `2e9216ceafb854d7bc113088a2f8b043654226a8`. The default upstream suite excludes tests gated behind `SLOW_TESTS`; passing it must not be described as passing the slow suite.
