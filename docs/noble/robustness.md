# ML-DSA fresh-input robustness checks

This experiment tests whether the row-dot improvement survives fresh caller identities, fresh processes, reversed/randomized order, two official releases, and two runtimes. It retains the original measurements and production patch. It does not introduce another cache or API.

The completed matrix is noble 0.7.0 and 0.7.1 on Node 22.23.2 and 24.3.0. Comparisons are always baseline versus patched code within the same release/runtime. Older-release behavior, including its validation and cleanup, remains unchanged. The row-dot operands stay canonical, each row has at most seven columns, and `7 * (8380417 - 1)^2 = 491619606331392 < 2^49`; reduction still occurs before int32 storage. Row sampling owns its polynomials, and each call’s output destination is independent of its operands.

Warmed calls cycle twelve varied fixture values with new Uint8Array identities and option objects on every invocation, including warmup calls. Values are repeated across complete corpus cycles; they are not newly generated on every invocation. This removes cross-call input-object reuse. Module constants and ordinary scratch buffers used inside a single operation remain part of the implementation. No per-key precomputation or signer/verifier instance is retained between calls.

Signing uses `extraEntropy: false`, so the measured calls are deterministic and exclude operating-system entropy acquisition. Supplied-entropy signing, prehash, external-mu, malformed inputs and ownership remain part of the separate correctness gate. Messages cover 0/64/1024/4096 bytes, contexts 0/31/255 bytes, and each fork has twelve different keys per parameter set plus separate warmup keys.

The report separates warmed one-shot latency, isolated first-operation latency in a fresh process, and parent-observed process-startup-inclusive lifetime. The latter includes loading and post-operation equality checks/serialization as well as startup; it must not be described as isolated cryptographic latency. Neither single-call measure flushes OS or hardware caches.

All four runtime/release correctness gates passed on frozen snapshot `c07d4385a773caa3`, including a fake-API worker test that proves single mode invokes exactly once. Their complete source/runtime/dependency hashes and checks are in `results/noble/experiments/robustness/gate-*.json`. All four final measurements completed under an exclusive machine window. An independent checker reproduced every paired ratio and summary from all 4,800 raw sample files and verified balanced order; see [its retained output](../../results/noble/experiments/robustness/independent-check.json). The runner and its correctness gates are in `libs/noble/experiments/robustness/`; it retains every raw result and refuses to overwrite evidence.

## Upstream conformance scope

The patched 0.7.1 source also passed the previously recorded default upstream suite; see the [upstream test log](../../results/noble/experiments/rowdot-upstream-tests-node22.txt) and [source/build provenance](../../results/noble/experiments/rowdot-upstream-validation.json). In that upstream `test/acvp.test.ts`, the `SLOW_TESTS` sampling condition applies to FIPS205 SLH-DSA names only. FIPS204 ML-DSA keyGen, sigGen and sigVer iterate all loaded cases in the default run. Prehashes weaker than a parameter set's required strength are deliberately checked for rejection. The slow SLH-DSA suite was not run, and no exact ML-DSA ACVP vector total is claimed here.

The four new runtime/release gates separately repeat the 219-case shared ML-DSA corpus, 72 option/ownership comparisons, allocation checks, exact-arithmetic oracle and fresh-process wrapper checks. They are not described as four complete reruns of the upstream suite.

## Reproduce

The experiment has its own pinned dependency locks for each release. Installations and patched copies live under ignored build paths; the original experiment's packages and results are retained. The runner checks both applied patches, verifies that the candidate differs, and hashes every installed package file plus scripts, locks, validation data and the selected Node executable.

```sh
python3 libs/noble/experiments/robustness/run.py prepare
python3 libs/noble/experiments/robustness/run.py check --node /absolute/path/to/node --version 0.7.1
python3 libs/noble/experiments/robustness/run.py bench --node /absolute/path/to/node --version 0.7.1 --out results/noble/experiments/robustness/new-run.json --forks 5 --rounds 4 --start 30 --single-cases 3 --budget-ms 250 --warmup-ms 200
```

Run the matching gate before each runtime/release measurement. The collector rejects a stale gate or changed source/runtime, odd warm round counts, fewer than five forks, and existing output paths. Run only one timing workload on the host at a time. The standard matrix is Node 22.23.2 and 24.3.0 crossed with noble 0.7.0 and 0.7.1, measured in this order: Node24/0.7.0, Node22/0.7.1, Node22/0.7.0, Node24/0.7.1.

Each fork randomizes parameter/operation order, warm/single mode order, and corpus order. Every warm fork has two AB and two BA rounds per cell. Each of three selected first-operation cases is measured once in each orientation, giving six balanced pairs per cell/fork. Both variants run in separate new processes even for warmed measurements, preventing cross-variant JIT interaction inside a process. Complete twelve-case warm cycles preserve equal rejection-sampling weights. All output checks happen after the operation timer; all verification return values are checked.

One matrix cell produces 600 paired observations: 240 warmed pairs and 360 first-operation pairs, with 1,200 durable individual sample files plus five corpora. No outliers or losing samples are removed. The reported statistic is each fork's median paired baseline/candidate ratio, then the median across five forks; fork min/max describe observed variation and are not confidence intervals. Process lifetime ratios are summarized only for single-operation workers because warmed workers run for a fixed time budget.

## Interpretation limits

This is one Apple M1 Pro / macOS host. It does not establish gains on x86, other engines, all applications or every payload. The two releases intentionally retain their own validation/cleanup logic and dependency versions; only within-release baseline/candidate comparisons estimate the patch's effect. The first-operation worker loads the benchmark fixture before its operation timer. Its startup-inclusive lifetime additionally includes that fixture loading, equality checks and JSON output, so it describes this complete worker rather than arbitrary application startup.

Fresh caller arrays rule out gains that require reusing those input objects. Source inspection confirms that the patch introduces no cross-call key cache, retained signer/verifier instance or new per-key precompute API. Warm operation timing still benefits from normal JIT compilation and normal CPU caches, and its twelve fixture values repeat across cycles. Internal per-operation scratch reuse and the signer's existing matrix within one signing operation are unchanged.

## Completed measurements

All 48 warmed operation cells improved, with all 240 warmed fork medians above one. Warmed signing improved 1.091–1.189× and verification 1.101–1.189× across the matrix. All 48 first-operation cell medians were above one (1.007–1.081×), but five individual fork medians regressed. Startup-inclusive cell medians ranged 0.990–1.032× with 13 of 48 below one; these measurements do not support a broad startup-speed claim. The tables below include every cell and retain these losses. Ratios above one are faster. Columns are warmed operation / first operation in a fresh process / process startup included, all using fresh caller buffers.

### noble 0.7.0 · Node 24.3.0

Measured 2026-10-11 23:14:16–23:20:09 UTC. All twelve warmed and all twelve first-operation cell medians exceed one; all sixty fork medians exceed one in each operation scope. Two startup-inclusive cell medians fall below one.

| Parameter | Operation | Warmed | First operation | Startup included |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-44 | `keygen` | 1.181× | 1.028× | 0.996× |
| ML-DSA-44 | `getPublicKey` | 1.199× | 1.018× | 1.007× |
| ML-DSA-44 | `sign` | 1.094× | 1.041× | 1.007× |
| ML-DSA-44 | `verify` | 1.101× | 1.029× | 0.992× |
| ML-DSA-65 | `keygen` | 1.226× | 1.060× | 1.006× |
| ML-DSA-65 | `getPublicKey` | 1.258× | 1.040× | 1.007× |
| ML-DSA-65 | `sign` | 1.124× | 1.049× | 1.017× |
| ML-DSA-65 | `verify` | 1.129× | 1.050× | 1.006× |
| ML-DSA-87 | `keygen` | 1.310× | 1.072× | 1.008× |
| ML-DSA-87 | `getPublicKey` | 1.337× | 1.064× | 1.005× |
| ML-DSA-87 | `sign` | 1.182× | 1.047× | 1.032× |
| ML-DSA-87 | `verify` | 1.187× | 1.042× | 1.012× |

[Complete paired measurements and embedded correctness gate](../../results/noble/experiments/robustness/fresh-0.7.0-node24.json). The matching `.raw.tar.gz` archive retains individual samples and exact corpora.

### noble 0.7.1 · Node 22.23.2

Measured 2026-10-11 23:20:29–23:26:21 UTC. All twelve warmed and all twelve first-operation cell medians exceed one. All sixty warmed fork medians exceed one; one first-operation fork is slower (ML-DSA-44 public-key derivation, 0.998×). Four startup-inclusive cell medians fall below one.

| Parameter | Operation | Warmed | First operation | Startup included |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-44 | `keygen` | 1.133× | 1.042× | 1.006× |
| ML-DSA-44 | `getPublicKey` | 1.141× | 1.024× | 1.001× |
| ML-DSA-44 | `sign` | 1.091× | 1.014× | 0.999× |
| ML-DSA-44 | `verify` | 1.102× | 1.026× | 1.018× |
| ML-DSA-65 | `keygen` | 1.171× | 1.029× | 0.990× |
| ML-DSA-65 | `getPublicKey` | 1.195× | 1.036× | 1.009× |
| ML-DSA-65 | `sign` | 1.123× | 1.042× | 1.025× |
| ML-DSA-65 | `verify` | 1.141× | 1.024× | 0.997× |
| ML-DSA-87 | `keygen` | 1.231× | 1.045× | 1.011× |
| ML-DSA-87 | `getPublicKey` | 1.246× | 1.041× | 1.000× |
| ML-DSA-87 | `sign` | 1.183× | 1.020× | 1.024× |
| ML-DSA-87 | `verify` | 1.189× | 1.030× | 0.991× |

[Complete paired measurements and embedded correctness gate](../../results/noble/experiments/robustness/fresh-0.7.1-node22.json). The matching `.raw.tar.gz` archive retains individual samples and exact corpora.

### noble 0.7.0 · Node 22.23.2

Measured 2026-10-11 23:26:41–23:32:34 UTC. All twelve warmed and all twelve first-operation cell medians exceed one. All sixty warmed fork medians exceed one; two first-operation forks are slower (ML-DSA-44 signing, 0.991×; ML-DSA-87 signing, 0.991×). Three startup-inclusive cell medians fall below one.

| Parameter | Operation | Warmed | First operation | Startup included |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-44 | `keygen` | 1.132× | 1.018× | 1.003× |
| ML-DSA-44 | `getPublicKey` | 1.141× | 1.017× | 1.011× |
| ML-DSA-44 | `sign` | 1.095× | 1.012× | 0.998× |
| ML-DSA-44 | `verify` | 1.105× | 1.013× | 1.016× |
| ML-DSA-65 | `keygen` | 1.169× | 1.023× | 0.999× |
| ML-DSA-65 | `getPublicKey` | 1.194× | 1.029× | 1.005× |
| ML-DSA-65 | `sign` | 1.118× | 1.056× | 1.021× |
| ML-DSA-65 | `verify` | 1.133× | 1.026× | 1.006× |
| ML-DSA-87 | `keygen` | 1.233× | 1.042× | 1.016× |
| ML-DSA-87 | `getPublicKey` | 1.249× | 1.027× | 1.015× |
| ML-DSA-87 | `sign` | 1.189× | 1.026× | 1.017× |
| ML-DSA-87 | `verify` | 1.187× | 1.028× | 0.996× |

[Complete paired measurements and embedded correctness gate](../../results/noble/experiments/robustness/fresh-0.7.0-node22.json). The matching `.raw.tar.gz` archive retains individual samples and exact corpora.

### noble 0.7.1 · Node 24.3.0

Measured 2026-10-11 23:33:01–23:38:54 UTC. All twelve warmed and all twelve first-operation cell medians exceed one. All sixty warmed fork medians exceed one; two first-operation forks are slower (ML-DSA-44 public-key derivation, 0.991×; ML-DSA-44 signing, 0.992×). Four startup-inclusive cell medians fall below one.

| Parameter | Operation | Warmed | First operation | Startup included |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-44 | `keygen` | 1.179× | 1.021× | 1.003× |
| ML-DSA-44 | `getPublicKey` | 1.202× | 1.007× | 0.997× |
| ML-DSA-44 | `sign` | 1.092× | 1.030× | 0.998× |
| ML-DSA-44 | `verify` | 1.103× | 1.020× | 1.006× |
| ML-DSA-65 | `keygen` | 1.234× | 1.045× | 1.003× |
| ML-DSA-65 | `getPublicKey` | 1.260× | 1.042× | 1.002× |
| ML-DSA-65 | `sign` | 1.123× | 1.056× | 1.017× |
| ML-DSA-65 | `verify` | 1.136× | 1.063× | 1.003× |
| ML-DSA-87 | `keygen` | 1.309× | 1.074× | 0.992× |
| ML-DSA-87 | `getPublicKey` | 1.333× | 1.081× | 0.997× |
| ML-DSA-87 | `sign` | 1.183× | 1.065× | 1.026× |
| ML-DSA-87 | `verify` | 1.187× | 1.053× | 1.004× |

[Complete paired measurements and embedded correctness gate](../../results/noble/experiments/robustness/fresh-0.7.1-node24.json). The matching `.raw.tar.gz` archive retains individual samples and exact corpora.

## Raw evidence archives

The four deterministic `.raw.tar.gz` archives retain every process sample, corpus and manifest (4,824 files total), including losing and noisy observations. Original raw directories remain locally available and are ignored by Git. [The archive manifest](../../results/noble/experiments/robustness/raw-archives.json) records each archive and report SHA-256, file count, content-tree hash and metadata policy. Archiving verifies every file byte-for-byte against the original directory; no samples are omitted. A separate [round-trip check](../../results/noble/experiments/robustness/archive-roundtrip-check.json) extracted all archives, repeated the complete independent audit from extracted files, and reproduced identical archive hashes.

To inspect or independently recompute a fresh checkout, first verify archive SHA-256 values against that manifest, then extract each archive next to its report and run the independent checker:

```sh
for archive in results/noble/experiments/robustness/*.raw.tar.gz; do
  tar -xzf "$archive" -C results/noble/experiments/robustness
done
python3 libs/noble/experiments/audit-robustness.py results/noble/experiments/robustness/fresh-*.json
```

The collector, archive builder and independent checker are separate programs. The production patch and historical experiment results are unchanged.
