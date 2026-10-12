# Ten new ML-DSA keys, changed implementation first

This separate sensitivity check uses the existing row-dot patch on noble 0.7.1 and Node 22.23.2. It preserves all previous experiments. Each of ML-DSA-44/65/87 has exactly ten new deterministic seeds, messages and contexts. Preparation smoke checks used a separate corpus ID and different seeds; none of the final keys was executed during preparation.

A fresh process imports only one variant for one parameter set. It first warms all three APIs on four disjoint seeds for sixteen cycles, then measures one public `keygen`, one deterministic `sign` and one valid `verify` for each of the ten measured keys. Each call receives fresh arrays/options, with copies constructed before its timer. No per-key cache, precomputed signer or verifier is retained. Signing uses `extraEntropy: false`. Key and signature encoding, caller-input preservation checks, positive result checks and a tampered-signature rejection happen outside clocks. Complete key/signature bytes are retained and must match the other variant exactly.

The coordinator runs every provider's changed batches before any provider's original batch. Candidate and baseline commands are deliberately separate; baseline requires the completed matching candidate report. This order is not balanced and does not control phase-to-phase machine drift. Ten keys measured once are a sensitivity check, not steady-state throughput, a confidence interval or a general provider ranking.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 libs/noble/experiments/tenkeys/run.py prepare
PYTHONDONTWRITEBYTECODE=1 python3 libs/noble/experiments/tenkeys/run.py check
# Only within the coordinator's global changed-first timing window:
PYTHONDONTWRITEBYTECODE=1 python3 libs/noble/experiments/tenkeys/run.py batch --variant candidate --out results/noble/experiments/tenkeys-candidate.json
# Only after ALL providers' candidate batches have completed:
PYTHONDONTWRITEBYTECODE=1 python3 libs/noble/experiments/tenkeys/run.py batch --variant baseline --candidate results/noble/experiments/tenkeys-candidate.json --out results/noble/experiments/tenkeys-baseline.json
```

Preparation requires the original robustness experiment's checked source snapshot. New manifests retain hashes of the installed package trees, selected Node executable, scripts and both corpora. The fake-API protocol regression verifies fresh input identities and exact measured call counts. Smoke checks compare all thirty new key/signature pairs across variants, including mutation and tamper assertions. Final collection rejects a stale gate or changed fingerprint and refuses existing output/raw paths. Per-parameter raw outputs are saved immediately.

The primary statistic is the sum of original wall times for ten keys divided by the sum of changed wall times, separately for each parameter/operation. Every per-key wall/CPU observation, ratio, median, range and loss is retained, together with CPU totals and timestamped side completion. Warmup and input copying are outside operation timings; OS/CPU caches are not flushed. The completed measurements below retain the entire one-pass corpus.

## Completed measurements

All nine operation/parameter totals and all ninety individual key/operation pairs improved. Total wall ratios are 1.187–1.244× for key generation, 1.145–1.202× for signing and 1.144–1.187× for verification. These calls use each measured key once per API and fresh caller arrays, so the gains in this check do not require reusing caller objects or a retained per-key precomputation.

Changed batches ran 2026-10-12T02:01:45Z–2026-10-12T02:01:50Z; original batches ran 2026-10-12T02:04:27Z–2026-10-12T02:04:33Z. The global coordinator completed the last changed batch at 2026-10-12T02:03:46.849833Z and started the first original batch at 2026-10-12T02:03:46.851953Z. Its separate `results/ten-key-order/execution/execution.json` record has SHA-256 `d369d404beb94bf7182b382f309c379d5120337a48e641fc69ed6a457f6890df`; this provider's independent check establishes its own local order, while that coordinator record establishes the six-provider order.

[Changed report](../../results/noble/experiments/tenkeys-candidate.json), [original report and all per-key comparisons](../../results/noble/experiments/tenkeys-baseline.json), [changed raw outputs](../../results/noble/experiments/tenkeys-candidate.json.raw/), [original raw outputs](../../results/noble/experiments/tenkeys-baseline.json.raw/) and [independent check](../../results/noble/experiments/tenkeys-independent-check.json) retain complete measurements, corpus bytes, exact output bytes, UTC timestamps and sealed manifests. The frozen snapshot is `ebc0f094e9258d13`. Raw times are integer nanoseconds; process CPU accounting has microsecond resolution and includes user plus system time. Ratios above one favor the changed implementation. No observations were removed.

| Parameter | Operation | Total wall speedup | Total CPU speedup | Per-key median | Per-key range | Slower keys |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ML-DSA-44 | `keygen` | 1.2443× | 1.2506× | 1.1951× | 1.1296–1.6400× | 0/10 |
| ML-DSA-44 | `sign` | 1.1689× | 1.1226× | 1.0953× | 1.0500–1.3493× | 0/10 |
| ML-DSA-44 | `verify` | 1.1478× | 1.1283× | 1.1070× | 1.0910–1.3916× | 0/10 |
| ML-DSA-65 | `keygen` | 1.1869× | 1.1749× | 1.1808× | 1.1392–1.2433× | 0/10 |
| ML-DSA-65 | `sign` | 1.1453× | 1.1457× | 1.1269× | 1.0614–1.1831× | 0/10 |
| ML-DSA-65 | `verify` | 1.1438× | 1.1506× | 1.1434× | 1.1253–1.1670× | 0/10 |
| ML-DSA-87 | `keygen` | 1.2261× | 1.2328× | 1.2369× | 1.0887–1.3100× | 0/10 |
| ML-DSA-87 | `sign` | 1.2024× | 1.1985× | 1.1997× | 1.0964–1.2375× | 0/10 |
| ML-DSA-87 | `verify` | 1.1866× | 1.1925× | 1.1855× | 1.1407–1.2392× | 0/10 |

The direction agrees with the [earlier balanced five-fork matrix](robustness.md), whose warmed signing gains were 1.091–1.189× and verification gains 1.101–1.189× across two releases/runtimes. This experiment uses new values, a different statistic and copies inputs outside timing; the earlier warmed worker included those copies. It therefore does not replace that matrix or establish larger steady-state gains. ML-DSA-44 signing illustrates the variability: total wall speedup is 1.169×, but the per-key median is 1.095× and total CPU speedup is 1.123×. No startup or first-operation claim is inferred from these already-warmed processes, and `getPublicKey` was not remeasured here.

The independent checker reproduced all ninety per-key ratios, all wall/CPU totals and all nine summaries. It checked thirty byte-identical public keys, secret keys and signatures, every positive verification/tamper rejection/input-preservation flag, distinct measured and warmup seeds, raw-output/report equality, and the source/package/runtime/corpus bindings. Both variants retain the production patch and its previously validated source exactly; no new cryptographic changes were made.

The separate [auditor](../../libs/noble/experiments/audit-tenkeys.py) requires the preserved source/runtime/build paths recorded in the manifest and checks their hashes before recomputing the raw statistics. On the measurement checkout, reproduce its retained output with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 libs/noble/experiments/audit-tenkeys.py results/noble/experiments/tenkeys-candidate.json results/noble/experiments/tenkeys-baseline.json
```

This is a single Apple M1 Pro/macOS host and one changed-first pass. Background scheduling, garbage collection or runtime activity and phase-to-phase machine drift can affect individual observations. Warmup excludes the measured seeds but does not flush OS, instruction or data caches. The ten-key result answers the requested key/order sensitivity check; it does not give confidence intervals or establish a ranking across providers.
