# Ten new SLH-DSA keys, changed implementation first

This separate sensitivity check uses the existing production SHA2-prefix patch without changing it. It covers all six SHA2 parameter sets and the unchanged SHAKE-128f control. Each set has exactly ten distinct new deterministic seeds, with matched messages/contexts in both variants. The final corpus is distinct from the preparation smoke corpus; none of the final keys was executed during preparation.

A dedicated process handles one parameter/variant. It warms the ordinary APIs on four disjoint seeds, then measures one key generation, one deterministic signature and one valid verification for each measured key. Caller buffers are copied and ordinary key/message objects are constructed before each timer; there is no retained cross-call cryptographic cache. Keygen must consume its exact seed. API error checks, key serialization, input-preservation checks, verification result checks and tampered-signature rejection occur outside clocks. Full key/signature bytes are retained and compared exactly across variants. Per-operation wall and process CPU times are recorded.

The coordinator runs all providers' candidate batches before any original batch. This deliberately unbalanced order can expose phase-to-phase drift. Exactly ten keys measured once are an order/key sensitivity check, not steady-state throughput, statistical confidence or a general provider ranking. Internal per-operation prefix reuse remains the production optimization; no state is retained between operations.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 libs/circl/experiments/tenkeys/run.py prepare
PYTHONDONTWRITEBYTECODE=1 python3 libs/circl/experiments/tenkeys/run.py check
# Only within the coordinator's global changed-first timing window:
PYTHONDONTWRITEBYTECODE=1 python3 libs/circl/experiments/tenkeys/run.py batch --variant candidate --out results/circl/experiments/tenkeys-candidate.json
# Only after ALL providers' candidate batches have completed:
PYTHONDONTWRITEBYTECODE=1 python3 libs/circl/experiments/tenkeys/run.py batch --variant baseline --candidate results/circl/experiments/tenkeys-candidate.json --out results/circl/experiments/tenkeys-baseline.json
```

Preparation copies the previously validated frozen source trees into new build directories, checks byte-equivalent source trees before adding the new driver, and builds distinct baseline/candidate executables. The original snapshots are untouched. Manifests hash the new sources/binaries, drivers and both corpora; a separate seventy-key differential smoke gate checks both variants before final collection. The corrected driver places error checks outside clocks and verifies complete seed consumption. Earlier preparation snapshots remain locally preserved and are not final measurements.

The primary result is total original wall time divided by total changed wall time over the ten keys, separately per parameter/operation. All individual wall/CPU times and per-key ratios, their median/range/loss count, and CPU totals remain visible. Each side records UTC start/end and saves its complete input corpus and per-parameter outputs. The completed measurements below retain the entire one-pass corpus.

## Completed measurements

All eighteen SHA2 operation/parameter totals and all 180 individual affected key/operation pairs improved. Total wall ratios are 1.310–1.386× for key generation, 1.313–1.390× for signing and 1.297–1.429× for verification. The unchanged SHAKE control is near parity, including a 0.9994× verification total and six keygen, one signing and three verification losing key observations; all are retained below.

Changed batches ran 2026-10-12T02:01:50Z–2026-10-12T02:02:04Z; original batches ran 2026-10-12T02:04:34Z–2026-10-12T02:04:52Z. The global coordinator completed the last changed batch at 2026-10-12T02:03:46.849833Z and started the first original batch at 2026-10-12T02:03:46.851953Z. Its separate `results/ten-key-order/execution/execution.json` record has SHA-256 `d369d404beb94bf7182b382f309c379d5120337a48e641fc69ed6a457f6890df`; this provider's independent check establishes its own local order, while that coordinator record establishes the six-provider order.

[Changed report](../../../results/circl/experiments/tenkeys-candidate.json), [original report and all per-key comparisons](../../../results/circl/experiments/tenkeys-baseline.json), [changed raw outputs](../../../results/circl/experiments/tenkeys-candidate.json.raw/), [original raw outputs](../../../results/circl/experiments/tenkeys-baseline.json.raw/) and [independent check](../../../results/circl/experiments/tenkeys-independent-check.json) retain complete measurements, corpus bytes, exact output bytes, UTC timestamps and sealed manifests. The frozen snapshot is `a0166cc840a01f83`. Raw times are integer nanoseconds; process CPU accounting has microsecond resolution and includes user plus system time. Ratios above one favor the changed implementation. No observations were removed.

| Parameter | Operation | Total wall speedup | Total CPU speedup | Per-key median | Per-key range | Slower keys |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| SHA2-128f | `keygen` | 1.3440× | 1.3400× | 1.3491× | 1.3054–1.3911× | 0/10 |
| SHA2-128f | `sign` | 1.3178× | 1.3172× | 1.3210× | 1.2964–1.3383× | 0/10 |
| SHA2-128f | `verify` | 1.3457× | 1.3436× | 1.3463× | 1.3201–1.3690× | 0/10 |
| SHA2-128s | `keygen` | 1.3411× | 1.3403× | 1.3425× | 1.3233–1.3570× | 0/10 |
| SHA2-128s | `sign` | 1.3128× | 1.3272× | 1.3320× | 1.1767–1.3355× | 0/10 |
| SHA2-128s | `verify` | 1.2973× | 1.2889× | 1.3031× | 1.1273–1.4445× | 0/10 |
| SHA2-192f | `keygen` | 1.3097× | 1.3151× | 1.3340× | 1.1095–1.3520× | 0/10 |
| SHA2-192f | `sign` | 1.3587× | 1.3575× | 1.3581× | 1.3356–1.3715× | 0/10 |
| SHA2-192f | `verify` | 1.3936× | 1.3934× | 1.3864× | 1.3465–1.4838× | 0/10 |
| SHA2-192s | `keygen` | 1.3443× | 1.3438× | 1.3458× | 1.3293–1.3548× | 0/10 |
| SHA2-192s | `sign` | 1.3751× | 1.3687× | 1.3708× | 1.3481–1.4368× | 0/10 |
| SHA2-192s | `verify` | 1.4117× | 1.4095× | 1.4201× | 1.2561–1.5187× | 0/10 |
| SHA2-256f | `keygen` | 1.3556× | 1.3515× | 1.3486× | 1.2622–1.4481× | 0/10 |
| SHA2-256f | `sign` | 1.3780× | 1.3767× | 1.3745× | 1.3544–1.4092× | 0/10 |
| SHA2-256f | `verify` | 1.3891× | 1.3887× | 1.3938× | 1.2673–1.5509× | 0/10 |
| SHA2-256s | `keygen` | 1.3857× | 1.3846× | 1.3865× | 1.3726–1.4002× | 0/10 |
| SHA2-256s | `sign` | 1.3897× | 1.3989× | 1.3999× | 1.2961–1.4081× | 0/10 |
| SHA2-256s | `verify` | 1.4288× | 1.4271× | 1.4356× | 1.3806–1.4749× | 0/10 |
| SHAKE-128f | `keygen` | 1.0057× | 1.0037× | 0.9982× | 0.9943–1.0712× | 6/10 |
| SHAKE-128f | `sign` | 1.0045× | 1.0035× | 1.0028× | 0.9990–1.0118× | 1/10 |
| SHAKE-128f | `verify` | 0.9994× | 0.9984× | 1.0008× | 0.9768–1.0170× | 3/10 |

The direction agrees with the [earlier balanced five-fork results](README.md): keygen 1.329–1.346×, signing 1.322–1.369× and verification 1.323–1.425×. The new SHA2-128s verification total is lower at 1.297×, while some other totals are higher. Different keys, one observation per key, a different summary statistic and unbalanced phase order make these differences unsuitable evidence for changing the earlier steady-state estimates. The control does not establish an improvement. This check measures ordinary API operation time with fresh objects; it does not measure allocation totals or peak memory.

The independent checker reproduced all 210 per-key ratios, all wall/CPU totals and all 21 summaries. It checked seventy byte-identical public keys, secret keys and signatures, every positive verification/tamper rejection/input-preservation flag, distinct measured and warmup seeds, raw-output/report equality, and the source/binary/corpus bindings. Both new executables contain the unchanged previously validated production source, with the new driver as the only addition to each copied tree.

The separate [auditor](../../../libs/circl/experiments/audit-tenkeys.py) requires the preserved source/runtime/build paths recorded in the manifest and checks their hashes before recomputing the raw statistics. On the measurement checkout, reproduce its retained output with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 libs/circl/experiments/audit-tenkeys.py results/circl/experiments/tenkeys-candidate.json results/circl/experiments/tenkeys-baseline.json
```

This is a single Apple M1 Pro/macOS host and one changed-first pass. Background scheduling, garbage collection or runtime activity and phase-to-phase machine drift can affect individual observations. Warmup excludes the measured seeds but does not flush OS, instruction or data caches. The ten-key result answers the requested key/order sensitivity check; it does not give confidence intervals or establish a ranking across providers.
