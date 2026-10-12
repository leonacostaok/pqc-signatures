# Ten-new-key sensitivity check

The ten-key totals show 1.1438–1.1911× for key construction and 1.0273–1.0618× for fresh-key signing. This is consistent with the scoped constructor benefit in the earlier repeated experiment. Ordinary signing and verification have mixed per-key results and outliers; this one pass does not establish new gains for those operations.

This is a one-pass sensitivity check requested after the repeated performance experiments. It preserves their sealed sources, production patches and results. Each affected parameter uses ten distinct new deterministic seeds, with matched messages, contexts and signing entropy across original and changed implementations. Two additional disjoint seeds warm each fresh process before the ten recorded keys; this bounded warmup is not a steady-state guarantee.

Each key contributes exactly one measured key-generation, ordinary-signing and verification call. Input decoding, entropy derivation, key/signature encoding, exact output comparisons and tamper checks occur outside their clocks. Every measured result is checked against the exact outputs established during untimed preparation. All output bytes, per-key wall/process CPU times, commands, process statuses and timestamps are retained. Each parameter and variant runs in a fresh process. Output paths cannot be reused, and a baseline batch requires its completed candidate batch.

The coordinated final order is all candidate batches across the six providers, followed by all baseline batches in the same provider order. This order is deliberately fixed for the requested sensitivity check, so time drift and order effects cannot be separated from implementation effects. The primary statistic is the sum of original wall time for the ten keys divided by the sum of changed wall time for the matching ten keys. Reports also retain every key ratio, median, range, losses and CPU totals; there are no exclusions or control normalization. This check does not replace the earlier repeated paired measurements.

The three ML-DSA parameter sets use deterministic signing with explicit zero signing entropy. Key generation means `SigningKey::from_seed`; ordinary signing uses the newly generated key. A separate `keygen_sign` metric includes construction of another fresh key and signing, retaining the key until after the clock so destruction is outside the sample. Verification uses a newly decoded public key and signature, with decoding outside the clock. The standalone binary links both pinned library variants, but each fresh process selects and executes only one variant. Release/default/zeroize features match the sealed experiment. Process CPU uses `getrusage` with microsecond resolution; individual short calls can quantize to zero.

The superseded preparation `tenkey-981027a2c750a158` is retained with its source snapshot and untimed logs. Its sign-result unwrapping was inside the timer; no final batch ran with it. The final driver moves those checks outside the clock and uses `tenkey-b9df94ee5da7eab7`.

The final batches completed successfully. Preparation results and frozen manifests are retained under `results/rustcrypto/experiments/tenkey-*`.

```sh
python3 libs/rustcrypto/experiments/tenkey.py batch --manifest libs/rustcrypto/build/keygen-reuse/tenkey-b9df94ee5da7eab7/manifest.json --variant candidate --out results/rustcrypto/experiments/tenkey-candidate.json
python3 libs/rustcrypto/experiments/tenkey.py batch --manifest libs/rustcrypto/build/keygen-reuse/tenkey-b9df94ee5da7eab7/manifest.json --variant baseline --out results/rustcrypto/experiments/tenkey-baseline.json --candidate results/rustcrypto/experiments/tenkey-candidate.json
python3 libs/rustcrypto/experiments/tenkey.py compare --candidate results/rustcrypto/experiments/tenkey-candidate.json --baseline results/rustcrypto/experiments/tenkey-baseline.json --out results/rustcrypto/experiments/tenkey-comparison.json
```

The recorded run completed all six providers' candidate batches before starting any baseline batch. Reproductions should preserve that requested ordering and run without competing benchmark or build workloads.

## Completed measurements

Candidate batch: `2026-10-12T02:02:04.588782+00:00` to `2026-10-12T02:02:04.726619+00:00`. Baseline batch: `2026-10-12T02:04:52.960167+00:00` to `2026-10-12T02:04:53.101750+00:00`. These are batch timestamps; per-process command and completion timestamps are retained in the raw directories.

The [comparison](../../results/rustcrypto/experiments/tenkey-comparison.json) retains every key ratio and all wall/CPU totals. The [independent review](../../results/rustcrypto/experiments/tenkey-independent-review.json) verifies each saved command, process status and stdout record, exact keys/signatures against prepared fixtures and the other variant, ten distinct measured keys per parameter, summary arithmetic, and frozen source/class/binary/corpus hashes. Every process exited successfully with empty stderr. No sample was excluded. No zero process-CPU samples occurred in this run; individual-call CPU quantization remains a clock limitation.

Wall totals below sum all ten calls. The primary ratio is original total divided by changed total; values below one are losses. The per-key median and range describe the ten matching keys and are not confidence intervals.

| Parameter / operation | Original ms | Changed ms | Total ratio | Median key ratio | Key range | Losing keys / 10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ML-DSA-44 / keygen | 1.2087 | 1.0567 | 1.1438× | 1.1652× | 0.9837–1.1744× | 1 |
| ML-DSA-44 / sign | 1.9925 | 1.9014 | 1.0479× | 0.9943× | 0.9759–1.5382× | 6 |
| ML-DSA-44 / verify | 0.3683 | 0.3677 | 1.0015× | 0.9989× | 0.9715–1.0690× | 6 |
| ML-DSA-44 / keygen_sign | 3.1572 | 3.0732 | 1.0273× | 1.0558× | 0.6646–1.1854× | 2 |
| ML-DSA-65 / keygen | 2.3072 | 1.9371 | 1.1911× | 1.1674× | 1.0006–1.3314× | 0 |
| ML-DSA-65 / sign | 7.6118 | 7.5398 | 1.0096× | 1.0021× | 0.9785–1.1786× | 4 |
| ML-DSA-65 / verify | 0.5269 | 0.5279 | 0.9981× | 1.0004× | 0.9788–1.0113× | 5 |
| ML-DSA-65 / keygen_sign | 9.9545 | 9.4377 | 1.0548× | 1.0710× | 1.0158–1.1252× | 0 |
| ML-DSA-87 / keygen | 3.1292 | 2.6351 | 1.1875× | 1.1824× | 1.1525–1.2218× | 0 |
| ML-DSA-87 / sign | 7.0871 | 7.0016 | 1.0122× | 1.0049× | 0.9932–1.0425× | 2 |
| ML-DSA-87 / verify | 0.8623 | 0.7835 | 1.1005× | 1.0073× | 0.9259–1.9396× | 2 |
| ML-DSA-87 / keygen_sign | 10.3442 | 9.7420 | 1.0618× | 1.0609× | 0.9409–1.2913× | 1 |

The earlier repeated experiment measured 1.1733–1.1775× for construction and 1.0376–1.0666× for fresh-key signing. This new-seed pass supports the same limited interpretation, without replacing the repeated evidence. ML-DSA-44 ordinary-sign total time yields 1.0479× despite six losing keys and a 1.5382× key ratio; ML-DSA-87 verification yields 1.1005× with a retained 1.9396× key ratio. These controls show why an apparent single-pass gain cannot establish faster ordinary signing or verification. The ML-DSA-44 fresh-key-sign loss down to 0.6646× and every other loss remain in the results.

Process CPU totals are retained separately from wall time in every summary cell. The Rust process clock includes user and system CPU. None of these totals normalize or remove wall-time losses.
