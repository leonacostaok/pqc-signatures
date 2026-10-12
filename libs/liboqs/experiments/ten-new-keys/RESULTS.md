# Ten new keys: recorded results

All six SHA2 parameter sets improved in this candidate-first pass. The ratio of total wall time over ten matched keys is 5.259–5.439× for key generation, 4.187–5.287× for signing, and 4.252–5.302× for verification. All 180 individual operation pairs improved in both wall and process CPU time; no rows were removed.

The table uses baseline/candidate speedups. “Total” is the ratio of the two sums over ten keys, not an average of their ratios. Per-key columns give the median and inclusive range. A loss means a ratio below 1; each row contains ten pairs. Exact nanosecond totals, all per-key ratios, and unrounded statistics are retained in [summary.json](evidence/summary.json).

| Parameter | Operation | Total wall | Total CPU | Per-key wall median [range] | Per-key CPU median [range] | Losses wall/CPU |
|---|---|---:|---:|---:|---:|---:|
| sha2-128f | keygen | 5.439× | 5.405× | 5.398 [5.338–5.782] | 5.389 [5.313–5.592] | 0/0 |
| sha2-128f | sign | 5.287× | 5.281× | 5.292 [5.192–5.354] | 5.286 [5.197–5.342] | 0/0 |
| sha2-128f | verify | 5.302× | 5.284× | 5.312 [4.877–5.480] | 5.304 [4.934–5.431] | 0/0 |
| sha2-128s | keygen | 5.409× | 5.407× | 5.428 [5.329–5.458] | 5.419 [5.360–5.435] | 0/0 |
| sha2-128s | sign | 5.247× | 5.254× | 5.256 [5.024–5.406] | 5.258 [5.182–5.307] | 0/0 |
| sha2-128s | verify | 5.187× | 5.152× | 5.121 [5.036–5.800] | 5.083 [5.019–5.568] | 0/0 |
| sha2-192f | keygen | 5.259× | 5.266× | 5.277 [4.970–5.387] | 5.272 [5.158–5.355] | 0/0 |
| sha2-192f | sign | 4.713× | 4.721× | 4.722 [4.646–4.770] | 4.723 [4.680–4.762] | 0/0 |
| sha2-192f | verify | 4.770× | 4.819× | 4.845 [4.055–5.018] | 4.840 [4.469–4.990] | 0/0 |
| sha2-192s | keygen | 5.272× | 5.281× | 5.295 [5.129–5.330] | 5.293 [5.222–5.318] | 0/0 |
| sha2-192s | sign | 4.532× | 4.531× | 4.533 [4.494–4.560] | 4.529 [4.503–4.552] | 0/0 |
| sha2-192s | verify | 4.252× | 4.273× | 4.385 [3.314–4.473] | 4.371 [3.507–4.451] | 0/0 |
| sha2-256f | keygen | 5.331× | 5.301× | 5.315 [5.136–5.501] | 5.299 [5.126–5.420] | 0/0 |
| sha2-256f | sign | 4.713× | 4.715× | 4.717 [4.676–4.743] | 4.718 [4.696–4.730] | 0/0 |
| sha2-256f | verify | 4.703× | 4.688× | 4.749 [4.328–4.814] | 4.741 [4.312–4.761] | 0/0 |
| sha2-256s | keygen | 5.368× | 5.305× | 5.255 [5.224–6.398] | 5.257 [5.223–5.782] | 0/0 |
| sha2-256s | sign | 4.187× | 4.244× | 4.257 [3.701–4.286] | 4.253 [4.168–4.276] | 0/0 |
| sha2-256s | verify | 4.342× | 4.369× | 4.465 [3.461–4.538] | 4.467 [3.664–4.513] | 0/0 |

The smallest individual wall ratio was 3.314× (SHA2-192s verification); its CPU ratio was 3.507×. SHA2-256s signing had a total-wall ratio of 4.187× and total-CPU ratio of 4.244×. Those observations remain in the dataset and do not support a universal 4.25× improvement floor.

The [earlier balanced experiment](../sha2-openssl/README.md) reported medians across six paired process rounds, with four cases averaged equally within each round: signing 4.27–5.28× and verification 4.41–5.29×. This pass uses new keys, a larger message/context corpus, a single operation of each kind per key, deterministic test-process entropy, and a different summary statistic. Its signing and verification gains agree in broad magnitude, while the lower ratios above show why the old minimum should not be transferred to new inputs. Key generation was not measured by that earlier experiment.

This is one order/input sensitivity pass, not a balanced repeated benchmark. Every liboqs candidate measurement preceded every liboqs baseline measurement, so variant order remains confounded with elapsed-time drift. The ten keys share a process per variant and are not ten independent process repetitions. No confidence interval is claimed. Fresh objects and buffers prevent application-level key caches from spanning operations; they do not erase CPU caches or other process state. Object construction, buffer allocation, validation, and operating-system entropy acquisition are outside the timed calls. CPU intervals additionally contain the two wall-clock reads. Results apply to this Apple M1 Pro arm64 host with the linked OpenSSL 3.6.4 backend; ordinary desktop scheduling can still affect individual wall measurements.

The completed candidate batch ran from `2026-10-12T02:01:37.806016+00:00` to `2026-10-12T02:01:44.638880+00:00`; the baseline ran from `2026-10-12T02:03:55.861116+00:00` to `2026-10-12T02:04:27.401693+00:00`. These local records establish liboqs candidate-first ordering. Cross-provider ordering belongs to the enclosing serial coordinator record.

Both variants generated 60 distinct measured keys and identical public-key, secret-key, and signature bytes. Every measured verification succeeded and every signature with the selected middle byte flipped was rejected outside the timers. This single tamper mutation is a consistency check, not exhaustive malformed-input validation. All six warmup seeds are distinct from the 60 measured seeds; smoke checks use a separate derivation domain.

The independent [audit.py](audit.py), which does not import the collection runner, reconstructs the complete input corpus, parses the native output archives, checks exact coverage and byte equality, recomputes all 180 matched operation pairs and 18 summary cells, and validates commands, timestamps, binaries, sources, backend, and the earlier seal. Its [machine-readable result](evidence/independent-check.json) binds the final summary and both raw result files. The original manifest has 303 listed files (8 build files, 8 experiment files, 287 production source files); checking the manifest itself brings the total to 304. All remain unchanged, as does production commit `b14f1b616f938698ebc0bf8b75b3736c30e1502c`.

The final [ready manifest](evidence/ready.json) binds the measured driver/runner sources and both driver binaries. [Candidate](evidence/final-candidate/result.json) and [baseline](evidence/final-baseline/result.json) result files bind their raw JSON lines and output archives. The shared output archive SHA-256 is `00d92a1912b4ab0f56811dd5810baa5514738b1462195a78343a47d609216a5f`. Preparation and smoke records, including the explicitly earlier `ready-pre-review.json`, are retained separately from final measurements. The acceptance regression checks pass, including rejection of incomplete or duplicate rows, wrong identities, failed verification/tamper verdicts, incorrect entropy consumption, and invalid timing values.

Recheck the recorded evidence without executing cryptographic benchmarks:

```sh
python3 libs/liboqs/experiments/ten-new-keys/check_runner.py
python3 libs/liboqs/experiments/ten-new-keys/audit.py
```
