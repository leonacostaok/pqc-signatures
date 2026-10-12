# OpenSSL ten-key candidate-first check

This sensitivity check uses ten distinct new deterministic seeds for each of the six SHA2 parameter sets and the unchanged SHAKE-128f control. Each variant starts a fresh process for each parameter. It first processes one separate warmup key, then measures key generation, deterministic signing and verification once for each of the ten new keys. Messages range from empty to 4,096 bytes and contexts from empty to 255 bytes. The candidate batch runs before the baseline batch; the complete six-provider schedule also places every candidate batch before any baseline batch.

The public EVP key-generation call includes creation and cleanup of its generation context. Signing and verification include creation, initialization and cleanup of their operation contexts. Key export, public-key import, input generation, output-buffer allocation, validation and key destruction occur outside timing. No key or operation object is reused across the ten cases. Signing uses each newly generated private key, and verification uses a separately imported public key. The production patch's existing operation-local public-prefix optimization remains enabled; no cross-call cache is added by the experiment.

Each measured operation records monotonic wall time and process CPU time. Every signature must verify, and a bit-flipped signature must fail outside timing. Complete encoded public keys, private keys and signatures are saved and compared exactly between variants. These are public deterministic test inputs, not operational keys. The new driver links the unchanged libraries from the previously validated production experiment; preparation verifies their recorded archive hashes and source commits, compiles both drivers with the same flags and checks ten separate smoke-domain keys for exact output equality before sealing the new inputs and binaries.

All 70 key/signature pairs matched byte for byte, and every valid/tampered signature check passed. On the four affected SHA2-192/256 sets, total-wall signing speedups were **1.108–1.194×** and verification **1.064–1.200×**. One affected individual verification call was slower; it is retained. The unchanged SHA2-128 and SHAKE control measurements remain in the table.

Speedup is total original time divided by total changed time across ten keys; above 1 is faster. CPU is process user plus system time. Losses count individual keys whose changed wall time exceeded the original.

| Parameter | Operation | Wall speedup | CPU speedup | Losing keys / 10 |
| --- | --- | ---: | ---: | ---: |
| SHA2-128f | keygen | 1.0004× | 1.0029× | 3 |
| SHA2-128f | sign | 1.0026× | 1.0020× | 4 |
| SHA2-128f | verify | 1.0123× | 1.0146× | 4 |
| SHA2-128s | keygen | 1.0067× | 1.0045× | 2 |
| SHA2-128s | sign | 0.9991× | 1.0030× | 2 |
| SHA2-128s | verify | 1.0197× | 1.0211× | 2 |
| SHA2-192f | keygen | 0.9863× | 0.9944× | 4 |
| SHA2-192f | sign | 1.1078× | 1.1041× | 0 |
| SHA2-192f | verify | 1.0642× | 1.0680× | 1 |
| SHA2-192s | keygen | 1.4473× | 1.0351× | 2 |
| SHA2-192s | sign | 1.1514× | 1.1467× | 0 |
| SHA2-192s | verify | 1.2003× | 1.1857× | 0 |
| SHA2-256f | keygen | 1.0475× | 1.0374× | 0 |
| SHA2-256f | sign | 1.1362× | 1.1161× | 0 |
| SHA2-256f | verify | 1.1031× | 1.1038× | 0 |
| SHA2-256s | keygen | 1.0171× | 1.0093× | 3 |
| SHA2-256s | sign | 1.1941× | 1.1918× | 0 |
| SHA2-256s | verify | 1.1774× | 1.1759× | 0 |
| SHAKE-128f | keygen | 1.0099× | 1.0075× | 5 |
| SHAKE-128f | sign | 1.0033× | 1.0028× | 2 |
| SHAKE-128f | verify | 1.0002× | 0.9987× | 5 |

The SHA2-192s key-generation wall ratio of 1.4473× is not evidence for a comparable computational gain: its process-CPU ratio is only 1.0351×. All individual observations remain in the raw evidence; this short pass does not establish the cause of the discrepancy.

See the [raw summary and per-key times](../../results/openssl/ten-key-order/summary.json), [independent cross-provider recomputation](../../results/ten-key-order/independent-check.json), [collector regression checks](../../results/openssl/ten-key-order/collector-regressions.json), and [global execution chronology](../../results/ten-key-order/execution/execution.json). This single candidate-first pass can expose sensitivity to new keys and reversed order; it cannot remove time-dependent machine load or establish a steady-state performance guarantee. It supplements the earlier balanced repeated comparison.

```sh
python3 libs/openssl/experiments/ten-key-order/run.py prepare --baseline-source /path/to/pinned-baseline --candidate-source /path/to/committed-candidate
python3 libs/openssl/experiments/ten-key-order/run.py run --side candidate --exclusive-window-granted
# Run all other providers' candidate batches before any baseline batch.
python3 libs/openssl/experiments/ten-key-order/run.py run --side baseline --exclusive-window-granted
python3 libs/openssl/experiments/ten-key-order/run.py summarize
```

Preparation and result directories must be new; commands refuse to replace existing evidence. This run uses OpenSSL baseline `122db7eb076bf0625df87b91bcc2dccfaccc4900` and candidate `cb722554afced3c3232104b15693c203734864cf` on the same Apple M1 Pro host as the earlier experiment.
