# Ten-key candidate-first check

This follow-up measures ten distinct new test keys per parameter set, running every changed implementation before any original implementation. The [execution plan](../results/ten-key-order/plan.json) fixes the provider order: OpenSSL, liboqs, noble, CIRCL, RustCrypto and Bouncy Castle. The [coordinator](../common/run-ten-key-order.py) executes those six candidate batches serially, followed by those six baseline batches in the same order. It saves each command, working directory, start/end time, exit status and output hashes; a failed batch stops the sequence without deleting prior output.

| Provider | Parameters | Distinct measured keys per variant |
| --- | --- | ---: |
| noble | Three ML-DSA sets | 30 |
| liboqs | Six SLH-DSA SHA2 sets | 60 |
| CIRCL | Six SLH-DSA SHA2 sets and SHAKE-128f control | 70 |
| RustCrypto | Three ML-DSA sets | 30 |
| OpenSSL | Six SLH-DSA SHA2 sets and SHAKE-128f control | 70 |
| Bouncy Castle | Twelve pure SLH-DSA sets | 120 |

Each variant measures one key-generation, signing and verification call per key: 380 distinct keys and 1,140 primary calls per variant. RustCrypto additionally measures constructing a fresh signing key and signing in one timed call, using the same ten seeds per set. The keys are new relative to the preceding performance studies. Seeds, messages, contexts and signing entropy are matched within each provider; they are public deterministic test material. Preparation may check their expected outputs, but every measured parameter/variant starts a new process and generates fresh key objects. Warmups use separate seeds. The providers use their own pinned production patches and APIs, so this is not a ranking of libraries.

The primary speedup is total original wall time divided by total changed wall time over all ten keys for a parameter/operation. Reports also retain per-key times, paired ratios, their median/range and all losses. Process CPU time accompanies wall time; Bouncy Castle additionally records current-thread CPU because process CPU can quantize to zero for short calls. Full public-key, private-key and signature outputs are compared between variants, and tampered signatures must fail outside the measurement clocks.

Input decoding, caller-buffer preparation, output serialization and validation are outside timing. Each provider report specifies key import/decoding and operation-context boundaries. The production patches' operation-local prefix reuse remains part of CIRCL/OpenSSL, and RustCrypto still constructs its existing public-key cache; no benchmark cache substitutes for cryptographic work. The exact production source patches are unchanged.

This is one candidate-first sensitivity check, not a balanced repeated experiment. The ten keys vary inputs, but do not provide ten independent machine/process replicates. Fixed side order can confound implementation with temperature, background load and time drift; no sample is discarded or normalized away. Java uses two complete warmup pipelines per parameter to bound slow SLH-DSA preparation, so its short-run JIT behavior must not be presented as steady-state throughput. Other work for this comparison is paused during the serial run; ordinary desktop processes remain active.

The full serial run completed on 12 October 2026, from 02:01:29 to 02:06:34 UTC. The last changed batch finished at 02:03:46.849833; the first original batch started at 02:03:46.851953. All 12 batches exited successfully. All **380 public/private-key and signature pairs matched exactly**, and all recorded valid/tampered signature checks passed. These differential checks supplement the earlier vector and negative-test suites; they are not a cryptographic security certification.

| Provider | Signing speedup | Verification speedup | Interpretation |
| --- | ---: | ---: | --- |
| noble ML-DSA | 1.145–1.202× | 1.144–1.187× | Gains across all three sets; key generation 1.187–1.244×; no losing individual keys |
| liboqs SLH-DSA SHA2 | 4.187–5.287× | 4.252–5.302× | Large gains reproduced across all six sets; key generation 5.259–5.439×; no losing individual keys |
| CIRCL SLH-DSA SHA2 | 1.313–1.390× | 1.297–1.429× | Gains across all six changed sets; key generation 1.310–1.386×; no affected losing individual keys |
| RustCrypto ML-DSA | 1.027–1.062× including fresh-key construction | No new claim | Constructor 1.144–1.191×; some individual losses remain; ordinary sign/verify are controls |
| OpenSSL SLH-DSA SHA2-192/256 | 1.108–1.194× | 1.064–1.200× | Gains across the four affected sets; one affected verification key lost |
| Bouncy Castle pure SLH-DSA | Mixed | 0.878–1.068× | No reliable general latency gain; prior allocation improvement remains a separate result |

Ranges are per-parameter ratios of total original wall time to total changed wall time across ten keys. They are not confidence intervals. CIRCL's SHAKE verification control is 0.9994×. OpenSSL controls include a 0.9991× signing result. Its SHA2-192s key-generation wall ratio of 1.4473× accompanies only 1.0351× CPU, so it is not promoted as a comparable computational improvement. Bouncy Castle SHAKE-192f is slower for key generation, signing and verification (0.9181×, 0.9316× and 0.8777×), with 8, 9 and 8 losing keys respectively. Fixed order and short Java warmup limit causal conclusions; no loss is removed or assigned an unproven cause.

The [independent checker](../common/audit-ten-key-order.py) recomputes 117 table cells from 1,170 paired operation timings, checks distinct keys, exact output equality and the global serial chronology, and saves [all totals, CPU totals, individual ratios and losses](../results/ten-key-order/independent-check.json). Each provider's own stricter runner additionally binds its source/build/input manifest and validates raw completion evidence. Earlier balanced repeated studies remain in [the provider improvement index](provider-improvements.md).

Detailed protocols and evidence: [liboqs](../libs/liboqs/experiments/ten-new-keys/README.md), [CIRCL](circl/ten-key-order.md), [RustCrypto](rustcrypto/tenkey-sensitivity.md), [OpenSSL](openssl/ten-key-order.md), [Bouncy Castle](bouncycastle/tenkey-sensitivity.md). Noble's separate evidence commit is linked below after publication.

To reproduce the independent calculation, obtain both evidence branches, then run `python3 common/audit-ten-key-order.py --provider-root noble=/path/to/noble-evidence-checkout --out /path/to/new-independent-check.json` from this evidence checkout. Use repeated `--provider-root name=/path` options if the other provider evidence is also held in separate checkouts. Recorded absolute source/build paths describe the original machine and must be rebuilt for new measurements.
