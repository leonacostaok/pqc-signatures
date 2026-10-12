# OpenSSL SLH-DSA SHA-512 prefix

The patch completes OpenSSL's existing per-operation public-prefix caching for SLH-DSA SHA2 security categories 3 and 5. H/T hashes currently repeat the same padded public seed block; the candidate saves its SHA-512 state once and copies it before processing each address and message. It adds one 216-byte context allocation per affected operation. SHA2 category 1 and SHAKE remain controls. There is no state shared across signing or verification operations.

## Scope and correctness

The baseline is OpenSSL `122db7eb076bf0625df87b91bcc2dccfaccc4900` (4.2.0 development); the production candidate is `cb722554afced3c3232104b15693c203734864cf`. The [patch](../../libs/openssl/experiments/sha512-prefix.patch) includes production code and an upstream regression test. The cached state depends only on public `PK.seed` and padding. The patch preserves digest input order, addresses, randomness, encoding and validation. Context duplication copies the complete state into separately owned storage; freeing clears that storage. It does not extend secret-key lifetime. Review is not a formal side-channel proof or cryptographic certification.

The [final gate](../../results/openssl/experiments/sha512-prefix-final-gate.json) binds the tested binaries to 216 shared vector/negative cases and six byte-matched reference cases per variant. An actual-source hash test checks 768 full-input SHA-256/SHA-512 results and context ownership: the baseline processes 65,536 redundant prefix bytes and the candidate processes none. Both variants match the digest oracle. The [varied corpus](../../results/openssl/experiments/sha512-prefix-varied-corpus-final.json) covers all six SHA2 parameter sets plus SHAKE-128f, three seeds, messages of 0/64/4096 bytes, contexts of 0/17/255 bytes, byte-identical deterministic keys/signatures, and tampered-signature rejection.

The [upstream SLH-DSA recipe](../../results/openssl/experiments/sha512-prefix-upstream-tests-final.txt) passes, including the new internal test; its FIPS-provider leg is skipped because the tested build does not enable that provider. [Targeted ASan/UBSan checks](../../results/openssl/experiments/sha512-prefix-sanitizer-final.txt) instrument the changed hash/context source; the rest of libcrypto is uninstrumented. The [optional no-deprecated compile check](../../results/openssl/experiments/sha512-prefix-no-deprecated.json) records failure before the header fix and success after it. [Runner regression checks](../../results/openssl/experiments/sha512-prefix-gate-regression.json) reject empty/duplicate suites and incomplete correctness evidence before timing starts.

## Measurement

The [final run](../../results/openssl/experiments/sha512-prefix-final.json) contains 1,260 balanced pairs. An [independent recomputation](../../results/openssl/experiments/sha512-prefix-independent-check.json) verifies every pair, all 42 case/operation cells and the following parameter summaries. Each parameter summary gives equal weight to the three fixture latencies on each side within a round, takes their baseline/candidate ratio, then takes the median of six rounds within each fork and the median of five forks. Ratios above 1 mean faster execution.

| Parameter | Sign wall | Sign CPU | Verify wall | Verify CPU |
| --- | ---: | ---: | ---: | ---: |
| SHA2-128f | 0.9976× | 0.9980× | 1.0002× | 1.0000× |
| SHA2-128s | 1.0009× | 1.0003× | 0.9994× | 0.9992× |
| SHA2-192f | 1.0944× | 1.0944× | 1.0730× | 1.0733× |
| SHA2-192s | 1.1360× | 1.1351× | 1.1721× | 1.1715× |
| SHA2-256f | 1.1006× | 1.1005× | 1.0821× | 1.0819× |
| SHA2-256s | 1.1952× | 1.1935× | 1.1497× | 1.1495× |
| SHAKE-128f | 1.0004× | 1.0005× | 0.9999× | 0.9992× |

Affected SHA2-192/256 signing improves 1.094–1.195× and verification 1.073–1.172×. All 120 affected case-level fork medians exceed 1; 12 of the 720 individual affected pairs lose and remain in the data. SHA2-128 and SHAKE controls stay near parity. Process CPU ratios agree closely with wall-time ratios. These are operation-local prefix reuse gains, with the added 216-byte context and its allocation included; they do not establish a no-reuse implementation advantage.

The controlled run uses one M1 Pro host, five forks, six balanced baseline/candidate rounds and 21 varied fixtures. Each side runs in a fresh process. Key import and one full warmup precede timing; each measured public EVP operation creates and frees its operation context, including prefix setup and cleanup. Deterministic signing gives matched workloads. Cases are shuffled, and execution order is balanced within every fork. Both wall and process CPU time cover the same operation loop. Baseline calibration determines matched iteration counts; the final statistic is the median of five within-fork median ratios. All pairs, controls and losses remain in the report.

These measurements do not cover cold start, key import, the FIPS provider or another architecture. Desktop processes remain active, although other agents' builds and tests are stopped. OS file caches are not flushed. The [source-binding check](../../results/openssl/experiments/sha512-prefix-source-binding-check.json) independently confirms the archived corpus, gate, binaries, experiment files and production diff match the measured inputs. See [provenance](../../results/openssl/experiments/sha512-prefix-final-provenance.json) and [reproduction instructions](../../libs/openssl/experiments/README.md). Python assertions must remain enabled (`PYTHONOPTIMIZE` unset, no `-O`).
