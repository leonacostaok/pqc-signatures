# OpenSSL SLH-DSA SHA-512 prefix experiment

The candidate caches the public `PK.seed || zero padding` SHA-512 prefix within one SLH-DSA operation for SHA2 security categories 3 and 5. Each H/T hash copies the complete prefix context before hashing its address and message. SHA2 category 1 and SHAKE are controls. There is no cache shared between API operations. This adds a SHA512 context allocation to each affected operation; the benchmark includes that setup and cleanup.

The baseline is OpenSSL commit `122db7eb076bf0625df87b91bcc2dccfaccc4900`. `sha512-prefix.patch` contains the production change and upstream regression tests. The independent review checks prefix length, full hash-context copying, deep clone ownership, allocation-failure cleanup, and secret lifetime. The added persistent context contains public data only. This is test and code-review evidence, not cryptographic certification.

## Reproduce

Create two source checkouts at the pinned commit, apply the patch to the candidate, then run from this repository:

```sh
libs/openssl/experiments/sha512-prefix-build.sh /absolute/baseline /absolute/candidate
python3 libs/openssl/experiments/sha512-prefix-gate.py --build libs/openssl/build/sha512-prefix --out results/openssl/experiments/sha512-prefix-final-gate.json
python3 libs/openssl/experiments/sha512-prefix-corpus.py --baseline libs/openssl/build/sha512-prefix/baseline/prefix-driver --candidate libs/openssl/build/sha512-prefix/candidate/prefix-driver --out libs/openssl/build/sha512-prefix/varied-corpus
```

The build script rejects identical baseline/candidate sources or binaries, mismatched source pins, and tracked candidate changes outside the recorded patch. The resource check requires the baseline to perform redundant prefix hashing and the candidate to avoid it, while both match independent full-input digest calculations. Shared vectors require exact keys and deterministic signatures, and expected acceptance or rejection. The varied corpus additionally checks three seeds, empty and long messages, contexts up to 255 bytes, and tampered signatures.

Final timing must run without other agent builds or tests. The runner refuses to overwrite an existing output. Each side of a pair runs in a fresh process; key import and one warmup precede timing. Every measured sign or verify call creates and frees its EVP context. Signatures use the deterministic mode for matched workloads. Cells are shuffled, and baseline/candidate order alternates equally within each fork. The report uses the median of within-fork median paired ratios and retains every raw pair, including losses.

```sh
python3 libs/openssl/experiments/sha512-prefix-bench.py --baseline libs/openssl/build/sha512-prefix/baseline/prefix-driver --candidate libs/openssl/build/sha512-prefix/candidate/prefix-driver --corpus libs/openssl/build/sha512-prefix/varied-corpus --gate results/openssl/experiments/sha512-prefix-final-gate.json --out results/openssl/experiments/sha512-prefix-final.json --forks 5 --rounds 6 --budget-ms 300 --exclusive-window-granted
```

The [final report](../../../docs/openssl/sha512-prefix.md) records signing gains of 1.094–1.195× and verification gains of 1.073–1.172× for affected SHA2-192/256 sets. Unchanged controls remain near parity. All raw losses are retained. The independent checker is `python3 libs/openssl/experiments/audit-final.py results/openssl/experiments/sha512-prefix-final.json --out /path/to/new-independent-check.json`. Exploratory pilot numbers are not final evidence. Measurements do not establish cold-start gains, other-architecture gains, or FIPS-provider behavior. The tested build does not enable the FIPS provider. Targeted sanitizer checks instrument the changed hash and context source, not all of libcrypto. OS caches are not flushed.
