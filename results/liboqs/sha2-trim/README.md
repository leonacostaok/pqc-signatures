# Remove redundant test includes

Commit `dd039f5f899aefb24b86b94c4b5cba1b2ec39f2f` removes three redundant lines from `tests/CMakeLists.txt`. That directory already adds the OpenSSL include path before creating the private SHA-2 test target. `OQS_USE_SHA2_OPENSSL` is a dependent option requiring `OQS_USE_OPENSSL`, so the removed target-specific setting adds no needed configuration.

A fresh Release configuration and targeted build of `test_slh_dsa_sha2` passed, followed by successful private digest, incremental-update and copied-state checks. [Commands and log hashes](checks.json), [source/build identities](proof.json) and [exact cleanup](cleanup.patch) are retained. The build used the final trimmed source tree before its commit; committing changed no source files.

Only test build configuration differs from the measured full patch `b14f1b616f938698ebc0bf8b75b3736c30e1502c`. Production sources and algorithm configuration are identical, so this cleanup does not introduce a new cryptographic runtime variant. Ablation timings continue to identify the original full commit explicitly; no new performance measurement is claimed for these three removed test-build lines.
