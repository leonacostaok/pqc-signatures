SLH-DSA uses portable SHA-2 compression even when the OpenSSL SHA-2 backend is enabled. Use OpenSSL's SHA-256 and SHA-512 block transforms while preserving existing hash states and clearing temporary contexts. Builds without the required OpenSSL APIs retain portable compression.

Related to [liboqs #2204](https://github.com/open-quantum-safe/liboqs/issues/2204). Cryptographic outputs, supported algorithms, and public APIs are unchanged.

[Tests and measurements (private repository)](https://github.com/leonacostaok/pqc-signatures/blob/PRIVATE_EVIDENCE_COMMIT/libs/liboqs/experiments/sha2-openssl/README.md)
