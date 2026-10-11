Constructing an ML-DSA signing key with `alloc` repeats public-key arithmetic already performed during key generation. Reuse `t1` and its encoding when building the cached verification key to avoid the second matrix product, inverse NTT, rounding pass and encoding.

[Measurements and methodology (private repository)]({{immutable_evidence_url}}).
