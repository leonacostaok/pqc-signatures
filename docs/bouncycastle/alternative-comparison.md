# Bouncy Castle alternatives

This campaign tests individual implementation changes against bc-java `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. It follows the [pattern research](pattern-research.md). Three Astra agents prepared independent NTT, matrix and WOTS experiments; the coordinating agent ran additional pinned native tests and serialized performance collection. This is AI-assisted supporting engineering and test work, not independent cryptographic certification.

## Alternatives and boundaries

| Group | Separate alternatives | Intended saving | Potential cost |
|---|---|---|---|
| ML-DSA NTT | Fold final inverse scaling; precompute public twiddle companions; combine those two changes | Fewer reductions or a shorter multiplication dependency | Extra constant loads and 1,024 bytes of static array payload for companions; different intermediate modular representatives for fusion |
| ML-DSA matrix | Reduce once per dot product; stream one matrix row; combine those two changes | Fewer reductions; fewer simultaneously allocated public matrix rows | Changed traversal can cost CPU; streaming applies to keygen/verification, while signing keeps its full matrix |
| SLH-DSA WOTS | Hoist one address object; remove redundant field clearing; use separate PRF/hash addresses; reuse chain output buffers; peel the buffer loop's first hash | Fewer temporary objects, field writes or copies | Extra address objects in some paths, aliasing constraints and different JIT behavior |

These changes preserve algorithm parameters and encoded key/signature sizes. They introduce no persistent key cache. Reusing a temporary row or buffer within one operation does not depend on seeing the same key again. Measurements include fresh operation objects and ordinary initialization; key import and validation of outputs remain outside the measured operation. The reports specify other boundary differences, so the three campaigns must not be pooled into a cross-group absolute-speed ranking.

Measured batches use distinct keys once per process: 128 for ML-DSA and 10 for SLH-DSA. Warmup keys are separate. Process order reverses within each comparison, and allocated-byte collection runs separately from timing. Repeated processes reuse the same input corpus for paired comparisons. These are bounded exploratory screens; a large iteration count inside a small number of processes does not establish statistical confidence across machines or JVM versions.

## Additional native correctness checks

Every one of the eight ML-DSA builds passed the complete pinned `MLDSATest` and `MLDSAWycheproofTest`: 14 and 3 native methods respectively. These cover ACVP vectors, pure/prehash/external-message rejection paths, encoding checks and 631 Wycheproof verification cases per build. Every one of the six WOTS builds passed four selected native `SLHDSATest` methods, with full verification-vector sampling enabled, plus the agents' exact-output checks across all 12 parameter sets. Full native SLH-DSA signing-vector suites were not repeated; the earlier full baseline/candidate suite took about 29 minutes per run.

The native runner verifies that the changed arithmetic/address classes load from the selected variant and checks its class hashes before and after execution. Test vectors are pinned to bc-test-data `3c385e9f4c0b12ce5a86d2b29a17fb3b68dd4e1a`. [Saved native records](../../results/bouncycastle/alternative-comparison/native/) and the [reproduction scripts](../../libs/bouncycastle/experiments/alternative-comparison/) preserve commands, class/source identities and outputs. Saved-evidence checking is distinct from rerunning the cryptographic tests.

## Interpretation

Results are pending. No new optimization is recommended from correctness checks alone. Allocation means bytes allocated by the calling thread per operation, not peak live heap, resident memory or stack use. Lower allocation can reduce GC pressure, but this campaign does not infer a GC-pause percentage from allocated bytes. All controlled builds and tests stop during each benchmark window; OS and user background activity remains. In particular, `fseventsd` consumed substantial CPU in pre-run snapshots, so this is not an isolated host.
