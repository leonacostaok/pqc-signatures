# Bouncy Castle signing and verification experiments

This follow-up starts from official `bcgit/bc-java` revision `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. The earlier FORS bit-extraction change reduced allocation but did not establish a repeatable whole-verification latency gain. These experiments investigate separate alternatives against the original baseline; they do not silently incorporate that patch.

The objective is to reduce time or allocation for independent keys. No candidate may retain a key-dependent cache between API calls, change signing entropy, relax verification, or substitute a different signature algorithm. Allocation means bytes allocated per operation, not retained heap or peak memory.

## Decomposition

| Family | Signing work to separate | Verification work to separate |
| --- | --- | --- |
| ML-DSA | Key decoding; message representative; public matrix sampling; secret NTT; per-attempt gamma sampling; NTT and matrix multiplication; decomposition and challenge; rejection/hint work; signature encoding | Key/signature decoding and bounds; message representative; public matrix sampling; NTT and matrix multiplication; hint application; final encoding/hash/comparison |
| SLH-DSA | Message randomizer and digest; FORS index extraction, leaves and tree hashing; WOTS secret derivation, chains and compression; XMSS authentication/hypertree; signature serialization | Signature parsing; message digest; FORS indices, leaf/path hashes and root compression; WOTS chains and compression; XMSS authentication/hypertree; root comparison |

Stage probes explain where work occurs and test local hypotheses. Nested stages overlap, microbenchmarks change JIT context, and ML-DSA signing retries depend on inputs. Stage times must not be summed into a predicted full-operation latency. Full API calls are measured separately without stage instrumentation.

## Alternatives

| Candidate | Change | Main hypothesis |
| --- | --- | --- |
| ML matrix scratch | One rejection-sampling buffer per matrix expansion | Reduce per-polynomial allocations without changing sampling |
| ML gamma scratch | One temporary buffer per sampled vector | Reduce allocations within each signing attempt |
| ML combined | Both changes | Determine whether benefits combine and whether either alone suffices |
| SLH WOTS chain buffer | Copy caller input once, then write each hash result into the same operation-local buffer | Reduce repeated allocation in chain hashing while retaining independent outputs |

These are hypotheses until correctness gates and measurements complete. Other source-level ideas are retained only if a bounded experiment can isolate them.

## Measurement and correctness rules

Baseline and candidates use the same pinned sources, dependencies, compiler and runtime settings, with source/class/driver/corpus hashes recorded before execution. Fresh processes isolate alternatives; final timing is serialized after coordinated builds and tests stop. Warmup and measurement use disjoint corpora. Every timed API call gets a fresh signer/verifier, with key import boundaries stated explicitly; a fixed input corpus is not evidence of persistent key caching.

Every result is consumed and checked against a prepared exact-output oracle outside the clock. Negative verification, input ownership and independent native regressions gate timing. Stage checks compare complete stage outputs, including sampler refill and mutable-buffer reuse cases, rather than only a successful final boolean.

Exploratory screening uses a predeclared balanced process order and retains raw wall time, CPU time, per-thread allocation, garbage-collection activity and losing samples. A 3% latency improvement or 10% whole-operation allocation reduction is a practical screening threshold, not a statistical significance test. Promising candidates require an independent confirmation run before an upstream performance claim. Controls and source-equivalent variants help distinguish shared runtime noise from a code effect.

The original benchmark harness and its known audit limitations remain separate from these targeted production experiments.
