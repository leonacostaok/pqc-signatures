# Ten new keys: candidate-first sensitivity check

The completed pass and independently checked results are in [RESULTS.md](RESULTS.md).

This separate experiment reuses the unchanged liboqs baseline `fd44469daeffe6b28f031f54f9bb66cbae69a572` and production candidate `b14f1b616f938698ebc0bf8b75b3736c30e1502c`. It preserves the earlier sealed experiment, production patch, and measured data. The new driver links the same static archives and OpenSSL 3.6.4 backend.

Each of the six SHA2 SLH-DSA parameter sets receives ten distinct deterministic test seeds, matching messages, contexts, and signing entropy in both variants. Messages span 0–8192 bytes and contexts 0–255 bytes. A separate seed warms each parameter before its ten measured keys; correctness smoke checks use a third disjoint domain. Input derivation is SHA256 over a documented label/counter domain, and the complete input bytes and per-case seed hashes are archived. These are public synthetic test keys, unsuitable for real use.

The driver calls public `OQS_SIG_keypair`, `OQS_SIG_sign_with_ctx_str`, and `OQS_SIG_verify_with_ctx_str` once each per measured key, in that order. The test-process `OQS_randombytes_custom_algorithm` callback supplies exactly 3n keygen seed bytes and n signing entropy bytes, failing on unexpected consumption. The timed work includes copying these fixed entropy bytes but excludes operating-system entropy acquisition. This exercises native public key generation and signing without any production RNG change; it is not a randomized-entropy cost benchmark.

Fresh OQS objects are created for each operation, and fresh key/signature/message/context buffers for each key. Object construction and buffer allocation are outside the timers; no decoded-key or stage cache is carried across operations. Wall time uses `CLOCK_MONOTONIC`; process user+system CPU uses `CLOCK_PROCESS_CPUTIME_ID`. Native API calls are timed, including key-dependent hash setup and the candidate's cleanup. Return codes, lengths, seed/key encoding, valid signature verification, and tamper rejection are checked outside the clock intervals. Every measured key produces archived public-key, secret-key, and signature bytes, compared exactly after both phases. No first-key signing/verification precheck warms that same key before its measured operations.

Preparation compiles only the new driver, runs the acceptance regression checks separately, and compares six smoke keys per variant. Final collection requires unchanged source, static archives, original sealed inputs, driver binaries, corpus, OpenSSL backend, and environment. Incomplete processes retain raw logs but do not emit a complete result. Output files cannot be overwritten. The candidate batch must complete before the baseline batch; cross-provider candidate-first ordering is enforced by external serial scheduling and checked using archived phase timestamps.

```sh
python3 libs/liboqs/experiments/ten-new-keys/check_runner.py
python3 libs/liboqs/experiments/ten-new-keys/run.py prepare
# Run each following command only in its granted exclusive phase.
python3 libs/liboqs/experiments/ten-new-keys/run.py measure --variant candidate --exclusive-window
python3 libs/liboqs/experiments/ten-new-keys/run.py measure --variant baseline --exclusive-window
```

Primary reporting is baseline total wall time divided by candidate total wall time over ten matched keys, separately for each parameter and operation. Also retain both CPU totals, per-key ratios, their median/range, and losses. This is one candidate-first then baseline sensitivity pass, with no extra forks or filtering. Variant order and elapsed-time drift are confounded; it cannot replace the earlier balanced repeated experiment or support independent-fork confidence intervals. Preparation and smoke records are distinct from the completed final measurement records.
