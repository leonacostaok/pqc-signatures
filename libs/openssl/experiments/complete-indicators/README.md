# C-provider completion indicators

This supporting experiment fills missing baseline timings and resource indicators for the published liboqs and OpenSSL changes. It does not invent candidate timings for algorithms the patches do not change. Source, compiled libraries, deterministic fixtures, correctness results, process commands, raw output, exit codes and collector versions are bound by manifests. Previous benchmark files and production patches remain unchanged.

| Measurement | Boundary and denominator |
|---|---|
| Missing baseline time | Three fresh processes per parameter/action, ten distinct fixture keys repeated across processes, one disjoint warmup; arithmetic mean of all 30 calls. No candidate or improvement percentage. Wall and process CPU clocks enclose the same public operation. |
| Operation allocations | Four matched distinct keys per side in fresh processes, after a disjoint warmup. OpenSSL allocator hooks also capture the configured OQS allocation entry points. Requested bytes, allocation count, tracked live-byte peak, bytes retained at API return, and net bytes after cleanup. Percentage uses original arithmetic mean. |
| Process peak RSS | Separate cold processes; Darwin `getrusage(RUSAGE_SELF).ru_maxrss` in bytes before and after the operation. Four samples per side, original/candidate medians as percentage denominator. Includes runtime, fixtures, key import and process overhead; small differences may be noise. |
| Stack diagnostic | Caller-owned 16 MiB guarded thread stack, painted before thread creation and scanned after join. Report observed overwritten extent, including thread startup/exit; this detects changed bytes, not exact peak reservation or a formal maximum. Four keys with `0xa5`, separate no-op controls with both patterns, and `0x5a` checks for representative SHA256/SHA512 paths. The no-op floor is not subtracted. |

Resource pairs use side orders AB, BA, BA, AB over the four keys. Stack-paint processes are separate from RSS processes because painting touches many pages. Resource runs do not produce latency claims. Where the original denominator is zero, percentage change is null with a reason. Fields not measured by a mode are null or absent in the summary even though the compact raw driver uses zero placeholders.

liboqs calls include `OQS_SIG_new`, the public keypair/sign/verify API, and `OQS_SIG_free`; caller-provided output buffers are outside the measured operation. OpenSSL calls include creation and cleanup of an EVP operation context; encoded-key import is outside. A newly generated EVP key remains live at API return and is then freed for net-live accounting. Signature generation uses controlled test entropy or the public deterministic option. Every result matches a baseline fixture byte-for-byte, and both variants reject a tampered signature in preparation. Caller input integrity is checked after every measured operation.

`prepare.py` builds and checks liboqs fixtures; `prepare-openssl.py` supplies OpenSSL source headers alongside generated headers. `seal.py` verifies the published runtime matches the frozen measured implementation and binds the collector. `collect.py` runs one serial phase only after an exclusive measurement window is granted. `summarize.py` verifies all process exits, identities, order, raw hashes and output checks before producing baseline-only timings and separate resource records. `test_collect.py` checks rejection of incomplete and malformed evidence.

```sh
python3 libs/openssl/experiments/complete-indicators/collect.py --manifest READY.json --phase baseline-timing --out NEW-TIMING-DIRECTORY
python3 libs/openssl/experiments/complete-indicators/collect.py --manifest READY.json --phase resources --out NEW-RESOURCE-DIRECTORY
python3 libs/openssl/experiments/complete-indicators/summarize.py --manifest READY.json --timings TIMING-DIRECTORY --resources RESOURCE-DIRECTORY --out SUMMARY.json
```

Preparation and supportive tests were AI-assisted. Raw observations and explicit validation gates support the reported measurements; neither the assistance nor these probes constitutes a security certification.
