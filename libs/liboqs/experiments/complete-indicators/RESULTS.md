# liboqs completion measurements

For the tested Apple M1 Pro/OpenSSL backend, the speed gain remains a favorable tradeoff: the earlier [balanced ablation](../sha2-ablation/RESULTS.md) reports 4.268–5.295× signing and 4.345–5.279× verification ratios, corresponding to about 76.6–81.1% and 77.0–81.1% less elapsed time. The new full-public-operation allocation probe finds no additional tracked heap cost. Observed overwritten stack depth increases by at most 312 bytes, or 7.69%, in these calls. This is a target-specific assessment; tight-stack applications still need their own complete build and worst-case analysis.

The backend uses deprecated public OpenSSL Transform APIs, with portable fallbacks for unsupported build configurations. The earlier [source/cleanup audit](../resource-audit/README.md) covers those guards and secret-state clearing; no measured gain is claimed for the fallback, other architectures or FIPS deployment.

The [summary](../../../../results/liboqs/complete-indicators/summary.json) adds 33 baseline timing cells: ML-DSA-44/65/87, all six SLH-DSA-SHAKE sets, and Falcon-512/1024, each with keygen/sign/verify. Each cell is the mean of 30 checked calls over ten distinct keys repeated in three fresh processes, with one disjoint warmup per process. These unchanged paths have no candidate comparison. This protocol includes public operation-object setup and differs from the earlier affected-path timing protocols; it must not be used for cross-provider rankings.

All 18 SHA2 parameter/operation cells request **88 → 88 bytes in one → one tracked allocation**, with tracked peak live bytes also **88 → 88** and zero retained/net bytes after return/cleanup. These bytes are the `OQS_SIG` operation object included in the boundary. Hooks cover the configured OpenSSL/OQS allocator entry points; caller-owned buffers, fixture storage, arbitrary system allocations and allocator metadata are outside this metric. This extends the earlier private-hash allocation probe to the complete public calls without claiming universal zero allocation.

| SHA2 sets | Operation | Observed stack bytes, original → candidate | Change |
|---|---|---:|---:|
| 128f / 128s | keygen | 3,960 → 3,968 | +0.20% |
| 128f / 128s | sign | 5,304 → 5,312 | +0.15% |
| 128f / 128s | verify | 4,184 → 4,176 | −0.19% |
| 192f / 192s | keygen | 4,056 → 4,128 | +1.78% |
| 192f / 192s | sign | 5,400 → 5,472 | +1.33% |
| 192f / 192s | verify | 4,232 → 4,304 | +1.70% |
| 256f / 256s | keygen | 4,056 → 4,368 | +7.69% |
| 256f / 256s | sign | 5,416 → 5,728 | +5.76% |
| 256f / 256s | verify | 4,232 → 4,544 | +7.37% |

Stack values are medians of four matched-key fresh-process diagnostics. A separate caller-owned guarded thread stack is painted before thread creation and scanned after join. This measures observed overwritten extent including thread startup/exit, not reserved frames or a proven operation maximum. The no-op floor is 272 bytes with both paint patterns on both variants and is not subtracted. Representative `0x5a` measurements match the `0xa5` observations. Earlier [compiler-frame measurements](../../../../results/liboqs/resource-audit/STACK.md) remain distinct: local frame increases reach 240 bytes, and cannot be summed to obtain a complete call-stack peak.

Separate cold-process peak-RSS medians range from 1,916,928–2,621,440 original bytes and 1,892,352–2,605,056 candidate bytes. Per-cell post-operation median changes range from −1.28% to +0.41%; all four pre/post observations and percentage denominators are retained in the summary. These process values include the runtime, corpus and other overhead, and do not establish a memory reduction or resolve the small operation-level changes.

All 99 baseline timing and 440 resource processes completed successfully. Exact public-key/secret-key/signature parity, valid verification and unchanged inputs were checked outside measurement boundaries; both variants rejected the selected tampered signatures during preparation. Every tracked allocation was freed. The [independent local check](../../../../results/liboqs/complete-indicators/independent-local-check.json) rechecks source/build/input hashes and raw outputs and independently recomputes the 33 timing and 18 resource cells. The earlier latency evidence retains all observed results, including individual ratios well below a universal 4× floor; no new affected-path timing claim comes from the resource runs.

The [ready manifest](../../../../results/liboqs/complete-indicators/ready.json) binds upstream `fd44469`, signed published `94b42a7`, and the frozen measured runtime `b14f1b6`. New unchanged-path baseline algorithms use the separately recorded baseline build. [The common protocol and commands](../../../openssl/experiments/complete-indicators/README.md) describe exact boundaries and reproduction. Initial unavailable-Ninja configuration evidence is preserved; the subsequent Makefile build and every final collection passed. No production source or previous evidence was modified.

For a checkout without the original local builds, run `python3 libs/openssl/experiments/complete-indicators/independent-check.py --provider liboqs --out /path/to/check.json`. The default checks committed source/configuration snapshots, fixture bytes, raw outputs and summary arithmetic through the [artifact inventory](../../../../results/liboqs/complete-indicators/artifact-inventory.json); it explicitly lists unverified compiled artifacts. Add `--local-builds` to require the original absolute paths and rehash their binary bytes as well. The original local checker execution and its versioned source are retained separately; replaying saved evidence is not a fresh benchmark or build.

Both the [saved-only replay](../../../../results/liboqs/complete-indicators/independent-saved-check.json) and the local mode passed. The shared [saved-reader tests](../../../../results/openssl/complete-indicators/saved-reader-tests.json) pass while denying reads outside the checkout and under ignored build directories, and reject missing rows, wrong means and missing source snapshots.
