# Resource and regression audit of PR 1461

The published change introduces no observed allocation increase or key-size increase in this audit. All four operation boundaries have exactly matching original/changed allocation counters across the scoped cases and feature configurations. The original uninstrumented timing executable also reserves smaller individual constructor frames for the candidate. Existing latency losses and the library's optional zeroization remain relevant limits; this does not establish universally unchanged memory or faster existing-key operations.

This audit concerns [RustCrypto/signatures PR 1461](https://github.com/RustCrypto/signatures/pull/1461), checked at head `43cad14d86b36607a3c4b47c59c30d91145f64c1` against `a84081789729c96dabb35f96cd000e434b247e02`. The [source binding](../../results/rustcrypto/resource-audit/source-binding.json) verifies that the signed head has exactly the old measured commit's tree and that every algorithm source file in old/new evidence equals its canonical Git revision. It preserves all earlier snapshots and results. No new latency benchmark or production change was made.

## Ownership, lifetime and feature behavior

The patch does not add a cache or enlarge the returned key types. `SigningKey` already owns its expanded key, seed and, with `alloc`, cached `VerifyingKey` ([signing.rs:38–47](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/signing.rs#L38)). The changed block fills that existing verification key from `rho`, `t1`, a cloned public matrix and the already encoded public key ([signing.rs:78–90](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/signing.rs#L78)). The old derivation already cloned the same matrix into the same constructor ([signing.rs:561–568](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/signing.rs#L561)). `VerifyingKey::new` still owns `t1` and its precomputed matrix/hash values through the same `MaybeBox` fields ([verifying.rs:19–41](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/verifying.rs#L19), [construction:58–71](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/verifying.rs#L58)). No shared mutable cache, reference into another key, or cross-key lifetime is introduced.

The allocating `Keypair` behavior still clones the stored verification key, while `AsRef` borrows it; without `alloc`, `verifying_key()` derives it afresh ([signing.rs:159–179](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/signing.rs#L159)). This caller-owned clone is outside the new allocation boundaries, as it was outside the original constructor timing. Ordinary signing and verification paths are unchanged. The changed cache block is conditional on `alloc`; it is absent from the no-alloc build.

Default library features do not include `zeroize`; the prior timed experiment explicitly enabled it. The secret seed and expanded-key Drop implementations are unchanged ([seed drop:223–227](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/signing.rs#L223), [expanded-key drop:645–658](https://github.com/leonacostaok/signatures/blob/43cad14d86b36607a3c4b47c59c30d91145f64c1/ml-dsa/src/signing.rs#L645)). Expanded-key drop clears secret vectors and their transforms when enabled; the public matrix is not secret. Unchanged Drop code does not prove that all temporary copies or stack storage are scrubbed. The changed construction order also changes when temporary values are consumed into the expanded key, so equal type sizes alone cannot establish equal temporary lifetimes or peak stack use.

## Accounting method

The separate probe builds exact original and published source snapshots with four feature configurations: default, default plus zeroize, alloc-only plus zeroize, and no-alloc plus zeroize. Package identities/workspace membership are adapted only to link both variants; algorithm sources differ solely in `signing.rs`. Four synthetic seeds per parameter cross message lengths 0/1/128/1024 and context lengths 0/1/31/255. A complete untimed correctness pass seals exact output digests before accounting. During collection, exact public/private encodings and signatures are compared internally across variants and fresh-key paths, with valid/tampered verification after operation boundaries. Private encodings are never serialized into the audit output.

A single-thread global allocator forwards to `System` and counts successful requested allocations/deallocations, requested bytes, live-byte change and its peak above entry. Each operation's output remains alive when accounting stops. Separate key/fresh-key drops must balance retained bytes exactly; no-alloc counters must remain zero and reallocations must remain absent. Public-key extraction/cloning, input construction, output encoding, digest generation and correctness checks are outside the boundaries. Fresh-key signing retains both its key and signature until the separate drop. These counters describe requested storage seen by this instrumented executable, not allocator metadata, resident memory, total process heap or latency.

For allocated keys, the probe observes exactly the initialized 32-byte seed allocation immediately before forwarding deallocation to `System`. It reports only whether that allocation was observed and all bytes were zero. It does not inspect expanded-key padding, freed storage or secret buffer contents, and it does not establish full expanded-key or stack clearing. A no-alloc seed has no corresponding heap deallocation to observe. Allocator hooks can alter optimization and code generation, so their frames and execution time are not used as production performance evidence.

## Verified allocation and sizes

The [complete accounting](../../results/rustcrypto/resource-audit/accounting.json) passes every source/binary/output seal, equality check, lifetime check and deallocation balance. All twelve cases in each feature configuration have identical counters across variants. The three allocating configurations produce the same following counts and requested bytes; for these calls, peak newly live bytes and bytes retained at return equal the requested total. Sizes include the operation's returned internal representation, with encoding outside the boundary.

| Parameter | Key construction, 4 allocations | Fresh-key sign, 6 allocations | Existing-key sign, 2 allocations | Existing-key verify |
| --- | ---: | ---: | ---: | ---: |
| ML-DSA-44 | 65,760 B | 70,880 B | 5,120 B | 0 B / 0 allocations |
| ML-DSA-65 | 108,768 B | 115,424 B | 6,656 B | 0 B / 0 allocations |
| ML-DSA-87 | 178,400 B | 187,616 B | 9,216 B | 0 B / 0 allocations |

The no-alloc configuration reports zero allocation, deallocation and retained heap bytes for every scoped operation. The output objects instead contain substantial inline storage. Every allocating key/fresh-key drop releases exactly the bytes retained by construction/fresh-key signing; no reallocations occur. Seed deallocation is observed and zero-filled with alloc+zeroize. It is observed and not zero-filled in both default implementations. No heap seed deallocation occurs in the no-alloc configuration. This default behavior predates the PR and is not a new regression.

| Parameter | Allocating SigningKey / VerifyingKey | ExpandedSigningKey | No-alloc SigningKey / VerifyingKey | Allocating / no-alloc Signature |
| --- | ---: | ---: | ---: | ---: |
| ML-DSA-44 | 64 / 48 B | 41,088 B | 41,120 / 24,672 B | 48 / 5,152 B |
| ML-DSA-65 | 64 / 48 B | 65,664 B | 65,696 / 43,104 B | 64 / 6,704 B |
| ML-DSA-87 | 64 / 48 B | 104,576 B | 104,608 / 73,824 B | 80 / 9,280 B |

Every size is equal between original and changed types. Allocating object sizes exclude their owned boxes; the earlier allocation table captures those returned heaps. Type sizes are neither encoded sizes nor stack high-water measurements. The encoded public/private-expanded/signature lengths also remain equal: 1,312/2,560/2,420 B, 1,952/4,032/3,309 B and 2,592/4,896/4,627 B respectively; seeds remain 32 B.

## Constructor frame inspection

The [frame evidence](../../results/rustcrypto/resource-audit/constructor-frames.json) inspects the original frozen Rust 1.93 arm64 release/default+zeroize timing executable, whose hash is checked against its original manifest. It is not the allocator-instrumented executable. The six `from_seed` prologues reserve a saved-register block, a fixed page-probe loop and a final tail. Parameter mapping is inferred from each function's unique encoded-public-key length immediate; complete disassemblies and arithmetic are retained.

| Parameter | Original constructor frame | Changed constructor frame | Difference |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 182,384 B | 142,352 B | −40,032 B |
| ML-DSA-65 | 214,736 B | 176,800 B | −37,936 B |
| ML-DSA-87 | 398,704 B | 343,328 B | −55,376 B |

These particular constructor frames shrink. They remain substantial, and exclude caller/callee frames, transient stack depth and stack scrubbing. No total stack high-water measurement was made. This result does not generalize to no-alloc builds, different optimization settings, compilers or targets; neither equal type sizes nor these prologues prove a universal stack guarantee.

## Retained timing negatives

The [loss inventory](../../results/rustcrypto/resource-audit/prior-losses.json) retains every losing raw pair from the earlier repeated run and every losing key from the ten-key pass, with hashes of the original files. The repeated run has five forks and thirty pairs per operation/parameter. Although all constructor/fresh-key-sign fork medians improve, some individual pairs lose. The table records those losses alongside the later one-pass sensitivity results; ratios below one favor the original.

| Parameter / operation | Losing forks / 5 | Losing pairs / 30 | Ten-key losses / 10 | Worst ten-key ratio |
| --- | ---: | ---: | ---: | ---: |
| ML-DSA-44 / constructor | 0 | 1 | 1 | 0.9837 |
| ML-DSA-65 / constructor | 0 | 0 | 0 | 1.0006 |
| ML-DSA-87 / constructor | 0 | 0 | 0 | 1.1525 |
| ML-DSA-44 / fresh-key sign | 0 | 0 | 2 | 0.6646 |
| ML-DSA-65 / fresh-key sign | 0 | 2 | 0 | 1.0158 |
| ML-DSA-87 / fresh-key sign | 0 | 0 | 1 | 0.9409 |
| ML-DSA-44 / existing-key sign | 2 | 14 | 6 | 0.9759 |
| ML-DSA-65 / existing-key sign | 2 | 13 | 4 | 0.9785 |
| ML-DSA-87 / existing-key sign | 2 | 16 | 2 | 0.9932 |
| ML-DSA-44 / verify | 2 | 14 | 6 | 0.9715 |
| ML-DSA-65 / verify | 3 | 15 | 5 | 0.9788 |
| ML-DSA-87 / verify | 2 | 15 | 2 | 0.9259 |

The repeated ML-DSA-44 existing-key signing control includes a 0.9224 fork median, and ML-DSA-65 verification has a 0.9999 overall median. The original report retained low CPU/wall ratios in the former, consistent with off-CPU interruption but not proof of its cause. The ten-key pass includes a fresh-key-sign ratio of 0.6646 and fixed all-candidate-before-all-original order, so drift and implementation effects cannot be separated. These observations constrain interpretation: evidence supports construction/fresh-key workflow savings on the measured host, not faster existing-key signing/verification or a promise that each invocation improves. No losses were removed or normalized away.

## Reproduction and limits

The [prepared manifest](../../results/rustcrypto/resource-audit/prepared-f6a9883529c2caf6.json), build/check logs, resolved Cargo lockfile, original/candidate source archives, [probe](../../libs/rustcrypto/experiments/resource-audit/probe.rs) and [collector](../../libs/rustcrypto/experiments/resource-audit/collect.py) preserve the measured implementation and scope. The first preparation failed because the snapshot omitted the README required by upstream `include_str!`; its failed logs remain. The corrected preparation includes that file and all four configurations pass. This was a harness setup failure, not a library failure.

```sh
python3 libs/rustcrypto/experiments/resource-audit/prepare.py
python3 libs/rustcrypto/experiments/resource-audit/collect.py \
  --manifest libs/rustcrypto/build/resource-audit/prepared-f6a9883529c2caf6/manifest.json \
  --out results/rustcrypto/resource-audit/new-accounting.json
```

Preparation refuses to overwrite an existing snapshot and records its generated path. Reproduction needs the pinned upstream Git objects, recorded Rust toolchain and offline dependency cache; the retained resolved Cargo lockfile supports exact dependency replay. The four synthetic cases are a bounded accounting check, not exhaustive signing-rejection coverage or a side-channel proof. The no-alloc library is exercised inside a std host driver, not on a freestanding embedded target. Physical allocator overhead, whole-process RSS, full secret-memory clearing and dynamic stack peaks remain unmeasured.
