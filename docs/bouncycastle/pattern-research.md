# Bouncy Castle: next optimization candidates

Three Astra agents independently examined algebra, SLH traversal/hash work, and JVM code shape. The strongest new mathematical candidate is inverse-NTT scale fusion. A separate, small address-hoisting probe already found a preliminary key-generation improvement and an allocation reduction. Neither is ready for an upstream performance claim.

## Ranked candidates

| Pattern | Concrete saving to test | Current evidence |
|---|---|---|
| Fold the last inverse-NTT butterfly and scale | 128 fewer Montgomery reductions per transform (10% of that kernel's reductions), one fewer array pass; no extra storage | Source-derived caller/range review and arithmetic oracle pass; no Java implementation or timing result yet. |
| Hoist WOTS address setup within one call | Avoid repeated address objects, clearing and field encoding | New two-pair screen below: promising keygen; signing allocation improves but latency is mixed. |
| Reduce a matrix row's dot product once | Replace L Montgomery reductions per coefficient with one; 3,072/6,144/12,288 fewer per ML-DSA matrix product | Algebraic/range argument; already proposed locally, still unbuilt. Traversal/reference-load costs might outweigh savings. |
| Stream matrix rows for verification/keygen | Retain one row instead of the entire matrix: 12/25/49 KiB fewer coefficient payload bytes for 44/65/87 | Existing proposal, not measured. Do not repeatedly regenerate signing's matrix during rejection retries. |
| Reuse SHAKE challenge scratch across signing retries | Avoid repeatedly constructing a digest and 136-byte buffer within one signing call | New source-grounded hypothesis. A one-attempt signature saves nothing; retain reset/cleanup behavior. |
| Peel the first hash from the buffered WOTS loop | Keep the allocating first step outside the repeated in-place loop | Precise follow-up to the earlier buffer patch's latency losses; unmeasured. |
| Replace treehash linked nodes with bounded arrays | O(height) local bookkeeping instead of per-leaf wrapper objects | Saved tree-stack patch exists, but its changed implementation remains unvalidated/unmeasured. |

These are implementation transformations of existing standardized algorithms. No persistent key/matrix cache is needed. Some are familiar compiler patterns applied at a cryptographic hot path; others use modular arithmetic to remove entire operations. Fewer reductions or bytes are not automatically the same percentage of end-to-end time saved.

## New address-hoisting screen

The candidate changes only WotsPlus: initialize separate PRF and HASH addresses once per call, then update chain/hash words. It preserves all 32 incoming address bytes before clearing domain-specific suffixes, leaves the original hash/chain routines unchanged, and uses fresh local objects for every call. Public-key compression still clears its own address. This is separate from the earlier WOTS buffer patch.

| Parameter / action | Wall time change | Thread CPU change | Allocated bytes change |
|---|---:|---:|---:|
| sha2-128f / keygen | 🟢 -4.18% | 🟢 -4.05% | 🟢 -9.86% |
| sha2-128f / sign | 🔴 +0.48% | 🔴 +0.90% | 🟢 -7.95% |
| sha2-128f / verify | 🔴 +1.08% | 🔴 +1.37% | 🔴 +0.18% |
| shake-128f / keygen | 🟢 -1.78% | 🟢 -1.56% | 🟢 -9.89% |
| shake-128f / sign | 🟢 -0.50% | 🔴 +0.08% | 🟢 -7.99% |
| shake-128f / verify | 🟢 -0.67% | 🟢 -0.58% | 🟢 -0.28% |

Negative means less time/allocation. Percentages compare the arithmetic means of the two process means, not confidence intervals. SHA2 keygen improves in both pairs (3.81% and 4.55% less wall time), with CPU corroboration. SHAKE keygen improves by 0.14% and 3.37%, so its smaller aggregate is less persuasive. SHA2 signing is mixed and slightly slower overall; SHAKE signing's small wall saving is not corroborated by lower thread CPU. Verification executes unchanged code: its movements must be treated as a control, not an algorithmic improvement.

The allocation reduction is consistent in both pairs: about 9.9% for keygen and 8.0% for signing. It measures bytes allocated by the calling thread, not retained heap, peak memory or GC pauses. This narrow screen establishes neither a general signing speedup nor an all-parameter benefit. Next, isolate address allocation from field-reset removal and confirm any winner with longer warmup, more balanced pairs, all parameter sets and a fresh corpus before proposing it upstream.

The predeclared screen ran 48 fresh JVMs sequentially: two balanced original/changed pairs for each of two fast sets and three actions, with timing and allocation separate. Each process uses 80 warmup calls on two disjoint keys and two measured rounds cycling four other keys. Timed rounds target 100 ms; allocation rounds use one complete four-key cycle. Ordinary operation objects are fresh; key decoding/import is outside timing. Short fixed warmup is a screen, not proof of steady-state JIT behavior. Shared-desktop noise remains possible.

Before timing, 24 transcript cases covered n=16/24/32, dirty address suffixes/upper tree bytes, and zero/full/patterned message digits. Original and changed versions produced identical ordered PRF/F/T_l transcript digests and retained caller/output ownership. The transcript engine is deliberately a test double, not a cryptographic implementation. Separately, both real implementations passed 72 keygen/sign/verify checks on two fast sets with 12 distinct fixture keys each, including tamper rejection and input ownership. Only WotsPlus.class differs between the frozen class trees.

[Independent evidence check](../../results/bouncycastle/pattern-research/address/independent-check.json) · [Raw plan, source identities, gates and results](../../results/bouncycastle/pattern-research/address/) · [Exact candidate patch](../../results/bouncycastle/pattern-research/address/preparation/address-hoist.patch) · [Reproduction](../../libs/bouncycastle/experiments/pattern-research/README.md).

## Mathematical candidate and rejected shortcuts

The [inverse-NTT note](pattern-research/invntt.md) gives the transformation, integer bounds and all seven caller checks. The oracle checks 260 transform vectors and 108 sparse products against independent schoolbook negacyclic convolution. Internal outputs sometimes differ by q; canonical equality and the small-product bounds are essential. This is a promising next implementation probe, not a measured speedup or formal verification.

Avoid unproductive shortcuts:

- XMSS authentication subtrees already cover disjoint leaves: 1+2+…+2^(h′−1)=2^h′−1. WOTS signing and recovery split a selected chain into digit+(15−digit)=15 steps. Fusion mainly removes bookkeeping here; a naive complete top-layer traversal can add work.
- SHA2 public-seed midstate reuse, direct compressed-address absorption, lazy Keccak output packing and separate key-generation root computation already exist in the pin.
- A SHAKE F input is 64/80/96 bytes, below its 136-byte rate. Copying a whole digest prefix state saves no permutation at that point and can add memory traffic.
- [HotSpot's SHA intrinsics](https://github.com/openjdk/jdk25u/blob/master/src/hotspot/share/classfile/vmIntrinsics.hpp) target specific JDK digest classes. Changing an interface field to a concrete BC type does not activate them. JCA backend changes, native/vector code and deletion of digest resets need separate compatibility/cleanup review.

Further narrow candidates are fixed-twiddle Montgomery companion constants (about 1 KiB static table), a fused copy/first-forward-NTT pass, flat WOTS result arrays, and bounds-check-friendly uniform parsing. Keep them separate to attribute gains. The earlier ML-DSA-87 verification result remains evidence for its combined build; it does not validate a newly isolated verification-only patch.

Supporting investigation, test construction and analysis are AI-assisted. Sources, patches, scripts and failed/unchanged controls are retained for independent review; none of this certifies cryptographic security.
