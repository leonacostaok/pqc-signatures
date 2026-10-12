# Bouncy Castle ML-DSA: operation-local work

Source is official bc-java `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`, also returned by the current remote `main` lookup. The previous 1.86 vendored ML-DSA implementation matches this source after package renaming and the documented visibility/row-accessor changes. Production changes live only in the separate `bc-java/worktrees/mldsa-sampling` worktree. Existing SLH work and published evidence are unchanged.

The first candidate shares scratch only within one matrix expansion and one gamma1 vector sampling call. It changes allocation ownership, not SHAKE, coefficient arithmetic, nonce order, rejection conditions, or output encoding. Compare baseline, matrix-only, gamma-only, and combined builds from the exact same upstream archive. These are alternatives under test, not established time improvements.

## Finer signing stages

All engine locations below are in `core/src/main/java/org/bouncycastle/crypto/signers/mldsa/MLDSAEngine.java` at the source pin. Whole-operation timings use the public lightweight API, fresh signer initialization, and unique measured keys. Expanded-key import derives the public key (`MLDSAPrivateKeyParameters.java:72–135`), so core-operation timings must explicitly exclude that import and any separate import-inclusive result must charge it.

| Stage | Source | Work and boundary |
|---|---|---|
| Key decoding/setup | `MLDSASigner.java:46–112`; engine395–405 | Clone encoded key fields, instantiate digest/engine, allocate vectors, unpack s1/s2/t0. |
| Message hash | signer115–123,166; engine350–353,387–392 | Absorb tr, mode/context and message; finalize mu. Keep caller message update in whole sign. |
| Per-sign seed | engine407–411 | Hash K, matched entropy and mu into rhoPrime. |
| Matrix sample | engine413; `PolyVecMatrix.java:32–37`, `Poly.java:48–96` | K*L SHAKE128 streams and 23-bit rejection sampling. Matrix is reused only within this signature's retries. |
| Secret NTT | engine415–418 | L+2K transforms of decoded secret polynomials. |
| Gamma1 sample, each attempt | engine421–425; `Poly.java:462–469` | L streams with nonce L*kappa+j; includes every rejected attempt. |
| y copy and NTT | engine427–428 | Keep y in coefficient domain while transforming z. |
| Matrix product | engine431–433 | K row dot products, reduce32 and inverse NTT. Can split these three substeps when timer overhead permits. |
| Decompose/challenge | engine436–446 | caddq, split w, pack w1, hash mu/w1, sample challenge, transform challenge. |
| Response/rejection | engine449–465 | c*s1 inverse transform, add y, z norm; c*s2 inverse transform, subtract from w0, w0 norm. Record both rejection reasons and attempted counts. |
| Hint/rejection | engine467–481 | c*t0 inverse transform/norm, add low part, form hints and check weight. |
| Final encoding | engine483–484 | Pack z and ordered hints into the signature. |

Vectors are allocated before the retry loop (`400–403`), contrary to the old `sign.md` wording. Only y's sampling byte arrays and challenge/digest scratch are freshly allocated during the loop; allocating vectors again is not a valid optimization target. Stage measurements will be separate instrumented diagnostics, with summed attempted work and rejection counts. They must not be substituted for uninstrumented whole-operation latency or treated as independently composable medians.

## Finer verification stages

| Stage | Source | Work and boundary |
|---|---|---|
| Key/message setup | signer94–112,120–123; engine356–365 | Clone public key fields, hash rho/t1 into tr, absorb mode/context/message. No cross-call tr cache. |
| Finalize mu | engine510–517 | Finalize into the transcript buffer. |
| Signature decode/validity | engine522–538; `Packing.java:111–154` | Exact length, z decode, cumulative hint limits, increasing indices, zero unused tail and z norm. Preserve early rejection. |
| Public-key decode | engine544; `Packing.java:18–26` | Decode all K t1 polynomials. |
| Challenge sample | engine547 | Sample c from c-tilde. |
| Matrix sample | engine549 | All K*L public SHAKE128 polynomial samples. |
| Forward transforms | engine551,554,556–557 | NTT(z), NTT(c), shift/NTT(t1). |
| Products/subtraction | engine552,558–561 | A*z, c*t1, subtract and reduce. |
| Inverse/canonicalization | engine562–564 | K inverse NTTs and conditional additions. |
| Hint/encoding | engine565–567 | UseHint followed by packed w1 output. |
| Final challenge | engine569–572 | Transcript hash and constant-time comparison. |

The old stage pipeline copies decoded vectors for replay and compares only c-tilde for its decode stage. New diagnostics must compare every decoded coefficient/hint and the accept/reject result outside all clocks. Old stage throughput/CPU also includes output hashing; those numbers are directional historical observations, not a quantitative oracle for the current candidate.

## Ranked next candidates

1. **Local sampling scratch, implemented first.** `Poly.java:52` allocates842 bytes per matrix polynomial; `Poly.java:464` allocates680 bytes per gamma1 polynomial. Share one buffer per matrix expansion and one per gamma vector/attempt. Matrix byte-array payload reduction is12,630/24,418/46,310 bytes for44/65/87; gamma reduction is2,040/2,720/4,080 bytes per attempt. These are source counts, excluding array headers and JIT escape effects. No guaranteed CPU gain: SHAKE permutations remain identical. Public rho scratch is overwritten for every sample; secret gamma scratch has call-local lifetime and is not newly retained. Synthetic refill tests must cover carry and poison, because280 initial draws almost never exhaust with real SHAKE seeds.
2. **Lazy row Montgomery reduction.** `Poly.java:195–215` already avoids product arrays but still reduces L products per coefficient. A long row sum followed by one Montgomery reduction could remove3,072/6,144/12,288 reductions per matrix product. This applies to keygen and every signing attempt as well as verification. The old `wApproxLongAccum` additionally fuses the c*t1 term and changes memory access order; its noisy results do not establish a production win. Start with the small row helper only, retain existing caller reductions, and test all signed bounds before a controlled screen.
3. **Offset decoding/packing.** `Packing.java:24,118` copies each320-byte t1 polynomial and576/640-byte z polynomial before unpacking. Offset-aware helpers can remove3,584/5,120/7,040 payload bytes per verify, while preserving all malformed-hint/norm checks. `Packing.java:13` likewise allocates a temporary t1 encoding per row during key generation. Expected CPU impact is small because these are minor stages; array savings are explicit. Avoid Java VarHandle as a first production change because the upstream base code targets Java8.
4. **Stream matrix rows in verification/keygen.** `PolyVecMatrix.java:12–21` allocates the complete K*L polynomial matrix although verification consumes each row once. A row-local path would save12,288/25,600/50,176 coefficient-array payload bytes relative to retaining all rows, plus object overhead. This is a larger refactor and must not be applied naively to signing: signing reuses A across all rejection attempts, so resampling rows each attempt adds substantial SHAKE work. Defer until the smaller sampling-buffer result is understood.
5. **Fuse hint/encoding or final inverse-NTT scaling.** UseHint/pack fusion can remove one coefficient write/read pass at engine565–567, but production already operates in-place and therefore has no extra PolyVec to remove. The old instrumented stage's extra copy overstates production allocation savings. Folding inverse-NTT's final scale loop (`Ntt.java:84–87`) into its last butterfly saves a pass but changes arithmetic ordering and needs a separate bound/differential proof. Neither is a large rewrite justified by current evidence.

For lazy reduction, all current forward-NTT inputs have absolute value below q, including decoded noncanonical eta fields and t1<<13; t1's largest value is1023*8192=q-1. With centered zetas below q/2, induction gives each of eight butterfly stages an extra contribution below q, so a conservative output bound is9q. Matrix entries are in[0,q). For L<=7, the signed row sum is below63q²=4,424,577,512,915,007, which is below q*2^31=17,996,808,470,921,216 and far below signed-long overflow. Cast operands to long before multiplication; preserve signed Montgomery reduction and its low32-bit wrap semantics. Modular equivalence does not imply identical unreduced intermediate representatives, so compare canonical inverse-transformed outputs and full deterministic signatures. The same bound must not be assumed for arbitrary int[] values or unrelated callers. No new secret-dependent branches, indices, division, aliasing or persistent storage are needed.

## Gates and timing policy

Freeze source, patch, compiled-class trees, driver, Java runtime and corpora hashes. Require four unequal variant source/class identities, patch application checks, positive exact test counts, and a baseline failure of the reduced-buffer resource gate. Check all three pure and prehash parameter sets, exact key/signature bytes from unchanged upstream, repeated calls, contexts0/1/255, messages0–4096 bytes, deterministic and fixed explicit entropy, caller ownership and malformed signatures. Resource tests inspect actual squeeze-buffer identity; forced167-byte test streams exercise carry1/carry2 refill independent of ordinary SHAKE distributions.

Performance waits for a root-granted exclusive window. Each variant/parameter/operation gets a fresh JVM; warmup keys are disjoint from measured keys, and each measured key is used once in its batch. Caller copies and expanded-key import occur outside the core-operation clock; signer/verifier creation, init, message update, and sign/verify are inside. Record every wall sample, calling-thread CPU and allocated bytes, then compare outputs and caller state after all counters stop. Retain losing/noisy results. Calling-thread CPU does not include JIT/GC helper threads and will be labeled accordingly. Whole-operation numbers use no instrumented sampling or timing hooks.

The separate instrumented profile mode warms on the same fixture values used for stage attribution, with a fresh signer each time. Its counters therefore describe source-bound diagnostic work and retry counts, not the disjoint-key performance protocol. Only the uninstrumented whole-operation and sampler screens use disjoint warmup corpora. Each untimed signing check performs verification and encoding/hash checks before the next measured call; that work can affect GC/JIT and is represented in separate checked-driver diagnostics, never included in the per-operation clocks. Sampler probes include vector/matrix construction, and the gamma probe also creates its64-byte seed; source-level buffer-count deltas are the primary interpretation of that diagnostic.
