# ML-DSA matrix alternatives

These are isolated, portable Java experiments against Bouncy Castle commit `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. Four separate source and class trees contain the pinned baseline, lazy row Montgomery reduction, streamed public matrix rows, and their combination. No sampler-buffer, digest, forward/inverse NTT, packing, rejection-limit, or signing matrix lifetime changes are included. This is a bounded correctness and performance screen, not a production safety certification.

## Exact changes

`lazy` changes only `Poly.pointwiseAccountMontgomery`: it sums the L signed 64-bit products for one coefficient and performs one Montgomery reduction, instead of reducing each product and summing the results. The source diff also changes the loop order to coefficient then column. It removes 3,072, 6,144, or 12,288 Montgomery reductions per complete matrix product for ML-DSA-44, -65, or -87 respectively. Repeated vector indexing and a less contiguous access pattern can offset that saving; arithmetic operation counts are not timing evidence.

`stream` adds `PolyVecMatrix.expandAndMultiply` and calls it from `generateKeyPairInternal`, `deriveT1`, and `doVerifyInternal`. It allocates one row of L polynomials, expands its columns with the existing `uniformBlocks(rho, i << 8)`, consumes the row using the unchanged dot product, and overwrites it with the next row. Each sampler call retains its nonce, output order, block size, rejection loop, and refill/carry code. Key generation and public-key derivation move independent SHAKE128 matrix expansion after secret sampling/unpacking and the forward NTT; the SHAKE128 matrix stream is separate from the SHAKE256 secret sampler. Verification moves expansion after its forward NTT. No secret-dependent loop or branch is added.

Signing still expands and retains its complete public matrix before its rejection loop; repeated signing attempts do not resample it. Consequently `stream` signing is an unchanged-operation control. `combined` uses the same streaming helper with the lazy row arithmetic. The selected source files and the complete diffs are archived beside the results.

The source-level coefficient-array payload avoided by streaming is `(K-1)*L*256*4`: 12,288, 25,600, and 50,176 bytes respectively, before object headers and other allocations. This is not a measurement of allocated bytes, peak memory, liveness, or GC. The original per-polynomial SHAKE output buffers are still allocated. The reused row contains public A coefficients; input and output vectors do not alias in the changed callers. No clearing operation is removed, no secret material is cached between API calls, and the existing secret-vector and signer lifetimes remain in place.

## Signed arithmetic and representative bounds

Let `q = 8,380,417`, `R = 2^32`, `L <= 7`. This argument applies to the actual pinned matrix callers, not arbitrary package-private arrays, aliases, changed parameters, or a future combination with another arithmetic patch. `Reduce.montgomeryReduce(a)` computes `t = signed32(a*qInv)`, then `(a-t*q)/R` as a signed integer. The low-word multiplication intentionally uses Java wraparound. Its low 32 bits remain correct even if the intermediate Java long multiplication wraps. The subtraction must not overflow, and the quotient must fit an int; both conditions are checked below. The implementation's unsigned shift followed by an int cast produces the same signed 32-bit quotient because the numerator is divisible by R.

The sampled matrix coefficients lie in `[0,q)`. Before the other vector's forward NTT, every actual caller has coefficients of absolute value below q: sampled or decoded eta values for key generation/derivation, sampled gamma1 values for signing, and norm-checked z values for verification. Even noncanonical decoded eta fields are bounded by `[-5,2]` or `[-11,4]`. For the verifier's separate challenge product, challenge coefficients are in `{-1,0,1}` and shifted t1 is at most `1023*8192 = q-1`.

The pinned forward NTT has eight stages and `|zeta| < q/2`. Starting with `|x| < q`, each Montgomery product has absolute value below q while the butterfly magnitude grows by at most q per stage. The conservative final bound is `|v| < 9q`, with no signed int overflow. The original individual matrix-product reduction has magnitude at most 4,337,377 and the sum of seven has magnitude at most 30,361,639. The lazy sum satisfies `|a| < 63q^2 = 4,424,577,512,915,007`, comfortably inside a signed long and below `q*2^31 = 17,996,808,470,921,216`. Each partial sum obeys the same absolute bound. Since `|t| <= 2^31`, the numerator magnitude is at most 22,421,385,983,836,223, below `Long.MAX_VALUE`. The lazy result has magnitude at most 5,220,386, below q. The BigInteger gate checks independent modular row products as well as source-level reduction counts.

Both row implementations compute the same residue modulo q, but their immediate signed representatives need not match. All changed matrix callers retain the original `reduce()` before inverse NTT. Verification first subtracts the unchanged challenge-times-t1 product; its magnitude is at most 5,514,723, so the subtraction remains far inside signed int range for either row implementation. `reduce32` adds `2^22`, shifts by 23, and subtracts a multiple of q. For the caller range just established, the shift quotient has magnitude at most 5, so the reduced magnitude is at most `2^22 + 5*8191`, below q. Its intermediate addition and multiplication are also safe.

From an inverse-NTT input of magnitude below q, an unchanged inverse butterfly can grow an unreduced sum/difference to at most `256q = 2,145,386,752`, still below `2^31`; a twiddle-product Montgomery result remains below q. The final multiply by 41,978 reduces every coefficient to magnitude at most 4,211,178. Key generation/derivation adds eta coefficients of magnitude at most 11, still inside `(-q,q)`. The existing `conditionalAddQ` therefore yields the unique representative in `[0,q)`. Signing's decomposition and verification's hint use likewise receive identical canonical representatives. This proves the downstream equivalence needed by these callers; it does not require the intermediate arrays to be bit-identical.

## Correctness evidence

Each isolated variant passed exact public-key, private-key, signature, and verification comparisons on all three pure and three SHA-512 prehash modes, including varied messages, contexts of length 0/1/255, and deterministic/randomized signatures. The archived correctness corpus has 72 cases; the separate measured corpus has 384 cases. Calls use fresh operation objects and compare retained caller buffers and encoded keys afterwards. The measured corpus was checked before any timing run.

The malformed-signature gate checks decreasing hint cumulative counts, counts above omega, duplicate hint positions, nonzero unused hint tails, both z-norm equality boundaries and interior neighbors, wrong message/context, truncated/extended signatures, and successful verification after negative calls. It performs 936 checks per variant. The matrix gate independently checks 18,432 coefficients against BigInteger arithmetic, preserves vector inputs, compares exact reduced/inverted canonical rows, and checks actual reduction counts. Six forced sampler cases use a 167-byte stream block with initial all-rejected bytes, exercising refill and both carry lengths; they compare exact nonce order, stream request positions/offsets/lengths, independently decoded coefficients, retained output ownership, and one-row versus full-matrix logical polynomial construction counts.

Before implementing the alternatives, baseline gates were demonstrated to fail the lazy reduction-count and streamed-helper requirements; those red logs are retained. The gate-only counting instrumentation lives in separate class overlays and is excluded from the measured classpath. Root independently ran the pinned native ML-DSA tests (14 methods) and Wycheproof tests (3 methods, 631 cases per variant), with class origins and before/after hashes checked. Those independent raw logs are retained in the root integration evidence.

## Predeclared collection protocol

The fixed screen has four variants, three parameter sets, three operations (keygen/sign/verify), and four rounds arranged as two pairs with the variant order reversed within each pair. Every variant receives its own fresh JVM. Timing and allocation run in separate JVM cohorts: 144 timing plus 144 allocation batches. Cell and key orders use recorded deterministic shuffle seeds. No result-dependent retries, omitted cells, or discarded losing observations are allowed.

Every JVM executes 1,000 warmup calls using the first two disjoint warmup keys, then 128 measured calls using each distinct measured key exactly once. Every call creates a fresh generator or signer/verifier through the ordinary lightweight API. Signer initialization, context/message update, and the cryptographic operation are inside the interval. Key decoding, fixture and caller-buffer copies, deterministic entropy-object setup, output encoding for keygen, output hashes, exact-result/ownership checks, and additional tamper checks are outside. This is the core one-shot API path with predecoded key objects, not an import-inclusive or cold-start claim. Repeating the same corpus across fresh process rounds is explicit; no measured key repeats within a batch.

Timing records wall time and calling-thread CPU only; allocation records calling-thread allocated bytes only. The primary ratio is baseline total divided by variant total over all four rounds, separately for wall and CPU. All four round ratios and all 512 paired-key losses/ties remain in the summary for each cell. Allocation is summarized separately and cannot establish reduced GC, peak or retained memory. JDK compilation and other threads are excluded from calling-thread CPU. Warmup count is fixed rather than a demonstrated compilation steady-state guarantee.

The pinned runtime is Temurin 25.0.4.1+1 on macOS aarch64, with `-Xms512m -Xmx512m -XX:ActiveProcessorCount=2` and empty Java option-injection environment variables. Source, class, driver, runtime, corpus and protocol hashes are checked before and after collection. Root observed `fseventsd` at approximately 80% CPU before the screen; controlled jobs are exclusive, but this is a shared workstation without a reserved CPU or thermal control. A four-round result is screening evidence requiring independent confirmation before a provider recommendation.

## Reproduction and saved-data audit

The experiment scripts are under `libs/bouncycastle/experiments/matrix-alternatives`; evidence is under `results/bouncycastle/matrix-alternatives`. `prepare.py` extracts the exact pinned upstream archive, constructs all variants, compiles source with `--release 8`, builds the JDK-25 measurement/gate drivers, runs correctness gates, and seals the prepared trees. `collect.py seal` writes a fixed plan after verification. `collect.py collect --exclusive-grant TEXT` requires a coordinator-granted exclusive window and creates a new result directory; it refuses to overwrite a prior collection. Preparation scripts, runner, and checker explicitly reject optimized Python execution.

`audit.py` checks archived source/fixture hashes, all preparation logs, every raw measurement's identity, checked output digest, unique measured key set, counter mode, pairing, all 288 jobs, and recomputes all ratios and losses. It never regenerates data or launches a JVM. Missing local runtime/class trees are explicitly reported as unavailable, rather than treating recorded hashes as verified binaries. The complete pinned baseline source archive, variant patches, selected full Java sources, and exact corpus files are portable evidence; machine-specific runtime and build class files are not redistributed. The preparation manifest's `java_version` field is empty because `java -version` writes to stderr; the saved `java-version.log` and sealed plan contain its actual output. The reusable batch driver retains schema label `bc-ntt-batch-v1`; the matrix plan and checker validate the concrete variant identity, class hashes, and operation fields.

All 288 planned JVMs completed successfully, with 36,864 checked measured calls. The saved-data audit reproduced all 27 comparisons and verified the unchanged local runtime/class/source trees. A relocated evidence-copy replay reproduced the same comparisons while explicitly simulating unavailable runtime/class/source paths; it verifies the portable source/fixture/raw evidence without claiming to verify absent binaries. Exact reproduction commands and paths are in the handoff.


## Screen results and disposition

Retain only the stream-only variant as a candidate for independent confirmation. Its source-level row lifetime reduction is independently gated, and the observed allocated-byte reduction is consistent with that mechanism. Do not promote the lazy or combined variant: lazy slows every signing parameter in all four rounds, and the combined patch mostly loses the stream-only latency advantage. These results do not establish a broadly faster provider patch. In particular, the unchanged stream-only ML-DSA-87 signing control appears 1.025 times faster, and ML-DSA-87 verification's 1.036 wall ratio corresponds to only 1.005 calling-thread CPU; both weaken attribution of small latency changes. ML-DSA-44 and -65 verification are the strongest latency follow-up cells (about 1.029 and 1.044 CPU ratios, with all four rounds favorable).

The timing cohort finished before seven unusually long allocation processes. Allocation job indices 224, 229, 239, 247, 264, 276 and 284 ran for approximately 827, 167, 61, 4,071, 2,084, 3,651 and 1,698 seconds by their recorded process timestamps. Their cause is unestablished. These intervals are archived in `environment-intervals.json`; no observations were removed or rerun. Calling-thread allocation counters still yielded checked results, but the allocation cohort was not a continuous stable-environment run. Treat its byte counts as an interrupted-cohort screen requiring uninterrupted confirmation, not as evidence of GC or memory-liveness improvement.

Ratios below are baseline divided by variant, so values above one favor the variant. Loss columns count unfavorable rounds out of four, separately for wall/CPU. Allocation deltas are variant minus baseline calling-thread bytes per call; negative values indicate fewer bytes. All raw key observations, four round ratios, and 512 paired-key loss/tie counts per metric remain in `summary.json` and the raw collection. The table retains every operation, including the unchanged streaming signing controls.

| Parameter | Operation | Variant | Wall ratio | CPU ratio | Losing rounds wall/CPU | Allocation delta B/call |
|---|---|---|---:|---:|---:|---:|
| ML-DSA-44 | keygen | lazy | 0.9690 | 0.9694 | 4/4 | +200.4 |
| ML-DSA-44 | keygen | stream | 1.0192 | 1.0183 | 1/1 | -12,794.8 |
| ML-DSA-44 | keygen | combined | 0.9866 | 0.9884 | 3/3 | -12,920.5 |
| ML-DSA-44 | sign | lazy | 0.9653 | 0.9646 | 4/4 | +96.0 |
| ML-DSA-44 | sign | stream | 1.0024 | 1.0001 | 2/2 | +96.0 |
| ML-DSA-44 | sign | combined | 0.9719 | 0.9698 | 4/4 | +0.0 |
| ML-DSA-44 | verify | lazy | 1.0011 | 0.9980 | 1/1 | -320.9 |
| ML-DSA-44 | verify | stream | 1.0333 | 1.0290 | 0/0 | -13,254.9 |
| ML-DSA-44 | verify | combined | 0.9979 | 0.9956 | 2/3 | -13,467.0 |
| ML-DSA-65 | keygen | lazy | 0.9591 | 0.9644 | 4/4 | +0.0 |
| ML-DSA-65 | keygen | stream | 1.0251 | 1.0250 | 0/0 | -26,775.4 |
| ML-DSA-65 | keygen | combined | 0.9850 | 0.9860 | 3/3 | -26,955.6 |
| ML-DSA-65 | sign | lazy | 0.9576 | 0.9580 | 4/4 | +180.0 |
| ML-DSA-65 | sign | stream | 0.9961 | 0.9963 | 3/3 | +180.0 |
| ML-DSA-65 | sign | combined | 0.9489 | 0.9504 | 4/4 | +0.0 |
| ML-DSA-65 | verify | lazy | 0.9930 | 0.9931 | 2/2 | -588.8 |
| ML-DSA-65 | verify | stream | 1.0440 | 1.0437 | 0/0 | -27,614.8 |
| ML-DSA-65 | verify | combined | 1.0203 | 1.0205 | 1/1 | -27,785.4 |
| ML-DSA-87 | keygen | lazy | 0.9849 | 0.9848 | 3/3 | +564.0 |
| ML-DSA-87 | keygen | stream | 1.0151 | 1.0146 | 1/1 | -52,810.9 |
| ML-DSA-87 | keygen | combined | 0.9686 | 0.9698 | 3/3 | -52,812.0 |
| ML-DSA-87 | sign | lazy | 0.9611 | 0.9604 | 4/4 | +0.0 |
| ML-DSA-87 | sign | stream | 1.0247 | 1.0233 | 0/0 | -336.0 |
| ML-DSA-87 | sign | combined | 0.9342 | 0.9691 | 4/4 | -336.0 |
| ML-DSA-87 | verify | lazy | 0.9437 | 0.9615 | 4/4 | -69.2 |
| ML-DSA-87 | verify | stream | 1.0357 | 1.0050 | 0/1 | -52,353.2 |
| ML-DSA-87 | verify | combined | 1.0090 | 0.9791 | 2/4 | -53,066.2 |

The conservative conclusion is that streaming offers a concrete allocation-saving design for one-use matrix callers, while lazy reduction is a measured negative result for this Java loop shape and runtime. No upstream patch is promoted from this screen; all three implemented alternatives, including the losses, remain reproducible.
