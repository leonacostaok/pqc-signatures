# SLH-DSA FORS bit extraction

The proposed Bouncy Castle change replaces the growing `BigInteger` accumulator in `Fors.base2B` with a fixed `int` window. The source baseline is `bcgit/bc-java` main `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. The production change is limited to `core/src/main/java/org/bouncycastle/crypto/signers/slhdsa/Fors.java`; package-local oracle tests are also included in [the patch](../../libs/bouncycastle/patches/fors-base2b.patch).

## Why the window is sufficient

All supported FORS parameter sets use index widths `b` in `{6,8,9,12,14}`. Immediately after extracting an index, there are at most seven unread bits. Refilling until at least `b` bits are present leaves at most `b+7 <= 21` active bits. Java's `int` left shift may discard older, already consumed high bits, but cannot discard any bit used by the next output. The unsigned right shift by `bits` followed by `(1 << b) - 1` therefore extracts exactly the same MSB-first index as the original positive `BigInteger`. Array allocation, result length, input access order, and parameter-dependent loop bounds are unchanged. No new secret-dependent lookup or control flow is introduced. This is a local code argument, not a formal constant-time certification of the JVM.

## Correctness and allocation evidence

The focused upstream tests cover a literal MSB-first example and 2,464 generated cases across every supported shape, every prefix length, zero/one bit patterns and seeded random data. The oracle extracts bits individually, independently of the window implementation. Baseline and candidate both pass; input immutability is checked.

The [full differential log](../../results/bouncycastle/experiments/fors-differential.txt) covers 48 cases across all 24 pure and prehash SLH-DSA modes, with distinct deterministic seeds, empty and 1,024-byte messages, empty and 255-byte contexts, and default or explicitly supplied signing entropy. It checks byte-identical public keys, secret keys and signatures, successful verification, and 240 negative-result comparisons for changed messages, contexts, signatures, and truncated or extended signatures. All pass and caller inputs remain unchanged. These are deterministic differential checks, not a substitute for known-answer vectors.

The resource regression gate requires at most 512 bytes allocated per helper call; baseline fails and candidate passes. HotSpot's per-thread allocation counter reports the following on the pinned Temurin 25.0.4.1 runtime after warmup, for 2,000 calls per shape. This measures allocation traffic, not retained heap or peak memory. JVM escape analysis can affect the exact baseline amount.

| Width | Indices | Baseline bytes/call | Candidate bytes/call |
| --- | --- | ---: | ---: |
| 6 | 33 | 18,328 | 152 |
| 12 | 14 | 7,712 | 72 |
| 8 | 33 | 14,256 | 152 |
| 14 | 17 | 10,392 | 88 |
| 9 | 35 | 17,976 | 160 |
| 14 | 22 | 14,640 | 104 |

Raw measurements: [baseline](../../results/bouncycastle/experiments/fors-baseline-allocation.json), [candidate](../../results/bouncycastle/experiments/fors-candidate-allocation.json). Candidate allocation consists of the returned `int[]` only.

The separate [whole-verification allocation gate](../../libs/bouncycastle/experiments/verify-allocation.py) measures complete valid verification with already decoded keys for all 12 pure parameter sets. Each side warms for 256 calls per parameter, then four paired batches each execute 128 calls in whole two-case corpus cycles. Every result is checked. Current-thread allocation includes identical reflective invocation overhead; fixture parsing, key decoding and argument-array construction are excluded. The variants share one fresh JVM, with order balanced across parameters and rounds. The [raw evidence](../../results/bouncycastle/experiments/fors-verify-allocation.json) binds the frozen preparation and the separate driver/collector/class hashes.

| Parameter | Baseline bytes/verify | Candidate bytes/verify | Reduction |
| --- | ---: | ---: | ---: |
| sha2_128f | 266,463.00 | 253,608.00 | 4.82% |
| sha2_128s | 103,097.31 | 95,890.56 | 6.99% |
| sha2_192f | 464,844.00 | 451,772.00 | 2.81% |
| sha2_192s | 170,140.00 | 159,820.00 | 6.07% |
| sha2_256f | 569,900.00 | 552,184.00 | 3.11% |
| sha2_256s | 294,872.00 | 280,888.00 | 4.74% |
| shake_128f | 263,120.00 | 250,427.41 | 4.82% |
| shake_128s | 98,484.00 | 91,328.00 | 7.27% |
| shake_192f | 467,648.00 | 454,640.00 | 2.78% |
| shake_192s | 171,872.00 | 161,576.00 | 5.99% |
| shake_256f | 560,580.00 | 542,936.00 | 3.15% |
| shake_256s | 288,576.00 | 274,528.00 | 4.87% |

These are medians across four fixed batches in one JVM, not cross-runtime guarantees or retained-heap measurements. Allocation falls in every retained pair. Small first-round JIT-related allocation changes remain visible in the raw rows; they are not filtered. The measured whole-verification reduction is 7,156–17,716 bytes per call (2.8–7.3%), independently of any latency result.

Current upstream core production and test compilation and `:core:checkstyleMain` succeeded; the [style log](../../results/bouncycastle/experiments/upstream-checkstyle.txt) is retained. All 41 SLH test-data files have been downloaded at upstream revision `3c385e9f4c0b12ce5a86d2b29a17fb3b68dd4e1a` and checked against their Git blob hashes; [the manifest](../../results/bouncycastle/experiments/upstream-test-data.json) also records SHA256. An initial Gradle suite-filter invocation unexpectedly included unrelated ASN.1 suites, reported missing unrelated test data, and was canceled to free the shared timing window. The exact affected suites subsequently passed through JUnitCore with `-Dtest.full=true`: the focused package tests, `AllTestsSLHDSA`, and `AllTestsSLHDSASigGen` (13 test methods, including all 204 vectors in the combined signature-generation file). See [the complete log](../../results/bouncycastle/experiments/upstream-slh-full.txt). Its printed elapsed time includes a coordination pause and is not a performance measurement.

## Timing protocol

The [runner](../../libs/bouncycastle/experiments/fors.py) builds isolated baseline and patched source copies from the pinned upstream revision. The [prepared manifest](../../results/bouncycastle/experiments/fors-prepared.json) binds the patch, every runner source, compiled class trees, corpus, JDK and JVM environment with hashes. Production classes target Java 8, matching upstream; the experiment driver runs on the pinned JDK 25. Both final protocols completed; the original shared-JVM run showed a systematic SHAKE verification loss, and the separate-process follow-up did not reproduce that pattern. Both results are reported below.

Each fresh JVM loads baseline and candidate through separate class loaders, warms both in fork-balanced order, and alternates paired AB/BA measurement order. Every sample runs whole corpus cycles, lasts at least the requested wall-time budget, and checks its final output after the timer. Both monotonic wall and process CPU time are retained. The corpus is fixed before timing; key decoding and fixture construction are outside measured calls. Timed verification includes creating and initializing a verifier with an already decoded public key. Five fresh forks and six rounds are required by the intended final invocation. Fork medians summarize paired baseline/candidate ratios; the range across fork medians is an observed range, not a confidence interval.

The two variants share a JVM heap, JIT runtime and garbage collector within each fork. Their separate class loaders isolate implementation classes but do not isolate garbage-collection pressure between paired samples. Balanced AB/BA order reduces order bias without proving that small wall-time changes are caused by the patch. Allocation counts provide a direct resource measurement; tiny or unstable latency changes will not support a faster-verification claim.

Run from this worktree only during an exclusive machine window:

```sh
python3 libs/bouncycastle/experiments/fors.py run --manifest libs/bouncycastle/build/fors-base2b/prepared-38afeddcb55e90be/manifest.json --out results/bouncycastle/experiments/fors-jdk25-arm64.json --forks 5 --start 10 --rounds 6 --budget-ms 250 --operations base2B,verify
```

A helper timing gain alone does not establish a signing or verification latency gain. Key generation does not use this helper. Any end-to-end claim must be limited to the operations and parameter sets actually measured. An exploratory one-fork helper driver check is excluded from final results.

## Original shared-JVM measurements

The [retained final output](../../results/bouncycastle/experiments/fors-jdk25-arm64.json) contains 540 paired samples and 18 summary cells from five forks and six rounds on an Apple M1 Pro with 16 GiB RAM and arm64 macOS/Darwin 25.2.0. The [independent recomputation](../../results/bouncycastle/experiments/fors-review.json) checked all raw counts, complete corpus cycles, orders, ratios, hierarchical summaries and frozen provenance. Every sample and loss is retained.

| Operation | Parameter | Baseline µs | Candidate µs | Paired speedup | Fork range |
| --- | --- | ---: | ---: | ---: | ---: |
| base2B | 12x14 | 1.3247 | 0.0553 | 24.8666× | 23.1039–28.2152× |
| base2B | 14x17 | 1.8712 | 0.0671 | 27.8866× | 26.1598–34.6763× |
| base2B | 14x22 | 2.5552 | 0.0873 | 29.1252× | 27.5937–35.4151× |
| base2B | 6x33 | 2.7355 | 0.0636 | 42.6635× | 38.4449–45.7378× |
| base2B | 8x33 | 2.5916 | 0.0698 | 37.6990× | 34.8650–40.8682× |
| base2B | 9x35 | 3.5531 | 0.0842 | 42.0310× | 38.3345–49.3114× |
| verify | sha2_128f | 2625.8223 | 2619.6708 | 0.9991× | 0.9957–1.0048× |
| verify | sha2_128s | 929.6107 | 926.7356 | 1.0008× | 0.9982–1.0025× |
| verify | sha2_192f | 3818.1080 | 3816.0985 | 1.0043× | 0.9977–1.0083× |
| verify | sha2_192s | 1287.3331 | 1272.9383 | 1.0061× | 0.9887–1.0271× |
| verify | sha2_256f | 3921.9893 | 3911.7041 | 1.0021× | 0.9902–1.0130× |
| verify | sha2_256s | 1973.3612 | 1933.6063 | 1.0079× | 1.0001–1.0280× |
| verify | shake_128f | 2124.9665 | 2148.9763 | 0.9874× | 0.9669–0.9916× |
| verify | shake_128s | 730.7481 | 742.6921 | 0.9829× | 0.9709–0.9898× |
| verify | shake_192f | 3201.7794 | 3257.2511 | 0.9848× | 0.9643–0.9879× |
| verify | shake_192s | 1081.5750 | 1103.4785 | 0.9898× | 0.9675–0.9954× |
| verify | shake_256f | 3203.8323 | 3270.4383 | 0.9884× | 0.9639–0.9913× |
| verify | shake_256s | 1564.5077 | 1579.2421 | 0.9896× | 0.9733–0.9941× |

Times are medians of fork median latencies; speedup uses paired ratios and need not equal the ratio of those two columns. Ranges describe the observed fork medians, not confidence intervals. Helper extraction improves by 24.9–42.7×. SHA2 verification is approximately neutral or modestly improved within observed fork variation. Every SHAKE parameter has a median ratio below one (0.9829–0.9898×), and every SHAKE fork loses. That systematic slowdown is an observed result of this protocol, not dismissed as noise. The allocation reduction remains a direct resource benefit; faster whole verification is not established.

The original JVM loads both implementations and traverses six SHA2 parameter sets before six SHAKE sets. Shared heaps/GC, initial class placement, and engine-call JIT profiles across the SHA2-to-SHAKE transition are plausible confounds. This is a hypothesis, not an established cause of the loss. The separate-process follow-up below examines a different execution model while preserving this observed loss.

## Separate-process follow-up

The new [collector](../../libs/bouncycastle/experiments/isolated-verify.py) and [driver](../../libs/bouncycastle/experiments/ForsIsolatedBenchmark.java) leave the original sources, class trees, fixture, runner and results intact. Each measured JVM has exactly one variant on its application classpath and one parameter set; its reported class-source location must match that variant's frozen tree. Both variants use the original complete-verification implementation and the same two-case corpus. Key parsing is outside timing; valid and tampered signatures are checked before warmup, and timed outputs retain the original post-timer check.

The predeclared final protocol used six process pairs per parameter, with exactly three baseline-first and three candidate-first pairs, two seconds warmup per process, and six rounds of at least 250 ms in whole two-case cycles. Each pair compares the two within-process median latencies; the summary is the median of six process-pair ratios. CPU time accompanies wall time. No completed processes or samples were excluded, and results were not normalized by control operations. The additional warmup and removal of cross-parameter profiling mean this follow-up can test a more isolated execution model without uniquely identifying which original confound caused any difference.

Parameter order remains fixed within each fork. The two cases per parameter give bounded corpus coverage; the timing results cover pure SLH-DSA verification with decoded keys and a new verifier per call, not signing or prehash performance. Timed calls check only the final result after each measured batch; preparation checks both valid cases and their tampered signatures. Process CPU time includes JIT compilation and garbage collection, so it is not a count of cryptographic work alone.

Every child process streams stdout/stderr to a unique raw-output directory, with command, order and exit-status records, so a later failure cannot erase completed measurements. Parsed metrics and complete pairs are also saved incrementally. Preparation logs are retained on failure. Collection requires both exact valid/tampered verification gates, the expected loaded class locations and JVM flags, intact source/class hashes, and Python assertions enabled; optimized Python is rejected. The original and follow-up collectors share the same timing lock.

The separate-process preparation passed: the new driver compiled, and both variants accepted all 24 valid cases and rejected all 24 tampered cases at the expected class-source locations. The [frozen manifest and preparation logs](../../results/bouncycastle/experiments/isolated-preparation) record those checks. The completed timing results follow; the original observed SHAKE losses remain part of the evidence.

The follow-up ran in an exclusive timing window with this predeclared command:

```sh
python3 libs/bouncycastle/experiments/isolated-verify.py run --manifest libs/bouncycastle/build/fors-base2b/isolated-8044dffd08bf7c63/manifest.json --out results/bouncycastle/experiments/fors-isolated-jdk25-arm64.json --forks 6 --start 20 --rounds 6 --budget-ms 250 --warmup-ms 2000
```

The [complete separate-process output](../../results/bouncycastle/experiments/fors-isolated-jdk25-arm64.json) contains 72 process pairs, 144 fresh JVMs and 864 measured rounds. The [independent recomputation](../../results/bouncycastle/experiments/fors-isolated-review.json) checked every raw stdout, command, status, metrics and pair record, all corpus cycles and round budgets, exact three-AB/three-BA balance, every wall/CPU summary, and all frozen source, class, JDK and fixture hashes. All processes exited successfully, with no stderr; no losses or outliers were removed. The [raw process records](../../results/bouncycastle/experiments/fors-isolated-jdk25-arm64.json.raw) are retained.

| Parameter | Baseline µs | Candidate µs | Wall speedup | Process-pair range | CPU speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| sha2_128f | 2576.8282 | 2617.7770 | 0.9951× | 0.9160–1.0072× | 0.9954× |
| sha2_128s | 900.1420 | 897.3686 | 1.0049× | 0.9215–1.0956× | 1.0043× |
| sha2_192f | 3842.0666 | 3793.7678 | 1.0003× | 0.9836–1.0476× | 0.9943× |
| sha2_192s | 1289.3622 | 1296.8410 | 0.9952× | 0.9675–1.0164× | 0.9963× |
| sha2_256f | 3926.4126 | 3841.7732 | 1.0035× | 0.9974–1.0409× | 1.0078× |
| sha2_256s | 1920.0254 | 1938.4034 | 0.9902× | 0.9631–1.0327× | 0.9937× |
| shake_128f | 2169.3442 | 2160.2163 | 1.0041× | 1.0008–1.0121× | 1.0037× |
| shake_128s | 746.3570 | 743.5098 | 1.0045× | 0.9995–1.0097× | 1.0050× |
| shake_192f | 3266.3018 | 3246.3707 | 1.0049× | 0.9982–1.5958× | 1.0031× |
| shake_192s | 1091.3327 | 1090.5905 | 1.0039× | 0.9872–1.0197× | 1.0068× |
| shake_256f | 3249.8874 | 3236.9798 | 1.0047× | 0.9976–1.0068× | 1.0061× |
| shake_256s | 1584.1341 | 1590.2281 | 0.9990× | 0.9935–1.0024× | 0.9993× |

Times are medians of the six within-process median latencies; speedup is the median of the six process-pair ratios and need not equal the ratio of the time columns. The cell medians span 0.9902–1.0049×. The original pattern of all six SHAKE parameters losing in every fork is not reproduced. This does not identify the original cause: process isolation, parameter isolation and warmup duration changed together. Latency remains mixed, including a 0.9902× median for SHA2-256s and a retained 1.5958× wall-time outlier for SHAKE-192f in fork 23 (its CPU ratio is 1.0325×). No reliable general whole-verification latency improvement is established.

The supported improvement is reduced allocation: eliminating temporary `BigInteger` objects cuts measured complete-verification allocation by 7,156–17,716 bytes per call on this runtime. The original systematic SHAKE slowdown remains an observed tradeoff in the shared-JVM protocol, and the follow-up does not justify a universal latency-neutral or faster-verification claim. No signing latency improvement was measured.

## Reproducing the preparation

Use a local Bouncy Castle checkout containing the pinned commit and a compatible JDK. Preparation builds isolated source copies, applies the recorded patch, runs the allocation gate and the full differential corpus, then prints a new hash-bound manifest path. The [exact binary fixture](../../results/bouncycastle/experiments/fors-fixtures.bin) has SHA256 `b68537703f7e28b1b99c21be063f0be20abbdfd9e47c09f41d418f99c6e83a0b`; it contains deterministic test keys and signatures. The small `fixtures.json` file is corpus metadata, not the binary fixture.

```sh
python3 libs/bouncycastle/experiments/fors.py prepare --upstream /path/to/bc-java --java-home /path/to/jdk-home --fixtures results/bouncycastle/experiments/fors-fixtures.bin
python3 libs/bouncycastle/experiments/isolated-verify.py prepare --manifest /path/printed/by/the/first/command/manifest.json
```

Use the printed manifests in the corresponding timing commands above and choose fresh output paths. The recorded manifests contain local paths and compiled-class hashes; they document this run rather than supplying portable compiled classes. Preparation and measurement are separate so compilation and correctness checks finish before an exclusive timing window begins.
