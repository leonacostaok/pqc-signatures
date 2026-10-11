# SLH-DSA SHA-2 compression experiment

The candidate adds an OpenSSL compression backend to liboqs's private SLH-DSA SHA-256 and SHA-512 implementations. Upstream already caches the padded public-seed block; this change preserves those cached states and replaces the remaining portable compression calls with OpenSSL's architecture-specific block transforms. Message framing, addresses, padding, tree traversal, signing randomness, and signature encoding are unchanged.

The baseline is official liboqs main at `fd44469daeffe6b28f031f54f9bb66cbae69a572`, retrieved for this experiment. The candidate is committed as `b14f1b616f938698ebc0bf8b75b3736c30e1502c` in `libs/liboqs/deps/liboqs/worktrees/sha2-performance`, branch `perf/slh-dsa-sha2-openssl`. The benchmark worktree is branch `perf/liboqs-performance`. The complete change is in `upstream.patch`; `evidence/committed-candidate.json` confirms its eight file sections equal the committed diff, ignoring file order, and that it applies to the pinned baseline. No push or PR has been made.

## Scope and compatibility

Acceleration is enabled only with `OQS_USE_SHA2_OPENSSL`, ordinary linking, and availability of OpenSSL's low-level SHA API. Builds without OpenSSL, with SHA-2 OpenSSL disabled, with `OQS_DLOPEN_OPENSSL`, or with `OPENSSL_NO_DEPRECATED` retain the portable implementation. The patch deliberately adds no global dispatch state, RNG interception, persistent cache, or heap allocation. All three full fallback configurations and the six upstream signature tests were rerun after the final cleanup change. The temporary OpenSSL context is explicitly cleared with `OPENSSL_cleanse` after copying the result back. `evidence/cleanse-red.json` records the missing-cleanup test failure before that adjustment, the updated backend probe checks both complete contexts are zeroed, and `sha2-*-compression-assembly.txt` confirms the cleanup calls survive optimization. The existing importer template and a source patch preserve the integration during upstream source refreshes.

OpenSSL's low-level SHA APIs are deprecated in OpenSSL 3; the portable fallback keeps builds that hide those APIs working. Whether maintainers prefer a different long-term acceleration interface remains a review question. Measurements here apply to this Apple arm64 host and OpenSSL build; x86, big-endian, Windows, and OpenSSL 1.1.1 execution are not covered.

## Correctness evidence

- `evidence/backend-red.json`: the backend-use test fails against unmodified upstream because neither OpenSSL transform is called.
- `evidence/hash-checks.json`: after the change, both transforms are called. Four configurations each pass 5,710 checks: 4,096 random chaining-state/block comparisons against exact portable upstream, plus 1,614 hash comparisons over six SHA-2 variants and padding/block boundaries. SHA-224/256/384/512 use Python hashlib as the oracle; SHA-512/224 and SHA-512/256 use OpenSSL EVP because the system Python does not expose them.
- `tests/test_slh_dsa_sha2.c` in the upstream candidate adds independently implemented digest comparisons, incremental updates, and cloned-state coverage around both block and padding boundaries. It is registered with the upstream test runner when SLH-DSA is enabled.
- `evidence/upstream-signature-tests.json` and `test-sig-*.log`: all six enabled pure SHA-2 upstream signature correctness tests pass, including native randomness, contexts, and rejection checks.
- `evidence/config-checks.json` and `config-checks-no-deprecated.json`: full builds and private-hash/public-signature tests pass without OpenSSL, with its SHA-2 disabled, and with deprecated APIs hidden.
- `evidence/dlopen-upstream-limitation.json`: the full macOS dlopen configuration fails on both unmodified upstream and candidate because upstream CMake discovers no ELF SONAME in a Mach-O library, leaving `OQS_OPENSSL_CRYPTO_SONAME` undefined. The isolated candidate dlopen fallback compiles and passes all 5,710 hash checks; a complete Linux dlopen build remains untested.
- `evidence/corpus-manifest.json` and `corpus-*.jsonl`: all 24 corpus cases pass exact key/signature equivalence between baseline and candidate, public API round trips with unchanged native randomness, and message/context/signature tamper rejection. Independently generated corpus files match byte for byte: SHA-256 `0879e36d029fde653b48e8156761f9ea44bc71c37e697767cdb65a6f41b3c36d`.

The final NIST run passes all 396 selected cases with explicit execution markers: 60 key-generation, 168 signing, and 168 verification cases. A separate adapter calls the public `OQS_SIG_verify_with_ctx_str` API for 84 external verification cases; the remaining cases use the unchanged upstream `vectors_sig` executable. `evidence/acvp-checked-execution.json` records every case, and `external-validation-run.json` records the exact commands and positive, negative, inverted-expectation, and missing-execution controls. The same native adapters pass all 216 shared SHA-2 cases from `common/validation/validation.json.gz`, including rejection cases, with no skips; see `shared-validation.json`. The existing production library and upstream executable remain unchanged.

This supersedes the initial NIST report: source review found that upstream `vectors_sig.c:1491` skips external verification in a SHA2-only build, so that first exit-zero run executed only 312 cases and skipped 84. `evidence/acvp-checks.json` explicitly records that limitation, and the adapter controls reproduce it. The legacy `check_acvp.py` is preserved byte for byte because it was part of the sealed experiment snapshot; use `check_acvp_executed.py` or `run_external_validation.py` for current validation. The first corrected run's logs are preserved with `pre-relocation-` prefixes; the final run uses the corrected driver's new filename. Inputs are from the upstream-pinned ACVP-Server tag `v1.1.0.42`; exact URLs, file sizes, and hashes are recorded in `evidence/acvp-vectors.json`. No full pytest-suite claim is made.

The complete corpus covers all six SHA-2 parameter sets with four distinct key/message/randomness cases each. Message lengths are 0, 32, 256, and 4096 bytes; the corresponding contexts are 0, 1, 17, and 255 bytes. Fixed public test seeds and additional randomness are passed only through existing internal fixture-generation APIs. The timed public signing function uses the production RNG normally.

## Observed results

The final cleanup-enabled run completed six balanced fresh-process pairs in 311.76 seconds, with 576 complete result rows. These are the medians of the six paired ratios, with each parameter's four corpus cases weighted equally:

| Parameter | Signing speedup | Verification speedup |
| --- | ---: | ---: |
| SHA2-128f | 5.28× | 5.29× |
| SHA2-128s | 5.27× | 5.17× |
| SHA2-192f | 4.71× | 4.85× |
| SHA2-192s | 4.51× | 4.41× |
| SHA2-256f | 4.68× | 4.74× |
| SHA2-256s | 4.27× | 4.46× |

All 72 parameter/operation paired ratios, each formed after averaging the four corpus cases, exceed 4.25×. Across the 288 individual case/operation paired ratios, the minimum is 4.13988×. Complete raw rows, ratios, bootstrap intervals, and the sealed source/build snapshot are under `evidence/final-paired`. These are observed improvements on an Apple M1 Pro arm64 host with OpenSSL 3.6.4, not cross-platform claims.

The host was exclusive of other coordinated agent builds/tests, but normal desktop processes remained active. Across 62 five-second diagnostics, aggregate non-benchmark CPU had a median of 58.7% and maximum of 175.2% of one core on an eight-core host. `evidence/host-load-assessment.json` gives per-process-round load, and `final-paired/host-load.json` preserves the samples using process names only. No cells or process pairs were discarded. These diagnostics limit claims of fully isolated timing; the observed gain is consistent in every retained pair.

`evidence/linked-backend-provenance.json` confirms both executables resolve the same `/opt/homebrew/Cellar/openssl@3/3.6.4_1/lib/libcrypto.3.dylib`, SHA-256 `a7e687f76c5b69423480050f6bfa91dc2c2f616866476cca485ebc2b68ed0b15`. Runtime version is OpenSSL 3.6.4. ARM SHA-1, SHA-256, SHA-512, SHA-3, and NEON capability sysctls are enabled; no OpenSSL CPU-capability or DYLD library overrides were present. The library hash was rechecked after timing.

## Timing protocol

`paired_benchmark.py` runs six independent baseline/candidate process pairs, alternating AB and BA. Every process exercises the whole 24-case corpus. Each case receives an untimed complete sign/verify warmup, then three timed complete public `OQS_SIG_sign_with_ctx_str` calls and thirty timed public verifications. Sign timing includes the production randomness call. Every generated signature is checked after its timed interval. Verification uses identical valid signature bytes for both builds. Corpus generation, key setup, allocation, warmup, and validation are outside the measured intervals.

Each reported parameter/operation gives equal weight to its four cases. Ratios are paired within process rounds; the report includes all six ratios, their median, the geometric mean, and a paired-round bootstrap interval. The interval describes variability on this host and corpus, not uncertainty across hardware or all possible inputs. The runner rejects missing/failed correctness evidence, incomplete or duplicated output rows, altered sealed source/build/library inputs, and pre-existing output directories.

`evidence/exploratory-pilot` is from the earlier pre-cleanse revision and is explicitly exploratory: one pair with one sign and five verifies while other investigations were active. It establishes feasibility and reserves an estimated six to eight minutes for the final run; its ratios must not be presented as final performance evidence. The final cleanup-enabled run is saved separately under `evidence/final-paired`.

## Reproduction

Use a clean official clone at the pinned baseline and apply the candidate patch to a separate worktree. Commands below run from this benchmark worktree. The scripts use Python's standard library except for the upstream pytest suite. CMake, a C compiler, pkg-config, and OpenSSL headers/libraries must be available. `check_hashes.py` currently uses macOS dynamic-library naming; adjust its linker flag and suffix before running on another platform.

Keep the committed evidence intact when reproducing: direct new output to a separate evidence directory and populate its required input manifests. In particular, the final timing runner and external validation runner refuse to replace their existing completed runs.

```sh
baseline="$PWD/libs/liboqs/deps/liboqs"
candidate="$baseline/worktrees/sha2-performance"
build="$PWD/libs/liboqs/build/sha2-openssl"
experiment="$PWD/libs/liboqs/experiments/sha2-openssl"
evidence="$build/reproduction-evidence"
mkdir -p "$evidence"
openssl_prefix="$(pkg-config --variable=prefix openssl)"
algorithms='SIG_slh_dsa_pure_sha2_128s;SIG_slh_dsa_pure_sha2_128f;SIG_slh_dsa_pure_sha2_192s;SIG_slh_dsa_pure_sha2_192f;SIG_slh_dsa_pure_sha2_256s;SIG_slh_dsa_pure_sha2_256f'
cmake -S "$baseline" -B "$build/baseline" -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON "-DOQS_MINIMAL_BUILD=$algorithms" "-DOPENSSL_ROOT_DIR=$openssl_prefix"
cmake -S "$candidate" -B "$build/candidate" -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON "-DOQS_MINIMAL_BUILD=$algorithms" "-DOPENSSL_ROOT_DIR=$openssl_prefix"
cmake --build "$build/baseline" --target test_sig -j2
cmake --build "$build/candidate" --target test_sig test_slh_dsa_sha2 vectors_sig -j2
python3 "$experiment/check_hashes.py" --baseline "$baseline" --candidate "$candidate" --build "$build/hash-checks" --evidence "$evidence"
python3 "$experiment/check_configs.py" --source "$candidate" --build "$build/configs" --evidence "$evidence" --only no-openssl
python3 "$experiment/check_configs.py" --source "$candidate" --build "$build/configs" --evidence "$evidence" --only sha2-disabled
python3 "$experiment/check_configs.py" --source "$candidate" --build "$build/configs" --evidence "$evidence" --only no-deprecated
```

For the NIST/shared rerun, download the three URLs listed in `evidence/acvp-vectors.json` into `$build/acvp/keyGen.json`, `sigGen.json`, and `sigVer.json`; the checked driver verifies their recorded hashes. Then use a fresh output directory:

```sh
replay_evidence="$build/replay-evidence"
mkdir -p "$replay_evidence"
cp "$experiment/evidence/acvp-vectors.json" "$replay_evidence/"
python3 "$experiment/run_external_validation.py" --build "$build" --validation "$PWD/common/validation/validation.json.gz" --evidence "$replay_evidence"
```

Exact compiler invocations for the two `corpus` executables are recorded in `evidence/corpus-build.json`. Generate and cross-check the fixed corpus with the following commands, recording stdout/exit status; the saved evidence files contain the original commands and results. The candidate-generated file must compare equal before timing.

```sh
"$build/baseline/corpus" generate "$build/corpus.bin"
"$build/candidate/corpus" check "$build/corpus.bin"
"$build/candidate/corpus" generate "$build/candidate-corpus.bin"
cmp "$build/corpus.bin" "$build/candidate-corpus.bin"
python3 "$experiment/seal.py" --baseline "$baseline" --candidate "$candidate" --build "$build" --evidence "$evidence"
```

After an exclusive timing window is granted:

```sh
python3 "$experiment/paired_benchmark.py" --build "$build" --evidence "$evidence" --output "$evidence/final-paired" --forks 6 --sign-iters 3 --verify-iters 30 --exclusive-window-granted
```
