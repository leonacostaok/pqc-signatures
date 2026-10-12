# Additional native checks

These scripts supplement the separate NTT, matrix and WOTS experiment gates. They do not measure performance. Use a fresh reproduction worktree so recorded evidence remains unchanged.

`prepare_native.py BC_JAVA_CHECKOUT JAVA_BINARY HAMCREST_JAR` exports bc-java `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`, compiles native tests with the checkout's JUnit 4.13.2 jar, and fetches the 36 selected ML-DSA test-data files from bc-test-data `3c385e9f4c0b12ce5a86d2b29a17fb3b68dd4e1a`. Downloads are checked against their pinned Git blob identities. The Java runtime and class identities are recorded. Build outputs stay under `libs/bouncycastle/build/alternative-comparison/`.

Run a prepared ML-DSA variant with:

```sh
python3 libs/bouncycastle/experiments/alternative-comparison/run_native.py --family ml --label ntt-fused --classes /absolute/path/to/fused/classes
```

For SLH-DSA, use `--family slh`, the corresponding `wots-VARIANT` label and `--slh-data /absolute/path/to/pinned/slh/test-data`. Its files must match `results/bouncycastle/experiments/upstream-test-data.json`. This selects complete native verification-vector methods and two API checks, not the entire native signing suite. `-Dtest.full=true` prevents the native vector sampler from reducing those selected methods.

The runner puts variant classes first on the classpath and verifies the origins of the changed arithmetic/address classes. Native test dependencies are separately compiled from the same source pin. A nonzero result is retained and fails the command. Every variant class file is hashed before and after the run; the runner refuses to overwrite an existing result label.

After all 14 labelled builds are present, check the saved evidence with:

```sh
python3 libs/bouncycastle/experiments/alternative-comparison/audit_native.py
```

This last command checks stored records, source/runner identities and pinned vector hashes; it does not need the original absolute binary paths and does not rerun cryptography. A passing saved-evidence audit does not prove that unavailable binaries would pass again. All entry points reject optimized Python because their checks use assertions.

`audit_chronology.py` checks every recorded benchmark process interval across the campaigns and verifies that the initial native gates preceded collection. It detects overlapping recorded benchmark processes; it cannot establish host isolation. `--initial-only` checks the three first-stage screens without their selected followups.

After the group audits have been saved under `results/bouncycastle/alternative-comparison/`, `report_measurements.py` renders every comparison into `docs/bouncycastle/alternative-measurements.md` and its machine-readable companion. Green/red marks numerical direction, not confidence. Static memory costs and unmeasured peak/GC metrics are documented separately.
