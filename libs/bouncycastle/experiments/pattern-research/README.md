# Bouncy Castle pattern probes

These are research probes, separate from production patches and the confirmed comparison table. [Findings and limits](../../../../docs/bouncycastle/pattern-research.md) distinguish source-derived savings, arithmetic equivalence checks, and a short whole-operation screen. Supporting tests and analysis are AI-assisted.

## Arithmetic oracle

```sh
python3 libs/bouncycastle/experiments/pattern-research/invntt_oracle.py
```

This uses committed pinned source snapshots and checks their hashes/constants. It compares the existing and folded inverse-NTT arithmetic, Java range bounds and independent schoolbook sparse products. It makes no timing claim and is not a Java signature implementation. Disabled assertions are rejected.

## Address-hoisting screen

```sh
python3 libs/bouncycastle/experiments/pattern-research/run_address_probe.py prepare \
  --original /path/to/slh-deep/prepared-c8eeabbff5cec835/manifest.json
python3 libs/bouncycastle/experiments/pattern-research/run_address_probe.py collect
```

The parent is the unchanged SLH baseline build at `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`, preserved by the [earlier source/evidence archive](../../../../results/bouncycastle/slh-deep/pilot-evidence.tar.gz). Its baseline source tar, class directory, fixtures and recorded JDK must be available. The preparation checks the parent class digest and exact WotsPlus source, copies dependencies into isolated directories, recompiles both WotsPlus variants with identical options, and requires only that class to differ. It compiles identical drivers, runs transcript and real-operation gates, and freezes hashes before measurement. No original source/build is modified.

The recorded parent manifest contains original absolute paths. A different machine needs a separate manifest copy pointing to reconstructed dependencies/JDK; do not edit the historical evidence. A different compiler/runtime is a new experiment, not a reproduction of old binary hashes. Preparation and collection refuse to overwrite existing output. Use a separate checkout for another run. Timing is serial; do not run benchmarks or builds concurrently.

`address_probe.py` is the frozen collector used for the recorded screen. Its assertion dependence was identified in review; `run_address_probe.py` is the guarded entry point added without changing those sealed collector bytes. Do not invoke the collector with `-O` or `PYTHONOPTIMIZE`.

The screen fixes two fast parameter sets, three whole actions, two balanced process pairs and separate timing/allocation workloads. Four measured fixture values repeat within each process, with fresh operation objects; two disjoint warmup keys receive 80 calls. Import/decoding is outside the inherited operation timer. Every measured output is checked after timing. This is a small warmed screen, not a fresh-unique-value-per-call experiment, all-parameter validation, native upstream approval or a peak-memory study.

## Saved-evidence review

```sh
python3 libs/bouncycastle/experiments/pattern-research/address_audit.py /path/to/checkout
```

This independently recomputes source/class/runtime bindings, all raw output/gate digests, schedule coverage, budgets and summary arithmetic. The local binary-binding checks require the recorded build paths and JDK; it must not be described as a portable binary verification on an empty clone. The committed [audit result](../../../../results/bouncycastle/pattern-research/address/independent-check.json), raw commands/results, patch, source snapshots and inventories remain available without those builds. Both audit entry points reject disabled assertions. No repository-native security certification is implied.
