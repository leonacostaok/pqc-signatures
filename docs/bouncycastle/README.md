# Bouncy Castle (Java) harness

| | |
|---|---|
| Library | Bouncy Castle `bcprov-jdk18on` **1.86** (+ `bcutil-jdk18on` 1.86), fetched from Maven Central, SHA-256 checked against the `.jar.sha256` published next to the artifact |
| Language / runtime | Java, OpenJDK 21.0.12.1 (HotSpot 64-bit Server VM, G1 GC, tiered C1/C2 JIT by default) |
| Algorithms | ML-DSA-44/65/87, all 12 SLH-DSA parameter sets (byte-matched), Falcon-512/1024 (cross-verify only) |
| Entry point | `libs/bouncycastle/run.sh build \| vectors \| crossverify \| bench` |
| Sources | `libs/bouncycastle/src/{Bench,Variants,Alg,Json}.java` (no build tool, plain `javac`) |

BC is a pure-Java implementation: no native code, no SIMD intrinsics beyond what HotSpot auto-vectorises.
ML-DSA lives in `org.bouncycastle.crypto.signers.mldsa` (engine `MLDSAEngine`, in-place NTT), SLH-DSA in
`org.bouncycastle.crypto.signers.slhdsa`, Falcon in `org.bouncycastle.pqc.crypto.falcon`. Two public API
layers exist: the JCA provider (`KeyPairGenerator`/`Signature.getInstance("ML-DSA", "BC")`) and the
"lightweight" API (`MLDSAKeyPairGenerator`, `MLDSASigner`, `SLHDSASigner`, key parameter classes). Both are used by the variants.

## Build

```
libs/bouncycastle/run.sh build
```

Downloads the two jars into `libs/bouncycastle/deps/` (idempotent, offline after the first run), verifies the
checksums and compiles the four source files into `libs/bouncycastle/build/classes` with `javac --release 21`.
Nothing else is needed: Maven/Gradle are deliberately not used so the build has no plugin/network dependency.

## How seeded key generation and deterministic signing were achieved

* **ML-DSA keygen from the 32-byte seed.** BC's `MLDSAKeyPairGenerator` draws exactly one 32-byte `xi` from the
  `SecureRandom` it is initialised with and calls `MLDSAEngine.generateKeyPairInternal(xi)` (FIPS 204
  `ML-DSA.KeyGen_internal`). The harness passes a `SecureRandom` subclass (`Alg.SeedRandom`) whose `nextBytes`
  returns the seed bytes in order and throws if more bytes are requested than the seed holds. The same object
  works through the JCA layer (`KeyPairGenerator.initialize(MLDSAParameterSpec, SecureRandom)`). Variant
  `keygen.v3` bypasses the RNG entirely via `new MLDSAPrivateKeyParameters(params, seed32, null)`, which BC
  treats as "seed form" and expands.
* **SLH-DSA keygen from `SK.seed || SK.prf || PK.seed`.** `SLHDSAKeyPairGenerator.generateKeyPair()` calls
  `random.nextBytes` three times, for `skSeed`, `skPrf`, `pkSeed` in that order (checked in the 1.86 source), which is
  exactly the layout of the shared seed, so the same `SeedRandom` reproduces `slh_keygen_internal`. `keygen.v3`
  calls `SLHDSAKeyPairGenerator.internalGenerateKeyPair(skSeed, skPrf, pkSeed)` directly.
* **Deterministic ML-DSA signing (rnd = 0^32).** `MLDSASigner.init(true, privateKey)` without a
  `ParametersWithRandom` leaves `random == null`, and `generateSignature()` then uses a zeroed 32-byte `rnd`.
  Through JCA, `Signature.initSign(PrivateKey)` (the overload without a `SecureRandom`) has the same effect
  (`BaseDeterministicOrRandomSignature` only wraps in `ParametersWithRandom` when an app random was given).
  Pure mode with empty context is the default (`ContextParameterSpec.EMPTY_CONTEXT_SPEC`).
* **Deterministic SLH-DSA signing (opt_rand = PK.seed).** Same mechanism: `SLHDSASigner` with `random == null`
  copies `PK.seed` into `optRand`.
* **Secret key encoding.** `MLDSAPrivateKeyParameters.getEncoded()` is the expanded FIPS 204 key
  `rho || K || tr || s1 || s2 || t0` (2560/4032/4896 bytes), never the seed; the JCA key exposes the same bytes via
  `MLDSAPrivateKey.getPrivateData()`. `SLHDSAPrivateKeyParameters.getEncoded()` is `SK.seed || SK.prf || PK.seed || PK.root`.
  Public keys: `rho || t1` and `PK.seed || PK.root`.
* **Falcon** is generated with a SHAKE256-stream `SecureRandom` seeded from `vectors.json` (reproducible but
  not interoperable, as the contract expects). BC stores the public key without the `0x00|logn` header byte and
  emits variable-length `0x30|logn || nonce || compressed` signatures; the artifacts file carries the standard
  forms (header byte added, signature zero-padded to 666/1280 bytes). When cross-verifying other libraries'
  Falcon entries the harness strips a 897/1793-byte key's header, drops zero padding and accepts both
  `0x20|logn` and `0x30|logn` signature headers (`Alg.falconNormaliseSig`).

`run.sh vectors` checks every byte-matchable parameter set against `common/reference.json` and exits non-zero on a
mismatch; `bench` recomputes the baseline artifacts at start-up, compares them to the reference, and every
variant compares every single output (pk+sk / signature / verify result and tamper rejection) to those bytes, so
the `match` field is always computed, never assumed.

## Benchmark driver

`Bench bench` runs in the parent JVM for variants that do not need JVM flags. Variants with JVM flags
(`keygen.v5`, `sign.v4`, `sign.v5`, `verify.v4`, `verify.v5`) are executed in a child JVM
(`java <flags> -cp ... Bench bench --child ...`) whose JSON lines are forwarded to the output file, so the
parent's own JIT/GC state never contaminates them. Per cell (variant, op, param):

1. one op to take the output digest and run the tamper check;
2. for parallel variants, one batch to size the batch (target >= 40 ms per batch, at most 16 ops per lane);
3. warm-up until >= 1 s *and* >= 20 ops, capped at ~3 s for the slow SLH-DSA operations, not recorded;
4. measured loop until `budget_ms` elapsed and >= 3 ops (2 if an op exceeds 5 s), cap 100 000 ops; per-op wall
   via `System.nanoTime()` (per batch / batch size for parallel variants); process CPU via
   `com.sun.management.OperatingSystemMXBean.getProcessCpuTime()` over the whole loop, divided by ops.

`cpu_util` above 1.0 for single-threaded variants is real: HotSpot's JIT compiler and GC threads also consume
CPU and are counted, as the contract requires. Extra fields in each line: `batch`, `jvm_flags` (where used),
`pk_sha256`/`sk_sha256` for keygen.

## Commands

```
libs/bouncycastle/run.sh build
libs/bouncycastle/run.sh vectors results/bouncycastle/artifacts.json
libs/bouncycastle/run.sh crossverify results/noble/artifacts.json results/bouncycastle/crossverify-noble.json
libs/bouncycastle/run.sh bench --out results/bouncycastle/bench.jsonl                     # full, 1 s budget
libs/bouncycastle/run.sh bench --out dev.jsonl --budget-ms 200 --params ML-DSA-44 --ops sign --variants sign.v2
```

## Known caveats

* Java numbers depend on JIT warm-up; the per-cell warm-up (3) is generous, but the parent JVM additionally
  benefits from earlier cells having compiled the shared Keccak/NTT code, so the first cells of a run are the
  "coldest". Child-JVM variants start cold every time (hence the warm-up cap matters for them most).
* `getProcessCpuTime` on Linux has coarse (tick) granularity for short loops; with a 1 s budget the error is ~1 %.
* The `parallel` variants report throughput over all cores; on the shared 4-core development box they are the
  noisiest numbers and should only be read from the quiet final run.
