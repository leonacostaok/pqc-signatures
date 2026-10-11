# pqc-signatures

Post-quantum signature benchmarks across six libraries: **ML-DSA** (FIPS 204), **SLH-DSA** (FIPS 205) and
Falcon. Each library's keygen, sign and verify are measured separately for time, CPU and memory, against
5 alternatives per process. Verify is also split into its algorithm stages, with alternatives per stage.
Every number comes from a run whose output was checked byte for byte.

| library | language | version |
|---|---|---|
| [noble](docs/noble/README.md) | JavaScript | @noble/post-quantum 0.7.1 |
| [liboqs](docs/liboqs/README.md) | C | 0.16.0 |
| [OpenSSL](docs/openssl/README.md) | C | 3.5.9 |
| [CIRCL](docs/circl/README.md) | Go | 1.6.5 |
| [RustCrypto](docs/rustcrypto/README.md) | Rust | ml-dsa 0.1.1, slh-dsa 0.2.0-rc.5 |
| [Bouncy Castle](docs/bouncycastle/README.md) | Java | 1.86 |

## Where to read

- **[RESULTS.md](RESULTS.md)**: all cross-library tables: baselines, best variants, variant leaderboards, verify stages, memory
- **[results/MATCH.md](results/MATCH.md)**: byte-match, cross-verification, validation and stage-agreement report
- **[docs/methodology.md](docs/methodology.md)**: how it was measured
- **[docs/approaches.md](docs/approaches.md)**: every alternative explained, grouped by idea
- **[docs/validation.md](docs/validation.md)**, **[docs/verify-stages.md](docs/verify-stages.md)**, **[docs/memory.md](docs/memory.md)**
- `docs/<lib>/{keygen,sign,verify,verify-stages,memory,validation}.md`: per-library, per-process write-ups with full tables

## Correctness: everything matches

- All 6 libraries produce **byte-identical** public keys, secret keys and signatures for all 15 ML-DSA / SLH-DSA
  parameter sets from the shared seeds ([common/reference.json](common/reference.json)).
- **36/36 cross-verification pairs** pass: every library verifies every other library's signatures (Falcon
  between noble, liboqs and Bouncy Castle) and rejects tampered copies.
- **Validation suite** (NIST ACVP FIPS 204/205 keyGen/sigGen/sigVer + 258 negative tests), run through every
  variant: 35,763 checks, **0 failures**. No library bugs found.
- **1,660 benchmark rows and 2,115 verify-stage rows** all match their reference; the canonical intermediate verify
  values (mu, A, w', w1, H_msg, FORS pk, WOTS pks, roots) agree across all libraries (93/93 comparisons).

## Headline results (baseline v0, median, 4-core x86-64, AVX2)

| | ML-DSA-44 sign | ML-DSA-44 verify | SLH-DSA-SHA2-128f sign | SLH-DSA-SHAKE-128s sign | SLH-DSA-SHAKE-128s verify |
|---|---|---|---|---|---|
| noble | 2.07 ms | 1.19 ms | 100.8 ms | 14.2 s | 12.4 ms |
| liboqs | **26.3 µs** | **18.0 µs** | **27.3 ms** | 1.10 s | 1.63 ms |
| OpenSSL | 253 µs | 132 µs | 46.3 ms | **0.99 s** | **0.92 ms** |
| CIRCL | 74.9 µs | 46.4 µs | 49.3 ms | 1.25 s | 1.08 ms |
| RustCrypto | 176 µs | 103 µs | 36.1 ms | 2.29 s | 1.89 ms |
| Bouncy Castle | 167 µs | 105 µs | 47.7 ms | 1.19 s | 1.06 ms |

## What we learned

- **ML-DSA is fast everywhere; SLH-DSA "s" signing is the real cost.** ML-DSA does everything in micro- to
  milliseconds. SLH-DSA "s" sets take 0.5–4 s per signature in compiled code (14–26 s in pure JS). Pick "f" sets if
  signing speed matters and signature size doesn't.
- **liboqs is fastest for ML-DSA by 2.5–10×** (hand-written AVX2 from mldsa-native); OpenSSL leads the SHAKE SLH-DSA
  sets and liboqs the SHA2 ones.
- **The biggest single wins were hashing tricks.** Caching the SHA-2 midstate of PK.seed (1.2–4× on SHA2 SLH-DSA in
  liboqs, OpenSSL, CIRCL, Bouncy Castle), and 4-lane AVX2 Keccak (RustCrypto SLH-DSA-SHAKE verify 4–5× faster).
- **Rewriting the hot code paths in noble gave 1.8–2.2×** across all processes (lazy NTT, unrolled Keccak, direct
  compression-function calls). Note this is our patched copy, not the npm package.
- **Build flags barely matter** for libraries that already ship assembly (±15%); **removing the assembly costs 20–40%**.
- **Per-key caching** (expanded matrix, NTT(t1), tr) gives 1.1–4× on ML-DSA verify/sign, but only when the same key
  is reused. Every caching result is labelled as such.
- **Batch parallelism scales (mostly 2.2–3.5× on 4 cores); splitting one ML-DSA verify across threads does not.** The
  stages are 5–500 µs, so the thread hand-off costs more than it saves.
- **Verify, best of everything:** combining the fastest stage from any library gives ML-DSA-44 verify in ~7 µs
  (with per-key caches) and SLH-DSA-SHAKE-128s in ~364 µs (vs 0.92 ms for the fastest stock library).
- **Stack:** most implementations stay at 1–8 KiB. RustCrypto ML-DSA keygen needs 197–428 KiB and liboqs ML-DSA
  30–113 KiB, which matters on embedded targets. **Heap** varies by orders of magnitude (Bouncy Castle allocates
  84 MB per SLH-DSA-SHAKE-128s signature; CIRCL's PGO build allocates 13.9 MB per SLH-DSA-SHA2 signature because
  of a heap escape).

## Caveats

- Numbers are from one VM (4 vCPU, AVX2 + AVX-512VL, no SHA-NI). Other CPUs, especially ones with SHA-NI or ARM, will rank differently.
- "Best" stage combinations that use per-key caches only apply when verifying many signatures under one key.
- Memory methods differ by runtime (stack painting in C/Rust/Go, calibrated recursion probes in JS/Java), so compare
  within a language more than across. A few JVM stack readings are 0 B, which are below the probe's resolution after JIT inlining.
- noble's SLH-DSA "s" sets have baseline-only memory measurements (same code path as "f").

## Reproduce

```sh
npm install
common/run-final.sh          # resumable: build, bench, verify stages, memory, validation for all libraries
common/run-all.sh            # one-shot variant, also redoes byte-match and cross-verification
```
Each library is driven by `libs/<lib>/run.sh {build|vectors|crossverify|bench|stages|memory|validate}`; the
contract is in [common/CONTRACT.md](common/CONTRACT.md). The validation suite is generated by
[common/gen-validation.mjs](common/gen-validation.mjs) from usnistgov/ACVP-Server.
