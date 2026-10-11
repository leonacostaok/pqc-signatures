# Library harness contract

Every library lives in `libs/<lib>/` and exposes one entry point, `libs/<lib>/run.sh`, so the
orchestrator (`common/run-all.sh`) can build, check and benchmark all libraries the same way.
Libraries: `noble`, `liboqs`, `openssl`, `circl`, `rustcrypto`, `bouncycastle`.

## Shared inputs

- `common/vectors.json`: message (64 bytes), empty context, one seed per parameter set.
  - ML-DSA: seed = xi (32 B) -> `ML-DSA.KeyGen_internal`. Pure ML-DSA, empty ctx, **deterministic** sign (rnd = 0^32).
  - SLH-DSA: seed = `SK.seed || SK.prf || PK.seed` (3n B) -> `slh_keygen_internal`. Pure, empty ctx,
    **deterministic** sign (opt_rand = PK.seed).
  - Falcon-512/1024: optional, cross-verify only (seed formats are not interoperable).
- `common/reference.json`: SHA-256 of pk, sk, sig for every byte-matchable param. Every library and every
  variant must reproduce these digests exactly. If an API cannot do seeded keygen or deterministic signing,
  find a supported way (custom RNG returning the seed bytes, internal API, importing the seed as a private
  key, etc.) and document it. Only fall back to "verify-only" if truly impossible, and say why.

Parameter names (use exactly): `ML-DSA-44 ML-DSA-65 ML-DSA-87`,
`SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}`, `Falcon-512 Falcon-1024`.

## Subcommands of `run.sh`

| command | what it does |
|---|---|
| `build` | idempotent: fetch deps, compile everything (all variants). Must succeed offline-ish after first run. |
| `vectors <out.json>` | baseline keygen+sign+verify for every supported param, writes artifacts (below). |
| `crossverify <artifacts.json> <out.json>` | verifies every entry of another library's artifacts file with baseline verify. |
| `bench --out <file.jsonl> [--budget-ms N] [--params a,b] [--ops keygen,sign,verify] [--variants id,id]` | benchmarks, one JSON line per (variant, op, param). |

Artifacts file (`vectors`):
```json
{"lib":"noble","lib_version":"0.7.1","entries":[
  {"param":"ML-DSA-44","pk_hex":"..","sig_hex":"..","sk_sha256":"..","pk_sha256":"..","sig_sha256":"..","self_verify":true}
]}
```
Crossverify file: `{"lib":"<verifier>","source":"<signer lib>","results":[{"param":"ML-DSA-44","ok":true,"error":null}]}`.
Unsupported params are skipped (not listed). Also add one tampered-signature check per param
(flip one bit of sig): must return `ok:false` -> report as `"tamper_rejected": true` in each result.

## Processes and variants

Three processes are measured separately: `keygen` (seed -> pk, sk), `sign` (sk, msg -> sig),
`verify` (pk, msg, sig -> bool). Each op is timed in isolation, inputs prepared outside the timed region.

For **each process** a library provides exactly **6 variants**: `<op>.v0` = baseline (the library used the
plain, documented way, default build) and `<op>.v1` .. `<op>.v5` = five alternatives / enhancements that
target that process (build flags, CPU features, different backend/API path, caching/precomputation,
parallel batching, runtime tuning, alternative crate/module, etc.). A variant may share a mechanism with
another op's variant, but each process gets its own list chosen for that process. Every variant must:
1. produce output identical to `common/reference.json` (keygen: pk_sha256 AND sk_sha256; sign: sig_sha256;
   verify: returns true on the reference pk/msg/sig and false on a tampered sig), and
2. be checked for that on every run (set `match` accordingly; never hardcode).

Hedged/randomized variants are not allowed for sign (they cannot byte-match). Parallel/batch variants
are allowed: report throughput (`ops_per_sec` over the batch) and set `threads`.

## Timing method

- Warm-up: at least 1 op (JIT runtimes: warm up properly, e.g. >= 200 ms or 20 ops, whichever is larger,
  capped so slow ops still finish), not recorded.
- Then run until `budget_ms` (default 1000) has elapsed AND at least 3 ops (2 if one op > 5 s), cap 100000.
- Record per-op wall time (monotonic high-res clock) for each iteration; for batch variants, wall per batch / batch size.
- CPU: process CPU time (user+sys; getrusage / process.cpuUsage / ThreadMXBean+process / etc.) over the
  whole measured loop, divided by ops. For multi-threaded variants this captures all threads.

JSON line schema (`bench`):
```json
{"lib":"noble","lib_version":"0.7.1","lang":"js","runtime":"node 22.22.0","variant":"sign.v2",
 "variant_name":"short-name","variant_desc":"one sentence","op":"sign","param":"ML-DSA-65",
 "iterations":123,"threads":1,"wall_ns_median":0,"wall_ns_mean":0,"wall_ns_p95":0,"wall_ns_min":0,
 "cpu_ns_per_op":0,"cpu_util":1.0,"ops_per_sec":0,"output_sha256":"..","match":true}
```
`cpu_util` = total CPU / total wall of the measured loop. `ops_per_sec` = ops / total measured wall seconds.
For verify, `output_sha256` = "true" if verify returned true (and tamper rejected) else "false".

## Documentation

`docs/<lib>/README.md` (overview, versions, build, how seeded/deterministic mode was achieved),
`docs/<lib>/keygen.md`, `docs/<lib>/sign.md`, `docs/<lib>/verify.md`: per process, describe each of the
6 variants (what, why it should help, how it was implemented), then results tables (median wall, CPU/op,
cpu_util, speedup vs v0) per param, and a short conclusion on what worked and what did not.
Results tables are generated from `results/<lib>/bench.jsonl` by `common/report.mjs` (the orchestrator
regenerates them after the final quiet benchmark run), so prose goes in the hand-written part above a
`<!-- RESULTS -->` marker; everything after the marker is overwritten.

## Machine etiquette

The box has 4 cores and other agents build/benchmark at the same time, so numbers taken during
development are noisy. Use `--budget-ms 200` and a few params while developing. The orchestrator
reruns every library's full bench sequentially on a quiet machine for the final numbers.
Keep build outputs inside `libs/<lib>/` (gitignored `build/`, `target/`, `node_modules/`, etc.).
Never write outside `libs/<lib>/`, `docs/<lib>/`, `results/<lib>/`.
