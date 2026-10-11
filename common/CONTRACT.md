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

---

# Phase 2: validation suite, verify stage split, stack memory

Three new `run.sh` subcommands. Same rules as above: every number must come from a run whose outputs
were checked, only write in your own lib/docs/results dirs, never commit.

## A. `validate <common/validation/validation.json.gz> <out.json>`

Gzipped JSON `{cases:[...]}` built by `common/gen-validation.mjs`: official NIST ACVP FIPS 204/205 vectors
(pure / external interface, with contexts) plus a negative/edge suite. Case kinds:

- `keygen`: `seed_hex` (ML-DSA xi; SLH-DSA SK.seed||SK.prf||PK.seed) -> must equal `expect_pk_hex` AND `expect_sk_hex`.
- `siggen`: deterministic sign of `msg_hex` with context `ctx_hex` under `sk_hex` -> must equal `expect_sig_hex`.
  (`sk_hex` is the FIPS-encoded secret key; import it, don't regenerate from a seed.)
- `sigver`: verify (`pk_hex`, `msg_hex`, `ctx_hex`, `sig_hex`) -> must equal `expect` (bool). `reason` says what
  was modified. Malformed input (wrong length, bad hint encoding, ...) must yield `false`; an exception or
  error return counts as `false`, a crash does not pass.

Run **every case through every variant of the matching process** (keygen cases through keygen.v0..v5,
siggen through sign.v0..v5, sigver through verify.v0..v5, and through your end-to-end verify stage pipeline
alternatives from section B where they exist). This matters most for caching/precomputing variants: they must
still reject everything. If a sign variant is too slow for SLH-DSA "s" siggen cases, it may skip those (record
`skipped` with a reason). Skip unsupported params (e.g. Falcon is not in the suite).

Output: `{"lib":..,"lib_version":..,"results":[{"id":..,"variant":"verify.v3","pass":true,"got":false,"error":null}],
"summary":{"<variant>":{"pass":N,"fail":N,"skipped":N}}}`. Failures must be investigated and explained in
`docs/<lib>/validation.md` (a real library bug is a finding, not something to hide).

## B. `stages --out <file.jsonl> [--budget-ms N] [--params a,b] [--stages x,y]`: verify split into stages

Verification is split into canonical stages that every library times separately (inputs for a stage are
precomputed from the previous stages, outside the timed region). Use the library's own internal functions
(call internals, vendor/patch the source with stage entry points, link internal symbols from the static lib,
reflection, ...); document how.

ML-DSA verify (FIPS 204 Alg 8 + external wrapper), on the reference pk/msg/sig (empty ctx):
| stage | work | canonical output for `output_sha256` |
|---|---|---|
| `decode` | pkDecode (rho, t1) + sigDecode (c~, z, h) incl. hint validity check | SHA-256 of `c~` only (internal reps differ) |
| `mu` | tr = H(pk, 64); mu = H(tr \|\| 0 \|\| 0 \|\| M, 64) | SHA-256 of mu (64 B) |
| `expandA` | A^ = ExpandA(rho) (NTT domain) | SHA-256 of coefficients reduced to [0,q), u32 LE, row-major k x l x 256 |
| `w_approx` | c = SampleInBall(c~); w' = NTT^-1(A^ o NTT(z) - NTT(c) o NTT(t1 * 2^d)) | SHA-256 of w' coefficients in [0,q), u32 LE, k x 256, normal domain |
| `hint_check` | ||z||inf check, w1' = UseHint(h, w'), c~' = H(mu \|\| w1Encode(w1'), lambda/4), compare | SHA-256 of w1Encode(w1') bytes |

SLH-DSA verify (FIPS 205 Alg 20 + external wrapper):
| stage | work | canonical output |
|---|---|---|
| `hmsg` | parse sig; digest = H_msg(R, PK.seed, PK.root, M'); split md / idx_tree / idx_leaf | SHA-256 of digest (m bytes) |
| `fors` | PK_FORS = fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS) | SHA-256 of PK_FORS |
| `ht_wots` | all d WOTS+ pkFromSig computations of the hypertree (given each layer's correct input message) | SHA-256 of the d WOTS public keys concatenated (layer 0 first) |
| `ht_auth` | all d XMSS auth-path root computations (given each layer's WOTS pk) + final compare with PK.root | SHA-256 of the d layer roots concatenated |

(Falcon: no stages required.) Canonical outputs must be identical across libraries; the orchestrator checks.

For **each stage**: `<stage>.v0` = the library's own implementation of that stage, plus alternatives
`<stage>.v1..v5` (aim for 5; at least 2 real ones per stage, never pad with near-duplicates; say in the docs
why a stage has fewer). Alternatives can be different algorithms (e.g. ExpandA with 4-way parallel SHAKE,
cached A, lazy reduction NTT, different Montgomery/Barrett reductions, precomputed NTT(t1*2^d), WOTS chains
batched across chains, SHA-256 midstate caching of PK.seed, fused auth-path hashing, ...), different backends,
build flags, etc. Each alternative is checked against v0's canonical output (`match`) on every run.

Also emit, per param, one `stage:"total"` line for the end-to-end verify built from v0 stages, and one
`stage:"total_best"` line for an end-to-end verify you assemble from your fastest correct stage alternatives
(must return true on the reference and false on the negative suite; run it through `validate` too).

JSON line: `{"lib","lib_version","lang","runtime","family":"ml-dsa|slh-dsa","stage","variant":"expandA.v2",
"variant_name","variant_desc","param","iterations","wall_ns_median","wall_ns_mean","wall_ns_p95","wall_ns_min",
"cpu_ns_per_op","cpu_util","ops_per_sec","threads","output_sha256","match"}`.

## C. `memory --out <file.jsonl> [--params a,b]`: stack (and heap) per operation

For keygen, sign and verify, for **every variant** (and for each verify stage v0 and `total_best`), measure the
peak **stack** used by one operation, plus heap where you can. Suggested methods (pick the most accurate your
runtime allows and document the resolution):
- C/C++ and Rust: run the op on a thread whose stack you allocate (pthread_attr_setstack), paint it with a
  pattern, run, scan for the high-water mark. Heap: count bytes via an interposed/global allocator
  (peak live bytes and total allocated per op).
- Go: goroutine stacks are growable and copied; e.g. pre-grow a goroutine stack, paint the unused part via
  unsafe, run with GC disabled, scan; or binary-search `debug.SetMaxStack` in subprocesses (power-of-two
  resolution). Heap: runtime.MemStats TotalAlloc / HeapAlloc deltas per op.
- JS (V8): binary-search the smallest `--stack-size` (KiB) for which the op still succeeds, in subprocesses;
  heap via `--expose-gc` + `v8.getHeapStatistics()` / allocation deltas.
- Java: binary-search the `Thread(.., stackSize)` that still completes without StackOverflowError (after JIT
  warm-up, and also interpreted with -Xint if cheap); heap via `ThreadMXBean.getThreadAllocatedBytes`.
Parallel variants: report per-worker stack and set `threads`.

JSON line: `{"lib","variant","op","param","stack_bytes","stack_method","stack_resolution_bytes",
"heap_alloc_bytes_per_op","heap_peak_bytes","heap_method","threads","match"}` (null when not measurable).
For verify stages use `op:"verify-stage"` and add `"stage"`.

## D. Docs

Add `docs/<lib>/validation.md`, `docs/<lib>/verify-stages.md`, `docs/<lib>/memory.md` (prose above
`<!-- RESULTS -->`, how it was measured, what each stage alternative does and why, conclusions). Update
`docs/<lib>/README.md` with the new subcommands.
