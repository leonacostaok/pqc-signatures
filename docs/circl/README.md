# Cloudflare CIRCL (Go)

Harness: `libs/circl/run.sh` (Go program in `libs/circl/cmd/pqcbench/`).

## Versions

| component | version |
|---|---|
| library | `github.com/cloudflare/circl` **v1.6.5** (latest release with `sign/mldsa/{mldsa44,mldsa65,mldsa87}` and `sign/slhdsa`) |
| language / runtime | Go. CIRCL v1.6.5 declares `go 1.25.0`, so the installed Go 1.24.7 toolchain auto-downloads and runs **go1.25.0** (`GOTOOLCHAIN=auto`, cached in the module cache). The `runtime` field of every bench line is `go1.25.0 linux/amd64`. |
| transitive deps | `golang.org/x/crypto v0.54.0`, `golang.org/x/sys v0.47.0` |

Coverage: ML-DSA-44/65/87 and all twelve SLH-DSA parameter sets (SHA2/SHAKE x 128/192/256 x s/f).
CIRCL has no Falcon / FN-DSA implementation, so Falcon is skipped (not listed in artifacts, bench or crossverify).

## Build

`run.sh build` is idempotent and produces four binaries from the same source under `libs/circl/build/`
(gitignored); `go build` caching makes re-runs instant, and `go mod download` populates the module cache so
later builds work offline.

| binary | build command | used by variants |
|---|---|---|
| `pqcbench-default` | `go build` | `*.v0`, `sign.v1`, `verify.v1`, `keygen.v4`, `*.v5` (also `vectors` and `crossverify`) |
| `pqcbench-purego`  | `go build -tags purego` | `keygen.v1`, `sign.v2`, `verify.v2` |
| `pqcbench-amd64v3` | `GOAMD64=v3 go build` | `keygen.v2`, `sign.v3`, `verify.v3` |
| `pqcbench-pgo`     | `go build -pgo=build/default.pgo` | `keygen.v3`, `sign.v4`, `verify.v4` |

`build/default.pgo` is a CPU profile (`runtime/pprof`) collected once by `pqcbench-default profile`: it runs
keygen/sign/verify for every parameter set in both the packed-key and pre-unpacked-key code paths for ~150 ms
each. Collecting it is the only slow part of the build (about a minute, dominated by SLH-DSA "s" signatures).

Each binary knows its flavor through `-ldflags "-X main.flavor=..."` and, when asked to `bench`, only runs
the variants assigned to that flavor; `run.sh bench` truncates the output file once and then runs the
four binaries in sequence, each appending its own JSON lines.

## Seeded key generation and deterministic signing

Everything byte-matches `common/reference.json` through public, documented API only (no internal packages:
`sign/mldsa/*/internal` is a Go `internal` package and cannot be imported from outside CIRCL).

- **ML-DSA keygen**: `mldsa44.NewKeyFromSeed(&seed)` with the 32-byte xi from `vectors.json` is exactly
  `ML-DSA.KeyGen_internal`. Keys are serialized with `PublicKey.Pack` / `PrivateKey.Pack` (FIPS 204
  encodings, 1312/2560 B etc.).
- **ML-DSA sign**: `mldsa44.SignTo(sk, msg, nil /*ctx*/, false /*randomized*/, sig)`: `randomized=false`
  makes CIRCL use rnd = 0^32, i.e. the FIPS 204 deterministic variant; nil context = empty context; the
  pure-mode domain separator `0 || len(ctx) || ctx` is added by the package.
- **ML-DSA verify**: `mldsa44.Verify(pk, msg, nil, sig)`.
- **SLH-DSA keygen**: `slhdsa.GenerateKey(rand io.Reader, id)` reads `SK.seed`, then `SK.prf`, then
  `PK.seed` (n bytes each) from the reader and calls `slhKeyGenInternal`. Feeding it a `bytes.Reader`
  over the contract seed `SK.seed || SK.prf || PK.seed` reproduces `slh_keygen_internal` exactly
  (verified against the reference digests for all 12 sets). Keys are serialized with `MarshalBinary`
  (`sk = seed || prf || pk.seed || pk.root`, `pk = seed || root`).
- **SLH-DSA sign**: `slhdsa.SignDeterministic(&priv, slhdsa.NewMessage(msg), nil)` uses
  `opt_rand = PK.seed` as FIPS 205 specifies for the deterministic variant; pure mode, empty context.
- **SLH-DSA verify**: `slhdsa.Verify(&pub, slhdsa.NewMessage(msg), sig, nil)`.

Every bench line recomputes its output and compares SHA-256 against `common/reference.json` at runtime
(`match`); for keygen both `pk_sha256` and `sk_sha256` must match (the line's `output_sha256` is the pk
digest), for sign `sig_sha256`, and verify must return true on the reference inputs and false on a
signature with one flipped bit. Batch variants additionally require every op in every batch to produce
output identical to the first op.

## What "baseline" means here

The contract defines the processes as `seed -> (pk, sk)`, `(sk, msg) -> sig` and `(pk, msg, sig) -> bool`
on serialized keys, so the baseline `sign.v0`/`verify.v0` start from the packed key bytes exactly as an
application that loads keys from storage would: `PrivateKey.UnmarshalBinary(skBytes)` (which runs
`ExpandA(rho)` and the NTTs of s1, s2, t0 for ML-DSA) and then `SignTo` into a freshly allocated buffer.
Keeping the unpacked `PrivateKey`/`PublicKey` object around is the first optimisation (`v1`), and it is the
single most effective one for ML-DSA.

## Timing method

- Wall time per op from `time.Now()` / `time.Since()` (Go's monotonic clock) around every call; for the
  parallel variants the wall per batch divided by the batch size (= number of workers).
- CPU time from `syscall.Getrusage(RUSAGE_SELF)` (user + sys) over the whole measured loop, divided by
  the number of ops; `cpu_util` = CPU / wall of the loop. Note that even single-threaded variants can show
  `cpu_util` slightly above 1.0: Go's garbage collector runs concurrently on other cores, and that time is
  charged to the process.
- Warm-up: at least one op (Go is AOT-compiled, no JIT) and then up to 100 ms / 10 calls, not recorded.
  Measured loop: until `budget_ms` elapsed and >= 3 calls (2 if a call takes > 5 s), capped at 100 000 calls.
- Inputs (seed, packed keys, reference signature, tamper check) are prepared once per process and never
  inside the timed region.

## Running

```
libs/circl/run.sh build
libs/circl/run.sh vectors results/circl/artifacts.json
libs/circl/run.sh crossverify results/<other>/artifacts.json results/circl/crossverify-<other>.json
libs/circl/run.sh bench --out results/circl/bench.jsonl [--budget-ms 1000] [--params ..] [--ops ..] [--variants ..]
# Phase 2
libs/circl/run.sh validate common/validation/validation.json.gz results/circl/validation.json
libs/circl/run.sh stages --out results/circl/stages.jsonl [--budget-ms 1000] [--params ..] [--stages ..]
libs/circl/run.sh memory --out results/circl/memory.jsonl [--params ..]
```

## Phase 2 (validation, verify stages, memory)

- `validate`: every ACVP/negative case through every variant of the matching process (keygen.v0-5,
  sign.v0-5, verify.v0-5 plus `verify.total` and `verify.total_best`); the default binary spawns the other
  three build flavors as sub-processes and merges their results. See `validation.md`.
- `stages`: ML-DSA verify split into `decode, mu, expandA, w_approx, hint_check` and SLH-DSA verify into
  `hmsg, fors, ht_wots, ht_auth`, each with CIRCL's own code as v0 plus alternatives, and `total` /
  `total_best` pipelines. CIRCL's internals are Go `internal` packages, so verbatim copies live under
  `libs/circl/vendorcircl/` (license kept, only import paths rewritten) with harness-added `stages.go`
  entry points. See `verify-stages.md`.
- `memory`: peak goroutine stack per op by pre-growing and painting a goroutine stack (GC off, async
  preemption off) and heap via `runtime.MemStats`. See `memory.md`.

`crossverify` and `bench` always write their output and exit 0; failures are reported in the `ok` /
`match` fields (plus a warning on stderr). `vectors` exits non-zero if any digest differs from the reference.
A full `bench` (18 variants x 15 params, 1 s budget) takes roughly 10-15 minutes because SLH-DSA "s" signing
costs about 2 s per operation in CIRCL; a full `validate` about 6-7 minutes (the SLH-DSA "s" sigGen cases run
through all six sign variants, nothing is skipped); a full `stages` about 8 minutes; `memory` about 1 minute.

## Cross-verification status (development run)

CIRCL's baseline verifier accepted every entry of its own artifacts and of the artifacts published by
bouncycastle, openssl and rustcrypto (15/15 each, tampered signatures rejected). Falcon entries from other
libraries are skipped.
