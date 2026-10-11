# RustCrypto (`ml-dsa` + `slh-dsa`)

Pure-Rust implementations of FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) from
[github.com/RustCrypto/signatures](https://github.com/RustCrypto/signatures). No Falcon (RustCrypto
has no FN-DSA crate), so this library covers ML-DSA-44/65/87 and all 12 SLH-DSA parameter sets.

| component | version | notes |
|---|---|---|
| `ml-dsa` | 0.1.1 | latest release on crates.io (stable 0.1 line) |
| `slh-dsa` | 0.2.0-rc.5 | latest *published* version (the newest non-prerelease is 0.1.0, which uses the older `digest 0.10` stack; rc.5 is what the 0.2 line will ship) |
| `sha3` 0.11 / `shake` 0.1 / `keccak` 0.2.2 | — | Keccak permutation: portable 64-bit software backend on x86-64 (the `simd256/512` backends need nightly `portable_simd`, so they are not usable on stable 1.97) |
| `sha2` 0.11 | — | SHA-256 uses the `x86-sha` (SHA-NI) backend at runtime when the CPU has it; the benchmark VM does **not** expose `sha_ni`, so the portable backend runs |
| toolchain | rustc/cargo 1.97.0, LLVM 22 | stable channel; `llvm-tools` component for `llvm-profdata` |

## Harness layout

```
libs/rustcrypto/
  Cargo.toml        one bin crate "pqcbench"; profiles release (v0) and lto (fat LTO, cgu=1, panic=abort)
  build.rs          bakes crate versions, rustc version and the build tag into the binary
  src/schemes.rs    byte-in/byte-out wrappers (keygen/sign/verify + cached-key closures) for all 15 params
  src/main.rs       vectors / crossverify / bench subcommands, timing loop, variant table
  run.sh            contract entry point; builds 7 binaries under target/<tag>/ and runs them in turn
```

The same source is compiled 7 times with different settings (build tags `base`, `native`, `lto`,
`mimalloc`, `pgo-keygen`, `pgo-sign`, `pgo-verify`). Every binary knows its tag and `bench` only emits
the variants that belong to it, so `run.sh bench` simply runs every binary with the same arguments and
they append to the same `.jsonl`. `run.sh build` is idempotent (cargo no-ops; PGO training is skipped
when the PGO binaries are newer than the sources). Builds use `CARGO_BUILD_JOBS=2` by default.

```
libs/rustcrypto/run.sh build
libs/rustcrypto/run.sh vectors results/rustcrypto/artifacts.json
libs/rustcrypto/run.sh crossverify results/noble/artifacts.json results/rustcrypto/crossverify-noble.json
libs/rustcrypto/run.sh bench --out results/rustcrypto/bench.jsonl [--budget-ms 1000] [--params ..] [--ops ..] [--variants ..]
```

## Seeded keygen and deterministic signing (byte-matching)

Both crates expose the FIPS "internal" algorithms, so no RNG tricks were needed:

* **ML-DSA keygen**: `SigningKey::<P>::from_seed(&xi)` is `ML-DSA.KeyGen_internal` (Alg. 6) on the
  32-byte ξ from `vectors.json`. `pk = sk.verifying_key().encode()` (pkEncode). The reference `sk`
  digest is over the FIPS *expanded* encoding (ρ‖K‖tr‖s1‖s2‖t0, 2560/4032/4896 bytes); `ml-dsa` 0.1
  treats the seed as the preferred private-key serialisation and marks the expanded form deprecated,
  but it is still available as `ExpandedSigningKey::to_expanded()` / `from_expanded()` (skEncode /
  skDecode), used with `#[allow(deprecated)]`.
* **ML-DSA sign**: `ExpandedSigningKey::sign_deterministic(msg, ctx = b"")` is the optional
  deterministic variant of `ML-DSA.Sign` (rnd = 0³²), pure mode, empty context. The `Signer` trait impl
  is the same thing.
* **ML-DSA verify**: `VerifyingKey::decode(pk)` + `Signature::decode(sig)` + `verify_with_context(msg, b"", &sig)`.
* **SLH-DSA keygen**: `SigningKey::<P>::slh_keygen_internal(sk_seed, sk_prf, pk_seed)` (Alg. 18) on the
  3n-byte seed split into thirds. `sk.to_bytes()` / `verifying_key().to_bytes()` give the FIPS encodings.
* **SLH-DSA sign**: `Signer::try_sign(msg)` = `slh_sign` with empty context and `opt_rand = None`, which
  the crate maps to `opt_rand = PK.seed`, i.e. exactly the deterministic variant of FIPS 205.
* **SLH-DSA verify**: `VerifyingKey::try_from(pk)`, `Signature::try_from(sig)`, `Verifier::verify`.

`run.sh vectors` reproduces all 15 digests of `common/reference.json` (checked on every run, exit 1
otherwise), and every bench line recomputes SHA-256 of the actual output of the measured loop and sets
`match` from it (for batch variants every element of the batch is checked; for verify, `match` also
requires that a signature with one flipped bit is rejected).

## What is inside the timed region

* keygen: seed bytes → key objects → encoded pk **and** encoded sk (`Vec<u8>` outputs).
* sign (v0): sk **bytes** → key decode (`from_expanded` / `try_from`) → deterministic sign → encoded
  signature. The decode is included on purpose: it is what a stateless caller (and the C-style APIs of
  the other libraries) pays per call. The `keycache` variant removes it.
* verify (v0): pk bytes → `VerifyingKey::decode` → signature decode → verify → bool. Again `keycache`
  hoists the key decode.

Timing: `std::time::Instant` per op (per batch / batch size for the rayon variants), process CPU time via
`libc::getrusage(RUSAGE_SELF)` over the whole measured loop (captures all rayon threads). Warm-up: up to
20 calls / 100 ms (at least 1). Then run until the budget elapsed and ≥ 3 calls (2 if an op takes > 5 s),
capped at 100 000 ops.

## Variant overview (details in keygen.md / sign.md / verify.md)

| id | keygen | sign | verify | build tag |
|---|---|---|---|---|
| v0 | default | default | default | `base` (`cargo build --release`) |
| v1 | native | native | native | `native` (`-C target-cpu=native`) |
| v2 | lto | lto | lto | `lto` (fat LTO, codegen-units=1, panic=abort) |
| v3 | pgo | pgo | pgo | `pgo-<op>` (native + fat LTO + PGO profile trained on that op only) |
| v4 | mimalloc | keycache | keycache | `mimalloc` / `base` |
| v5 | par (rayon batch) | par | par | `base`, 4 threads, batch = 16 |

Things that were considered and rejected: `keccak` SIMD backends (nightly only), `sha2` SHA-NI backend
(CPU lacks it, and the crate already auto-selects at runtime), disabling the `alloc` feature of `ml-dsa`
(only replaces a handful of `Box`es with stack arrays; the double A_hat expansion in keygen is the same
either way), external-μ signing (`sign_mu_deterministic`: would move part of the work out of the timed
region, which is not an honest sign benchmark), randomized signing (cannot byte-match).

## Problems / caveats

* `slh-dsa` is used at a release candidate (0.2.0-rc.5). Its API already matches what the 0.2 release
  will have; the 0.1.0 stable crate would pull in a second `digest`/`sha2` major version.
* SLH-DSA signing (especially the `s` sets, ~0.5–3 s per op in this pure-Rust code) dominates the wall
  time of a full bench run; with `--budget-ms 1000` the full run takes roughly 10–15 min.
* The Keccak permutation is scalar 64-bit code; `target-cpu=native` helps little for SHAKE-based sets
  because there is no vectorised Keccak on stable Rust.
