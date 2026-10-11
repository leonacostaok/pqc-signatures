# OpenSSL 3.5 (native ML-DSA / SLH-DSA providers)

## Overview

| | |
|---|---|
| Library | OpenSSL `openssl-3.5.9` (LTS branch), built from source |
| Why from source | the system OpenSSL is 3.0.13, which has no post-quantum algorithms; ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) landed in the default provider in 3.5 |
| Language of the harness | C driver (`libs/openssl/src/pqc_driver.c`), `clock_gettime(CLOCK_MONOTONIC)` + `getrusage(RUSAGE_SELF)` |
| Linking | static `libcrypto.a`, one driver binary per build flavour |
| Params covered | `ML-DSA-44/65/87`, all 12 `SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}` |
| Not covered | Falcon-512/1024: OpenSSL has no FN-DSA implementation, entries are skipped |

The implementation under test is OpenSSL's own portable C code (`crypto/ml_dsa/`, `crypto/slh_dsa/`),
which calls the EVP digest layer for every SHAKE/SHA-2 invocation; only the hash primitives have
assembly (x86_64 Keccak-1600 and SHA-256/512 with SHA-NI/AVX dispatch), there is no vectorised NTT.

## Build

```
libs/openssl/run.sh build
```

* clones `https://github.com/openssl/openssl` at tag `openssl-3.5.9` into `libs/openssl/deps/openssl` (git, shallow);
* configures and builds three static libcrypto flavours out-of-tree in `libs/openssl/build/obj-<flavour>`
  and installs them to `libs/openssl/build/<flavour>` (`make -j2 build_libs install_dev`, about 2 min each):

| flavour | Configure options | used by |
|---|---|---|
| `default` | `linux-x86_64 no-shared no-tests no-apps no-docs no-engine no-legacy no-dso no-module no-comp no-zlib no-dtls no-ssl3` (stock `-O3`, asm on) | `*.v0 v1 v2 v5` |
| `noasm` | default + `no-asm` | `*.v3` |
| `native` | default + `-O3 -march=native -flto -ffat-lto-objects` | `*.v4` |

* compiles the driver sources (`src/pqc_driver.c`, `pqc_stages.c`, `pqc_validate.c`, `pqc_memory.c`) three
  times (`-DBUILD_LABEL=<flavour>`, include paths to the source tree's internal headers and the flavour's generated
  `configuration.h`; the `native` driver is itself built with `-O3 -march=native -flto` so the LTO link can
  inline across the libcrypto boundary) into `libs/openssl/build/bin/pqc_driver_<flavour>`.

`run.sh bench` simply runs all three binaries with the same arguments; each binary executes only the variants
that belong to its flavour, so one `bench.jsonl` collects everything. The build is idempotent (each step is
skipped when its output exists) and needs no network after the first run.

## Seeded keygen and deterministic signing

* **Keygen from the shared seed.** Both keymgmts accept a `"seed"` keygen parameter
  (`OSSL_PKEY_PARAM_ML_DSA_SEED` and `OSSL_PKEY_PARAM_SLH_DSA_SEED` are both the string `"seed"`):
  `EVP_PKEY_keygen_init` -> `EVP_PKEY_CTX_set_params(seed)` -> `EVP_PKEY_keygen`.
  For ML-DSA the 32-byte xi goes straight into `ML-DSA.KeyGen_internal`; for SLH-DSA the 3n bytes are
  `SK.seed || SK.prf || PK.seed` exactly as in `slh_keygen_internal`, so both match the noble reference.
  (ML-DSA additionally supports importing the seed with `EVP_PKEY_fromdata`, used by `keygen.v2`.)
* **Key bytes.** `pk` = `EVP_PKEY_get_octet_string_param(key, "pub")`, `sk` = `... "priv"`: the FIPS 204 encoded
  sk (2560/4032/4896 B) and the FIPS 205 `SK.seed||SK.prf||PK.seed||PK.root` (4n B). Both digests match
  `common/reference.json` for all 15 params.
* **Deterministic signing.** The signature parameter `"deterministic"` (`OSSL_SIGNATURE_PARAM_DETERMINISTIC`) = 1 is
  passed to `EVP_PKEY_sign_message_init`. For ML-DSA this sets rnd = 0^32, for SLH-DSA opt_rand = PK.seed,
  i.e. exactly the modes the contract asks for. Context string is left at its default (empty), message
  encoding at its default (pure mode, `0x00 || 0x00 || msg`).
* **Verification** imports the public key with `EVP_PKEY_fromdata(... "pub" ...)` and uses
  `EVP_PKEY_verify_message_init` + `EVP_PKEY_verify`. The tamper check flips bit 0 of the middle byte of the signature.

Every bench line re-derives SHA-256 of its output and compares with the reference at runtime
(`match`), on the first op, on every subsequent op (byte compare against the first output) and on the last op.

## Commands

```
libs/openssl/run.sh build
libs/openssl/run.sh vectors     results/openssl/artifacts.json
libs/openssl/run.sh crossverify results/<other>/artifacts.json results/openssl/crossverify-<other>.json
libs/openssl/run.sh bench    --out results/openssl/bench.jsonl   [--budget-ms 1000] [--params a,b] [--ops keygen,sign] [--variants keygen.v1,sign.v5]
libs/openssl/run.sh validate common/validation/validation.json.gz results/openssl/validation.json   # phase 2 A
libs/openssl/run.sh stages   --out results/openssl/stages.jsonl  [--budget-ms 1000] [--params a,b] [--stages expandA,fors,total]  # phase 2 B
libs/openssl/run.sh memory   --out results/openssl/memory.jsonl  [--params a,b]                     # phase 2 C
libs/openssl/run.sh list        # variant table
```

Phase 2 (see `validation.md`, `verify-stages.md`, `memory.md`): the same three binaries implement the
validation-suite runner (`src/pqc_validate.c`), the verify stage split (`src/pqc_stages.c`, linked against
libcrypto's internal `ossl_ml_dsa_*` / `ossl_slh_*` / `ossl_sha3_*` symbols and internal headers, with
`crypto/ml_dsa/ml_dsa_encoders.c` vendored into the stage TU for the static decoders) and the stack/heap
measurement (`src/pqc_memory.c`, painted pthread stack + `CRYPTO_set_mem_functions` counters).
`stages` and `memory` append to their jsonl like `bench`; `validate` writes per-build partial files under
`libs/openssl/build/validate/` and merges them.

## Variants at a glance

| op | v0 | v1 | v2 | v3 | v4 | v5 |
|---|---|---|---|---|---|---|
| keygen | fresh ctx per call | prefetch + reused ctx | `EVP_PKEY_fromdata` seed import (ML-DSA only) | `no-asm` build | `-O3 -march=native -flto` build | 4 pthreads |
| sign | fresh ctx + size query per call | prefetch + reused ctx | `EVP_PKEY_CTX_dup` of a template | `no-asm` build | native+LTO build | 4 pthreads |
| verify | fresh ctx per call | prefetch + reused ctx | caller-computed mu (`"mu"=1`, ML-DSA only) | `no-asm` build | native+LTO build | 4 pthreads |

See `keygen.md`, `sign.md`, `verify.md` for the rationale and results. Extra JSON fields emitted beyond the contract
schema: `build` (flavour), `batch_size` (ops per timed batch, 1 except for the thread variants), `sk_sha256` (keygen).

## Notes / caveats

* Two variants are ML-DSA-only (`keygen.v2`, `verify.v2`) because the SLH-DSA provider has neither a seed import
  through `fromdata` nor an external-mu interface; those (variant, SLH-DSA) cells are absent rather than faked.
* The thread variants report throughput over a batch of `4 x k` ops (k sized so a thread works ~2 ms per batch);
  `wall_ns_*` is wall per batch divided by the batch size, `cpu_ns_per_op` includes all threads (`getrusage(RUSAGE_SELF)`).
* The numbers in the per-process files below `<!-- RESULTS -->` were taken on a shared, busy 4-core box with
  `--budget-ms 200` and are only indicative; the orchestrator regenerates them.
