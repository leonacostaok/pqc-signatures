# Vendored CIRCL internals (v1.6.5)

Verbatim copies of `github.com/cloudflare/circl@v1.6.5` packages whose Go `internal` visibility
prevents calling them from this harness, with only import paths / package names rewritten
(see `../run.sh` and `docs/circl/verify-stages.md`):

| here | upstream |
|---|---|
| `sha3` | `internal/sha3` |
| `keccakf1600` | `simd/keccakf1600` |
| `dilithium`, `dilithium/params` | `sign/internal/dilithium` |
| `mldsa44i`, `mldsa65i`, `mldsa87i` | `sign/mldsa/mldsa{44,65,87}/internal` |
| `slhdsa` (without `scheme.go`) | `sign/slhdsa` |
| `conv` | `internal/conv` |

Harness-added files are named `stages*.go` and are the only non-upstream code. License: `LICENSE` (BSD-3-Clause, Cloudflare).
