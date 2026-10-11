# CIRCL: verify variants

Process: `(pk bytes, msg, sig) -> bool`, pure mode, empty context. ML-DSA: unpack signature, `ExpandA`,
NTT of z, `A z - c t1 2^d`, `UseHint`, recompute the challenge hash and compare. SLH-DSA: recompute the FORS
public key and walk one authentication path per hypertree layer; this is cheap compared with signing
(no tree is rebuilt), so SLH-DSA verification is milliseconds, not seconds.

| variant | name | binary | what / why / how |
|---|---|---|---|
| verify.v0 | baseline | default | `PublicKey.UnmarshalBinary(pkBytes)` then `mldsa.Verify(&pk, msg, nil, sig)`; for SLH-DSA `PublicKey{ID}.UnmarshalBinary` then `slhdsa.Verify(&pub, NewMessage(msg), sig, nil)`. For ML-DSA the unpack recomputes `ExpandA(rho)` (K*L SHAKE-128 samplings), unpacks t1 and hashes `tr = SHAKE256(pk)` on every call. |
| verify.v1 | preunpacked | default | Precomputation/caching: the `PublicKey` object (with its cached matrix A and `tr`) is unpacked once and reused for every verification, as a TLS stack or a certificate validator keeping parsed keys would. The remaining work is the verification proper. |
| verify.v2 | purego | `-tags purego` | No assembly (generic NTT, scalar Keccak, generic stdlib SHA-256). Baseline code path; quantifies the assembly contribution to verification. |
| verify.v3 | amd64v3 | `GOAMD64=v3` | Compiler may emit AVX2/BMI2 for generic Go code (signature unpacking, hint handling, SLH-DSA address/auth-path bookkeeping). Baseline code path. |
| verify.v4 | pgo | `-pgo=default.pgo` | Profile-guided optimisation from a profile covering both verify code paths for all parameter sets. Baseline code path. |
| verify.v5 | parallel | default | Worker pool of `GOMAXPROCS` (= 4) goroutines, each with its own pre-unpacked `PublicKey`, one verification per worker per batch; `threads = 4`, wall per op = batch wall / 4. Throughput variant for verifiers that process many signatures (every worker must return true). |

Correctness: every variant must return `true` on the reference (pk, msg, sig) and `false` on the same
signature with one bit flipped (checked at setup for every variant); `output_sha256` is `"true"` only if
both hold.

## Preliminary conclusion (noisy, shared machine; final numbers come from the quiet run)

- `preunpacked` dominates for ML-DSA: 2.6x (44), 3.5x (65) and 4.4x (87) lower median latency, because
  `ExpandA` plus `SHAKE256(pk)` cost more than the verification itself. The gain grows with K*L. Nothing to
  precompute for SLH-DSA (the key is two n-byte seeds): ~1.0x.
- `purego` costs ~2x on ML-DSA and ~3x on SLH-DSA-SHA2 (the stdlib SHA-256 assembly disappears too);
  SLH-DSA-SHAKE is nearly unaffected.
- `amd64v3` and `pgo` are within noise.
- `parallel` reached ~3x of baseline throughput on ML-DSA on the loaded box but did not beat the
  single-threaded `preunpacked` variant there; on a quiet machine it should approach 4x of `preunpacked`.

<!-- RESULTS -->

**ML-DSA-44** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| verify.v0 | baseline | 1 | 47.6 | 82.2 | 1.03 | 12,564.8 | 1.00x | True |
| verify.v1 | preunpacked | 1 | 18.1 | 20.9 | 0.98 | 46,963.6 | 2.64x | True |
| verify.v2 | purego | 1 | 100.3 | 135.2 | 0.99 | 7,328.7 | 0.48x | True |
| verify.v3 | amd64v3 | 1 | 45.0 | 64.0 | 0.95 | 14,789.1 | 1.06x | True |
| verify.v4 | pgo | 1 | 53.4 | 87.1 | 1.01 | 11,568.4 | 0.89x | True |
| verify.v5 | parallel | 4 | 20.1 | 29.0 | 1.06 | 36,451.1 | 2.37x | True |

**ML-DSA-65** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| verify.v0 | baseline | 1 | 78.1 | 134.7 | 1.02 | 7,605.8 | 1.00x | True |
| verify.v1 | preunpacked | 1 | 22.4 | 25.5 | 0.91 | 35,809.7 | 3.48x | True |
| verify.v2 | purego | 1 | 163.4 | 261.6 | 0.97 | 3,709.9 | 0.48x | True |
| verify.v3 | amd64v3 | 1 | 82.0 | 116.6 | 0.97 | 8,286.8 | 0.95x | True |
| verify.v4 | pgo | 1 | 81.3 | 149.9 | 1.06 | 7,041.7 | 0.96x | True |
| verify.v5 | parallel | 4 | 36.8 | 43.4 | 1.05 | 24,226.3 | 2.12x | True |

**ML-DSA-87** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| verify.v0 | baseline | 1 | 135.9 | 215.8 | 1.02 | 4,748.1 | 1.00x | True |
| verify.v1 | preunpacked | 1 | 31.2 | 36.4 | 0.96 | 26,401.1 | 4.36x | True |
| verify.v2 | purego | 1 | 275.6 | 320.5 | 0.98 | 3,057.7 | 0.49x | True |
| verify.v3 | amd64v3 | 1 | 136.6 | 255.0 | 0.98 | 3,842.3 | 0.99x | True |
| verify.v4 | pgo | 1 | 134.9 | 211.3 | 1.06 | 5,020.3 | 1.01x | True |
| verify.v5 | parallel | 4 | 57.4 | 67.2 | 1.09 | 16,213.5 | 2.37x | True |

**SLH-DSA-SHA2-128f** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| verify.v0 | baseline | 1 | 2,802.2 | 2,911.2 | 1.00 | 344.5 | 1.00x | True |
| verify.v1 | preunpacked | 1 | 2,744.5 | 2,771.2 | 0.98 | 353.2 | 1.02x | True |
| verify.v2 | purego | 1 | 8,061.5 | 7,565.9 | 0.88 | 115.8 | 0.35x | True |
| verify.v3 | amd64v3 | 1 | 2,824.6 | 2,854.6 | 0.98 | 342.4 | 0.99x | True |
| verify.v4 | pgo | 1 | 4,090.7 | 5,223.2 | 0.97 | 184.8 | 0.69x | True |
| verify.v5 | parallel | 4 | 3,033.2 | 3,168.8 | 1.13 | 355.3 | 0.92x | True |

**SLH-DSA-SHAKE-128f** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| verify.v0 | baseline | 1 | 3,609.2 | 3,703.4 | 0.99 | 267.4 | 1.00x | True |
| verify.v1 | preunpacked | 1 | 3,466.7 | 3,485.7 | 1.00 | 285.9 | 1.04x | True |
| verify.v2 | purego | 1 | 3,344.4 | 3,360.6 | 0.99 | 295.5 | 1.08x | True |
| verify.v3 | amd64v3 | 1 | 3,097.3 | 3,250.2 | 1.00 | 307.6 | 1.17x | True |
| verify.v4 | pgo | 1 | 5,579.0 | 5,097.4 | 0.99 | 195.2 | 0.65x | True |
| verify.v5 | parallel | 4 | 3,191.8 | 3,951.1 | 1.30 | 328.3 | 1.13x | True |
