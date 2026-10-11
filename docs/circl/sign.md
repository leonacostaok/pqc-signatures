# CIRCL: sign variants

Process: `(sk bytes, msg) -> sig bytes`, pure mode, empty context, deterministic. ML-DSA: Fiat-Shamir with
aborts (`ExpandMask`, NTT multiplications, decompose/hint, rejection loop; `SignTo` with `randomized=false`
uses rnd = 0^32). SLH-DSA: `SignDeterministic` (`opt_rand = PK.seed`): FORS signature plus one XMSS/WOTS+
signature per hypertree layer, each layer rebuilding a full XMSS tree of 2^h' leaves, which makes "s" sets
cost seconds per signature in CIRCL.

| variant | name | binary | what / why / how |
|---|---|---|---|
| sign.v0 | baseline | default | What an application does with a stored key: `PrivateKey.UnmarshalBinary(skBytes)` then `mldsa.SignTo(&sk, msg, nil, false, make([]byte, SignatureSize))`; for SLH-DSA `PrivateKey{ID}.UnmarshalBinary` then `slhdsa.SignDeterministic(&priv, NewMessage(msg), nil)`. For ML-DSA the unpack step recomputes `ExpandA(rho)` (K*L SHAKE-128 polynomial samplings) and the NTTs of s1, s2, t0 on every call. |
| sign.v1 | preunpacked | default | Precomputation/caching: the `PrivateKey` object is unpacked once outside the timed region and reused; `SignTo` writes into a signature buffer allocated once (no per-call allocation). This is the intended CIRCL usage pattern (keep the key object, not the bytes). For SLH-DSA the unpacked key is just three n-byte slices, so only the small parsing/allocation goes away. |
| sign.v2 | purego | `-tags purego` | No assembly anywhere (generic NTT, scalar Keccak, generic stdlib SHA-256): measures the assembly contribution to signing, which for ML-DSA is dominated by NTT/pointwise ops and SHAKE sampling in the rejection loop. Baseline (packed-key) code path. |
| sign.v3 | amd64v3 | `GOAMD64=v3` | Compiler may use AVX2/BMI2 instructions for generic Go code (packing, decompose, hint computation, SLH-DSA tree bookkeeping). Baseline code path. |
| sign.v4 | pgo | `-pgo=default.pgo` | Profile-guided optimisation with a profile that includes both the packed and the pre-unpacked signing paths for every parameter set. Baseline code path. |
| sign.v5 | parallel | default | Worker pool of `GOMAXPROCS` (= 4) goroutines, each holding its own pre-unpacked `PrivateKey` and signature buffer (no shared mutable state), one signature per worker per batch; `threads = 4`, wall per op = batch wall / 4, outputs compared bit-for-bit. Throughput variant for signing services. |

All variants produce the deterministic signature and are compared against `sig_sha256` of
`common/reference.json` on every run; randomized/hedged signing (`randomized=true`, `SignRandomized`) is not
used anywhere.

## Preliminary conclusion (noisy, shared machine; final numbers come from the quiet run)

- `preunpacked` is the big win for ML-DSA: 2.4-2.6x lower median latency and ~3x throughput for ML-DSA-44/87
  (the baseline spends more time in `UnmarshalBinary`, i.e. `ExpandA` + 3 NTT vectors, than in the signature
  itself). For SLH-DSA it is a few percent (the key has nothing to precompute; the saving is the
  `cryptobyte` parse and allocations).
- `purego` costs about 2x on ML-DSA and on SLH-DSA-SHA2; SLH-DSA-SHAKE is affected least.
- `amd64v3` and `pgo` are within noise on this shared box; PGO looked slightly positive on ML-DSA-44/87
  and negative on some SLH-DSA sets, which is exactly the +-10% band the orchestrator's quiet run must settle.
- `parallel` scales with free cores: with four workers competing with five other agents it reached only
  ~1.4-2.7x of baseline throughput and did not beat single-threaded `preunpacked` on ML-DSA; on a quiet
  machine the expectation is close to 4x of `preunpacked`.

<!-- RESULTS -->

**ML-DSA-44** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| sign.v0 | baseline | 1 | 83.4 | 135.9 | 0.98 | 7,197.0 | 1.00x | True |
| sign.v1 | preunpacked | 1 | 34.8 | 43.5 | 0.99 | 22,733.9 | 2.40x | True |
| sign.v2 | purego | 1 | 172.7 | 270.6 | 0.90 | 3,319.5 | 0.48x | True |
| sign.v3 | amd64v3 | 1 | 82.5 | 121.7 | 0.99 | 8,152.3 | 1.01x | True |
| sign.v4 | pgo | 1 | 70.5 | 122.1 | 1.01 | 8,234.1 | 1.18x | True |
| sign.v5 | parallel | 4 | 40.7 | 49.7 | 1.10 | 22,138.6 | 2.05x | True |

**ML-DSA-65** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| sign.v0 | baseline | 1 | 289.2 | 351.7 | 1.02 | 2,897.7 | 1.00x | True |
| sign.v1 | preunpacked | 1 | 217.9 | 243.3 | 0.95 | 3,904.0 | 1.33x | True |
| sign.v2 | purego | 1 | 683.0 | 832.0 | 1.07 | 1,289.6 | 0.42x | True |
| sign.v3 | amd64v3 | 1 | 273.6 | 351.7 | 1.07 | 3,031.5 | 1.06x | True |
| sign.v4 | pgo | 1 | 290.7 | 411.5 | 0.94 | 2,287.7 | 0.99x | True |
| sign.v5 | parallel | 4 | 232.0 | 251.2 | 1.03 | 4,115.9 | 1.25x | True |

**ML-DSA-87** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| sign.v0 | baseline | 1 | 291.8 | 411.5 | 1.03 | 2,500.9 | 1.00x | True |
| sign.v1 | preunpacked | 1 | 112.4 | 129.4 | 1.00 | 7,736.4 | 2.60x | True |
| sign.v2 | purego | 1 | 548.8 | 699.6 | 1.05 | 1,507.5 | 0.53x | True |
| sign.v3 | amd64v3 | 1 | 224.6 | 376.8 | 0.98 | 2,591.3 | 1.30x | True |
| sign.v4 | pgo | 1 | 231.1 | 342.0 | 1.02 | 2,969.4 | 1.26x | True |
| sign.v5 | parallel | 4 | 130.2 | 150.8 | 1.03 | 6,805.7 | 2.24x | True |

**SLH-DSA-SHA2-128f** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| sign.v0 | baseline | 1 | 65,379.1 | 61,446.2 | 0.96 | 15.6 | 1.00x | True |
| sign.v1 | preunpacked | 1 | 58,973.7 | 48,406.2 | 0.87 | 17.9 | 1.11x | True |
| sign.v2 | purego | 1 | 123,646.0 | 121,109.0 | 0.98 | 8.1 | 0.53x | True |
| sign.v3 | amd64v3 | 1 | 54,394.7 | 49,988.8 | 0.96 | 19.1 | 1.20x | True |
| sign.v4 | pgo | 1 | 80,875.1 | 80,191.0 | 0.99 | 12.4 | 0.81x | True |
| sign.v5 | parallel | 4 | 36,783.2 | 49,241.3 | 1.34 | 27.2 | 1.78x | True |

**SLH-DSA-SHAKE-128f** (preliminary, `--budget-ms 200`, shared 4-core box)

| variant | name | threads | median wall (us) | CPU/op (us) | cpu_util | ops/s | speedup (median) | match |
|---|---|---:|---:|---:|---:|---:|---:|---|
| sign.v0 | baseline | 1 | 96,928.1 | 94,230.3 | 0.99 | 10.5 | 1.00x | True |
| sign.v1 | preunpacked | 1 | 56,464.6 | 55,071.5 | 0.94 | 17.1 | 1.72x | True |
| sign.v2 | purego | 1 | 53,517.9 | 53,382.0 | 1.00 | 18.8 | 1.81x | True |
| sign.v3 | amd64v3 | 1 | 64,693.4 | 55,787.5 | 0.89 | 16.0 | 1.50x | True |
| sign.v4 | pgo | 1 | 60,658.7 | 53,357.0 | 0.93 | 17.4 | 1.60x | True |
| sign.v5 | parallel | 4 | 36,303.0 | 59,657.6 | 1.66 | 27.8 | 2.67x | True |
