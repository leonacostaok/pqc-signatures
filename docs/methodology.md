# Methodology

## What is measured

Six libraries, one machine, the same inputs:

| lib | language | version | ML-DSA | SLH-DSA | Falcon |
|---|---|---|---|---|---|
| [noble](noble/README.md) | JavaScript (Node 22, Bun) | @noble/post-quantum 0.7.1 | 44/65/87 | all 12 | 512/1024 |
| [liboqs](liboqs/README.md) | C (mldsa-native, slhdsa-c, PQClean) | 0.16.0 | 44/65/87 | all 12 | 512/1024 |
| [openssl](openssl/README.md) | C | 3.5.9 (LTS) | 44/65/87 | all 12 | — |
| [circl](circl/README.md) | Go 1.25 | cloudflare/circl 1.6.5 | 44/65/87 | all 12 | — |
| [rustcrypto](rustcrypto/README.md) | Rust 1.97 | ml-dsa 0.1.1, slh-dsa 0.2.0-rc.5 | 44/65/87 | all 12 | — |
| [bouncycastle](bouncycastle/README.md) | Java 21 | bcprov-jdk18on 1.86 | 44/65/87 | all 12 | 512/1024 |

Every library implements the same harness contract ([common/CONTRACT.md](../common/CONTRACT.md)) behind
`libs/<lib>/run.sh`, so one orchestrator ([common/run-all.sh](../common/run-all.sh)) builds, validates and
benchmarks all of them the same way.

## Same inputs, same outputs

- [common/vectors.json](../common/vectors.json): one 64-byte message and one seed per parameter set, derived
  from SHAKE256 of a label so anyone can reproduce them.
- Key generation is seeded (ML-DSA `xi`, SLH-DSA `SK.seed||SK.prf||PK.seed`) and signing is deterministic
  (ML-DSA `rnd = 0^32`, SLH-DSA `opt_rand = PK.seed`), so every library must produce **byte-identical**
  public keys, secret keys and signatures. [common/reference.json](../common/reference.json) holds their SHA-256.
- Each library had to find its own way to do seeded/deterministic operation (public seed APIs, custom RNG
  callbacks that hand out exactly the seed bytes, internal APIs, SecureRandom subclasses). How is documented in each
  `docs/<lib>/README.md`.

## Processes measured separately

1. **keygen**: seed -> (pk, sk)
2. **sign**: (sk, msg) -> sig
3. **verify**: (pk, msg, sig) -> bool, additionally split into stages (see [verify-stages.md](verify-stages.md))

Inputs are prepared outside the timed region. Each process has a baseline (`v0`, the plain documented API
and default build) and 5 alternatives (`v1..v5`) chosen for that process (see [approaches.md](approaches.md)).

## Timing

- Warm-up (longer for JIT runtimes), then the op runs until the budget (1 s) has elapsed and at least 3 ops
  (2 if one op takes more than 5 s) were done.
- Wall time per op from a monotonic clock, reported as median / mean / p95 / min.
- CPU time from the process (user + sys, all threads) over the measured loop, divided by ops. `cpu_util` =
  CPU / wall: about 1 for single-threaded code, about 4 for 4-thread batches. JIT and GC threads can push
  single-threaded runtimes slightly above 1.
- Throughput (`ops/s`) is the basis for speedups so parallel batch variants are credited for throughput,
  while CPU/op shows what they cost.
- The final numbers come from one sequential run of every library on an otherwise idle 4-core x86-64 VM
  (AVX2, AVX-512VL, no SHA-NI). Development runs were taken while six agents shared the box and are not used.

## Correctness gates (every number is from a checked run)

- Every benchmark line recomputes the digest of what that variant actually produced and compares it with the
  reference (`match`); verify variants must accept the reference signature and reject a bit-flipped one.
- Cross-verification: every library verifies every other library's signatures (including Falcon between noble,
  liboqs and Bouncy Castle) and rejects a tampered copy.
- The validation suite (see [validation.md](validation.md)) runs NIST ACVP vectors and a negative suite through
  **every variant** of every process.
- Verify stages: each stage alternative's intermediate output must equal the library's own stage output,
  and the canonical stage outputs must be identical across all libraries.

## Memory

Peak stack per operation and heap allocated per operation for every variant, with the most accurate method each
runtime allows (see [memory.md](memory.md)).
