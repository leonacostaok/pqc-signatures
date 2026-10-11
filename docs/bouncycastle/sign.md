# Bouncy Castle: sign variants

Process: (sk, msg) -> sig. ML-DSA signing in BC (`MLDSAEngine.generateSignature`) unpacks s1/s2/t0 from the
encoded key, re-expands the matrix A from rho with SHAKE128 on **every** call (nothing is cached in the key
object), NTTs the secret vectors and then runs the Fiat-Shamir-with-aborts loop; each attempt allocates fresh
`PolyVec`s. SLH-DSA signing is the heavy one: FORS + d XMSS tree signatures, each rebuilt from scratch, i.e.
hundreds of thousands of hash compressions for the "s" parameter sets (seconds in pure Java).

All variants sign deterministically (rnd = 0^32 / opt_rand = PK.seed, see README) and the signature is compared
to the reference bytes on every iteration. Hedged signing is not used anywhere.

| id | name | what | why it might help |
|---|---|---|---|
| sign.v0 | `jca` | **Baseline.** `Signature.getInstance("ML-DSA" or "SLH-DSA", "BC")`, `initSign(privateKey)` (no `SecureRandom` => deterministic), `update(msg)`, `sign()`; new `Signature` object per op. The `PrivateKey` is built once from the FIPS encoding via `KeyFactory` + PKCS#8. | - |
| sign.v1 | `lightweight` | `new MLDSASigner()` / `new SLHDSASigner()`, `init(true, privateKeyParameters)`, `update` + `generateSignature()`; new signer per op. | Drops the JCA layer: no provider lookup, no `BaseDeterministicOrRandomSignature` re-init dance, no `ByteArrayOutputStream` message buffering (SLH-DSA's SPI buffers the whole message before signing). |
| sign.v2 | `reuse-signer` | One lightweight signer initialised once per key and reused: per op only `update(msg)` + `generateSignature()`. | `MLDSASigner.init` clones rho/K/t0/s1/s2 out of the key object and absorbs `tr` into the SHAKE256 state; `SLHDSASigner.init` clones the four key halves. With reuse these happen once; the engine's `reset()` after each signature keeps the object valid. This is as much key-state precomputation as BC's public API permits (A is still re-expanded per call inside the engine). |
| sign.v3 | `parallel` | Batch of signatures over a 4-thread pool, each lane owning its own initialised signer (as in v2); throughput numbers, `threads = 4`. | Measures multi-core scaling of signing, which for SLH-DSA is the only practical way to get acceptable latency-per-core out of pure Java, and exposes allocation/GC contention for ML-DSA. |
| sign.v4 | `c2-only` | `lightweight` code path in a child JVM with `-XX:-TieredCompilation`. | Without tiering HotSpot interprets until the C2 threshold and then compiles straight to the fully optimised tier; it avoids C1 intermediate code and profile-pollution from the warm-up phase, which sometimes yields better peak code for tight integer loops such as the NTT / Keccak permutation. (It also shows how much the warm-up cost matters: the warm-up phase is slower.) |
| sign.v5 | `epsilon-nogc` | `lightweight` code path in a child JVM with `-XX:+UseEpsilonGC -Xms8g -Xmx8g` (no-op collector). The measured loop stops early if the heap passes 85 % so the JVM never dies. | Removes garbage collection and all GC barriers from the measurement: the result is the pure allocation+compute cost of BC's signing code, i.e. an upper bound on what any GC tuning could achieve. Also a direct read-out of how allocation-heavy each parameter set is (the loop's iteration count vs the 8 GB heap). |

Implementation notes: for ML-DSA the message is passed via `update(byte[],int,int)` so the SHAKE absorb is part
of the op; for SLH-DSA the one-shot `generateSignature(byte[] msg)` is the only entry point. Key objects
(`MLDSAPrivateKeyParameters(params, skBytes, null)`, which derives t1 once, and `SLHDSAPrivateKeyParameters`) are
prepared before the loop.

<!-- RESULTS -->
