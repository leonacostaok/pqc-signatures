# Bouncy Castle: keygen variants

Process: seed -> (pk, sk). ML-DSA: 32-byte xi expanded by `ML-DSA.KeyGen_internal` (SHAKE256 expansion of
rho/rho'/K, matrix A expansion with SHAKE128, rejection sampling of s1/s2, NTT, t = A s1 + s2, power2round,
tr = H(pk)). SLH-DSA: `slh_keygen_internal` computes `PK.root` by building the whole top XMSS tree
(2^h' WOTS+ key generations), which is why SLH-DSA keygen is far more expensive than ML-DSA keygen and is
dominated by hashing (SHA-256 or SHAKE256 compression calls).

Every variant feeds the same seed, so every op produces the reference pk/sk; both are compared to the
expected bytes on every iteration.

| id | name | what | why it might help |
|---|---|---|---|
| keygen.v0 | `jca` | **Baseline.** `KeyPairGenerator.getInstance("ML-DSA" or "SLH-DSA", "BC")`, `initialize(MLDSAParameterSpec/SLHDSAParameterSpec, seedRandom)`, `generateKeyPair()`; a fresh generator per op, exactly as the BC documentation shows. | - |
| keygen.v1 | `jca-reuse` | One JCA `KeyPairGenerator` created and initialised once, `generateKeyPair()` called repeatedly (the seed RNG is rewound before each call). | Skips the provider lookup (`Security` service map, reflection, `MLDSAKeyGenerationParameters` construction) per op. For ML-DSA keygen (~100 us) that overhead is a measurable fraction. |
| keygen.v2 | `lightweight` | BC lightweight API: `new MLDSAKeyPairGenerator()` / `new SLHDSAKeyPairGenerator()`, `init(new *KeyGenerationParameters(seedRandom, params))`, `generateKeyPair()`; returns `AsymmetricCipherKeyPair` with raw parameter objects. | No JCA layer at all: no `BCMLDSAPrivateKey`/`BCMLDSAPublicKey` wrapper allocation, no `KeyPair`, no `SecureRandom` default-DRBG lookup. |
| keygen.v3 | `internal-seed` | Seed expansion without any `SecureRandom`: ML-DSA `new MLDSAPrivateKeyParameters(params, seed32, null)` (BC recognises the 32-byte form and runs `generateKeyPairInternal`) then `getPublicKeyParameters()`; SLH-DSA `SLHDSAKeyPairGenerator.internalGenerateKeyPair(skSeed, skPrf, pkSeed)`. | Removes the RNG indirection and the generator object; it is also the cleanest expression of the FIPS `KeyGen_internal` entry point and the path the parallel variant uses. |
| keygen.v4 | `parallel` | Batch of `internal-seed` keygens spread over a fixed pool of `availableProcessors()` threads (4 here); the batch size is tuned so a batch lasts >= 40 ms. Reported numbers are throughput (wall per batch / batch size) and `threads = 4`. | Keygen is embarrassingly parallel and BC's engines are per-call objects with no shared mutable state, so a server generating many keys should scale with cores; this measures how well, including GC/alloc contention. |
| keygen.v5 | `parallelgc` | Same code as `lightweight` (v2) but in a child JVM started with `-XX:+UseParallelGC -Xms2g -Xmx2g -Xmn1200m -XX:+AlwaysPreTouch`. | ML-DSA keygen allocates several `PolyVec`/`int[256]` arrays per op (A matrix: k*l polynomials), SLH-DSA allocates many small `byte[]` per hash call. ParallelGC has cheaper allocation and no G1 write/read barriers, and a pre-touched 1.2 GB young generation makes minor collections rare during the measured loop. |

Implementation notes: `SeedRandom` (`Alg.java`) returns the seed bytes sequentially and is reset before each op
(v0-v2); v3/v4 slice the seed themselves. The JCA variants obtain the raw bytes for the match check via
`MLDSAPublicKey.getPublicData()`/`MLDSAPrivateKey.getPrivateData()`; the SLH-DSA JCA private key has no raw
accessor, so its PKCS#8 encoding is compared to a precomputed expected encoding (cheap, and outside the timed region).

<!-- RESULTS -->
