# Approaches: every alternative, grouped by idea

Each library tried a baseline plus five alternatives per process (keygen, sign, verify) and up to five per verify
stage. The same handful of ideas came back in different clothes in every language. This page explains each idea
once, says where it was tried, and links to the per-library pages for exact implementations and numbers.
Measured results are in [../RESULTS.md](../RESULTS.md).

## 1. Caching per-key work (precomputation)

**Idea.** Much of ML-DSA's sign and verify cost depends only on the key, not on the message: decoding the key,
expanding the public matrix `A = ExpandA(rho)` (k·l polynomials of SHAKE-128 rejection sampling), the NTTs of
`s1, s2, t0` for signing and of `t1·2^d` for verifying, and `tr = H(pk)`. Doing that once per key and reusing it
removes those steps from every later operation.

**Where.** noble `sign.v3 keycache` / `verify.v3 pkcache`, circl `sign.v1/verify.v1 preunpacked`, rustcrypto
`sign.v4/verify.v4 keycache`, Bouncy Castle `sign.v2/verify.v2 reuse-signer`, OpenSSL `verify.v2 external-mu`
(caches tr), and stage alternatives `mu: cached tr`, `expandA: cached A`, `w_approx: cached NTT(t1·2^d)` in every
library.

**When it applies.** Only when the same key signs or verifies many times (servers, firmware update
verifiers, a long-lived signing service). A one-shot verify under a fresh key pays the full cost, so stage tables
always show cached and uncached alternatives separately, and every `total_best` that relies on caches says so.
SLH-DSA has almost no per-key work to cache (noble caches the top XMSS tree for signing; that is the only real win).

**Safety.** Every caching variant runs the full validation suite: wrong keys, wrong contexts and malformed signatures
must still be rejected. They all are.

## 2. Faster hashing backends

**Idea.** SLH-DSA is nothing but hashing (thousands to millions of SHA-256/512 or SHAKE-256 calls per operation), and
ML-DSA spends a large share of its time in SHAKE. Swapping the hash backend changes everything.

- **SHA-2 midstate of `PK.seed`.** In the SHA2 parameter sets every tweakable hash starts with `PK.seed` padded to a
  full block. Compressing that block once and restoring the state per call skips one compression per hash.
  Tried in liboqs (`fasthash`), OpenSSL (`low-level` stages), circl (`alt-hash`), Bouncy Castle (`FastHash`),
  noble (`fastjs`). RustCrypto's crate already did it, so it saw no gain.
- **Calling the compression function directly** on pre-padded blocks, instead of the generic init/update/final
  API, removes buffering and allocation overhead for 50–100 byte inputs (noble fastjs, liboqs fasthash, rustcrypto rawhash).
- **Native vs library hashes.** noble tried `node:crypto` (OpenSSL) instead of its pure-JS hashes. That is a big win for
  SHAKE but a big loss for SHA-256 on tiny inputs, because each native call costs more than the hash. Bouncy Castle
  tried the JDK's intrinsified SHA-256 instead of BC's pure-Java digest, which helps a lot. circl tried Go's stdlib
  `crypto/sha3`, which made no difference.
- **4-way SIMD Keccak.** AVX2 can run four Keccak-f[1600] permutations at once. ExpandA samples k·l independent
  polynomials and SLH-DSA has many independent WOTS+ chains and FORS trees, so 4-lane Keccak fits naturally.
  circl and liboqs (mldsa-native) already use it for ExpandA. RustCrypto's agent wrote an AVX2 4-lane Keccak with a
  work-list scheduler for WOTS chains; this was the largest SHAKE win of the project.
- **Unrolled scalar Keccak** (noble's generated `fast-keccak`, Bouncy Castle's own Keccak with lanes in locals).

## 3. Arithmetic (ML-DSA NTT and polynomial math)

- **Lazy reduction.** Skip modular reduction between NTT layers and reduce once at the end, accumulating in wider
  integers (noble `lazy-ntt` on Float64, rustcrypto `montgomery` with i64 accumulation, OpenSSL own int32 Montgomery
  NTT, Bouncy Castle `long-accum`).
- **Fused passes.** Do UseHint + w1Encode + norm check in one pass instead of three (circl, OpenSSL, Bouncy Castle,
  noble, rustcrypto). Unpack z/t1 with 64-bit word loads instead of byte-by-byte (circl fused decode, rustcrypto
  fastunpack, noble word-unpack, Bouncy Castle VarHandle wide-unpack).
- **Assembly vs portable code.** Measured the other way round: building without assembly (`no-asm`, Go `purego`)
  shows how much the hand-written AVX2 NTT and Keccak are worth.

## 4. Compiler and build

- `-O3 -march=native` / `-C target-cpu=native` / `GOAMD64=v3`: let the compiler use AVX2/BMI2 everywhere.
- **LTO** (link-time optimization, fat LTO + 1 codegen unit in Rust) and **PGO** (profile-guided optimization:
  gcc `-fprofile-use`, Rust `-Cprofile-use`, Go `-pgo`). The profile is trained on the exact operation being measured.
- **clang vs gcc** (liboqs).
- Findings worth knowing: liboqs non-dist builds silently drop the AVX-512VL SHA-3 backend (fixed in the driver),
  and Go's PGO build moved a SHA-256 digest to the heap, so SLH-DSA-SHA2 signing allocated 13.9 MB per signature.

## 5. Runtime tuning

- **JavaScript:** Bun (JavaScriptCore) instead of Node (V8).
- **JVM:** C2-only (`-XX:-TieredCompilation`), ParallelGC with pre-touched heap, Epsilon GC (no GC at all),
  aggressive inlining limits.
- **Go:** GC off (`SetGCPercent(-1)`).
- **Rust:** mimalloc instead of the system allocator.

## 6. API path and object reuse

Same algorithm, less ceremony: fetch algorithm objects once (OpenSSL `EVP_SIGNATURE_fetch`), reuse or duplicate
contexts, call internal seeded/deterministic functions directly instead of the public dispatcher (liboqs `internal`),
use the lightweight API instead of JCA (Bouncy Castle), skip re-validation (noble internal APIs). These cost
microseconds, so they matter only for the fast ML-DSA operations in C.

## 7. Parallelism

Two kinds:
- **Batch parallelism** (`*.v5 parallel/pthread-x4/workers-x4/rayon`): 4 independent operations on 4 cores.
  Throughput scales almost linearly and latency does not change; CPU/op stays the same or grows.
- **Intra-operation parallelism** (stage alternatives: ExpandA rows, w_approx rows, FORS trees, WOTS chains,
  hypertree layers on threads/goroutines/rayon/worker_threads): for ML-DSA the stages take 10–500 µs, so the
  thread hand-off costs more than it saves. For SLH-DSA hypertree work it can pay off, but the 4-lane SIMD
  Keccak gets similar gains on one core.

## 8. Verify split into stages

See [verify-stages.md](verify-stages.md): ML-DSA verify = decode, mu, expandA, w_approx, hint_check; SLH-DSA
verify = hmsg, fors, ht_wots, ht_auth. Each library timed its own implementation of each stage and up to five
alternatives, assembled its fastest correct combination (`total_best`), and every stage's canonical intermediate
output was matched across all six libraries.
