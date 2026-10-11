/*
 * pqc_stages.c - verification split into canonical stages (CONTRACT.md phase 2 B).
 *
 * The stages call OpenSSL's internal ML-DSA / SLH-DSA functions directly: the
 * driver is linked statically against libcrypto.a, so the non-exported
 * ossl_ml_dsa_* / ossl_slh_* symbols and the internal headers in
 * crypto/ml_dsa, crypto/slh_dsa and include/internal are available. The few
 * static helpers that have no internal entry point (poly_decode_10_bits,
 * ossl_ml_dsa_sig_decode's packet logic) are obtained by #including
 * crypto/ml_dsa/ml_dsa_encoders.c into this translation unit with its public
 * symbols renamed (st_ml_dsa_*), i.e. "vendored" verbatim.
 *
 * v0 of every stage is OpenSSL's own code path; the alternatives are
 * documented in docs/openssl/verify-stages.md.
 */
#include "pqc_stages.h"
#include <pthread.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/byteorder.h>
#include "internal/sha3.h"
#include "internal/packet.h"

/* --- ML-DSA internals: most of the crypto/ml_dsa headers have no include
 * guards, so they are pulled in exactly once through the vendored encoders.c.
 * Vendoring the encoders makes the static poly_decode_10_bits / hint decoder
 * (OpenSSL's own decode code) callable in isolation. */
#define ossl_ml_dsa_pk_encode st_ml_dsa_pk_encode
#define ossl_ml_dsa_pk_decode st_ml_dsa_pk_decode
#define ossl_ml_dsa_sk_encode st_ml_dsa_sk_encode
#define ossl_ml_dsa_sk_decode st_ml_dsa_sk_decode
#define ossl_ml_dsa_sig_encode st_ml_dsa_sig_encode
#define ossl_ml_dsa_sig_decode st_ml_dsa_sig_decode
#define ossl_ml_dsa_poly_decode_expand_mask st_ml_dsa_poly_decode_expand_mask
#define ossl_ml_dsa_w1_encode st_ml_dsa_w1_encode
#include "ml_dsa_encoders.c"
#undef ossl_ml_dsa_pk_encode
#undef ossl_ml_dsa_pk_decode
#undef ossl_ml_dsa_sk_encode
#undef ossl_ml_dsa_sk_decode
#undef ossl_ml_dsa_sig_encode
#undef ossl_ml_dsa_sig_decode
#undef ossl_ml_dsa_poly_decode_expand_mask
#undef ossl_ml_dsa_w1_encode
#include "ml_dsa_matrix.h"
/* the libcrypto originals that are still called directly (their prototypes
 * above were renamed by the macros) */
int ossl_ml_dsa_pk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len);

/* --- SLH-DSA internals */
#include "slh_dsa_local.h"
#include "slh_dsa_key.h"

/* ------------------------------------------------------------------ tables */

const char *ML_STAGE_NAMES[5] = { "decode", "mu", "expandA", "w_approx", "hint_check" };
const char *SLH_STAGE_NAMES[4] = { "hmsg", "fors", "ht_wots", "ht_auth" };

enum { MD_OSSL, MD_OWN };
enum { MU_OSSL, MU_CACHED_TR, MU_LL, MU_EVP_REUSE };
enum { EA_OSSL, EA_CACHED, EA_LL, EA_THREADS };
enum { W_OSSL, W_CACHED_T1, W_OWN_NTT, W_CACHED_OWN };
enum { HC_OSSL, HC_LL, HC_FUSED };
enum { HM_OSSL, HM_LL, HM_LL_MID };
enum { X_OSSL, X_LL, X_THREADS };

/* total_best: fastest stateless single-threaded alternative per stage, chosen
 * from the development measurements (see docs/openssl/verify-stages.md). */
const int BEST_ML[5] = { MD_OWN, MU_LL, EA_LL, W_OWN_NTT, HC_FUSED };
const int BEST_SLH[4] = { HM_LL, X_LL, X_LL, X_LL };

const stage_variant_t STAGE_VARIANTS[] = {
    /* ML-DSA decode */
    { 1, 0, 0, MD_OSSL, 0, "default", "ossl-decoders",
      "OpenSSL's pkDecode (rho copy + poly_decode_10_bits x k) and ossl_ml_dsa_sig_decode (c~, 18/20-bit z unpack, hint decode with the omega/ordering/padding checks), PACKET based." },
    { 1, 0, 1, MD_OWN, 0, "default", "own-unpack-u64",
      "Own unpacker: t1 via 5-byte -> 4x10-bit u64 shifts, z via a 64-bit shift register, same hint validity rules; no PACKET bookkeeping." },
    { 1, 0, 2, MD_OSSL, 0, "native", "ossl-decoders-native",
      "v0 code compiled in the -O3 -march=native -flto libcrypto/driver build." },
    /* ML-DSA mu */
    { 1, 1, 0, MU_OSSL, 0, "default", "ossl-evp-shake",
      "OpenSSL path: EVP_MD_CTX_new, tr = SHAKE256(pk) (as in ossl_ml_dsa_pk_decode), mu = SHAKE256(tr || M') (as in verify_internal), EVP_MD_CTX_free." },
    { 1, 1, 1, MU_CACHED_TR, SF_CACHE, "default", "cached-tr",
      "tr cached per public key (OpenSSL keeps it in ML_DSA_KEY); only SHAKE256(tr || M') on a reused EVP_MD_CTX." },
    { 1, 1, 2, MU_LL, 0, "default", "lowlevel-sha3",
      "Both SHAKE256 calls through the internal ossl_sha3_* Keccak API on a stack KECCAK1600_CTX (no EVP fetch/dispatch/alloc)." },
    { 1, 1, 3, MU_OSSL, 0, "noasm", "ossl-evp-shake-noasm",
      "v0 code with the no-asm libcrypto (C Keccak-f[1600])." },
    { 1, 1, 4, MU_OSSL, 0, "native", "ossl-evp-shake-native",
      "v0 code in the -O3 -march=native -flto build." },
    { 1, 1, 5, MU_EVP_REUSE, 0, "default", "evp-reused-ctx",
      "Both SHAKE256 calls through EVP but on a prefetched EVP_MD and one reused EVP_MD_CTX (no allocation per call)." },
    /* ML-DSA expandA */
    { 1, 2, 0, EA_OSSL, 0, "default", "ossl-expand-A",
      "EVP_MD_CTX_new + ossl_ml_dsa_matrix_expand_A (SHAKE128 via EVP per polynomial, 168-byte squeezes, rejection sampling) + free." },
    { 1, 2, 1, EA_CACHED, SF_CACHE, "default", "cached-A",
      "A^ precomputed once per public key and memcpy'd (k*l KiB); the per-verify cost of a cached matrix." },
    { 1, 2, 2, EA_LL, 0, "default", "lowlevel-sha3",
      "Same rejection sampling but SHAKE128 driven through ossl_sha3_init/update/squeeze on a stack context (no EVP)." },
    { 1, 2, 3, EA_OSSL, 0, "noasm", "ossl-expand-A-noasm",
      "v0 code with the no-asm libcrypto (C Keccak)." },
    { 1, 2, 4, EA_OSSL, 0, "native", "ossl-expand-A-native",
      "v0 code in the -O3 -march=native -flto build." },
    { 1, 2, 5, EA_THREADS, SF_THREADS, "default", "pthread-x4-rows",
      "The k*l polynomials are expanded by 4 threads (persistent worker pool released through a barrier per call, low-level SHAKE128 per thread)." },
    /* ML-DSA w_approx */
    { 1, 3, 0, W_OSSL, 0, "default", "ossl-ntt",
      "OpenSSL code: SampleInBall+NTT(c), NTT(t1*2^d), pointwise mult (Montgomery, uint32), NTT(z), matrix_mult_vector, vector_sub, NTT^-1." },
    { 1, 3, 1, W_CACHED_T1, SF_CACHE, "default", "cached-ntt-t1",
      "NTT(t1*2^d) precomputed per public key; saves k forward NTTs per verify, rest as v0." },
    { 1, 3, 2, W_OWN_NTT, 0, "default", "own-int32-mont-ntt",
      "Own signed int32 NTT/NTT^-1 with lazy reduction (reference-style Montgomery butterflies, one final mod q), pointwise Montgomery products accumulated without intermediate reduction." },
    { 1, 3, 3, W_OSSL, 0, "native", "ossl-ntt-native",
      "v0 code in the -O3 -march=native -flto build (auto-vectorised butterflies)." },
    { 1, 3, 4, W_CACHED_OWN, SF_CACHE, "default", "cached-t1+own-ntt",
      "v1 and v2 combined: cached NTT(t1*2^d) in the int32 representation plus the own lazy NTT." },
    /* ML-DSA hint_check */
    { 1, 4, 0, HC_OSSL, 0, "default", "ossl-usehint-w1encode",
      "OpenSSL code: vector_max(z) bound check, vector_use_hint, ossl_ml_dsa_w1_encode, SHAKE256(mu || w1) via EVP (ctx allocated per call), memcmp with c~." },
    { 1, 4, 1, HC_LL, 0, "default", "lowlevel-sha3",
      "As v0 but the final SHAKE256 through ossl_sha3_* on a stack context." },
    { 1, 4, 2, HC_FUSED, 0, "default", "fused-usehint-pack",
      "UseHint and w1Encode fused into one pass that packs 4/6-bit values straight into the byte buffer (no intermediate w1 polynomial), z bound in the same sweep, low-level SHAKE256." },
    { 1, 4, 3, HC_OSSL, 0, "noasm", "ossl-noasm",
      "v0 code with the no-asm libcrypto." },
    { 1, 4, 4, HC_OSSL, 0, "native", "ossl-native",
      "v0 code in the -O3 -march=native -flto build." },

    /* SLH-DSA hmsg */
    { 0, 0, 0, HM_OSSL, 0, "default", "ossl-H_msg",
      "OpenSSL's H_msg through the SLH_DSA_HASH_CTX: SHAKE256 XOF (SHAKE sets) or SHA-256/512 digest + PKCS1_MGF1 (SHA2 sets), all via EVP." },
    { 0, 0, 1, HM_OSSL, 0, "noasm", "ossl-H_msg-noasm",
      "v0 code with the no-asm libcrypto." },
    { 0, 0, 2, HM_OSSL, 0, "native", "ossl-H_msg-native",
      "v0 code in the -O3 -march=native -flto build." },
    { 0, 0, 3, HM_LL, 0, "default", "lowlevel-hash",
      "SHAKE sets: ossl_sha3_* XOF; SHA2 sets: SHA256/SHA512_* digest and an own MGF1 loop (no EVP, no PKCS1_MGF1)." },
    { 0, 0, 4, HM_LL_MID, SF_SHA2ONLY, "default", "mgf1-seed-midstate",
      "SHA2 sets only: the MGF1 seed (R || PK.seed || digest) is absorbed once into a SHA-2 context that is copied for every counter block instead of re-hashed." },
    /* SLH-DSA fors */
    { 0, 1, 0, X_OSSL, 0, "default", "ossl-fors_pkFromSig",
      "ossl_slh_fors_pk_from_sig: k leaf F() calls, k*a H() auth-path steps and one T() over the roots, all via EVP digests on the key's hash ctx." },
    { 0, 1, 1, X_OSSL, 0, "noasm", "ossl-fors-noasm",
      "v0 code with the no-asm libcrypto." },
    { 0, 1, 2, X_OSSL, 0, "native", "ossl-fors-native",
      "v0 code in the -O3 -march=native -flto build." },
    { 0, 1, 3, X_LL, 0, "default", "lowlevel-midstate",
      "Same tree walk with F/H/T on low-level primitives: SHA2 sets reuse a SHA-256/512 midstate of PK.seed||toByte(0) (one compression saved per call), SHAKE sets use ossl_sha3_* on the stack." },
    { 0, 1, 4, X_THREADS, SF_THREADS, "default", "pthread-x4-trees",
      "The k FORS trees are split over 4 threads (persistent pool, barrier per call), each thread using the low-level primitives; T() over the roots on the caller." },
    /* SLH-DSA ht_wots */
    { 0, 2, 0, X_OSSL, 0, "default", "ossl-wots_pkFromSig",
      "d calls of ossl_slh_wots_pk_from_sig (chains of F() via EVP, T() compression) with each layer's correct message." },
    { 0, 2, 1, X_OSSL, 0, "noasm", "ossl-wots-noasm",
      "v0 code with the no-asm libcrypto." },
    { 0, 2, 2, X_OSSL, 0, "native", "ossl-wots-native",
      "v0 code in the -O3 -march=native -flto build." },
    { 0, 2, 3, X_LL, 0, "default", "lowlevel-midstate",
      "Own chain walk with F/T on low-level SHA-2 (PK.seed midstate) / ossl_sha3 primitives." },
    { 0, 2, 4, X_THREADS, SF_THREADS, "default", "pthread-x4-layers",
      "The d layers (independent given their messages) are split over 4 threads, low-level primitives." },
    /* SLH-DSA ht_auth */
    { 0, 3, 0, X_OSSL, 0, "default", "ossl-xmss-authpath",
      "The auth-path loop of ossl_slh_xmss_pk_from_sig (hm H() calls per layer via EVP on the key's hash ctx), for all d layers, plus the PK.root compare." },
    { 0, 3, 1, X_OSSL, 0, "noasm", "ossl-authpath-noasm",
      "v0 code with the no-asm libcrypto." },
    { 0, 3, 2, X_OSSL, 0, "native", "ossl-authpath-native",
      "v0 code in the -O3 -march=native -flto build." },
    { 0, 3, 3, X_LL, 0, "default", "lowlevel-midstate",
      "Same loop with H on low-level SHA-2 (PK.seed midstate) / ossl_sha3 primitives." },
    { 0, 3, 4, X_THREADS, SF_THREADS, "default", "pthread-x4-layers",
      "The d root computations (independent given the WOTS pks) are split over 4 threads, low-level primitives." },
};
const size_t NSTAGE_VARIANTS = sizeof(STAGE_VARIANTS) / sizeof(STAGE_VARIANTS[0]);

int stage_v0_method(int mldsa, int sidx)
{
    (void)mldsa; (void)sidx;
    return 0; /* every stage's v0 method enum is 0 */
}

const stage_variant_t *stage_variant_find(int mldsa, int sidx, int vidx)
{
    for (size_t i = 0; i < NSTAGE_VARIANTS; i++)
        if (STAGE_VARIANTS[i].mldsa == mldsa && STAGE_VARIANTS[i].sidx == sidx && STAGE_VARIANTS[i].vidx == vidx)
            return &STAGE_VARIANTS[i];
    return NULL;
}

/* ------------------------------------------------------------ thread pool */
/* A persistent pool of NTHREADS-1 workers plus the calling thread; a call
 * publishes (fn, ctx, ntasks), releases the start barrier, every thread takes
 * the tasks i = tid, tid+T, ..., and the end barrier joins them again. */

typedef struct {
    int (*fn)(void *, int);
    void *ctx;
    int ntasks;
    int ok[NTHREADS];
    volatile int stop;
    pthread_barrier_t start, end;
    pthread_t th[NTHREADS];
    int ready;
} pool_t;
static pool_t g_pool;

static void pool_work(int tid)
{
    pool_t *p = &g_pool;
    int ok = 1;
    for (int i = tid; i < p->ntasks; i += NTHREADS)
        if (!p->fn(p->ctx, i))
            ok = 0;
    p->ok[tid] = ok;
}

static void *pool_thread(void *a)
{
    int tid = (int)(intptr_t)a;
    for (;;) {
        pthread_barrier_wait(&g_pool.start);
        if (g_pool.stop)
            break;
        pool_work(tid);
        pthread_barrier_wait(&g_pool.end);
    }
    return NULL;
}

static void pool_init(void)
{
    if (g_pool.ready) return;
    pthread_barrier_init(&g_pool.start, NULL, NTHREADS);
    pthread_barrier_init(&g_pool.end, NULL, NTHREADS);
    for (int i = 1; i < NTHREADS; i++)
        pthread_create(&g_pool.th[i], NULL, pool_thread, (void *)(intptr_t)i);
    g_pool.ready = 1;
}

static int run_tasks(int (*fn)(void *, int), void *ctx, int ntasks)
{
    if (ntasks <= 0) return 1;
    pool_init();
    g_pool.fn = fn; g_pool.ctx = ctx; g_pool.ntasks = ntasks;
    pthread_barrier_wait(&g_pool.start);
    pool_work(0);
    pthread_barrier_wait(&g_pool.end);
    int ok = 1;
    for (int i = 0; i < NTHREADS; i++)
        ok &= g_pool.ok[i];
    return ok;
}

/* ------------------------------------------------------- low level SHAKE */

static int shake_ll(int bits, const uint8_t *in1, size_t l1, const uint8_t *in2, size_t l2,
                    const uint8_t *in3, size_t l3, const uint8_t *in4, size_t l4,
                    uint8_t *out, size_t outlen)
{
    KECCAK1600_CTX c;
    return ossl_sha3_init(&c, 0x1f, bits)
        && ossl_sha3_update(&c, in1, l1)
        && ossl_sha3_update(&c, in2, l2)
        && ossl_sha3_update(&c, in3, l3)
        && ossl_sha3_update(&c, in4, l4)
        && ossl_sha3_final(&c, out, outlen);
}

/* ============================================================== ML-DSA */

typedef struct {
    const ML_DSA_PARAMS *prm;
    ML_DSA_KEY *key;
    size_t k, l, ctl, w1len;
    const uint8_t *pk, *sig, *mprime;
    size_t pk_len, sig_len, mprime_len;
    /* v0 outputs (inputs of the following stages) */
    uint8_t rho0[32];
    POLY *t10, *z0, *h0;
    uint8_t ct0[64];
    ML_DSA_SIG sig0;
    uint8_t mu0[64];
    POLY *A0;
    MATRIX A0m;
    POLY *w0;
    VECTOR w0v;
    uint8_t *w1enc0;
    /* caches */
    POLY *ct1c;             /* NTT(t1 * 2^d), OpenSSL representation */
    VECTOR ct1cv;
    int32_t *t1ntt_own;     /* NTT(t1 * 2^d), own int32 representation */
    /* scratch outputs */
    uint8_t rhot[32];
    POLY *t1t, *zt, *ht;
    uint8_t ctt[64];
    ML_DSA_SIG sigt;
    uint8_t mut[64];
    POLY *At;
    MATRIX Atm;
    POLY *wt;
    VECTOR wtv;
    uint8_t *w1t;
    POLY *tmp;              /* k + l + k polys */
    int32_t *own;           /* (l + 2k) * 256 */
    EVP_MD_CTX *mdctx;
    int hint_ok_t;          /* result of the last hint_check run */
} mld_t;

static void own_zetas_init(void);
static void own_t1_ntt(mld_t *m, int32_t *out);
static int ml_expandA(mld_t *m, int method, MATRIX *A);
static void mld_free(mld_t *m);

static int evp_type_of(const char *name)
{
    if (strcmp(name, "ML-DSA-44") == 0) return EVP_PKEY_ML_DSA_44;
    if (strcmp(name, "ML-DSA-65") == 0) return EVP_PKEY_ML_DSA_65;
    return EVP_PKEY_ML_DSA_87;
}

static mld_t *mld_new(const param_t *p, const uint8_t *pk, size_t pk_len, const uint8_t *sig, size_t sig_len,
                      const uint8_t *mprime, size_t mprime_len)
{
    mld_t *m = calloc(1, sizeof(*m));
    m->key = ossl_ml_dsa_key_new(NULL, NULL, evp_type_of(p->name));
    if (m->key == NULL || !ossl_ml_dsa_pk_decode(m->key, pk, pk_len)) {
        ossl_ml_dsa_key_free(m->key);
        free(m);
        ERR_clear_error();
        return NULL;
    }
    m->prm = m->key->params;
    m->k = m->prm->k;
    m->l = m->prm->l;
    m->ctl = (size_t)m->prm->bit_strength / 4;
    m->w1len = m->k * (m->prm->gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV88 ? 192 : 128);
    m->pk = pk; m->pk_len = pk_len; m->sig = sig; m->sig_len = sig_len;
    m->mprime = mprime; m->mprime_len = mprime_len;
    size_t k = m->k, l = m->l;
    m->t10 = calloc(k, sizeof(POLY)); m->z0 = calloc(l, sizeof(POLY)); m->h0 = calloc(k, sizeof(POLY));
    m->A0 = calloc(k * l, sizeof(POLY)); matrix_init(&m->A0m, m->A0, k, l);
    m->w0 = calloc(k, sizeof(POLY)); vector_init(&m->w0v, m->w0, k);
    m->w1enc0 = calloc(1, m->w1len);
    m->ct1c = calloc(k, sizeof(POLY)); vector_init(&m->ct1cv, m->ct1c, k);
    m->t1ntt_own = calloc(k * 256, sizeof(int32_t));
    m->t1t = calloc(k, sizeof(POLY)); m->zt = calloc(l, sizeof(POLY)); m->ht = calloc(k, sizeof(POLY));
    m->At = calloc(k * l, sizeof(POLY)); matrix_init(&m->Atm, m->At, k, l);
    m->wt = calloc(k, sizeof(POLY)); vector_init(&m->wtv, m->wt, k);
    m->w1t = calloc(1, m->w1len);
    m->tmp = calloc(2 * k + l, sizeof(POLY));
    m->own = calloc((l + 2 * k) * 256, sizeof(int32_t));
    m->mdctx = EVP_MD_CTX_new();
    vector_init(&m->sig0.z, m->z0, l); vector_init(&m->sig0.hint, m->h0, k);
    m->sig0.c_tilde = m->ct0; m->sig0.c_tilde_len = m->ctl;
    vector_init(&m->sigt.z, m->zt, l); vector_init(&m->sigt.hint, m->ht, k);
    m->sigt.c_tilde = m->ctt; m->sigt.c_tilde_len = m->ctl;
    /* per-public-key precomputation used by the SF_CACHE variants (depends on pk only) */
    vector_scale_power2_round_ntt(&m->key->t1, &m->ct1cv);
    own_zetas_init();
    own_t1_ntt(m, m->t1ntt_own);
    if (!ml_expandA(m, EA_OSSL, &m->A0m)) {
        mld_free(m);
        return NULL;
    }
    return m;
}

static void mld_free(mld_t *m)
{
    if (m == NULL) return;
    ossl_ml_dsa_key_free(m->key);
    free(m->t10); free(m->z0); free(m->h0); free(m->A0); free(m->w0); free(m->w1enc0);
    free(m->ct1c); free(m->t1ntt_own); free(m->t1t); free(m->zt); free(m->ht); free(m->At);
    free(m->wt); free(m->w1t); free(m->tmp); free(m->own);
    EVP_MD_CTX_free(m->mdctx);
    free(m);
}

/* ---- stage 0: decode */

static int ml_decode(mld_t *m, int method, uint8_t rho[32], POLY *t1, ML_DSA_SIG *out)
{
    const ML_DSA_PARAMS *prm = m->prm;
    if (m->pk_len != prm->pk_len)
        return 0;
    if (method == MD_OSSL) {
        PACKET pkt;
        if (!PACKET_buf_init(&pkt, m->pk, m->pk_len)
            || !PACKET_copy_bytes(&pkt, rho, ML_DSA_RHO_BYTES))
            return 0;
        for (size_t i = 0; i < m->k; i++)
            if (!poly_decode_10_bits(t1 + i, &pkt))
                return 0;
        return st_ml_dsa_sig_decode(out, m->sig, m->sig_len, prm);
    }
    /* MD_OWN */
    if (m->sig_len != prm->sig_len)
        return 0;
    memcpy(rho, m->pk, 32);
    const uint8_t *in = m->pk + 32;
    for (size_t i = 0; i < m->k; i++) {
        uint32_t *c = t1[i].coeff;
        for (int j = 0; j < 64; j++, in += 5, c += 4) {
            uint64_t v = (uint64_t)in[0] | (uint64_t)in[1] << 8 | (uint64_t)in[2] << 16
                | (uint64_t)in[3] << 24 | (uint64_t)in[4] << 32;
            c[0] = (uint32_t)(v & 1023); c[1] = (uint32_t)((v >> 10) & 1023);
            c[2] = (uint32_t)((v >> 20) & 1023); c[3] = (uint32_t)((v >> 30) & 1023);
        }
    }
    memcpy(out->c_tilde, m->sig, m->ctl);
    in = m->sig + m->ctl;
    uint32_t range = (uint32_t)prm->gamma1;
    int bits = range == (1u << 19) ? 20 : 18;
    uint32_t mask = (1u << bits) - 1;
    for (size_t i = 0; i < m->l; i++) {
        uint32_t *c = out->z.poly[i].coeff;
        uint64_t acc = 0;
        int nb = 0;
        for (int j = 0; j < 256; j++) {
            while (nb < bits) {
                acc |= (uint64_t)*in++ << nb;
                nb += 8;
            }
            c[j] = mod_sub(range, (uint32_t)(acc & mask));
            acc >>= bits;
            nb -= bits;
        }
    }
    /* hints: omega bytes of indices then k limits */
    uint32_t omega = (uint32_t)prm->omega;
    const uint8_t *hin = in, *limits = in + omega;
    size_t ci = 0;
    vector_zero(&out->hint);
    for (size_t i = 0; i < m->k; i++) {
        uint32_t limit = limits[i];
        int last = -1;
        if (limit < ci || limit > omega)
            return 0;
        while (ci < limit) {
            int b = hin[ci++];
            if (last >= 0 && b <= last)
                return 0;
            last = b;
            out->hint.poly[i].coeff[b] = 1;
        }
    }
    for (; ci < omega; ci++)
        if (hin[ci] != 0)
            return 0;
    return 1;
}

/* ---- stage 1: mu */

static int ml_mu(mld_t *m, int method, uint8_t mu[64])
{
    const ML_DSA_KEY *key = m->key;
    uint8_t tr[64];
    switch (method) {
    case MU_OSSL: {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int ok = c != NULL
            && shake_xof(c, key->shake256_md, m->pk, m->pk_len, tr, 64)
            && shake_xof_2(c, key->shake256_md, tr, 64, m->mprime, m->mprime_len, mu, 64);
        EVP_MD_CTX_free(c);
        return ok;
    }
    case MU_CACHED_TR:
        return shake_xof_2(m->mdctx, key->shake256_md, key->tr, 64, m->mprime, m->mprime_len, mu, 64);
    case MU_EVP_REUSE:
        return shake_xof(m->mdctx, key->shake256_md, m->pk, m->pk_len, tr, 64)
            && shake_xof_2(m->mdctx, key->shake256_md, tr, 64, m->mprime, m->mprime_len, mu, 64);
    default: /* MU_LL */
        return shake_ll(256, m->pk, m->pk_len, NULL, 0, NULL, 0, NULL, 0, tr, 64)
            && shake_ll(256, tr, 64, m->mprime, m->mprime_len, NULL, 0, NULL, 0, mu, 64);
    }
}

/* ---- stage 2: expandA */

static int ll_rej_ntt_poly(const uint8_t *seed, POLY *out)
{
    KECCAK1600_CTX c;
    uint8_t blk[168];
    int j = 0;
    if (!ossl_sha3_init(&c, 0x1f, 128) || !ossl_sha3_update(&c, seed, 34))
        return 0;
    for (;;) {
        if (!ossl_sha3_squeeze(&c, blk, sizeof(blk)))
            return 0;
        for (const uint8_t *b = blk; b < blk + 168; b += 3) {
            uint32_t v = (uint32_t)b[0] | (uint32_t)b[1] << 8 | ((uint32_t)b[2] & 0x7f) << 16;
            if (v < ML_DSA_Q) {
                out->coeff[j++] = v;
                if (j == 256)
                    return 1;
            }
        }
    }
}

typedef struct { mld_t *m; MATRIX *A; } ea_task_t;
static int ea_task(void *ctx, int t)
{
    ea_task_t *e = ctx;
    uint8_t seed[34];
    memcpy(seed, e->m->key->rho, 32);
    seed[32] = (uint8_t)(t % e->m->l); /* column j */
    seed[33] = (uint8_t)(t / e->m->l); /* row i */
    return ll_rej_ntt_poly(seed, e->A->m_poly + t);
}

static int ml_expandA(mld_t *m, int method, MATRIX *A)
{
    switch (method) {
    case EA_OSSL: {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int ok = c != NULL && ossl_ml_dsa_matrix_expand_A(c, m->key->shake128_md, m->key->rho, A);
        EVP_MD_CTX_free(c);
        return ok;
    }
    case EA_CACHED:
        memcpy(A->m_poly, m->A0, m->k * m->l * sizeof(POLY));
        return 1;
    case EA_THREADS: {
        ea_task_t e = { m, A };
        return run_tasks(ea_task, &e, (int)(m->k * m->l));
    }
    default: { /* EA_LL */
        ea_task_t e = { m, A };
        for (int t = 0; t < (int)(m->k * m->l); t++)
            if (!ea_task(&e, t))
                return 0;
        return 1;
    }
    }
}

/* ---- stage 3: w_approx */

/* own signed-int32 Montgomery NTT (reference-style, lazy reduction) */
#define OQ 8380417
#define OQINV 58728449
#define OMONT (-4186625)
#define OF 41978
static int32_t own_zetas[256];
static int own_zetas_ready = 0;

static int32_t own_mont_reduce(int64_t a)
{
    int32_t t = (int32_t)((uint32_t)a * (uint32_t)OQINV);
    return (int32_t)((a - (int64_t)t * OQ) >> 32);
}

static void own_zetas_init(void)
{
    if (own_zetas_ready) return;
    for (int i = 0; i < 256; i++) {
        int brv = 0;
        for (int b = 0; b < 8; b++) if (i & (1 << b)) brv |= 1 << (7 - b);
        uint64_t z = 1, base = 1753;
        for (int e = brv; e > 0; e >>= 1) {
            if (e & 1) z = z * base % OQ;
            base = base * base % OQ;
        }
        z = (z << 32) % OQ; /* Montgomery form */
        int32_t s = (int32_t)z;
        if (s > OQ / 2) s -= OQ;
        own_zetas[i] = s;
    }
    own_zetas_ready = 1;
}

static void own_ntt(int32_t a[256])
{
    unsigned len, start, j, k = 0;
    for (len = 128; len > 0; len >>= 1)
        for (start = 0; start < 256; start = j + len) {
            int32_t zeta = own_zetas[++k];
            for (j = start; j < start + len; ++j) {
                int32_t t = own_mont_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
}

static void own_invntt_tomont(int32_t a[256])
{
    unsigned len, start, j, k = 256;
    for (len = 1; len < 256; len <<= 1)
        for (start = 0; start < 256; start = j + len) {
            int32_t zeta = -own_zetas[--k];
            for (j = start; j < start + len; ++j) {
                int32_t t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = own_mont_reduce((int64_t)zeta * a[j + len]);
            }
        }
    for (j = 0; j < 256; ++j)
        a[j] = own_mont_reduce((int64_t)OF * a[j]);
}

static void own_t1_ntt(mld_t *m, int32_t *out)
{
    for (size_t i = 0; i < m->k; i++) {
        for (int j = 0; j < 256; j++)
            out[i * 256 + j] = (int32_t)(m->key->t1.poly[i].coeff[j] << ML_DSA_D_BITS);
        own_ntt(out + i * 256);
    }
}

static int ml_w_approx(mld_t *m, int method, const ML_DSA_SIG *sig, const MATRIX *A, VECTOR *w)
{
    const ML_DSA_PARAMS *prm = m->prm;
    size_t k = m->k, l = m->l;
    POLY c;
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    int ok = mc != NULL && ossl_ml_dsa_poly_sample_in_ball(&c, sig->c_tilde, (int)sig->c_tilde_len,
                                                            mc, m->key->shake256_md, (uint32_t)prm->tau);
    EVP_MD_CTX_free(mc);
    if (!ok)
        return 0;
    if (method == W_OSSL || method == W_CACHED_T1) {
        VECTOR ct1, zc;
        vector_init(&ct1, m->tmp, k);
        vector_init(&zc, m->tmp + k, l);
        poly_ntt(&c);
        if (method == W_OSSL)
            vector_scale_power2_round_ntt(&m->key->t1, &ct1);
        else
            vector_copy(&ct1, &m->ct1cv);
        vector_mult_scalar(&ct1, &c, &ct1);
        vector_copy(&zc, &sig->z);
        vector_ntt(&zc);
        matrix_mult_vector(A, &zc, w);
        vector_sub(w, &ct1, w);
        vector_ntt_inverse(w);
        return 1;
    }
    /* own int32 NTT */
    own_zetas_init();
    int32_t *z = m->own, *t1n = m->own + l * 256, *acc = t1n + k * 256, cn[256];
    for (int j = 0; j < 256; j++)
        cn[j] = (int32_t)c.coeff[j];
    own_ntt(cn);
    for (size_t j = 0; j < l; j++) {
        for (int t = 0; t < 256; t++)
            z[j * 256 + t] = (int32_t)sig->z.poly[j].coeff[t];
        own_ntt(z + j * 256);
    }
    if (method == W_OWN_NTT)
        own_t1_ntt(m, t1n);
    else
        t1n = m->t1ntt_own;
    for (size_t i = 0; i < k; i++) {
        int32_t *r = acc + i * 256;
        for (int t = 0; t < 256; t++) {
            /* one 64-bit accumulation of the l products minus c*t1, then a single
             * Montgomery reduction: |r| < q, which the lazy NTT^-1 requires */
            int64_t s = -(int64_t)cn[t] * t1n[i * 256 + t];
            for (size_t j = 0; j < l; j++)
                s += (int64_t)A->m_poly[i * l + j].coeff[t] * z[j * 256 + t];
            r[t] = own_mont_reduce(s);
        }
        own_invntt_tomont(r);
        for (int t = 0; t < 256; t++) {
            int32_t v = r[t] % OQ;
            if (v < 0) v += OQ;
            w->poly[i].coeff[t] = (uint32_t)v;
        }
    }
    return 1;
}

/* ---- stage 4: hint_check */

static int ml_hint_check(mld_t *m, int method, const ML_DSA_SIG *sig, const uint8_t mu[64],
                         const VECTOR *w, uint8_t *w1enc)
{
    const ML_DSA_PARAMS *prm = m->prm;
    uint32_t gamma2 = (uint32_t)prm->gamma2;
    uint8_t ct[64];
    uint32_t z_max;
    int ok;
    if (method == HC_FUSED) {
        z_max = 0;
        for (size_t i = 0; i < m->l; i++)
            poly_max(&sig->z.poly[i], &z_max);
        uint8_t *o = w1enc;
        for (size_t i = 0; i < m->k; i++) {
            const uint32_t *r = w->poly[i].coeff, *h = sig->hint.poly[i].coeff;
            if (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32) {
                for (int t = 0; t < 256; t += 2) {
                    uint32_t a = ossl_ml_dsa_key_compress_use_hint(h[t], r[t], gamma2);
                    uint32_t b = ossl_ml_dsa_key_compress_use_hint(h[t + 1], r[t + 1], gamma2);
                    *o++ = (uint8_t)(a | (b << 4));
                }
            } else {
                for (int t = 0; t < 256; t += 4) {
                    uint32_t a = ossl_ml_dsa_key_compress_use_hint(h[t], r[t], gamma2);
                    uint32_t b = ossl_ml_dsa_key_compress_use_hint(h[t + 1], r[t + 1], gamma2);
                    uint32_t c = ossl_ml_dsa_key_compress_use_hint(h[t + 2], r[t + 2], gamma2);
                    uint32_t d = ossl_ml_dsa_key_compress_use_hint(h[t + 3], r[t + 3], gamma2);
                    uint32_t v = a | (b << 6) | (c << 12) | (d << 18);
                    *o++ = (uint8_t)v; *o++ = (uint8_t)(v >> 8); *o++ = (uint8_t)(v >> 16);
                }
            }
        }
        ok = shake_ll(256, mu, 64, w1enc, m->w1len, NULL, 0, NULL, 0, ct, m->ctl);
    } else {
        VECTOR w1;
        vector_init(&w1, m->tmp, m->k);
        z_max = vector_max(&sig->z);
        vector_use_hint(&sig->hint, w, gamma2, &w1);
        st_ml_dsa_w1_encode(&w1, gamma2, w1enc, m->w1len);
        if (method == HC_OSSL) {
            EVP_MD_CTX *c = EVP_MD_CTX_new();
            ok = c != NULL && shake_xof_3(c, m->key->shake256_md, mu, 64, w1enc, m->w1len, NULL, 0, ct, m->ctl);
            EVP_MD_CTX_free(c);
        } else {
            ok = shake_ll(256, mu, 64, w1enc, m->w1len, NULL, 0, NULL, 0, ct, m->ctl);
        }
    }
    return ok && z_max < (uint32_t)(prm->gamma1 - prm->beta) && memcmp(ct, sig->c_tilde, m->ctl) == 0;
}

/* ============================================================== SLH-DSA */

typedef struct {
    const SLH_DSA_PARAMS *prm;
    SLH_DSA_KEY *key;
    SLH_DSA_HASH_CTX *hctx;
    const SLH_HASH_FUNC *hashf;
    const SLH_ADRS_FUNC *adrsf;
    size_t n, m, md_len, k, a, d, hm, wlen, adrs_len;
    int is_shake, big512;
    const uint8_t *pk, *sig, *mprime, *pk_seed, *pk_root, *r, *fors_sig, *ht_sig;
    size_t pk_len, sig_len, mprime_len;
    /* v0 outputs */
    uint8_t digest0[64];
    uint64_t tree0;
    uint32_t leaf0;
    uint64_t tree_ids[32];
    uint32_t leaf_ids[32];
    uint8_t pkfors0[32], wots0[32 * 32], roots0[32 * 32];
    /* scratch */
    uint8_t digestt[64], pkforst[32], wotst[32 * 32], rootst[32 * 32];
    /* midstates (SHA2 sets): PK.seed || toByte(0, b - n) absorbed */
    SHA256_CTX ms256;
    SHA512_CTX ms512;
    int auth_ok_t;
} slh_t;

static slh_t *slh_new(const param_t *p, const uint8_t *pk, size_t pk_len, const uint8_t *sig, size_t sig_len,
                      const uint8_t *mprime, size_t mprime_len)
{
    slh_t *s = calloc(1, sizeof(*s));
    s->key = ossl_slh_dsa_key_new(NULL, NULL, p->name);
    if (s->key == NULL || !ossl_slh_dsa_set_pub(s->key, pk, pk_len)) {
        ossl_slh_dsa_key_free(s->key);
        free(s);
        ERR_clear_error();
        return NULL;
    }
    s->hctx = ossl_slh_dsa_hash_ctx_new(s->key);
    s->prm = s->key->params;
    s->hashf = s->key->hash_func;
    s->adrsf = s->key->adrs_func;
    s->n = s->prm->n; s->m = s->prm->m; s->k = s->prm->k; s->a = s->prm->a; s->d = s->prm->d; s->hm = s->prm->hm;
    s->md_len = (s->k * s->a + 7) >> 3;
    s->wlen = 2 * s->n + 3;
    s->is_shake = s->prm->is_shake;
    s->big512 = !s->is_shake && s->n > 16;
    s->adrs_len = s->is_shake ? SLH_ADRS_SIZE : SLH_ADRSC_SIZE;
    s->pk = pk; s->pk_len = pk_len; s->sig = sig; s->sig_len = sig_len;
    s->mprime = mprime; s->mprime_len = mprime_len;
    s->pk_seed = SLH_DSA_PK_SEED(s->key);
    s->pk_root = SLH_DSA_PK_ROOT(s->key);
    s->r = sig;
    s->fors_sig = sig + s->n;
    s->ht_sig = s->fors_sig + s->k * (s->a + 1) * s->n;
    if (!s->is_shake) {
        uint8_t zeros[128] = { 0 };
        SHA256_Init(&s->ms256);
        SHA256_Update(&s->ms256, s->pk_seed, s->n);
        SHA256_Update(&s->ms256, zeros, 64 - s->n);
        SHA512_Init(&s->ms512);
        SHA512_Update(&s->ms512, s->pk_seed, s->n);
        SHA512_Update(&s->ms512, zeros, 128 - s->n);
    }
    return s;
}

static void slh_free(slh_t *s)
{
    if (s == NULL) return;
    ossl_slh_dsa_hash_ctx_free(s->hctx);
    ossl_slh_dsa_key_free(s->key);
    free(s);
}

/* low-level F / H / T (the "LL" primitives) */
static int ll_hash(slh_t *s, int big, const uint8_t *adrs, const uint8_t *m1, size_t l1,
                   const uint8_t *m2, size_t l2, uint8_t *out)
{
    if (s->is_shake)
        return shake_ll(256, s->pk_seed, s->n, adrs, SLH_ADRS_SIZE, m1, l1, m2, l2, out, s->n);
    uint8_t dig[64];
    if (big && s->big512) {
        SHA512_CTX c = s->ms512;
        SHA512_Update(&c, adrs, SLH_ADRSC_SIZE);
        SHA512_Update(&c, m1, l1);
        if (l2) SHA512_Update(&c, m2, l2);
        SHA512_Final(dig, &c);
    } else {
        SHA256_CTX c = s->ms256;
        SHA256_Update(&c, adrs, SLH_ADRSC_SIZE);
        SHA256_Update(&c, m1, l1);
        if (l2) SHA256_Update(&c, m2, l2);
        SHA256_Final(dig, &c);
    }
    memcpy(out, dig, s->n);
    return 1;
}
#define F_LL(s, adrs, m, out) ll_hash(s, 0, adrs, m, (s)->n, NULL, 0, out)
#define H_LL(s, adrs, m1, m2, out) ll_hash(s, 1, adrs, m1, (s)->n, m2, (s)->n, out)
#define T_LL(s, adrs, m, len, out) ll_hash(s, 1, adrs, m, len, NULL, 0, out)

static uint64_t be_bytes(const uint8_t *b, size_t len)
{
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) v = (v << 8) | b[i];
    return v;
}

static void slh_layer_ids(slh_t *s, uint64_t tree, uint32_t leaf)
{
    uint32_t mask = (1u << s->hm) - 1;
    for (size_t i = 0; i < s->d; i++) {
        s->tree_ids[i] = tree;
        s->leaf_ids[i] = leaf;
        leaf = (uint32_t)(tree & mask);
        tree >>= s->hm;
    }
}

/* ---- stage 0: hmsg */

static int own_mgf1(slh_t *s, int midstate, const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen)
{
    uint8_t dig[64], cnt[4];
    size_t sz = s->big512 ? 64 : 32, done = 0;
    SHA256_CTX m256; SHA512_CTX m512;
    if (midstate) {
        if (s->big512) { SHA512_Init(&m512); SHA512_Update(&m512, seed, seed_len); }
        else { SHA256_Init(&m256); SHA256_Update(&m256, seed, seed_len); }
    }
    for (uint32_t c = 0; done < outlen; c++) {
        cnt[0] = (uint8_t)(c >> 24); cnt[1] = (uint8_t)(c >> 16); cnt[2] = (uint8_t)(c >> 8); cnt[3] = (uint8_t)c;
        if (s->big512) {
            SHA512_CTX x;
            if (midstate) x = m512; else { SHA512_Init(&x); SHA512_Update(&x, seed, seed_len); }
            SHA512_Update(&x, cnt, 4);
            SHA512_Final(dig, &x);
        } else {
            SHA256_CTX x;
            if (midstate) x = m256; else { SHA256_Init(&x); SHA256_Update(&x, seed, seed_len); }
            SHA256_Update(&x, cnt, 4);
            SHA256_Final(dig, &x);
        }
        size_t take = outlen - done < sz ? outlen - done : sz;
        memcpy(out + done, dig, take);
        done += take;
    }
    return 1;
}

/* split the digest: md || tree idx || leaf idx (as OpenSSL's get_tree_ids) */
static void slh_split(slh_t *s, const uint8_t *digest, uint64_t *tree, uint32_t *leaf)
{
    const uint8_t *p = digest + s->md_len;
    size_t tlen = (s->prm->h - s->hm + 7) >> 3, llen = (s->hm + 7) >> 3;
    uint64_t tmask = (~(uint64_t)0) >> (64 - (s->prm->h - s->hm));
    *tree = be_bytes(p, tlen) & tmask;
    *leaf = (uint32_t)(be_bytes(p + tlen, llen) & (((uint64_t)1 << s->hm) - 1));
}

static int slh_hmsg(slh_t *s, int method, uint8_t *digest, uint64_t *tree, uint32_t *leaf)
{
    size_t n = s->n;
    if (s->sig_len != s->prm->sig_len)
        return 0;
    if (method == HM_OSSL) {
        if (!s->hashf->H_MSG(s->hctx, s->r, s->pk_seed, s->pk_root, s->mprime, s->mprime_len, digest, 64))
            return 0;
    } else if (s->is_shake) {
        if (!shake_ll(256, s->r, n, s->pk_seed, n, s->pk_root, n, s->mprime, s->mprime_len, digest, s->m))
            return 0;
    } else {
        uint8_t seed[64 + 64];
        size_t sz = s->big512 ? 64 : 32;
        memcpy(seed, s->r, n);
        memcpy(seed + n, s->pk_seed, n);
        if (s->big512) {
            SHA512_CTX c; SHA512_Init(&c);
            SHA512_Update(&c, s->r, n); SHA512_Update(&c, s->pk_seed, n); SHA512_Update(&c, s->pk_root, n);
            SHA512_Update(&c, s->mprime, s->mprime_len); SHA512_Final(seed + 2 * n, &c);
        } else {
            SHA256_CTX c; SHA256_Init(&c);
            SHA256_Update(&c, s->r, n); SHA256_Update(&c, s->pk_seed, n); SHA256_Update(&c, s->pk_root, n);
            SHA256_Update(&c, s->mprime, s->mprime_len); SHA256_Final(seed + 2 * n, &c);
        }
        own_mgf1(s, method == HM_LL_MID, seed, 2 * n + sz, digest, s->m);
    }
    slh_split(s, digest, tree, leaf);
    return 1;
}

/* ---- stage 1: fors */

static void base_2b(const uint8_t *in, uint32_t b, uint32_t *out, size_t out_len)
{
    uint32_t bits = 0, total = 0, mask = (1u << b) - 1;
    for (size_t c = 0; c < out_len; c++) {
        while (bits < b) { total = (total << 8) | *in++; bits += 8; }
        bits -= b;
        out[c] = (total >> bits) & mask;
    }
}

typedef struct { slh_t *s; const uint8_t *md; uint32_t ids[35]; uint8_t roots[35 * 32]; uint8_t adrs_base[32]; } fors_task_t;

static int fors_tree_ll(void *ctx, int i)
{
    fors_task_t *f = ctx;
    slh_t *s = f->s;
    size_t n = s->n, a = s->a;
    uint8_t adrs[32], node[32];
    memcpy(adrs, f->adrs_base, 32);
    uint32_t id = f->ids[i], node_id = id + (uint32_t)i * (1u << a);
    const uint8_t *sk = s->fors_sig + (size_t)i * (a + 1) * n;
    s->adrsf->set_tree_height(adrs, 0);
    s->adrsf->set_tree_index(adrs, node_id);
    if (!F_LL(s, adrs, sk, node))
        return 0;
    for (size_t j = 0; j < a; j++) {
        const uint8_t *auth = sk + (j + 1) * n;
        s->adrsf->set_tree_height(adrs, (uint32_t)j + 1);
        int ok;
        if ((id & 1) == 0) {
            node_id >>= 1;
            s->adrsf->set_tree_index(adrs, node_id);
            ok = H_LL(s, adrs, node, auth, node);
        } else {
            node_id = (node_id - 1) >> 1;
            s->adrsf->set_tree_index(adrs, node_id);
            ok = H_LL(s, adrs, auth, node, node);
        }
        if (!ok) return 0;
        id >>= 1;
    }
    memcpy(f->roots + (size_t)i * n, node, n);
    return 1;
}

static int slh_fors(slh_t *s, int method, const uint8_t *md, uint64_t tree, uint32_t leaf, uint8_t *pk_out)
{
    uint8_t adrs[32];
    s->adrsf->zero(adrs);
    s->adrsf->set_tree_address(adrs, tree);
    s->adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_FORS_TREE);
    s->adrsf->set_keypair_address(adrs, leaf);
    if (method == X_OSSL) {
        PACKET pkt;
        return PACKET_buf_init(&pkt, s->fors_sig, s->k * (s->a + 1) * s->n)
            && ossl_slh_fors_pk_from_sig(s->hctx, &pkt, md, s->pk_seed, adrs, pk_out, s->n);
    }
    fors_task_t *f = calloc(1, sizeof(*f));
    f->s = s; f->md = md;
    memcpy(f->adrs_base, adrs, 32);
    base_2b(md, (uint32_t)s->a, f->ids, s->k);
    int ok;
    if (method == X_THREADS) {
        ok = run_tasks(fors_tree_ll, f, (int)s->k);
    } else {
        ok = 1;
        for (int i = 0; i < (int)s->k; i++)
            ok &= fors_tree_ll(f, i);
    }
    if (ok) {
        uint8_t pk_adrs[32];
        s->adrsf->copy(pk_adrs, adrs);
        s->adrsf->set_type_and_clear(pk_adrs, SLH_ADRS_TYPE_FORS_ROOTS);
        s->adrsf->copy_keypair_address(pk_adrs, adrs);
        ok = T_LL(s, pk_adrs, f->roots, s->k * s->n, pk_out);
    }
    free(f);
    return ok;
}

/* ---- stage 2: ht_wots (one layer) */

static void layer_adrs(slh_t *s, size_t layer, uint8_t adrs[32])
{
    s->adrsf->zero(adrs);
    s->adrsf->set_layer_address(adrs, (uint32_t)layer);
    s->adrsf->set_tree_address(adrs, s->tree_ids[layer]);
}

static const uint8_t *layer_sig(slh_t *s, size_t layer)
{
    return s->ht_sig + layer * (s->wlen + s->hm) * s->n;
}

static int wots_layer(slh_t *s, int method, size_t layer, const uint8_t *msg, uint8_t *pk_out)
{
    uint8_t adrs[32];
    size_t n = s->n, len = s->wlen;
    layer_adrs(s, layer, adrs);
    s->adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_WOTS_HASH);
    s->adrsf->set_keypair_address(adrs, s->leaf_ids[layer]);
    if (method == X_OSSL) {
        PACKET pkt;
        return PACKET_buf_init(&pkt, layer_sig(s, layer), len * n)
            && ossl_slh_wots_pk_from_sig(s->hctx, &pkt, msg, s->pk_seed, adrs, pk_out, n);
    }
    uint8_t nib[67 + 3], tmp[(2 * 32 + 3) * 32], pk_adrs[32];
    size_t len1 = 2 * n;
    uint16_t csum = 0;
    for (size_t i = 0; i < n; i++) {
        nib[2 * i] = msg[i] >> 4;
        nib[2 * i + 1] = msg[i] & 15;
    }
    for (size_t i = 0; i < len1; i++) csum += nib[i];
    csum = (uint16_t)(15 * len1) - csum;
    nib[len1] = (csum >> 8) & 15; nib[len1 + 1] = (csum >> 4) & 15; nib[len1 + 2] = csum & 15;
    const uint8_t *sig_i = layer_sig(s, layer);
    for (size_t i = 0; i < len; i++, sig_i += n) {
        uint8_t *t = tmp + i * n;
        s->adrsf->set_chain_address(adrs, (uint32_t)i);
        memcpy(t, sig_i, n);
        for (uint32_t j = nib[i]; j < 15; j++) {
            s->adrsf->set_hash_address(adrs, j);
            if (!F_LL(s, adrs, t, t))
                return 0;
        }
    }
    s->adrsf->copy(pk_adrs, adrs);
    s->adrsf->set_type_and_clear(pk_adrs, SLH_ADRS_TYPE_WOTS_PK);
    s->adrsf->copy_keypair_address(pk_adrs, adrs);
    return T_LL(s, pk_adrs, tmp, len * n, pk_out);
}

/* ---- stage 3: ht_auth (one layer) */

static int auth_layer(slh_t *s, int method, size_t layer, const uint8_t *wots_pk, uint8_t *root_out)
{
    uint8_t adrs[32], node[32];
    size_t n = s->n;
    uint32_t node_id = s->leaf_ids[layer];
    const uint8_t *auth = layer_sig(s, layer) + s->wlen * n;
    layer_adrs(s, layer, adrs);
    s->adrsf->set_type_and_clear(adrs, SLH_ADRS_TYPE_TREE);
    memcpy(node, wots_pk, n);
    for (size_t k = 0; k < s->hm; k++, auth += n) {
        int ok;
        s->adrsf->set_tree_height(adrs, (uint32_t)k + 1);
        if ((node_id & 1) == 0) {
            node_id >>= 1;
            s->adrsf->set_tree_index(adrs, node_id);
            ok = method == X_OSSL ? s->hashf->H(s->hctx, s->pk_seed, adrs, node, auth, node, n)
                                  : H_LL(s, adrs, node, auth, node);
        } else {
            node_id = (node_id - 1) >> 1;
            s->adrsf->set_tree_index(adrs, node_id);
            ok = method == X_OSSL ? s->hashf->H(s->hctx, s->pk_seed, adrs, auth, node, node, n)
                                  : H_LL(s, adrs, auth, node, node);
        }
        if (!ok) return 0;
    }
    memcpy(root_out, node, n);
    return 1;
}

typedef struct { slh_t *s; const uint8_t *in; uint8_t *out; int wots; } layer_task_t;
static int layer_task(void *ctx, int layer)
{
    layer_task_t *t = ctx;
    slh_t *s = t->s;
    const uint8_t *msg = t->in + (size_t)layer * s->n; /* wots: layer messages; auth: wots pks */
    return t->wots ? wots_layer(s, X_LL, (size_t)layer, msg, t->out + (size_t)layer * s->n)
                   : auth_layer(s, X_LL, (size_t)layer, msg, t->out + (size_t)layer * s->n);
}

/* all layers; for ht_wots `in` = layer messages (pk_fors, root_0, ..., root_{d-2}) */
static int slh_all_layers(slh_t *s, int method, int wots, const uint8_t *in, uint8_t *out)
{
    if (method == X_THREADS) {
        layer_task_t t = { s, in, out, wots };
        return run_tasks(layer_task, &t, (int)s->d);
    }
    for (size_t i = 0; i < s->d; i++) {
        int ok = wots ? wots_layer(s, method, i, in + i * s->n, out + i * s->n)
                      : auth_layer(s, method, i, in + i * s->n, out + i * s->n);
        if (!ok) return 0;
    }
    return 1;
}

/* ============================================================ wrapper */

struct stage_ctx {
    int mldsa;
    mld_t *m;
    slh_t *s;
    uint8_t *mprime;
    size_t mprime_len;
    char sha0[MAX_STAGES][65];
    uint8_t layer_msgs0[32 * 32];  /* SLH: pk_fors || roots0[0..d-2] */
};

static uint8_t *encode_mprime(const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len, size_t *len)
{
    uint8_t *m = malloc(2 + ctx_len + msg_len);
    m[0] = 0;
    m[1] = (uint8_t)ctx_len;
    memcpy(m + 2, ctx, ctx_len);
    memcpy(m + 2 + ctx_len, msg, msg_len);
    *len = 2 + ctx_len + msg_len;
    return m;
}

stage_ctx_t *stage_ctx_new(const param_t *p, const uint8_t *pk, size_t pk_len,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sig, size_t sig_len)
{
    if (ctx_len > 255)
        return NULL;
    stage_ctx_t *s = calloc(1, sizeof(*s));
    s->mldsa = p->is_mldsa;
    s->mprime = encode_mprime(msg, msg_len, ctx, ctx_len, &s->mprime_len);
    if (s->mldsa)
        s->m = mld_new(p, pk, pk_len, sig, sig_len, s->mprime, s->mprime_len);
    else
        s->s = slh_new(p, pk, pk_len, sig, sig_len, s->mprime, s->mprime_len);
    if (s->m == NULL && s->s == NULL) {
        free(s->mprime);
        free(s);
        return NULL;
    }
    return s;
}

void stage_ctx_free(stage_ctx_t *s)
{
    if (s == NULL) return;
    mld_free(s->m);
    slh_free(s->s);
    free(s->mprime);
    free(s);
}

int stage_ctx_is_mldsa(const stage_ctx_t *s) { return s->mldsa; }
int stage_ctx_nstages(const stage_ctx_t *s) { return s->mldsa ? 5 : 4; }
const char *stage_ctx_stage_name(const stage_ctx_t *s, int i) { return s->mldsa ? ML_STAGE_NAMES[i] : SLH_STAGE_NAMES[i]; }

static void sha_polys(const POLY *p, size_t n, char sha[65])
{
    uint8_t *buf = malloc(n * 256 * 4), *o = buf;
    for (size_t i = 0; i < n; i++)
        for (int j = 0; j < 256; j++) {
            uint32_t v = p[i].coeff[j];
            *o++ = (uint8_t)v; *o++ = (uint8_t)(v >> 8); *o++ = (uint8_t)(v >> 16); *o++ = (uint8_t)(v >> 24);
        }
    sha256_hex(buf, n * 256 * 4, sha);
    free(buf);
}

/* run stage sidx with method into the scratch outputs; the inputs are the v0 outputs */
static int stage_op(stage_ctx_t *s, int sidx, int method)
{
    if (s->mldsa) {
        mld_t *m = s->m;
        switch (sidx) {
        case 0: return ml_decode(m, method, m->rhot, m->t1t, &m->sigt);
        case 1: return ml_mu(m, method, m->mut);
        case 2: return ml_expandA(m, method, &m->Atm);
        case 3: return ml_w_approx(m, method, &m->sig0, &m->A0m, &m->wtv);
        default: return (m->hint_ok_t = ml_hint_check(m, method, &m->sig0, m->mu0, &m->w0v, m->w1t));
        }
    } else {
        slh_t *t = s->s;
        uint64_t tree; uint32_t leaf;
        switch (sidx) {
        case 0: return slh_hmsg(t, method, t->digestt, &tree, &leaf);
        case 1: return slh_fors(t, method, t->digest0, t->tree0, t->leaf0, t->pkforst);
        case 2: return slh_all_layers(t, method, 1, s->layer_msgs0, t->wotst);
        default: {
            int ok = slh_all_layers(t, method, 0, t->wots0, t->rootst);
            t->auth_ok_t = ok && memcmp(t->rootst + (t->d - 1) * t->n, t->pk_root, t->n) == 0;
            return t->auth_ok_t;
        }
        }
    }
}

static void stage_sha(stage_ctx_t *s, int sidx, char sha[65])
{
    if (s->mldsa) {
        mld_t *m = s->m;
        switch (sidx) {
        case 0: sha256_hex(m->ctt, m->ctl, sha); break;
        case 1: sha256_hex(m->mut, 64, sha); break;
        case 2: sha_polys(m->At, m->k * m->l, sha); break;
        case 3: sha_polys(m->wt, m->k, sha); break;
        default: sha256_hex(m->w1t, m->w1len, sha); break;
        }
    } else {
        slh_t *t = s->s;
        switch (sidx) {
        case 0: sha256_hex(t->digestt, t->m, sha); break;
        case 1: sha256_hex(t->pkforst, t->n, sha); break;
        case 2: sha256_hex(t->wotst, t->d * t->n, sha); break;
        default: sha256_hex(t->rootst, t->d * t->n, sha); break;
        }
    }
}

/* copy scratch outputs of stage sidx into the v0 slots */
static void stage_commit(stage_ctx_t *s, int sidx)
{
    if (s->mldsa) {
        mld_t *m = s->m;
        switch (sidx) {
        case 0:
            memcpy(m->rho0, m->rhot, 32);
            memcpy(m->t10, m->t1t, m->k * sizeof(POLY));
            memcpy(m->z0, m->zt, m->l * sizeof(POLY));
            memcpy(m->h0, m->ht, m->k * sizeof(POLY));
            memcpy(m->ct0, m->ctt, m->ctl);
            break;
        case 1: memcpy(m->mu0, m->mut, 64); break;
        case 2: memcpy(m->A0, m->At, m->k * m->l * sizeof(POLY)); break;
        case 3: memcpy(m->w0, m->wt, m->k * sizeof(POLY)); break;
        default: memcpy(m->w1enc0, m->w1t, m->w1len); break;
        }
    } else {
        slh_t *t = s->s;
        switch (sidx) {
        case 0: memcpy(t->digest0, t->digestt, 64); break;
        case 1:
            memcpy(t->pkfors0, t->pkforst, t->n);
            memcpy(s->layer_msgs0, t->pkfors0, t->n);
            break;
        case 2: memcpy(t->wots0, t->wotst, t->d * t->n); break;
        default:
            memcpy(t->roots0, t->rootst, t->d * t->n);
            memcpy(s->layer_msgs0 + t->n, t->roots0, (t->d - 1) * t->n);
            break;
        }
    }
}

int stage_prepare(stage_ctx_t *s)
{
    int ok;
    if (s->mldsa) {
        ok = 1;
        for (int i = 0; i < 5 && ok; i++) {
            ok = stage_op(s, i, 0);
            if (ok) {
                stage_sha(s, i, s->sha0[i]);
                stage_commit(s, i);
            }
        }
        return ok;
    }
    slh_t *t = s->s;
    ok = stage_op(s, 0, 0);
    if (!ok) return 0;
    stage_sha(s, 0, s->sha0[0]);
    stage_commit(s, 0);
    slh_split(t, t->digest0, &t->tree0, &t->leaf0);
    slh_layer_ids(t, t->tree0, t->leaf0);
    ok = stage_op(s, 1, 0);
    if (!ok) return 0;
    stage_sha(s, 1, s->sha0[1]);
    stage_commit(s, 1);
    /* the hypertree layers are sequential (layer i signs root i-1): walk them
     * with the v0 code to produce every layer's message, WOTS pk and root */
    const uint8_t *node = t->pkfors0;
    for (size_t i = 0; i < t->d; i++) {
        if (!wots_layer(t, X_OSSL, i, node, t->wots0 + i * t->n)
            || !auth_layer(t, X_OSSL, i, t->wots0 + i * t->n, t->roots0 + i * t->n))
            return 0;
        node = t->roots0 + i * t->n;
        if (i + 1 < t->d)
            memcpy(s->layer_msgs0 + (i + 1) * t->n, node, t->n);
    }
    sha256_hex(t->wots0, t->d * t->n, s->sha0[2]);
    sha256_hex(t->roots0, t->d * t->n, s->sha0[3]);
    return memcmp(node, t->pk_root, t->n) == 0;
}

int stage_exec(stage_ctx_t *s, int sidx, int method)
{
    return stage_op(s, sidx, method);
}

int stage_run(stage_ctx_t *s, int sidx, int method, char sha[65])
{
    int ok = stage_op(s, sidx, method);
    stage_sha(s, sidx, sha);
    if (ok && s->mldsa && sidx == 0) {
        /* decode: besides c~, the alternative must reproduce z and h exactly */
        mld_t *m = s->m;
        if (memcmp(m->zt, m->z0, m->l * sizeof(POLY)) != 0 || memcmp(m->ht, m->h0, m->k * sizeof(POLY)) != 0
            || memcmp(m->t1t, m->t10, m->k * sizeof(POLY)) != 0 || memcmp(m->rhot, m->rho0, 32) != 0)
            ok = 0;
    }
    return ok;
}

int stage_pipeline(stage_ctx_t *s, const int *methods)
{
    if (s->mldsa) {
        mld_t *m = s->m;
        if (!ml_decode(m, methods[0], m->rhot, m->t1t, &m->sigt))
            return 0;
        if (!ml_mu(m, methods[1], m->mut))
            return 0;
        if (!ml_expandA(m, methods[2], &m->Atm))
            return 0;
        if (!ml_w_approx(m, methods[3], &m->sigt, &m->Atm, &m->wtv))
            return 0;
        return ml_hint_check(m, methods[4], &m->sigt, m->mut, &m->wtv, m->w1t);
    } else {
        slh_t *t = s->s;
        uint64_t tree; uint32_t leaf;
        uint8_t node[32];
        int mw = methods[2] == X_THREADS ? X_LL : methods[2];
        int ma = methods[3] == X_THREADS ? X_LL : methods[3];
        if (!slh_hmsg(t, methods[0], t->digestt, &tree, &leaf))
            return 0;
        slh_layer_ids(t, tree, leaf);
        if (!slh_fors(t, methods[1], t->digestt, tree, leaf, node))
            return 0;
        for (size_t i = 0; i < t->d; i++) {
            uint8_t wpk[32];
            if (!wots_layer(t, mw, i, node, wpk) || !auth_layer(t, ma, i, wpk, node))
                return 0;
        }
        return memcmp(node, t->pk_root, t->n) == 0;
    }
}

/* =========================================================== stages cmd */

typedef struct { stage_ctx_t *s; int sidx, method; } stage_cb_t;
static int stage_cb(void *a)
{
    stage_cb_t *c = a;
    return stage_op(c->s, c->sidx, c->method);
}
typedef struct { stage_ctx_t *s; const int *methods; } pipe_cb_t;
static int pipe_cb(void *a)
{
    pipe_cb_t *c = a;
    return stage_pipeline(c->s, c->methods);
}

static int pipeline_check(stage_ctx_t *s, const int *methods, const param_t *p)
{
    /* must accept the reference signature and reject a one-bit-flipped copy */
    if (stage_pipeline(s, methods) != 1)
        return 0;
    uint8_t *t = malloc(p->sig_len);
    memcpy(t, p->sig, p->sig_len);
    t[p->sig_len / 2] ^= 1;
    stage_ctx_t *s2 = stage_ctx_new(p, p->pk, p->pk_len, p->msg, p->msg_len, p->ctx, p->ctx_len, t, p->sig_len);
    int rej = s2 != NULL && stage_prepare(s2) == 0 && stage_pipeline(s2, methods) == 0;
    stage_ctx_free(s2);
    free(t);
    return rej;
}

int cmd_stages(vectors_t *V, const char *out_path, int budget_ms, const char *params, const char *stages_sel)
{
    FILE *out = fopen(out_path, "a");
    if (out == NULL)
        die("cannot open %s", out_path);
    int bad = 0;
    for (int pi = 0; pi < V->nparams; pi++) {
        param_t *p = &V->params[pi];
        if (!list_has(params, p->name))
            continue;
        if (!prepare_param(V, p, 1))
            bad++;
        stage_ctx_t *s = stage_ctx_new(p, p->pk, p->pk_len, p->msg, p->msg_len, p->ctx, p->ctx_len, p->sig, p->sig_len);
        if (s == NULL || !stage_prepare(s)) {
            fprintf(stderr, "%s: stage preparation failed\n", p->name);
            bad++;
            stage_ctx_free(s);
            continue;
        }
        int ns = stage_ctx_nstages(s);
        const char *family = p->is_mldsa ? "ml-dsa" : "slh-dsa";
        int is_sha2 = !p->is_mldsa && strstr(p->name, "SHA2") != NULL;
        for (int si = 0; si < ns; si++) {
            const char *sname = stage_ctx_stage_name(s, si);
            if (!list_has(stages_sel, sname))
                continue;
            for (size_t vi = 0; vi < NSTAGE_VARIANTS; vi++) {
                const stage_variant_t *v = &STAGE_VARIANTS[vi];
                if (v->mldsa != p->is_mldsa || v->sidx != si || strcmp(v->build, BUILD_LABEL) != 0)
                    continue;
                if ((v->flags & SF_SHA2ONLY) && !is_sha2)
                    continue;
                char id[64], sha[65] = "";
                snprintf(id, sizeof(id), "%s.v%d", sname, v->vidx);
                fprintf(stderr, "[%s] %s %s ...", BUILD_LABEL, id, p->name);
                int ok = stage_run(s, si, v->method, sha);
                int match = ok && strcmp(sha, s->sha0[si]) == 0;
                bench_stats_t st = { 0 };
                stage_cb_t cb = { s, si, v->method };
                int lok = 1;
                bench_loop(&st, budget_ms, stage_cb, &cb, &lok);
                char sha2[65];
                if (!stage_run(s, si, v->method, sha2) || strcmp(sha2, s->sha0[si]) != 0)
                    match = 0;
                if (!lok) match = 0;
                line_meta_t m = { "stage", id, v->name, v->desc, NULL, sname, family, p->name,
                                  (v->flags & SF_THREADS) ? NTHREADS : 1, sha, NULL,
                                  match ? NULL : (ok ? "canonical output differs from v0" : "stage failed"), match };
                emit_line(out, &m, &st);
                free(st.samples);
                fprintf(stderr, " %s\n", match ? "ok" : "MISMATCH");
            }
        }
        if (strcmp(BUILD_LABEL, "default") == 0 && list_has(stages_sel, "total")) {
            int v0[MAX_STAGES] = { 0, 0, 0, 0, 0 };
            const int *best = p->is_mldsa ? BEST_ML : BEST_SLH;
            const int *sel[2] = { v0, best };
            const char *ids[2] = { "total", "total_best" };
            for (int t = 0; t < 2; t++) {
                char desc[512];
                desc[0] = 0;
                strcat(desc, t == 0 ? "End-to-end verify assembled from the v0 (OpenSSL code) stages: "
                                    : "End-to-end verify assembled from the fastest stateless single-threaded stage alternatives: ");
                for (int si = 0; si < ns; si++) {
                    const stage_variant_t *sv = NULL;
                    for (size_t vi = 0; vi < NSTAGE_VARIANTS; vi++)
                        if (STAGE_VARIANTS[vi].mldsa == p->is_mldsa && STAGE_VARIANTS[vi].sidx == si
                            && STAGE_VARIANTS[vi].method == sel[t][si] && strcmp(STAGE_VARIANTS[vi].build, "default") == 0
                            && !(STAGE_VARIANTS[vi].flags & SF_SHA2ONLY)) { sv = &STAGE_VARIANTS[vi]; break; }
                    char piece[64];
                    snprintf(piece, sizeof(piece), "%s%s.v%d", si ? ", " : "", stage_ctx_stage_name(s, si), sv ? sv->vidx : 0);
                    strcat(desc, piece);
                }
                fprintf(stderr, "[%s] %s %s ...", BUILD_LABEL, ids[t], p->name);
                int match = pipeline_check(s, sel[t], p);
                bench_stats_t st = { 0 };
                pipe_cb_t cb = { s, sel[t] };
                int lok = 1;
                bench_loop(&st, budget_ms, pipe_cb, &cb, &lok);
                if (!lok) match = 0;
                line_meta_t m = { "stage", ids[t], t == 0 ? "v0-pipeline" : "best-pipeline", desc, NULL, ids[t], family, p->name,
                                  1, match ? "true" : "false", NULL, match ? NULL : "pipeline verify failed", match };
                emit_line(out, &m, &st);
                free(st.samples);
                fprintf(stderr, " %s\n", match ? "ok" : "FAIL");
            }
        }
        stage_ctx_free(s);
    }
    fclose(out);
    return bad ? 1 : 0;
}
