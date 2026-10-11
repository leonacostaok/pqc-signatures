/*
 * pqc_driver.c - OpenSSL 3.5+ ML-DSA / SLH-DSA benchmark driver for the
 * pqc-signatures harness (see common/CONTRACT.md).
 *
 * One binary is produced per OpenSSL build flavour (default / noasm / native);
 * the flavour is baked in with -DBUILD_LABEL="...". Every variant whose build
 * field differs from BUILD_LABEL is skipped by this binary, so libs/openssl/run.sh
 * simply invokes every binary with the same arguments.
 *
 * Subcommands:
 *   vectors     <vectors.json> <reference.json> <out.json>
 *   crossverify <vectors.json> <artifacts.json> <out.json>
 *   bench       <vectors.json> <reference.json> --out <f.jsonl> [--budget-ms N]
 *               [--params a,b] [--ops keygen,sign,verify] [--variants id,id]
 *   list        (prints the variant table)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#ifndef BUILD_LABEL
#define BUILD_LABEL "default"
#endif
#ifndef DRIVER_CFLAGS
#define DRIVER_CFLAGS ""
#endif

#define LIB_NAME "openssl"
#define MAX_PARAMS 32
#define MAX_SAMPLES 100000
#define NTHREADS 4

/* ------------------------------------------------------------------ utils */

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "pqc_driver: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t cpu_ns(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ((uint64_t)ru.ru_utime.tv_sec + (uint64_t)ru.ru_stime.tv_sec) * 1000000000ull
        + ((uint64_t)ru.ru_utime.tv_usec + (uint64_t)ru.ru_stime.tv_usec) * 1000ull;
}

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        die("cannot open %s: %s", path, strerror(errno));
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n)
        die("cannot read %s", path);
    buf[n] = 0;
    fclose(f);
    if (len)
        *len = (size_t)n;
    return buf;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *hex2bin(const char *hex, size_t *outlen)
{
    size_t n = strlen(hex);
    if (n % 2)
        die("odd hex length");
    uint8_t *out = malloc(n / 2 + 1);
    for (size_t i = 0; i < n / 2; i++) {
        int a = hexval(hex[2 * i]), b = hexval(hex[2 * i + 1]);
        if (a < 0 || b < 0)
            die("bad hex");
        out[i] = (uint8_t)(a * 16 + b);
    }
    *outlen = n / 2;
    return out;
}

static char *bin2hex(const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    char *s = malloc(2 * n + 1);
    for (size_t i = 0; i < n; i++) {
        s[2 * i] = d[b[i] >> 4];
        s[2 * i + 1] = d[b[i] & 15];
    }
    s[2 * n] = 0;
    return s;
}

static void sha256_hex(const uint8_t *data, size_t len, char out[65])
{
    uint8_t md[32];
    unsigned int mdlen = 32;
    if (!EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL))
        die("EVP_Digest failed");
    char *h = bin2hex(md, 32);
    memcpy(out, h, 65);
    free(h);
}

/* ------------------------------------------------------------ mini JSON */
/* Enough for the flat, well-formed files of this project. */

static const char *skip_ws(const char *p, const char *end)
{
    while (p < end && isspace((unsigned char)*p))
        p++;
    return p;
}

/* find the value of "key" inside [s,end); returns pointer at value start or NULL */
static const char *json_find(const char *s, const char *end, const char *key)
{
    size_t kl = strlen(key);
    const char *p = s;
    while (p < end) {
        const char *q = memmem(p, (size_t)(end - p), key, kl);
        if (q == NULL)
            return NULL;
        if (q > s && q[-1] == '"' && q + kl < end && q[kl] == '"') {
            const char *v = skip_ws(q + kl + 1, end);
            if (v < end && *v == ':')
                return skip_ws(v + 1, end);
        }
        p = q + 1;
    }
    return NULL;
}

static char *json_get_string(const char *s, const char *end, const char *key)
{
    const char *v = json_find(s, end, key);
    if (v == NULL || *v != '"')
        return NULL;
    v++;
    const char *e = memchr(v, '"', (size_t)(end - v));
    if (e == NULL)
        return NULL;
    char *out = malloc((size_t)(e - v) + 1);
    memcpy(out, v, (size_t)(e - v));
    out[e - v] = 0;
    return out;
}

static int json_get_bool(const char *s, const char *end, const char *key, int dflt)
{
    const char *v = json_find(s, end, key);
    if (v == NULL)
        return dflt;
    if (strncmp(v, "true", 4) == 0)
        return 1;
    if (strncmp(v, "false", 5) == 0)
        return 0;
    return dflt;
}

/* given p at '{' or '[', return pointer just past the matching close */
static const char *json_match_close(const char *p, const char *end)
{
    int depth = 0, instr = 0;
    for (; p < end; p++) {
        char c = *p;
        if (instr) {
            if (c == '\\') p++;
            else if (c == '"') instr = 0;
            continue;
        }
        if (c == '"') instr = 1;
        else if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') {
            depth--;
            if (depth == 0)
                return p + 1;
        }
    }
    return NULL;
}

/* iterate objects in the array that starts at arr ('['); *it = NULL to start */
static int json_next_object(const char *arr, const char *end, const char **it,
                            const char **ostart, const char **oend)
{
    const char *p = (*it == NULL) ? arr + 1 : *it;
    const char *aend = json_match_close(arr, end);
    if (aend == NULL)
        return 0;
    while (p < aend) {
        if (*p == '{') {
            const char *e = json_match_close(p, aend);
            if (e == NULL)
                return 0;
            *ostart = p;
            *oend = e;
            *it = e;
            return 1;
        }
        p++;
    }
    return 0;
}

/* ------------------------------------------------------------- vectors */

typedef struct {
    char *name;      /* "ML-DSA-44" */
    int is_mldsa;
    uint8_t *seed;
    size_t seed_len;
    /* reference digests (may be NULL if no reference file) */
    char *ref_pk, *ref_sk, *ref_sig;
    /* material computed by the baseline path (filled by prepare_param) */
    EVP_PKEY *key;   /* key pair generated from the seed */
    EVP_PKEY *pub;   /* public-only key imported from pk bytes */
    uint8_t *pk, *sk, *sig;
    size_t pk_len, sk_len, sig_len;
} param_t;

typedef struct {
    uint8_t *msg;
    size_t msg_len;
    param_t params[MAX_PARAMS];
    int nparams;
} vectors_t;

static void load_vectors(vectors_t *V, const char *path)
{
    size_t n;
    char *buf = read_file(path, &n);
    const char *end = buf + n;
    char *mh = json_get_string(buf, end, "message_hex");
    if (mh == NULL)
        die("vectors: no message_hex");
    V->msg = hex2bin(mh, &V->msg_len);
    free(mh);
    const char *arr = json_find(buf, end, "params");
    if (arr == NULL || *arr != '[')
        die("vectors: no params array");
    const char *it = NULL, *os, *oe;
    V->nparams = 0;
    while (json_next_object(arr, end, &it, &os, &oe)) {
        char *name = json_get_string(os, oe, "name");
        char *fam = json_get_string(os, oe, "family");
        char *seed = json_get_string(os, oe, "seed_hex");
        if (name == NULL || fam == NULL || seed == NULL)
            die("vectors: bad param entry");
        if (strcmp(fam, "ml-dsa") == 0 || strcmp(fam, "slh-dsa") == 0) {
            if (V->nparams >= MAX_PARAMS)
                die("too many params");
            param_t *p = &V->params[V->nparams++];
            memset(p, 0, sizeof(*p));
            p->name = name;
            p->is_mldsa = strcmp(fam, "ml-dsa") == 0;
            p->seed = hex2bin(seed, &p->seed_len);
        } else {
            free(name); /* Falcon etc: unsupported by OpenSSL, skipped */
        }
        free(fam);
        free(seed);
    }
    free(buf);
}

static void load_reference(vectors_t *V, const char *path)
{
    size_t n;
    char *buf = read_file(path, &n);
    const char *end = buf + n;
    for (int i = 0; i < V->nparams; i++) {
        param_t *p = &V->params[i];
        const char *v = json_find(buf, end, p->name);
        if (v == NULL || *v != '{')
            die("reference: no entry for %s", p->name);
        const char *e = json_match_close(v, end);
        p->ref_pk = json_get_string(v, e, "pk_sha256");
        p->ref_sk = json_get_string(v, e, "sk_sha256");
        p->ref_sig = json_get_string(v, e, "sig_sha256");
        if (!p->ref_pk || !p->ref_sk || !p->ref_sig)
            die("reference: incomplete entry for %s", p->name);
    }
    free(buf);
}

/* ------------------------------------------------------- crypto helpers */

static EVP_PKEY *keygen_from_seed(OSSL_LIB_CTX *libctx, const char *propq,
                                  const char *alg, const uint8_t *seed, size_t seed_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, alg, propq);
    OSSL_PARAM params[2];
    /* "seed" is both OSSL_PKEY_PARAM_ML_DSA_SEED and OSSL_PKEY_PARAM_SLH_DSA_SEED */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                  (void *)seed, seed_len);
    params[1] = OSSL_PARAM_construct_end();
    if (ctx == NULL
        || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_params(ctx, params) <= 0
        || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int get_octets(EVP_PKEY *key, const char *name, uint8_t *out, size_t cap, size_t *len)
{
    return EVP_PKEY_get_octet_string_param(key, name, out, cap, len) == 1;
}

static EVP_PKEY *pubkey_from_bytes(const char *alg, const uint8_t *pk, size_t pk_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pk, pk_len);
    params[1] = OSSL_PARAM_construct_end();
    if (ctx == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static const OSSL_PARAM *det_params(void)
{
    static OSSL_PARAM p[2];
    static int det = 1;
    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[1] = OSSL_PARAM_construct_end();
    return p;
}

/* baseline sign: fresh ctx, implicit fetch, size query, one-shot sign */
static int sign_baseline(EVP_PKEY *key, const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len, size_t cap)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    size_t need = 0;
    int ok = ctx != NULL
        && EVP_PKEY_sign_message_init(ctx, NULL, det_params()) > 0
        && EVP_PKEY_sign(ctx, NULL, &need, msg, msg_len) > 0
        && need <= cap
        && (*sig_len = cap, EVP_PKEY_sign(ctx, sig, sig_len, msg, msg_len) > 0);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* baseline verify: fresh ctx, implicit fetch, one-shot verify. 1 = valid, 0 = invalid, -1 = error */
static int verify_baseline(EVP_PKEY *pub, const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    int r = -1;
    if (ctx != NULL && EVP_PKEY_verify_message_init(ctx, NULL, NULL) > 0) {
        r = EVP_PKEY_verify(ctx, sig, sig_len, msg, msg_len);
        if (r != 1) {
            r = 0;
            ERR_clear_error();
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return r;
}

/* Generate pk/sk/sig for a param with the baseline path and check the reference */
static int prepare_param(vectors_t *V, param_t *p, int verbose)
{
    uint8_t buf[8192];
    p->key = keygen_from_seed(NULL, NULL, p->name, p->seed, p->seed_len);
    if (p->key == NULL)
        die("keygen failed for %s", p->name);
    if (!get_octets(p->key, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof(buf), &p->pk_len))
        die("get pub failed for %s", p->name);
    p->pk = malloc(p->pk_len);
    memcpy(p->pk, buf, p->pk_len);
    if (!get_octets(p->key, OSSL_PKEY_PARAM_PRIV_KEY, buf, sizeof(buf), &p->sk_len))
        die("get priv failed for %s", p->name);
    p->sk = malloc(p->sk_len);
    memcpy(p->sk, buf, p->sk_len);
    p->pub = pubkey_from_bytes(p->name, p->pk, p->pk_len);
    if (p->pub == NULL)
        die("pub import failed for %s", p->name);
    uint8_t *sig = malloc(65536);
    if (!sign_baseline(p->key, V->msg, V->msg_len, sig, &p->sig_len, 65536))
        die("sign failed for %s", p->name);
    p->sig = sig;
    int ok = 1;
    if (p->ref_pk != NULL) {
        char h[65];
        sha256_hex(p->pk, p->pk_len, h);
        if (strcmp(h, p->ref_pk) != 0) { ok = 0; if (verbose) fprintf(stderr, "%s: pk digest MISMATCH\n", p->name); }
        sha256_hex(p->sk, p->sk_len, h);
        if (strcmp(h, p->ref_sk) != 0) { ok = 0; if (verbose) fprintf(stderr, "%s: sk digest MISMATCH\n", p->name); }
        sha256_hex(p->sig, p->sig_len, h);
        if (strcmp(h, p->ref_sig) != 0) { ok = 0; if (verbose) fprintf(stderr, "%s: sig digest MISMATCH\n", p->name); }
    }
    return ok;
}

/* ------------------------------------------------------------ variants */

enum { OP_KEYGEN, OP_SIGN, OP_VERIFY };
enum { IMPL_BASE, IMPL_REUSE, IMPL_FROMDATA, IMPL_DUP, IMPL_MU, IMPL_THREADS };
static const char *op_names[] = { "keygen", "sign", "verify" };

typedef struct {
    const char *id, *name, *desc, *build;
    int op, impl, threads, mldsa_only;
} variant_t;

static const variant_t VARIANTS[] = {
    { "keygen.v0", "evp-baseline",
      "Default build; per call: EVP_PKEY_CTX_new_from_name (implicit keymgmt fetch), keygen_init, set 'seed' param, EVP_PKEY_keygen, EVP_PKEY_CTX_free.",
      "default", OP_KEYGEN, IMPL_BASE, 1, 0 },
    { "keygen.v1", "prefetch-reuse-ctx",
      "Default build; EVP_KEYMGMT fetched once, one EVP_PKEY_CTX initialised once (keygen_init + seed) and reused: only EVP_PKEY_keygen per call.",
      "default", OP_KEYGEN, IMPL_REUSE, 1, 0 },
    { "keygen.v2", "fromdata-seed-import",
      "Default build; key built by EVP_PKEY_fromdata importing the 32-byte 'seed' into a reused fromdata ctx (ML-DSA only: SLH-DSA keymgmt has no seed import).",
      "default", OP_KEYGEN, IMPL_FROMDATA, 1, 1 },
    { "keygen.v3", "no-asm-build",
      "libcrypto configured with no-asm (pure C Keccak/SHA-2/AES, no CPU feature dispatch); baseline API path.",
      "noasm", OP_KEYGEN, IMPL_BASE, 1, 0 },
    { "keygen.v4", "native-lto-build",
      "libcrypto configured with -O3 -march=native -flto (driver linked with LTO too); baseline API path.",
      "native", OP_KEYGEN, IMPL_BASE, 1, 0 },
    { "keygen.v5", "pthread-x4",
      "Default build; 4 worker threads, each with its own prefetched/reused EVP_PKEY_CTX, throughput measured over a batch.",
      "default", OP_KEYGEN, IMPL_THREADS, NTHREADS, 0 },

    { "sign.v0", "evp-baseline",
      "Default build; per call: EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_sign_message_init(NULL algo => implicit EVP_SIGNATURE fetch, deterministic=1), size query, EVP_PKEY_sign, free.",
      "default", OP_SIGN, IMPL_BASE, 1, 0 },
    { "sign.v1", "prefetch-reuse-ctx",
      "Default build; EVP_SIGNATURE fetched once, ctx initialised once with deterministic=1 and reused: only EVP_PKEY_sign per call, no size query.",
      "default", OP_SIGN, IMPL_REUSE, 1, 0 },
    { "sign.v2", "ctx-dup-template",
      "Default build; an initialised template ctx is EVP_PKEY_CTX_dup'ed per call (fresh ctx per op without fetch/init), then EVP_PKEY_sign + free.",
      "default", OP_SIGN, IMPL_DUP, 1, 0 },
    { "sign.v3", "no-asm-build",
      "libcrypto configured with no-asm (pure C Keccak/SHA-2); baseline API path.",
      "noasm", OP_SIGN, IMPL_BASE, 1, 0 },
    { "sign.v4", "native-lto-build",
      "libcrypto configured with -O3 -march=native -flto; baseline API path.",
      "native", OP_SIGN, IMPL_BASE, 1, 0 },
    { "sign.v5", "pthread-x4",
      "Default build; 4 worker threads, each with its own prefetched/reused sign ctx on the same key, throughput over a batch.",
      "default", OP_SIGN, IMPL_THREADS, NTHREADS, 0 },

    { "verify.v0", "evp-baseline",
      "Default build; per call: EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_verify_message_init(NULL algo => implicit fetch), EVP_PKEY_verify, free.",
      "default", OP_VERIFY, IMPL_BASE, 1, 0 },
    { "verify.v1", "prefetch-reuse-ctx",
      "Default build; EVP_SIGNATURE fetched once, verify ctx initialised once and reused: only EVP_PKEY_verify per call.",
      "default", OP_VERIFY, IMPL_REUSE, 1, 0 },
    { "verify.v2", "external-mu",
      "Default build; mu = SHAKE256(tr || 0x00 || 0x00 || msg) computed by the caller with a cached tr = SHAKE256(pk), then EVP_PKEY_verify with the 'mu'=1 signature param (ML-DSA only).",
      "default", OP_VERIFY, IMPL_MU, 1, 1 },
    { "verify.v3", "no-asm-build",
      "libcrypto configured with no-asm (pure C Keccak/SHA-2); baseline API path.",
      "noasm", OP_VERIFY, IMPL_BASE, 1, 0 },
    { "verify.v4", "native-lto-build",
      "libcrypto configured with -O3 -march=native -flto; baseline API path.",
      "native", OP_VERIFY, IMPL_BASE, 1, 0 },
    { "verify.v5", "pthread-x4",
      "Default build; 4 worker threads, each with its own prefetched/reused verify ctx on the same public key, throughput over a batch.",
      "default", OP_VERIFY, IMPL_THREADS, NTHREADS, 0 },
};
#define NVARIANTS (sizeof(VARIANTS) / sizeof(VARIANTS[0]))

/* --------------------------------------------------------------- worker */

typedef struct {
    const variant_t *v;
    param_t *p;
    const vectors_t *V;
    int impl;                 /* effective implementation for this worker */
    EVP_KEYMGMT *km;
    EVP_SIGNATURE *sigalg;
    EVP_PKEY_CTX *ctx;        /* reused ctx (REUSE / FROMDATA / MU) or template (DUP) */
    EVP_MD *shake;
    EVP_MD_CTX *mdctx;
    uint8_t tr[64];
    uint8_t *out;             /* keygen: pk||sk ; sign: sig ; verify: 1 byte */
    size_t out_len, out_cap;
    int ok;                   /* 0 after any failure */
} worker_t;

static int worker_init(worker_t *w, const variant_t *v, param_t *p, const vectors_t *V, int impl)
{
    memset(w, 0, sizeof(*w));
    w->v = v;
    w->p = p;
    w->V = V;
    w->impl = impl;
    w->ok = 1;
    w->out_cap = 65536 + 8192;
    w->out = malloc(w->out_cap);
    OSSL_PARAM seedp[2];
    seedp[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, p->seed, p->seed_len);
    seedp[1] = OSSL_PARAM_construct_end();

    switch (v->op) {
    case OP_KEYGEN:
        if (impl == IMPL_REUSE) {
            w->km = EVP_KEYMGMT_fetch(NULL, p->name, NULL);
            if (w->km == NULL) return 0;
            w->ctx = EVP_PKEY_CTX_new_from_name(NULL, p->name, NULL);
            if (w->ctx == NULL
                || EVP_PKEY_keygen_init(w->ctx) <= 0
                || EVP_PKEY_CTX_set_params(w->ctx, seedp) <= 0)
                return 0;
        } else if (impl == IMPL_FROMDATA) {
            w->km = EVP_KEYMGMT_fetch(NULL, p->name, NULL);
            w->ctx = EVP_PKEY_CTX_new_from_name(NULL, p->name, NULL);
            if (w->km == NULL || w->ctx == NULL || EVP_PKEY_fromdata_init(w->ctx) <= 0)
                return 0;
        }
        break;
    case OP_SIGN:
        if (impl == IMPL_REUSE || impl == IMPL_DUP) {
            w->sigalg = EVP_SIGNATURE_fetch(NULL, p->name, NULL);
            w->ctx = EVP_PKEY_CTX_new_from_pkey(NULL, p->key, NULL);
            if (w->sigalg == NULL || w->ctx == NULL
                || EVP_PKEY_sign_message_init(w->ctx, w->sigalg, det_params()) <= 0)
                return 0;
        }
        break;
    case OP_VERIFY:
        if (impl == IMPL_REUSE) {
            w->sigalg = EVP_SIGNATURE_fetch(NULL, p->name, NULL);
            w->ctx = EVP_PKEY_CTX_new_from_pkey(NULL, p->pub, NULL);
            if (w->sigalg == NULL || w->ctx == NULL
                || EVP_PKEY_verify_message_init(w->ctx, w->sigalg, NULL) <= 0)
                return 0;
        } else if (impl == IMPL_MU) {
            int mu = 1;
            OSSL_PARAM mup[2];
            mup[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MU, &mu);
            mup[1] = OSSL_PARAM_construct_end();
            w->sigalg = EVP_SIGNATURE_fetch(NULL, p->name, NULL);
            w->ctx = EVP_PKEY_CTX_new_from_pkey(NULL, p->pub, NULL);
            w->shake = EVP_MD_fetch(NULL, "SHAKE256", NULL);
            w->mdctx = EVP_MD_CTX_new();
            if (w->sigalg == NULL || w->ctx == NULL || w->shake == NULL || w->mdctx == NULL
                || EVP_PKEY_verify_message_init(w->ctx, w->sigalg, mup) <= 0)
                return 0;
            /* tr = SHAKE256(pk, 64), FIPS 204 Alg 6 line 9 / Alg 8 line 4 */
            if (!EVP_DigestInit_ex(w->mdctx, w->shake, NULL)
                || !EVP_DigestUpdate(w->mdctx, p->pk, p->pk_len)
                || !EVP_DigestFinalXOF(w->mdctx, w->tr, 64))
                return 0;
        }
        break;
    }
    return 1;
}

static void worker_free(worker_t *w)
{
    EVP_PKEY_CTX_free(w->ctx);
    EVP_KEYMGMT_free(w->km);
    EVP_SIGNATURE_free(w->sigalg);
    EVP_MD_free(w->shake);
    EVP_MD_CTX_free(w->mdctx);
    free(w->out);
}

/* one keygen op: writes pk||sk into w->out */
static int op_keygen(worker_t *w)
{
    param_t *p = w->p;
    EVP_PKEY *key = NULL;
    size_t pkl = 0, skl = 0;
    int ok;
    if (w->impl == IMPL_BASE) {
        key = keygen_from_seed(NULL, NULL, p->name, p->seed, p->seed_len);
    } else if (w->impl == IMPL_REUSE) {
        if (EVP_PKEY_keygen(w->ctx, &key) <= 0)
            key = NULL;
    } else { /* IMPL_FROMDATA */
        OSSL_PARAM seedp[2];
        seedp[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, p->seed, p->seed_len);
        seedp[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_fromdata(w->ctx, &key, EVP_PKEY_KEYPAIR, seedp) <= 0)
            key = NULL;
    }
    ok = key != NULL
        && get_octets(key, OSSL_PKEY_PARAM_PUB_KEY, w->out, w->out_cap, &pkl)
        && get_octets(key, OSSL_PKEY_PARAM_PRIV_KEY, w->out + pkl, w->out_cap - pkl, &skl);
    EVP_PKEY_free(key);
    w->out_len = pkl + skl;
    return ok;
}

static int op_sign(worker_t *w)
{
    param_t *p = w->p;
    const vectors_t *V = w->V;
    int ok;
    w->out_len = w->out_cap;
    if (w->impl == IMPL_BASE) {
        ok = sign_baseline(p->key, V->msg, V->msg_len, w->out, &w->out_len, w->out_cap);
    } else if (w->impl == IMPL_REUSE) {
        ok = EVP_PKEY_sign(w->ctx, w->out, &w->out_len, V->msg, V->msg_len) > 0;
    } else { /* IMPL_DUP */
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_dup(w->ctx);
        ok = c != NULL && EVP_PKEY_sign(c, w->out, &w->out_len, V->msg, V->msg_len) > 0;
        EVP_PKEY_CTX_free(c);
    }
    return ok;
}

/* returns 1 (valid), 0 (invalid) or -1 (error); sig/len allow the tamper check */
static int op_verify_sig(worker_t *w, const uint8_t *sig, size_t sig_len)
{
    param_t *p = w->p;
    const vectors_t *V = w->V;
    int r;
    if (w->impl == IMPL_BASE) {
        r = verify_baseline(p->pub, V->msg, V->msg_len, sig, sig_len);
    } else if (w->impl == IMPL_REUSE) {
        r = EVP_PKEY_verify(w->ctx, sig, sig_len, V->msg, V->msg_len);
    } else { /* IMPL_MU */
        uint8_t mu[64];
        static const uint8_t pre[2] = { 0x00, 0x00 }; /* domain sep 0, ctx len 0 */
        if (!EVP_DigestInit_ex(w->mdctx, w->shake, NULL)
            || !EVP_DigestUpdate(w->mdctx, w->tr, 64)
            || !EVP_DigestUpdate(w->mdctx, pre, 2)
            || !EVP_DigestUpdate(w->mdctx, V->msg, V->msg_len)
            || !EVP_DigestFinalXOF(w->mdctx, mu, 64))
            return -1;
        r = EVP_PKEY_verify(w->ctx, sig, sig_len, mu, 64);
    }
    if (r != 1) {
        ERR_clear_error();
        r = 0;
    }
    return r;
}

static int op_verify(worker_t *w)
{
    int r = op_verify_sig(w, w->p->sig, w->p->sig_len);
    w->out[0] = (uint8_t)(r == 1);
    w->out_len = 1;
    return r == 1;
}

static int worker_op(worker_t *w)
{
    int ok;
    switch (w->v->op) {
    case OP_KEYGEN: ok = op_keygen(w); break;
    case OP_SIGN:   ok = op_sign(w); break;
    default:        ok = op_verify(w); break;
    }
    if (!ok)
        w->ok = 0;
    return ok;
}

/* check worker output against the reference digests; fills out_sha/sk_sha */
static int worker_check_reference(worker_t *w, char out_sha[65], char sk_sha[65])
{
    param_t *p = w->p;
    char h[65];
    sk_sha[0] = 0;
    if (!w->ok)
        return 0;
    switch (w->v->op) {
    case OP_KEYGEN:
        if (w->out_len != p->pk_len + p->sk_len)
            return 0;
        sha256_hex(w->out, p->pk_len, out_sha);
        sha256_hex(w->out + p->pk_len, p->sk_len, sk_sha);
        return strcmp(out_sha, p->ref_pk) == 0 && strcmp(sk_sha, p->ref_sk) == 0;
    case OP_SIGN:
        sha256_hex(w->out, w->out_len, out_sha);
        return strcmp(out_sha, p->ref_sig) == 0;
    default: {
        /* valid sig must verify, a one-bit-flipped sig must be rejected */
        int good = w->out_len == 1 && w->out[0] == 1;
        uint8_t *t = malloc(p->sig_len);
        memcpy(t, p->sig, p->sig_len);
        t[p->sig_len / 2] ^= 0x01;
        int rej = op_verify_sig(w, t, p->sig_len) == 0;
        free(t);
        /* the ctx may be reused afterwards; make sure a good verify still passes */
        int again = op_verify_sig(w, p->sig, p->sig_len) == 1;
        strcpy(out_sha, (good && rej && again) ? "true" : "false");
        (void)h;
        return good && rej && again;
    }
    }
}

/* -------------------------------------------------------- thread batch */

typedef struct {
    worker_t *w;
    int per_thread;
    pthread_barrier_t *start, *end;
    volatile int *stop;
    pthread_t tid;
} thread_arg_t;

static void *thread_main(void *arg)
{
    thread_arg_t *t = arg;
    for (;;) {
        pthread_barrier_wait(t->start);
        if (*t->stop)
            break;
        for (int i = 0; i < t->per_thread; i++)
            worker_op(t->w);
        pthread_barrier_wait(t->end);
    }
    return NULL;
}

/* ---------------------------------------------------------------- bench */

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static void json_escape(FILE *f, const char *s)
{
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fputc('\\', f);
        fputc(*s, f);
    }
}

typedef struct {
    const char *out_path;
    int budget_ms;
    const char *params, *ops, *variants;
} bench_opts_t;

static int list_has(const char *list, const char *item)
{
    if (list == NULL)
        return 1;
    size_t il = strlen(item);
    const char *p = list;
    while (*p) {
        const char *c = strchr(p, ',');
        size_t l = c ? (size_t)(c - p) : strlen(p);
        if (l == il && strncmp(p, item, il) == 0)
            return 1;
        if (!c) break;
        p = c + 1;
    }
    return 0;
}

static void emit_line(FILE *out, const variant_t *v, param_t *p, int threads, int batch,
                      uint64_t *samples, size_t n, uint64_t wall_total, uint64_t cpu_total,
                      const char *out_sha, const char *sk_sha, int match, const char *error)
{
    uint64_t *s = malloc(n * sizeof(*s));
    memcpy(s, samples, n * sizeof(*s));
    qsort(s, n, sizeof(*s), cmp_u64);
    double mean = 0;
    for (size_t i = 0; i < n; i++) mean += (double)s[i];
    mean /= (double)(n ? n : 1);
    uint64_t med = n ? ((n & 1) ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : 0;
    size_t i95 = n ? (size_t)((0.95 * (double)n) + 0.999999) - 1 : 0;
    if (i95 >= n) i95 = n ? n - 1 : 0;
    size_t ops = n * (size_t)batch;
    fprintf(out, "{\"lib\":\"%s\",\"lib_version\":\"%s\",\"lang\":\"c\",\"runtime\":\"",
            LIB_NAME, OPENSSL_VERSION_STR);
    json_escape(out, "OpenSSL " OPENSSL_VERSION_STR " static libcrypto, build=" BUILD_LABEL
                     ", gcc " __VERSION__ " " DRIVER_CFLAGS);
    fprintf(out, "\",\"build\":\"%s\",\"variant\":\"%s\",\"variant_name\":\"%s\",\"variant_desc\":\"",
            BUILD_LABEL, v->id, v->name);
    json_escape(out, v->desc);
    fprintf(out, "\",\"op\":\"%s\",\"param\":\"%s\",\"iterations\":%zu,\"batch_size\":%d,\"threads\":%d,",
            op_names[v->op], p->name, ops, batch, threads);
    fprintf(out, "\"wall_ns_median\":%llu,\"wall_ns_mean\":%.0f,\"wall_ns_p95\":%llu,\"wall_ns_min\":%llu,",
            (unsigned long long)med, mean, (unsigned long long)(n ? s[i95] : 0),
            (unsigned long long)(n ? s[0] : 0));
    double cpu_per_op = ops ? (double)cpu_total / (double)ops : 0;
    double cpu_util = wall_total ? (double)cpu_total / (double)wall_total : 0;
    double ops_per_sec = wall_total ? (double)ops / ((double)wall_total / 1e9) : 0;
    fprintf(out, "\"cpu_ns_per_op\":%.0f,\"cpu_util\":%.4f,\"ops_per_sec\":%.3f,",
            cpu_per_op, cpu_util, ops_per_sec);
    fprintf(out, "\"output_sha256\":\"%s\",", out_sha);
    if (sk_sha && sk_sha[0])
        fprintf(out, "\"sk_sha256\":\"%s\",", sk_sha);
    if (error)
        fprintf(out, "\"error\":\"%s\",", error);
    fprintf(out, "\"match\":%s}\n", match ? "true" : "false");
    fflush(out);
    free(s);
}

static void bench_one(FILE *out, const vectors_t *V, param_t *p, const variant_t *v, int budget_ms)
{
    uint64_t *samples = malloc(MAX_SAMPLES * sizeof(uint64_t));
    size_t n = 0;
    char out_sha[65] = "", sk_sha[65] = "";
    int match = 0;
    const char *error = NULL;
    uint64_t budget = (uint64_t)budget_ms * 1000000ull;

    if (v->impl != IMPL_THREADS) {
        worker_t w;
        if (!worker_init(&w, v, p, (vectors_t *)V, v->impl)) {
            error = "worker init failed";
            ERR_print_errors_fp(stderr);
        } else {
            /* warm-up (not recorded) + first reference check */
            uint64_t t0 = now_ns();
            worker_op(&w);
            uint64_t first_op = now_ns() - t0;
            match = worker_check_reference(&w, out_sha, sk_sha);
            if (!match)
                error = w.ok ? "output does not match reference" : "operation failed";
            uint8_t *expect = malloc(w.out_len);
            size_t expect_len = w.out_len;
            memcpy(expect, w.out, expect_len);
            size_t min_iters = first_op > 5000000000ull ? 2 : 3;
            uint64_t wall_total = 0, cpu0 = cpu_ns(), wall0 = now_ns();
            while (n < MAX_SAMPLES) {
                uint64_t a = now_ns();
                worker_op(&w);
                uint64_t b = now_ns();
                samples[n++] = b - a;
                if (w.out_len != expect_len || memcmp(w.out, expect, expect_len) != 0)
                    match = 0;
                wall_total = b - wall0;
                if (wall_total >= budget && n >= min_iters)
                    break;
            }
            uint64_t cpu_total = cpu_ns() - cpu0;
            if (!w.ok) { match = 0; if (!error) error = "operation failed during loop"; }
            /* re-check the last output against the reference (never hardcoded) */
            if (match) {
                char o2[65], s2[65];
                if (!worker_check_reference(&w, o2, s2))
                    match = 0;
            }
            emit_line(out, v, p, 1, 1, samples, n, wall_total, cpu_total, out_sha, sk_sha, match, error);
            free(expect);
        }
        worker_free(&w);
    } else {
        int T = v->threads;
        worker_t ws[NTHREADS];
        thread_arg_t ta[NTHREADS];
        pthread_barrier_t start, end;
        volatile int stop = 0;
        int ok = 1;
        /* worker threads use the prefetch/reuse path */
        for (int i = 0; i < T; i++)
            if (!worker_init(&ws[i], v, p, (vectors_t *)V, IMPL_REUSE)) ok = 0;
        if (!ok) {
            error = "worker init failed";
            emit_line(out, v, p, T, 1, samples, 0, 0, 0, "", "", 0, error);
        } else {
            /* estimate single-op time to size the batch (~2 ms per thread) */
            uint64_t t0 = now_ns();
            worker_op(&ws[0]);
            uint64_t est = now_ns() - t0;
            match = worker_check_reference(&ws[0], out_sha, sk_sha);
            if (!match)
                error = ws[0].ok ? "output does not match reference" : "operation failed";
            uint8_t *expect = malloc(ws[0].out_len);
            size_t expect_len = ws[0].out_len;
            memcpy(expect, ws[0].out, expect_len);
            int per = (int)(2000000ull / (est ? est : 1));
            if (per < 1) per = 1;
            if (per > 32) per = 32;
            int batch = per * T;
            pthread_barrier_init(&start, NULL, (unsigned)T + 1);
            pthread_barrier_init(&end, NULL, (unsigned)T + 1);
            for (int i = 0; i < T; i++) {
                ta[i].w = &ws[i]; ta[i].per_thread = per; ta[i].start = &start; ta[i].end = &end; ta[i].stop = &stop;
                pthread_create(&ta[i].tid, NULL, thread_main, &ta[i]);
            }
            /* warm-up batch */
            pthread_barrier_wait(&start);
            pthread_barrier_wait(&end);
            size_t min_iters = est > 5000000000ull ? 2 : 3;
            uint64_t wall_total = 0, cpu0 = cpu_ns(), wall0 = now_ns();
            while (n < MAX_SAMPLES) {
                uint64_t a = now_ns();
                pthread_barrier_wait(&start);
                pthread_barrier_wait(&end);
                uint64_t b = now_ns();
                samples[n++] = (b - a) / (uint64_t)batch;
                for (int i = 0; i < T; i++)
                    if (!ws[i].ok || ws[i].out_len != expect_len || memcmp(ws[i].out, expect, expect_len) != 0)
                        match = 0;
                wall_total = b - wall0;
                if (wall_total >= budget && n >= min_iters)
                    break;
            }
            uint64_t cpu_total = cpu_ns() - cpu0;
            stop = 1;
            pthread_barrier_wait(&start);
            for (int i = 0; i < T; i++)
                pthread_join(ta[i].tid, NULL);
            pthread_barrier_destroy(&start);
            pthread_barrier_destroy(&end);
            if (match) {
                for (int i = 0; i < T; i++) {
                    char o2[65], s2[65];
                    if (!worker_check_reference(&ws[i], o2, s2))
                        match = 0;
                }
            }
            if (!match && !error) error = "output mismatch in a worker thread";
            emit_line(out, v, p, T, batch, samples, n, wall_total, cpu_total, out_sha, sk_sha, match, error);
            free(expect);
        }
        for (int i = 0; i < T; i++)
            worker_free(&ws[i]);
    }
    free(samples);
}

static int cmd_bench(vectors_t *V, bench_opts_t *o)
{
    FILE *out = fopen(o->out_path, "a");
    if (out == NULL)
        die("cannot open %s", o->out_path);
    int bad = 0;
    for (int i = 0; i < V->nparams; i++)
        if (list_has(o->params, V->params[i].name) && !prepare_param(V, &V->params[i], 1))
            bad++;
    for (size_t vi = 0; vi < NVARIANTS; vi++) {
        const variant_t *v = &VARIANTS[vi];
        if (strcmp(v->build, BUILD_LABEL) != 0)
            continue;
        if (!list_has(o->ops, op_names[v->op]) || !list_has(o->variants, v->id))
            continue;
        for (int i = 0; i < V->nparams; i++) {
            param_t *p = &V->params[i];
            if (!list_has(o->params, p->name))
                continue;
            if (v->mldsa_only && !p->is_mldsa)
                continue;
            fprintf(stderr, "[%s] %s %s ...", BUILD_LABEL, v->id, p->name);
            uint64_t t0 = now_ns();
            bench_one(out, V, p, v, o->budget_ms);
            fprintf(stderr, " %.2fs\n", (double)(now_ns() - t0) / 1e9);
        }
    }
    fclose(out);
    return bad ? 1 : 0;
}

/* ------------------------------------------------------------- vectors */

static int cmd_vectors(vectors_t *V, const char *out_path)
{
    FILE *out = fopen(out_path, "w");
    if (out == NULL)
        die("cannot open %s", out_path);
    fprintf(out, "{\"lib\":\"%s\",\"lib_version\":\"%s\",\"entries\":[\n", LIB_NAME, OPENSSL_VERSION_STR);
    int bad = 0;
    for (int i = 0; i < V->nparams; i++) {
        param_t *p = &V->params[i];
        int match = prepare_param(V, p, 1);
        int self = verify_baseline(p->pub, V->msg, V->msg_len, p->sig, p->sig_len) == 1;
        char hpk[65], hsk[65], hsig[65];
        sha256_hex(p->pk, p->pk_len, hpk);
        sha256_hex(p->sk, p->sk_len, hsk);
        sha256_hex(p->sig, p->sig_len, hsig);
        char *pkh = bin2hex(p->pk, p->pk_len), *sigh = bin2hex(p->sig, p->sig_len);
        fprintf(out, "%s{\"param\":\"%s\",\"pk_hex\":\"%s\",\"sig_hex\":\"%s\",\"sk_sha256\":\"%s\","
                     "\"pk_sha256\":\"%s\",\"sig_sha256\":\"%s\",\"self_verify\":%s,\"reference_match\":%s}",
                i ? ",\n" : "", p->name, pkh, sigh, hsk, hpk, hsig, self ? "true" : "false",
                match ? "true" : "false");
        free(pkh);
        free(sigh);
        fprintf(stderr, "%-20s pk=%zu sk=%zu sig=%zu self_verify=%d reference_match=%d\n",
                p->name, p->pk_len, p->sk_len, p->sig_len, self, match);
        if (!match || !self)
            bad++;
    }
    fprintf(out, "\n]}\n");
    fclose(out);
    fprintf(stderr, "%d/%d params match the reference\n", V->nparams - bad, V->nparams);
    return bad ? 1 : 0;
}

/* --------------------------------------------------------- crossverify */

static int cmd_crossverify(vectors_t *V, const char *art_path, const char *out_path)
{
    size_t n;
    char *buf = read_file(art_path, &n);
    const char *end = buf + n;
    char *src = json_get_string(buf, end, "lib");
    const char *arr = json_find(buf, end, "entries");
    if (arr == NULL || *arr != '[')
        die("artifacts: no entries array");
    FILE *out = fopen(out_path, "w");
    if (out == NULL)
        die("cannot open %s", out_path);
    fprintf(out, "{\"lib\":\"%s\",\"source\":\"%s\",\"results\":[\n", LIB_NAME, src ? src : "unknown");
    const char *it = NULL, *os, *oe;
    int first = 1, bad = 0, total = 0;
    while (json_next_object(arr, end, &it, &os, &oe)) {
        char *param = json_get_string(os, oe, "param");
        char *pkh = json_get_string(os, oe, "pk_hex");
        char *sigh = json_get_string(os, oe, "sig_hex");
        if (param == NULL)
            continue;
        param_t *p = NULL;
        for (int i = 0; i < V->nparams; i++)
            if (strcmp(V->params[i].name, param) == 0)
                p = &V->params[i];
        if (p == NULL) { /* unsupported (e.g. Falcon): skip */
            fprintf(stderr, "%-20s skipped (unsupported)\n", param);
            free(param); free(pkh); free(sigh);
            continue;
        }
        const char *error = NULL;
        int ok = 0, tamper_rejected = 0;
        if (pkh == NULL || sigh == NULL) {
            error = "missing pk_hex/sig_hex";
        } else {
            size_t pkl, sl;
            uint8_t *pk = hex2bin(pkh, &pkl), *sig = hex2bin(sigh, &sl);
            EVP_PKEY *pub = pubkey_from_bytes(param, pk, pkl);
            if (pub == NULL) {
                error = "public key import failed";
                ERR_clear_error();
            } else {
                int r = verify_baseline(pub, V->msg, V->msg_len, sig, sl);
                ok = r == 1;
                if (r == 0) error = "verify returned 0";
                else if (r < 0) error = "verify error";
                sig[sl / 2] ^= 0x01;
                tamper_rejected = verify_baseline(pub, V->msg, V->msg_len, sig, sl) == 0;
                EVP_PKEY_free(pub);
            }
            free(pk); free(sig);
        }
        fprintf(out, "%s{\"param\":\"%s\",\"ok\":%s,\"error\":%s%s%s,\"tamper_rejected\":%s}",
                first ? "" : ",\n", param, ok ? "true" : "false",
                error ? "\"" : "", error ? error : "null", error ? "\"" : "",
                tamper_rejected ? "true" : "false");
        fprintf(stderr, "%-20s ok=%d tamper_rejected=%d%s%s\n", param, ok, tamper_rejected,
                error ? " error=" : "", error ? error : "");
        first = 0;
        total++;
        if (!ok || !tamper_rejected) bad++;
        free(param); free(pkh); free(sigh);
    }
    fprintf(out, "\n]}\n");
    fclose(out);
    free(src);
    free(buf);
    fprintf(stderr, "crossverify: %d/%d ok\n", total - bad, total);
    return bad ? 1 : 0;
}

/* ----------------------------------------------------------------- main */

static void usage(void)
{
    fprintf(stderr,
        "usage: pqc_driver vectors <vectors.json> <reference.json> <out.json>\n"
        "       pqc_driver crossverify <vectors.json> <artifacts.json> <out.json>\n"
        "       pqc_driver bench <vectors.json> <reference.json> --out f.jsonl [--budget-ms N]\n"
        "                  [--params a,b] [--ops keygen,sign,verify] [--variants id,id]\n"
        "       pqc_driver list\n");
    exit(2);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        usage();
    if (strcmp(argv[1], "list") == 0) {
        for (size_t i = 0; i < NVARIANTS; i++)
            printf("%s\t%s\t%s\t%s\n", VARIANTS[i].id, VARIANTS[i].build, VARIANTS[i].name, VARIANTS[i].desc);
        return 0;
    }
    if (strcmp(argv[1], "version") == 0) {
        printf("%s\n", OPENSSL_VERSION_STR);
        return 0;
    }
    vectors_t V;
    memset(&V, 0, sizeof(V));
    if (strcmp(argv[1], "vectors") == 0) {
        if (argc != 5) usage();
        load_vectors(&V, argv[2]);
        load_reference(&V, argv[3]);
        return cmd_vectors(&V, argv[4]);
    }
    if (strcmp(argv[1], "crossverify") == 0) {
        if (argc != 5) usage();
        load_vectors(&V, argv[2]);
        return cmd_crossverify(&V, argv[3], argv[4]);
    }
    if (strcmp(argv[1], "bench") == 0) {
        if (argc < 4) usage();
        bench_opts_t o = { NULL, 1000, NULL, NULL, NULL };
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) o.out_path = argv[++i];
            else if (strcmp(argv[i], "--budget-ms") == 0 && i + 1 < argc) o.budget_ms = atoi(argv[++i]);
            else if (strcmp(argv[i], "--params") == 0 && i + 1 < argc) o.params = argv[++i];
            else if (strcmp(argv[i], "--ops") == 0 && i + 1 < argc) o.ops = argv[++i];
            else if (strcmp(argv[i], "--variants") == 0 && i + 1 < argc) o.variants = argv[++i];
            else usage();
        }
        if (o.out_path == NULL) usage();
        load_vectors(&V, argv[2]);
        load_reference(&V, argv[3]);
        return cmd_bench(&V, &o);
    }
    usage();
    return 2;
}
