/* Shared declarations for the OpenSSL pqc-signatures driver (phase 1 + phase 2). */
#ifndef PQC_COMMON_H
#define PQC_COMMON_H
#define _GNU_SOURCE
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>

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

/* ---- utils (pqc_driver.c) */
void die(const char *fmt, ...);
uint64_t now_ns(void);
uint64_t cpu_ns(void);
char *read_file(const char *path, size_t *len);
uint8_t *hex2bin(const char *hex, size_t *outlen);
char *bin2hex(const uint8_t *b, size_t n);
void sha256_hex(const uint8_t *data, size_t len, char out[65]);
void json_escape(FILE *f, const char *s);
int list_has(const char *list, const char *item);

/* ---- mini JSON (pqc_driver.c) */
const char *json_find(const char *s, const char *end, const char *key);
char *json_get_string(const char *s, const char *end, const char *key);
int json_get_bool(const char *s, const char *end, const char *key, int dflt);
const char *json_match_close(const char *p, const char *end);
typedef struct { const char *p, *aend; } json_iter_t;
int json_iter_init(json_iter_t *it, const char *arr, const char *end);
int json_iter_next(json_iter_t *it, const char **ostart, const char **oend);

/* ---- vectors / params */
typedef struct {
    char *name;      /* "ML-DSA-44" */
    int is_mldsa;
    uint8_t *seed;
    size_t seed_len;
    char *ref_pk, *ref_sk, *ref_sig;   /* reference digests (NULL if none) */
    EVP_PKEY *key;   /* key pair (seeded keygen or imported sk) */
    EVP_PKEY *pub;   /* public-only key imported from pk bytes */
    uint8_t *pk, *sk, *sig;
    size_t pk_len, sk_len, sig_len;
    const uint8_t *msg; size_t msg_len;   /* message to sign/verify */
    const uint8_t *ctx; size_t ctx_len;   /* context string (<= 255) */
} param_t;

typedef struct {
    uint8_t *msg;
    size_t msg_len;
    param_t params[MAX_PARAMS];
    int nparams;
} vectors_t;

void load_vectors(vectors_t *V, const char *path);
void load_reference(vectors_t *V, const char *path);
int prepare_param(vectors_t *V, param_t *p, int verbose);
param_t *find_param(vectors_t *V, const char *name);

/* ---- crypto helpers */
EVP_PKEY *keygen_from_seed(OSSL_LIB_CTX *libctx, const char *propq, const char *alg,
                           const uint8_t *seed, size_t seed_len);
EVP_PKEY *pubkey_from_bytes(const char *alg, const uint8_t *pk, size_t pk_len);
EVP_PKEY *privkey_from_bytes(const char *alg, const uint8_t *sk, size_t sk_len);
int get_octets(EVP_PKEY *key, const char *name, uint8_t *out, size_t cap, size_t *len);
int build_sig_params(OSSL_PARAM out[4], const param_t *p, int deterministic, int mu);
int sign_baseline(EVP_PKEY *key, const param_t *p, uint8_t *sig, size_t *sig_len, size_t cap);
int verify_baseline(EVP_PKEY *pub, const param_t *p, const uint8_t *sig, size_t sig_len);

/* ---- variants / workers */
enum { OP_KEYGEN, OP_SIGN, OP_VERIFY };
enum { IMPL_BASE, IMPL_REUSE, IMPL_FROMDATA, IMPL_DUP, IMPL_MU, IMPL_THREADS };
extern const char *op_names[];

typedef struct {
    const char *id, *name, *desc, *build;
    int op, impl, threads, mldsa_only;
} variant_t;
extern const variant_t VARIANTS[];
extern const size_t NVARIANTS;

typedef struct {
    const variant_t *v;
    param_t *p;
    int impl;
    EVP_KEYMGMT *km;
    EVP_SIGNATURE *sigalg;
    EVP_PKEY_CTX *ctx;
    EVP_MD *shake;
    EVP_MD_CTX *mdctx;
    uint8_t tr[64];
    uint8_t *out;
    size_t out_len, out_cap;
    int ok;
} worker_t;

int worker_init(worker_t *w, const variant_t *v, param_t *p, int impl);
void worker_free(worker_t *w);
int worker_op(worker_t *w);
int op_verify_sig(worker_t *w, const uint8_t *sig, size_t sig_len);
int worker_check_reference(worker_t *w, char out_sha[65], char sk_sha[65]);

/* ---- generic timing loop + JSON line emission */
typedef struct {
    uint64_t *samples;
    size_t n;
    uint64_t wall_total, cpu_total;
    int batch;          /* ops per sample */
} bench_stats_t;

/* runs op() until budget; op returns 0 on failure (sets *ok = 0) */
void bench_loop(bench_stats_t *st, int budget_ms, int (*op)(void *), void *arg, int *ok);

typedef struct {
    const char *kind;        /* "op" (phase 1) or "stage" */
    const char *variant, *variant_name, *variant_desc;
    const char *op, *stage, *family, *param;
    int threads;
    const char *output_sha256, *sk_sha256, *error;
    int match;
} line_meta_t;
void emit_line(FILE *out, const line_meta_t *m, const bench_stats_t *st);

/* ---- phase 2 entry points */
int cmd_stages(vectors_t *V, const char *out_path, int budget_ms, const char *params, const char *stages);
int cmd_validate(vectors_t *V, const char *suite_path, const char *out_path);
int cmd_memory(vectors_t *V, const char *out_path, const char *params);
int cmd_merge_validate(int argc, char **argv);
void mem_hooks_install(void);

#endif
