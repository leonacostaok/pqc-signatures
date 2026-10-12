#define _POSIX_C_SOURCE 200809L
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

typedef struct { unsigned char *p; size_t n; } bytes;
typedef struct { char *alg; bytes seed, sk, pk, msg, ctx, sig; } input;
static void die(const char *s) { fprintf(stderr, "%s\n", s); ERR_print_errors_fp(stderr); exit(2); }
static char *line(FILE *f)
{
    char *s = NULL; size_t cap = 0; ssize_t n = getline(&s, &cap, f);
    if (n < 0) die("missing input line");
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = 0;
    return s;
}
static bytes hexline(FILE *f)
{
    char *s = line(f); size_t len = strlen(s); bytes b = {malloc(len / 2 + 1), len / 2};
    if (b.p == NULL || len % 2) die("bad hex input");
    for (size_t i = 0; i < b.n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) die("bad hex byte");
        b.p[i] = (unsigned char)v;
    }
    free(s); return b;
}
static EVP_PKEY *import_key(const input *in, int pub)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, in->alg, NULL);
    bytes b = pub ? in->pk : in->sk;
    OSSL_PARAM p[] = {OSSL_PARAM_construct_octet_string(pub ? OSSL_PKEY_PARAM_PUB_KEY : OSSL_PKEY_PARAM_PRIV_KEY, b.p, b.n), OSSL_PARAM_construct_end()};
    if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0)
        EVP_PKEY_fromdata(ctx, &key, pub ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, p);
    EVP_PKEY_CTX_free(ctx); return key;
}
static EVP_PKEY *keygen(const input *in)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, in->alg, NULL);
    OSSL_PARAM p[] = {OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, in->seed.p, in->seed.n), OSSL_PARAM_construct_end()};
    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_CTX_set_params(ctx, p) > 0)
        EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx); return key;
}
static int operation(const input *in, EVP_PKEY *key, int verify, unsigned char *sig, size_t *len)
{
    int deterministic = 1, result = 0;
    OSSL_PARAM p[] = {OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic), OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, in->ctx.p, in->ctx.n), OSSL_PARAM_construct_end()};
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx != NULL) {
        if (verify) {
            if (EVP_PKEY_verify_message_init(ctx, NULL, p + 1) > 0)
                result = EVP_PKEY_verify(ctx, in->sig.p, in->sig.n, in->msg.p, in->msg.n);
        } else if (EVP_PKEY_sign_message_init(ctx, NULL, p) > 0) {
            *len = 50000;
            result = EVP_PKEY_sign(ctx, sig, len, in->msg.p, in->msg.n);
        }
    }
    EVP_PKEY_CTX_free(ctx); return result;
}
static uint64_t now(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) die("clock"); return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec; }
static void printhex(const unsigned char *p, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", p[i]); }
int main(int argc, char **argv)
{
    if (argc < 3) die("usage: driver keygen|sign|verify input [iterations]");
    FILE *f = fopen(argv[2], "r"); if (!f) die("open input");
    input in = {0}; in.alg = line(f); in.seed = hexline(f); in.sk = hexline(f); in.pk = hexline(f); in.msg = hexline(f); in.ctx = hexline(f); in.sig = hexline(f); fclose(f);
    int gen = strcmp(argv[1], "keygen") == 0, verify = strcmp(argv[1], "verify") == 0;
    if (!gen && !verify && strcmp(argv[1], "sign")) die("bad operation");
    size_t iterations = argc > 3 ? strtoull(argv[3], NULL, 10) : 1;
    if (!iterations) die("zero iterations");
    EVP_PKEY *key = gen ? NULL : import_key(&in, verify);
    unsigned char sig[50000], pk[128], sk[256]; size_t len = 0, pklen = 0, sklen = 0;
    int result = 0;
    /* Benchmarks use valid inputs only. One full warmup is outside the timer. */
    if (argc > 3) {
        if (gen) { EVP_PKEY *warm = keygen(&in); if (!warm) die("warmup keygen"); EVP_PKEY_free(warm); }
        else if (!key || operation(&in, key, verify, sig, &len) != 1) die("warmup operation");
    }
    struct rusage cpu_start, cpu_end;
    if (getrusage(RUSAGE_SELF, &cpu_start)) die("cpu clock");
    uint64_t start = now();
    for (size_t i = 0; i < iterations; i++) {
        if (gen) { EVP_PKEY_free(key); key = keygen(&in); result = key != NULL; }
        else result = key ? operation(&in, key, verify, sig, &len) : 0;
        if (argc > 3 && result != 1) die("benchmark operation failed");
    }
    uint64_t elapsed = now() - start;
    if (getrusage(RUSAGE_SELF, &cpu_end)) die("cpu clock");
    int64_t cpu_ns = ((int64_t)cpu_end.ru_utime.tv_sec - cpu_start.ru_utime.tv_sec
        + (int64_t)cpu_end.ru_stime.tv_sec - cpu_start.ru_stime.tv_sec) * 1000000000
        + ((int64_t)cpu_end.ru_utime.tv_usec - cpu_start.ru_utime.tv_usec
        + (int64_t)cpu_end.ru_stime.tv_usec - cpu_start.ru_stime.tv_usec) * 1000;
    if (gen && result) {
        if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pk, sizeof(pk), &pklen)
            || !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, sk, sizeof(sk), &sklen)) die("export key");
    }
    if (!gen && !verify && result == 1) {
        input check = in; check.sig.p = sig; check.sig.n = len;
        if (operation(&check, key, 1, sig, &len) != 1) die("signed output does not verify");
    }
    printf("{\"ok\":%s,\"iterations\":%zu,\"elapsed_ns\":%llu,\"cpu_ns\":%lld", result == 1 ? "true" : "false", iterations, (unsigned long long)elapsed, (long long)cpu_ns);
    if (argc == 3 && result == 1) {
        if (gen) { printf(",\"pk_hex\":\""); printhex(pk, pklen); printf("\",\"sk_hex\":\""); printhex(sk, sklen); printf("\""); }
        else if (!verify) { printf(",\"sig_hex\":\""); printhex(sig, len); printf("\""); }
    }
    puts("}");
    EVP_PKEY_free(key); free(in.alg); free(in.seed.p); free(in.sk.p); free(in.pk.p); free(in.msg.p); free(in.ctx.p); free(in.sig.p);
    return 0;
}
