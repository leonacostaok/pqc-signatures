/* Untimed requested-byte accounting for the SLH hash-context lifecycle. */
#include "internal/deprecated.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include "crypto/slh_dsa/slh_dsa_local.h"
#include "crypto/slh_dsa/slh_dsa_key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #c); exit(2); } } while (0)
typedef struct { void *ptr; size_t size; int clear; } allocation;
static allocation slots[64];
static size_t attempts, allocations, requested, live, peak, frees, failures, cleared;
static size_t fail_at;
static int active;
static void *count_malloc(size_t size, const char *file, int line)
{
    void *p;
    (void)file; (void)line;
    if (active && ++attempts == fail_at) { failures++; return NULL; }
    p = malloc(size);
    REQUIRE(p != NULL);
    if (active) {
        size_t i;
        for (i = 0; i < 64 && slots[i].ptr != NULL; ++i) {}
        REQUIRE(i < 64);
        slots[i] = (allocation){p, size, 0};
        allocations++; requested += size; live += size;
        if (live > peak) peak = live;
        memset(p, 0xa5, size);
    }
    return p;
}
static void count_free(void *p, const char *file, int line)
{
    (void)file; (void)line;
    for (size_t i = 0; i < 64; ++i) {
        if (p != NULL && slots[i].ptr == p) {
            if (slots[i].clear) {
                const unsigned char *b = p;
                for (size_t j = 0; j < slots[i].size; ++j) REQUIRE(b[j] == 0);
                cleared++;
            }
            REQUIRE(live >= slots[i].size); live -= slots[i].size; frees++;
            slots[i].ptr = NULL; break;
        }
    }
    free(p);
}
static void *count_realloc(void *p, size_t size, const char *file, int line)
{
    (void)file; (void)line;
    REQUIRE(!active); /* Context allocation paths must not hide reallocations. */
    return realloc(p, size);
}
static void begin(size_t failure)
{
    REQUIRE(!active && live == 0);
    memset(slots, 0, sizeof(slots));
    attempts = allocations = requested = peak = frees = failures = cleared = 0;
    fail_at = failure; active = 1;
}
static void expect_clear(void *p)
{
    if (p == NULL) return;
    for (size_t i = 0; i < 64; ++i) if (slots[i].ptr == p) { slots[i].clear = 1; return; }
    REQUIRE(0);
}
static void mark_context(SLH_DSA_HASH_CTX *ctx)
{
    expect_clear(ctx->shactx); expect_clear(ctx->shactx_pkseed); expect_clear(ctx->scratch);
#ifdef CACHED_SHA512
    expect_clear(ctx->shactx_pkseed_sha512);
#endif
}
static void emit(const char *parameter, const char *action, size_t failure,
    size_t retained, const unsigned char *out, size_t n)
{
    REQUIRE(live == 0 && allocations == frees);
    active = 0;
    printf("{\"parameter\":\"%s\",\"action\":\"%s\",\"fail_at\":%zu,\"attempts\":%zu,\"allocations\":%zu,\"requested_bytes\":%zu,\"peak_live_bytes\":%zu,\"retained_bytes\":%zu,\"net_live_bytes\":%zu,\"frees\":%zu,\"failures\":%zu,\"cleared_allocations\":%zu,\"hash_ctx_size\":%zu,\"sha256_ctx_size\":%zu,\"sha512_ctx_size\":%zu,\"output_hex\":\"", parameter, action, failure, attempts, allocations, requested, peak, retained, live, frees, failures, cleared, sizeof(SLH_DSA_HASH_CTX), sizeof(SHA256_CTX), sizeof(SHA512_CTX));
    for (size_t i = 0; i < n; ++i) printf("%02x", out[i]);
    puts("\"}");
}
static void exercise(SLH_DSA_KEY *key, SLH_DSA_HASH_CTX *ctx, unsigned char *out)
{
    unsigned char address[32], message[128], secret[32];
    size_t n = key->params->n;
    size_t count = allocations;
    for (size_t i = 0; i < sizeof(address); ++i) address[i] = (unsigned char)(i * 3 + 1);
    for (size_t i = 0; i < sizeof(message); ++i) message[i] = (unsigned char)(i * 5 + 7);
    for (size_t i = 0; i < sizeof(secret); ++i) secret[i] = (unsigned char)(i * 7 + 11);
    REQUIRE(key->hash_func->H(ctx, key->pub, address, message, message+n, out, n));
    REQUIRE(key->hash_func->T(ctx, key->pub, address, message, 2*n, out+n, n));
    REQUIRE(memcmp(out, out+n, n) == 0);
    REQUIRE(key->hash_func->PRF(ctx, key->pub, secret, address, out+2*n, n));
    REQUIRE(allocations == count); /* H/T/PRF do not allocate once initialized. */
}
int main(void)
{
    static const char *names[] = {"SLH-DSA-SHA2-128f","SLH-DSA-SHA2-192f","SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128f","SLH-DSA-SHAKE-192f","SLH-DSA-SHAKE-256f"};
    REQUIRE(CRYPTO_set_mem_functions(count_malloc,count_realloc,count_free));
    /* Initialize error-thread bookkeeping before allocation-failure windows. */
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE); ERR_clear_error();
    for (size_t index = 0; index < sizeof(names)/sizeof(names[0]); ++index) {
        SLH_DSA_KEY key = {0}; unsigned char out[96] = {0}, saved[96];
        SLH_DSA_HASH_CTX *ctx, *dup; size_t n, new_count, dup_count, retained;
        key.params = ossl_slh_dsa_params_get(names[index]); REQUIRE(key.params != NULL);
        n = key.params->n; key.pub = key.priv + 2*n;
        key.hash_func = ossl_slh_get_hash_fn(key.params->is_shake,key.params->security_category);
        for (size_t i=0;i<n;++i) key.pub[i]=(unsigned char)(i*11+index);
        begin(0); ctx=ossl_slh_dsa_hash_ctx_new(&key); REQUIRE(ctx != NULL);
        new_count=attempts;retained=live;mark_context(ctx);exercise(&key,ctx,out);
        ossl_slh_dsa_hash_ctx_free(ctx); emit(names[index],"new-use-free",0,retained,out,3*n);
        for (size_t fail=1;fail<=new_count;++fail) {
            begin(fail);ctx=ossl_slh_dsa_hash_ctx_new(&key);REQUIRE(ctx==NULL && failures==1);
            ERR_clear_error();emit(names[index],"new-oom",fail,0,NULL,0);
        }
        ctx=ossl_slh_dsa_hash_ctx_new(&key);REQUIRE(ctx!=NULL);exercise(&key,ctx,saved);
        begin(0);dup=ossl_slh_dsa_hash_ctx_dup(ctx);REQUIRE(dup!=NULL);
        dup_count=attempts;retained=live;mark_context(dup);
        REQUIRE(dup->scratch!=ctx->scratch && dup->shactx_pkseed!=ctx->shactx_pkseed);
#ifdef CACHED_SHA512
        REQUIRE(ctx->shactx_pkseed_sha512==NULL || dup->shactx_pkseed_sha512!=ctx->shactx_pkseed_sha512);
#endif
        ossl_slh_dsa_hash_ctx_free(ctx);exercise(&key,dup,out);REQUIRE(memcmp(saved,out,3*n)==0);
        ossl_slh_dsa_hash_ctx_free(dup);emit(names[index],"dup-use-after-source-free",0,retained,out,3*n);
        ctx=ossl_slh_dsa_hash_ctx_new(&key);REQUIRE(ctx!=NULL);
        for (size_t fail=1;fail<=dup_count;++fail) {
            begin(fail);dup=ossl_slh_dsa_hash_ctx_dup(ctx);REQUIRE(dup==NULL && failures==1);
            ERR_clear_error();emit(names[index],"dup-oom",fail,0,NULL,0);
            exercise(&key,ctx,out);REQUIRE(memcmp(saved,out,3*n)==0);
        }
        ossl_slh_dsa_hash_ctx_free(ctx);
    }
    OPENSSL_cleanup();
    return 0;
}
