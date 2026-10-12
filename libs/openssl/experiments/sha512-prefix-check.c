/* Exercise the real hash implementation; count bytes without replacing SHA. */
#include "internal/deprecated.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
static size_t sha512_bytes;
static int counted_sha512_update(SHA512_CTX *ctx, const void *p, size_t n)
{
    sha512_bytes += n;
    return SHA512_Update(ctx, p, n);
}
#define SHA512_Update counted_sha512_update
#define ossl_slh_get_hash_fn tested_slh_get_hash_fn
#include "crypto/slh_dsa/slh_hash.c"
#undef ossl_slh_get_hash_fn
#undef SHA512_Update

static void reference(size_t n, const unsigned char *seed,
    const unsigned char *adrs, const unsigned char *msg, size_t len,
    unsigned char *out)
{
    unsigned char input[128 + SLH_ADRSC_SIZE + 4096];
    unsigned char digest[64];
    size_t prefix = n == 16 ? 64 : 128;
    memset(input, 0, prefix);
    memcpy(input, seed, n);
    memcpy(input + prefix, adrs, SLH_ADRSC_SIZE);
    memcpy(input + prefix + SLH_ADRSC_SIZE, msg, len);
    if (n == 16)
        SHA256(input, prefix + SLH_ADRSC_SIZE + len, digest);
    else
        SHA512(input, prefix + SLH_ADRSC_SIZE + len, digest);
    memcpy(out, digest, n);
}

int main(int argc, char **argv)
{
    const int require_cache = argc > 1 && strcmp(argv[1], "--require-cache") == 0;
    unsigned char msg[4096], adrs[SLH_ADRSC_SIZE], want[32], out[34];
    size_t cases = 0, excess = 0;
    for (size_t n = 16; n <= 32; n += 8) {
        SLH_DSA_PARAMS params = {0};
        params.n = n;
        params.security_category = n == 16 ? 1 : n == 24 ? 3 : 5;
        for (size_t sample = 0; sample < 16; sample++) {
            SLH_DSA_KEY key = {0};
            key.params = &params;
            key.hash_func = tested_slh_get_hash_fn(0, params.security_category);
            key.pub = key.priv + 2 * n;
            for (size_t i = 0; i < n; i++) key.pub[i] = (unsigned char)(sample * 17 + i * 43);
            for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (unsigned char)(sample * 23 + i * 71);
            for (size_t i = 0; i < sizeof(adrs); i++) adrs[i] = (unsigned char)(sample * 37 + i * 53);
            SLH_DSA_HASH_CTX *ctx = ossl_slh_dsa_hash_ctx_new(&key);
            assert(ctx != NULL);
            SLH_DSA_HASH_CTX *dup = ossl_slh_dsa_hash_ctx_dup(ctx);
            assert(dup != NULL);
            ossl_slh_dsa_hash_ctx_free(ctx);
            for (size_t rep = 0; rep < 8; rep++) {
                size_t lengths[] = {0, 1, n, 2 * n, 127, 128, 129, SLH_WOTS_LEN(n) * n};
                size_t len = lengths[rep];
                adrs[0] ^= (unsigned char)(rep + 1);
                msg[0] ^= (unsigned char)(rep + 3);
                reference(n, key.pub, adrs, msg, len, want);
                memset(out, 0xa5, sizeof(out));
                sha512_bytes = 0;
                assert(key.hash_func->T(dup, key.pub, adrs, msg, len, out + 1, n));
                assert(memcmp(out + 1, want, n) == 0);
                assert(out[0] == 0xa5 && out[n + 1] == 0xa5);
                if (n > 16) excess += sha512_bytes - (SLH_ADRSC_SIZE + len);
                cases++;
                reference(n, key.pub, adrs, msg, 2 * n, want);
                sha512_bytes = 0;
                assert(key.hash_func->H(dup, key.pub, adrs, msg, msg + n, out + 1, n));
                assert(memcmp(out + 1, want, n) == 0);
                assert(out[0] == 0xa5 && out[n + 1] == 0xa5);
                if (n > 16) excess += sha512_bytes - (SLH_ADRSC_SIZE + 2 * n);
                cases++;
            }
            ossl_slh_dsa_hash_ctx_free(dup);
        }
    }
    printf("{\"hash_cases\":%zu,\"redundant_prefix_bytes\":%zu}\n", cases, excess);
    if (require_cache && excess != 0) {
        fprintf(stderr, "Repeated H/T calls rehash the public seed prefix\n");
        return 1;
    }
    return 0;
}
