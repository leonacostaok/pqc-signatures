/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200809L
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "slh_dsa.h"

static const slh_param_t *parameters[] = {
    &slh_dsa_sha2_128f, &slh_dsa_sha2_128s, &slh_dsa_sha2_192f,
    &slh_dsa_sha2_192s, &slh_dsa_sha2_256f, &slh_dsa_sha2_256s
};
static const char *names[] = {
    "SLH_DSA_PURE_SHA2_128F", "SLH_DSA_PURE_SHA2_128S", "SLH_DSA_PURE_SHA2_192F",
    "SLH_DSA_PURE_SHA2_192S", "SLH_DSA_PURE_SHA2_256F", "SLH_DSA_PURE_SHA2_256S"
};
static const size_t message_lengths[] = {0, 32, 256, 4096};
static const size_t context_lengths[] = {0, 1, 17, 255};
static void require(int ok, const char *reason) {
    if (!ok) { fprintf(stderr, "%s\n", reason); exit(1); }
}
static uint64_t now_ns(void) {
    struct timespec t;
    require(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "clock failure");
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
/* Reproducible public test material only. Production RNG is never replaced. */
static void fill(uint8_t *out, size_t n, uint64_t tag) {
    uint64_t x = tag + UINT64_C(0x9e3779b97f4a7c15);
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17; out[i] = (uint8_t)x;
    }
}
static void transfer(FILE *f, uint8_t *b, size_t n, int write) {
    require((write ? fwrite(b, 1, n, f) : fread(b, 1, n, f)) == n, "incomplete corpus");
}
int main(int argc, char **argv) {
    require(argc == 3 || argc == 5, "usage: corpus generate|check|bench FILE [sign-iters verify-iters]");
    int generate = strcmp(argv[1], "generate") == 0;
    int bench = strcmp(argv[1], "bench") == 0;
    require(generate || bench || strcmp(argv[1], "check") == 0, "invalid mode");
    unsigned sign_iters = argc == 5 ? (unsigned)strtoul(argv[3], NULL, 10) : 3;
    unsigned verify_iters = argc == 5 ? (unsigned)strtoul(argv[4], NULL, 10) : 30;
    require(sign_iters > 0 && verify_iters > 0, "iterations must be positive");
    FILE *file = fopen(argv[2], generate ? "wb" : "rb");
    require(file != NULL, "cannot open corpus");
    uint8_t magic[] = "OQSSHA2-v1";
    if (generate) transfer(file, magic, sizeof(magic), 1);
    else { uint8_t readmagic[sizeof(magic)]; transfer(file, readmagic, sizeof(magic), 0); require(memcmp(magic, readmagic, sizeof(magic)) == 0, "wrong corpus version"); }
    OQS_init();
    for (unsigned p = 0; p < 6; p++) {
        const slh_param_t *prm = parameters[p];
        OQS_SIG *api = OQS_SIG_new(names[p]);
        require(api != NULL, "parameter is disabled");
        size_t n = slh_pk_sz(prm) / 2, sigsize = slh_sig_sz(prm);
        uint8_t *expected = malloc(sigsize), *actual = malloc(sigsize);
        require(expected && actual, "allocation failure");
        for (unsigned c = 0; c < 4; c++) {
            uint8_t seeds[96], rnd[32], sk[128], pk[64], message[4096], context[255];
            size_t mlen = message_lengths[c], clen = context_lengths[c], actual_len = 0;
            uint64_t tag = (uint64_t)p * 4096 + (uint64_t)c * 128;
            fill(seeds, sizeof(seeds), tag);
            fill(rnd, sizeof(rnd), tag+1);
            fill(message, sizeof(message), tag+2);
            fill(context, sizeof(context), tag+3);
            if (generate) {
                require(slh_keygen_internal(sk, pk, seeds, seeds+n, seeds+2*n, prm) == 0, "keygen failed");
                require(slh_sign(expected, message, mlen, context, clen, sk, rnd, prm) == sigsize, "fixture sign failed");
            }
            transfer(file, sk, slh_sk_sz(prm), generate);
            transfer(file, pk, slh_pk_sz(prm), generate);
            transfer(file, expected, sigsize, generate);
            require(OQS_SIG_verify_with_ctx_str(api, message, mlen, expected, sigsize, context, clen, pk) == OQS_SUCCESS, "fixture verification failed");
            if (!bench) {
                uint8_t sk_again[128], pk_again[64];
                require(slh_keygen_internal(sk_again, pk_again, seeds, seeds+n, seeds+2*n, prm) == 0, "regeneration failed");
                require(memcmp(sk, sk_again, slh_sk_sz(prm)) == 0 && memcmp(pk, pk_again, slh_pk_sz(prm)) == 0, "key bytes differ");
                require(slh_sign(actual, message, mlen, context, clen, sk, rnd, prm) == sigsize && memcmp(actual, expected, sigsize) == 0, "signature bytes differ");
                expected[sigsize/2] ^= 1;
                require(OQS_SIG_verify_with_ctx_str(api, message, mlen, expected, sigsize, context, clen, pk) != OQS_SUCCESS, "signature mutation accepted");
                expected[sigsize/2] ^= 1;
                if (mlen) { message[0] ^= 1; require(OQS_SIG_verify_with_ctx_str(api, message, mlen, expected, sigsize, context, clen, pk) != OQS_SUCCESS, "message mutation accepted"); message[0] ^= 1; }
                if (clen) { context[0] ^= 1; require(OQS_SIG_verify_with_ctx_str(api, message, mlen, expected, sigsize, context, clen, pk) != OQS_SUCCESS, "context mutation accepted"); context[0] ^= 1; }
                require(OQS_SIG_sign_with_ctx_str(api, actual, &actual_len, message, mlen, context, clen, sk) == OQS_SUCCESS && actual_len == sigsize, "public sign failed");
                require(OQS_SIG_verify_with_ctx_str(api, message, mlen, actual, actual_len, context, clen, pk) == OQS_SUCCESS, "public round trip failed");
                printf("{\"parameter\":\"%s\",\"case\":%u,\"checked\":true}\n", names[p], c);
            } else {
                /* One full untimed warmup per operation and corpus case. */
                require(OQS_SIG_sign_with_ctx_str(api, actual, &actual_len, message, mlen, context, clen, sk) == OQS_SUCCESS, "sign warmup failed");
                require(OQS_SIG_verify_with_ctx_str(api, message, mlen, actual, actual_len, context, clen, pk) == OQS_SUCCESS, "warmup invalid");
                uint64_t elapsed = 0;
                for (unsigned j = 0; j < sign_iters; j++) {
                    uint64_t start = now_ns();
                    OQS_STATUS status = OQS_SIG_sign_with_ctx_str(api, actual, &actual_len, message, mlen, context, clen, sk);
                    elapsed += now_ns()-start;
                    require(status == OQS_SUCCESS && actual_len == sigsize, "timed sign failed");
                    require(OQS_SIG_verify_with_ctx_str(api, message, mlen, actual, actual_len, context, clen, pk) == OQS_SUCCESS, "timed signature invalid");
                }
                printf("{\"parameter\":\"%s\",\"case\":%u,\"message_bytes\":%zu,\"context_bytes\":%zu,\"operation\":\"sign\",\"iterations\":%u,\"total_ns\":%llu}\n", names[p], c, mlen, clen, sign_iters, (unsigned long long)elapsed);
                elapsed = 0;
                for (unsigned j = 0; j < verify_iters; j++) {
                    uint64_t start = now_ns();
                    OQS_STATUS status = OQS_SIG_verify_with_ctx_str(api, message, mlen, expected, sigsize, context, clen, pk);
                    elapsed += now_ns()-start;
                    require(status == OQS_SUCCESS, "timed verify failed");
                }
                printf("{\"parameter\":\"%s\",\"case\":%u,\"message_bytes\":%zu,\"context_bytes\":%zu,\"operation\":\"verify\",\"iterations\":%u,\"total_ns\":%llu}\n", names[p], c, mlen, clen, verify_iters, (unsigned long long)elapsed);
            }
            fflush(stdout);
        }
        free(actual); free(expected); OQS_SIG_free(api);
    }
    if (!generate) require(fgetc(file) == EOF, "unexpected trailing corpus bytes");
    require(fclose(file) == 0, "corpus close failed");
    OQS_destroy();
    return 0;
}
