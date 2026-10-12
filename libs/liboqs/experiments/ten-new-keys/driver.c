#define _POSIX_C_SOURCE 200809L
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *names[] = {
    "SLH_DSA_PURE_SHA2_128F", "SLH_DSA_PURE_SHA2_128S", "SLH_DSA_PURE_SHA2_192F",
    "SLH_DSA_PURE_SHA2_192S", "SLH_DSA_PURE_SHA2_256F", "SLH_DSA_PURE_SHA2_256S"
};
static const size_t sizes[] = {16, 16, 24, 24, 32, 32};
static const uint8_t *entropy;
static size_t entropy_left;
static void require(int ok, const char *why) {
    if (!ok) { fprintf(stderr, "%s\n", why); exit(2); }
}
/* Test-process callback only: the public API still performs native keygen/sign.
 * Fail on unexpected requests; never install this in production applications. */
static void test_randombytes(uint8_t *out, size_t len) {
    require(len <= entropy_left, "unexpected entropy request");
    memcpy(out, entropy, len); entropy += len; entropy_left -= len;
}
static uint64_t clock_ns(clockid_t id) {
    struct timespec t; require(clock_gettime(id, &t) == 0, "clock failure");
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static void read_bytes(FILE *f, uint8_t *out, size_t n) {
    require(fread(out, 1, n, f) == n, "truncated input");
}
static uint32_t read_u32(FILE *f) {
    uint8_t x[4]; read_bytes(f, x, 4);
    return x[0] | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
}
static void write_bytes(FILE *f, const uint8_t *x, size_t n) {
    require(fwrite(x, 1, n, f) == n, "output failure");
}
static void write_u32(FILE *f, size_t n) {
    uint8_t x[4] = {(uint8_t)n, (uint8_t)(n >> 8), (uint8_t)(n >> 16), (uint8_t)(n >> 24)};
    write_bytes(f, x, 4);
}
static OQS_SIG *new_api(unsigned p) {
    OQS_SIG *api = OQS_SIG_new(names[p]); require(api != NULL, "parameter disabled"); return api;
}
int main(int argc, char **argv) {
    require(argc == 4 && (!strcmp(argv[3], "1") || !strcmp(argv[3], "10")), "usage: driver INPUT OUTPUT 1|10");
    unsigned count = (unsigned)strtoul(argv[3], NULL, 10);
    FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "wbx");
    require(in && out, "cannot open files (output must not exist)");
    uint8_t magic[8]; read_bytes(in, magic, 8); require(!memcmp(magic, "OQSTENK1", 8), "wrong input header");
    write_bytes(out, (const uint8_t *)"OQSTENO1", 8);
    OQS_init(); OQS_randombytes_custom_algorithm(test_randombytes);
    for (unsigned p = 0; p < 6; ++p) {
        for (int key = -1; key < (int)count; ++key) {
            size_t n = sizes[p], mlen = read_u32(in), clen = read_u32(in);
            require(mlen <= 8192 && clen <= 255, "invalid input length");
            uint8_t seed[96], rnd[32];
            uint8_t *message = calloc(mlen ? mlen : 1, 1), *context = calloc(clen ? clen : 1, 1);
            require(message && context, "allocation failure");
            read_bytes(in, seed, 3*n); read_bytes(in, rnd, n);
            read_bytes(in, message, mlen); read_bytes(in, context, clen);
            OQS_SIG *api = new_api(p);
            size_t pklen = api->length_public_key, sklen = api->length_secret_key, sigcap = api->length_signature, siglen = 0;
            uint8_t *pk = calloc(pklen, 1), *sk = calloc(sklen, 1), *sig = calloc(sigcap, 1);
            require(pk && sk && sig && pklen == 2*n && sklen == 4*n, "allocation or parameter failure");
            uint64_t wall[3], cpu[3], c0, w0, w1, c1;
            entropy = seed; entropy_left = 3*n;
            c0 = clock_ns(CLOCK_PROCESS_CPUTIME_ID); w0 = clock_ns(CLOCK_MONOTONIC);
            OQS_STATUS status = OQS_SIG_keypair(api, pk, sk);
            w1 = clock_ns(CLOCK_MONOTONIC); c1 = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
            wall[0] = w1-w0; cpu[0] = c1-c0;
            require(status == OQS_SUCCESS && entropy_left == 0, "keygen/entropy failure");
            require(!memcmp(sk, seed, 3*n) && !memcmp(pk, sk+2*n, 2*n), "key encoding/seed mismatch");
            OQS_SIG_free(api); api = new_api(p);
            entropy = rnd; entropy_left = n;
            c0 = clock_ns(CLOCK_PROCESS_CPUTIME_ID); w0 = clock_ns(CLOCK_MONOTONIC);
            status = OQS_SIG_sign_with_ctx_str(api, sig, &siglen, message, mlen, context, clen, sk);
            w1 = clock_ns(CLOCK_MONOTONIC); c1 = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
            wall[1] = w1-w0; cpu[1] = c1-c0;
            require(status == OQS_SUCCESS && entropy_left == 0 && siglen == sigcap, "sign/entropy failure");
            OQS_SIG_free(api); api = new_api(p);
            c0 = clock_ns(CLOCK_PROCESS_CPUTIME_ID); w0 = clock_ns(CLOCK_MONOTONIC);
            status = OQS_SIG_verify_with_ctx_str(api, message, mlen, sig, siglen, context, clen, pk);
            w1 = clock_ns(CLOCK_MONOTONIC); c1 = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
            wall[2] = w1-w0; cpu[2] = c1-c0;
            require(status == OQS_SUCCESS, "generated signature rejected");
            OQS_SIG_free(api); api = new_api(p);
            sig[siglen/2] ^= 1;
            require(OQS_SIG_verify_with_ctx_str(api, message, mlen, sig, siglen, context, clen, pk) != OQS_SUCCESS, "tamper accepted");
            sig[siglen/2] ^= 1; OQS_SIG_free(api);
            if (key >= 0) {
                write_u32(out, pklen); write_u32(out, sklen); write_u32(out, siglen);
                write_bytes(out, pk, pklen); write_bytes(out, sk, sklen); write_bytes(out, sig, siglen);
                printf("{\"parameter\":\"%s\",\"key\":%d,\"message_bytes\":%zu,\"context_bytes\":%zu,\"valid\":true,\"tamper_rejected\":true,\"rng_keygen_bytes\":%zu,\"rng_sign_bytes\":%zu", names[p], key, mlen, clen, 3*n, n);
                const char *ops[] = {"keygen", "sign", "verify"};
                for (unsigned j = 0; j < 3; ++j) printf(",\"%s_wall_ns\":%llu,\"%s_cpu_ns\":%llu", ops[j], (unsigned long long)wall[j], ops[j], (unsigned long long)cpu[j]);
                puts("}"); require(fflush(stdout) == 0, "stdout failure");
            }
            OQS_MEM_cleanse(sk, sklen); OQS_MEM_cleanse(seed, sizeof(seed)); OQS_MEM_cleanse(rnd, sizeof(rnd));
            free(pk); free(sk); free(sig); free(message); free(context);
        }
    }
    require(fgetc(in) == EOF, "trailing input");
    require(fclose(in) == 0 && fclose(out) == 0, "file close failure");
    OQS_destroy(); return 0;
}
