/* SPDX-License-Identifier: MIT */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include "sha2_api.h"
static unsigned calls256, calls512, cleanse_calls, cleanse_failed;
static size_t cleansed_bytes;
void probe_cleanse(void *buffer, size_t size) {
    ++cleanse_calls;
    cleansed_bytes += size;
    OPENSSL_cleanse(buffer, size);
    for (size_t i = 0; i < size; i++)
        if (((const unsigned char *)buffer)[i] != 0) cleanse_failed = 1;
}
void probe256(SHA256_CTX *ctx, const unsigned char *block) {
    ++calls256;
    SHA256_Transform(ctx, block);
}
void probe512(SHA512_CTX *ctx, const unsigned char *block) {
    ++calls512;
    SHA512_Transform(ctx, block);
}
#ifndef EXPECT_256
#define EXPECT_256 1
#endif
#ifndef EXPECT_512
#define EXPECT_512 1
#endif
int main(void) {
    uint8_t digest[64];
    sha2_256(digest, "abc", 3);
    sha2_512(digest, "abc", 3);
    printf("SHA256_Transform calls: %u; SHA512_Transform calls: %u\n", calls256, calls512);
    printf("cleanse calls: %u; bytes: %zu; failed: %u\n", cleanse_calls, cleansed_bytes, cleanse_failed);
    return calls256 != EXPECT_256 || calls512 != EXPECT_512 || cleanse_calls != EXPECT_256 + EXPECT_512 || cleanse_failed ||
        cleansed_bytes != EXPECT_256 * sizeof(SHA256_CTX) + EXPECT_512 * sizeof(SHA512_CTX);
}
