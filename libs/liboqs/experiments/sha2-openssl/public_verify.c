/* Public-API adapter for SLH external vectors; no algorithm or RNG changes. */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int nibble(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *decode(const char *text, size_t *length) {
    size_t size = strlen(text);
    if (size % 2 != 0) return NULL;
    *length = size / 2;
    unsigned char *out = malloc(*length ? *length : 1);
    if (out == NULL) return NULL;
    for (size_t i = 0; i < *length; i++) {
        int hi = nibble((unsigned char)text[2 * i]);
        int lo = nibble((unsigned char)text[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(out); return NULL; }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return out;
}

int main(int argc, char **argv) {
    if (argc != 7 || (strcmp(argv[6], "0") != 0 && strcmp(argv[6], "1") != 0))
        return 2;
    OQS_init();
    OQS_SIG *algorithm = OQS_SIG_new(argv[1]);
    size_t pk_len = 0, msg_len = 0, sig_len = 0, ctx_len = 0;
    unsigned char *pk = decode(argv[2], &pk_len);
    unsigned char *msg = decode(argv[3], &msg_len);
    unsigned char *sig = decode(argv[4], &sig_len);
    unsigned char *ctx = decode(argv[5], &ctx_len);
    int result = 2;
    if (algorithm == NULL || pk == NULL || msg == NULL || sig == NULL || ctx == NULL
        || pk_len != algorithm->length_public_key || ctx_len > 255)
        goto done;
    int accepted = OQS_SIG_verify_with_ctx_str(algorithm, msg, msg_len,
        sig, sig_len, ctx_len ? ctx : NULL, ctx_len, pk) == OQS_SUCCESS;
    printf("public_verify_executed: %d\n", accepted);
    result = accepted == (argv[6][0] == '1') ? 0 : 1;
done:
    free(pk); free(msg); free(sig); free(ctx);
    OQS_SIG_free(algorithm);
    OQS_destroy();
    return result;
}
