/* Reuse the reviewed public-EVP helpers without changing the sealed driver. */
#define main sealed_driver_main
#include "../sha512-prefix-driver.c"
#undef main

static uint64_t cpu_now(void)
{
    struct rusage u;
    if (getrusage(RUSAGE_SELF, &u)) die("cpu clock");
    return ((uint64_t)u.ru_utime.tv_sec + u.ru_stime.tv_sec) * 1000000000
        + ((uint64_t)u.ru_utime.tv_usec + u.ru_stime.tv_usec) * 1000;
}
int main(int argc, char **argv)
{
    if (argc != 3) die("usage: ten-key-driver candidate|baseline input");
    if (strcmp(argv[1], "candidate") && strcmp(argv[1], "baseline")) die("variant");
    FILE *f = fopen(argv[2], "r");
    if (!f) die("open input");
    char *alg = line(f);
    /* First triplet is a disjoint, untimed warmup; the next ten are measured. */
    for (int sample = -1; sample < 10; sample++) {
        input in = {0}; in.alg = alg;
        in.seed = hexline(f); in.msg = hexline(f); in.ctx = hexline(f);
        unsigned char pk[128], sk[256], sig[50000];
        size_t pklen = 0, sklen = 0, siglen = 0;
        uint64_t w, c, wall[3], cpu[3];
        c = cpu_now(); w = now();
        EVP_PKEY *key = keygen(&in);
        wall[0] = now() - w; cpu[0] = cpu_now() - c;
        if (!key) die("keygen failed");
        if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pk, sizeof(pk), &pklen)
            || !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, sk, sizeof(sk), &sklen)) die("export");
        in.pk = (bytes){pk, pklen}; in.sk = (bytes){sk, sklen};
        c = cpu_now(); w = now();
        int signed_ok = operation(&in, key, 0, sig, &siglen);
        wall[1] = now() - w; cpu[1] = cpu_now() - c;
        if (signed_ok != 1) die("sign failed");
        in.sig = (bytes){sig, siglen};
        EVP_PKEY *public_key = import_key(&in, 1);
        if (!public_key) die("import public key");
        c = cpu_now(); w = now();
        int verified = operation(&in, public_key, 1, sig, &siglen);
        wall[2] = now() - w; cpu[2] = cpu_now() - c;
        if (verified != 1 || siglen == 0) die("verify failed");
        sig[siglen / 2] ^= 1;
        int rejected = operation(&in, public_key, 1, sig, &siglen) != 1;
        sig[siglen / 2] ^= 1;
        if (!rejected) die("tampered signature accepted");
        if (sample >= 0) {
            printf("{\"variant\":\"%s\",\"parameter\":\"%s\",\"key_index\":%d,\"message_bytes\":%zu,\"context_bytes\":%zu,\"verified\":true,\"tamper_rejected\":true", argv[1], alg, sample, in.msg.n, in.ctx.n);
            const char *ops[] = {"keygen", "sign", "verify"};
            for (int op = 0; op < 3; op++) printf(",\"%s_wall_ns\":%llu,\"%s_cpu_ns\":%llu", ops[op], (unsigned long long)wall[op], ops[op], (unsigned long long)cpu[op]);
            printf(",\"pk_hex\":\""); printhex(pk, pklen);
            printf("\",\"sk_hex\":\""); printhex(sk, sklen);
            printf("\",\"sig_hex\":\""); printhex(sig, siglen); puts("\"}"); fflush(stdout);
        }
        EVP_PKEY_free(public_key); EVP_PKEY_free(key);
        OPENSSL_cleanse(sk, sizeof(sk));
        free(in.seed.p); free(in.msg.p); free(in.ctx.p);
    }
    if (fgetc(f) != EOF) die("unexpected trailing input");
    fclose(f); free(alg); return 0;
}
