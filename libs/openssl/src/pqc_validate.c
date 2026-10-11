/*
 * pqc_validate.c - ACVP / negative validation suite runner (CONTRACT.md phase 2 A).
 *
 * Every case is run through every variant of the matching process that belongs
 * to this binary's build flavour, plus (for sigver cases) through the verify
 * stage pipeline with each stage alternative, and the total / total_best
 * pipelines. The per-build partial results (one JSON object per line) are
 * merged by `merge-validate` into the contract's output format.
 */
#include "pqc_stages.h"

typedef struct {
    FILE *out;
    int pass, fail, skipped;
} vstats_t;

static void emit_result(vstats_t *st, const char *id, const char *variant, int pass, int got,
                        const char *error, const char *skipped)
{
    fprintf(st->out, "{\"id\":\"%s\",\"variant\":\"%s\",\"pass\":%s,\"got\":%s,\"error\":%s%s%s",
            id, variant, pass ? "true" : "false", got ? "true" : "false",
            error ? "\"" : "", error ? error : "null", error ? "\"" : "");
    if (skipped)
        fprintf(st->out, ",\"skipped\":\"%s\"", skipped);
    fprintf(st->out, "}\n");
    if (skipped) st->skipped++;
    else if (pass) st->pass++;
    else st->fail++;
}

/* run one phase-1 variant on a per-case param; returns pass; *got = output equals expectation (keygen/siggen) or verify result */
static int run_variant_case(const variant_t *v, param_t *c, const uint8_t *expect, size_t expect_len,
                            int expect_bool, int *got, const char **error)
{
    worker_t w;
    int impl = v->impl == IMPL_THREADS ? IMPL_REUSE : v->impl;
    *got = 0;
    *error = NULL;
    if (!worker_init(&w, v, c, impl)) {
        worker_free(&w);
        if (v->op == OP_VERIFY) /* e.g. public key import failed: verify must be false */
            return expect_bool == 0;
        *error = "init failed";
        return 0;
    }
    int ok = worker_op(&w);
    if (v->op == OP_VERIFY) {
        *got = ok;
        worker_free(&w);
        return *got == expect_bool;
    }
    if (!ok) {
        *error = "operation failed";
        worker_free(&w);
        return 0;
    }
    *got = w.out_len == expect_len && memcmp(w.out, expect, expect_len) == 0;
    if (!*got)
        *error = "output differs from expected";
    worker_free(&w);
    return *got;
}

int cmd_validate(vectors_t *V, const char *suite_path, const char *out_path)
{
    size_t n;
    char *buf = read_file(suite_path, &n);
    const char *end = buf + n;
    json_iter_t it;
    if (!json_iter_init(&it, json_find(buf, end, "cases"), end))
        die("validation: no cases array");
    vstats_t st = { fopen(out_path, "w"), 0, 0, 0 };
    if (st.out == NULL)
        die("cannot open %s", out_path);
    const char *os, *oe;
    int ncases = 0;
    while (json_iter_next(&it, &os, &oe)) {
        char *id = json_get_string(os, oe, "id");
        char *kind = json_get_string(os, oe, "kind");
        char *pname = json_get_string(os, oe, "param");
        if (!id || !kind || !pname)
            die("validation: malformed case");
        param_t *tpl = find_param(V, pname);
        if (tpl == NULL) { /* unsupported param (e.g. Falcon): skipped, not listed */
            free(id); free(kind); free(pname);
            continue;
        }
        ncases++;
        param_t c;
        memset(&c, 0, sizeof(c));
        c.name = tpl->name;
        c.is_mldsa = tpl->is_mldsa;
        int is_sha2 = !c.is_mldsa && strstr(c.name, "SHA2") != NULL;
        char *msg_h = json_get_string(os, oe, "msg_hex");
        char *ctx_h = json_get_string(os, oe, "ctx_hex");
        uint8_t *msg = NULL, *ctx = NULL;
        size_t msg_len = 0, ctx_len = 0;
        if (msg_h) { msg = hex2bin(msg_h, &msg_len); }
        if (ctx_h) { ctx = hex2bin(ctx_h, &ctx_len); }
        c.msg = msg; c.msg_len = msg_len; c.ctx = ctx; c.ctx_len = ctx_len;

        if (strcmp(kind, "keygen") == 0) {
            char *seed_h = json_get_string(os, oe, "seed_hex");
            char *epk = json_get_string(os, oe, "expect_pk_hex");
            char *esk = json_get_string(os, oe, "expect_sk_hex");
            size_t pkl, skl;
            uint8_t *pk = hex2bin(epk, &pkl), *sk = hex2bin(esk, &skl);
            uint8_t *expect = malloc(pkl + skl);
            memcpy(expect, pk, pkl); memcpy(expect + pkl, sk, skl);
            c.seed = hex2bin(seed_h, &c.seed_len);
            c.pk_len = pkl; c.sk_len = skl;
            for (size_t vi = 0; vi < NVARIANTS; vi++) {
                const variant_t *v = &VARIANTS[vi];
                if (v->op != OP_KEYGEN || strcmp(v->build, BUILD_LABEL) != 0 || (v->mldsa_only && !c.is_mldsa))
                    continue;
                int got; const char *err;
                int pass = run_variant_case(v, &c, expect, pkl + skl, 0, &got, &err);
                emit_result(&st, id, v->id, pass, got, err, NULL);
            }
            free(seed_h); free(epk); free(esk); free(pk); free(sk); free(expect); free(c.seed);
        } else if (strcmp(kind, "siggen") == 0) {
            char *sk_h = json_get_string(os, oe, "sk_hex");
            char *esig = json_get_string(os, oe, "expect_sig_hex");
            size_t skl, sl;
            uint8_t *sk = hex2bin(sk_h, &skl), *esg = hex2bin(esig, &sl);
            c.key = privkey_from_bytes(c.name, sk, skl);
            for (size_t vi = 0; vi < NVARIANTS; vi++) {
                const variant_t *v = &VARIANTS[vi];
                if (v->op != OP_SIGN || strcmp(v->build, BUILD_LABEL) != 0 || (v->mldsa_only && !c.is_mldsa))
                    continue;
                int got = 0; const char *err = NULL;
                int pass = 0;
                if (c.key == NULL)
                    err = "private key import failed";
                else
                    pass = run_variant_case(v, &c, esg, sl, 0, &got, &err);
                emit_result(&st, id, v->id, pass, got, err, NULL);
            }
            EVP_PKEY_free(c.key);
            free(sk_h); free(esig); free(sk); free(esg);
        } else if (strcmp(kind, "sigver") == 0) {
            char *pk_h = json_get_string(os, oe, "pk_hex");
            char *sig_h = json_get_string(os, oe, "sig_hex");
            int expect = json_get_bool(os, oe, "expect", 0);
            size_t pkl, sl;
            uint8_t *pk = hex2bin(pk_h, &pkl), *sig = hex2bin(sig_h, &sl);
            c.pub = pubkey_from_bytes(c.name, pk, pkl); /* NULL on bad length -> verify false */
            c.pk = pk; c.pk_len = pkl; c.sig = sig; c.sig_len = sl;
            for (size_t vi = 0; vi < NVARIANTS; vi++) {
                const variant_t *v = &VARIANTS[vi];
                if (v->op != OP_VERIFY || strcmp(v->build, BUILD_LABEL) != 0 || (v->mldsa_only && !c.is_mldsa))
                    continue;
                int got; const char *err;
                int pass = run_variant_case(v, &c, NULL, 0, expect, &got, &err);
                emit_result(&st, id, v->id, pass, got, err, NULL);
            }
            /* verify stage pipelines: each stage alternative of this build in an otherwise-v0 pipeline */
            stage_ctx_t *sc = stage_ctx_new(&c, pk, pkl, c.msg, c.msg_len, c.ctx, c.ctx_len, sig, sl);
            int nst = c.is_mldsa ? 5 : 4;
            for (size_t vi = 0; vi < NSTAGE_VARIANTS; vi++) {
                const stage_variant_t *sv = &STAGE_VARIANTS[vi];
                if (sv->mldsa != c.is_mldsa || strcmp(sv->build, BUILD_LABEL) != 0)
                    continue;
                if ((sv->flags & SF_SHA2ONLY) && !is_sha2)
                    continue;
                int methods[MAX_STAGES] = { 0, 0, 0, 0, 0 };
                methods[sv->sidx] = sv->method;
                char vid[64];
                snprintf(vid, sizeof(vid), "stages.%s.v%d", c.is_mldsa ? ML_STAGE_NAMES[sv->sidx] : SLH_STAGE_NAMES[sv->sidx], sv->vidx);
                int got = sc != NULL && stage_pipeline(sc, methods) == 1;
                emit_result(&st, id, vid, got == expect, got, NULL, NULL);
            }
            if (strcmp(BUILD_LABEL, "default") == 0) {
                int v0[MAX_STAGES] = { 0, 0, 0, 0, 0 };
                const int *best = c.is_mldsa ? BEST_ML : BEST_SLH;
                int got = sc != NULL && stage_pipeline(sc, v0) == 1;
                emit_result(&st, id, "stages.total", got == expect, got, NULL, NULL);
                got = sc != NULL && stage_pipeline(sc, best) == 1;
                emit_result(&st, id, "stages.total_best", got == expect, got, NULL, NULL);
            }
            (void)nst;
            stage_ctx_free(sc);
            EVP_PKEY_free(c.pub);
            free(pk_h); free(sig_h); free(pk); free(sig);
        }
        free(msg); free(ctx); free(msg_h); free(ctx_h);
        free(id); free(kind); free(pname);
        ERR_clear_error();
    }
    fclose(st.out);
    free(buf);
    fprintf(stderr, "[%s] validate: %d cases, %d pass, %d fail, %d skipped\n", BUILD_LABEL, ncases, st.pass, st.fail, st.skipped);
    return st.fail ? 1 : 0;
}

/* merge the per-build partial files into the contract format with a per-variant summary */
int cmd_merge_validate(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: merge-validate <out.json> <partial.jsonl>...\n");
        return 2;
    }
    FILE *out = fopen(argv[0], "w");
    if (out == NULL)
        die("cannot open %s", argv[0]);
    fprintf(out, "{\"lib\":\"%s\",\"lib_version\":\"%s\",\"results\":[\n", LIB_NAME, OPENSSL_VERSION_STR);
    typedef struct { char name[64]; int pass, fail, skipped; } sum_t;
    sum_t *sums = calloc(256, sizeof(sum_t));
    int nsum = 0, first = 1, total_fail = 0;
    for (int f = 1; f < argc; f++) {
        size_t n;
        char *buf = read_file(argv[f], &n);
        char *line = buf, *nl;
        while (line < buf + n && (nl = strchr(line, '\n')) != NULL) {
            *nl = 0;
            if (*line) {
                fprintf(out, "%s%s", first ? "" : ",\n", line);
                first = 0;
                char *variant = json_get_string(line, nl, "variant");
                int pass = json_get_bool(line, nl, "pass", 0);
                int skipped = json_find(line, nl, "skipped") != NULL;
                sum_t *s = NULL;
                for (int i = 0; i < nsum; i++)
                    if (strcmp(sums[i].name, variant) == 0) s = &sums[i];
                if (s == NULL && nsum < 256) {
                    s = &sums[nsum++];
                    snprintf(s->name, sizeof(s->name), "%s", variant);
                }
                if (s) {
                    if (skipped) s->skipped++;
                    else if (pass) s->pass++;
                    else { s->fail++; total_fail++; }
                }
                free(variant);
            }
            line = nl + 1;
        }
        free(buf);
    }
    fprintf(out, "\n],\"summary\":{");
    for (int i = 0; i < nsum; i++)
        fprintf(out, "%s\"%s\":{\"pass\":%d,\"fail\":%d,\"skipped\":%d}", i ? "," : "",
                sums[i].name, sums[i].pass, sums[i].fail, sums[i].skipped);
    fprintf(out, "}}\n");
    fclose(out);
    for (int i = 0; i < nsum; i++)
        fprintf(stderr, "%-28s pass=%d fail=%d skipped=%d\n", sums[i].name, sums[i].pass, sums[i].fail, sums[i].skipped);
    free(sums);
    return total_fail ? 1 : 0;
}
