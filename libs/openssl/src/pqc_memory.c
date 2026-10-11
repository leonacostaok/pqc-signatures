/*
 * pqc_memory.c - peak stack / heap per operation (CONTRACT.md phase 2 C).
 *
 * Stack: the operation runs on a pthread whose 16 MiB stack we allocate and
 * paint with 0xA5; afterwards the lowest non-painted byte gives the high-water
 * mark. The same measurement with an empty thread function (glibc's TLS block,
 * start frame, ...) is subtracted, so stack_bytes is what the operation itself
 * used (resolution: 16 bytes, i.e. the stack alignment).
 * Heap: CRYPTO_set_mem_functions installs counting malloc/realloc/free before
 * any OpenSSL allocation, so every OpenSSL allocation (and only those) is
 * counted: total bytes allocated during the op and the peak of live bytes
 * above the level before the op.
 */
#include "pqc_stages.h"
#include <pthread.h>
#include <stdatomic.h>
#include <openssl/crypto.h>

/* ----------------------------------------------------------- heap hooks */

static _Atomic uint64_t g_alloc_total, g_live, g_peak;
static int g_hooks = 0;

static void note_alloc(size_t n)
{
    atomic_fetch_add(&g_alloc_total, n);
    uint64_t live = atomic_fetch_add(&g_live, n) + n;
    uint64_t peak = atomic_load(&g_peak);
    while (live > peak && !atomic_compare_exchange_weak(&g_peak, &peak, live))
        ;
}

static void *m_malloc(size_t n, const char *f, int l)
{
    (void)f; (void)l;
    uint8_t *p = malloc(n + 16);
    if (p == NULL) return NULL;
    memcpy(p, &n, sizeof(n));
    note_alloc(n);
    return p + 16;
}

static void m_free(void *p, const char *f, int l)
{
    (void)f; (void)l;
    if (p == NULL) return;
    uint8_t *b = (uint8_t *)p - 16;
    size_t n;
    memcpy(&n, b, sizeof(n));
    atomic_fetch_sub(&g_live, n);
    free(b);
}

static void *m_realloc(void *p, size_t n, const char *f, int l)
{
    if (p == NULL) return m_malloc(n, f, l);
    uint8_t *b = (uint8_t *)p - 16;
    size_t old;
    memcpy(&old, b, sizeof(old));
    void *q = m_malloc(n, f, l);
    if (q == NULL) return NULL;
    memcpy(q, p, old < n ? old : n);
    m_free(p, f, l);
    return q;
}

void mem_hooks_install(void)
{
    g_hooks = CRYPTO_set_mem_functions(m_malloc, m_realloc, m_free);
}

/* -------------------------------------------------------- stack painting */

#define STACK_SIZE (16u << 20)
#define PAINT 0xA5

typedef struct {
    int (*fn)(void *);
    void *arg;
    int ret;
    uint64_t alloc0, alloc1, live0, peak1;
} run_arg_t;

static void *stack_tramp(void *a)
{
    run_arg_t *r = a;
    r->alloc0 = atomic_load(&g_alloc_total);
    r->live0 = atomic_load(&g_live);
    atomic_store(&g_peak, r->live0);
    r->ret = r->fn(r->arg);
    r->alloc1 = atomic_load(&g_alloc_total);
    r->peak1 = atomic_load(&g_peak);
    return NULL;
}

static int noop_fn(void *a) { (void)a; return 1; }

/* returns the stack high-water mark in bytes (from the top of the stack) */
static size_t run_on_painted_stack(run_arg_t *r)
{
    uint8_t *stk = aligned_alloc(4096, STACK_SIZE);
    memset(stk, PAINT, STACK_SIZE);
    pthread_attr_t at;
    pthread_t th;
    pthread_attr_init(&at);
    pthread_attr_setstack(&at, stk, STACK_SIZE);
    if (pthread_create(&th, &at, stack_tramp, r) != 0)
        die("pthread_create failed");
    pthread_join(th, NULL);
    pthread_attr_destroy(&at);
    size_t i = 0;
    while (i < STACK_SIZE && stk[i] == PAINT)
        i++;
    free(stk);
    return STACK_SIZE - i;
}

static size_t g_baseline = 0;

static size_t measure(int (*fn)(void *), void *arg, int *ret, uint64_t *alloc, uint64_t *peak)
{
    run_arg_t r = { fn, arg, 0, 0, 0, 0, 0 };
    size_t used = run_on_painted_stack(&r);
    *ret = r.ret;
    *alloc = r.alloc1 - r.alloc0;
    *peak = r.peak1 > r.live0 ? r.peak1 - r.live0 : 0;
    return used > g_baseline ? used - g_baseline : 0;
}

static void emit_mem(FILE *out, const char *variant, const char *op, const char *stage, const char *param,
                     size_t stack, uint64_t alloc, uint64_t peak, int threads, int match)
{
    fprintf(out, "{\"lib\":\"%s\",\"lib_version\":\"%s\",\"build\":\"%s\",\"variant\":\"%s\",\"op\":\"%s\",",
            LIB_NAME, OPENSSL_VERSION_STR, BUILD_LABEL, variant, op);
    if (stage)
        fprintf(out, "\"stage\":\"%s\",", stage);
    fprintf(out, "\"param\":\"%s\",\"stack_bytes\":%zu,\"stack_method\":\"painted 16 MiB pthread stack (pthread_attr_setstack), "
                 "high-water mark minus empty-thread baseline\",\"stack_resolution_bytes\":16,", param, stack);
    if (g_hooks)
        fprintf(out, "\"heap_alloc_bytes_per_op\":%llu,\"heap_peak_bytes\":%llu,\"heap_method\":\"CRYPTO_set_mem_functions "
                     "counting allocator: bytes allocated during the op / peak live bytes above the pre-op level (OpenSSL allocations only)\",",
                (unsigned long long)alloc, (unsigned long long)peak);
    else
        fprintf(out, "\"heap_alloc_bytes_per_op\":null,\"heap_peak_bytes\":null,\"heap_method\":null,");
    fprintf(out, "\"threads\":%d,\"match\":%s}\n", threads, match ? "true" : "false");
    fflush(out);
}

static int worker_cb(void *a) { return worker_op((worker_t *)a); }

typedef struct { stage_ctx_t *s; int sidx, method; char sha[65]; } stage_arg_t;
static int stage_cb(void *a)
{
    stage_arg_t *x = a;
    return stage_run(x->s, x->sidx, x->method, x->sha);
}
typedef struct { stage_ctx_t *s; const int *methods; } pipe_arg_t;
static int pipe_cb(void *a)
{
    pipe_arg_t *x = a;
    return stage_pipeline(x->s, x->methods);
}

int cmd_memory(vectors_t *V, const char *out_path, const char *params)
{
    FILE *out = fopen(out_path, "a");
    if (out == NULL)
        die("cannot open %s", out_path);
    /* baseline: empty thread on a painted stack (take the max of a few runs) */
    for (int i = 0; i < 3; i++) {
        run_arg_t r = { noop_fn, NULL, 0, 0, 0, 0, 0 };
        size_t b = run_on_painted_stack(&r);
        if (b > g_baseline) g_baseline = b;
    }
    fprintf(stderr, "[%s] empty-thread stack baseline: %zu bytes, heap hooks: %s\n", BUILD_LABEL, g_baseline,
            g_hooks ? "installed" : "NOT installed");
    int bad = 0;
    for (int pi = 0; pi < V->nparams; pi++) {
        param_t *p = &V->params[pi];
        if (!list_has(params, p->name))
            continue;
        if (!prepare_param(V, p, 1))
            bad++;
        /* phase-1 variants */
        for (size_t vi = 0; vi < NVARIANTS; vi++) {
            const variant_t *v = &VARIANTS[vi];
            if (strcmp(v->build, BUILD_LABEL) != 0 || (v->mldsa_only && !p->is_mldsa))
                continue;
            worker_t w;
            int impl = v->impl == IMPL_THREADS ? IMPL_REUSE : v->impl;
            if (!worker_init(&w, v, p, impl)) {
                emit_mem(out, v->id, op_names[v->op], NULL, p->name, 0, 0, 0, v->threads, 0);
                worker_free(&w);
                continue;
            }
            worker_op(&w); /* warm-up: lazy one-time allocations (property cache, etc.) are not the op's */
            int ret; uint64_t alloc, peak;
            size_t stack = measure(worker_cb, &w, &ret, &alloc, &peak);
            char o[65], s[65];
            int match = ret && worker_check_reference(&w, o, s);
            emit_mem(out, v->id, op_names[v->op], NULL, p->name, stack, alloc, peak, v->threads, match);
            worker_free(&w);
        }
        /* verify stages (v0 of each stage) + total / total_best pipelines: default build only */
        if (strcmp(BUILD_LABEL, "default") == 0) {
            stage_ctx_t *sc = stage_ctx_new(p, p->pk, p->pk_len, p->msg, p->msg_len, p->ctx, p->ctx_len, p->sig, p->sig_len);
            if (sc == NULL || !stage_prepare(sc)) {
                fprintf(stderr, "%s: stage preparation failed\n", p->name);
                bad++;
            } else {
                int ns = stage_ctx_nstages(sc);
                for (int si = 0; si < ns; si++) {
                    stage_arg_t a = { sc, si, 0, "" };
                    stage_cb(&a); /* warm-up */
                    int ret; uint64_t alloc, peak;
                    size_t stack = measure(stage_cb, &a, &ret, &alloc, &peak);
                    char id[64];
                    snprintf(id, sizeof(id), "%s.v0", stage_ctx_stage_name(sc, si));
                    emit_mem(out, id, "verify-stage", stage_ctx_stage_name(sc, si), p->name, stack, alloc, peak, 1, ret);
                }
                int v0[MAX_STAGES] = { 0, 0, 0, 0, 0 };
                const int *sel[2] = { v0, p->is_mldsa ? BEST_ML : BEST_SLH };
                const char *ids[2] = { "total", "total_best" };
                for (int t = 0; t < 2; t++) {
                    pipe_arg_t a = { sc, sel[t] };
                    pipe_cb(&a);
                    int ret; uint64_t alloc, peak;
                    size_t stack = measure(pipe_cb, &a, &ret, &alloc, &peak);
                    emit_mem(out, ids[t], "verify-stage", ids[t], p->name, stack, alloc, peak, 1, ret == 1);
                }
            }
            stage_ctx_free(sc);
        }
        fprintf(stderr, "[%s] memory %s done\n", BUILD_LABEL, p->name);
    }
    fclose(out);
    return bad ? 1 : 0;
}
