/*
 * liboqs benchmark / vector driver for the pqc-signatures project.
 *
 * One binary is compiled per liboqs build variant (see run.sh). The binary
 * offers three "API paths":
 *   - api    : plain OQS_SIG_* dispatcher API, determinism obtained through
 *              OQS_randombytes_custom_algorithm (seed bytes for keygen,
 *              rnd = 0^32 for ML-DSA sign, opt_rand = PK.seed for SLH-DSA sign).
 *   - direct : the vendored internal functions are called directly
 *              (mld_sign_keypair_internal / mld_sign_signature_internal with
 *              rnd = 0 / mld_sign_verify_internal for ML-DSA and
 *              slh_keygen_internal / slh_sign(addrnd = NULL) / slh_verify for
 *              SLH-DSA). No RNG involvement, no OQS_SIG dispatcher.
 *   - threads: the "api" path executed by N pthreads on a batch (throughput).
 *
 * Subcommands (all read a flat "spec" file produced by run.sh from
 * common/vectors.json + common/reference.json):
 *   vectors <spec>                     -> one line per param (artifacts)
 *   crossverify <spec> <entries>       -> one line per entry (ok, tamper)
 *   bench <spec> [options]             -> one JSON line per (op, param)
 *
 * Spec file format (one record per line):
 *   msg <hex>
 *   param <name> <oqs-alg-name> <seed_hex> <pk_sha256|-> <sk_sha256|-> <sig_sha256|->
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include <openssl/evp.h>
#include <oqs/oqs.h>

/* ------------------------------------------------------------------ */
/* internal liboqs symbols used by the "direct" path                    */
/* ------------------------------------------------------------------ */

/* slhdsa-c (src/sig/slh_dsa/slh_dsa_c/slh_dsa.h) */
typedef struct slh_param_s slh_param_t;
extern int slh_keygen_internal(uint8_t *sk, uint8_t *pk, const uint8_t *sk_seed,
                               const uint8_t *sk_prf, const uint8_t *pk_seed,
                               const slh_param_t *prm);
extern size_t slh_sign(uint8_t *sig, const uint8_t *m, size_t m_sz,
                       const uint8_t *ctx, size_t ctx_sz, const uint8_t *sk,
                       const uint8_t *addrnd, const slh_param_t *prm);
extern int slh_verify(const uint8_t *m, size_t m_sz, const uint8_t *sig,
                      size_t sig_sz, const uint8_t *ctx, size_t ctx_sz,
                      const uint8_t *pk, const slh_param_t *prm);
extern const slh_param_t slh_dsa_sha2_128s, slh_dsa_sha2_128f, slh_dsa_sha2_192s,
       slh_dsa_sha2_192f, slh_dsa_sha2_256s, slh_dsa_sha2_256f, slh_dsa_shake_128s,
       slh_dsa_shake_128f, slh_dsa_shake_192s, slh_dsa_shake_192f, slh_dsa_shake_256s,
       slh_dsa_shake_256f;

/* mldsa-native internal API (src/sig/ml_dsa/mldsa-native_<set>/mldsa/src/sign.h) */
typedef int (*mld_keypair_internal_fn)(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
typedef int (*mld_signature_internal_fn)(uint8_t *sig, size_t *siglen, const uint8_t *m,
        size_t mlen, const uint8_t *pre, size_t prelen, const uint8_t rnd[32],
        const uint8_t *sk, int externalmu);
typedef int (*mld_verify_internal_fn)(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                      size_t mlen, const uint8_t *pre, size_t prelen,
                                      const uint8_t *pk, int externalmu);

#define MLD_DECL(P)                                                                        \
	extern int P##_keypair_internal(uint8_t *, uint8_t *, const uint8_t *);                \
	extern int P##_signature_internal(uint8_t *, size_t *, const uint8_t *, size_t,        \
	                                  const uint8_t *, size_t, const uint8_t *,            \
	                                  const uint8_t *, int);                               \
	extern int P##_verify_internal(const uint8_t *, size_t, const uint8_t *, size_t,       \
	                               const uint8_t *, size_t, const uint8_t *, int);

MLD_DECL(PQCP_MLDSA_NATIVE_MLDSA44_C)
MLD_DECL(PQCP_MLDSA_NATIVE_MLDSA65_C)
MLD_DECL(PQCP_MLDSA_NATIVE_MLDSA87_C)
#ifdef OQS_ENABLE_SIG_ml_dsa_44_x86_64
MLD_DECL(PQCP_MLDSA_NATIVE_MLDSA44_X86_64)
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_65_x86_64
MLD_DECL(PQCP_MLDSA_NATIVE_MLDSA65_X86_64)
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_87_x86_64
MLD_DECL(PQCP_MLDSA_NATIVE_MLDSA87_X86_64)
#endif

/* ------------------------------------------------------------------ */
/* small helpers                                                        */
/* ------------------------------------------------------------------ */

static void die(const char *msg) {
	fprintf(stderr, "bench: %s\n", msg);
	exit(2);
}

static int hexval(int c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static size_t unhex(const char *s, uint8_t **out) {
	size_t n = strlen(s);
	if (n == 1 && s[0] == '-') { *out = NULL; return 0; }
	if (n % 2) die("odd hex length");
	uint8_t *b = malloc(n / 2 + 1);
	for (size_t i = 0; i < n / 2; i++) {
		int h = hexval(s[2 * i]), l = hexval(s[2 * i + 1]);
		if (h < 0 || l < 0) die("bad hex");
		b[i] = (uint8_t)(h * 16 + l);
	}
	*out = b;
	return n / 2;
}

static void tohex(const uint8_t *b, size_t n, char *out) {
	static const char *d = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
	out[2 * n] = 0;
}

static void sha256_hex(const uint8_t *b, size_t n, char out[65]) {
	uint8_t d[32];
	unsigned int dl = 32;
	if (!EVP_Digest(b, n, d, &dl, EVP_sha256(), NULL)) die("EVP_Digest failed");
	tohex(d, 32, out);
}

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t cpu_ns(void) {
	struct rusage ru;
	getrusage(RUSAGE_SELF, &ru);
	return ((uint64_t)ru.ru_utime.tv_sec + (uint64_t)ru.ru_stime.tv_sec) * 1000000000ull +
	       ((uint64_t)ru.ru_utime.tv_usec + (uint64_t)ru.ru_stime.tv_usec) * 1000ull;
}

static int cmp_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

/* ------------------------------------------------------------------ */
/* deterministic RNG                                                    */
/* ------------------------------------------------------------------ */

/* The custom RNG hands out a fixed byte string. liboqs asks for exactly the
 * bytes the algorithm consumes (ML-DSA: 32-byte xi on keygen, 32-byte rnd on
 * sign; SLH-DSA: 3n bytes SK.seed||SK.prf||PK.seed on keygen, n bytes
 * opt_rand on sign). If a consumer asks for more (Falcon: 48-byte seed,
 * 40-byte nonce) the pattern is repeated, which is fine for Falcon because
 * no byte match is expected there. The callback is stateless and therefore
 * safe to call from several threads at once. */
static const uint8_t *g_rng_buf = NULL;
static size_t g_rng_len = 0;

static void fixed_randombytes(uint8_t *out, size_t n) {
	if (g_rng_len == 0) die("RNG requested without pattern");
	for (size_t i = 0; i < n; i++) out[i] = g_rng_buf[i % g_rng_len];
}

static void rng_set(const uint8_t *b, size_t n) {
	g_rng_buf = b;
	g_rng_len = n;
}

/* ------------------------------------------------------------------ */
/* parameter description                                                */
/* ------------------------------------------------------------------ */

typedef enum { FAM_MLDSA, FAM_SLHDSA, FAM_FALCON } family_t;

typedef struct {
	char name[40];
	char alg[48];
	uint8_t *seed;
	size_t seed_len;
	char pk_sha[65], sk_sha[65], sig_sha[65]; /* "-" when no reference */
	family_t fam;
	OQS_SIG *sig;
	/* direct-path handles */
	const slh_param_t *prm;
	mld_keypair_internal_fn mld_kp;
	mld_signature_internal_fn mld_sign;
	mld_verify_internal_fn mld_verify;
} param_t;

static uint8_t *g_msg = NULL;
static size_t g_msg_len = 0;
static param_t g_params[32];
static int g_nparams = 0;

static const slh_param_t *slh_prm_for(const char *alg) {
	struct { const char *n; const slh_param_t *p; } t[] = {
		{"SLH_DSA_PURE_SHA2_128S", &slh_dsa_sha2_128s}, {"SLH_DSA_PURE_SHA2_128F", &slh_dsa_sha2_128f},
		{"SLH_DSA_PURE_SHA2_192S", &slh_dsa_sha2_192s}, {"SLH_DSA_PURE_SHA2_192F", &slh_dsa_sha2_192f},
		{"SLH_DSA_PURE_SHA2_256S", &slh_dsa_sha2_256s}, {"SLH_DSA_PURE_SHA2_256F", &slh_dsa_sha2_256f},
		{"SLH_DSA_PURE_SHAKE_128S", &slh_dsa_shake_128s}, {"SLH_DSA_PURE_SHAKE_128F", &slh_dsa_shake_128f},
		{"SLH_DSA_PURE_SHAKE_192S", &slh_dsa_shake_192s}, {"SLH_DSA_PURE_SHAKE_192F", &slh_dsa_shake_192f},
		{"SLH_DSA_PURE_SHAKE_256S", &slh_dsa_shake_256s}, {"SLH_DSA_PURE_SHAKE_256F", &slh_dsa_shake_256f},
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) if (!strcmp(t[i].n, alg)) return t[i].p;
	return NULL;
}

static int g_have_avx2 = 0;

#define MLD_BIND(p, P)                                                                     \
	do { (p)->mld_kp = P##_keypair_internal; (p)->mld_sign = P##_signature_internal;       \
	     (p)->mld_verify = P##_verify_internal; } while (0)

static void bind_mldsa(param_t *p) {
	if (!strcmp(p->alg, "ML-DSA-44")) {
		MLD_BIND(p, PQCP_MLDSA_NATIVE_MLDSA44_C);
#ifdef OQS_ENABLE_SIG_ml_dsa_44_x86_64
		if (g_have_avx2) MLD_BIND(p, PQCP_MLDSA_NATIVE_MLDSA44_X86_64);
#endif
	} else if (!strcmp(p->alg, "ML-DSA-65")) {
		MLD_BIND(p, PQCP_MLDSA_NATIVE_MLDSA65_C);
#ifdef OQS_ENABLE_SIG_ml_dsa_65_x86_64
		if (g_have_avx2) MLD_BIND(p, PQCP_MLDSA_NATIVE_MLDSA65_X86_64);
#endif
	} else if (!strcmp(p->alg, "ML-DSA-87")) {
		MLD_BIND(p, PQCP_MLDSA_NATIVE_MLDSA87_C);
#ifdef OQS_ENABLE_SIG_ml_dsa_87_x86_64
		if (g_have_avx2) MLD_BIND(p, PQCP_MLDSA_NATIVE_MLDSA87_X86_64);
#endif
	} else die("unknown ML-DSA alg");
}

static void load_spec(const char *path) {
	FILE *f = fopen(path, "r");
	if (!f) die("cannot open spec");
	char line[4096];
	while (fgets(line, sizeof line, f)) {
		char *save = NULL;
		char *tok = strtok_r(line, " \t\r\n", &save);
		if (!tok) continue;
		if (!strcmp(tok, "msg")) {
			g_msg_len = unhex(strtok_r(NULL, " \t\r\n", &save), &g_msg);
		} else if (!strcmp(tok, "param")) {
			param_t *p = &g_params[g_nparams];
			memset(p, 0, sizeof *p);
			snprintf(p->name, sizeof p->name, "%s", strtok_r(NULL, " \t\r\n", &save));
			snprintf(p->alg, sizeof p->alg, "%s", strtok_r(NULL, " \t\r\n", &save));
			p->seed_len = unhex(strtok_r(NULL, " \t\r\n", &save), &p->seed);
			snprintf(p->pk_sha, 65, "%s", strtok_r(NULL, " \t\r\n", &save));
			snprintf(p->sk_sha, 65, "%s", strtok_r(NULL, " \t\r\n", &save));
			snprintf(p->sig_sha, 65, "%s", strtok_r(NULL, " \t\r\n", &save));
			if (!OQS_SIG_alg_is_enabled(p->alg)) {
				fprintf(stderr, "bench: %s (%s) not enabled in this build, skipping\n", p->name, p->alg);
				free(p->seed);
				continue;
			}
			p->sig = OQS_SIG_new(p->alg);
			if (!p->sig) die("OQS_SIG_new failed");
			if (!strncmp(p->alg, "ML-DSA", 6)) { p->fam = FAM_MLDSA; bind_mldsa(p); }
			else if (!strncmp(p->alg, "SLH_DSA", 7)) { p->fam = FAM_SLHDSA; p->prm = slh_prm_for(p->alg); if (!p->prm) die("slh prm"); }
			else p->fam = FAM_FALCON;
			g_nparams++;
		}
	}
	fclose(f);
	if (!g_msg) die("spec has no msg");
}

static param_t *find_param(const char *name) {
	for (int i = 0; i < g_nparams; i++) if (!strcmp(g_params[i].name, name)) return &g_params[i];
	return NULL;
}

/* ------------------------------------------------------------------ */
/* the three operations, api and direct paths                           */
/* ------------------------------------------------------------------ */

typedef enum { PATH_API, PATH_DIRECT } path_t;

static const uint8_t PURE_PREFIX[2] = {0x00, 0x00}; /* 0x00 || len(ctx)=0 for pure ML-DSA, empty ctx */
static const uint8_t ZERO32[32] = {0};

/* Prepare the deterministic RNG for an op (api path). */
static void rng_prepare(const param_t *p, const char *op, const uint8_t *sk) {
	if (!strcmp(op, "keygen")) {
		rng_set(p->seed, p->seed_len);
	} else if (!strcmp(op, "sign")) {
		if (p->fam == FAM_MLDSA) rng_set(ZERO32, 32);                 /* rnd = 0^32 */
		else if (p->fam == FAM_SLHDSA) {                                /* opt_rand = PK.seed */
			size_t n = p->sig->length_public_key / 2;
			rng_set(sk + 2 * n, n);
		} else rng_set(p->seed, p->seed_len);                           /* Falcon nonce: any fixed bytes */
	}
}

static int do_keygen(const param_t *p, path_t path, uint8_t *pk, uint8_t *sk) {
	if (path == PATH_API) return OQS_SIG_keypair(p->sig, pk, sk) == OQS_SUCCESS;
	switch (p->fam) {
	case FAM_MLDSA: return p->mld_kp(pk, sk, p->seed) == 0;
	case FAM_SLHDSA: {
		size_t n = p->sig->length_public_key / 2;
		return slh_keygen_internal(sk, pk, p->seed, p->seed + n, p->seed + 2 * n, p->prm) == 0;
	}
	default: return OQS_SIG_keypair(p->sig, pk, sk) == OQS_SUCCESS; /* Falcon: no internal seeded API */
	}
}

static int do_sign(const param_t *p, path_t path, uint8_t *sig, size_t *siglen, const uint8_t *sk) {
	if (path == PATH_API) return OQS_SIG_sign(p->sig, sig, siglen, g_msg, g_msg_len, sk) == OQS_SUCCESS;
	switch (p->fam) {
	case FAM_MLDSA: return p->mld_sign(sig, siglen, g_msg, g_msg_len, PURE_PREFIX, 2, ZERO32, sk, 0) == 0;
	case FAM_SLHDSA: *siglen = slh_sign(sig, g_msg, g_msg_len, NULL, 0, sk, NULL, p->prm); return *siglen != 0;
	default: return OQS_SIG_sign(p->sig, sig, siglen, g_msg, g_msg_len, sk) == OQS_SUCCESS;
	}
}

static int do_verify(const param_t *p, path_t path, const uint8_t *sig, size_t siglen, const uint8_t *pk) {
	if (path == PATH_API) return OQS_SIG_verify(p->sig, g_msg, g_msg_len, sig, siglen, pk) == OQS_SUCCESS;
	switch (p->fam) {
	case FAM_MLDSA: return p->mld_verify(sig, siglen, g_msg, g_msg_len, PURE_PREFIX, 2, pk, 0) == 0;
	case FAM_SLHDSA: return slh_verify(g_msg, g_msg_len, sig, siglen, NULL, 0, pk, p->prm) == 1;
	default: return OQS_SIG_verify(p->sig, g_msg, g_msg_len, sig, siglen, pk) == OQS_SUCCESS;
	}
}

/* Reference key material + signature for a param, produced with the api path. */
typedef struct {
	uint8_t *pk, *sk, *sig;
	size_t pklen, sklen, siglen;
} material_t;

static void make_material(const param_t *p, material_t *m) {
	m->pklen = p->sig->length_public_key;
	m->sklen = p->sig->length_secret_key;
	m->pk = malloc(m->pklen);
	m->sk = malloc(m->sklen);
	m->sig = malloc(p->sig->length_signature);
	rng_prepare(p, "keygen", NULL);
	if (!do_keygen(p, PATH_API, m->pk, m->sk)) die("keygen failed");
	rng_prepare(p, "sign", m->sk);
	if (!do_sign(p, PATH_API, m->sig, &m->siglen, m->sk)) die("sign failed");
}

/* ------------------------------------------------------------------ */
/* vectors                                                              */
/* ------------------------------------------------------------------ */

static int cmd_vectors(void) {
	int rc = 0;
	for (int i = 0; i < g_nparams; i++) {
		param_t *p = &g_params[i];
		material_t m;
		make_material(p, &m);
		int ok = do_verify(p, PATH_API, m.sig, m.siglen, m.pk);
		char pkh[65], skh[65], sgh[65];
		sha256_hex(m.pk, m.pklen, pkh);
		sha256_hex(m.sk, m.sklen, skh);
		sha256_hex(m.sig, m.siglen, sgh);
		char *pkhex = malloc(2 * m.pklen + 1), *sighex = malloc(2 * m.siglen + 1);
		tohex(m.pk, m.pklen, pkhex);
		tohex(m.sig, m.siglen, sighex);
		int ref = strcmp(p->pk_sha, "-") != 0;
		int match = !ref ? -1 : (!strcmp(pkh, p->pk_sha) && !strcmp(skh, p->sk_sha) && !strcmp(sgh, p->sig_sha));
		printf("%s %s %s %s %s %s %d %d\n", p->name, pkhex, sighex, skh, pkh, sgh, ok, match);
		if (!ok || match == 0) rc = 1;
		free(pkhex); free(sighex); free(m.pk); free(m.sk); free(m.sig);
	}
	return rc;
}

/* ------------------------------------------------------------------ */
/* crossverify: entries file has lines "<param> <pk_hex> <sig_hex>"     */
/* ------------------------------------------------------------------ */

static int cmd_crossverify(const char *entries) {
	FILE *f = fopen(entries, "r");
	if (!f) die("cannot open entries");
	size_t cap = 1 << 20;
	char *line = malloc(cap);
	while (fgets(line, (int)cap, f)) {
		char *save = NULL;
		char *name = strtok_r(line, " \t\r\n", &save);
		if (!name) continue;
		char *pkhex = strtok_r(NULL, " \t\r\n", &save);
		char *sighex = strtok_r(NULL, " \t\r\n", &save);
		param_t *p = find_param(name);
		if (!p) continue; /* unsupported: skipped */
		uint8_t *pk, *sig;
		size_t pklen = unhex(pkhex, &pk), siglen = unhex(sighex, &sig);
		const char *err = NULL;
		int ok = 0, tamper_rejected = 0;
		if (pklen != p->sig->length_public_key) err = "pk length mismatch";
		else if (siglen > p->sig->length_signature) err = "sig too long";
		else {
			ok = do_verify(p, PATH_API, sig, siglen, pk);
			if (!ok) err = "verify returned false";
			sig[siglen / 2] ^= 0x01; /* flip one bit */
			tamper_rejected = !do_verify(p, PATH_API, sig, siglen, pk);
		}
		printf("%s %d %d %s\n", name, ok, tamper_rejected, err ? err : "-");
		free(pk); free(sig);
	}
	free(line);
	fclose(f);
	return 0;
}

/* ------------------------------------------------------------------ */
/* bench                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
	const param_t *p;
	const char *op;
	path_t path;
	const material_t *m;
	/* per-thread scratch */
	uint8_t *pk, *sk, *sig;
	size_t siglen;
	int ok;
	/* batch control */
	int ops_per_thread;
} job_t;

static int run_once(job_t *j) {
	const param_t *p = j->p;
	if (!strcmp(j->op, "keygen")) return do_keygen(p, j->path, j->pk, j->sk);
	if (!strcmp(j->op, "sign")) return do_sign(p, j->path, j->sig, &j->siglen, j->m->sk);
	return do_verify(p, j->path, j->m->sig, j->m->siglen, j->m->pk);
}

/* check that a job's last output is byte-identical to the reference */
static int job_output_matches(job_t *j, char *out_sha) {
	const param_t *p = j->p;
	if (!strcmp(j->op, "keygen")) {
		char h[65];
		sha256_hex(j->pk, p->sig->length_public_key, out_sha);
		sha256_hex(j->sk, p->sig->length_secret_key, h);
		if (!strcmp(p->pk_sha, "-")) { /* no reference (Falcon): self-consistency */
			return memcmp(j->pk, j->m->pk, p->sig->length_public_key) == 0 &&
			       memcmp(j->sk, j->m->sk, p->sig->length_secret_key) == 0;
		}
		return !strcmp(out_sha, p->pk_sha) && !strcmp(h, p->sk_sha);
	}
	if (!strcmp(j->op, "sign")) {
		sha256_hex(j->sig, j->siglen, out_sha);
		if (!strcmp(p->sig_sha, "-"))
			return j->siglen == j->m->siglen && memcmp(j->sig, j->m->sig, j->siglen) == 0;
		return !strcmp(out_sha, p->sig_sha);
	}
	strcpy(out_sha, j->ok ? "true" : "false");
	return j->ok;
}

/* thread pool for batch variants */
typedef struct {
	int nthreads;
	pthread_t *th;
	job_t *jobs;
	pthread_barrier_t start, done;
	volatile int quit;
} pool_t;

typedef struct { pool_t *pool; int idx; } warg_t;

static void *worker2(void *arg) {
	warg_t *w = arg;
	pool_t *pool = w->pool;
	job_t *j = &pool->jobs[w->idx];
	for (;;) {
		pthread_barrier_wait(&pool->start);
		if (pool->quit) break;
		int ok = 1;
		for (int k = 0; k < j->ops_per_thread; k++) ok &= run_once(j);
		j->ok = ok;
		pthread_barrier_wait(&pool->done);
	}
	return NULL;
}

typedef struct {
	const char *lib_version, *lang, *runtime, *variant, *variant_name, *variant_desc;
	int threads;
	path_t path;
	uint64_t budget_ms;
} bench_cfg_t;

static void json_escape(const char *s, FILE *f) {
	for (; *s; s++) {
		if (*s == '"' || *s == '\\') fputc('\\', f);
		fputc(*s, f);
	}
}

static void bench_one(const bench_cfg_t *cfg, const param_t *p, const char *op) {
	material_t m;
	make_material(p, &m);
	int nth = cfg->threads > 0 ? cfg->threads : 1;
	job_t *jobs = calloc(nth, sizeof(job_t));
	for (int t = 0; t < nth; t++) {
		jobs[t].p = p; jobs[t].op = op; jobs[t].path = cfg->path; jobs[t].m = &m;
		jobs[t].pk = malloc(p->sig->length_public_key);
		jobs[t].sk = malloc(p->sig->length_secret_key);
		jobs[t].sig = malloc(p->sig->length_signature);
		jobs[t].ops_per_thread = 1;
	}
	rng_prepare(p, op, m.sk);

	/* warm-up: at least 1 op, up to 5 ops or 100 ms, and first match check */
	char out_sha[65] = "";
	int match = 1;
	uint64_t one_op_ns = 0;
	{
		uint64_t t0 = now_ns();
		int n = 0;
		do {
			uint64_t a = now_ns();
			jobs[0].ok = run_once(&jobs[0]);
			one_op_ns = now_ns() - a;
			n++;
		} while (n < 5 && now_ns() - t0 < 100000000ull);
		match &= job_output_matches(&jobs[0], out_sha);
	}
	/* for verify: check the tampered signature is rejected (same path) */
	if (!strcmp(op, "verify")) {
		uint8_t *bad = malloc(m.siglen);
		memcpy(bad, m.sig, m.siglen);
		bad[m.siglen / 2] ^= 0x01;
		int rej = !do_verify(p, cfg->path, bad, m.siglen, m.pk);
		free(bad);
		if (!rej) { match = 0; strcpy(out_sha, "false"); }
	}

	/* measured loop */
	size_t cap = 100000, nsamp = 0;
	uint64_t *samp = malloc(cap * sizeof *samp);
	uint64_t total_ops = 0;
	pool_t pool = {0};
	if (nth > 1) {
		/* batch sizing: aim for ~2 ms per thread per batch, 1..64 ops */
		int opt = (int)(2000000ull / (one_op_ns ? one_op_ns : 1));
		if (opt < 1) opt = 1;
		if (opt > 64) opt = 64;
		for (int t = 0; t < nth; t++) jobs[t].ops_per_thread = opt;
		pool.nthreads = nth; pool.jobs = jobs;
		pool.th = calloc(nth, sizeof(pthread_t));
		pthread_barrier_init(&pool.start, NULL, nth + 1);
		pthread_barrier_init(&pool.done, NULL, nth + 1);
		warg_t *wa = calloc(nth, sizeof *wa);
		for (int t = 0; t < nth; t++) { wa[t].pool = &pool; wa[t].idx = t; pthread_create(&pool.th[t], NULL, worker2, &wa[t]); }
		/* one untimed batch to warm every thread */
		pthread_barrier_wait(&pool.start); pthread_barrier_wait(&pool.done);
		for (int t = 0; t < nth; t++) { char h[65]; match &= job_output_matches(&jobs[t], h); }
	}
	uint64_t budget_ns = cfg->budget_ms * 1000000ull;
	uint64_t min_ops = one_op_ns > 5000000000ull ? 2 : 3;
	uint64_t cpu0 = cpu_ns(), wall0 = now_ns(), wall_end = wall0;
	int all_ok = 1;
	for (;;) {
		uint64_t a = now_ns();
		if (nth > 1) {
			pthread_barrier_wait(&pool.start);
			pthread_barrier_wait(&pool.done);
			uint64_t d = now_ns() - a;
			size_t batch = (size_t)nth * (size_t)jobs[0].ops_per_thread;
			for (int t = 0; t < nth; t++) all_ok &= jobs[t].ok;
			for (size_t k = 0; k < batch && nsamp < cap; k++) samp[nsamp++] = d / batch;
			total_ops += batch;
		} else {
			jobs[0].ok = run_once(&jobs[0]);
			uint64_t d = now_ns() - a;
			all_ok &= jobs[0].ok;
			if (nsamp < cap) samp[nsamp++] = d;
			total_ops++;
		}
		wall_end = now_ns();
		if (total_ops >= 100000) break;
		if (wall_end - wall0 >= budget_ns && total_ops >= min_ops) break;
	}
	uint64_t cpu1 = cpu_ns();
	uint64_t wall_total = wall_end - wall0, cpu_total = cpu1 - cpu0;
	if (nth > 1) {
		pool.quit = 1;
		pthread_barrier_wait(&pool.start);
		for (int t = 0; t < nth; t++) pthread_join(pool.th[t], NULL);
	}
	/* final match check on the last outputs */
	for (int t = 0; t < nth; t++) { char h[65]; match &= job_output_matches(&jobs[t], h); }
	if (!all_ok) match = 0;
	if (!strcmp(op, "verify")) strcpy(out_sha, match ? "true" : "false");

	qsort(samp, nsamp, sizeof *samp, cmp_u64);
	long double mean = 0;
	for (size_t i = 0; i < nsamp; i++) mean += samp[i];
	mean /= nsamp ? nsamp : 1;
	uint64_t median = nsamp ? samp[nsamp / 2] : 0;
	uint64_t p95 = nsamp ? samp[(size_t)((nsamp - 1) * 0.95)] : 0;
	uint64_t mn = nsamp ? samp[0] : 0;

	FILE *f = stdout;
	fprintf(f, "{\"lib\":\"liboqs\",\"lib_version\":\"%s\",\"lang\":\"%s\",\"runtime\":\"", cfg->lib_version, cfg->lang);
	json_escape(cfg->runtime, f);
	fprintf(f, "\",\"variant\":\"%s\",\"variant_name\":\"%s\",\"variant_desc\":\"", cfg->variant, cfg->variant_name);
	json_escape(cfg->variant_desc, f);
	fprintf(f, "\",\"op\":\"%s\",\"param\":\"%s\",\"iterations\":%llu,\"threads\":%d,"
	        "\"wall_ns_median\":%llu,\"wall_ns_mean\":%.0Lf,\"wall_ns_p95\":%llu,\"wall_ns_min\":%llu,"
	        "\"cpu_ns_per_op\":%.0f,\"cpu_util\":%.3f,\"ops_per_sec\":%.3f,\"output_sha256\":\"%s\",\"match\":%s,"
	        "\"match_basis\":\"%s\"}\n",
	        op, p->name, (unsigned long long)total_ops, nth,
	        (unsigned long long)median, mean, (unsigned long long)p95, (unsigned long long)mn,
	        (double)cpu_total / (double)total_ops, wall_total ? (double)cpu_total / (double)wall_total : 0.0,
	        wall_total ? (double)total_ops * 1e9 / (double)wall_total : 0.0, out_sha, match ? "true" : "false",
	        strcmp(p->pk_sha, "-") ? "reference" : "self-verify");
	fflush(f);

	for (int t = 0; t < nth; t++) { free(jobs[t].pk); free(jobs[t].sk); free(jobs[t].sig); }
	free(jobs); free(samp); free(m.pk); free(m.sk); free(m.sig);
}

static int in_list(const char *list, const char *item) {
	if (!list || !*list) return 1;
	size_t n = strlen(item);
	const char *s = list;
	while (*s) {
		const char *e = strchr(s, ',');
		size_t l = e ? (size_t)(e - s) : strlen(s);
		if (l == n && !strncmp(s, item, n)) return 1;
		if (!e) break;
		s = e + 1;
	}
	return 0;
}

/* Non-dist liboqs builds never install the AVX512VL SHA-3 backend (the
 * selection only exists in the OQS_DIST_X86_64_BUILD branch of
 * Keccak_Dispatch), so they run SHAKE on the AVX2 Keccak. --sha3 avx512vl
 * re-selects it at run time through the public callback API. */
#if defined(OQS_USE_SHA3_AVX512VL)
extern const struct OQS_SHA3_callbacks sha3_avx512vl_callbacks;
extern const struct OQS_SHA3_x4_callbacks sha3_x4_avx512vl_callbacks;
#endif
static int select_sha3(const char *which) {
	if (strcmp(which, "avx512vl")) return 0;
#if defined(OQS_USE_SHA3_AVX512VL)
	/* OQS_CPU_has_extension() always returns 0 in non-dist builds, so use the compiler's probe */
	if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl")) {
		OQS_SHA3_set_callbacks((struct OQS_SHA3_callbacks *)&sha3_avx512vl_callbacks);
		OQS_SHA3_x4_set_callbacks((struct OQS_SHA3_x4_callbacks *)&sha3_x4_avx512vl_callbacks);
		return 1;
	}
#endif
	fprintf(stderr, "bench: AVX512VL SHA-3 backend not available, keeping default\n");
	return 0;
}

static int cmd_bench(int argc, char **argv) {
	bench_cfg_t cfg = { OQS_VERSION_TEXT, "c", "liboqs", "x.v0", "baseline", "", 1, PATH_API, 1000 };
	const char *params = NULL, *ops = NULL;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--budget-ms") && i + 1 < argc) cfg.budget_ms = strtoull(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--params") && i + 1 < argc) params = argv[++i];
		else if (!strcmp(argv[i], "--ops") && i + 1 < argc) ops = argv[++i];
		else if (!strcmp(argv[i], "--threads") && i + 1 < argc) cfg.threads = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--path") && i + 1 < argc) cfg.path = !strcmp(argv[++i], "direct") ? PATH_DIRECT : PATH_API;
		else if (!strcmp(argv[i], "--variant") && i + 1 < argc) cfg.variant = argv[++i];
		else if (!strcmp(argv[i], "--variant-name") && i + 1 < argc) cfg.variant_name = argv[++i];
		else if (!strcmp(argv[i], "--variant-desc") && i + 1 < argc) cfg.variant_desc = argv[++i];
		else if (!strcmp(argv[i], "--runtime") && i + 1 < argc) cfg.runtime = argv[++i];
		else if (!strcmp(argv[i], "--sha3") && i + 1 < argc) select_sha3(argv[++i]);
		else { fprintf(stderr, "unknown option %s\n", argv[i]); return 2; }
	}
	static const char *all_ops[] = {"keygen", "sign", "verify"};
	for (int oi = 0; oi < 3; oi++) {
		if (!in_list(ops, all_ops[oi])) continue;
		for (int i = 0; i < g_nparams; i++) {
			if (!in_list(params, g_params[i].name)) continue;
			bench_one(&cfg, &g_params[i], all_ops[oi]);
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: bench vectors <spec> | crossverify <spec> <entries> | bench <spec> [opts] | info\n");
		return 2;
	}
	OQS_init();
#if defined(OQS_DIST_BUILD)
	g_have_avx2 = OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&
	              OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT);
#elif defined(OQS_USE_AVX2_INSTRUCTIONS) && defined(OQS_USE_BMI2_INSTRUCTIONS) && defined(OQS_USE_POPCNT_INSTRUCTIONS)
	g_have_avx2 = 1; /* non-dist build: OQS_CPU_has_extension() is a stub, backend chosen at compile time */
#endif
	OQS_randombytes_custom_algorithm(fixed_randombytes);
	load_spec(argv[2]);
	int rc = 2;
	if (!strcmp(argv[1], "vectors")) rc = cmd_vectors();
	else if (!strcmp(argv[1], "crossverify") && argc >= 4) rc = cmd_crossverify(argv[3]);
	else if (!strcmp(argv[1], "bench")) rc = cmd_bench(argc - 3, argv + 3);
	else fprintf(stderr, "unknown command\n");
	OQS_destroy();
	return rc;
}
