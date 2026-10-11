/* ================================================================== */
/* Phase 2: validation suite, verify stages, stack/heap memory          */
/* ================================================================== */

/* ---- stage op tables (stages_mldsa.c, compiled per param set + backend) */
#define STG_EXT(NN) \
	extern const stg_mldsa_ops stg_mldsa_##NN##_c; \
	extern const stg_mldsa_ops stg_mldsa_##NN##_x86;
STG_EXT(44) STG_EXT(65) STG_EXT(87)

static const stg_mldsa_ops *mld_ops_for(const param_t *p, int want_c) {
	int x86 = g_have_avx2 && !want_c;
	if (!strcmp(p->alg, "ML-DSA-44")) return x86 ? &stg_mldsa_44_x86 : &stg_mldsa_44_c;
	if (!strcmp(p->alg, "ML-DSA-65")) return x86 ? &stg_mldsa_65_x86 : &stg_mldsa_65_c;
	if (!strcmp(p->alg, "ML-DSA-87")) return x86 ? &stg_mldsa_87_x86 : &stg_mldsa_87_c;
	return NULL;
}

/* mode string: comma list of c, ossl, cached, oneway */
typedef struct { int backend_c; unsigned bits; } stg_mode_t;
static stg_mode_t parse_mode(const char *s) {
	stg_mode_t m = {0, 0};
	if (!s) return m;
	if (in_list(s, "c")) m.backend_c = 1;
	if (in_list(s, "ossl")) m.bits |= STG_MODE_OSSL;
	if (in_list(s, "cached")) m.bits |= STG_MODE_CACHED;
	if (in_list(s, "oneway")) m.bits |= STG_MODE_ONEWAY;
	return m;
}

/* A stage context: everything a stage needs, inputs prepared outside timing. */
typedef struct {
	const param_t *p;
	const stg_mldsa_ops *mops; void *mst;
	const stg_slh_ops *sops; void *sst;
	const uint8_t *pk, *sig, *m, *ctx; size_t pklen, siglen, mlen, ctxlen;
	uint8_t pre[2 + 255]; size_t prelen;
	stg_mode_t mode;
} stage_ctx_t;

static void stage_ctx_init(stage_ctx_t *c, const param_t *p, stg_mode_t mode, const uint8_t *pk, size_t pklen,
                           const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen) {
	memset(c, 0, sizeof *c);
	c->p = p; c->mode = mode; c->pk = pk; c->pklen = pklen; c->sig = sig; c->siglen = siglen; c->m = m; c->mlen = mlen; c->ctx = ctx; c->ctxlen = ctxlen;
	c->prelen = make_pre(c->pre, ctx, ctxlen);
	/* 64-byte aligned, zeroed state: the AVX2 backend requires MLD_ALIGN(32)-aligned polynomials */
	if (p->fam == FAM_MLDSA) { c->mops = mld_ops_for(p, mode.backend_c); if (posix_memalign(&c->mst, 64, c->mops->state_size)) die("memalign"); memset(c->mst, 0, c->mops->state_size); }
	else if (p->fam == FAM_SLHDSA) { c->sops = &stg_slh; if (posix_memalign(&c->sst, 64, c->sops->state_size)) die("memalign"); memset(c->sst, 0, c->sops->state_size); }
}
static void stage_ctx_free(stage_ctx_t *c) { free(c->mst); free(c->sst); }

static const char *MLD_STAGES[] = {"decode", "mu", "expandA", "w_approx", "hint_check", NULL};
static const char *SLH_STAGES[] = {"hmsg", "fors", "ht_wots", "ht_auth", NULL};

static int stage_index(const param_t *p, const char *stage) {
	const char **t = p->fam == FAM_MLDSA ? MLD_STAGES : SLH_STAGES;
	for (int i = 0; t[i]; i++) if (!strcmp(t[i], stage)) return i;
	return -1;
}

/* run stage number i (with the context's mode); returns stage result */
static int run_stage_i(stage_ctx_t *c, int i) {
	unsigned b = c->mode.bits;
	if (c->mops) {
		switch (i) {
		case 0: return c->mops->decode(c->mst, c->pk, c->pklen, c->sig, c->siglen);
		case 1: return c->mops->mu(c->mst, c->pre, c->prelen, c->m, c->mlen, b);
		case 2: return c->mops->expandA(c->mst, b);
		case 3: return c->mops->w_approx(c->mst, b);
		case 4: return c->mops->hint_check(c->mst, b);
		}
	} else {
		switch (i) {
		case 0: return c->sops->hmsg(c->sst, c->p->prm, c->pk, c->pklen, c->sig, c->siglen, c->m, c->mlen, c->ctx, c->ctxlen);
		case 1: return c->sops->fors(c->sst);
		case 2: return c->sops->ht_wots(c->sst);
		case 3: return c->sops->ht_auth(c->sst);
		}
	}
	return 0;
}

/* full pipeline (= verify); for SLH the untimed layer preparation sits between fors and ht_wots */
static int run_pipeline(stage_ctx_t *c) {
	int n = c->mops ? 5 : 4;
	for (int i = 0; i < n; i++) {
		if (!run_stage_i(c, i)) return 0;
		if (!c->mops && i == 1 && !c->sops->prepare_layers(c->sst)) return 0;
	}
	return 1;
}

/* canonical output hash of stage i from the current state */
static void stage_output_sha(stage_ctx_t *c, int i, char out[65]) {
	if (c->mops) {
		const stg_mldsa_ops *o = c->mops;
		uint8_t *buf; size_t n;
		switch (i) {
		case 0: sha256_hex(o->out_ctilde(c->mst), o->ctilde_len, out); return;
		case 1: sha256_hex(o->out_mu(c->mst), o->mu_len, out); return;
		case 2: n = o->out_expandA_len; buf = malloc(n); o->out_expandA(c->mst, buf); sha256_hex(buf, n, out); free(buf); return;
		case 3: n = o->out_w_len; buf = malloc(n); o->out_w(c->mst, buf); sha256_hex(buf, n, out); free(buf); return;
		case 4: sha256_hex(o->out_w1(c->mst), o->out_w1_len, out); return;
		}
	} else {
		const stg_slh_ops *o = c->sops; size_t n; const uint8_t *b = NULL;
		switch (i) {
		case 0: b = o->out_digest(c->sst, &n); break;
		case 1: b = o->out_fors(c->sst, &n); break;
		case 2: b = o->out_wots(c->sst, &n); break;
		case 3: b = o->out_roots(c->sst, &n); break;
		}
		sha256_hex(b, n, out);
	}
}

/* ---- painted-stack thread -------------------------------------------- */

#define PAINT_SIZE (16u << 20)
#define PAINT_BYTE 0xA5
static uint8_t *g_paint = NULL;
static size_t g_paint_baseline = 0;

typedef struct { void (*fn)(void *); void *arg; uint8_t *sp_top; } paint_job_t;
/* glibc's thread start code dirties stack below our frame before calling us,
 * so the trampoline re-paints everything below its own frame (minus a safety
 * margin) and records its stack pointer; the high-water mark is measured
 * from there. */
static void *paint_tramp(void *a) {
	paint_job_t *j = a;
	volatile uint8_t anchor = 0;
	uint8_t *sp = (uint8_t *)&anchor;
	j->sp_top = sp;
	if (sp - 256 > g_paint) memset(g_paint, PAINT_BYTE, (size_t)(sp - 256 - g_paint));
	j->fn(j->arg);
	(void)anchor;
	return NULL;
}

/* run fn(arg) on a freshly painted private stack and return the high-water mark (bytes) */
static size_t painted_run_raw(void (*fn)(void *), void *arg) {
	if (!g_paint) {
		g_paint = mmap(NULL, PAINT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (g_paint == MAP_FAILED) die("mmap stack");
	}
	memset(g_paint, PAINT_BYTE, PAINT_SIZE);
	pthread_attr_t at; pthread_t th; paint_job_t j = {fn, arg};
	pthread_attr_init(&at);
	pthread_attr_setstack(&at, g_paint, PAINT_SIZE);
	if (pthread_create(&th, &at, paint_tramp, &j)) die("pthread_create (painted)");
	pthread_join(th, NULL);
	pthread_attr_destroy(&at);
	size_t i = 0;
	while (i < PAINT_SIZE && g_paint[i] == PAINT_BYTE) i++;
	uint8_t *low = g_paint + i;
	return low < j.sp_top ? (size_t)(j.sp_top - low) : 0; /* touched bytes below the trampoline frame */
}
static void noop_fn(void *a) { (void)a; }
static size_t painted_run(void (*fn)(void *), void *arg) {
	if (!g_paint_baseline) {
		size_t b = (size_t)-1;
		for (int k = 0; k < 3; k++) { size_t x = painted_run_raw(noop_fn, NULL); if (x < b) b = x; }
		g_paint_baseline = b;
	}
	size_t used = painted_run_raw(fn, arg);
	return used > g_paint_baseline ? used - g_paint_baseline : 0;
}

/* ---- memory: heap counters from memhook.c ------------------------------ */
extern size_t mh_live, mh_peak, mh_total, mh_calls;
extern int mh_enabled;
extern void mh_reset(void);

/* ---- validate -------------------------------------------------------- */

typedef struct {
	char id[160], kind[16], param[40];
	uint8_t *ctx, *f1, *f2, *f3; size_t ctxlen, l1, l2, l3;
	int expect;
} vcase_t;

typedef struct {
	const param_t *p; path_t path; const vcase_t *c;
	const char *pipeline; stg_mode_t mode;
	int got, ok; char err[96];
} vjob_t;

static void vjob_run(void *arg) {
	vjob_t *j = arg; const param_t *p = j->p; const vcase_t *c = j->c;
	j->ok = 0; j->got = -1; j->err[0] = 0;
	if (!strcmp(c->kind, "keygen")) {
		if (c->l1 != p->seed_len) { snprintf(j->err, sizeof j->err, "seed length %zu", c->l1); return; }
		param_t q = *p; q.seed = c->f1; q.seed_len = c->l1;   /* direct path takes the seed from the param */
		uint8_t *pk = malloc(p->sig->length_public_key), *sk = malloc(p->sig->length_secret_key);
		rng_set(c->f1, c->l1);
		int r = do_keygen(&q, j->path, pk, sk);
		j->got = r && c->l2 == p->sig->length_public_key && c->l3 == p->sig->length_secret_key &&
		         !memcmp(pk, c->f2, c->l2) && !memcmp(sk, c->f3, c->l3);
		if (!r) snprintf(j->err, sizeof j->err, "keygen returned error");
		j->ok = j->got == 1;
		free(pk); free(sk);
	} else if (!strcmp(c->kind, "siggen")) {
		if (c->l1 != p->sig->length_secret_key) { snprintf(j->err, sizeof j->err, "sk length %zu", c->l1); return; }
		uint8_t *sig = malloc(p->sig->length_signature); size_t siglen = 0;
		if (p->fam == FAM_MLDSA) rng_set(ZERO32, 32);
		else { size_t n = p->sig->length_public_key / 2; rng_set(c->f1 + 2 * n, n); }
		int r = do_sign_ctx(p, j->path, sig, &siglen, c->f1, c->f2, c->l2, c->ctx, c->ctxlen);
		j->got = r && siglen == c->l3 && !memcmp(sig, c->f3, c->l3);
		if (!r) snprintf(j->err, sizeof j->err, "sign returned error");
		j->ok = j->got == 1;
		free(sig);
	} else { /* sigver: f1 = pk, f2 = msg, f3 = sig */
		if (c->l1 != p->sig->length_public_key) { j->got = 0; snprintf(j->err, sizeof j->err, "pk length %zu rejected by driver", c->l1); }
		else if (!j->pipeline) j->got = do_verify_ctx(p, j->path, c->f3, c->l3, c->f1, c->f2, c->l2, c->ctx, c->ctxlen) ? 1 : 0;
		else {
			stage_ctx_t sc; stage_ctx_init(&sc, p, j->mode, c->f1, c->l1, c->f3, c->l3, c->f2, c->l2, c->ctx, c->ctxlen);
			j->got = run_pipeline(&sc) ? 1 : 0;
			stage_ctx_free(&sc);
		}
		j->ok = j->got == c->expect;
	}
}

static void *vjob_thread(void *a) { vjob_run(a); return NULL; }

static int cmd_validate(const char *cases_path, int argc, char **argv) {
	path_t path = PATH_API; int threads = 1; const char *pipeline = NULL; const char *modestr = NULL; const char *variant = "?";
	const char *skip_kind = NULL; const char *skip_params = NULL;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--path") && i + 1 < argc) path = !strcmp(argv[++i], "direct") ? PATH_DIRECT : PATH_API;
		else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--pipeline") && i + 1 < argc) pipeline = argv[++i];
		else if (!strcmp(argv[i], "--mode") && i + 1 < argc) modestr = argv[++i];
		else if (!strcmp(argv[i], "--variant") && i + 1 < argc) variant = argv[++i];
		else if (!strcmp(argv[i], "--sha3") && i + 1 < argc) select_sha3(argv[++i]);
		else if (!strcmp(argv[i], "--skip-kind") && i + 1 < argc) skip_kind = argv[++i];
		else if (!strcmp(argv[i], "--skip-params") && i + 1 < argc) skip_params = argv[++i];
		else { fprintf(stderr, "validate: unknown option %s\n", argv[i]); return 2; }
	}
	const char *kind_for_variant = !strncmp(variant, "keygen", 6) ? "keygen" : !strncmp(variant, "sign", 4) ? "siggen" : "sigver";
	stg_mode_t mode = parse_mode(modestr);
	FILE *f = fopen(cases_path, "r");
	if (!f) die("cannot open cases");
	char *line = NULL; size_t cap = 0;
	while (getline(&line, &cap, f) > 0) {
		vcase_t c; memset(&c, 0, sizeof c);
		char *save = NULL, *tok = strtok_r(line, " \t\r\n", &save);
		if (!tok || strcmp(tok, "case")) continue;
		snprintf(c.id, sizeof c.id, "%s", strtok_r(NULL, " \t\r\n", &save));
		snprintf(c.kind, sizeof c.kind, "%s", strtok_r(NULL, " \t\r\n", &save));
		snprintf(c.param, sizeof c.param, "%s", strtok_r(NULL, " \t\r\n", &save));
		if (strcmp(c.kind, kind_for_variant)) continue;
		c.ctxlen = unhex(strtok_r(NULL, " \t\r\n", &save), &c.ctx);
		c.l1 = unhex(strtok_r(NULL, " \t\r\n", &save), &c.f1);
		c.l2 = unhex(strtok_r(NULL, " \t\r\n", &save), &c.f2);
		c.l3 = unhex(strtok_r(NULL, " \t\r\n", &save), &c.f3);
		char *e = strtok_r(NULL, " \t\r\n", &save);
		c.expect = e ? atoi(e) : 1;
		const param_t *p = find_param(c.param);
		if (p && ((skip_kind && !strcmp(skip_kind, c.kind) && skip_params && in_list(skip_params, c.param)))) {
			/* handled by another binary (family split of total_best): not reported here */
		} else if (p && !(pipeline && p->fam == FAM_FALCON)) {
			int ok = 1, got = -1; char err[96] = "";
			if (threads <= 1) {
				vjob_t j = {p, path, &c, pipeline, mode, -1, 0, ""};
				vjob_run(&j); ok = j.ok; got = j.got; strcpy(err, j.err);
			} else {
				vjob_t *js = calloc(threads, sizeof *js); pthread_t *th = calloc(threads, sizeof *th);
				for (int t = 0; t < threads; t++) { js[t].p = p; js[t].path = path; js[t].c = &c; js[t].pipeline = pipeline; js[t].mode = mode; pthread_create(&th[t], NULL, vjob_thread, &js[t]); }
				for (int t = 0; t < threads; t++) { pthread_join(th[t], NULL); ok &= js[t].ok; if (t == 0) { got = js[t].got; strcpy(err, js[t].err); } else if (js[t].got != got) { ok = 0; snprintf(err, sizeof err, "threads disagree"); } }
				free(js); free(th);
			}
			printf("%s %s %s %d %s\n", c.id, variant, ok ? "pass" : "fail", got, err[0] ? err : "-");
		}
		free(c.ctx); free(c.f1); free(c.f2); free(c.f3);
	}
	free(line); fclose(f);
	return 0;
}

/* ---- stages ---------------------------------------------------------- */

typedef struct { stage_ctx_t *c; int i; } stage_job_t;
static void stage_job_fn(void *a) { stage_job_t *j = a; run_stage_i(j->c, j->i); }
typedef struct { stage_ctx_t *c; int ok; } pipe_job_t;
static void pipe_job_fn(void *a) { pipe_job_t *j = a; j->ok = run_pipeline(j->c); }

static const char *ref_lookup(const char *refs, const char *param) {
	/* refs = "param=sha,param=sha" */
	static char out[65];
	if (!refs) return NULL;
	const char *s = refs; size_t n = strlen(param);
	while (*s) {
		const char *e = strchr(s, ','); size_t l = e ? (size_t)(e - s) : strlen(s);
		if (l > n + 1 && !strncmp(s, param, n) && s[n] == '=') { snprintf(out, sizeof out, "%.*s", (int)(l - n - 1), s + n + 1); return out; }
		if (!e) break; s = e + 1;
	}
	return NULL;
}

static void emit_stage_line(const bench_cfg_t *cfg, const param_t *p, const char *stage, uint64_t *samp, size_t nsamp,
                            uint64_t total_ops, uint64_t wall_total, uint64_t cpu_total, const char *out_sha, int match) {
	qsort(samp, nsamp, sizeof *samp, cmp_u64);
	long double mean = 0; for (size_t i = 0; i < nsamp; i++) mean += samp[i]; mean /= nsamp ? nsamp : 1;
	printf("{\"lib\":\"liboqs\",\"lib_version\":\"%s\",\"lang\":\"c\",\"runtime\":\"", cfg->lib_version); json_escape(cfg->runtime, stdout);
	printf("\",\"family\":\"%s\",\"stage\":\"%s\",\"variant\":\"%s\",\"variant_name\":\"%s\",\"variant_desc\":\"",
	       p->fam == FAM_MLDSA ? "ml-dsa" : "slh-dsa", stage, cfg->variant, cfg->variant_name); json_escape(cfg->variant_desc, stdout);
	printf("\",\"param\":\"%s\",\"iterations\":%llu,\"wall_ns_median\":%llu,\"wall_ns_mean\":%.0Lf,\"wall_ns_p95\":%llu,\"wall_ns_min\":%llu,"
	       "\"cpu_ns_per_op\":%.0f,\"cpu_util\":%.3f,\"ops_per_sec\":%.3f,\"threads\":1,\"output_sha256\":\"%s\",\"match\":%s}\n",
	       p->name, (unsigned long long)total_ops, (unsigned long long)(nsamp ? samp[nsamp / 2] : 0), mean,
	       (unsigned long long)(nsamp ? samp[(size_t)((nsamp - 1) * 0.95)] : 0), (unsigned long long)(nsamp ? samp[0] : 0),
	       (double)cpu_total / (double)(total_ops ? total_ops : 1), wall_total ? (double)cpu_total / wall_total : 0.0,
	       wall_total ? (double)total_ops * 1e9 / wall_total : 0.0, out_sha, match ? "true" : "false");
	fflush(stdout);
}

static int cmd_stages(int argc, char **argv) {
	bench_cfg_t cfg = { OQS_VERSION_TEXT, "c", "liboqs", "x.v0", "baseline", "", 1, PATH_API, 1000 };
	const char *params = NULL, *stage = NULL, *modestr = NULL, *refs = NULL, *family = NULL;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--budget-ms") && i + 1 < argc) cfg.budget_ms = strtoull(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--params") && i + 1 < argc) params = argv[++i];
		else if (!strcmp(argv[i], "--stage") && i + 1 < argc) stage = argv[++i];
		else if (!strcmp(argv[i], "--mode") && i + 1 < argc) modestr = argv[++i];
		else if (!strcmp(argv[i], "--ref") && i + 1 < argc) refs = argv[++i];
		else if (!strcmp(argv[i], "--family") && i + 1 < argc) family = argv[++i];
		else if (!strcmp(argv[i], "--variant") && i + 1 < argc) cfg.variant = argv[++i];
		else if (!strcmp(argv[i], "--variant-name") && i + 1 < argc) cfg.variant_name = argv[++i];
		else if (!strcmp(argv[i], "--variant-desc") && i + 1 < argc) cfg.variant_desc = argv[++i];
		else if (!strcmp(argv[i], "--runtime") && i + 1 < argc) cfg.runtime = argv[++i];
		else if (!strcmp(argv[i], "--sha3") && i + 1 < argc) select_sha3(argv[++i]);
		else { fprintf(stderr, "stages: unknown option %s\n", argv[i]); return 2; }
	}
	if (!stage) { fprintf(stderr, "stages: --stage required\n"); return 2; }
	stg_mode_t mode = parse_mode(modestr);
	int is_total = !strcmp(stage, "total") || !strcmp(stage, "total_best");
	for (int pi = 0; pi < g_nparams; pi++) {
		const param_t *p = &g_params[pi];
		if (p->fam == FAM_FALCON) continue;
		if (!in_list(params, p->name)) continue;
		if (family && strcmp(family, p->fam == FAM_MLDSA ? "ml-dsa" : "slh-dsa")) continue;
		int si = is_total ? -1 : stage_index(p, stage);
		if (!is_total && si < 0) continue;
		material_t m; make_material(p, &m);
		stage_ctx_t c; stage_ctx_init(&c, p, mode, m.pk, m.pklen, m.sig, m.siglen, g_msg, g_msg_len, NULL, 0);
		/* reference pipeline (library backend, default modes) for the in-process match check */
		stg_mode_t m0 = {0, 0};
		stage_ctx_t r; stage_ctx_init(&r, p, m0, m.pk, m.pklen, m.sig, m.siglen, g_msg, g_msg_len, NULL, 0);
		int ref_ok = run_pipeline(&r);
		char ref_sha[65] = "", out_sha[65] = "";
		int match = ref_ok;
		size_t cap = 100000, nsamp = 0; uint64_t *samp = malloc(cap * sizeof *samp);
		uint64_t total_ops = 0, wall0, wall_end, cpu0, cpu1;
		if (is_total) {
			/* warm-up (also warms caches of cached variants), then check true / tampered-false */
			pipe_job_t j = {&c, 0};
			pipe_job_fn(&j); int t_ok = j.ok;
			uint8_t *bad = malloc(m.siglen); memcpy(bad, m.sig, m.siglen); bad[m.siglen / 2] ^= 1;
			stage_ctx_t cb; stage_ctx_init(&cb, p, mode, m.pk, m.pklen, bad, m.siglen, g_msg, g_msg_len, NULL, 0);
			int rej = !run_pipeline(&cb); stage_ctx_free(&cb); free(bad);
			match = t_ok && rej;
			strcpy(out_sha, match ? "true" : "false");
			uint64_t budget = cfg.budget_ms * 1000000ull;
			cpu0 = cpu_ns(); wall0 = now_ns(); wall_end = wall0;
			for (;;) {
				uint64_t a = now_ns(); pipe_job_fn(&j); uint64_t d = now_ns() - a;
				if (!j.ok) match = 0;
				if (nsamp < cap) samp[nsamp++] = d; total_ops++;
				wall_end = now_ns();
				if (total_ops >= 100000 || (wall_end - wall0 >= budget && total_ops >= 3)) break;
			}
			cpu1 = cpu_ns();
		} else {
			/* prepare inputs: run the pipeline once with this variant (fills state, warms caches) */
			if (!run_pipeline(&c)) match = 0;
			stage_output_sha(&r, si, ref_sha);
			stage_job_t j = {&c, si};
			stage_job_fn(&j);
			stage_output_sha(&c, si, out_sha);
			if (strcmp(out_sha, ref_sha)) match = 0;
			const char *rv = ref_lookup(refs, p->name);
			if (rv && strcmp(rv, out_sha)) match = 0;
			uint64_t budget = cfg.budget_ms * 1000000ull;
			cpu0 = cpu_ns(); wall0 = now_ns(); wall_end = wall0;
			for (;;) {
				uint64_t a = now_ns(); stage_job_fn(&j); uint64_t d = now_ns() - a;
				if (nsamp < cap) samp[nsamp++] = d; total_ops++;
				wall_end = now_ns();
				if (total_ops >= 100000 || (wall_end - wall0 >= budget && total_ops >= 3)) break;
			}
			cpu1 = cpu_ns();
			char again[65]; stage_output_sha(&c, si, again);
			if (strcmp(again, out_sha)) match = 0;
		}
		emit_stage_line(&cfg, p, stage, samp, nsamp, total_ops, wall_end - wall0, cpu1 - cpu0, out_sha, match);
		free(samp); stage_ctx_free(&c); stage_ctx_free(&r); free(m.pk); free(m.sk); free(m.sig);
	}
	return 0;
}

/* ---- memory ---------------------------------------------------------- */

typedef struct { job_t *j; int ok; } mem_job_t;
static void mem_job_fn(void *a) { mem_job_t *m = a; m->ok = run_once(m->j); m->j->ok = m->ok; }

static int cmd_memory(int argc, char **argv) {
	const char *params = NULL, *op = "verify", *stage = NULL, *modestr = NULL, *variant = "?", *family = NULL;
	path_t path = PATH_API; int threads = 1;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--params") && i + 1 < argc) params = argv[++i];
		else if (!strcmp(argv[i], "--op") && i + 1 < argc) op = argv[++i];
		else if (!strcmp(argv[i], "--stage") && i + 1 < argc) stage = argv[++i];
		else if (!strcmp(argv[i], "--mode") && i + 1 < argc) modestr = argv[++i];
		else if (!strcmp(argv[i], "--variant") && i + 1 < argc) variant = argv[++i];
		else if (!strcmp(argv[i], "--path") && i + 1 < argc) path = !strcmp(argv[++i], "direct") ? PATH_DIRECT : PATH_API;
		else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--sha3") && i + 1 < argc) select_sha3(argv[++i]);
		else if (!strcmp(argv[i], "--family") && i + 1 < argc) family = argv[++i];
		else { fprintf(stderr, "memory: unknown option %s\n", argv[i]); return 2; }
	}
	stg_mode_t mode = parse_mode(modestr);
	for (int pi = 0; pi < g_nparams; pi++) {
		const param_t *p = &g_params[pi];
		if (!in_list(params, p->name)) continue;
		if (stage && p->fam == FAM_FALCON) continue;
		if (family && strcmp(family, p->fam == FAM_MLDSA ? "ml-dsa" : p->fam == FAM_SLHDSA ? "slh-dsa" : "falcon")) continue;
		material_t m; make_material(p, &m);
		size_t stack = 0, heap_total = 0, heap_peak = 0; int match = 0;
		if (!stage) {
			job_t j = {0}; j.p = p; j.op = op; j.path = path; j.m = &m; j.ops_per_thread = 1;
			j.pk = malloc(p->sig->length_public_key); j.sk = malloc(p->sig->length_secret_key); j.sig = malloc(p->sig->length_signature);
			rng_prepare(p, op, m.sk);
			mem_job_t mj = {&j, 0};
			mem_job_fn(&mj);                       /* warm-up (one-time lazy init inside liboqs happens here) */
			mh_reset(); mh_enabled = 1;
			stack = painted_run(mem_job_fn, &mj);
			mh_enabled = 0; heap_total = mh_total; heap_peak = mh_peak;
			char sha[65]; match = job_output_matches(&j, sha);
			if (!strcmp(op, "verify")) {
				uint8_t *bad = malloc(m.siglen); memcpy(bad, m.sig, m.siglen); bad[m.siglen / 2] ^= 1;
				if (do_verify(p, path, bad, m.siglen, m.pk)) match = 0; free(bad);
			}
			free(j.pk); free(j.sk); free(j.sig);
		} else {
			int is_total = !strcmp(stage, "total") || !strcmp(stage, "total_best");
			int si = is_total ? -1 : stage_index(p, stage);
			if (!is_total && si < 0) { free(m.pk); free(m.sk); free(m.sig); continue; }
			stage_ctx_t c; stage_ctx_init(&c, p, mode, m.pk, m.pklen, m.sig, m.siglen, g_msg, g_msg_len, NULL, 0);
			match = run_pipeline(&c);           /* fills inputs, warms caches */
			if (is_total) {
				pipe_job_t j = {&c, 0};
				mh_reset(); mh_enabled = 1; stack = painted_run(pipe_job_fn, &j); mh_enabled = 0;
				match = match && j.ok;
			} else {
				stg_mode_t m0 = {0, 0}; stage_ctx_t r; stage_ctx_init(&r, p, m0, m.pk, m.pklen, m.sig, m.siglen, g_msg, g_msg_len, NULL, 0);
				run_pipeline(&r); char a[65], b[65]; stage_output_sha(&r, si, a);
				stage_job_t j = {&c, si};
				mh_reset(); mh_enabled = 1; stack = painted_run(stage_job_fn, &j); mh_enabled = 0;
				stage_output_sha(&c, si, b); match = match && !strcmp(a, b);
				stage_ctx_free(&r);
			}
			heap_total = mh_total; heap_peak = mh_peak;
			stage_ctx_free(&c);
		}
		printf("{\"lib\":\"liboqs\",\"variant\":\"%s\",\"op\":\"%s\",", variant, stage ? "verify-stage" : op);
		if (stage) printf("\"stage\":\"%s\",", stage);
		printf("\"param\":\"%s\",\"stack_bytes\":%zu,\"stack_method\":\"private pthread stack (16 MiB) re-painted with 0xA5 below the trampoline frame, high-water scan from that frame, minus the trampoline+call overhead of %zu B\","
		       "\"stack_resolution_bytes\":16,\"heap_alloc_bytes_per_op\":%zu,\"heap_peak_bytes\":%zu,"
		       "\"heap_method\":\"interposed malloc/calloc/realloc/memalign in the static binary (malloc_usable_size accounting)\",\"threads\":%d,\"match\":%s}\n",
		       p->name, stack, g_paint_baseline, heap_total, heap_peak, threads, match ? "true" : "false");
		fflush(stdout);
		free(m.pk); free(m.sk); free(m.sig);
	}
	return 0;
}
