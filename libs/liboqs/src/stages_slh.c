/*
 * SLH-DSA verify split into the canonical stages (FIPS 205 Alg. 20) on top of
 * liboqs's vendored slhdsa-c.
 *
 * slhdsa-c keeps fors_pk_from_sig / wots_pk_from_sig / xmss_pk_from_sig /
 * ht_verify static, so this translation unit #includes slh_dsa.c itself (the
 * unmodified vendored file of the flavour being built) with its ten global
 * functions renamed through -D flags (run.sh), which makes the static helpers
 * callable here while liboqs.a keeps its own copies. Hash primitives
 * (prm->h_msg, h_f, h_h, h_t, chain) are the library's, so e.g. the fasthash
 * flavour's OpenSSL/AVX2 primitives are picked up automatically.
 */
#include SLH_DSA_C_SOURCE   /* e.g. "/.../src/sig/slh_dsa/slh_dsa_c/slh_dsa.c" */

#include "stages.h"

#define STG_MAX_D 22

typedef struct {
	const slh_param_t *prm;
	slh_var_t var;
	const uint8_t *pk, *sig, *m, *ctx;
	size_t siglen, mlen, ctxlen;
	uint8_t digest[SLH_MAX_M];
	uint64_t i_tree; uint32_t i_leaf;
	uint8_t pk_fors[SLH_MAX_N];
	uint64_t tree_addr[STG_MAX_D]; uint32_t leaf[STG_MAX_D];
	uint8_t layer_msg[STG_MAX_D][SLH_MAX_N];   /* input message of each hypertree layer */
	uint8_t wots_pk[STG_MAX_D][SLH_MAX_N];
	uint8_t roots[STG_MAX_D][SLH_MAX_N];
	uint8_t wots_cat[STG_MAX_D * SLH_MAX_N], roots_cat[STG_MAX_D * SLH_MAX_N];
	int ok;
} sst_t;

static const uint8_t *sig_ht_of(const sst_t *st) {
	const slh_param_t *prm = st->prm;
	return st->sig + (1 + prm->k * (1 + prm->a)) * prm->n;
}
static size_t xmss_sig_sz(const slh_param_t *prm) { return (prm->hp + get_len(prm)) * prm->n; }

static int st_hmsg(void *vst, const slh_param_t *prm, const uint8_t *pk, size_t pklen, const uint8_t *sig, size_t siglen,
                   const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen) {
	sst_t *st = vst;
	st->prm = prm; st->pk = pk; st->sig = sig; st->siglen = siglen; st->m = m; st->mlen = mlen; st->ctx = ctx; st->ctxlen = ctxlen;
	st->ok = 0;
	if (ctxlen > 255 || pklen != slh_pk_sz(prm) || siglen != slh_sig_sz(prm) || prm->d > STG_MAX_D) return 0;
	prm->mk_var(&st->var, pk, NULL, prm);
	/* R = sig[0..n): H_msg(R, PK.seed, PK.root, M' = 0 || |ctx| || ctx || M) */
	prm->h_msg(&st->var, st->digest, sig, m, mlen, ctx, ctxlen);
	split_digest(&st->i_tree, &st->i_leaf, st->digest, prm);
	return 1;
}

static int st_fors(void *vst) {
	sst_t *st = vst;
	slh_var_t *var = &st->var;
	adrs_zero(var);
	adrs_set_tree_address(var, st->i_tree);
	adrs_set_type_and_clear_not_kp(var, ADRS_FORS_TREE);
	adrs_set_key_pair_address(var, st->i_leaf);
	fors_pk_from_sig(var, st->pk_fors, st->sig + st->prm->n, st->digest);
	return 1;
}

/* reference pass through the hypertree (slhdsa-c's own xmss_pk_from_sig),
 * recording every layer's address and input message; not timed */
static int st_prepare_layers(void *vst) {
	sst_t *st = vst;
	const slh_param_t *prm = st->prm;
	slh_var_t *var = &st->var;
	uint64_t t = st->i_tree; uint32_t l = st->i_leaf;
	const uint8_t *s = sig_ht_of(st);
	uint8_t node[SLH_MAX_N];
	memcpy(node, st->pk_fors, prm->n);
	for (uint32_t j = 0; j < prm->d; j++) {
		st->tree_addr[j] = t; st->leaf[j] = l;
		memcpy(st->layer_msg[j], node, prm->n);
		adrs_zero(var);
		adrs_set_layer_address(var, j);
		adrs_set_tree_address(var, t);
		xmss_pk_from_sig(var, node, l, s, node);
		s += xmss_sig_sz(prm);
		l = (uint32_t)(t & ((1u << prm->hp) - 1)); t >>= prm->hp;
	}
	return 1;
}

/* all d WOTS+ pkFromSig computations, each with its layer's correct input */
static int st_ht_wots(void *vst) {
	sst_t *st = vst;
	const slh_param_t *prm = st->prm;
	slh_var_t *var = &st->var;
	const uint8_t *s = sig_ht_of(st);
	for (uint32_t j = 0; j < prm->d; j++) {
		adrs_zero(var);
		adrs_set_layer_address(var, j);
		adrs_set_tree_address(var, st->tree_addr[j]);
		adrs_set_type_and_clear_not_kp(var, ADRS_WOTS_HASH);
		adrs_set_key_pair_address(var, st->leaf[j]);
		wots_pk_from_sig(var, st->wots_pk[j], s, st->layer_msg[j]);
		memcpy(st->wots_cat + j * prm->n, st->wots_pk[j], prm->n);
		s += xmss_sig_sz(prm);
	}
	return 1;
}

/* all d XMSS auth-path root computations from the WOTS+ pks, then the final compare */
static int st_ht_auth(void *vst) {
	sst_t *st = vst;
	const slh_param_t *prm = st->prm;
	slh_var_t *var = &st->var;
	size_t n = prm->n;
	const uint8_t *s = sig_ht_of(st);
	for (uint32_t j = 0; j < prm->d; j++) {
		uint8_t *root = st->roots[j];
		uint32_t idx = st->leaf[j];
		const uint8_t *auth = s + get_len(prm) * n;
		memcpy(root, st->wots_pk[j], n);
		adrs_zero(var);
		adrs_set_layer_address(var, j);
		adrs_set_tree_address(var, st->tree_addr[j]);
		adrs_set_type_and_clear_not_kp(var, ADRS_WOTS_HASH);
		adrs_set_key_pair_address(var, idx);
		adrs_set_type_and_clear(var, ADRS_TREE);
		for (uint32_t k = 0; k < prm->hp; k++) {
			adrs_set_tree_height(var, k + 1);
			adrs_set_tree_index(var, idx >> (k + 1));
			if (((idx >> k) & 1) == 0) prm->h_h(var, root, root, auth);
			else prm->h_h(var, root, auth, root);
			auth += n;
		}
		memcpy(st->roots_cat + j * n, root, n);
		s += xmss_sig_sz(prm);
	}
	st->ok = memcmp(st->roots[prm->d - 1], var->pk_root, n) == 0;
	return st->ok;
}

static const uint8_t *o_digest(void *vst, size_t *len) { sst_t *st = vst; *len = st->prm->m; return st->digest; }
static const uint8_t *o_fors(void *vst, size_t *len) { sst_t *st = vst; *len = st->prm->n; return st->pk_fors; }
static const uint8_t *o_wots(void *vst, size_t *len) { sst_t *st = vst; *len = st->prm->d * st->prm->n; return st->wots_cat; }
static const uint8_t *o_roots(void *vst, size_t *len) { sst_t *st = vst; *len = st->prm->d * st->prm->n; return st->roots_cat; }
static int o_ok(void *vst) { return ((sst_t *)vst)->ok; }

const stg_slh_ops stg_slh = {
	sizeof(sst_t), st_hmsg, st_fors, st_ht_wots, st_ht_auth, st_prepare_layers,
	o_digest, o_fors, o_wots, o_roots, o_ok,
};
