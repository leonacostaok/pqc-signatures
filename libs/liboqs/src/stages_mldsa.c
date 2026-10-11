/*
 * ML-DSA verify split into the canonical stages, built directly on the
 * vendored mldsa-native internals of liboqs. This file is compiled once per
 * (parameter set, backend) with the same -D / -I flags liboqs uses for the
 * corresponding object library, so the mld_* names resolve to the symbols in
 * liboqs.a (PQCP_MLDSA_NATIVE_MLDSA<NN>_<X86_64|C>_*).
 *
 * The stage bodies mirror mld_sign_verify_internal() in mldsa/src/sign.c
 * (same calls in the same order); alternatives are selected by `mode` bits.
 */
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>
#include <oqs/sha3.h>

#include "mldsa/src/common.h"
#include "mldsa/src/params.h"
#include "mldsa/src/poly.h"
#include "mldsa/src/poly_kl.h"
#include "mldsa/src/polyvec.h"
#include "mldsa/src/polyvec_lazy.h"
#include "mldsa/src/packing.h"
#include "mldsa/src/ct.h"

#include "stages.h"

#define PURE_MAX_PRE (2 + 255)

typedef struct {
	/* inputs */
	const uint8_t *pk, *sig;
	size_t siglen;
	uint8_t pre[PURE_MAX_PRE]; size_t prelen;
	const uint8_t *m; size_t mlen;
	/* decode */
	uint8_t c[MLDSA_CTILDEBYTES];
	MLD_ALIGN mld_polyvecl z_raw;            /* normal domain, as decoded */
	MLD_ALIGN mld_poly t1[MLDSA_K];
	MLD_ALIGN mld_poly h[MLDSA_K];
	/* mu */
	uint8_t mu[MLDSA_CRHBYTES];
	/* expandA */
	MLD_ALIGN mld_polymat mat;
	/* w_approx */
	MLD_ALIGN mld_poly w[MLDSA_K];           /* w' = invNTT(A z - c t1 2^d), [0,q) */
	/* hint_check */
	uint8_t w1buf[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES];
	int ok;
	/* caches (keyed by pk contents) */
	uint8_t cache_pk[MLDSA_CRYPTO_PUBLICKEYBYTES];
	int tr_valid, mat_valid, t1hat_valid;
	uint8_t tr[MLDSA_TRBYTES];
	MLD_ALIGN mld_polymat mat_cache;
	MLD_ALIGN mld_poly t1hat[MLDSA_K];
	/* standard-order permutation of the backend's NTT-domain layout */
	uint16_t perm[MLDSA_N];
	int perm_ready;
} st_t;

/* ---- helpers ------------------------------------------------------- */

static void shake256_lib(uint8_t *out, size_t outlen, const uint8_t *a, size_t al,
                         const uint8_t *b, size_t bl, const uint8_t *c, size_t cl) {
	/* identical to mld_H(): liboqs incremental SHAKE256 (fips202 glue) */
	OQS_SHA3_shake256_inc_ctx s;
	OQS_SHA3_shake256_inc_init(&s);
	OQS_SHA3_shake256_inc_absorb(&s, a, al);
	if (bl) OQS_SHA3_shake256_inc_absorb(&s, b, bl);
	if (cl) OQS_SHA3_shake256_inc_absorb(&s, c, cl);
	OQS_SHA3_shake256_inc_finalize(&s);
	OQS_SHA3_shake256_inc_squeeze(out, outlen, &s);
	OQS_SHA3_shake256_inc_ctx_release(&s);
}

static void shake256_ossl(uint8_t *out, size_t outlen, const uint8_t *a, size_t al,
                          const uint8_t *b, size_t bl, const uint8_t *c, size_t cl) {
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
	EVP_DigestUpdate(ctx, a, al);
	if (bl) EVP_DigestUpdate(ctx, b, bl);
	if (cl) EVP_DigestUpdate(ctx, c, cl);
	EVP_DigestFinalXOF(ctx, out, outlen);
	EVP_MD_CTX_free(ctx);
}

/* Derive, once, where standard coefficient i lives in the backend's NTT-domain
 * layout (the x86_64 backend keeps NTT-domain polys in a custom lane order;
 * the C backend's permutation is the identity). The permutation only moves
 * int32 lanes, so feeding 0..255 through it reveals it exactly. */
static void init_perm(st_t *st) {
	MLD_ALIGN mld_poly p;
	for (int i = 0; i < MLDSA_N; i++) p.coeffs[i] = i;
	mld_poly_permute_bitrev_to_custom_optional(&p);
	for (int j = 0; j < MLDSA_N; j++) st->perm[p.coeffs[j]] = (uint16_t)j;
	st->perm_ready = 1;
}

static int cache_key_ok(st_t *st) { return memcmp(st->cache_pk, st->pk, MLDSA_CRYPTO_PUBLICKEYBYTES) == 0; }
static void cache_key_set(st_t *st) {
	if (!cache_key_ok(st)) { memcpy(st->cache_pk, st->pk, MLDSA_CRYPTO_PUBLICKEYBYTES); st->tr_valid = st->mat_valid = st->t1hat_valid = 0; }
}

/* ---- stages -------------------------------------------------------- */

static int s_decode(void *vst, const uint8_t *pk, size_t pklen, const uint8_t *sig, size_t siglen) {
	st_t *st = vst;
	if (!st->perm_ready) init_perm(st);
	if (pklen != MLDSA_CRYPTO_PUBLICKEYBYTES || siglen != MLDSA_CRYPTO_BYTES) return 0;
	st->pk = pk; st->sig = sig; st->siglen = siglen;
	/* sigDecode: c~, z, h (hint validity checked by mld_sig_unpack_hints) */
	memcpy(st->c, sig, MLDSA_CTILDEBYTES);
	mld_polyvecl_unpack_z(&st->z_raw, sig + MLDSA_CTILDEBYTES);
	for (unsigned i = 0; i < MLDSA_K; i++) {
		mld_unpack_pk_t1(&st->t1[i], pk, i);                 /* pkDecode: t1 (rho stays in pk) */
		if (mld_sig_unpack_hints(&st->h[i], sig, i) != 0) return 0;
	}
	return 1;
}

static int s_mu(void *vst, const uint8_t *pre, size_t prelen, const uint8_t *m, size_t mlen, unsigned mode) {
	st_t *st = vst;
	if (prelen > PURE_MAX_PRE) return 0;
	memcpy(st->pre, pre, prelen); st->prelen = prelen; st->m = m; st->mlen = mlen;
	void (*H)(uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t) =
	    (mode & STG_MODE_OSSL) ? shake256_ossl : shake256_lib;
	uint8_t tr[MLDSA_TRBYTES];
	if (mode & STG_MODE_CACHED) {
		cache_key_set(st);
		if (!st->tr_valid) { H(st->tr, MLDSA_TRBYTES, st->pk, MLDSA_CRYPTO_PUBLICKEYBYTES, NULL, 0, NULL, 0); st->tr_valid = 1; }
		memcpy(tr, st->tr, MLDSA_TRBYTES);
	} else {
		H(tr, MLDSA_TRBYTES, st->pk, MLDSA_CRYPTO_PUBLICKEYBYTES, NULL, 0, NULL, 0);
	}
	H(st->mu, MLDSA_CRHBYTES, tr, MLDSA_TRBYTES, pre, prelen, m, mlen);
	return 1;
}

static int s_expandA(void *vst, unsigned mode) {
	st_t *st = vst;
	if (mode & STG_MODE_CACHED) {
		cache_key_set(st);
		if (!st->mat_valid) { mld_polyvec_matrix_expand(&st->mat_cache, st->pk); st->mat_valid = 1; }
		memcpy(&st->mat, &st->mat_cache, sizeof st->mat);
		return 1;
	}
	if (mode & STG_MODE_ONEWAY) {
		/* one SHAKE128 stream per matrix entry (reference ExpandA), same rej. sampler */
		MLD_ALIGN uint8_t seed[MLDSA_SEEDBYTES + 2];
		memcpy(seed, st->pk, MLDSA_SEEDBYTES);
		for (unsigned i = 0; i < MLDSA_K; i++)
			for (unsigned j = 0; j < MLDSA_L; j++) {
				unsigned nonce = (i << 8) + j;
				seed[MLDSA_SEEDBYTES] = (uint8_t)nonce; seed[MLDSA_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);
				mld_poly_uniform(&st->mat.vec[i].vec[j], seed);
				mld_poly_permute_bitrev_to_custom_optional(&st->mat.vec[i].vec[j]);
			}
		return 1;
	}
	mld_polyvec_matrix_expand(&st->mat, st->pk);   /* liboqs: 4-way SHAKE128 */
	return 1;
}

static int s_w_approx(void *vst, unsigned mode) {
	st_t *st = vst;
	MLD_ALIGN mld_polyvecl z;
	MLD_ALIGN mld_poly cp, tmp;
	memcpy(&z, &st->z_raw, sizeof z);
	mld_polyvecl_ntt(&z);
	mld_poly_challenge(&cp, st->c);
	mld_poly_ntt(&cp);
	int cached = (mode & STG_MODE_CACHED) != 0;
	if (cached) {
		cache_key_set(st);
		if (!st->t1hat_valid) {
			for (unsigned i = 0; i < MLDSA_K; i++) { st->t1hat[i] = st->t1[i]; mld_poly_shiftl(&st->t1hat[i]); mld_poly_ntt(&st->t1hat[i]); }
			st->t1hat_valid = 1;
		}
	}
	for (unsigned i = 0; i < MLDSA_K; i++) {
		mld_poly *w1 = &st->w[i];
		mld_polyvec_matrix_pointwise_montgomery_row(w1, &st->mat, &z, i);
		if (cached) tmp = st->t1hat[i];
		else { tmp = st->t1[i]; mld_poly_shiftl(&tmp); mld_poly_ntt(&tmp); }
		mld_poly_pointwise_montgomery(&tmp, &cp);
		mld_poly_sub(w1, &tmp);
		mld_poly_reduce(w1);
		mld_poly_invntt_tomont(w1);
		mld_poly_caddq(w1);
	}
	return 1;
}

static int s_hint_check(void *vst, unsigned mode) {
	st_t *st = vst;
	uint8_t c2[MLDSA_CTILDEBYTES];
	st->ok = 0;
	if (mld_polyvecl_chknorm(&st->z_raw, MLDSA_GAMMA1 - MLDSA_BETA)) return 0;
	for (unsigned i = 0; i < MLDSA_K; i++) {
		MLD_ALIGN mld_poly w1 = st->w[i];
		mld_poly_use_hint(&w1, &st->h[i]);
		mld_polyw1_pack(st->w1buf + i * MLDSA_POLYW1_PACKEDBYTES, &w1);
	}
	if (mode & STG_MODE_OSSL)
		shake256_ossl(c2, MLDSA_CTILDEBYTES, st->mu, MLDSA_CRHBYTES, st->w1buf, sizeof st->w1buf, NULL, 0);
	else
		shake256_lib(c2, MLDSA_CTILDEBYTES, st->mu, MLDSA_CRHBYTES, st->w1buf, sizeof st->w1buf, NULL, 0);
	st->ok = mld_ct_memcmp(st->c, c2, MLDSA_CTILDEBYTES) == 0;
	return st->ok;
}

/* ---- canonical outputs --------------------------------------------- */

static const uint8_t *o_ctilde(void *vst) { return ((st_t *)vst)->c; }
static const uint8_t *o_mu(void *vst) { return ((st_t *)vst)->mu; }
static const uint8_t *o_w1(void *vst) { return ((st_t *)vst)->w1buf; }

static void put_poly(const st_t *st, const mld_poly *p, int permuted, uint8_t *dst) {
	for (int i = 0; i < MLDSA_N; i++) {
		int32_t v = p->coeffs[permuted ? st->perm[i] : i];
		v %= MLDSA_Q; if (v < 0) v += MLDSA_Q;
		uint32_t u = (uint32_t)v;
		dst[4 * i] = (uint8_t)u; dst[4 * i + 1] = (uint8_t)(u >> 8); dst[4 * i + 2] = (uint8_t)(u >> 16); dst[4 * i + 3] = (uint8_t)(u >> 24);
	}
}
static void o_expandA(void *vst, uint8_t *dst) {
	st_t *st = vst;
	for (unsigned i = 0; i < MLDSA_K; i++)
		for (unsigned j = 0; j < MLDSA_L; j++) put_poly(st, &st->mat.vec[i].vec[j], 1, dst + ((i * MLDSA_L) + j) * 4 * MLDSA_N);
}
static void o_w(void *vst, uint8_t *dst) {
	st_t *st = vst;
	for (unsigned i = 0; i < MLDSA_K; i++) put_poly(st, &st->w[i], 0, dst + i * 4 * MLDSA_N);
}

const stg_mldsa_ops STG_NAME = {
	STG_BACKEND_NAME, MLD_CONFIG_PARAMETER_SET, sizeof(st_t),
	(size_t)MLDSA_K * MLDSA_L * 4 * MLDSA_N, (size_t)MLDSA_K * 4 * MLDSA_N, (size_t)MLDSA_K * MLDSA_POLYW1_PACKEDBYTES,
	MLDSA_CTILDEBYTES, MLDSA_CRHBYTES,
	s_decode, s_mu, s_expandA, s_w_approx, s_hint_check,
	o_ctilde, o_mu, o_expandA, o_w, o_w1,
};
