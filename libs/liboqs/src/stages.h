/* Stage interfaces shared by bench.c, stages_mldsa.c and stages_slh.c */
#ifndef PQC_STAGES_H
#define PQC_STAGES_H
#include <stddef.h>
#include <stdint.h>

/* ---- ML-DSA -------------------------------------------------------- */
/* mode bits for the alternative implementations of a stage */
#define STG_MODE_OSSL    1u   /* SHAKE through OpenSSL EVP (mu, hint_check) */
#define STG_MODE_CACHED  2u   /* cached tr / A / NTT(t1*2^d) keyed by pk */
#define STG_MODE_ONEWAY  4u   /* expandA with 1-way SHAKE128 (mld_poly_uniform) */

typedef struct stg_mldsa_ops {
	const char *backend;      /* "x86_64" or "c" */
	int paramset;             /* 44 / 65 / 87 */
	size_t state_size;
	size_t out_expandA_len, out_w_len, out_w1_len, ctilde_len, mu_len;
	/* every stage returns 1 on success (0 = reject / malformed) */
	int (*decode)(void *st, const uint8_t *pk, size_t pklen, const uint8_t *sig, size_t siglen);
	int (*mu)(void *st, const uint8_t *pre, size_t prelen, const uint8_t *m, size_t mlen, unsigned mode);
	int (*expandA)(void *st, unsigned mode);
	int (*w_approx)(void *st, unsigned mode);
	int (*hint_check)(void *st, unsigned mode);
	/* canonical outputs (pointer into state, length in the fields above) */
	const uint8_t *(*out_ctilde)(void *st);
	const uint8_t *(*out_mu)(void *st);
	void (*out_expandA)(void *st, uint8_t *dst);   /* u32 LE, standard order, [0,q) */
	void (*out_w)(void *st, uint8_t *dst);         /* u32 LE, standard order, [0,q) */
	const uint8_t *(*out_w1)(void *st);
} stg_mldsa_ops;

/* ---- SLH-DSA ------------------------------------------------------- */
typedef struct slh_param_s slh_param_t;
typedef struct stg_slh_ops {
	size_t state_size;
	int (*hmsg)(void *st, const slh_param_t *prm, const uint8_t *pk, size_t pklen, const uint8_t *sig, size_t siglen,
	            const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen);
	int (*fors)(void *st);
	int (*ht_wots)(void *st);     /* needs layer inputs: call prepare_layers() first (untimed) */
	int (*ht_auth)(void *st);     /* needs wots pks: from ht_wots */
	int (*prepare_layers)(void *st); /* reference pass computing every layer's input message */
	/* canonical outputs */
	const uint8_t *(*out_digest)(void *st, size_t *len);
	const uint8_t *(*out_fors)(void *st, size_t *len);
	const uint8_t *(*out_wots)(void *st, size_t *len);
	const uint8_t *(*out_roots)(void *st, size_t *len);
	int (*ok)(void *st);
} stg_slh_ops;

extern const stg_slh_ops stg_slh;
#endif
