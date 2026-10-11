/* Verify stage split (phase 2 B) - API used by stages/validate/memory commands. */
#ifndef PQC_STAGES_H
#define PQC_STAGES_H
#include "pqc_common.h"

#define MAX_STAGES 5
#define SF_THREADS 1   /* parallel variant (excluded from total_best) */
#define SF_CACHE   2   /* uses per-public-key precomputation (excluded from total_best) */
#define SF_SHA2ONLY 4  /* only for SLH-DSA-SHA2 parameter sets */

typedef struct {
    int mldsa;          /* family */
    int sidx;           /* stage index within the family */
    int vidx;           /* variant number (0..5) */
    int method;         /* implementation selector passed to stage_run */
    int flags;
    const char *build;
    const char *name, *desc;
} stage_variant_t;

extern const stage_variant_t STAGE_VARIANTS[];
extern const size_t NSTAGE_VARIANTS;
extern const char *ML_STAGE_NAMES[5];
extern const char *SLH_STAGE_NAMES[4];
extern const int BEST_ML[5];
extern const int BEST_SLH[4];

typedef struct stage_ctx stage_ctx_t;

/* pk/sig/msg/ctx are borrowed. Returns NULL if pk has the wrong length. */
stage_ctx_t *stage_ctx_new(const param_t *p, const uint8_t *pk, size_t pk_len,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sig, size_t sig_len);
void stage_ctx_free(stage_ctx_t *s);
int stage_ctx_is_mldsa(const stage_ctx_t *s);
int stage_ctx_nstages(const stage_ctx_t *s);
const char *stage_ctx_stage_name(const stage_ctx_t *s, int sidx);
/* Runs the v0 implementation of every stage in order, storing the canonical
 * inputs/outputs for later stages. Returns the verify result (1 valid / 0 not). */
int stage_prepare(stage_ctx_t *s);
/* Runs one stage with the given method on the v0-produced inputs; writes the
 * canonical SHA-256 (hex) of its output. Returns 1 on success, 0 if the stage
 * reported failure/rejection. */
int stage_run(stage_ctx_t *s, int sidx, int method, char sha[65]);
/* Full verification pipeline with one method per stage. 1 = valid, 0 = invalid. */
int stage_pipeline(stage_ctx_t *s, const int *methods);
/* the method of variant v0 for stage sidx of the family */
int stage_v0_method(int mldsa, int sidx);
const stage_variant_t *stage_variant_find(int mldsa, int sidx, int vidx);

#endif
