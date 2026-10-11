/*
 * Heap accounting by interposing the allocator entry points in the (statically
 * linked) driver: every malloc-family call in liboqs, OpenSSL and the driver
 * itself goes through here. Sizes are taken from malloc_usable_size() on both
 * the allocation and the free side so the two always agree.
 */
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);
extern void __libc_free(void *);

/* plain (non-atomic) counters: the memory subcommand measures single-threaded */
size_t mh_live = 0, mh_peak = 0, mh_total = 0, mh_calls = 0;
int mh_enabled = 0;

static inline void acct_alloc(void *p) {
	if (!mh_enabled || !p) return;
	size_t n = malloc_usable_size(p);
	mh_live += n; mh_total += n; mh_calls++;
	if (mh_live > mh_peak) mh_peak = mh_live;
}
static inline void acct_free(void *p) {
	if (!mh_enabled || !p) return;
	size_t n = malloc_usable_size(p);
	mh_live = n > mh_live ? 0 : mh_live - n;
}

void mh_reset(void) { mh_live = 0; mh_peak = 0; mh_total = 0; mh_calls = 0; }

void *malloc(size_t n) { void *p = __libc_malloc(n); acct_alloc(p); return p; }
void *calloc(size_t a, size_t b) { void *p = __libc_calloc(a, b); acct_alloc(p); return p; }
void *realloc(void *q, size_t n) { acct_free(q); void *p = __libc_realloc(q, n); acct_alloc(p); return p; }
void *memalign(size_t al, size_t n) { void *p = __libc_memalign(al, n); acct_alloc(p); return p; }
void *aligned_alloc(size_t al, size_t n) { void *p = __libc_memalign(al, n); acct_alloc(p); return p; }
void *valloc(size_t n) { void *p = __libc_memalign(4096, n); acct_alloc(p); return p; }
int posix_memalign(void **out, size_t al, size_t n) {
	void *p = __libc_memalign(al, n);
	if (!p) return ENOMEM;
	acct_alloc(p); *out = p; return 0;
}
void free(void *p) { acct_free(p); __libc_free(p); }
