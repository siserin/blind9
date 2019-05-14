/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <malloc.h>

#include <isc/atomic.h>
#include <isc/bind9.h>
#include <isc/hash.h>
#include <isc/json.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>
#include <isc/xml.h>

#include "mem_p.h"

#define MCTXLOCK(m, l) LOCK(l)
#define MCTXUNLOCK(m, l) UNLOCK(l)

#ifndef ISC_MEM_DEBUGGING
#define ISC_MEM_DEBUGGING 0
#endif
LIBISC_EXTERNAL_DATA unsigned int isc_mem_debugging = ISC_MEM_DEBUGGING;
LIBISC_EXTERNAL_DATA unsigned int isc_mem_flags = ISC_MEMFLAG_DEFAULT;

/*
 * Constants.
 */

#define ALIGNMENT_SIZE		8U		/*%< must be a power of 2 */
#define DEBUG_TABLE_COUNT	512U
#define PERTHREAD_TABLE_SIZE	128
#define PERTHREAD_TABLE_POOL	96

/*
 * Types.
 */

#if ISC_MEM_TRACKLINES
typedef struct debuglink debuglink_t;
struct debuglink {
	ISC_LINK(debuglink_t)	link;
	const void	       *ptr;
	size_t			size;
	const char	       *file;
	unsigned int		line;
};

typedef ISC_LIST(debuglink_t)	debuglist_t;

#define FLARG_PASS	, file, line
#define FLARG		, const char *file, unsigned int line
#else
#define FLARG_PASS
#define FLARG
#endif

typedef struct element element;
struct element {
	element *		next;
};

typedef struct {
	/*!
	 * This structure must be ALIGNMENT_SIZE bytes.
	 */
	union {
		size_t		size;
		isc_mem_t	*ctx;
		char		bytes[ALIGNMENT_SIZE];
	} u;
} size_info;

typedef struct {
#if __STDC_VERSION__ >= 201112L
	_Alignas(64)
#endif
	atomic_uint_fast64_t		gets;
	atomic_uint_fast64_t		totalgets;
	atomic_int_fast64_t		total;
	atomic_int_fast64_t		inuse;
	atomic_int_fast64_t		maxinuse;
	atomic_int_fast64_t		malloced;
	atomic_int_fast64_t		maxmalloced;
} perthread_t;

#define MEM_MAGIC		ISC_MAGIC('M', 'e', 'm', 'C')
#define VALID_CONTEXT(c)	ISC_MAGIC_VALID(c, MEM_MAGIC)

/* List of all active memory contexts. */

static ISC_LIST(isc_mem_t)	contexts;

static isc_once_t		once = ISC_ONCE_INIT;
static isc_mutex_t		contextslock;

/*%
 * Total size of lost memory due to a bug of external library.
 * Locked by the global lock.
 */
static uint64_t		totallost;

#if defined(HAVE_THREAD_LOCAL)
#include <threads.h>
static thread_local int tid = -1;
#elif defined(HAVE___THREAD)
static __thread int tid = -1;
#elif defined(HAVE___DECLSPEC_THREAD)
static __declspec( thread ) int tid = -1;
#else
#error "Unknown method for defining a TLS variable!"
#endif
static atomic_uint_fast32_t	pt_max = 0;

struct isc_mem {
	unsigned int		magic;
	isc_mutex_t		lock;
	atomic_bool		checkfree;
	perthread_t		*pt;
	isc_refcount_t		references;
	char			name[16];
	void *			tag;

	atomic_uint_fast64_t	hi_water;
	atomic_uint_fast64_t	lo_water;
	atomic_bool		hi_called;
	atomic_bool		is_overmem;
	isc_mem_water_t	water;
	void *			water_arg;
	ISC_LIST(isc_mempool_t) pools;
	unsigned int		poolcnt;

#if ISC_MEM_TRACKLINES
	debuglist_t *		debuglist;
	size_t			debuglistcnt;
#endif

	ISC_LINK(isc_mem_t)	link;
};

#define MEMPOOL_MAGIC		ISC_MAGIC('M', 'E', 'M', 'p')
#define VALID_MEMPOOL(c)	ISC_MAGIC_VALID(c, MEMPOOL_MAGIC)

struct isc_mempool {
	/* always unlocked */
	unsigned int	magic;
	isc_mutex_t    *lock;		/*%< optional lock */
	isc_mem_t      *mctx;		/*%< our memory context */
	/*%< locked via the memory context's lock */
	ISC_LINK(isc_mempool_t)	link;	/*%< next pool in this mem context */
	/*%< optionally locked from here down */
	element        *items;		/*%< low water item list */
	size_t		size;		/*%< size of each item on this pool */
	unsigned int	maxalloc;	/*%< max number of items allowed */
	unsigned int	allocated;	/*%< # of items currently given out */
	unsigned int	freecount;	/*%< # of items on reserved list */
	unsigned int	freemax;	/*%< # of items allowed on free list */
	unsigned int	fillcount;	/*%< # of items to fetch on each fill */
	/*%< Stats only. */
	unsigned int	gets;		/*%< # of requests to this pool */
	/*%< Debugging only. */
#if ISC_MEMPOOL_NAMES
	char		name[16];	/*%< printed name in stats reports */
#endif
};

/*
 * Private Inline-able.
 */

#if ! ISC_MEM_TRACKLINES
#define ADD_TRACE(a, b, c, d, e)
#define DELETE_TRACE(a, b, c, d, e)
#define ISC_MEMFUNC_SCOPE
#else
#define TRACE_OR_RECORD (ISC_MEM_DEBUGTRACE|ISC_MEM_DEBUGRECORD)
#define ADD_TRACE(a, b, c, d, e) \
	do { \
		if (ISC_UNLIKELY((isc_mem_debugging & TRACE_OR_RECORD) != 0 && \
				 b != NULL))				\
		{							\
			MCTXLOCK(a, &a->lock);				\
			add_trace_entry(a, b, c, d, e);			\
			MCTXUNLOCK(a, &a->lock);			\
		}							\
	} while (0)
#define DELETE_TRACE(a, b, c, d, e)					\
	do {								\
		if (ISC_UNLIKELY((isc_mem_debugging & TRACE_OR_RECORD) != 0 && \
				 b != NULL))				\
		{							\
			MCTXLOCK(a, &a->lock);				\
			delete_trace_entry(a, b, c, d, e);		\
			MCTXUNLOCK(a, &a->lock);			\
		}							\
	} while(0)

static void
print_active(const isc_mem_t *ctx, FILE *out);

#endif /* ISC_MEM_TRACKLINES */


static inline perthread_t *
get_perthread(const isc_mem_t *ctx) {
	INSIST(tid < PERTHREAD_TABLE_SIZE);
	if (ISC_UNLIKELY(tid == -1)) {
		tid = atomic_fetch_add_relaxed(&pt_max, 1);
		if (tid >= PERTHREAD_TABLE_SIZE) {
			tid %= (PERTHREAD_TABLE_SIZE - PERTHREAD_TABLE_POOL);
			tid += PERTHREAD_TABLE_POOL;
		}
		INSIST(tid < PERTHREAD_TABLE_SIZE);
	}
	return (&ctx->pt[tid]);
}

#define _register(field)						\
	static int64_t							\
	get_##field(const isc_mem_t *ctx) {				\
		int64_t value = 0;					\
		unsigned int max = atomic_load_acquire(&pt_max);	\
		for (unsigned int i = 0; i < max; i++)			\
		{							\
			value += atomic_load_relaxed(&(ctx)->pt[i].field); \
		}							\
		return (value);					\
	}

_register(total);
_register(inuse);
_register(maxinuse);
_register(malloced);
_register(maxmalloced);
_register(gets);
_register(totalgets);

/*
 * Private.
 */

static void *
default_memalloc(const size_t size) {
	void *ptr;

	ptr = malloc(size);

	/*
	 * If the space cannot be allocated, a null pointer is returned. If the
	 * size of the space requested is zero, the behavior is
	 * implementation-defined: either a null pointer is returned, or the
	 * behavior is as if the size were some nonzero value, except that the
	 * returned pointer shall not be used to access an object.
	 * [ISO9899 § 7.22.3]
	 *
	 * [ISO9899]
	 *   ISO/IEC WG 9899:2011: Programming languages - C.
	 *   International Organization for Standardization, Geneva, Switzerland.
	 *   http://www.open-std.org/JTC1/SC22/WG14/www/docs/n1570.pdf
	 */

	if (ptr == NULL && size != 0) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(errno, strbuf, sizeof(strbuf));
		isc_error_fatal(__FILE__, __LINE__, "malloc failed: %s",
				strbuf);
	}

	return (ptr);
}

static void
default_memfree(void *ptr) {
	free(ptr);
}

#if ISC_MEM_TRACKLINES
/*!
 * mctx must be locked.
 */
static void
add_trace_entry(isc_mem_t *mctx, const void *ptr, size_t size FLARG) {
	int64_t malloced;
	debuglink_t *dl;
	perthread_t *pt = get_perthread(mctx);
	uint32_t hash;
	uint32_t idx;

	if ((isc_mem_debugging & ISC_MEM_DEBUGTRACE) != 0) {
		fprintf(stderr, "add %p size %zu file %s line %u mctx %p\n",
			ptr, size, file, line, mctx);
	}

	if (mctx->debuglist == NULL)
		return;

	hash = isc_hash_function(&ptr, sizeof(ptr), true, NULL);
	idx = hash % DEBUG_TABLE_COUNT;

	dl = default_memalloc(sizeof(debuglink_t));
	INSIST(dl != NULL);
	malloced = atomic_fetch_add_relaxed(&pt->malloced, sizeof(debuglink_t))
		+ sizeof(debuglink_t);
	if (malloced > atomic_load_relaxed(&pt->maxmalloced)) {
		atomic_store_relaxed(&pt->maxmalloced, malloced);
	}

	ISC_LINK_INIT(dl, link);
	dl->ptr = ptr;
	dl->size = size;
	dl->file = file;
	dl->line = line;

	ISC_LIST_PREPEND(mctx->debuglist[idx], dl, link);
	mctx->debuglistcnt++;
}

static void
delete_trace_entry(isc_mem_t *mctx, const void *ptr, size_t size,
		   const char *file, unsigned int line)
{
	debuglink_t *dl;
	perthread_t *pt = get_perthread(mctx);
	uint32_t hash;
	uint32_t idx;

	if ((isc_mem_debugging & ISC_MEM_DEBUGTRACE) != 0) {
		fprintf(stderr, "del %p size %zu file %s line %u mctx %p\n",
			ptr, size, file, line, mctx);
	}

	if (mctx->debuglist == NULL)
		return;

	hash = isc_hash_function(&ptr, sizeof(ptr), true, NULL);
	idx = hash % DEBUG_TABLE_COUNT;

	dl = ISC_LIST_HEAD(mctx->debuglist[idx]);
	while (ISC_LIKELY(dl != NULL)) {
		if (ISC_UNLIKELY(dl->ptr == ptr)) {
			ISC_LIST_UNLINK(mctx->debuglist[idx], dl, link);
			atomic_fetch_sub_release(&pt->malloced, sizeof(*dl));
			free(dl);
			return;
		}
		dl = ISC_LIST_NEXT(dl, link);
	}

	/*
	 * If we get here, we didn't find the item on the list.  We're
	 * screwed.
	 */
	INSIST(0);
	ISC_UNREACHABLE();
}
#endif /* ISC_MEM_TRACKLINES */

/* Memory accounting helper functions */

static inline void
mem_accounting_add(const isc_mem_t *ctx, const size_t size) {
	perthread_t *pt = get_perthread(ctx);
	int64_t malloced;
	if (ISC_UNLIKELY(tid > PERTHREAD_TABLE_POOL)) {
		atomic_fetch_add_relaxed(&pt->gets, 1);
		atomic_fetch_add_relaxed(&pt->totalgets, 1);
		atomic_fetch_add_relaxed(&pt->total, size);
		atomic_fetch_add_relaxed(&pt->inuse, size);
		malloced = atomic_fetch_add_relaxed(&pt->malloced, size) + size;
	} else {
		uint64_t *p = &pt->gets;
		(*p)++;
		p = &pt->totalgets;
		(*p)++;
		p = &pt->total;
		(*p)+=size;
		p = &pt->inuse;
		(*p)+=size;
		p = &pt->malloced;
		(*p) += size;
		malloced = (*p);
	}
	if (malloced > atomic_load_relaxed(&pt->maxmalloced)) {
		atomic_store_relaxed(&pt->maxmalloced, malloced);
	}		
}

static inline void
mem_accounting_del(const isc_mem_t *ctx, const size_t size) {
	perthread_t * pt = get_perthread(ctx);
	if (ISC_UNLIKELY(tid > PERTHREAD_TABLE_POOL)) {
		atomic_fetch_sub_relaxed(&pt->gets, 1);
		atomic_fetch_sub_relaxed(&pt->inuse, size);
		atomic_fetch_sub_relaxed(&pt->malloced, size);
	} else {
		uint64_t *p = &pt->gets;
		(*p)--;
		p = &pt->inuse;
		(*p)-=size;
		p = &pt->malloced;
		(*p) -= size;
	}
}

static inline void *
mem_getunlocked(const isc_mem_t *ctx, const size_t size) {
	void *ret;

	ret = default_memalloc(size);
	if (ISC_UNLIKELY((isc_mem_flags & ISC_MEMFLAG_FILL) != 0)) {
		memset(ret, 0xbe, size); /* Mnemonic for "beef". */
	}
	mem_accounting_add(ctx, size);

	return (ret);
}

/* coverity[+free : arg-1] */
static inline void
mem_putunlocked(const isc_mem_t *ctx, void *mem, const size_t size) {
	if (ISC_UNLIKELY((isc_mem_flags & ISC_MEMFLAG_FILL) != 0)){
		memset(mem, 0xde, size); /* Mnemonic for "dead". */
	}
	default_memfree(mem);
	mem_accounting_del(ctx, size);
}

static void
initialize_action(void) {
	isc_mutex_init(&contextslock);
	ISC_LIST_INIT(contexts);
	totallost = 0;
}

/*
 * Public.
 */

isc_result_t
isc_mem_create(isc_mem_t **ctxp)
{
	isc_mem_t *ctx;
	perthread_t *pt;
	int i;
	REQUIRE(ctxp != NULL && *ctxp == NULL);

	STATIC_ASSERT((ALIGNMENT_SIZE & (ALIGNMENT_SIZE - 1)) == 0,
		      "wrong alignment size");

	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);

	ctx = default_memalloc(sizeof(*ctx));

	isc_mutex_init(&ctx->lock);

	isc_refcount_init(&ctx->references, 1);
	memset(ctx->name, 0, sizeof(ctx->name));
	ctx->tag = NULL;
	ctx->pt = memalign(64, (PERTHREAD_TABLE_SIZE * sizeof(perthread_t)));
	for (i=0; i<PERTHREAD_TABLE_SIZE; i++) {
		atomic_init(&ctx->pt[i].gets, 0);
		atomic_init(&ctx->pt[i].totalgets, 0);
		atomic_init(&ctx->pt[i].inuse, 0);
		atomic_init(&ctx->pt[i].maxinuse, 0);
		atomic_init(&ctx->pt[i].malloced, 0);
		atomic_init(&ctx->pt[i].maxmalloced, 0);
	}
	pt = get_perthread(ctx);
	atomic_init(&pt->total, 0);
	atomic_init(&pt->inuse, 0);
	atomic_init(&pt->maxinuse, 0);
	atomic_init(&pt->malloced, sizeof(*ctx));
	atomic_init(&pt->maxmalloced, sizeof(*ctx));
	atomic_init(&ctx->hi_water, 0);
	atomic_init(&ctx->lo_water, 0);
	atomic_init(&ctx->hi_called, false);
	atomic_init(&ctx->is_overmem, false);
	ctx->water = NULL;
	ctx->water_arg = NULL;
	atomic_init(&ctx->checkfree, true);
#if ISC_MEM_TRACKLINES
	ctx->debuglist = NULL;
	ctx->debuglistcnt = 0;
#endif
	ISC_LIST_INIT(ctx->pools);
	ctx->poolcnt = 0;

#if ISC_MEM_TRACKLINES
	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGRECORD) != 0)) {
		unsigned int j;
		ctx->debuglist = default_memalloc((DEBUG_TABLE_COUNT *
						   sizeof(debuglist_t)));
		RUNTIME_CHECK(ctx->debuglist != NULL);
		for (j = 0; j < DEBUG_TABLE_COUNT; j++)
			ISC_LIST_INIT(ctx->debuglist[j]);
		atomic_fetch_add_relaxed(&pt->malloced,
				 DEBUG_TABLE_COUNT * sizeof(debuglist_t));
		atomic_fetch_add_relaxed(&pt->maxmalloced,
				 DEBUG_TABLE_COUNT * sizeof(debuglist_t));
	}
#endif

	LOCK(&contextslock);
	ISC_LIST_INITANDAPPEND(contexts, ctx, link);
	UNLOCK(&contextslock);

	ctx->magic = MEM_MAGIC;

	*ctxp = ctx;

	return (ISC_R_SUCCESS);
}

static void
destroy(isc_mem_t *ctx) {
	unsigned int i;
	perthread_t *pt = get_perthread(ctx);

	LOCK(&contextslock);
	ISC_LIST_UNLINK(contexts, ctx, link);
	totallost = get_inuse(ctx);
	UNLOCK(&contextslock);

	ctx->magic = 0;

	INSIST(ISC_LIST_EMPTY(ctx->pools));

#if ISC_MEM_TRACKLINES
	if (ISC_UNLIKELY(ctx->debuglist != NULL)) {
		debuglink_t *dl;
		for (i = 0; i < DEBUG_TABLE_COUNT; i++)
			for (dl = ISC_LIST_HEAD(ctx->debuglist[i]);
			     dl != NULL;
			     dl = ISC_LIST_HEAD(ctx->debuglist[i])) {
				if (ctx->checkfree && dl->ptr != NULL)
					print_active(ctx, stderr);
				INSIST (!ctx->checkfree || dl->ptr == NULL);

				ISC_LIST_UNLINK(ctx->debuglist[i],
						dl, link);
				free(dl);
				pt->malloced -= sizeof(*dl);
			}

		default_memfree(ctx->debuglist);
		pt->malloced -= DEBUG_TABLE_COUNT * sizeof(debuglist_t);
	}
#endif

	if (ctx->checkfree) {
		int64_t gets = get_gets(ctx);
		if (gets != 0) {
			fprintf(stderr,
				"Failing assertion due to probable "
				"leaked memory in context %p (\"%s\") "
				"(stats.gets == %" PRIu64 ").\n",
				ctx, ctx->name, gets);
#if ISC_MEM_TRACKLINES
			print_active(ctx, stderr);
#endif
			INSIST(gets == 0);
		}
	}

	isc_mutex_destroy(&ctx->lock);

	pt->malloced -= sizeof(*ctx);
	if (ctx->checkfree) {
		int64_t malloced = get_malloced(ctx);
		INSIST(malloced == 0);
	}
	default_memfree(ctx);
}

void
isc_mem_attach(isc_mem_t *source, isc_mem_t **targetp) {
	REQUIRE(VALID_CONTEXT(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
isc_mem_detach(isc_mem_t **ctxp) {
	REQUIRE(ctxp != NULL && VALID_CONTEXT(*ctxp));
	isc_mem_t *ctx = *ctxp;
	*ctxp = NULL;

	if (isc_refcount_decrement(&ctx->references) == 1) {
		isc_refcount_destroy(&ctx->references);
		destroy(ctx);
	}
}

/*
 * isc_mem_putanddetach() is the equivalent of:
 *
 * mctx = NULL;
 * isc_mem_attach(ptr->mctx, &mctx);
 * isc_mem_detach(&ptr->mctx);
 * isc_mem_put(mctx, ptr, sizeof(*ptr);
 * isc_mem_detach(&mctx);
 */

void
isc__mem_putanddetach(isc_mem_t **ctxp, void *ptr, const size_t size FLARG) {
	REQUIRE(ctxp != NULL && VALID_CONTEXT(*ctxp));
	REQUIRE(ptr != NULL);
	isc_mem_t *ctx = *ctxp;
	*ctxp = NULL;

	if (ISC_UNLIKELY((isc_mem_debugging &
			  (ISC_MEM_DEBUGSIZE|ISC_MEM_DEBUGCTX)) != 0))
	{
		if ((isc_mem_debugging & ISC_MEM_DEBUGSIZE) != 0) {
			size_info *si = &(((size_info *)ptr)[-1]);
			size_t oldsize = si->u.size - ALIGNMENT_SIZE;
			if ((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0)
				oldsize -= ALIGNMENT_SIZE;
			INSIST(oldsize == size);
		}
		isc__mem_free((isc_mem_t *)ctx, ptr FLARG_PASS);

		goto destroy;
	}

	DELETE_TRACE(ctx, ptr, size, file, line);

	mem_putunlocked(ctx, ptr, size);

destroy:
	if (isc_refcount_decrement(&ctx->references) == 1) {
		isc_refcount_destroy(&ctx->references);
		destroy(ctx);
	}
}

void
isc_mem_destroy(isc_mem_t **ctxp) {
	isc_mem_t *ctx;

	/*
	 * This routine provides legacy support for callers who use mctxs
	 * without attaching/detaching.
	 */

	REQUIRE(ctxp != NULL);
	ctx = *ctxp;
	REQUIRE(VALID_CONTEXT(ctx));

#if ISC_MEM_TRACKLINES
	if (isc_refcount_decrement(&ctx->references) != 1) {
		print_active(ctx, stderr);
	}
#else
	INSIST(isc_refcount_decrement(&ctx->references) == 1);
#endif
	isc_refcount_destroy(&ctx->references);
	destroy(ctx);

	*ctxp = NULL;
}

void *
isc__mem_get(isc_mem_t *ctx, const size_t size FLARG) {
	void *ptr;
	perthread_t *pt;

	REQUIRE(VALID_CONTEXT(ctx));
	pt = get_perthread(ctx);

	if (ISC_UNLIKELY((isc_mem_debugging &
			  (ISC_MEM_DEBUGSIZE|ISC_MEM_DEBUGCTX)) != 0))
		return (isc__mem_allocate(ctx, size FLARG_PASS));

	ptr = mem_getunlocked(ctx, size);

	ADD_TRACE(ctx, ptr, size, file, line);

	if (ctx->water != NULL) {
		int64_t inuse = get_inuse(ctx);
		int64_t hi_water = atomic_load_acquire(&ctx->hi_water);

		if (hi_water != 0U && inuse > hi_water) {
			atomic_store_release(&ctx->is_overmem, true);
			if (!atomic_load_acquire(&ctx->hi_called)) {
				(ctx->water)(ctx->water_arg, ISC_MEM_HIWATER);
			}
		}
		if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGUSAGE) != 0) &&
		    hi_water != 0U && inuse > hi_water)
		{
			fprintf(stderr, "maxinuse = %" PRId64 "\n", inuse);
		}
	}

	int64_t inuse = atomic_load_relaxed(&pt->inuse);

	if (inuse > atomic_load_relaxed(&pt->maxinuse)) {
		atomic_store_relaxed(&pt->maxinuse, inuse);
	}

	return (ptr);
}

void
isc__mem_put(isc_mem_t *ctx, void *ptr, size_t size FLARG) {
	size_info *si;
	size_t oldsize;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	if (ISC_UNLIKELY((isc_mem_debugging &
			  (ISC_MEM_DEBUGSIZE|ISC_MEM_DEBUGCTX)) != 0))
	{
		if ((isc_mem_debugging & ISC_MEM_DEBUGSIZE) != 0) {
			si = &(((size_info *)ptr)[-1]);
			oldsize = si->u.size - ALIGNMENT_SIZE;
			if ((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0)
				oldsize -= ALIGNMENT_SIZE;
			INSIST(oldsize == size);
		}
		isc__mem_free((isc_mem_t *)ctx, ptr FLARG_PASS);
		return;
	}

	DELETE_TRACE(ctx, ptr, size, file, line);

	mem_putunlocked(ctx, ptr, size);

	if (ctx->water != NULL) {
		/*
		 * The check against ctx->lo_water == 0 is for the condition
		 * when the context was pushed over hi_water but then had
		 * isc_mem_setwater() called with 0 for hi_water and lo_water.
		 */
		int64_t inuse = get_inuse(ctx);
		int64_t lo_water = atomic_load_acquire(&ctx->lo_water);

		if ((inuse < lo_water) || (lo_water == 0U)) {
			atomic_store_release(&ctx->is_overmem, false);
			if (atomic_load_acquire(&ctx->hi_called)) {
				(ctx->water)(ctx->water_arg, ISC_MEM_LOWATER);
			}
		}
	}
}

void
isc_mem_waterack(isc_mem_t *ctx, const int flag) {
	REQUIRE(VALID_CONTEXT(ctx));

	if (flag == ISC_MEM_LOWATER) {
		atomic_store_release(&ctx->hi_called, false);
	} else if (flag == ISC_MEM_HIWATER) {
		atomic_store_release(&ctx->hi_called, true);
	}
}

#if ISC_MEM_TRACKLINES
static void
print_active(const isc_mem_t *mctx, FILE *out) {
	if (mctx->debuglist != NULL) {
		debuglink_t *dl;
		unsigned int i;
		bool found;

		fputs("Dump of all outstanding memory allocations:\n", out);
		found = false;
		for (i = 0; i < DEBUG_TABLE_COUNT; i++) {
			dl = ISC_LIST_HEAD(mctx->debuglist[i]);

			if (dl != NULL) {
				found = true;
			}

			while (dl != NULL) {
				if (dl->ptr != NULL) {
					fprintf(out,
						"\tptr %p size %zu file %s line %u\n",
						dl->ptr, dl->size,
						dl->file, dl->line);
				}
				dl = ISC_LIST_NEXT(dl, link);
			}
		}

		if (!found) {
			fputs("\tNone.\n", out);
		}
	}
}
#endif

/*
 * Print the stats on the stream "out" with suitable formatting.
 */
void
isc_mem_stats(isc_mem_t *ctx, FILE *out) {
	isc_mempool_t *pool;
	int64_t gets=0, totalgets=0;

	REQUIRE(VALID_CONTEXT(ctx));

	gets = get_gets(ctx);
	totalgets = get_totalgets(ctx);

	fprintf(out, "[Memory statistics]\n%11" PRIu64 " gets, %11" PRIu64 " rem\n",
		gets, totalgets);

	MCTXLOCK(ctx, &ctx->lock);
	/*
	 * Note that since a pool can be locked now, these stats might be
	 * somewhat off if the pool is in active use at the time the stats
	 * are dumped.  The link fields are protected by the isc_mem_t's
	 * lock, however, so walking this list and extracting integers from
	 * stats fields is always safe.
	 */
	pool = ISC_LIST_HEAD(ctx->pools);
	if (pool != NULL) {
		fputs("[Pool statistics]\n", out);
		fprintf(out, "%15s %10s %10s %10s %10s %10s %10s %10s %1s\n",
			"name", "size", "maxalloc", "allocated", "freecount",
			"freemax", "fillcount", "gets", "L");
	}
	while (pool != NULL) {
		fprintf(out, "%15s %10lu %10u %10u %10u %10u %10u %10u %s\n",
#if ISC_MEMPOOL_NAMES
			pool->name,
#else
			"(not tracked)",
#endif
			(unsigned long) pool->size, pool->maxalloc,
			pool->allocated, pool->freecount, pool->freemax,
			pool->fillcount, pool->gets,
			(pool->lock == NULL ? "N" : "Y"));
		pool = ISC_LIST_NEXT(pool, link);
	}

#if ISC_MEM_TRACKLINES
	print_active(ctx, out);
#endif

	MCTXUNLOCK(ctx, &ctx->lock);
}

/*
 * Replacements for malloc() and free() -- they implicitly remember the
 * size of the object allocated (with some additional overhead).
 */

static void *
mem_allocateunlocked(isc_mem_t *ctx, size_t size) {
	size_info *si;

	size += ALIGNMENT_SIZE;
	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0))
		size += ALIGNMENT_SIZE;

	si = mem_getunlocked(ctx, size);

	if (si == NULL)
		return (NULL);
	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0)) {
		si->u.ctx = ctx;
		si++;
	}
	si->u.size = size;
	return (&si[1]);
}

void *
isc__mem_allocate(isc_mem_t *ctx, const size_t size FLARG) {
	size_info *si;
	perthread_t *pt;

	REQUIRE(VALID_CONTEXT(ctx));
	pt = get_perthread(ctx);

	si = mem_allocateunlocked((isc_mem_t *)ctx, size);

	ADD_TRACE(ctx, si, si[-1].u.size, file, line);

	if (ctx->water != NULL) {
		int64_t inuse = get_inuse(ctx);
		int64_t hi_water = atomic_load_acquire(&ctx->hi_water);

		if (hi_water != 0U) {
			bool exp_f = false;
			if (inuse > hi_water) {
				atomic_store_release(&ctx->is_overmem, true);
			}
			if (atomic_compare_exchange_weak_acq_rel(&ctx->hi_called, &exp_f, true))
			{
				(ctx->water)(ctx->water_arg, ISC_MEM_HIWATER);
			}
		}
		if (ISC_UNLIKELY(isc_mem_debugging & ISC_MEM_DEBUGUSAGE) != 0) {
			if (hi_water != 0U && inuse > hi_water) {
				fprintf(stderr, "maxinuse = %lu\n",
					(unsigned long)inuse);
			}
		}
	}

	int64_t inuse = atomic_load_relaxed(&pt->inuse);

	if (inuse > atomic_load_relaxed(&pt->maxinuse)) {
		atomic_store_relaxed(&pt->maxinuse, inuse);
	}

	return (si);
}

void *
isc__mem_reallocate(isc_mem_t *ctx, void *ptr, size_t size FLARG) {
	void *new_ptr = NULL;
	size_t oldsize, copysize;

	REQUIRE(VALID_CONTEXT(ctx));

	/*
	 * This function emulates the realloc(3) standard library function:
	 * - if size > 0, allocate new memory; and if ptr is non NULL, copy
	 *   as much of the old contents to the new buffer and free the old one.
	 *   Note that when allocation fails the original pointer is intact;
	 *   the caller must free it.
	 * - if size is 0 and ptr is non NULL, simply free the given ptr.
	 * - this function returns:
	 *     pointer to the newly allocated memory, or
	 *     NULL if allocation fails or doesn't happen.
	 */
	if (size > 0U) {
		new_ptr = isc__mem_allocate(ctx, size FLARG_PASS);
		if (new_ptr != NULL && ptr != NULL) {
			oldsize = (((size_info *)ptr)[-1]).u.size;
			INSIST(oldsize >= ALIGNMENT_SIZE);
			oldsize -= ALIGNMENT_SIZE;
			if (ISC_UNLIKELY((isc_mem_debugging &
					  ISC_MEM_DEBUGCTX) != 0))
			{
				INSIST(oldsize >= ALIGNMENT_SIZE);
				oldsize -= ALIGNMENT_SIZE;
			}
			copysize = (oldsize > size) ? size : oldsize;
			memmove(new_ptr, ptr, copysize);
			isc__mem_free(ctx, ptr FLARG_PASS);
		}
	} else if (ptr != NULL) {
		isc__mem_free(ctx, ptr FLARG_PASS);
	}

	return (new_ptr);
}

void
isc__mem_free(isc_mem_t *ctx, void *ptr FLARG) {
	size_info *si;
	size_t size;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0)) {
		si = &(((size_info *)ptr)[-2]);
		REQUIRE(si->u.ctx == ctx);
		size = si[1].u.size;
	} else {
		si = &(((size_info *)ptr)[-1]);
		size = si->u.size;
	}

	DELETE_TRACE(ctx, ptr, size, file, line);

	mem_putunlocked(ctx, si, size);

	/*
	 * The check against ctx->lo_water == 0 is for the condition
	 * when the context was pushed over hi_water but then had
	 * isc_mem_setwater() called with 0 for hi_water and lo_water.
	 */
	if (ctx->water != NULL) {
		int64_t inuse = get_inuse(ctx);
		int64_t lo_water = atomic_load_acquire(&ctx->lo_water);

		if (inuse < lo_water || lo_water == 0U) {
			bool exp_t = true;
			atomic_store_release(&ctx->is_overmem, false);
			if (atomic_compare_exchange_weak_acq_rel(&ctx->hi_called,
								 &exp_t, false))
			{
				(ctx->water)(ctx->water_arg, ISC_MEM_LOWATER);
			}
		}
	}
}


/*
 * Other useful things.
 */

char *
isc__mem_strdup(isc_mem_t *mctx, const char *s FLARG) {
	size_t len;
	char *ns;

	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(s != NULL);

	len = strlen(s) + 1;

	ns = isc__mem_allocate((isc_mem_t *)mctx, len FLARG_PASS);

	if (ns != NULL)
		strlcpy(ns, s, len);

	return (ns);
}

void
isc_mem_setdestroycheck(isc_mem_t *ctx, const bool flag) {
	REQUIRE(VALID_CONTEXT(ctx));

	atomic_store_release(&ctx->checkfree, flag);
}

size_t
isc_mem_inuse(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (get_inuse(ctx));
}

size_t
isc_mem_maxinuse(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (get_maxinuse(ctx));
}

size_t
isc_mem_total(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (get_total(ctx));
}

void
isc_mem_setwater(isc_mem_t *ctx,
		 const isc_mem_water_t water, void *water_arg,
		 const size_t hiwater, const size_t lowater)
{
	bool callwater = false;
	isc_mem_water_t oldwater;
	void *oldwater_arg;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(hiwater >= lowater);

	/* XXXOND: ctx->water could be changed to atomic_uintptr_t
	 * for lockless operations
	 */
	MCTXLOCK(ctx, &ctx->lock);
	oldwater = ctx->water;
	oldwater_arg = ctx->water_arg;
	if (water == NULL) {
		callwater = atomic_load_acquire(&ctx->hi_called);
		ctx->water = NULL;
		ctx->water_arg = NULL;
		ctx->hi_water = 0;
		ctx->lo_water = 0;
	} else {
		int64_t inuse = get_inuse(ctx);

		if (atomic_load_acquire(&ctx->hi_called) &&
		    (ctx->water != water || ctx->water_arg != water_arg ||
		     inuse < (int64_t)lowater || lowater == 0U)) {
			callwater = true;
		}
		ctx->water = water;
		ctx->water_arg = water_arg;
		ctx->hi_water = hiwater;
		ctx->lo_water = lowater;
	}
	MCTXUNLOCK(ctx, &ctx->lock);

	if (callwater && oldwater != NULL) {
		(oldwater)(oldwater_arg, ISC_MEM_LOWATER);
	}
}

bool
isc_mem_isovermem(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (atomic_load_acquire(&ctx->is_overmem));
}

void
isc_mem_setname(isc_mem_t *ctx, const char *name, void *tag) {
	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	strlcpy(ctx->name, name, sizeof(ctx->name));
	ctx->tag = tag;
	UNLOCK(&ctx->lock);
}

const char *
isc_mem_getname(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	if (ctx->name[0] == 0) {
		return ("");
	}

	return (ctx->name);
}

void *
isc_mem_gettag(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (ctx->tag);
}

/*
 * Memory pool stuff
 */

isc_result_t
isc_mempool_create(isc_mem_t *mctx, size_t size,
		   isc_mempool_t **mpctxp) {
	isc_mempool_t *mpctx;

	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(size > 0U);
	REQUIRE(mpctxp != NULL && *mpctxp == NULL);

	/*
	 * Allocate space for this pool, initialize values, and if all works
	 * well, attach to the memory context.
	 */
	mpctx = isc_mem_get((isc_mem_t *)mctx, sizeof(isc_mempool_t));
	RUNTIME_CHECK(mpctx != NULL);

	mpctx->lock = NULL;
	mpctx->mctx = mctx;
	/*
	 * Mempools are stored as a linked list of element.
	 */
	if (size < sizeof(element)) {
		size = sizeof(element);
	}
	mpctx->size = size;
	mpctx->maxalloc = UINT_MAX;
	mpctx->allocated = 0;
	mpctx->freecount = 0;
	mpctx->freemax = 1;
	mpctx->fillcount = 1;
	mpctx->gets = 0;
#if ISC_MEMPOOL_NAMES
	mpctx->name[0] = 0;
#endif
	mpctx->items = NULL;

	mpctx->magic = MEMPOOL_MAGIC;

	*mpctxp = mpctx;

	MCTXLOCK(mctx, &mctx->lock);
	ISC_LIST_INITANDAPPEND(mctx->pools, mpctx, link);
	mctx->poolcnt++;
	MCTXUNLOCK(mctx, &mctx->lock);

	return (ISC_R_SUCCESS);
}

void
isc_mempool_setname(isc_mempool_t *mpctx, const char *name) {
	REQUIRE(name != NULL);
	REQUIRE(VALID_MEMPOOL(mpctx));

#if ISC_MEMPOOL_NAMES
	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	strlcpy(mpctx->name, name, sizeof(mpctx->name));

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
#else
	UNUSED(mpctx);
	UNUSED(name);
#endif
}

void
isc_mempool_destroy(isc_mempool_t **mpctxp) {
	isc_mempool_t *mpctx;
	isc_mem_t *mctx;
	isc_mutex_t *lock;
	element *item;

	REQUIRE(mpctxp != NULL);
	REQUIRE(VALID_MEMPOOL(*mpctxp));

	mpctx = *mpctxp;
#if ISC_MEMPOOL_NAMES
	if (mpctx->allocated > 0)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mempool_destroy(): mempool %s "
				 "leaked memory",
				 mpctx->name);
#endif
	REQUIRE(mpctx->allocated == 0);

	mctx = mpctx->mctx;

	lock = mpctx->lock;

	if (lock != NULL)
		LOCK(lock);

	/*
	 * Return any items on the free list
	 */
	MCTXLOCK(mctx, &mctx->lock);
	while (mpctx->items != NULL) {
		INSIST(mpctx->freecount > 0);
		mpctx->freecount--;
		item = mpctx->items;
		mpctx->items = item->next;

		mem_putunlocked(mctx, item, mpctx->size);
	}
	MCTXUNLOCK(mctx, &mctx->lock);

	/*
	 * Remove our linked list entry from the memory context.
	 */
	MCTXLOCK(mctx, &mctx->lock);
	ISC_LIST_UNLINK(mctx->pools, mpctx, link);
	mctx->poolcnt--;
	MCTXUNLOCK(mctx, &mctx->lock);

	mpctx->magic = 0;

	isc_mem_put((isc_mem_t *)mpctx->mctx, mpctx, sizeof(isc_mempool_t));

	if (lock != NULL) {
		UNLOCK(lock);
	}

	*mpctxp = NULL;
}

void
isc_mempool_associatelock(isc_mempool_t *mpctx, isc_mutex_t *lock) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mpctx->lock == NULL);
	REQUIRE(lock != NULL);

	mpctx->lock = lock;
}

void *
isc__mempool_get(isc_mempool_t *mpctx FLARG) {
	element *item;
	isc_mem_t *mctx;
	unsigned int i;

	REQUIRE(VALID_MEMPOOL(mpctx));

	mctx = mpctx->mctx;
	return (isc__mem_get(mctx, mpctx->size));
}

/* coverity[+free : arg-1] */
void
isc__mempool_put(isc_mempool_t *mpctx, void *mem FLARG) {
	isc_mem_t *mctx;
	element *item;

	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mem != NULL);
	mctx = mpctx->mctx;
	isc__mem_put(mctx, mem, mpctx->size);
}

/*
 * Quotas
 */

void
isc_mempool_setfreemax(isc_mempool_t *mpctx, unsigned int limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->freemax = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getfreemax(isc_mempool_t *mpctx) {
	unsigned int freemax;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	freemax = mpctx->freemax;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (freemax);
}

unsigned int
isc_mempool_getfreecount(isc_mempool_t *mpctx) {
	unsigned int freecount;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	freecount = mpctx->freecount;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (freecount);
}

void
isc_mempool_setmaxalloc(isc_mempool_t *mpctx, const size_t limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(limit > 0);

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->maxalloc = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getmaxalloc(isc_mempool_t *mpctx) {
	unsigned int maxalloc;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	maxalloc = mpctx->maxalloc;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (maxalloc);
}

unsigned int
isc_mempool_getallocated(isc_mempool_t *mpctx) {
	unsigned int allocated;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	allocated = mpctx->allocated;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (allocated);
}

void
isc_mempool_setfillcount(isc_mempool_t *mpctx, const size_t limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(limit > 0);

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->fillcount = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getfillcount(isc_mempool_t *mpctx) {
	unsigned int fillcount;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	fillcount = mpctx->fillcount;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (fillcount);
}

/*
 * Requires contextslock to be held by caller.
 */
static void
print_contexts(FILE *file) {
	isc_mem_t *ctx;

	for (ctx = ISC_LIST_HEAD(contexts);
	     ctx != NULL;
	     ctx = ISC_LIST_NEXT(ctx, link))
	{
		fprintf(file, "context: %p (%s): %" PRIuFAST32 " references\n",
			ctx,
			ctx->name[0] == 0 ? "<unknown>" : ctx->name,
			isc_refcount_current(&ctx->references));
		print_active(ctx, file);
	}
	fflush(file);
}

void
isc_mem_checkdestroyed(FILE *file) {
#if !ISC_MEM_TRACKLINES
	UNUSED(file);
#endif

	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);

	LOCK(&contextslock);
	if (!ISC_LIST_EMPTY(contexts)) {
#if ISC_MEM_TRACKLINES
		if (ISC_UNLIKELY((isc_mem_debugging & TRACE_OR_RECORD) != 0)) {
			print_contexts(file);
		}
#endif
		INSIST(0);
		ISC_UNREACHABLE();
	}
	UNLOCK(&contextslock);
}

unsigned int
isc_mem_references(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (isc_refcount_current(&ctx->references));
}

typedef struct summarystat {
	uint64_t	total;
	uint64_t	inuse;
	uint64_t	malloced;
	uint64_t	blocksize;
	uint64_t	contextsize;
} summarystat_t;

#ifdef HAVE_LIBXML2
#define TRY0(a) do { xmlrc = (a); if (xmlrc < 0) goto error; } while(0)
static int
xml_renderctx(isc_mem_t *ctx, summarystat_t *summary,
	      const xmlTextWriterPtr writer)
{
	int xmlrc;
	int64_t total=0, inuse=0, maxinuse=0, malloced=0, maxmalloced=0;

	REQUIRE(VALID_CONTEXT(ctx));

	total = get_total(ctx);
	inuse = get_inuse(ctx);
	maxinuse = get_maxinuse(ctx);
	malloced = get_malloced(ctx);
	maxmalloced = get_maxmalloced(ctx);

	MCTXLOCK(ctx, &ctx->lock);

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "context"));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "id"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%p", ctx));
	TRY0(xmlTextWriterEndElement(writer)); /* id */

	if (ctx->name[0] != 0) {
		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "name"));
		TRY0(xmlTextWriterWriteFormatString(writer, "%s", ctx->name));
		TRY0(xmlTextWriterEndElement(writer)); /* name */
	}

	summary->contextsize += sizeof(*ctx);
#if ISC_MEM_TRACKLINES
	if (ctx->debuglist != NULL) {
		summary->contextsize +=
			DEBUG_TABLE_COUNT * sizeof(debuglist_t) +
			ctx->debuglistcnt * sizeof(debuglink_t);
	}
#endif
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "references"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIuFAST32,
					    isc_refcount_current(&ctx->references)));
	TRY0(xmlTextWriterEndElement(writer)); /* references */

	summary->total += total;
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "total"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    (uint64_t)total));
	TRY0(xmlTextWriterEndElement(writer)); /* total */

	summary->inuse += inuse;
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "inuse"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    (uint64_t)inuse));
	TRY0(xmlTextWriterEndElement(writer)); /* inuse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "maxinuse"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    (uint64_t)maxinuse));
	TRY0(xmlTextWriterEndElement(writer)); /* maxinuse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "malloced"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    (uint64_t)malloced));
	TRY0(xmlTextWriterEndElement(writer)); /* malloced */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "maxmalloced"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    (uint64_t)maxmalloced));
	TRY0(xmlTextWriterEndElement(writer)); /* maxmalloced */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "pools"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%u", ctx->poolcnt));
	TRY0(xmlTextWriterEndElement(writer)); /* pools */
	summary->contextsize += ctx->poolcnt * sizeof(isc_mempool_t);

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "hiwater"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    (uint64_t)ctx->hi_water));
	TRY0(xmlTextWriterEndElement(writer)); /* hiwater */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "lowater"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    (uint64_t)ctx->lo_water));
	TRY0(xmlTextWriterEndElement(writer)); /* lowater */

	TRY0(xmlTextWriterEndElement(writer)); /* context */

 error:
	MCTXUNLOCK(ctx, &ctx->lock);

	return (xmlrc);
}

int
isc_mem_renderxml(const xmlTextWriterPtr writer) {
	isc_mem_t *ctx;
	summarystat_t summary;
	uint64_t lost;
	int xmlrc;

	memset(&summary, 0, sizeof(summary));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "contexts"));

	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);

	LOCK(&contextslock);
	lost = totallost;
	for (ctx = ISC_LIST_HEAD(contexts);
	     ctx != NULL;
	     ctx = ISC_LIST_NEXT(ctx, link)) {
		xmlrc = xml_renderctx(ctx, &summary, writer);
		if (xmlrc < 0) {
			UNLOCK(&contextslock);
			goto error;
		}
	}
	UNLOCK(&contextslock);

	TRY0(xmlTextWriterEndElement(writer)); /* contexts */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "summary"));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "TotalUse"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    summary.total));
	TRY0(xmlTextWriterEndElement(writer)); /* TotalUse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "InUse"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    summary.inuse));
	TRY0(xmlTextWriterEndElement(writer)); /* InUse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "Malloced"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    summary.malloced));
	TRY0(xmlTextWriterEndElement(writer)); /* InUse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "BlockSize"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    summary.blocksize));
	TRY0(xmlTextWriterEndElement(writer)); /* BlockSize */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "ContextSize"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    summary.contextsize));
	TRY0(xmlTextWriterEndElement(writer)); /* ContextSize */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "Lost"));
	TRY0(xmlTextWriterWriteFormatString(writer,
					    "%" PRIu64 "",
					    lost));
	TRY0(xmlTextWriterEndElement(writer)); /* Lost */

	TRY0(xmlTextWriterEndElement(writer)); /* summary */
 error:
	return (xmlrc);
}

#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON
#define CHECKMEM(m) RUNTIME_CHECK(m != NULL)

static isc_result_t
json_renderctx(isc_mem_t *ctx, summarystat_t *summary, json_object *array) {
	json_object *ctxobj, *obj;
	char buf[1024];
	int64_t total=0, inuse=0, maxinuse=0, malloced=0, maxmalloced=0;
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(summary != NULL);
	REQUIRE(array != NULL);

	total = get_total(ctx);
	inuse = get_inuse(ctx);
	maxinuse = get_maxinuse(ctx);
	malloced = get_malloced(ctx);
	maxmalloced = get_maxmalloced(ctx);

	MCTXLOCK(ctx, &ctx->lock);

	summary->contextsize += sizeof(*ctx);
	summary->total += total;
	summary->inuse += inuse;
	summary->malloced += malloced;
#if ISC_MEM_TRACKLINES
	if (ctx->debuglist != NULL) {
		summary->contextsize +=
			DEBUG_TABLE_COUNT * sizeof(debuglist_t) +
			ctx->debuglistcnt * sizeof(debuglink_t);
	}
#endif

	ctxobj = json_object_new_object();
	CHECKMEM(ctxobj);

	snprintf(buf, sizeof(buf), "%p", ctx);
	obj = json_object_new_string(buf);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "id", obj);

	if (ctx->name[0] != 0) {
		obj = json_object_new_string(ctx->name);
		CHECKMEM(obj);
		json_object_object_add(ctxobj, "name", obj);
	}

	obj = json_object_new_int64(isc_refcount_current(&ctx->references));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "references", obj);

	obj = json_object_new_int64(total);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "total", obj);

	obj = json_object_new_int64(inuse);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "inuse", obj);

	obj = json_object_new_int64(maxinuse);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "maxinuse", obj);

	obj = json_object_new_int64(malloced);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "malloced", obj);

	obj = json_object_new_int64(maxmalloced);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "maxmalloced", obj);

	obj = json_object_new_int64(ctx->poolcnt);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "pools", obj);

	summary->contextsize += ctx->poolcnt * sizeof(isc_mempool_t);

	obj = json_object_new_int64(ctx->hi_water);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "hiwater", obj);

	obj = json_object_new_int64(ctx->lo_water);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "lowater", obj);

	MCTXUNLOCK(ctx, &ctx->lock);
	json_object_array_add(array, ctxobj);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mem_renderjson(json_object *memobj) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_mem_t *ctx;
	summarystat_t summary;
	uint64_t lost;
	json_object *ctxarray, *obj;

	memset(&summary, 0, sizeof(summary));
	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);

	ctxarray = json_object_new_array();
	CHECKMEM(ctxarray);

	LOCK(&contextslock);
	lost = totallost;
	for (ctx = ISC_LIST_HEAD(contexts);
	     ctx != NULL;
	     ctx = ISC_LIST_NEXT(ctx, link)) {
		result = json_renderctx(ctx, &summary, ctxarray);
		if (result != ISC_R_SUCCESS) {
			UNLOCK(&contextslock);
			goto error;
		}
	}
	UNLOCK(&contextslock);

	obj = json_object_new_int64(summary.total);
	CHECKMEM(obj);
	json_object_object_add(memobj, "TotalUse", obj);

	obj = json_object_new_int64(summary.inuse);
	CHECKMEM(obj);
	json_object_object_add(memobj, "InUse", obj);

	obj = json_object_new_int64(summary.malloced);
	CHECKMEM(obj);
	json_object_object_add(memobj, "Malloced", obj);

	obj = json_object_new_int64(summary.blocksize);
	CHECKMEM(obj);
	json_object_object_add(memobj, "BlockSize", obj);

	obj = json_object_new_int64(summary.contextsize);
	CHECKMEM(obj);
	json_object_object_add(memobj, "ContextSize", obj);

	obj = json_object_new_int64(lost);
	CHECKMEM(obj);
	json_object_object_add(memobj, "Lost", obj);

	json_object_object_add(memobj, "contexts", ctxarray);
	return (ISC_R_SUCCESS);

 error:
	if (ctxarray != NULL)
		json_object_put(ctxarray);
	return (result);
}
#endif /* HAVE_JSON */

void
isc__mem_printactive(isc_mem_t *ctx, FILE *file) {
#if ISC_MEM_TRACKLINES
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(file != NULL);

	print_active(ctx, file);
#else
	UNUSED(ctx);
	UNUSED(file);
#endif
}
