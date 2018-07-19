/*
 * include/common/buffer.h
 * Buffer management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _COMMON_BUFFER_H
#define _COMMON_BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/buf.h>
#include <common/chunk.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/istbuf.h>
#include <common/memory.h>


/* an element of the <buffer_wq> list. It represents an object that need to
 * acquire a buffer to continue its process. */
struct buffer_wait {
	void *target;              /* The waiting object that should be woken up */
	int (*wakeup_cb)(void *);  /* The function used to wake up the <target>, passed as argument */
	struct list list;          /* Next element in the <buffer_wq> list */
};

extern struct pool_head *pool_head_buffer;
extern struct buffer buf_empty;
extern struct buffer buf_wanted;
extern struct list buffer_wq;
__decl_hathreads(extern HA_SPINLOCK_T buffer_wq_lock);

int init_buffer();
void deinit_buffer();
int buffer_replace2(struct buffer *b, char *pos, char *end, const char *str, int len);
void buffer_dump(FILE *o, struct buffer *b, int from, int to);

/*****************************************************************/
/* These functions are used to compute various buffer area sizes */
/*****************************************************************/

/* Return 1 if the buffer has less than 1/4 of its capacity free, otherwise 0 */
static inline int buffer_almost_full(const struct buffer *buf)
{
	if (buf == &buf_empty)
		return 0;

	return b_almost_full(buf);
}

/**************************************************/
/* Functions below are used for buffer allocation */
/**************************************************/

/* Allocates a buffer and replaces *buf with this buffer. If no memory is
 * available, &buf_wanted is used instead. No control is made to check if *buf
 * already pointed to another buffer. The allocated buffer is returned, or
 * NULL in case no memory is available.
 */
static inline struct buffer *b_alloc(struct buffer **buf)
{
	struct buffer *b;

	*buf = &buf_wanted;
	b = pool_alloc_dirty(pool_head_buffer);
	if (likely(b)) {
		b->size = pool_head_buffer->size - sizeof(struct buffer);
		b_reset(b);
		*buf = b;
	}
	return b;
}

/* Allocates a buffer and replaces *buf with this buffer. If no memory is
 * available, &buf_wanted is used instead. No control is made to check if *buf
 * already pointed to another buffer. The allocated buffer is returned, or
 * NULL in case no memory is available. The difference with b_alloc() is that
 * this function only picks from the pool and never calls malloc(), so it can
 * fail even if some memory is available.
 */
static inline struct buffer *b_alloc_fast(struct buffer **buf)
{
	struct buffer *b;

	*buf = &buf_wanted;
	b = pool_get_first(pool_head_buffer);
	if (likely(b)) {
		b->size = pool_head_buffer->size - sizeof(struct buffer);
		b_reset(b);
		*buf = b;
	}
	return b;
}

/* Releases buffer *buf (no check of emptiness) */
static inline void __b_drop(struct buffer **buf)
{
	pool_free(pool_head_buffer, *buf);
}

/* Releases buffer *buf if allocated. */
static inline void b_drop(struct buffer **buf)
{
	if (!(*buf)->size)
		return;
	__b_drop(buf);
}

/* Releases buffer *buf if allocated, and replaces it with &buf_empty. */
static inline void b_free(struct buffer **buf)
{
	b_drop(buf);
	*buf = &buf_empty;
}

/* Ensures that <buf> is allocated. If an allocation is needed, it ensures that
 * there are still at least <margin> buffers available in the pool after this
 * allocation so that we don't leave the pool in a condition where a session or
 * a response buffer could not be allocated anymore, resulting in a deadlock.
 * This means that we sometimes need to try to allocate extra entries even if
 * only one buffer is needed.
 *
 * We need to lock the pool here to be sure to have <margin> buffers available
 * after the allocation, regardless how many threads that doing it in the same
 * time. So, we use internal and lockless memory functions (prefixed with '__').
 */
static inline struct buffer *b_alloc_margin(struct buffer **buf, int margin)
{
	struct buffer *b;

	if ((*buf)->size)
		return *buf;

	*buf = &buf_wanted;
#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_LOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	/* fast path */
	if ((pool_head_buffer->allocated - pool_head_buffer->used) > margin) {
		b = __pool_get_first(pool_head_buffer);
		if (likely(b)) {
#ifndef CONFIG_HAP_LOCKLESS_POOLS
			HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif
			b->size = pool_head_buffer->size - sizeof(struct buffer);
			b_reset(b);
			*buf = b;
			return b;
		}
	}

	/* slow path, uses malloc() */
	b = __pool_refill_alloc(pool_head_buffer, margin);

#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	if (b) {
		b->size = pool_head_buffer->size - sizeof(struct buffer);
		b_reset(b);
		*buf = b;
	}
	return b;
}


/* Offer a buffer currently belonging to target <from> to whoever needs one.
 * Any pointer is valid for <from>, including NULL. Its purpose is to avoid
 * passing a buffer to oneself in case of failed allocations (e.g. need two
 * buffers, get one, fail, release it and wake up self again). In case of
 * normal buffer release where it is expected that the caller is not waiting
 * for a buffer, NULL is fine.
 */
void __offer_buffer(void *from, unsigned int threshold);

static inline void offer_buffers(void *from, unsigned int threshold)
{
	HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	if (LIST_ISEMPTY(&buffer_wq)) {
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		return;
	}
	__offer_buffer(from, threshold);
	HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
}


#endif /* _COMMON_BUFFER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
