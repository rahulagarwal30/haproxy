/*
 * internal HTTP message
 *
 * Copyright 2018 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/chunk.h>
#include <proto/htx.h>

struct htx htx_empty = { .size = 0, .data = 0, .used = 0 };

/* Defragments an HTTP message, removing unused blocks and unwrapping blocks and
 * their contents. A temporary message is used to do so. This function never
 * fails. if <blk> is not NULL, we replace it by the new block address, after
 * the defragmentation. The new <blk> is returned.
 */
/* TODO: merge data blocks into one */
struct htx_blk *htx_defrag(struct htx *htx, struct htx_blk *blk)
{
        struct buffer *chunk = get_trash_chunk();
        struct htx *tmp = htx_from_buf(chunk);
        struct htx_blk *newblk, *oldblk;
        uint32_t new, old;
        uint32_t addr, blksz;

        if (!htx->used)
                return NULL;

        new  = 0;
        addr = 0;
        tmp->size = htx->size;

        /* start from the head */
        for (old = htx_get_head(htx); old != -1; old = htx_get_next(htx, old)) {
                oldblk = htx_get_blk(htx, old);
                if (htx_get_blk_type(oldblk) == HTX_BLK_UNUSED) {
                        htx->used--;
                        continue;
                }

                newblk = htx_get_blk(tmp, new);
                newblk->addr = addr;
                newblk->info = oldblk->info;
                blksz = htx_get_blksz(oldblk);

                memcpy((void *)tmp->blocks + addr, htx_get_blk_ptr(htx, oldblk), blksz);
                new++;
                addr += blksz;

                /* if <blk> is defined, set its new location */
                if (blk != NULL && blk == oldblk)
                        blk = newblk;
        } while (new < htx->used);

        htx->wrap = htx->used;
        htx->front = htx->tail = new - 1;
        memcpy((void *)htx->blocks, (void *)tmp->blocks, htx->size);

        return blk;
}

/* Reserves a new block in the HTTP message <htx> with a content of <blksz>
 * bytes. If there is not enough space, NULL is returned. Otherwise the reserved
 * block is returned and the HTTP message is updated. Space for this new block
 * is reserved in the HTTP message. But it is the caller responsibility to set
 * right info in the block to reflect the stored data.
 */
static struct htx_blk *htx_reserve_nxblk(struct htx *htx, uint32_t blksz)
{
        struct htx_blk *blk, *prevblk, *headblk, *frtblk;
        uint32_t used;
        uint32_t tail;
        uint32_t prev;
        uint32_t wrap;
        uint32_t head;
        int32_t headroom, tailroom;

        if (blksz > htx_free_data_space(htx))
                return NULL; /* full */

        if (!htx->used) {
                /* Empty message */
                htx->front = htx->tail = 0;
                htx->wrap  = htx->used = 1;
                blk = htx_get_blk(htx, htx->tail);
                blk->addr = 0;
                htx->data = blksz;
                return blk;
        }

        used = htx->used + 1;
        tail = htx->tail + 1;
        prev = htx->tail;
        wrap = htx->wrap;
        head = htx_get_head(htx);

        if (tail == wrap) {
                frtblk = htx_get_blk(htx, htx->front);

                /* Blocks don't wrap for now. We either need to push the new one
                 * on top of others or to defragement the table. */
                if (sizeof(htx->blocks[0]) * htx_pos_to_idx(htx, wrap+1) >= frtblk->addr + htx_get_blksz(frtblk))
                        wrap++;
                else if (tail >= used) /* There is hole at the beginning */
                        tail = 0;
                else {
                        /* No more room, tail hits data. We have to realign the
                         * whole message. */
                        goto defrag;
                }
        }
        else if (used >= wrap) {
                /* We have hit the tail, we need to reorganize the blocks. */
                goto defrag;
        }

        /* Now we have updated tail, used and wrap, we know that there is some
         * available room at least from the protocol's perspective. This space
         * is split in two areas :
         *
         *   1: the space between the beginning of the blocks table and the
         *      front data's address. This space will only be used if data don't
         *      wrap yet.

         *   2: If the previous tail was the front block, the space between the
         *      beginning of the message and the head data's address.
         *      Otherwise, the space between the tail data's address and the
         *      tail's one.
         */
        prevblk = htx_get_blk(htx, prev);
        headblk = htx_get_blk(htx, head);
        if (prevblk->addr >= headblk->addr) {
                /* the area was contiguous */
                frtblk = htx_get_blk(htx, htx->front);
                tailroom = sizeof(htx->blocks[0]) * htx_pos_to_idx(htx, wrap) - (frtblk->addr + htx_get_blksz(frtblk));
                headroom = headblk->addr;

                if (tailroom >= (int32_t)blksz) {
                        /* install upfront and update ->front */
                        blk = htx_get_blk(htx, tail);
                        blk->addr = frtblk->addr + htx_get_blksz(frtblk);
                        htx->front = tail;
                }
                else if (headroom >= (int32_t)blksz) {
                        blk = htx_get_blk(htx, tail);
                        blk->addr = 0;
                }
                else {
                        /* need to defragment the table before inserting upfront */
                        goto defrag;
                }
        }
        else {
                /* it's already wrapped so we can't store anything in the tailroom */
                headroom = headblk->addr - (prevblk->addr + htx_get_blksz(prevblk));

                if (headroom >= (int32_t)blksz) {
                        blk = htx_get_blk(htx, tail);
                        blk->addr = prevblk->addr + htx_get_blksz(prevblk);
                }
                else {
                  defrag:
                        /* need to defragment the table before inserting upfront */
                        htx_defrag(htx, NULL);
                        frtblk = htx_get_blk(htx, htx->front);
                        wrap = htx->wrap + 1;
                        tail = htx->tail + 1;
                        used = htx->used + 1;
                        blk = htx_get_blk(htx, tail);
                        blk->addr = frtblk->addr + htx_get_blksz(frtblk);
                        htx->front = tail;
                }
        }

        htx->wrap  = wrap;
        htx->tail  = tail;
        htx->used  = used;
        htx->data += blksz;
        return blk;
}

/* Adds a new block of type <type> in the HTTP message <htx>. Its content size
 * is passed but it is the caller responsibility to do the copy.
 */
struct htx_blk *htx_add_blk(struct htx *htx, enum htx_blk_type type, uint32_t blksz)
{
        struct htx_blk *blk;

        blk = htx_reserve_nxblk(htx, blksz);
        if (!blk)
                return NULL;

        blk->info = (type << 28);
        return blk;
}

/* Removes the block <blk> from the HTTP message <htx>. The function returns the
 * block following <blk> or NULL if <blk> is the last block or the last
 * inserted one.
 */
struct htx_blk *htx_remove_blk(struct htx *htx, struct htx_blk *blk)
{
        uint32_t next, head, pos;

        if (htx_get_blk_type(blk) != HTX_BLK_UNUSED) {
                /* Mark the block as unused, decrement allocated size */
                htx->data -= htx_get_blksz(blk);
                blk->info = ((uint32_t)HTX_BLK_UNUSED << 28);
        }

        /* This is the last block in use */
        if (htx->used == 1/* || !htx->data */) {
                htx->front = htx->tail = 0;
                htx->wrap  = htx->used = 0;
                htx->data = 0;
                return NULL;
        }

        /* There is at least 2 blocks, so tail is always >= 0 */
        pos  = htx_get_blk_pos(htx, blk);
        head = htx_get_head(htx);
        blk  = NULL;
        next = pos + 1; /* By default retrun the next block */
        if (htx->tail + 1 == htx->wrap) {
                /* The HTTP message doesn't wrap */
                if (pos == head) {
                        /* remove the head, so just return the new head */
                        htx->used--;
                        next = htx_get_head(htx);
                }
                else if (pos == htx->tail) {
                        /* remove the tail. this was the last inserted block so
                         * return NULL. */
                        htx->wrap--;
                        htx->tail--;
                        htx->used--;
                        goto end;
                }
        }
        else {
                /* The HTTP message wraps */
                if (pos == htx->tail) {
                        /* remove the tail. try to unwrap the message (pos == 0)
                         * and return NULL. */
                        htx->tail = ((pos == 0) ? htx->wrap-1 : htx->tail-1);
                        htx->used--;
                        goto end;
                }
                else if (pos == head) {
                        /* remove the head, try to unwrap the message (pos+1 ==
                         * wrap) and return the new head */
                        htx->used--;
                        if (pos + 1 == htx->wrap)
                                htx->wrap = htx->tail + 1;
                        next = htx_get_head(htx);
                }
        }

        blk = htx_get_blk(htx, next);
  end:
        if (pos == htx->front)
                htx->front = htx_find_front(htx);
        return blk;
}

/* Tries to append data to the last inserted block, if the type matches and if
 * there is enough non-wrapping space. Only DATA and TRAILERS content can be
 * appended. If the append fails, a new block is inserted. If an error occurred,
 * NULL is returned. Otherwise, on success, the updated block (or the new one)
 * is returned.
*/
static struct htx_blk *htx_append_blk_value(struct htx *htx, enum htx_blk_type type,
					    const struct ist data)
{
        struct htx_blk *blk;
        struct ist     v;

        if (!htx->used)
                goto add_new_block;

        /* Not enough space to store data */
        if (data.len > htx_free_data_space(htx))
                return NULL;

        /* Append only DATA et TRAILERS data */
        if (type != HTX_BLK_DATA && type != HTX_BLK_TLR)
                goto add_new_block;

        /* get the tail block */
        blk = htx_get_blk(htx, htx->tail);

        /* Don't try to append data if the last inserted block is not of the
         * same type */
        if (type != htx_get_blk_type(blk))
                goto add_new_block;

        /*
         * Same type and enough space: append data
         */
        if (htx->tail + 1 == htx->wrap) {
                struct htx_blk *frtblk = htx_get_blk(htx, htx->front);
                int32_t tailroom = sizeof(htx->blocks[0]) * htx_pos_to_idx(htx, htx->tail) - (frtblk->addr + htx_get_blksz(frtblk));
                if (tailroom >= (int32_t)data.len)
                        goto append_data;
                htx_defrag(htx, NULL);
                blk = htx_get_blk(htx, htx->tail);
        }
        else {
                struct htx_blk *headblk = htx_get_blk(htx, htx_get_head(htx));
                int32_t headroom = headblk->addr - (blk->addr + htx_get_blksz(blk));
                if (headroom >= (int32_t)data.len)
                        goto append_data;
                htx_defrag(htx, NULL);
                blk = htx_get_blk(htx, htx->tail);
        }

  append_data:
        /* get the value of the tail block */
        /* FIXME: check v.len + data.len < 256MB */
        v = htx_get_blk_value(htx, blk);

        /* Append data and update the block itself */
        memcpy(v.ptr + v.len, data.ptr, data.len);
        htx_set_blk_value_len(blk, v.len + data.len);

        /* Update HTTP message */
        htx->data += data.len;

        return blk;

  add_new_block:
        /* FIXME: check tlr.len (< 256MB) */
        blk = htx_add_blk(htx, type, data.len);
        if (!blk)
                return NULL;

        blk->info += data.len;
        memcpy(htx_get_blk_ptr(htx, blk), data.ptr, data.len);
        return blk;
}

/* Replaces a value part of a block by a new one. The new part can be smaller or
 * larger than the old one. This function works for any kind of block with
 * attached data. It returns the new block on success, otherwise it returns
 * NULL.
 */
struct htx_blk *htx_replace_blk_value(struct htx *htx, struct htx_blk *blk,
                                      const struct ist old, const struct ist new)
{
        struct htx_blk *frtblk;
        struct buffer  *tmp;
        struct ist n, v;
        uint32_t info, room;

        n = htx_get_blk_name(htx, blk);
        v = htx_get_blk_value(htx, blk);

        /* easy case, new data are smaller, so replace it in-place */
        if (new.len <= old.len) {
                memcpy(old.ptr, new.ptr, new.len);
                if (old.len != v.len)
                        memmove(old.ptr + new.len, old.ptr + old.len, (v.ptr + v.len) - (old.ptr + old.len));
                htx_set_blk_value_len(blk, v.len - old.len + new.len);
                htx->data -= (old.len - new.len);
                return blk;
        }

        /* we need to allocate more space to store the new header value */
        if ((new.len - old.len) > htx_free_space(htx))
                return NULL; /* not enough space */

        /*
         * Copy the new header in a temp buffer
         */
        tmp = get_trash_chunk();

        /*     1. copy the header name */
        chunk_memcat(tmp, n.ptr, n.len);

        /*     2. copy value before old part, if any */
        if (old.ptr != v.ptr)
                chunk_memcat(tmp, v.ptr, old.ptr - v.ptr);

        /*     3. copy new value */
        chunk_memcat(tmp, new.ptr, new.len);

        /*     4. copy value after old part if any */
        if (old.len != v.len)
                chunk_memcat(tmp, old.ptr + old.len, (v.ptr + v.len) - (old.ptr + old.len));

        /*
         * temporarely remove space reserved for the header
         */
        info = blk->info;
        blk->info &= 0xf0000000;
        htx->data -= (n.len + v.len);

        /*
         * Try to find right addr to copy all the data
         */
        if (htx->tail + 1 == htx->wrap) {
                frtblk = htx_get_blk(htx, htx->front);
                room   = sizeof(htx->blocks[0]) * htx_pos_to_idx(htx, htx->tail) - (frtblk->addr + htx_get_blksz(frtblk));
                if (room >= htx->data) {
                        blk->addr = frtblk->addr + htx_get_blksz(frtblk);
                        goto replace_value;
                }
        }

        /* HTX message need to be defragmented first */
        blk    = htx_defrag(htx, blk);
        frtblk = htx_get_blk(htx, htx->front);
        blk->addr = frtblk->addr + htx_get_blksz(frtblk);

  replace_value:
        blk->info = info;
        htx_set_blk_value_len(blk, v.len - old.len + new.len);
        memcpy(htx_get_blk_ptr(htx, blk), tmp->area, tmp->data);
        htx->data += tmp->data;
        htx->front = htx_get_blk_pos(htx, blk);

        return blk;
}

/* Transfer HTX blocks from <src> to <dst>, stopping on the first block of the
 * type <mark> (typically EOH, EOD or EOM) or when <count> bytes of data were
 * moved. It returns the number of bytes of data moved and the last HTX block
 * inserted in <dst>.
 */
struct htx_ret htx_xfer_blks(struct htx *dst, struct htx *src, uint32_t count,
			     enum htx_blk_type mark)
{
	struct htx_blk   *blk, *dstblk;
	enum htx_blk_type type;
	uint32_t          info, max, sz, ret;

	ret = 0;
	blk = htx_get_blk(src, htx_get_head(src));
	dstblk = NULL;
	while (blk && ret <= count) {
		type = htx_get_blk_type(blk);

		/* Ingore unused block */
		if (type == HTX_BLK_UNUSED)
			goto next;

		sz = htx_get_blksz(blk);
		if (!sz) {
			dstblk = htx_reserve_nxblk(dst, 0);
			if (!dstblk)
				break;
			dstblk->info = blk->info;
			goto next;
		}

		info = blk->info;
		max = htx_free_data_space(dst);
		if (max > count)
			max = count;
		if (sz > max) {
			sz = max;
			info = (type << 28) + sz;
			/* Headers and pseudo headers must be fully copied  */
			if (type < HTX_BLK_DATA || !sz)
				break;
		}

		dstblk = htx_reserve_nxblk(dst, sz);
		if (!dstblk)
			break;
		dstblk->info = info;
		memcpy(htx_get_blk_ptr(dst, dstblk), htx_get_blk_ptr(src, blk), sz);

		ret += sz;
		if (blk->info != info) {
			/* Partial move: don't remove <blk> from <src> but
			 * resize its content */
			blk->addr += sz;
			htx_set_blk_value_len(blk, htx_get_blksz(blk) - sz);
			src->data -= sz;
			break;
		}

	  next:
		blk = htx_remove_blk(src, blk);
		if (type == mark)
			break;

	}

	return (struct htx_ret){.ret = ret, .blk = dstblk};
}

static struct htx_blk *htx_new_blk_value(struct htx *htx, struct htx_blk *blk,
					 uint32_t newsz)
{
        struct htx_blk *frtblk;
        uint32_t sz, room;
        int32_t delta;

	sz = htx_get_blksz(blk);
        delta = newsz - sz;

        /* easy case, new value is smaller, so replace it in-place */
        if (delta <= 0) {
		/* Reset value size. It is the caller responsibility to set the new one */
		blk->info &= 0xf0000000;
                htx->data += delta;
                return blk;
        }

        /* we need to allocate more space to store the new value */
        if (delta > htx_free_space(htx))
                return NULL; /* not enough space */

        /*
         * temporarely remove space reserved for the old value
         */
	/* Reset value size. It is the caller responsibility to set the new one */
	blk->info &= 0xf0000000;
        htx->data -= sz;

        /*
         * Try to find right addr to copy all the data
         */
        if (htx->tail + 1 == htx->wrap) {
                frtblk = htx_get_blk(htx, htx->front);
                room   = sizeof(htx->blocks[0]) * htx_pos_to_idx(htx, htx->tail) - (frtblk->addr + htx_get_blksz(frtblk));
                if (room >= newsz)
                        goto replace_value;
        }

        /* HTX message need to be defragmented first */
        blk    = htx_defrag(htx, blk);
        frtblk = htx_get_blk(htx, htx->front);

  replace_value:
        blk->addr = frtblk->addr + htx_get_blksz(frtblk);
        htx->data += newsz;
        htx->front = htx_get_blk_pos(htx, blk);

        return blk;
}

/* Replaces an header by a new one. The new header can be smaller or larger than
 * the old one. It returns the new block on success, otherwise it returns NULL.
 */
struct htx_blk *htx_replace_header(struct htx *htx, struct htx_blk *blk,
                                   const struct ist name, const struct ist value)
{
        enum htx_blk_type type;

        type = htx_get_blk_type(blk);
        if (type != HTX_BLK_HDR)
                return NULL;

	blk = htx_new_blk_value(htx, blk, (name.len + value.len));
	if (!blk)
		return NULL;

	blk->info = (type << 28) + (value.len << 8) + name.len;
        memcpy(htx_get_blk_ptr(htx, blk), name.ptr, name.len);
        memcpy(htx_get_blk_ptr(htx, blk) + name.len, value.ptr, value.len);

        return blk;
}

static void htx_set_blk_reqline(struct htx *htx, struct htx_blk *blk, const union h1_sl sl)
{
	union htx_sl *htx_sl;

	htx_sl = htx_get_blk_ptr(htx, blk);
	htx_sl->rq.meth = sl.rq.meth;

	htx_sl->rq.m_len = sl.rq.m.len;
	htx_sl->rq.u_len = sl.rq.u.len;
	htx_sl->rq.v_len = sl.rq.v.len;

	memcpy(htx_sl->rq.l,                             sl.rq.m.ptr, sl.rq.m.len);
	memcpy(htx_sl->rq.l + sl.rq.m.len,               sl.rq.u.ptr, sl.rq.u.len);
	memcpy(htx_sl->rq.l + sl.rq.m.len + sl.rq.u.len, sl.rq.v.ptr, sl.rq.v.len);
}


static void htx_set_blk_resline(struct htx *htx, struct htx_blk *blk, const union h1_sl sl)
{
	union htx_sl *htx_sl;

	htx_sl = htx_get_blk_ptr(htx, blk);
	htx_sl->st.status = sl.st.status;

	htx_sl->st.v_len = sl.st.v.len;
	htx_sl->st.c_len = sl.st.c.len;
	htx_sl->st.r_len = sl.st.r.len;

	memcpy(htx_sl->st.l,                             sl.st.v.ptr, sl.st.v.len);
	memcpy(htx_sl->st.l + sl.st.v.len,               sl.st.c.ptr, sl.st.c.len);
	memcpy(htx_sl->st.l + sl.st.v.len + sl.st.c.len, sl.st.r.ptr, sl.st.r.len);
}

/* Replaces the request start line a new one. It returns the new block on
 * success, otherwise it returns NULL.
 */
struct htx_blk *htx_replace_reqline(struct htx *htx, struct htx_blk *blk,
				    const union h1_sl sl)
{
        enum htx_blk_type type;
	uint32_t size;

        type = htx_get_blk_type(blk);
        if (type != HTX_BLK_REQ_SL)
                return NULL;

	size = sizeof(struct htx_sl) + sl.rq.m.len + sl.rq.u.len + sl.rq.v.len;
	blk = htx_new_blk_value(htx, blk, size);
	if (!blk)
		return NULL;

	blk->info = (type << 28) + size;
        htx_set_blk_reqline(htx, blk, sl);
	return blk;
}

/* Replaces the response start line a new one. It returns the new block on
 * success, otherwise it returns NULL.
 */
struct htx_blk *htx_replace_resline(struct htx *htx, struct htx_blk *blk,
				    const union h1_sl sl)
{
        enum htx_blk_type type;
	uint32_t size;

        type = htx_get_blk_type(blk);
        if (type != HTX_BLK_RES_SL)
                return NULL;

	size = sizeof(struct htx_sl) + sl.rq.m.len + sl.rq.u.len + sl.rq.v.len;
	blk = htx_new_blk_value(htx, blk, size);
	if (!blk)
		return NULL;

	blk->info = (type << 28) + size;
        htx_set_blk_resline(htx, blk, sl);
	return blk;
}


/* Adds an HTX block of type SL in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL.
 */
struct htx_blk *htx_add_reqline(struct htx *htx, const union h1_sl sl)
{
        struct htx_blk *blk;
	uint32_t size;

	size = sizeof(struct htx_sl) + sl.rq.m.len + sl.rq.u.len + sl.rq.v.len;

        /* FIXME: check size (< 256MB) */
        blk = htx_add_blk(htx, HTX_BLK_REQ_SL, size);
        if (!blk)
                return NULL;

        blk->info += size;
        htx_set_blk_reqline(htx, blk, sl);
        return blk;
}

/* Adds an HTX block of type SL in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL.
 */
struct htx_blk *htx_add_resline(struct htx *htx, const union h1_sl sl)
{
        struct htx_blk *blk;
	uint32_t size;

	size = sizeof(struct htx_sl) + sl.st.v.len + sl.st.c.len + sl.st.r.len;

        /* FIXME: check size (< 256MB) */
        blk = htx_add_blk(htx, HTX_BLK_RES_SL, size);
        if (!blk)
                return NULL;

        blk->info += size;
        htx_set_blk_resline(htx, blk, sl);
        return blk;
}

/* Adds an HTX block of type HDR in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL.
 */
struct htx_blk *htx_add_header(struct htx *htx, const struct ist name,
                               const struct ist value)
{
        struct htx_blk *blk;

        /* FIXME: check name.len (< 256B) and value.len (< 1MB) */
        blk = htx_add_blk(htx, HTX_BLK_HDR, name.len + value.len);
        if (!blk)
                return NULL;

        blk->info += (value.len << 8) + name.len;
        memcpy(htx_get_blk_ptr(htx, blk), name.ptr, name.len);
        memcpy(htx_get_blk_ptr(htx, blk)  + name.len, value.ptr, value.len);
        return blk;
}

struct htx_blk *htx_add_all_headers(struct htx *htx, const struct http_hdr *hdrs)
{
	int i;

	for (i = 0; hdrs[i].n.len; i++) {
		if (!htx_add_header(htx, hdrs[i].n, hdrs[i].v))
			return NULL;
	}
	return htx_add_endof(htx, HTX_BLK_EOH);
}
/* Adds an HTX block of type PHDR in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL.
 */
struct htx_blk *htx_add_pseudo_header(struct htx *htx,  enum htx_phdr_type phdr,
                                      const struct ist value)
{
        struct htx_blk *blk;

        /* FIXME: check value.len ( < 1MB) */
        blk = htx_add_blk(htx, HTX_BLK_PHDR, value.len);
        if (!blk)
                return NULL;

        blk->info += (value.len << 8) + phdr;
        memcpy(htx_get_blk_ptr(htx, blk), value.ptr, value.len);
        return blk;
}

/* Adds an HTX block of type EOH,EOD or EOM in <htx>. It returns the new block
 * on success. Otherwise, it returns NULL.
 */
struct htx_blk *htx_add_endof(struct htx *htx, enum htx_blk_type type)
{
        struct htx_blk *blk;

        blk = htx_add_blk(htx, type, 1);
        if (!blk)
                return NULL;

        blk->info += 1;
        return blk;
}


/* Adds an HTX block of type DATA in <htx>. It first tries to append data if
 * possible. It returns the new block on success. Otherwise, it returns NULL.
 */
struct htx_blk *htx_add_data(struct htx *htx, const struct ist data)
{
        return htx_append_blk_value(htx, HTX_BLK_DATA, data);
}

/* Adds an HTX block of type TLR in <htx>. It first tries to append trailers
 * data if possible. It returns the new block on success. Otherwise, it returns
 * NULL.
 */
struct htx_blk *htx_add_trailer(struct htx *htx, const struct ist tlr)
{
        return htx_append_blk_value(htx, HTX_BLK_TLR, tlr);
}

/* Adds an HTX block of type OOB in <htx>. It returns the new block on
 * success. Otherwise, it returns NULL.
 */
struct htx_blk *htx_add_oob(struct htx *htx, const struct ist oob)
{
        struct htx_blk *blk;

        /* FIXME: check oob.len (< 256MB) */
        blk = htx_add_blk(htx, HTX_BLK_OOB, oob.len);
        if (!blk)
                return NULL;

        blk->info += oob.len;
        memcpy(htx_get_blk_ptr(htx, blk), oob.ptr, oob.len);
        return blk;
}

struct htx_blk *htx_add_data_before(struct htx *htx, const struct htx_blk *ref,
				    const struct ist data)
{
	struct htx_blk *blk;
	int32_t prev;

        /* FIXME: check data.len (< 256MB) */
        blk = htx_add_blk(htx, HTX_BLK_DATA, data.len);
        if (!blk)
                return NULL;

        blk->info += data.len;
        memcpy(htx_get_blk_ptr(htx, blk), data.ptr, data.len);

	for (prev = htx_get_prev(htx, htx->tail); prev != -1; prev = htx_get_prev(htx, prev)) {
		struct htx_blk *pblk = htx_get_blk(htx, prev);

		/* Swap .addr and .info fields */
		blk->addr ^= pblk->addr; pblk->addr ^= blk->addr; blk->addr ^= pblk->addr;
		blk->info ^= pblk->info; pblk->info ^= blk->info; blk->info ^= pblk->info;

		if (blk->addr == pblk->addr)
			blk->addr += htx_get_blksz(pblk);
		htx->front = prev;

		if (pblk == ref)
			break;
		blk = pblk;
	}
	return blk;
}

/* Appends the string representation of the request line block <blk> to the
 * chunk <chk>. It returns 1 if data are successfully appended, otherwise it
 * returns 0.
 */
int htx_reqline_to_str(const union htx_sl *sl, struct buffer *chk)
{
	if (sl->rq.m_len + sl->rq.u_len + sl->rq.v_len + 4 > b_room(chk))
		return 0;

	chunk_memcat(chk, sl->rq.l, sl->rq.m_len);
	chunk_memcat(chk, " ", 1);
	chunk_memcat(chk, sl->rq.l + sl->rq.m_len, sl->rq.u_len);
	chunk_memcat(chk, " ", 1);
	chunk_memcat(chk, sl->rq.l + sl->rq.m_len + sl->rq.u_len, sl->rq.v_len);
	chunk_memcat(chk, "\r\n", 2);

	return 1;
}

/* Appends the string representation of the status line block <blk> to the chunk
 * <chk>. It returns 1 if data are successfully appended, otherwise it
 * returns 0.
 */
int htx_stline_to_str(const union htx_sl *sl, struct buffer *chk)
{
	if (sl->st.v_len + sl->st.c_len + sl->st.r_len + 4 > b_size(chk))
		return 0;

	chunk_memcat(chk, sl->st.l, sl->st.v_len);
	chunk_memcat(chk, " ", 1);
	chunk_memcat(chk, sl->st.l + sl->st.v_len, sl->st.c_len);
	chunk_memcat(chk, " ", 1);
	chunk_memcat(chk, sl->st.l + sl->st.v_len + sl->st.c_len, sl->st.r_len);
	chunk_memcat(chk, "\r\n", 2);

	return 1;
}

/* Appends the string representation of the header block <blk> to the chunk
 * <chk>. It returns 1 if data are successfully appended, otherwise it returns
 * 0.
 */
int htx_hdr_to_str(const struct ist n, const struct ist v, struct buffer *chk)
{
	if (n.len + v.len + 4 > b_room(chk))
		return 0;

	chunk_memcat(chk, n.ptr, n.len);
	chunk_memcat(chk, ": ", 2);
	chunk_memcat(chk, v.ptr, v.len);
	chunk_memcat(chk, "\r\n", 2);

	return 1;
}

/* Appends the string representation of the data block <blk> to the chunk
 * <chk>. If <chunked> is non-zero, it emits HTTP/1 chunk-encoded data. It
 * returns 1 if data are successfully appended, otherwise it returns 0.
 */
int htx_data_to_str(const struct ist data, struct buffer *chk, int chunked)
{
	if (chunked) {
		uint32_t chksz;
		char     tmp[10];
		char    *beg, *end;

		chksz = data.len;

		beg = end = tmp+10;
		*--beg = '\n';
		*--beg = '\r';
		do {
			*--beg = hextab[chksz & 0xF];
		} while (chksz >>= 4);

		if (data.len + (end - beg) + 2 > b_room(chk))
			return 0;
		chunk_memcat(chk, beg, end - beg);
		chunk_memcat(chk, data.ptr, data.len);
		chunk_memcat(chk, "\r\n", 2);
	}
	else {
		if (!chunk_memcat(chk, data.ptr, data.len))
			return 0;
	}

	return 1;
}

/* Appends the string representation of the trailer block <blk> to the chunk
 * <chk>. It returns 1 if data are successfully appended, otherwise it returns
 * 0.
 */
int htx_trailer_to_str(const struct ist tlr, struct buffer *chk)
{
	/* FIXME: be sure the CRLF is here or remove it when inserted */
	if (!chunk_memcat(chk, tlr.ptr, tlr.len))
		return 0;
	return 1;
}
