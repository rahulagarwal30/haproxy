/*
 * Channel management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/buffer.h>
#include <proto/channel.h>
#include <types/global.h>


struct pool_head *pool2_channel;


/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_channel()
{
	pool2_channel = create_pool("channel", sizeof(struct channel) + global.tune.bufsize, MEM_F_SHARED);
	return pool2_channel != NULL;
}

/* Schedule up to <bytes> more bytes to be forwarded via the channel without
 * notifying the owner task. Any data pending in the buffer are scheduled to be
 * sent as well, in the limit of the number of bytes to forward. This must be
 * the only method to use to schedule bytes to be forwarded. If the requested
 * number is too large, it is automatically adjusted. The number of bytes taken
 * into account is returned. Directly touching ->to_forward will cause lockups
 * when buf->o goes down to zero if nobody is ready to push the remaining data.
 */
unsigned long long channel_forward(struct channel *buf, unsigned long long bytes)
{
	unsigned int new_forward;
	unsigned int forwarded;
	unsigned int bytes32;

	bytes32 = bytes;

	/* hint: avoid comparisons on long long for the fast case, since if the
	 * length does not fit in an unsigned it, it will never be forwarded at
	 * once anyway.
	 */
	if (bytes <= ~0U) {
		if (bytes32 <= buf->buf.i) {
			/* OK this amount of bytes might be forwarded at once */
			if (!bytes32)
				return 0;
			b_adv(&buf->buf, bytes32);
			return bytes;
		}
	}

	forwarded = buf->buf.i;
	b_adv(&buf->buf, buf->buf.i);

	/* Note: the case below is the only case where we may return
	 * a byte count that does not fit into a 32-bit number.
	 */
	if (likely(buf->to_forward == CHN_INFINITE_FORWARD))
		return bytes;

	if (likely(bytes == CHN_INFINITE_FORWARD)) {
		buf->to_forward = bytes;
		return bytes;
	}

	new_forward = buf->to_forward + bytes - forwarded;
	bytes = forwarded; /* at least those bytes were scheduled */

	if (new_forward <= buf->to_forward) {
		/* integer overflow detected, let's assume no more than 2G at once */
		new_forward = MID_RANGE(new_forward);
	}

	if (new_forward > buf->to_forward) {
		bytes += new_forward - buf->to_forward;
		buf->to_forward = new_forward;
	}
	return bytes;
}

/* writes <len> bytes from message <msg> to the channel's buffer. Returns -1 in
 * case of success, -2 if the message is larger than the buffer size, or the
 * number of bytes available otherwise. The send limit is automatically
 * adjusted to the amount of data written. FIXME-20060521: handle unaligned
 * data. Note: this function appends data to the buffer's output and possibly
 * overwrites any pending input data which are assumed not to exist.
 */
int bo_inject(struct channel *buf, const char *msg, int len)
{
	int max;

	if (len == 0)
		return -1;

	if (len > buf->buf.size) {
		/* we can't write this chunk and will never be able to, because
		 * it is larger than the buffer. This must be reported as an
		 * error. Then we return -2 so that writers that don't care can
		 * ignore it and go on, and others can check for this value.
		 */
		return -2;
	}

	max = buffer_realign(&buf->buf);

	if (len > max)
		return max;

	memcpy(buf->buf.p, msg, len);
	buf->buf.o += len;
	buf->buf.p = b_ptr(&buf->buf, len);
	buf->total += len;
	return -1;
}

/* Tries to copy character <c> into the channel's buffer after some length
 * controls. The buf->o and to_forward pointers are updated. If the channel
 * input is closed, -2 is returned. If there is not enough room left in the
 * buffer, -1 is returned. Otherwise the number of bytes copied is returned
 * (1). Channel flag READ_PARTIAL is updated if some data can be transferred.
 */
int bi_putchr(struct channel *buf, char c)
{
	if (unlikely(channel_input_closed(buf)))
		return -2;

	if (channel_full(buf))
		return -1;

	*bi_end(&buf->buf) = c;

	buf->buf.i++;
	buf->flags |= CF_READ_PARTIAL;

	if (buf->to_forward >= 1) {
		if (buf->to_forward != CHN_INFINITE_FORWARD)
			buf->to_forward--;
		b_adv(&buf->buf, 1);
	}

	buf->total++;
	return 1;
}

/* Tries to copy block <blk> at once into the channel's buffer after length
 * controls. The buf->o and to_forward pointers are updated. If the channel
 * input is closed, -2 is returned. If the block is too large for this buffer,
 * -3 is returned. If there is not enough room left in the buffer, -1 is
 * returned. Otherwise the number of bytes copied is returned (0 being a valid
 * number). Channel flag READ_PARTIAL is updated if some data can be
 * transferred.
 */
int bi_putblk(struct channel *buf, const char *blk, int len)
{
	int max;

	if (unlikely(channel_input_closed(buf)))
		return -2;

	max = buffer_max_len(buf);
	if (unlikely(len > max - buffer_len(&buf->buf))) {
		/* we can't write this chunk right now because the buffer is
		 * almost full or because the block is too large. Return the
		 * available space or -2 if impossible.
		 */
		if (len > max)
			return -3;

		return -1;
	}

	if (unlikely(len == 0))
		return 0;

	/* OK so the data fits in the buffer in one or two blocks */
	max = buffer_contig_space_with_res(&buf->buf, buf->buf.size - max);
	memcpy(bi_end(&buf->buf), blk, MIN(len, max));
	if (len > max)
		memcpy(buf->buf.data, blk + max, len - max);

	buf->buf.i += len;
	buf->total += len;
	if (buf->to_forward) {
		unsigned long fwd = len;
		if (buf->to_forward != CHN_INFINITE_FORWARD) {
			if (fwd > buf->to_forward)
				fwd = buf->to_forward;
			buf->to_forward -= fwd;
		}
		b_adv(&buf->buf, fwd);
	}

	/* notify that some data was read from the SI into the buffer */
	buf->flags |= CF_READ_PARTIAL;
	return len;
}

/* Gets one text line out of a channel's buffer from a stream interface.
 * Return values :
 *   >0 : number of bytes read. Includes the \n if present before len or end.
 *   =0 : no '\n' before end found. <str> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 * The channel status is not changed. The caller must call bo_skip() to
 * update it. The '\n' is waited for as long as neither the buffer nor the
 * output are full. If either of them is full, the string may be returned
 * as is, without the '\n'.
 */
int bo_getline(struct channel *buf, char *str, int len)
{
	int ret, max;
	char *p;

	ret = 0;
	max = len;

	/* closed or empty + imminent close = -1; empty = 0 */
	if (unlikely((buf->flags & CF_SHUTW) || channel_is_empty(buf))) {
		if (buf->flags & (CF_SHUTW|CF_SHUTW_NOW))
			ret = -1;
		goto out;
	}

	p = bo_ptr(&buf->buf);

	if (max > buf->buf.o) {
		max = buf->buf.o;
		str[max-1] = 0;
	}
	while (max) {
		*str++ = *p;
		ret++;
		max--;

		if (*p == '\n')
			break;
		p = buffer_wrap_add(&buf->buf, p + 1);
	}
	if (ret > 0 && ret < len && ret < buf->buf.o &&
	    *(str-1) != '\n' &&
	    !(buf->flags & (CF_SHUTW|CF_SHUTW_NOW)))
		ret = 0;
 out:
	if (max)
		*str = 0;
	return ret;
}

/* Gets one full block of data at once from a channel's buffer, optionally from
 * a specific offset. Return values :
 *   >0 : number of bytes read, equal to requested size.
 *   =0 : not enough data available. <blk> is left undefined.
 *   <0 : no more bytes readable because output is shut.
 * The channel status is not changed. The caller must call bo_skip() to
 * update it.
 */
int bo_getblk(struct channel *buf, char *blk, int len, int offset)
{
	int firstblock;

	if (buf->flags & CF_SHUTW)
		return -1;

	if (len + offset > buf->buf.o) {
		if (buf->flags & (CF_SHUTW|CF_SHUTW_NOW))
			return -1;
		return 0;
	}

	firstblock = buf->buf.data + buf->buf.size - bo_ptr(&buf->buf);
	if (firstblock > offset) {
		if (firstblock >= len + offset) {
			memcpy(blk, bo_ptr(&buf->buf) + offset, len);
			return len;
		}

		memcpy(blk, bo_ptr(&buf->buf) + offset, firstblock - offset);
		memcpy(blk + firstblock - offset, buf->buf.data, len - firstblock + offset);
		return len;
	}

	memcpy(blk, buf->buf.data + offset - firstblock, len);
	return len;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
