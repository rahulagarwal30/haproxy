/*
 * include/proto/proto_http.h
 * This file contains HTTP/2 protocol definitions.
 *
 * Copyright (C) 2000-2016 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_PROTO_H2_H
#define _PROTO_PROTO_H2_H

#include <common/config.h>
#include <types/proto_h2.h>
#include <types/stream.h>
#include <proto/channel.h>

/* human-readable frame type names */
extern const char *h2_ft_strings[H2_FT_ENTRIES];


int h2c_frt_init(struct stream *s);

/* receives the next H2 frame and stores the length in <len>, the flags and
 * the type in <type> ((flags << 8) | type), and the stream ID in <sid>.
 * If the frame is properly received, the channel is automatically advanced.
 * Otherwise 0 is returned if bytes are missing, or -1 if the channel is
 * closed.
 */
static inline int h2_get_frame(struct channel *chn, int *len, int *type, int *sid)
{
	uint8_t copy[9];
	const uint8_t *ptr;
	int i;

	/* closed or incomplete + imminent close = -1; incomplete = 0 */
	if (unlikely((chn->flags & CF_SHUTW) || chn->buf->o < 9)) {
		if (chn->flags & (CF_SHUTW|CF_SHUTW_NOW))
			return -1;
		return 0;
	}

	ptr = (const uint8_t *)bo_ptr(chn->buf);
	if (unlikely(ptr + 9 > (uint8_t *)chn->buf->data + chn->buf->size)) {
		/* unwrap buffer wrap */
		for (i = 0; i < 9; i++)
			copy[i] = *b_ptr(chn->buf, (int)(i - chn->buf->o));
		ptr = copy;
	}

	*len  = (ptr[0] << 16) + (ptr[1] << 8) + ptr[2];
	*type = (ptr[4] << 8) + ptr[3];
	*sid  = ((ptr[5] << 24) + (ptr[6] << 16) + (ptr[7] << 8) + ptr[8]) & 0x7fffffff;

	bo_skip(chn, 9);
	return 1;
}

/* returns a const string giving the name of frame type <type>. It may contain
 * the flags which are ignored.
 */
static inline const char *h2_ft_str(int type)
{
	type &= 0xff;
	if (type >= H2_FT_ENTRIES)
		return "_UNKNOWN_";
	return h2_ft_strings[type];
}

#endif /* _PROTO_PROTO_H2_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
