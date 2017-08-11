/*
 * include/proto/h2common.h
 * This file contains HTTP/2 protocol definitions.
 *
 * Copyright (C) 2000-2016 Willy Tarreau - w@1wt.eu
 * Copyright 2017 HAProxy Technologies
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

#ifndef _PROTO_H2COMMON_H
#define _PROTO_H2COMMON_H

#include <common/config.h>
#include <types/h2common.h>
#include <types/stream.h>
#include <proto/channel.h>

/* see h2common.c */
extern const char *h2_ft_strings[H2_FT_ENTRIES];
extern const char h2_conn_preface[24];
extern int h2_settings_header_table_size;
extern int h2_settings_initial_window_size;
extern int h2_settings_max_concurrent_streams;


/* reads a 32-bit value at position <str> using big-endian encoding and returns
 * it. The caller guarantees there are enough data.
 */
static inline uint32_t h2_u32_decode(const void *str)
{
#if defined(__x86_64__) ||					\
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
	/* unaligned accesses are OK */
	return ntohl(*(uint32_t *)str);
#else
	/* no unaligned accesses */
	uint8_t *in = str;

	return ((uint32_t)in[0] << 24) |
	       ((uint32_t)in[1] << 16) |
	       ((uint32_t)in[2] <<  8) |
	        (uint32_t)in[3];
#endif
}

/* reads a 16-bit value at position <str> using big-endian encoding and returns
 * it. The caller guarantees there are enough data.
 */
static inline uint16_t h2_u16_decode(const void *str)
{
#if defined(__x86_64__) ||					\
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
	/* unaligned accesses are OK */
	return ntohs(*(uint16_t *)str);
#else
	/* no unaligned accesses */
	uint8_t *in = str;

	return ((uint16_t)in[2] <<  8) | (uint16_t)in[3];
#endif
}

/* writes 32-bit value <v> at position <str> in big-endian encoding. The caller
 * guarantees there is enough room.
 */
static inline void h2_u32_encode(void *str, uint32_t v)
{
#if defined(__x86_64__) ||                                              \
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
	/* unaligned accesses are OK */
	uint32_t *out = str;
	*out = htonl(v);
#else
	/* no unaligned accesses */
	uint8_t *out = str;
	uint16_t vh = v >> 16; // help the compiler

	out[3] = v;
	out[1] = vh;
	out[2] = v >> 8;
	out[0] = vh >> 8;
#endif
}

/* writes 16-bit value <v> at position <str> in big-endian encoding. The caller
 * guarantees there is enough room.
 */
static inline void h2_u16_encode(void *str, uint16_t v)
{
#if defined(__x86_64__) ||                                              \
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
	/* unaligned accesses are OK */
	uint16_t *out = str;
	*out = htonl(v);
#else
	/* no unaligned accesses */
	uint8_t *out = str;

	out[1] = v;
	out[0] = v >> 8;
#endif
}

/* Peeks frame headers from the next H2 frame and stores the length in <len>,
 * the flags and the type in <type> ((flags << 8) | type), and the stream ID in
 * <sid>. The channel is *not* automatically advanced, it's up to the caller to
 * do it using h2_skip_frame_header(), or to use h2_get_frame_header() to do
 * both. A positive value is returned on success, 0 is returned if bytes are
 * missing, and -1 if the channel is closed.
 */
static inline int h2_peek_frame_header(struct channel *chn, int *len, int *type, int *sid)
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
	*sid  = h2_u32_decode(ptr + 5) & 0x7fffffff;
	return 1;
}

/* skip the next 9 bytes corresponding to the frame header possibly parsed by
 * h2_peek_frame_header() above.
 */
static inline void h2_skip_frame_header(struct channel *chn)
{
	bo_skip(chn, 9);
}

/* same as above, automatically advances the channel on success */
static inline int h2_get_frame_header(struct channel *chn, int *len, int *type, int *sid)
{
	int ret;

	ret = h2_peek_frame_header(chn, len, type, sid);
	if (ret > 0)
		h2_skip_frame_header(chn);
	return ret;
}

/* returns the frame type without the flags */
static inline int h2_ft(int type)
{
	return type & 0xff;
}

/* returns the frame flags without the type */
static inline int h2_ff(int type)
{
	return (type >> 8) & 0xff;
}

/* writes the 24-bit frame size <len> at address <frame> */
static inline void h2_set_frame_size(void *frame, uint32_t len)
{
	uint8_t *out = frame;

	out[0] = len >> 16;
	out[1] = len >>  8;
	out[2] = len >>  0;
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

#endif /* _PROTO_H2COMMON_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
