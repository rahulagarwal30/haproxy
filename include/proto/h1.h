/*
 * include/proto/h1.h
 * This file contains HTTP/1 protocol definitions.
 *
 * Copyright (C) 2000-2017 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_H1_H
#define _PROTO_H1_H

#include <common/buffer.h>
#include <common/compiler.h>
#include <common/config.h>
#include <common/http.h>
#include <common/http-hdr.h>
#include <common/standard.h>
#include <types/h1.h>

int h1_headers_to_hdr_list(char *start, const char *stop,
                           struct http_hdr *hdr, unsigned int hdr_num,
                           struct h1m *h1m, union h1_sl *slp);
int h1_measure_trailers(const struct buffer *buf, unsigned int ofs, unsigned int max);

int h1_parse_cont_len_header(struct h1m *h1m, struct ist *value);
void h1_parse_xfer_enc_header(struct h1m *h1m, struct ist value);
void h1_parse_connection_header(struct h1m *h1m, struct ist value);

/* for debugging, reports the HTTP/1 message state name */
static inline const char *h1m_state_str(enum h1m_state msg_state)
{
	switch (msg_state) {
	case H1_MSG_RQBEFORE:    return "MSG_RQBEFORE";
	case H1_MSG_RQBEFORE_CR: return "MSG_RQBEFORE_CR";
	case H1_MSG_RQMETH:      return "MSG_RQMETH";
	case H1_MSG_RQMETH_SP:   return "MSG_RQMETH_SP";
	case H1_MSG_RQURI:       return "MSG_RQURI";
	case H1_MSG_RQURI_SP:    return "MSG_RQURI_SP";
	case H1_MSG_RQVER:       return "MSG_RQVER";
	case H1_MSG_RQLINE_END:  return "MSG_RQLINE_END";
	case H1_MSG_RPBEFORE:    return "MSG_RPBEFORE";
	case H1_MSG_RPBEFORE_CR: return "MSG_RPBEFORE_CR";
	case H1_MSG_RPVER:       return "MSG_RPVER";
	case H1_MSG_RPVER_SP:    return "MSG_RPVER_SP";
	case H1_MSG_RPCODE:      return "MSG_RPCODE";
	case H1_MSG_RPCODE_SP:   return "MSG_RPCODE_SP";
	case H1_MSG_RPREASON:    return "MSG_RPREASON";
	case H1_MSG_RPLINE_END:  return "MSG_RPLINE_END";
	case H1_MSG_HDR_FIRST:   return "MSG_HDR_FIRST";
	case H1_MSG_HDR_NAME:    return "MSG_HDR_NAME";
	case H1_MSG_HDR_COL:     return "MSG_HDR_COL";
	case H1_MSG_HDR_L1_SP:   return "MSG_HDR_L1_SP";
	case H1_MSG_HDR_L1_LF:   return "MSG_HDR_L1_LF";
	case H1_MSG_HDR_L1_LWS:  return "MSG_HDR_L1_LWS";
	case H1_MSG_HDR_VAL:     return "MSG_HDR_VAL";
	case H1_MSG_HDR_L2_LF:   return "MSG_HDR_L2_LF";
	case H1_MSG_HDR_L2_LWS:  return "MSG_HDR_L2_LWS";
	case H1_MSG_LAST_LF:     return "MSG_LAST_LF";
	case H1_MSG_CHUNK_SIZE:  return "MSG_CHUNK_SIZE";
	case H1_MSG_DATA:        return "MSG_DATA";
	case H1_MSG_CHUNK_CRLF:  return "MSG_CHUNK_CRLF";
	case H1_MSG_TRAILERS:    return "MSG_TRAILERS";
	case H1_MSG_DONE:        return "MSG_DONE";
	case H1_MSG_TUNNEL:      return "MSG_TUNNEL";
	default:                 return "MSG_??????";
	}
}

/* This function may be called only in HTTP_MSG_CHUNK_CRLF. It reads the CRLF or
 * a possible LF alone at the end of a chunk. The caller should adjust msg->next
 * in order to include this part into the next forwarding phase.  Note that the
 * caller must ensure that head+start points to the first byte to parse.  It
 * returns the number of bytes parsed on success, so the caller can set msg_state
 * to HTTP_MSG_CHUNK_SIZE. If not enough data are available, the function does not
 * change anything and returns zero. Otherwise it returns a negative value
 * indicating the error positionn relative to <stop>. Note: this function is
 * designed to parse wrapped CRLF at the end of the buffer.
 */
static inline int h1_skip_chunk_crlf(const struct buffer *buf, int start, int stop)
{
	const char *ptr = b_peek(buf, start);
	int bytes = 1;

	/* NB: we'll check data availability at the end. It's not a
	 * problem because whatever we match first will be checked
	 * against the correct length.
	 */
	if (*ptr == '\r') {
		bytes++;
		ptr++;
		if (ptr >= b_wrap(buf))
			ptr = b_orig(buf);
	}

	if (bytes > stop - start)
		return 0;

	if (*ptr != '\n') // negative position to stop
		return ptr - __b_peek(buf, stop);

	return bytes;
}

/* Parse the chunk size start at buf + start and stops before buf + stop. The
 * positions are relative to the buffer's head.
 * It returns the chunk size in <res> and the amount of bytes read this way :
 *   < 0 : error at this position relative to <stop>
 *   = 0 : not enough bytes to read a complete chunk size
 *   > 0 : number of bytes successfully read that the caller can skip
 * On success, the caller should adjust its msg->next to point to the first
 * byte of data after the chunk size, so that we know we can forward exactly
 * msg->next bytes, and msg->sol to contain the exact number of bytes forming
 * the chunk size. That way it is always possible to differentiate between the
 * start of the body and the start of the data. Note: this function is designed
 * to parse wrapped CRLF at the end of the buffer.
 */
static inline int h1_parse_chunk_size(const struct buffer *buf, int start, int stop, unsigned int *res)
{
	const char *ptr = b_peek(buf, start);
	const char *ptr_old = ptr;
	const char *end = b_wrap(buf);
	unsigned int chunk = 0;

	stop -= start; // bytes left
	start = stop;  // bytes to transfer

	/* The chunk size is in the following form, though we are only
	 * interested in the size and CRLF :
	 *    1*HEXDIGIT *WSP *[ ';' extensions ] CRLF
	 */
	while (1) {
		int c;
		if (!stop)
			return 0;
		c = hex2i(*ptr);
		if (c < 0) /* not a hex digit anymore */
			break;
		if (unlikely(++ptr >= end))
			ptr = b_orig(buf);
		if (unlikely(chunk & 0xF8000000)) /* integer overflow will occur if result >= 2GB */
			goto error;
		chunk = (chunk << 4) + c;
		stop--;
	}

	/* empty size not allowed */
	if (unlikely(ptr == ptr_old))
		goto error;

	while (HTTP_IS_SPHT(*ptr)) {
		if (++ptr >= end)
			ptr = b_orig(buf);
		if (--stop == 0)
			return 0;
	}

	/* Up to there, we know that at least one byte is present at *ptr. Check
	 * for the end of chunk size.
	 */
	while (1) {
		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* we now have a CR or an LF at ptr */
			if (likely(*ptr == '\r')) {
				if (++ptr >= end)
					ptr = b_orig(buf);
				if (--stop == 0)
					return 0;
			}

			if (*ptr != '\n')
				goto error;
			if (++ptr >= end)
				ptr = b_orig(buf);
			--stop;
			/* done */
			break;
		}
		else if (likely(*ptr == ';')) {
			/* chunk extension, ends at next CRLF */
			if (++ptr >= end)
				ptr = b_orig(buf);
			if (--stop == 0)
				return 0;

			while (!HTTP_IS_CRLF(*ptr)) {
				if (++ptr >= end)
					ptr = b_orig(buf);
				if (--stop == 0)
					return 0;
			}
			/* we have a CRLF now, loop above */
			continue;
		}
		else
			goto error;
	}

	/* OK we found our CRLF and now <ptr> points to the next byte, which may
	 * or may not be present. Let's return the number of bytes parsed.
	 */
	*res = chunk;
	return start - stop;
 error:
	*res = 0; // just to stop gcc's -Wuninitialized warning :-(
	return -stop;
}

/* initializes an H1 message for a request */
static inline struct h1m *h1m_init_req(struct h1m *h1m)
{
	h1m->state = H1_MSG_RQBEFORE;
	h1m->next = 0;
	h1m->flags = H1_MF_NONE;
	h1m->curr_len = 0;
	h1m->body_len = 0;
	h1m->err_pos = -2;
	h1m->err_state = 0;
	return h1m;
}

/* initializes an H1 message for a response */
static inline struct h1m *h1m_init_res(struct h1m *h1m)
{
	h1m->state = H1_MSG_RPBEFORE;
	h1m->next = 0;
	h1m->flags = H1_MF_RESP;
	h1m->curr_len = 0;
	h1m->body_len = 0;
	h1m->err_pos = -2;
	h1m->err_state = 0;
	return h1m;
}

#endif /* _PROTO_H1_H */
