/*
 * HTTP/2 protocol converter
 *
 * Copyright 2000-2016 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sys/types.h>

#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/cli.h>
#include <types/global.h>

#include <proto/channel.h>
#include <proto/cli.h>
#include <proto/frontend.h>
#include <proto/hpack-dec.h>
#include <proto/hpack-enc.h>
#include <proto/hpack-hdr.h>
#include <proto/log.h>
#include <proto/proto_tcp.h>
#include <proto/proto_h2.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>


static void h2c_frt_io_handler(struct appctx *appctx);
static void h2c_frt_release_handler(struct appctx *appctx);
static void h2s_frt_io_handler(struct appctx *appctx);
static void h2s_frt_release_handler(struct appctx *appctx);

struct pool_head *pool2_h2c;
struct pool_head *pool2_h2s;

static const char h2_conn_preface[24] = // PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
	"\x50\x52\x49\x20\x2a\x20\x48\x54"
	"\x54\x50\x2f\x32\x2e\x30\x0d\x0a"
	"\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a";

const char *h2_ft_strings[H2_FT_ENTRIES] = {
	[H2_FT_DATA]          = "DATA",
	[H2_FT_HEADERS]       = "HEADERS",
	[H2_FT_PRIORITY]      = "PRIORITY",
	[H2_FT_RST_STREAM]    = "RST_STREAM",
	[H2_FT_SETTINGS]      = "SETTINGS",
	[H2_FT_PUSH_PROMISE]  = "PUSH_PROMISE",
	[H2_FT_PING]          = "PING",
	[H2_FT_GOAWAY]        = "GOAWAY",
	[H2_FT_WINDOW_UPDATE] =	"WINDOW_UPDATE",
};

const char *h2_ss_strings[H2_SS_ENTRIES] = {
	[H2_SS_IDLE]   = "idle",
	[H2_SS_INIT]   = "init", /* not part of the spec */
	[H2_SS_RLOC]   = "reserved(local)",
	[H2_SS_RREM]   = "reserved(remote)",
	[H2_SS_OPEN]   = "open",
	[H2_SS_HREM]   = "half-closed(remote)",
	[H2_SS_HLOC]   = "half-closed(local)",
	[H2_SS_CLOSED] = "closed",
};

struct applet h2c_frt_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<H2CFRT>", /* used for logging */
	.fct = h2c_frt_io_handler,
	.release = h2c_frt_release_handler,
};

struct applet h2s_frt_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<H2SFRT>", /* used for logging */
	.fct = h2s_frt_io_handler,
	.release = h2s_frt_release_handler,
};

/* 4 const streams for the 4 possible RST states */
const struct h2s *h2_closed_streams[4] = {
	&(const struct h2s){
		.h2c       = NULL,
		.appctx    = NULL,
		.st        = H2_SS_CLOSED,
		.rst       = 0,
		.id        = 0,
	},
	&(const struct h2s){
		.h2c       = NULL,
		.appctx    = NULL,
		.st        = H2_SS_CLOSED,
		.rst       = 1,
		.id        = 0,
	},
	&(const struct h2s){
		.h2c       = NULL,
		.appctx    = NULL,
		.st        = H2_SS_CLOSED,
		.rst       = 2,
		.id        = 0,
	},
	&(const struct h2s){
		.h2c       = NULL,
		.appctx    = NULL,
		.st        = H2_SS_CLOSED,
		.rst       = 3,
		.id        = 0,
	},
};

const struct h2s *h2_idle_stream = &(const struct h2s){
	.h2c       = NULL,
	.appctx    = NULL,
	.st        = H2_SS_IDLE,
	.rst       = H2_RST_NONE,
	.id        = 0,
};

/* a few global settings */
static int h2_settings_header_table_size      =  4096; /* initial value */
static int h2_settings_initial_window_size    = 65535; /* initial value */
static int h2_settings_max_concurrent_streams =   100;

/* try to send a settings frame on the connection. Returns 0 if not possible
 * yet, <0 on error, >0 on success. See RFC7540#11.3 for the various codes.
 */
static int h2c_frt_snd_settings(struct h2c *h2c)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct channel *res = si_ic(si);
	char buf_data[100]; // enough for 15 settings
	struct chunk buf;
	int ret = -1;

	if (h2c_mux_busy(h2c))
		goto end;

	if ((res->buf == &buf_empty) &&
	    !channel_alloc_buffer(res, &appctx->buffer_wait)) {
		si_applet_cant_put(si);
		goto end;
	}

	chunk_init(&buf, buf_data, sizeof(buf_data));
	chunk_memcpy(&buf,
	       "\x00\x00\x00"      /* length    : 0 for now */
	       "\x04\x00"          /* type      : 4 (settings), flags : 0 */
	       "\x00\x00\x00\x00", /* stream ID : 0 */
	       9);

	if (h2_settings_header_table_size != 4096) {
		char str[6] = "\x00\x01"; /* header_table_size */

		h2_u32_encode(str + 2, h2_settings_header_table_size);
		chunk_memcat(&buf, str, 6);
	}

	if (h2_settings_initial_window_size != 65535) {
		char str[6] = "\x00\x04"; /* initial_window_size */

		h2_u32_encode(str + 2, h2_settings_initial_window_size);
		chunk_memcat(&buf, str, 6);
	}

	if (h2_settings_max_concurrent_streams != 0) {
		char str[6] = "\x00\x03"; /* max_concurrent_streams */

		/* Note: 0 means "unlimited" for haproxy's config but not for
		 * the protocol, so never send this value!
		 */
		h2_u32_encode(str + 2, h2_settings_max_concurrent_streams);
		chunk_memcat(&buf, str, 6);
	}

	if (global.tune.bufsize != 16384) {
		char str[6] = "\x00\x05"; /* max_frame_size */

		/* note: similarly we could also emit MAX_HEADER_LIST_SIZE to
		 * match bufsize - rewrite size, but at the moment it seems
		 * that clients don't take care of it.
		 */
		h2_u32_encode(str + 2, global.tune.bufsize);
		chunk_memcat(&buf, str, 6);
	}

	h2_set_frame_size(buf.str, buf.len - 9);
	ret = bi_putchk(res, &buf);

 end:
	fprintf(stderr, "[%d] sent settings = %d\n", appctx->st0, ret);

	/* success: >= 0 ; wait: -1; failure: < -1 */
	return ret + 1;
}

/* try to send an ACK for a settings frame on the connection. Returns 0 if not
 * possible yet, <0 on error, >0 on success.
 */
static int h2c_frt_ack_settings(struct h2c *h2c)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct channel *res = si_ic(si);
	int ret = -1;

	if (h2c_mux_busy(h2c))
		goto end;

	if ((res->buf == &buf_empty) &&
	    !channel_alloc_buffer(res, &appctx->buffer_wait)) {
		si_applet_cant_put(si);
		goto end;
	}

	ret = bi_putblk(res,
			"\x00\x00\x00"     /* length : 0 (no data)  */
			"\x04" "\x01"      /* type   : 4, flags : ACK */
			"\x00\x00\x00\x00" /* stream ID */, 9);

 end:
	fprintf(stderr, "[%d] sent settings ACK = %d\n", appctx->st0, ret);

	/* success: >= 0 ; wait: -1; failure: < -1 */
	return ret + 1;
}

/* try to send a window update for stream id <sid> and value <increment>.
 * Returns 0 if not possible yet, <0 on error, >0 on success.
 */
static int h2c_frt_window_update(struct h2c *h2c, int sid, uint32_t increment)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct channel *res = si_ic(si);
	char str[13];
	int ret = -1;

	if (h2c_mux_busy(h2c))
		goto end;

	if ((res->buf == &buf_empty) &&
	    !channel_alloc_buffer(res, &appctx->buffer_wait)) {
		si_applet_cant_put(si);
		goto end;
	}

	/* len: 4, type: 8, flags: none */
	memcpy(str, "\x00\x00\x04\x08\x00", 5);
	h2_u32_encode(str + 5, sid);
	h2_u32_encode(str + 9, increment);

	ret = bi_putblk(res, str, 13);
 end:
	fprintf(stderr, "[%d] sent WINDOW_UPDATE (%d,%u) = %d\n", appctx->st0, sid, increment, ret);

	/* success: >= 0 ; wait: -1; failure: < -1 */
	return ret + 1;
}

/* try to send pending window updates for the connection. It's safe to call it
 * with no pending updates. Returns 0 if not possible yet, <0 on error, >0 on
 * success.
 */
static int h2c_frt_send_window_updates(struct h2c *h2c)
{
	int ret = 1;

	if (h2c->rcvd_c) {
		/* send WU for the connection */
		ret = h2c_frt_window_update(h2c, 0, h2c->rcvd_c);
		if (ret <= 0)
			return ret;
		h2c->rcvd_c = 0;
	}

	if (h2c->rcvd_s) {
		/* send WU for the stream */
		ret = h2c_frt_window_update(h2c, h2c->dsi, h2c->rcvd_s);
		if (ret <= 0)
			return ret;
		h2c->rcvd_s = 0;
	}
	return ret;
}

/* try to send an ACK for a ping frame on the connection. Returns 0 if not
 * possible yet, <0 on error, >0 on success.
 */
static int h2c_frt_ack_ping(struct h2c *h2c, const char *payload)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct channel *res = si_ic(si);
	char str[17];
	int ret = -1;

	if (h2c_mux_busy(h2c))
		goto end;

	if ((res->buf == &buf_empty) &&
	    !channel_alloc_buffer(res, &appctx->buffer_wait)) {
		si_applet_cant_put(si);
		goto end;
	}

	memcpy(str,
	       "\x00\x00\x08"     /* length : 8 (same payload) */
	       "\x06" "\x01"      /* type   : 6, flags : ACK   */
	       "\x00\x00\x00\x00" /* stream ID */, 9);
	memcpy(str + 9, payload, 8);
	ret = bi_putblk(res, str, 17);
 end:
	fprintf(stderr, "[%d] sent settings ACK = %d\n", appctx->st0, ret);

	/* success: >= 0 ; wait: -1; failure: < -1 */
	return ret + 1;
}

/* try to send a GOAWAY frame on the connection to report an error, with
 * h2c->errcode as the error code. Returns 0 if not possible yet, <0 on error,
 * >0 on success. Don't use this for a graceful shutdown since h2c->max_id is
 * used as the last stream ID.
 */
static int h2c_frt_send_goaway_error(struct h2c *h2c)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct channel *res = si_ic(si);
	char str[17];
	int ret = -1;

	if (h2c_mux_busy(h2c))
		goto end;

	if ((res->buf == &buf_empty) &&
	    !channel_alloc_buffer(res, &appctx->buffer_wait)) {
		si_applet_cant_put(si);
		goto end;
	}

	/* len: 8, type: 7, flags: none, sid: 0 */
	memcpy(str, "\x00\x00\x08\x07\x00\x00\x00\x00\x00", 9);
	h2_u32_encode(str + 9, h2c->max_id);
	h2_u32_encode(str + 13, h2c->errcode);

	ret = bi_putblk(res, str, 17);
 end:
	fprintf(stderr, "[%d] sent GOAWAY (%d,%x) = %d\n", appctx->st0, h2c->max_id, h2c->errcode, ret);

	/* success: >= 0 ; wait: -1; failure: < -1 */
	return ret + 1;
}

/* creates a new stream <id> on the h2c connection and returns it, or NULL in
 * case of memory allocation error.
 */
static struct h2s *h2c_stream_new(struct h2c *h2c, int id)
{
	struct session *sess = si_strm(h2c->appctx->owner)->sess;
	struct appctx *appctx;
	struct stream *s;
	struct task *t;
	struct h2s *h2s;

	/* DEBUG CODE */
	struct eb32_node *node = eb32_lookup(&h2c->streams_by_id, id);
	if (node) {
		h2s = container_of(node, struct h2s, by_id);
		fprintf(stderr, "%s:%d(%s): BUG!: h2c=%p id=%d ret=%p id=%d\n", __FILE__, __LINE__, __FUNCTION__, h2c, id, h2s, id);
	}

	if (!id)
		fprintf(stderr, "%s:%d(%s): BUG!: h2c=%p id=%d\n", __FILE__, __LINE__, __FUNCTION__, h2c, id);

	if (id <= h2c->max_id)
		fprintf(stderr, "%s:%d(%s): BUG!: h2c=%p id=%d <= max_id=%d\n", __FILE__, __LINE__, __FUNCTION__, h2c, id, h2c->max_id);
	/* /DEBUG */

	h2s = pool_alloc2(pool2_h2s);
	if (!h2s)
		goto out;

	h2s->h2c       = h2c;
	h2s->mws       = h2c->miw;
	h2s->flags     = H2_SF_NONE;
	h2s->errcode   = H2_ERR_NO_ERROR;
	h2s->st        = H2_SS_IDLE;
	h2s->rst       = H2_RST_NONE;
	h2s->blocked   = H2_BLK_NONE;
	h2s->by_id.key = h2s->id = id;
	LIST_INIT(&h2s->list);
	h2c->max_id    = id;
	eb32_insert(&h2c->streams_by_id, &h2s->by_id);

	appctx = appctx_new(&h2s_frt_applet);
	if (!appctx)
		goto out_close;

	h2s->appctx = appctx;
	appctx->ctx.h2s.ctx = h2s;
	appctx->st0 = 0;

	t = task_new();
	if (!t)
		goto out_free_appctx;

	t->nice = sess->listener->nice;

	s = stream_new(sess, t, &appctx->obj_type);
	if (!s)
		goto out_free_task;

//	/* The tasks below are normally what is supposed to be done by
//	 * fe->accept().
//	 */
//	s->flags = SF_ASSIGNED|SF_ADDR_SET;

	/* applet is waiting for data */
	si_applet_cant_get(&s->si[0]);
	appctx_wakeup(appctx);

	sess->listener->nbconn++; /* FIXME: we have no choice for now as the stream will decrease it */
	sess->fe->feconn++; /* FIXME: we must increase it as it will be decresed at the end of the stream. beconn will be increased later */
	jobs++;
	if (!(sess->listener->options & LI_O_UNLIMITED))
		actconn++;
	totalconn++;

	h2m_init(&h2s->req, &s->req);
	h2m_init(&h2s->res, &s->res);
	return h2s;

	/* Error unrolling */
// out_free_strm:
//	LIST_DEL(&s->by_sess);
//	LIST_DEL(&s->list);
//	pool_free2(pool2_stream, s);
 out_free_task:
	task_free(t);
 out_free_appctx:
	appctx_free(appctx);
 out_close:
	pool_free2(pool2_h2s, h2s);
	h2s = NULL;
 out:
	return h2s;
}

/* Increase all streams' outgoing window size by the difference passed in
 * argument. This is needed upon receipt of the settings frame if the initial
 * window size is different. The difference may be negative and the resulting
 * window size as well, for the time it takes to receive some window updates.
 */
static void h2c_update_all_ws(struct h2c *h2c, int diff)
{
	struct h2s *h2s;
	struct eb32_node *node;

	if (!diff)
		return;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		h2s->mws += diff;
		node = eb32_next(node);
	}
}

/* processes a SETTINGS frame whose payload is <payload> for <plen> bytes, and
 * ACKs it if needed. Returns 0 if not possible yet, <0 on error, >0 on success.
 */
static int h2c_frt_handle_settings(struct h2c *h2c, const char *payload, int plen)
{
	if ((h2_ff(h2c->dft) & H2_F_SETTINGS_ACK))
		return 1;

	if (h2c->dsi != 0) {
		/* settings apply to connection */
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		return -1;
	}

	if (h2c->dfl % 6) {
		/* frame length must be multiple of 6 */
		h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
		return -1;
	}

	/* process full frame only */
	if (plen < h2c->dfl)
		return 0;

	/* parse the frame */
	while (plen > 0) {
		uint16_t type = h2_u16_decode(payload);
		int32_t  arg  = h2_u32_decode(payload + 2);

		switch (type) {
		case H2_SETTINGS_INITIAL_WINDOW_SIZE:
			/* we need to update all existing streams with the
			 * difference from the previous iws.
			 */
			h2c_update_all_ws(h2c, arg - h2c->miw);
			h2c->miw = arg;
			break;
		case H2_SETTINGS_MAX_FRAME_SIZE:
			if (arg < 16384 || arg > 16777215) { // RFC7540#6.5.2
				h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
				return -1;
			}
			h2c->mfs = arg;
			break;
		}
		payload += 6;
		plen -= 6;
	}

	return h2c_frt_ack_settings(h2c);
}

/* processes a WINDOW_UPDATE frame whose payload is <payload> for <plen> bytes.
 * Returns 0 if not possible yet, <0 on error, >0 on success.
 */
static int h2c_frt_handle_window_update(struct h2c *h2c, const char *payload, int plen)
{
	int32_t inc;

	if (h2c->dfl != 4) {
		/* frame length must be exactly 4 */
		h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
		return -1;
	}

	/* process full frame only */
	if (plen < h2c->dfl)
		return 0;

	/* parse the frame */
	inc = h2_u32_decode(payload);

	if (inc == 0) {
		/* FIXME: this is incorrect, the spec says that it is a
		 * connection error only if sent to the connection,
		 * otherwise it's a stream error.
		 */
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		return -1;
	}

	if (h2c->dsi != 0) {
		struct h2s *h2s = h2c_st_by_id(h2c, h2c->dsi);

		/* it's not an error to receive WU on a closed stream, though
		 * it's uncertain (but harmless) on an idle one.
		 */
		if (h2s->st != H2_SS_IDLE && h2s->st != H2_SS_CLOSED)
			h2s->mws += inc;
	}
	else
		h2c->mws += inc;

	return 1;
}

/* processes a PING frame and ACKs it if needed. The caller must pass the
 * pointer to the payload in <payload>. Returns 0 if not possible yet, <0 on
 * error, >0 on success.
 */
static int h2c_frt_handle_ping(struct h2c *h2c, const char *payload)
{
	/* frame length must be exactly 8 */
	if (h2c->dfl != 8) {
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		return -1;
	}

	if (!(h2_ff(h2c->dft) & H2_F_PING_ACK))
		return h2c_frt_ack_ping(h2c, payload);

	return 1;
}

/* This function parses a contiguous HTTP/1 headers block starting at <start>
 * and ending before <stop>, at once, and converts it to either an HTTP/2
 * HEADERS frame (if <out> is not NULL), or to a list of (name,value) pairs
 * representing header fields into the array <hdr> of size <hdr_num>, whose
 * last entry will have an empty name and an empty value. If <hdr_num> is too
 * small to represent the whole message, an error is returned. If <h2m> is not
 * NULL, some protocol elements such as content-length and transfer-encoding
 * will be parsed and stored there as well.
 *
 * For now it's limited to the response. If the header block is incomplete,
 * 0 is returned, waiting to be called again with more data to try it again.
 *
 * The code derived from the main HTTP/1 parser but was simplified and
 * optimized to process responses produced or forwarded by haproxy. The caller
 * is responsible for ensuring that the message doesn't wrap, and should ensure
 * it is complete to avoid having to retry the operation after a failed
 * attempt. The message is not supposed to be invalid, which is why a few
 * properties such as the character set used in the header field names are not
 * checked. In case of an unparsable response message, a negative value will be
 * returned with h2m->err_pos and h2m->err_state matching the location and
 * state where the error was met. Leading blank likes are tolerated but not
 * recommended.
 *
 * This function returns :
 *   < 0 in case of error. In this case, h2m->err_state is filled (if h2m is
 *       set) with the state the error occurred in and h2-m>err_pos with the
 *       the position relative to <start>
 *   = 0 in case of missing data.
 *   > 0 on success, it then corresponds to the number of bytes read since
 *       <start> so that the caller can go on with the payload.
 */
int h1_headers_to_h2(char *start, const char *stop,
                     struct chunk *out, struct hpack_hdr *hdr, unsigned int hdr_num,
                     struct h2m *h2m)
{
	enum ht_state state = HTTP_MSG_RPBEFORE;
	register char *ptr  = start;
	register const char *end  = stop;
	unsigned int hdr_count = 0;
	unsigned int code = 0; /* status code, ASCII form */
	unsigned int st_c;     /* beginning of status code, relative to msg_start */
	unsigned int st_c_l;   /* length of status code */
	unsigned int sol = 0;  /* start of line */
	unsigned int col = 0;  /* position of the colon */
	unsigned int eol = 0;  /* end of line */
	unsigned int sov = 0;  /* start of value */
	unsigned int skip = 0; /* number of bytes skipped at the beginning */
	struct ist n, v;       /* header name and value during parsing */

	if (unlikely(ptr >= end))
		goto http_msg_ood;

	switch (state)	{
	case HTTP_MSG_RPBEFORE:
	http_msg_rpbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, we may have skipped some
			 * heading CRLF. Skip them now.
			 */
			skip += ptr - start;
			start = ptr;

			sol = 0;
			hdr_count = 0;
			state = HTTP_MSG_RPVER;
			goto http_msg_rpver;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = HTTP_MSG_RPBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, HTTP_MSG_RPBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore_cr, http_msg_ood, state, HTTP_MSG_RPBEFORE_CR);
		/* stop here */

	case HTTP_MSG_RPBEFORE_CR:
	http_msg_rpbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RPBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, HTTP_MSG_RPBEFORE);
		/* stop here */

	case HTTP_MSG_RPVER:
	http_msg_rpver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver, http_msg_ood, state, HTTP_MSG_RPVER);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			/* version length = ptr - start */
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, HTTP_MSG_RPVER_SP);
		}
		state = HTTP_MSG_RPVER;
		goto http_msg_invalid;

	case HTTP_MSG_RPVER_SP:
	http_msg_rpver_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			code = 0;
			st_c = ptr - start;
			goto http_msg_rpcode;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, HTTP_MSG_RPVER_SP);
		/* so it's a CR/LF, this is invalid */
		state = HTTP_MSG_RPVER_SP;
		goto http_msg_invalid;

	case HTTP_MSG_RPCODE:
	http_msg_rpcode:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			code = (code << 8) + *ptr;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode, http_msg_ood, state, HTTP_MSG_RPCODE);
		}

		if (likely(HTTP_IS_SPHT(*ptr))) {
			st_c_l = ptr - start - st_c;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, HTTP_MSG_RPCODE_SP);
		}

		/* so it's a CR/LF, so there is no reason phrase */
		st_c_l = ptr - start - st_c;

	http_msg_rsp_reason:
		/* reason = ptr - start; */
		/* reason length = 0 */
		goto http_msg_rpline_eol;

	case HTTP_MSG_RPCODE_SP:
	http_msg_rpcode_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			/* reason = ptr - start */
			goto http_msg_rpreason;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, HTTP_MSG_RPCODE_SP);
		/* so it's a CR/LF, so there is no reason phrase */
		goto http_msg_rsp_reason;

	case HTTP_MSG_RPREASON:
	http_msg_rpreason:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpreason, http_msg_ood, state, HTTP_MSG_RPREASON);
		/* reason length = ptr - start - reason */
	http_msg_rpline_eol:
		/* We have seen the end of line. Note that we do not
		 * necessarily have the \n yet, but at least we know that we
		 * have EITHER \r OR \n, otherwise the response would not be
		 * complete. We can then record the response length and return
		 * to the caller which will be able to register it.
		 */

		if (likely(out)) {
			if (out->len < out->size && code == 0x00323030)
				out->str[out->len++] = 0x88; // indexed field : idx[08]=(":status", "200")
			else if (out->len < out->size && code == 0x00333034)
				out->str[out->len++] = 0x8b; // indexed field : idx[11]=(":status", "304")
			else if (unlikely(st_c_l != 3 || out->len + 2 + st_c_l > out->size)) {
				state = HTTP_MSG_RPREASON;
				goto http_msg_invalid;
			}
			else {
				/* basic encoding of the status code */
				out->str[out->len++] = 0x48; // indexed name -- name=":status" (idx 8)
				out->str[out->len++] = 0x03; // 3 bytes status
				out->str[out->len++] = start[st_c];
				out->str[out->len++] = start[st_c + 1];
				out->str[out->len++] = start[st_c + 2];
			}
		}
		else {
			if (unlikely(hdr_count >= hdr_num)) {
				state = HTTP_MSG_RPREASON;
				goto http_msg_invalid;
			}
			hpack_set_hdr(&hdr[hdr_count++], ist(":status"), ist2(start + st_c, st_c_l));
		}

		sol = ptr - start;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpline_end, http_msg_ood, state, HTTP_MSG_RPLINE_END);
		goto http_msg_rpline_end;

	case HTTP_MSG_RPLINE_END:
	http_msg_rpline_end:
		/* sol must point to the first of CR or LF. */
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RPLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, HTTP_MSG_HDR_FIRST);
		/* stop here */

	case HTTP_MSG_HDR_FIRST:
	http_msg_hdr_first:
		sol = ptr - start;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	case HTTP_MSG_HDR_NAME:
	http_msg_hdr_name:
		/* assumes sol points to the first char */
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* turn it to lower case if needed */
			if (isupper((unsigned char)*ptr))
				*ptr = tolower(*ptr);
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, HTTP_MSG_HDR_NAME);
		}

		if (likely(*ptr == ':')) {
			col = ptr - start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, HTTP_MSG_HDR_L1_SP);
		}

		if (HTTP_IS_LWS(*ptr)) {
			state = HTTP_MSG_HDR_NAME;
			goto http_msg_invalid;
		}

		/* now we have a non-token character in the header field name,
		 * it's up to the H1 layer to have decided whether or not it
		 * was acceptable. If we find it here, it was considered
		 * acceptable due to configuration rules so we obey.
		 */
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, HTTP_MSG_HDR_NAME);

	case HTTP_MSG_HDR_L1_SP:
	http_msg_hdr_l1_sp:
		/* assumes sol points to the first char */
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, HTTP_MSG_HDR_L1_SP);

		/* header value can be basically anything except CR/LF */
		sov = ptr - start;

		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_val;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lf, http_msg_ood, state, HTTP_MSG_HDR_L1_LF);
		goto http_msg_hdr_l1_lf;

	case HTTP_MSG_HDR_L1_LF:
	http_msg_hdr_l1_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_HDR_L1_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lws, http_msg_ood, state, HTTP_MSG_HDR_L1_LWS);

	case HTTP_MSG_HDR_L1_LWS:
	http_msg_hdr_l1_lws:
		if (likely(HTTP_IS_SPHT(*ptr))) {
			/* replace HT,CR,LF with spaces */
			for (; start + sov < ptr; sov++)
				start[sov] = ' ';
			goto http_msg_hdr_l1_sp;
		}
		/* we had a header consisting only in spaces ! */
		eol = sov;
		goto http_msg_complete_header;

	case HTTP_MSG_HDR_VAL:
	http_msg_hdr_val:
		/* assumes sol points to the first char, and sov
		 * points to the first character of the value.
		 */

		/* speedup: we'll skip packs of 4 or 8 bytes not containing bytes 0x0D
		 * and lower. In fact since most of the time is spent in the loop, we
		 * also remove the sign bit test so that bytes 0x8e..0x0d break the
		 * loop, but we don't care since they're very rare in header values.
		 */
#if defined(__x86_64__)
		while (ptr <= end - sizeof(long)) {
			if ((*(long *)ptr - 0x0e0e0e0e0e0e0e0eULL) & 0x8080808080808080ULL)
				goto http_msg_hdr_val2;
			ptr += sizeof(long);
		}
#endif
#if defined(__x86_64__) || \
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
		while (ptr <= end - sizeof(int)) {
			if ((*(int*)ptr - 0x0e0e0e0e) & 0x80808080)
				goto http_msg_hdr_val2;
			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = HTTP_MSG_HDR_VAL;
			goto http_msg_ood;
		}
	http_msg_hdr_val2:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_val2, http_msg_ood, state, HTTP_MSG_HDR_VAL);

		eol = ptr - start;
		/* Note: we could also copy eol into ->eoh so that we have the
		 * real header end in case it ends with lots of LWS, but is this
		 * really needed ?
		 */
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lf, http_msg_ood, state, HTTP_MSG_HDR_L2_LF);
		goto http_msg_hdr_l2_lf;

	case HTTP_MSG_HDR_L2_LF:
	http_msg_hdr_l2_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_HDR_L2_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lws, http_msg_ood, state, HTTP_MSG_HDR_L2_LWS);

	case HTTP_MSG_HDR_L2_LWS:
	http_msg_hdr_l2_lws:
		if (unlikely(HTTP_IS_SPHT(*ptr))) {
			/* LWS: replace HT,CR,LF with spaces */
			for (; start + eol < ptr; eol++)
				start[eol] = ' ';
			goto http_msg_hdr_val;
		}
	http_msg_complete_header:
		/*
		 * It was a new header, so the last one is finished. Assumes
		 * <sol> points to the first char of the name, <col> to the
		 * colon, <sov> points to the first character of the value and
		 * <eol> to the first CR or LF so we know how the line ends. We
		 * will trim spaces around the value. It's possible to do it by
		 * adjusting <eol> and <sov> which are no more used after this.
		 * We can add the header field to the list.
		 */
		while (sov < eol && HTTP_IS_LWS(start[sov]))
			sov++;

		while (eol - 1 > sov && HTTP_IS_LWS(start[eol - 1]))
			eol--;


		n = ist2(start + sol, col - sol);
		v = ist2(start + sov, eol - sov);
		if (out) {
			/* check a few very common response header fields to encode
			 * them using the static header table.
			 */
			if (!hpack_encode_header(out, n, v)) {
				state = HTTP_MSG_HDR_L2_LWS;
				goto http_msg_invalid;
			}
		} else if (!isteq(n, ist("connection")) &&
		           !isteq(n, ist("proxy-connection")) &&
		           !isteq(n, ist("keep-alive")) &&
		           !isteq(n, ist("upgrade")) &&
		           !isteq(n, ist("transfer-encoding"))) {
			/* only encode valid headers for HTTP/2 */
			if (unlikely(hdr_count >= hdr_num)) {
				state = HTTP_MSG_HDR_L2_LWS;
				goto http_msg_invalid;
			}

			hpack_set_hdr(&hdr[hdr_count++], n, v);
		}

		if (h2m) {
			long long cl;

			if (isteq(n, ist("transfer-encoding"))) {
				h2m->flags &= ~H2_MF_CLEN;
				h2m->flags |= H2_MF_CHNK;
			}
			else if (isteq(n, ist("content-length")) && !(h2m->flags & H2_MF_CHNK)) {
				h2m->flags |= H2_MF_CLEN;
				strl2llrc(v.ptr, v.len, &cl);
				h2m->curr_len = h2m->body_len = cl;
			}
		}

		sol = ptr - start;
		if (likely(!HTTP_IS_CRLF(*ptr)))
			goto http_msg_hdr_name;

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	case HTTP_MSG_LAST_LF:
	http_msg_last_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_LAST_LF);
		ptr++;
		/* <ptr> now points to the first byte of payload. If needed sol
		 * still points to the first of either CR or LF of the empty
		 * line ending the headers block.
		 */
		if (!out) {
			if (unlikely(hdr_count >= hdr_num)) {
				state = HTTP_MSG_LAST_LF;
				goto http_msg_invalid;
			}
			hpack_set_hdr(&hdr[hdr_count++], ist(""), ist(""));
		}
		state = HTTP_MSG_BODY;
		break;

	default:
		/* impossible states */
		goto http_msg_invalid;
	}

	/* reaching here, we've parsed the whole message and the state is
	 * HTTP_MSG_BODY.
	 */
	return ptr - start + skip;

 http_msg_ood:
	/* out of data at <ptr> during state <state> */
	return 0;

 http_msg_invalid:
	/* invalid message, error at <ptr> */
	if (h2m) {
		h2m->err_state = state;
		h2m->err_pos = ptr - start + skip;
	}
	return -1;
}


/* processes a HEADERS frame. The caller must pass the pointer to the payload
 * in <payload> and to a temporary buffer in <outbuf> for the decoded traffic.
 * Returns 0 if it needs to yield, <0 on error, >0 on success.
 */
static int h2c_frt_handle_headers(struct h2c *h2c, const char *payload, struct chunk *outbuf)
{
	struct h2s *h2s;

	if (h2_ff(h2c->dft) & H2_F_HEADERS_END_STREAM)
		fprintf(stderr, "[4] HEADERS with END_STREAM\n");
	if (h2_ff(h2c->dft) & H2_F_HEADERS_END_HEADERS)
		fprintf(stderr, "[4] HEADERS with END_HEADERS\n");
	if (h2_ff(h2c->dft) & H2_F_HEADERS_PADDED)
		fprintf(stderr, "[4] HEADERS with PADDED\n");
	if (h2_ff(h2c->dft) & H2_F_HEADERS_PRIORITY)
		fprintf(stderr, "[4] HEADERS with PRIORITY\n");

	h2s = h2c_st_by_id(h2c, h2c->dsi);
	fprintf(stderr, "    [h2s=%p:%s]", h2s, h2_ss_str(h2s->st));

	if (h2s->st != H2_SS_IDLE) {
		/* stream already exists, we might just be coming back from a
		 * previously failed allocation.
		 */
		if (h2s->st != H2_SS_INIT) {
			fprintf(stderr, "    received headers frame at state %s for stream %d!", h2_ss_str(h2s->st), h2c->dsi);
			h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		}
	}
	else if (h2c->dsi <= h2c->max_id) {
		fprintf(stderr, "    reused ID %d (max_id=%d)!", h2c->dsi, h2c->max_id);
		h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
		return -1;
	}
	else {
		h2s = h2c_stream_new(h2c, h2c->dsi);
		if (!h2s) {
			fprintf(stderr, "    failed to allocate h2s stream for ID %d!", h2c->dsi);
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return -1;
		}
		h2s->st = H2_SS_INIT;
	}

	/* If we fail the buffer allocation here, we'll pause the parsing in
	 * the connection and resume in the stream, going through the code path
	 * corresponding to H2_SS_INIT.
	 */
	if (si_ic(h2s->appctx->owner)->buf == &buf_empty &&
	    !channel_alloc_buffer(si_ic(h2s->appctx->owner), &h2s->appctx->buffer_wait)) {
		si_applet_cant_put(h2s->appctx->owner);
		return 0;
	}

	h2s->st = H2_SS_OPEN;
	if (h2_ff(h2c->dft) & H2_F_HEADERS_END_STREAM)
		h2s->st = H2_SS_HREM;

	fprintf(stderr, " [newh2s=%p:%s]\n", h2s, h2_ss_str(h2s->st));

	if (h2_ff(h2c->dft) & H2_F_HEADERS_END_STREAM) {
		// FIXME: ignore PAD, StreamDep and PRIO for now
		const uint8_t *hdrs = (uint8_t *)payload;
		int flen = h2c->dfl;

		if (h2_ff(h2c->dft) & H2_F_HEADERS_PADDED) {
			hdrs += 1;
			flen -= 1;
		}
		if (h2_ff(h2c->dft) & H2_F_HEADERS_PRIORITY) {
			hdrs += 4; // stream dep
			flen -= 4;
		}
		if (h2_ff(h2c->dft) & H2_F_HEADERS_PRIORITY) {
			hdrs += 1; // weight
			flen -= 1;
		}

		outbuf->len = hpack_decode_frame(h2c->ddht, hdrs, flen, outbuf->str, outbuf->size - 1);
		if (outbuf->len < 0) {
			//fprintf(stderr, "hpack_decode_frame() = %d\n", outbuf->len);
			h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
			return -1;
		}

		outbuf->str[outbuf->len] = 0;
		fprintf(stderr, "request: %d bytes :\n<%s>\n", outbuf->len, outbuf->str);

		if (bi_putchk(si_ic(h2s->appctx->owner), outbuf) < 0) {
			si_applet_cant_put(h2s->appctx->owner);
			printf("failed to copy to h2s buffer\n");
		}

		/* FIXME: certainly not sufficient */
		stream_int_notify(h2s->appctx->owner);

		/* FIXME: temporary to unlock the client until we respond */
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
	}

	return 1;
}

/* processes a PRIORITY frame. The caller must pass the pointer to the payload
 * in <payload>. Returns 0 if it needs to yield, <0 on error, >0 on success.
 */
static int h2c_frt_handle_priority(struct h2c *h2c, const char *payload)
{
	struct h2s *h2s;

	fprintf(stderr, "   ");
	if (payload[0] & 0x80)
		fprintf(stderr, " [EXCLUSIVE] ");

	fprintf(stderr, " [dep=%d] ", ((payload[0] & 0x7f)<<24) + ((unsigned char)payload[1] << 16) + ((unsigned char)payload[2] << 8) + (unsigned char)payload[3]);

	fprintf(stderr, " [weight=%d] ", (unsigned char)payload[4]);

	h2s = h2c_st_by_id(h2c, h2c->dsi);
	fprintf(stderr, " [h2s=%p:%s]", h2s, h2_ss_str(h2s->st));
	fprintf(stderr, "\n");
	return 1;
}

/* processes a DATA frame. The caller must pass the pointer to the payload
 * in <payload> for length <plen>. Returns 0 if it needs to yield, <0 on error, >0 on success.
 */
static int h2c_frt_handle_data(struct h2c *h2c, const char *payload, int plen)
{
	struct h2s *h2s;

	/* FIXME: drops data for now */

	if (h2_ff(h2c->dft) & H2_F_DATA_END_STREAM)
		fprintf(stderr, "[4] DATA with END_STREAM\n");
	if (h2_ff(h2c->dft) & H2_F_DATA_PADDED)
		fprintf(stderr, "[4] DATA with PADDED\n");

	h2c->rcvd_c += plen;
	h2c->rcvd_s += plen; // warning, this can also affect the closed streams!

	h2s = h2c_st_by_id(h2c, h2c->dsi);
	fprintf(stderr, "    [h2s=%p:%s] rcvd_c=%u rcvd_s=%u", h2s, h2_ss_str(h2s->st), h2c->rcvd_c, h2c->rcvd_s);

	if (h2s->st == H2_SS_OPEN && (h2_ff(h2c->dft) & H2_F_DATA_END_STREAM))
		h2s->st = H2_SS_HREM;
	fprintf(stderr, " [h2s=%p:%s]\n", h2s, h2_ss_str(h2s->st));

	{
		static unsigned int foo;
		foo += plen;
		fprintf(stderr, "stream=%d total = %u\n", h2c->dsi, foo);
	}
#define DONT_CLOSE
#ifndef DONT_CLOSE
	// DATA not implemented yet
	h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
	return -1;
#endif
	return 1;
}

/* Try to send a HEADERS frame matching HTTP/1 response present in the response
 * channel attached to <h2m>, for stream id <sid> over connection <h2c>, and
 * using <outbuf> as a temporary output buffer. Returns 0 if not possible yet,
 * <0 on error, >0 on success.
 */
static int h2c_frt_make_resp_headers(struct h2c *h2c, int sid, struct h2m *h2m, struct chunk *outbuf)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct channel *res = si_ic(si);
	int ret = -1;
	int skip = 0;
	int es_now = 0;

	if (h2c_mux_busy(h2c))
		goto end;

	if ((res->buf == &buf_empty) &&
	    !channel_alloc_buffer(res, &appctx->buffer_wait)) {
		si_applet_cant_put(si);
		goto end;
	}

	chunk_reset(outbuf);

	/* len: 0x000000 (fill later), type: 1(HEADERS), flags: ENDH=4 */
	memcpy(outbuf->str, "\x00\x00\x00\x01\x04", 5);
	h2_u32_encode(outbuf->str + 5, sid); // 4 bytes
	outbuf->len = 9;

	skip = h2m->chn->buf->o;
	ret = h1_headers_to_h2(bo_ptr(h2m->chn->buf), bo_ptr(h2m->chn->buf) + h2m->chn->buf->o,
	                       outbuf, NULL, 0, h2m);
	if (ret <= 0) { // incomplete or error
		ret--;
		goto end;
	}
	skip = ret;

	/* we may need to add END_STREAM */
	if (((h2m->flags & H2_MF_CLEN) && !h2m->body_len) || h2m->chn->flags & CF_SHUTW)
		es_now = 1;

	/* update the frame's size */
	h2_set_frame_size(outbuf->str, outbuf->len - 9);

	if (es_now)
		outbuf->str[4] |= H2_F_HEADERS_END_STREAM;

	ret = bi_putblk(res, outbuf->str, outbuf->len);

	/* consume incoming H1 response */
	if (ret > 0) {
		bo_skip(h2m->chn, skip);
		/* for now we don't implemented CONTINUATION, so we wait for a
		 * body or directly end in TRL2.
		 */
		if (es_now)
			h2m->state = H2_MS_TRL2;
		else
			h2m->state = H2_MS_BODY;
	}

 end:
	fprintf(stderr, "[%d] sent simple H2 response (sid=%d) = %d bytes (%d in, ep=%u, es=%s)\n", appctx->st0, sid, ret, skip, h2m->err_pos, http_msg_state_str(h2m->err_state));

	/* success: >= 0 ; wait: -1; failure: < -1 */
	return ret + 1;
}

/* Try to send a DATA frame matching HTTP/1 response present in the response
 * channel attached to <h2m>, for stream id <sid> over connection <h2c>, and
 * using <outbuf> as a temporary output buffer. Returns 0 if not possible yet,
 * <0 on error, >0 on success.
 */
static int h2c_frt_make_resp_data(struct h2c *h2c, struct h2s *h2s, struct chunk *outbuf)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct h2m *h2m = &h2s->res;
	struct channel *res = si_ic(si);
	int ret = -1;
	int es_now = 0;
	int size = 0;

	if (h2c_mux_busy(h2c))
		goto end;

	if ((res->buf == &buf_empty) &&
	    !channel_alloc_buffer(res, &appctx->buffer_wait)) {
		si_applet_cant_put(si);
		goto end;
	}

	chunk_reset(outbuf);

	/* len: 0x000000 (fill later), type: 0(DATA), flags: none=0 */
	memcpy(outbuf->str, "\x00\x00\x00\x00\x00", 5);
	h2_u32_encode(outbuf->str + 5, h2s->id); // 4 bytes
	outbuf->len = 9;

	switch (h2m->flags & (H2_MF_CLEN|H2_MF_CHNK)) {
	case 0:           /* no content length, read till SHUTW */
		size = h2m->chn->buf->o;
		break;
	case H2_MF_CLEN:  /* content-length: read only h2m->body_len */
		size = h2m->chn->buf->o;
		if ((long long)size > h2m->curr_len)
			size = h2m->curr_len;
		break;
	default:          /* te:chunked : parse chunks */
		ret = -2; // FIXME: chunk not done for now
		goto end;
	}

	/* we have in <size> the exact number of bytes we need to copy from
	 * the H1 buffer. We need to check this against the connection's and
	 * the stream's send windows, and to ensure that this fits in the max
	 * frame size and in the buffer's available space minus 9 bytes (for
	 * the frame header). The connection's flow control is applied last so
	 * that we can use a separate list of streams which are immediately
	 * unblocked on window opening. Note: we don't implement padding.
	 */
	if (size > h2s->mws)
		size = h2s->mws;

	if (h2c->mfs && size > h2c->mfs)
		size = h2c->mfs;

	if (size + 9 > outbuf->size)
		size = outbuf->size - 9;

	if (size + 9 > res->buf->size)
		size = res->buf->size - 9;

	if (size <= 0)
		goto blocked_strm;

	if (size > h2c->mws)
		size = h2c->mws;

	if (size <= 0)
		goto blocked_conn;

	/* copy whatever we can */

	ret = bo_getblk(h2m->chn, outbuf->str + outbuf->len, size, 0);
	if (ret <= 0 || ret != size) {
		/* FIXME: must never happen */
		ret = -2;
		goto end;
	}

	/* we may need to add END_STREAM */
	/* FIXME: bug below, CF_SHUTW must not be considered if size was trimmed to fit the output buffer */
	if (((h2m->flags & H2_MF_CLEN) && !(h2m->curr_len - size)) || (h2m->chn->flags & CF_SHUTW))
		es_now = 1;

	/* update the frame's size */
	h2_set_frame_size(outbuf->str, size);

	if (es_now)
		outbuf->str[4] |= H2_F_DATA_END_STREAM;

	ret = bi_putblk(res, outbuf->str, size + 9);

	/* consume incoming H1 response */
	if (ret > 0) {
		bo_skip(h2m->chn, size);
		h2m->curr_len -= size;
		h2s->mws -= size;
		h2c->mws -= size;
		/* no trailers for now */
		if (es_now)
			h2m->state = H2_MS_TRL2;
	}

 end:
	fprintf(stderr, "[%d] sent simple H2 DATA response (sid=%d) = %d bytes (%d in, ep=%u, es=%s, h2cws=%d h2sws=%d)\n", appctx->st0, h2s->id, ret, size, h2m->err_pos, http_msg_state_str(h2m->err_state), h2c->mws, h2s->mws);

	/* success: >= 0 ; wait: -1; failure: < -1 */
	return ret + 1;

 blocked_conn:
	/* FIXME: subscribe to blocked list */
	fprintf(stderr, "### blocked_conn\n");
	return 0;

 blocked_strm:
	/* FIXME: subscribe to blocked list */
	fprintf(stderr, "### blocked_strm\n");
	return 0;
}

/* try to process active streams which are waiting for the connections to be
 * usable. Returns < 0 on error, 0 if nothing was done, > 0 on success.
 */
static int h2c_frt_process_active(struct h2c *h2c, struct h2s *only_h2s, struct chunk *outbuf)
{
	struct h2s *h2s;
	int sid;
	int ret;

	/* no need to try if the connection's send window is still empty */
	if (h2c->mws < 0)
		return 0;

	while (!LIST_ISEMPTY(&h2c->active_list) && (!only_h2s || h2c->active_list.n == &only_h2s->list)) {
		h2s = LIST_ELEM(h2c->active_list.n, struct h2s *, list);
		sid = h2s->id;

		do {
			switch (h2s->res.state) {
			case H2_MS_HDR0:
			case H2_MS_HDR1: /* not used right now */
				ret = h2c_frt_make_resp_headers(h2c, sid, &h2s->res, outbuf);
				break;
			case H2_MS_TRL2: /* this is the end */
				LIST_DEL(h2c->active_list.n);
				LIST_INIT(h2c->active_list.n);
				ret = 0;
				break;
			case H2_MS_BODY:
				ret = h2c_frt_make_resp_data(h2c, h2s, outbuf);
				break;
			default:
				ret = -1; // state should never happen
				break;
			}

			if (ret == 0) // buffer full, stop sending
				return 1;

			if (ret < 0) {
				h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
				return -1;
			}
		} while (ret > 0 && h2s->res.state != H2_MS_TRL2);

		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
	}
	return 1;
}

/* processes more incoming frames for connection <h2c>, limiting this to stream
 * <only_h2s> if non-null. It is designed to be called from both sides to make
 * progress on the connection, either when releasing some room on the stream
 * side, or when new data arrive on the connection side. Return values are :
 *   -1 : error already set on the connection
 *    0 : had to stop (buffer full, end of input stream, etc)
 *    1 : need to let the h2c handler verify and take action (eg: other stream).
 */
static int h2c_frt_process_frames(struct h2c *h2c, struct h2s *only_h2s)
{
	struct appctx *appctx = h2c->appctx;
	struct stream_interface *si = appctx->owner;
	struct channel *req = si_oc(si);
	struct chunk *outbuf = NULL;
	struct chunk *in = NULL;
	int frame_len;
	int ret;

	in = alloc_trash_chunk();
	if (!in)
		goto error;

	outbuf = alloc_trash_chunk();
	if (!outbuf)
		goto error;

	while (1) {
		if (appctx->st0 == H2_CS_ERROR)
			goto error;

		if (appctx->st0 == H2_CS_FRAME_H || appctx->st0 == H2_CS_SETTINGS1) {
			/* we need to read a new frame. h2c->dsi might not yet
			 * have been reset, so we'll have to do it whenever we
			 * leave this block.
			 */
			int dfl, dft, dsi;

			/* just for debugging */
			if ((ret = bo_getblk(req, in->str, req->buf->o, 0)) > 0) {
				fprintf(stderr, "[%d] -- %d bytes received ---\n", appctx->st0, ret);
				debug_hexdump(stderr, "[H2RD] ", in->str, 0, ret);
				fprintf(stderr, "----------------------------\n");
			}

			ret = h2_peek_frame_header(req, &dfl, &dft, &dsi);
			if (ret < 0) {
				h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
				goto error;
			}

			if (ret == 0)
				goto out_empty;

			fprintf(stderr, "[%d] Received frame of %d bytes, type %d (%s), flags %02x, sid %d [max_id=%d]\n",
				appctx->st0, dfl,
				dft & 0xff, h2_ft_str(dft),
				dft >> 8, dsi, h2c->max_id);

			if (unlikely(appctx->st0 == H2_CS_SETTINGS1)) {
				/* supports a single frame type here */
				if (h2_ft(dft) != H2_FT_SETTINGS ||
				    (h2_ff(dft) & H2_F_SETTINGS_ACK)) {
					h2c_error(h2c, H2_ERR_PROTOCOL_ERROR);
					goto error;
				}
				appctx->st0 = H2_CS_FRAME_H;
			}

			/* appctx->st0 is H2_CS_FRAME_H now */
			if (h2c->dsi != dsi) {
				/* switching to a new stream ID, let's send pending window updates */
				ret = h2c_frt_send_window_updates(h2c);
				if (ret <= 0)
					goto done;
			}

			h2c->dfl = dfl;
			h2c->dft = dft;
			h2c->dsi = dsi;
			h2_skip_frame_header(req);
			appctx->st0 = H2_CS_FRAME_P;
		}

		/* read the incoming frame into in->str. FIXME: for now we don't check the
		 * frame length but it's limited by the fact that we read into a trash buffer.
		 */
		frame_len = bo_getblk(req, in->str, h2c->dfl, 0);
		if (h2c->dfl && frame_len <= 0) {
			if (frame_len < 0 || req->buf->o == req->buf->size) {
				fprintf(stderr, "[%d] Truncated frame payload: %d/%d bytes read only\n", appctx->st0, req->buf->o, h2c->dfl);
				h2c_error(h2c, H2_ERR_FRAME_SIZE_ERROR);
				goto error;
			}
			fprintf(stderr, "[%d] Received incomplete frame (%d/%d bytes), waiting [cflags=0x%08x]\n", appctx->st0, req->buf->o, h2c->dfl, req->flags);
			goto out_empty;
		}

		if (frame_len > 0) {
			fprintf(stderr, "[%d] Frame payload: %d bytes :\n", appctx->st0, h2c->dfl);
			debug_hexdump(stderr, "[H2RD] ", in->str, 0, h2c->dfl);
			fprintf(stderr, "--------------\n");
		}

		switch (h2_ft(h2c->dft)) {
		case H2_FT_SETTINGS:
			ret = h2c_frt_handle_settings(h2c, in->str, frame_len);
			break;

		case H2_FT_PING:
			ret = h2c_frt_handle_ping(h2c, in->str);
			break;

		case H2_FT_PRIORITY:
			ret = h2c_frt_handle_priority(h2c, in->str);
			break;

		case H2_FT_HEADERS:
			/* don't process other streams when coming from a stream */
			if (only_h2s && h2c->dsi != only_h2s->id)
				goto out_empty;

			ret = h2c_frt_handle_headers(h2c, in->str, outbuf);
			break;

		case H2_FT_DATA:
			/* don't process other streams when coming from a stream */
			if (only_h2s && h2c->dsi != only_h2s->id)
				goto out_empty;

			ret = h2c_frt_handle_data(h2c, in->str, frame_len);
			break;

		case H2_FT_WINDOW_UPDATE:
			ret = h2c_frt_handle_window_update(h2c, in->str, frame_len);
			break;

		default:
			/* don't process other streams when coming from a stream */
			if (only_h2s && h2c->dsi != only_h2s->id)
				goto out_empty;

			ret = 1; // assume success for frames that we ignore. 0=yield, <0=fail.
		}

		if (ret <= 0)
			goto done;

		bo_skip(req, frame_len);
		appctx->st0 = H2_CS_FRAME_H;
	}

 out_empty:
	/* Nothing more to read. We may have to send window updates for the
	 * current stream. We can only have rcvd_c/s valid after processing
	 * a frame payload (hence before processing a frame header) so we
	 * do not care much about the connection's state.
	 */
	ret = h2c_frt_send_window_updates(h2c);

 done:
	/* branch here for all cases of ret <= 0 where 0 means "can't write,
	 * output full" and <0 means internal error, and >0 simply means "done".
	 */
	if (ret < 0) {
		h2c_error(h2c, H2_ERR_INTERNAL_ERROR);
		goto error;
	}
	if (!ret)
		h2c->flags |= H2_CF_BUFFER_FULL;

	/* also try to process the outgoing side */
	ret = h2c_frt_process_active(h2c, only_h2s, outbuf);
	if (ret < 0)
		goto error;

	/* when called from the H2S side we need to make sure data will
	 * move on the H2C side.
	 */
	if (only_h2s) {
		si_applet_wake_cb(si);
		channel_release_buffer(si_ic(si), &appctx->buffer_wait);
	}

	free_trash_chunk(outbuf);
	free_trash_chunk(in);
	return 0;

 error:
	/* when called from the H2S side we need to make sure data will
	 * move on the H2C side.
	 */
	if (only_h2s) {
		si_applet_wake_cb(si);
		channel_release_buffer(si_ic(si), &appctx->buffer_wait);
	}

	free_trash_chunk(outbuf);
	free_trash_chunk(in);
	return -1;
}


/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to send HTTP stats over a TCP socket. The mechanism is very simple.
 * appctx->st0 contains the operation in progress (dump, done). The handler
 * automatically unregisters itself once transfer is complete.
 */
static void h2c_frt_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct h2c *h2c = appctx->ctx.h2c.ctx;
	struct channel *req = si_oc(si);
	struct channel *res = si_ic(si);
	char preface[sizeof(h2_conn_preface)];
	int ret;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	h2c->flags &= ~H2_CF_BUFFER_FULL;

	if (appctx->st0 == H2_CS_INIT) {
		fprintf(stderr, "[%d] H2: first call\n", appctx->st0);
		ret = h2c_frt_snd_settings(h2c);
		if (!ret)
			goto out;
		if (ret < 0)
			goto fail;
		appctx->st0 = H2_CS_PREFACE;
	}

	if (appctx->st0 == H2_CS_PREFACE) {
		ret = bo_getblk(req, preface, sizeof(h2_conn_preface), 0);
		if (ret < 0)
			goto fail;
		if (ret == 0)
			goto out;

		if (ret != sizeof(h2_conn_preface) ||
		    memcmp(preface, h2_conn_preface, sizeof(h2_conn_preface)) != 0) {
			fprintf(stderr, "[%d] Received bad preface (%d bytes) :\n", appctx->st0, ret);
			debug_hexdump(stderr, "[H2RD] ", preface, 0, ret);
			fprintf(stderr, "--------------\n");
			si_shutr(si);
			res->flags |= CF_READ_NULL;
			si_shutw(si);
			goto out;
		}

		bo_skip(req, ret);
		fprintf(stderr, "[%d] H2: preface found (%d bytes)!\n", appctx->st0, ret);
		appctx->st0 = H2_CS_SETTINGS1;
	}

	if (appctx->st0 != H2_CS_ERROR2 && appctx->st0 != H2_CS_ERROR) {
		ret = h2c_frt_process_frames(h2c, NULL);
		switch (ret) {
		case -1: /* error met, error code already set */
			goto error;
		case 0:  /* can't make progress (input empty, output full) ; flags already updated */
			goto out;
		}
		/* here we catch other return codes including the wake up code */
	}

	if (appctx->st0 == H2_CS_ERROR2) /* must never happen */
		goto fail;

	if (appctx->st0 == H2_CS_ERROR)
		goto error;

 out:
	if ((req->flags & CF_SHUTW) && (si->state == SI_ST_EST) /*&& (appctx->st0 < CLI_ST_OUTPUT)*/) {
		DPRINTF(stderr, "%s@%d: buf to si closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* We have no more processing to do, and nothing more to send, and
		 * the client side has closed. So we'll forward this state downstream
		 * on the response buffer.
		 */
		si_shutr(si);
		res->flags |= CF_READ_NULL;
	}
	return;

 error:
	/* errcode is already filled, send GOAWAY now and
	 * close. We also silently destroy any incoming data to
	 * possibly unlock the sender and make it read pending data.
	 */
	bo_skip(req, req->buf->o);

	ret = h2c_frt_send_goaway_error(h2c);
	if (!ret) {
		h2c->flags |= H2_CF_BUFFER_FULL;
		goto out;
	}

	if (ret > 0) {
		/* OK message sent, let's close now, and
		 * fall through the failure code path.
		 */
		appctx->st0 = H2_CS_ERROR2;
		res->flags |= CF_READ_NULL;
	}

 fail:
	si_shutr(si);
	si_shutw(si);
}

static void h2c_frt_release_handler(struct appctx *appctx)
{
	struct h2c *h2c = appctx->ctx.h2c.ctx;
	struct stream_interface *si;
	struct h2s *h2s;
	struct eb32_node *node;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		node = eb32_next(node);

		/* kill the stream's appctx if it exists and let the orphaned
		 * stream finish in error.
		 */
		if (h2s->appctx->owner) {
			si = h2s->appctx->owner;
			si->flags |= SI_FL_ERR;
			si_release_endpoint(si);
		}

		pool_free2(pool2_h2s, h2s);
	}

	hpack_dht_free(h2c->ddht);
	pool_free2(pool2_h2c, h2c);
	appctx->ctx.h2c.ctx = NULL;
}

/* tries to initialize the front H2 applet and returns non-zero, or fails and
 * returns zero.
 */
int h2c_frt_init(struct stream *s)
{
	struct appctx *appctx;
	struct h2c *h2c;

	h2c = pool_alloc2(pool2_h2c);
	if (!h2c)
		goto fail;

	h2c->ddht = hpack_dht_alloc(h2_settings_header_table_size);
	if (!h2c->ddht)
		goto fail;

	s->target = &h2c_frt_applet.obj_type;
	if (unlikely(!stream_int_register_handler(&s->si[1], objt_applet(s->target)))) {
		s->logs.tv_request = now;
		// impossible to return an error on the connection here
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_RESOURCE;
		goto fail;
	}

	/* Initialise the context. */
	appctx = si_appctx(&s->si[1]);
	memset(&appctx->ctx, 0, sizeof(appctx->ctx));
	appctx->st0 = H2_CS_INIT;
	appctx->ctx.h2c.ctx = h2c;
	h2c->appctx = appctx;
	h2c->max_id = 0;
	h2c->errcode = H2_ERR_NO_ERROR;
	h2c->flags = H2_CF_NONE;
	h2c->dsi = -1;
	h2c->msi = -1;
	h2c->miw = 65535; /* mux initial window size */
	h2c->mws = 65535; /* mux window size */
	h2c->mfs = 16384; /* initial max frame size */
	h2c->streams_by_id = EB_ROOT_UNIQUE;
	LIST_INIT(&h2c->active_list);

	/* Now we can schedule the applet. */
	si_applet_cant_get(&s->si[1]);
	appctx_wakeup(appctx);

	s->sess->fe->fe_counters.intercepted_req++;

	/* ensure we don't go through the backend and server assignment */
	s->flags |= SF_TUNNEL | SF_ASSIGNED;
	s->req.analysers &= AN_REQ_FLT_END;
	s->req.analyse_exp = TICK_ETERNITY;
	s->res.analysers &= AN_RES_FLT_END;
	s->res.analyse_exp = TICK_ETERNITY;
	channel_forward_forever(&s->req);
	channel_forward_forever(&s->res);
	return 1;
 fail:
	pool_free2(pool2_h2c, h2c);
	return 0;
}

/* this is the other side of the h2c_frt_applet, it deals with the stream */
static void h2s_frt_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct channel *req = si_ic(si);
	struct channel *res = si_oc(si);
	struct h2s *h2s = appctx->ctx.h2s.ctx;
	struct h2c *h2c = h2s->h2c;

	/* FIXME: to do later */
	fprintf(stderr, "in %s : h2s=%p h2c=%p req->i=%d res->o=%d res->i=%d\n", __FUNCTION__, h2s, h2c, req->buf->i, res->buf->o, res->buf->i);

	if (res->buf->o || (res->flags & CF_SHUTW))
		LIST_ADDQ(&h2c->active_list, &h2s->list);

	debug_hexdump(stderr, "[H1RD] ", res->buf->data, 0, res->buf->o);

	h2c_frt_process_frames(h2c, h2s);

	if (!res->buf->o && !(res->flags & CF_SHUTW)) {
		LIST_DEL(&h2s->list);
		LIST_INIT(&h2s->list);
	}

	si_applet_cant_get(si);
	si_applet_stop_put(si);
}

static void h2s_frt_release_handler(struct appctx *appctx)
{
	struct h2s *h2s = appctx->ctx.h2s.ctx;

	/* FIXME: to do later */
	fprintf(stderr, "in %s\n", __FUNCTION__);
	if (!LIST_ISEMPTY(&h2s->list))
		LIST_DEL(&h2s->list);
}

/* config parser for global "tune.h2.header-table-size" */
static int h2_parse_header_table_size(char **args, int section_type, struct proxy *curpx,
                                      struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_header_table_size = atoi(args[1]);
	if (h2_settings_header_table_size < 4096 || h2_settings_header_table_size > 65536) {
		memprintf(err, "'%s' expects a numeric value between 4096 and 65536.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.initial-window-size" */
static int h2_parse_initial_window_size(char **args, int section_type, struct proxy *curpx,
                                        struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_initial_window_size = atoi(args[1]);
	if (h2_settings_initial_window_size < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.max-concurrent-streams" */
static int h2_parse_max_concurrent_streams(char **args, int section_type, struct proxy *curpx,
                                           struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_max_concurrent_streams = atoi(args[1]);
	if (h2_settings_max_concurrent_streams < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.h2.header-table-size",      h2_parse_header_table_size      },
	{ CFG_GLOBAL, "tune.h2.initial-window-size",    h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ 0, NULL, NULL }
}};

__attribute__((constructor))
static void __h2_init(void)
{
	pool2_h2c = create_pool("h2c", sizeof(struct h2c), MEM_F_SHARED);
	pool2_h2s = create_pool("h2s", sizeof(struct h2s), MEM_F_SHARED);
	cfg_register_keywords(&cfg_kws);
}
