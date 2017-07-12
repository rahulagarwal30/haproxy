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

/* try to send a settings frame on the connection. Returns 0 if not possible
 * yet, <0 on error, >0 on success.
 */
static int h2c_frt_snd_settings(struct h2c *h2c)
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
			"\x04" "\x00"      /* type   : 4, flags : 0 */
			"\x00\x00\x00\x00" /* stream ID */, 9);

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

/* processes a SETTINGS frame and ACKs it if needed. Returns 0 if not possible
 * yet, <0 on error, >0 on success.
 */
static int h2c_frt_handle_settings(struct h2c *h2c)
{
	if (!(h2_ff(h2c->dft) & H2_F_SETTINGS_ACK))
		return h2c_frt_ack_settings(h2c);
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

		/* if we're in the context of a stream, stop when facing another one */
		if (only_h2s && h2c->dsi != only_h2s->id)
			goto wakeup;

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
			ret = h2c_frt_handle_settings(h2c);
			break;

		case H2_FT_PING:
			ret = h2c_frt_handle_ping(h2c, in->str);
			break;

		case H2_FT_PRIORITY:
			ret = h2c_frt_handle_priority(h2c, in->str);
			break;

		case H2_FT_HEADERS:
			ret = h2c_frt_handle_headers(h2c, in->str, outbuf);
			break;

		case H2_FT_DATA:
			ret = h2c_frt_handle_data(h2c, in->str, frame_len);
			break;
		default:
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

	free_trash_chunk(outbuf);
	free_trash_chunk(in);
	return 0;

 error:
	free_trash_chunk(outbuf);
	free_trash_chunk(in);
	return -1;

 wakeup:
	free_trash_chunk(outbuf);
	free_trash_chunk(in);
	return 1;
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

	h2c->ddht = hpack_dht_alloc(4096);
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
	h2c->streams_by_id = EB_ROOT_UNIQUE;

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
	struct h2s *h2s = appctx->ctx.h2s.ctx;
	struct h2c *h2c = h2s->h2c;

	/* FIXME: to do later */
	fprintf(stderr, "in %s : h2s=%p h2c=%p\n", __FUNCTION__, h2s, h2c);

	h2c_frt_process_frames(h2c, h2s);

	si_applet_cant_get(si);
	si_applet_stop_put(si);
}

static void h2s_frt_release_handler(struct appctx *appctx)
{
	/* FIXME: to do later */
	fprintf(stderr, "in %s\n", __FUNCTION__);
}

__attribute__((constructor))
static void __h2_init(void)
{
	pool2_h2c = create_pool("h2c", sizeof(struct h2c), MEM_F_SHARED);
	pool2_h2s = create_pool("h2s", sizeof(struct h2s), MEM_F_SHARED);
}
