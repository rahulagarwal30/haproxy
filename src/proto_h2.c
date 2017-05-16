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

/* creates a new stream <id> on the h2c connection and returns it, or NULL in
 * case of memory allocation error.
 */
static struct h2s *h2c_stream_new(struct h2c *h2c, int id)
{
	struct h2s *h2s;

	/* DEBUG CODE */
	struct eb32_node *node = eb32_lookup(&h2c->streams_by_id, id);
	if (node) {
		h2s = container_of(node, struct h2s, by_id);
		fprintf(stderr, "%s:%d(%s): BUG!: h2c=%p id=%d ret=%p id=%d\n", __FILE__, __LINE__, __FUNCTION__, h2c, id, h2s, id);
	}

	if (!id)
		fprintf(stderr, "%s:%d(%s): BUG!: h2c=%p id=%d\n", __FILE__, __LINE__, __FUNCTION__, h2c, id);
	/* /DEBUG */

	h2s = pool_alloc2(pool2_h2s);
	if (!h2s)
		goto out;

	h2s->h2c       = h2c;
	h2s->appctx    = h2c->appctx;
	h2s->st        = H2_SS_IDLE;
	h2s->rst       = H2_RST_NONE;
	h2s->by_id.key = h2s->id = id;
	eb32_insert(&h2c->streams_by_id, &h2s->by_id);
 out:
	return h2s;
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
	struct chunk *temp = NULL;
	struct h2s *h2s;
	int reql;
	int ret;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	temp = get_trash_chunk();

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
		reql = bo_getblk(req, temp->str, sizeof(h2_conn_preface), 0);
		if (reql < 0)
			goto fail;
		if (reql == 0)
			goto out;

		if (reql != sizeof(h2_conn_preface) ||
		    memcmp(temp->str, h2_conn_preface, sizeof(h2_conn_preface)) != 0) {
			fprintf(stderr, "[%d] Received bad preface (%d bytes) :\n", appctx->st0, reql);
			debug_hexdump(stderr, "[H2RD] ", temp->str, 0, reql);
			fprintf(stderr, "--------------\n");
			si_shutr(si);
			res->flags |= CF_READ_NULL;
			si_shutw(si);
			goto out;
		}

		bo_skip(req, reql);
		fprintf(stderr, "[%d] H2: preface found (%d bytes)!\n", appctx->st0, reql);
		appctx->st0 = H2_CS_SETTINGS1;
	}

	while (1) {
		if (h2c->dsi < 0) {
			/* we need to read a new frame */

			/* just for debugging */
			if ((reql = bo_getblk(req, temp->str, req->buf->o, 0)) > 0) {
				fprintf(stderr, "[%d] -- %d bytes received ---\n", appctx->st0, reql);
				debug_hexdump(stderr, "[H2RD] ", temp->str, 0, reql);
				fprintf(stderr, "----------------------------\n");
			}

			reql = h2_get_frame(req, &h2c->dfl, &h2c->dft, &h2c->dsi);
			if (reql < 0)
				goto fail;
			if (reql == 0)
				goto out;

			fprintf(stderr, "[%d] Received frame of %d bytes, type %d (%s), flags %02x, sid %d\n",
				appctx->st0, h2c->dfl,
				h2c->dft & 0xff, h2_ft_str(h2c->dft),
				h2c->dft >> 8, h2c->dsi);

			if (unlikely(appctx->st0 == H2_CS_SETTINGS1)) {
				// supports a single frame type here
				if (h2_ft(h2c->dft) != H2_FT_SETTINGS ||
				    (h2_ff(h2c->dft) & H2_F_SETTINGS_ACK))
					goto fail;
				appctx->st0 = H2_CS_FRAME;
			}
		}

		/* read the incoming frame into temp->str. FIXME: for now we don't check the
		 * frame length but it's limited by the fact that we read into a trash buffer.
		 */
		if ((bo_getblk(req, temp->str, h2c->dfl, 0)) > 0) {
			fprintf(stderr, "[%d] Frame payload: %d bytes :\n", appctx->st0, h2c->dfl);
			debug_hexdump(stderr, "[H2RD] ", temp->str, 0, h2c->dfl);
			fprintf(stderr, "--------------\n");
		}

		ret = 1; // assume success for frames that we ignore. 0=yield, <0=fail.
		switch (h2_ft(h2c->dft)) {
		case H2_FT_SETTINGS:
			if (!(h2_ff(h2c->dft) & H2_F_SETTINGS_ACK))
				ret = h2c_frt_ack_settings(h2c);
			break;

		case H2_FT_PING:
			/* frame length must be exactly 8 */
			if (h2c->dfl != 8)
				goto fail;

			if (!(h2_ff(h2c->dft) & H2_F_PING_ACK))
				ret = h2c_frt_ack_ping(h2c, temp->str);
			break;

		case H2_FT_PRIORITY:
			fprintf(stderr, "   ");
			if (temp->str[0] & 0x80)
				fprintf(stderr, " [EXCLUSIVE] ");

			fprintf(stderr, " [dep=%d] ", ((temp->str[0] & 0x7f)<<24) + ((unsigned char)temp->str[1] << 16) + ((unsigned char)temp->str[2] << 8) + (unsigned char)temp->str[3]);

			fprintf(stderr, " [weight=%d] ", (unsigned char)temp->str[4]);

			h2s = h2c_st_by_id(h2c, h2c->dsi);
			fprintf(stderr, " [h2s=%p:%s]", h2s, h2s ? h2_ss_str(h2s->st) : "idle");
			fprintf(stderr, "\n");
			break;

		case H2_FT_HEADERS:
			if (h2_ff(h2c->dft) & H2_F_HEADERS_END_STREAM)
				fprintf(stderr, "[%d] HEADERS with END_STREAM\n", appctx->st0);
			if (h2_ff(h2c->dft) & H2_F_HEADERS_END_HEADERS)
				fprintf(stderr, "[%d] HEADERS with END_HEADERS\n", appctx->st0);
			if (h2_ff(h2c->dft) & H2_F_HEADERS_PADDED)
				fprintf(stderr, "[%d] HEADERS with PADDED\n", appctx->st0);
			if (h2_ff(h2c->dft) & H2_F_HEADERS_PRIORITY)
				fprintf(stderr, "[%d] HEADERS with PRIORITY\n", appctx->st0);

			h2s = h2c_st_by_id(h2c, h2c->dsi);
			fprintf(stderr, "    [h2s=%p:%s]", h2s, h2s ? h2_ss_str(h2s->st) : "idle");

			h2s = h2c_stream_new(h2c, h2c->dsi);
			h2s->st = H2_SS_OPEN;
			if (h2_ff(h2c->dft) & H2_F_HEADERS_END_STREAM)
				h2s->st = H2_SS_HREM;
			fprintf(stderr, " [newh2s=%p:%s]\n", h2s, h2s ? h2_ss_str(h2s->st) : "idle");

		case H2_FT_DATA:
			if (h2_ff(h2c->dft) & H2_F_DATA_END_STREAM)
				fprintf(stderr, "[%d] DATA with END_STREAM\n", appctx->st0);
			if (h2_ff(h2c->dft) & H2_F_DATA_PADDED)
				fprintf(stderr, "[%d] DATA with PADDED\n", appctx->st0);

			h2s = h2c_st_by_id(h2c, h2c->dsi);
			fprintf(stderr, "    [h2s=%p:%s]", h2s, h2s ? h2_ss_str(h2s->st) : "idle");

			if (h2s->st == H2_SS_OPEN && (h2_ff(h2c->dft) & H2_F_DATA_END_STREAM))
				h2s->st = H2_SS_HREM;
			fprintf(stderr, " [h2s=%p:%s]\n", h2s, h2s ? h2_ss_str(h2s->st) : "idle");
		}

		if (!ret)
			goto out;

		if (ret < 0)
			goto fail;

		bo_skip(req, h2c->dfl);
		h2c->dsi = -1;
	}

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

 fail:
	si_shutr(si);
	si_shutw(si);
	return;
}

static void h2c_frt_release_handler(struct appctx *appctx)
{
	struct h2c *h2c = appctx->ctx.h2c.ctx;
	struct h2s *h2s;
	struct eb32_node *node;

	node = eb32_first(&h2c->streams_by_id);
	while (node) {
		h2s = container_of(node, struct h2s, by_id);
		node = eb32_next(node);
		pool_free2(pool2_h2s, h2s);
	}

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

__attribute__((constructor))
static void __h2_init(void)
{
	pool2_h2c = create_pool("h2c", sizeof(struct h2c), MEM_F_SHARED);
	pool2_h2s = create_pool("h2s", sizeof(struct h2s), MEM_F_SHARED);
}
