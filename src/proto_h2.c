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

struct applet h2c_frt_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<H2CFRT>", /* used for logging */
	.fct = h2c_frt_io_handler,
	.release = NULL,
};


/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to send HTTP stats over a TCP socket. The mechanism is very simple.
 * appctx->st0 contains the operation in progress (dump, done). The handler
 * automatically unregisters itself once transfer is complete.
 */
static void h2c_frt_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct channel *req = si_oc(si);
	struct channel *res = si_ic(si);
	struct chunk *temp = NULL;
	int reql;
	int flen, ftype, sid;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	temp = get_trash_chunk();

	if (appctx->st0 == H2_CS_INIT) {
		fprintf(stderr, "[%d] H2: first call\n", appctx->st0);
		appctx->st0 = H2_CS_PREFACE;
	}

	if (appctx->st0 == H2_CS_PREFACE) {
		reql = bo_getblk(req, temp->str, sizeof(h2_conn_preface), 0);
		if (reql <= 0)
			goto stop;

		if (reql != sizeof(h2_conn_preface) ||
		    memcmp(temp->str, h2_conn_preface, sizeof(h2_conn_preface)) != 0) {
			fprintf(stderr, "[%d] Received bad preface (%d bytes) :\n", appctx->st0, reql);
			debug_hexdump(stderr, "[H2RD] ", temp->str, 0, reql);
			fprintf(stderr, "--------------\n");
			si_shutr(si);
			res->flags |= CF_READ_NULL;
			si_shutw(si);
			goto stop;
		}

		bo_skip(req, reql);
		fprintf(stderr, "[%d] H2: preface found (%d bytes)!\n", appctx->st0, reql);
		appctx->st0 = H2_CS_SETTINGS1;
	}

	if ((reql = bo_getblk(req, temp->str, req->buf->o, 0)) > 0) {
		fprintf(stderr, "[%d] -- Request received: %d bytes ---\n", appctx->st0, reql);
		debug_hexdump(stderr, "[H2RD] ", temp->str, 0, reql);
		fprintf(stderr, "----------------------------\n");
	}

	while ((reql = h2_get_frame(req, &flen, &ftype, &sid)) > 0) {
		fprintf(stderr, "[%d] Received frame of %d bytes, flags %02x, type %d (%s), sid %d\n",
			appctx->st0, flen, ftype >> 8, ftype, h2_ft_str(ftype), sid);

		if ((bo_getblk(req, temp->str, flen, 0)) > 0) {
			fprintf(stderr, "[%d] Frame payload: %d bytes :\n", appctx->st0, flen);
			debug_hexdump(stderr, "[H2RD] ", temp->str, 0, flen);
			fprintf(stderr, "--------------\n");
		}
		bo_skip(req, flen);
	}

	//while ((reql = bo_getline(req, temp->str, temp->size)) > 0) {
	//	fprintf(stderr, "[%d] Request received: %d bytes :\n", appctx->st0, reql);
	//	debug_hexdump(stderr, temp->str, 0, reql);
	//	fprintf(stderr, "--------------\n");
	//	bo_skip(req, reql);
	//}


 stop:
	/* closed or EOL not found */
	if (reql < 0) { // closed
		fprintf(stderr, "Closed!\n");
		si_shutw(si);
	}

 out:
	//if ((res->flags & CF_SHUTR) && (si->state == SI_ST_EST)) {
	//	DPRINTF(stderr, "%s@%d: si to buf closed. req=%08x, res=%08x, st=%d\n",
	//		__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
	//	/* Other side has closed, let's abort if we have no more processing to do
	//	 * and nothing more to consume. This is comparable to a broken pipe, so
	//	 * we forward the close to the request side so that it flows upstream to
	//	 * the client.
	//	 */
	//	si_shutw(si);
	//}

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
}

/* tries to initialize the front H2 applet and returns non-zero, or fails and
 * returns zero.
 */
int h2c_frt_init(struct stream *s)
{
	struct appctx *appctx;

	s->target = &h2c_frt_applet.obj_type;
	if (unlikely(!stream_int_register_handler(&s->si[1], objt_applet(s->target)))) {
		s->logs.tv_request = now;
		// impossible to return an error on the connection here
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_RESOURCE;
		return 0;
	}

	/* Initialise the context. */
	appctx = si_appctx(&s->si[1]);
	memset(&appctx->ctx, 0, sizeof(appctx->ctx));
	appctx->st0 = H2_CS_INIT;

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
}

__attribute__((constructor))
static void __h2_init(void)
{
	pool2_h2c = create_pool("h2c", sizeof(struct h2c), MEM_F_SHARED);
	pool2_h2s = create_pool("h2s", sizeof(struct h2s), MEM_F_SHARED);
}
