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
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>


static void h2c_frt_io_handler(struct appctx *appctx);


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

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	temp = get_trash_chunk();

	while ((reql = bo_getline(req, temp->str, temp->size)) > 0) {
		fprintf(stderr, "Request received: %d bytes :\n", reql);
		debug_hexdump(stderr, "[H2RD] ]", temp->str, 0, reql);
		fprintf(stderr, "--------------\n");
		bo_skip(req, reql);
	}
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
