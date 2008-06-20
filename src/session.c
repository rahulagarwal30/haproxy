/*
 * Server management functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>

#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>

#include <types/backend.h>
#include <types/capture.h>
#include <types/log.h>
#include <types/proxy.h>
#include <types/server.h>

#include <proto/buffers.h>
#include <proto/hdr_idx.h>
#include <proto/log.h>
#include <proto/session.h>
#include <proto/queue.h>


struct pool_head *pool2_session;

/*
 * frees  the context associated to a session. It must have been removed first.
 */
void session_free(struct session *s)
{
	struct http_txn *txn = &s->txn;
	struct proxy *fe = s->fe;

	if (s->pend_pos)
		pendconn_free(s->pend_pos);
	if (s->srv)  /* there may be requests left pending in queue */
		process_srv_queue(s->srv);
	if (unlikely(s->srv_conn)) {
		/* the session still has a reserved slot on a server, but
		 * it should normally be only the same as the one above,
		 * so this should not happen in fact.
		 */
		sess_change_server(s, NULL);
	}

	if (s->req)
		pool_free2(pool2_buffer, s->req);
	if (s->rep)
		pool_free2(pool2_buffer, s->rep);

	if (fe) {
		if (txn->hdr_idx.v != NULL)
			pool_free2(fe->hdr_idx_pool, txn->hdr_idx.v);

		if (txn->rsp.cap != NULL) {
			struct cap_hdr *h;
			for (h = fe->rsp_cap; h; h = h->next) {
				if (txn->rsp.cap[h->index] != NULL)
					pool_free2(h->pool, txn->rsp.cap[h->index]);
			}
			pool_free2(fe->rsp_cap_pool, txn->rsp.cap);
		}
		if (txn->req.cap != NULL) {
			struct cap_hdr *h;
			for (h = fe->req_cap; h; h = h->next) {
				if (txn->req.cap[h->index] != NULL)
					pool_free2(h->pool, txn->req.cap[h->index]);
			}
			pool_free2(fe->req_cap_pool, txn->req.cap);
		}
	}
	if (txn->uri)
		pool_free2(pool2_requri, txn->uri);
	if (txn->cli_cookie)
		pool_free2(pool2_capture, txn->cli_cookie);
	if (txn->srv_cookie)
		pool_free2(pool2_capture, txn->srv_cookie);

	pool_free2(pool2_session, s);

	/* We may want to free the maximum amount of pools if the proxy is stopping */
	if (fe && unlikely(fe->state == PR_STSTOPPED)) {
		if (pool2_buffer)
			pool_flush2(pool2_buffer);
		if (fe->hdr_idx_pool)
			pool_flush2(fe->hdr_idx_pool);
		if (pool2_requri)
			pool_flush2(pool2_requri);
		if (pool2_capture)
			pool_flush2(pool2_capture);
		if (pool2_session)
			pool_flush2(pool2_session);
		if (fe->req_cap_pool)
			pool_flush2(fe->req_cap_pool);
		if (fe->rsp_cap_pool)
			pool_flush2(fe->rsp_cap_pool);
	}
}


/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_session()
{
	pool2_session = create_pool("session", sizeof(struct session), MEM_F_SHARED);
	return pool2_session != NULL;
}

void session_process_counters(struct session *s)
{
	unsigned long long bytes;

	if (s->req) {
		bytes = s->req->total - s->logs.bytes_in;
		s->logs.bytes_in = s->req->total;
		if (bytes) {
			s->fe->bytes_in          += bytes;

			if (s->be != s->fe)
				s->be->bytes_in  += bytes;

			if (s->srv)
				s->srv->bytes_in += bytes;
		}
	}

	if (s->rep) {
		bytes = s->rep->total - s->logs.bytes_out;
		s->logs.bytes_out = s->rep->total;
		if (bytes) {
			s->fe->bytes_out          += bytes;

			if (s->be != s->fe)
				s->be->bytes_out  += bytes;

			if (s->srv)
				s->srv->bytes_out += bytes;
		}
	}
}

/*
 * This function adjusts sess->srv_conn and maintains the previous and new
 * server's served session counts. Setting newsrv to NULL is enough to release
 * current connection slot. This function also notifies any LB algo which might
 * expect to be informed about any change in the number of active sessions on a
 * server.
 */
void sess_change_server(struct session *sess, struct server *newsrv)
{
	if (sess->srv_conn == newsrv)
		return;

	if (sess->srv_conn) {
		sess->srv_conn->served--;
		sess->srv_conn = NULL;
	}

	if (newsrv) {
		newsrv->served++;
		sess->srv_conn = newsrv;
	}
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
