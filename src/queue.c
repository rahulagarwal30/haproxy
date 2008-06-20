/*
 * Queue management functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/memory.h>
#include <common/time.h>

#include <types/proxy.h>
#include <types/session.h>

#include <proto/queue.h>
#include <proto/server.h>
#include <proto/task.h>


struct pool_head *pool2_pendconn;

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_pendconn()
{
	pool2_pendconn = create_pool("pendconn", sizeof(struct pendconn), MEM_F_SHARED);
	return pool2_pendconn != NULL;
}

/* returns the effective dynamic maxconn for a server, considering the minconn
 * and the proxy's usage relative to its dynamic connections limit. It is
 * expected that 0 < s->minconn <= s->maxconn when this is called. If the
 * server is currently warming up, the slowstart is also applied to the
 * resulting value, which can be lower than minconn in this case, but never
 * less than 1.
 */
unsigned int srv_dynamic_maxconn(const struct server *s)
{
	unsigned int max;

	if (s->proxy->beconn >= s->proxy->fullconn)
		/* no fullconn or proxy is full */
		max = s->maxconn;
	else if (s->minconn == s->maxconn)
		/* static limit */
		max = s->maxconn;
	else max = MAX(s->minconn,
		       s->proxy->beconn * s->maxconn / s->proxy->fullconn);

	if ((s->state & SRV_WARMINGUP) &&
	    now.tv_sec < s->last_change + s->slowstart &&
	    now.tv_sec >= s->last_change) {
		unsigned int ratio;
		ratio = MAX(1, 100 * (now.tv_sec - s->last_change) / s->slowstart);
		max = max * ratio / 100;
	}
	return max;
}


/*
 * Manages a server's connection queue. This function will try to dequeue as
 * many pending sessions as possible, and wake them up.
 */
void process_srv_queue(struct server *s)
{
	struct proxy  *p = s->proxy;
	int maxconn;

	/* First, check if we can handle some connections queued at the proxy. We
	 * will take as many as we can handle.
	 */

	maxconn = srv_dynamic_maxconn(s);
	while (s->served < maxconn) {
		struct session *sess = pendconn_get_next_sess(s, p);
		if (sess == NULL)
			break;
		task_wakeup(sess->task);
	}
}

/* Detaches the next pending connection from either a server or a proxy, and
 * returns its associated session. If no pending connection is found, NULL is
 * returned. Note that neither <srv> nor <px> may be NULL.
 * Priority is given to the oldest request in the queue if both <srv> and <px>
 * have pending requests. This ensures that no request will be left unserved.
 * The session is immediately marked as "assigned", and both its <srv> and
 * <srv_conn> are set to <srv>,
 */
struct session *pendconn_get_next_sess(struct server *srv, struct proxy *px)
{
	struct pendconn *ps, *pp;
	struct session *sess;

	ps = pendconn_from_srv(srv);
	pp = pendconn_from_px(px);
	/* we want to get the definitive pendconn in <ps> */
	if (!pp) {
		if (!ps)
			return NULL;
	} else {
		/* pendconn exists in the proxy queue */
		if (!ps || tv_islt(&pp->sess->logs.tv_request, &ps->sess->logs.tv_request)) {
			ps = pp;
			ps->sess->srv = srv;
		}
	}
	sess = ps->sess;
	pendconn_free(ps);

	/* we want to note that the session has now been assigned a server */
	sess->flags |= SN_ASSIGNED;
	sess->srv = srv;
	sess->srv_conn = srv;
	srv->served++;
	if (px->lbprm.server_take_conn)
		px->lbprm.server_take_conn(srv);

	return sess;
}

/* Adds the session <sess> to the pending connection list of server <sess>->srv
 * or to the one of <sess>->proxy if srv is NULL. All counters and back pointers
 * are updated accordingly. Returns NULL if no memory is available, otherwise the
 * pendconn itself. If the session was already marked as served, its flag is
 * cleared. It is illegal to call this function with a non-NULL sess->srv_conn.
 */
struct pendconn *pendconn_add(struct session *sess)
{
	struct pendconn *p;

	p = pool_alloc2(pool2_pendconn);
	if (!p)
		return NULL;

	sess->pend_pos = p;
	p->sess = sess;
	p->srv  = sess->srv;

	if (sess->flags & SN_ASSIGNED && sess->srv) {
		LIST_ADDQ(&sess->srv->pendconns, &p->list);
		sess->srv->nbpend++;
		sess->logs.srv_queue_size += sess->srv->nbpend;
		if (sess->srv->nbpend > sess->srv->nbpend_max)
			sess->srv->nbpend_max = sess->srv->nbpend;
	} else {
		LIST_ADDQ(&sess->be->pendconns, &p->list);
		sess->be->nbpend++;
		sess->logs.prx_queue_size += sess->be->nbpend;
		if (sess->be->nbpend > sess->be->nbpend_max)
			sess->be->nbpend_max = sess->be->nbpend;
	}
	sess->be->totpend++;
	return p;
}

/*
 * Detaches pending connection <p>, decreases the pending count, and frees
 * the pending connection. The connection might have been queued to a specific
 * server as well as to the proxy. The session also gets marked unqueued.
 */
void pendconn_free(struct pendconn *p)
{
	LIST_DEL(&p->list);
	p->sess->pend_pos = NULL;
	if (p->srv)
		p->srv->nbpend--;
	else
		p->sess->be->nbpend--;
	p->sess->be->totpend--;
	pool_free2(pool2_pendconn, p);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
