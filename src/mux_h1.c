/*
 * HTT/1 mux-demux for connections
 *
 * Copyright 2018 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <common/cfgparse.h>
#include <common/config.h>

#include <types/pipe.h>
#include <types/proxy.h>
#include <types/session.h>

#include <proto/connection.h>
#include <proto/h1.h>
#include <proto/http_htx.h>
#include <proto/htx.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>

/*
 *  H1 Connection flags (32 bits)
 */
#define H1C_F_NONE           0x00000000

/* Flags indicating why writing output data are blocked */
#define H1C_F_OUT_ALLOC      0x00000001 /* mux is blocked on lack of output buffer */
#define H1C_F_OUT_FULL       0x00000002 /* mux is blocked on output buffer full */
/* 0x00000004 - 0x00000008 unused */

/* Flags indicating why reading input data are blocked. */
#define H1C_F_IN_ALLOC       0x00000010 /* mux is blocked on lack of input buffer */
#define H1C_F_IN_FULL        0x00000020 /* mux is blocked on input buffer full */
/* 0x00000040 - 0x00000080 unused */

/* Flags indicating why parsing data are blocked */
#define H1C_F_RX_ALLOC       0x00000100 /* mux is blocked on lack of rx buffer */
#define H1C_F_RX_FULL        0x00000200 /* mux is blocked on rx buffer full */
/* 0x00000400 - 0x00000800 unused */

#define H1C_F_CS_ERROR       0x00001000 /* connection must be closed ASAP because an error occurred */
#define H1C_F_CS_SHUTW_NOW   0x00002000 /* connection must be shut down for writes ASAP */
#define H1C_F_CS_SHUTW       0x00004000 /* connection is already shut down */
#define H1C_F_CS_WAIT_CONN   0x00008000 /* waiting for the connection establishment */

#define H1C_F_WAIT_NEXT_REQ  0x00010000 /*  waiting for the next request to start, use keep-alive timeout */

/*
 * H1 Stream flags (32 bits)
 */
#define H1S_F_NONE           0x00000000
#define H1S_F_ERROR          0x00000001 /* An error occurred on the H1 stream */
#define H1S_F_REQ_ERROR      0x00000002 /* An error occurred during the request parsing/xfer */
#define H1S_F_RES_ERROR      0x00000004 /* An error occurred during the response parsing/xfer */
#define H1S_F_MSG_XFERED     0x00000008 /* current message was transferred to the data layer */
#define H1S_F_WANT_KAL       0x00000010
#define H1S_F_WANT_TUN       0x00000020
#define H1S_F_WANT_CLO       0x00000040
#define H1S_F_WANT_MSK       0x00000070
#define H1S_F_NOT_FIRST      0x00000080 /* The H1 stream is not the first one */
#define H1S_F_BUF_FLUSH      0x00000100 /* Flush input buffers (ibuf and rxbuf) and don't read more data */


/* H1 connection descriptor */
struct h1c {
	struct connection *conn;
	struct proxy *px;
	uint32_t flags;                  /* Connection flags: H1C_F_* */

	struct buffer ibuf;              /* Input buffer to store data before parsing */
	struct buffer obuf;              /* Output buffer to store data after reformatting */

	struct buffer_wait buf_wait;     /* Wait list for buffer allocation */
	struct wait_event wait_event;    /* To be used if we're waiting for I/Os */

	struct h1s *h1s;                 /* H1 stream descriptor */
	struct task *task;               /* timeout management task */

	int idle_exp;                    /* expiration date for idle connections, in ticks (client-side only)*/
	int http_exp;                    /* expiration date for HTTP headers parsing (client-side only) */
};

/* H1 stream descriptor */
struct h1s {
	struct h1c *h1c;
	struct conn_stream *cs;
	uint32_t flags; /* Connection flags: H1S_F_* */

	struct buffer rxbuf; /*receive buffer, always valid (buf_empty or real buffer) */

	struct wait_event *recv_wait; /* Address of the wait_event the conn_stream associated is waiting on */
	struct wait_event *send_wait; /* Address of the wait_event the conn_stream associated is waiting on */

	struct h1m req;
	struct h1m res;

	enum http_meth_t meth; /* HTTP resquest method */
	uint16_t status;       /* HTTP response status */
};

/* the h1c and h1s pools */
static struct pool_head *pool_head_h1c;
static struct pool_head *pool_head_h1s;

static struct task *h1_timeout_task(struct task *t, void *context, unsigned short state);
static int h1_recv(struct h1c *h1c);
static int h1_send(struct h1c *h1c);
static int h1_process(struct h1c *h1c);
static struct task *h1_io_cb(struct task *t, void *ctx, unsigned short state);
static void h1_shutw_conn(struct connection *conn);

/*****************************************************/
/* functions below are for dynamic buffer management */
/*****************************************************/
/*
 * Indicates whether or not the we may call the h1_recv() function to
 * attempt to receive data into the buffer and/or parse pending data. The
 * condition is a bit complex due to some API limits for now. The rules are the
 * following :
 *   - if an error or a shutdown was detected on the connection and the buffer
 *     is empty, we must not attempt to receive
 *   - if the input buffer failed to be allocated, we must not try to receive
 *      and we know there is nothing pending
 *   - if no flag indicates a blocking condition, we may attempt to receive,
 *     regardless of whether the input buffer is full or not, so that only de
 *     receiving part decides whether or not to block. This is needed because
 *     the connection API indeed prevents us from re-enabling receipt that is
 *     already enabled in a polled state, so we must always immediately stop as
 *     soon as the mux can't proceed so as never to hit an end of read with data
 *     pending in the buffers.
 *   - otherwise must may not attempt to receive
 */
static inline int h1_recv_allowed(const struct h1c *h1c)
{
	if (b_data(&h1c->ibuf) == 0 &&
	    (h1c->flags & (H1C_F_CS_ERROR||H1C_F_CS_SHUTW) ||
	     h1c->conn->flags & CO_FL_ERROR ||
	     conn_xprt_read0_pending(h1c->conn)))
		return 0;

	if (!(h1c->flags & (H1C_F_IN_ALLOC|H1C_F_IN_FULL)))
		return 1;

	return 0;
}

/*
 * Tries to grab a buffer and to re-enables processing on mux <target>. The h1
 * flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the connection is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
static int h1_buf_available(void *target)
{
	struct h1c *h1c = target;

	if ((h1c->flags & H1C_F_IN_ALLOC) && b_alloc_margin(&h1c->ibuf, 0)) {
		h1c->flags &= ~H1C_F_IN_ALLOC;
		if (h1_recv_allowed(h1c))
			tasklet_wakeup(h1c->wait_event.task);
		return 1;
	}

	if ((h1c->flags & H1C_F_OUT_ALLOC) && b_alloc_margin(&h1c->obuf, 0)) {
		h1c->flags &= ~H1C_F_OUT_ALLOC;
		tasklet_wakeup(h1c->wait_event.task);
		return 1;
	}

	if ((h1c->flags & H1C_F_RX_ALLOC) && h1c->h1s && b_alloc_margin(&h1c->h1s->rxbuf, 0)) {
		h1c->flags &= ~H1C_F_RX_ALLOC;
		if (h1_recv_allowed(h1c))
			tasklet_wakeup(h1c->wait_event.task);
		return 1;
	}

	return 0;
}

/*
 * Allocate a buffer. If if fails, it adds the mux in buffer wait queue.
 */
static inline struct buffer *h1_get_buf(struct h1c *h1c, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(LIST_ISEMPTY(&h1c->buf_wait.list)) &&
	    unlikely((buf = b_alloc_margin(bptr, 0)) == NULL)) {
		h1c->buf_wait.target = h1c;
		h1c->buf_wait.wakeup_cb = h1_buf_available;
		HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		LIST_ADDQ(&buffer_wq, &h1c->buf_wait.list);
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		__conn_xprt_stop_recv(h1c->conn);
	}
	return buf;
}

/*
 * Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
static inline void h1_release_buf(struct h1c *h1c, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(h1c->buf_wait.target, tasks_run_queue);
	}
}

static int h1_avail_streams(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	return h1c->h1s ? 0 : 1;
}


/*****************************************************************/
/* functions below are dedicated to the mux setup and management */
/*****************************************************************/
static struct h1s *h1s_create(struct h1c *h1c, struct conn_stream *cs)
{
	struct h1s *h1s;

	h1s = pool_alloc(pool_head_h1s);
	if (!h1s)
		goto end;

	h1s->h1c = h1c;
	h1c->h1s = h1s;

	h1s->cs    = NULL;
	h1s->rxbuf = BUF_NULL;
	h1s->flags = H1S_F_NONE;

	h1s->recv_wait = NULL;
	h1s->send_wait = NULL;

	h1m_init_req(&h1s->req);
	h1s->req.flags |= H1_MF_NO_PHDR;

	h1m_init_res(&h1s->res);
	h1s->res.flags |= H1_MF_NO_PHDR;

	h1s->status = 0;
	h1s->meth   = HTTP_METH_OTHER;

	if (!conn_is_back(h1c->conn)) {
		if (h1c->px->options2 & PR_O2_REQBUG_OK)
			h1s->req.err_pos = -1;

		if (h1c->flags & H1C_F_WAIT_NEXT_REQ)
			h1s->flags |= H1S_F_NOT_FIRST;
		h1c->flags &= ~H1C_F_WAIT_NEXT_REQ;
		h1c->http_exp = tick_add_ifset(now_ms, h1c->px->timeout.httpreq);
	}
	else {
		if (h1c->px->options2 & PR_O2_RSPBUG_OK)
			h1s->res.err_pos = -1;
	}

	/* If a conn_stream already exists, attach it to this H1S */
	if (cs) {
		cs->ctx = h1s;
		h1s->cs = cs;
	}
  end:
	return h1s;
}

static void h1s_destroy(struct h1s *h1s)
{
	if (h1s) {
		struct h1c *h1c = h1s->h1c;

		h1c->h1s = NULL;
		h1c->flags &= ~(H1C_F_RX_FULL|H1C_F_RX_ALLOC);

		if (h1s->recv_wait != NULL)
			h1s->recv_wait->wait_reason &= ~SUB_CAN_RECV;
		if (h1s->send_wait != NULL)
			h1s->send_wait->wait_reason &= ~SUB_CAN_SEND;

		if (!conn_is_back(h1c->conn)) {
			h1c->flags |= H1C_F_WAIT_NEXT_REQ;
			h1c->http_exp = tick_add_ifset(now_ms, h1c->px->timeout.httpka);
		}

		h1_release_buf(h1c, &h1s->rxbuf);
		cs_free(h1s->cs);
		pool_free(pool_head_h1s, h1s);
	}
}

static struct conn_stream *h1s_new_cs(struct h1s *h1s)
{
	struct conn_stream *cs;

	cs = cs_new(h1s->h1c->conn);
	if (!cs)
		goto err;
	h1s->cs = cs;
	cs->ctx = h1s;

	if (h1s->flags & H1S_F_NOT_FIRST)
		cs->flags |= CS_FL_NOT_FIRST;

	if (stream_create_from_cs(cs) < 0)
		goto err;
	return cs;

  err:
	cs_free(cs);
	h1s->cs = NULL;
	return NULL;
}

/*
 * Initialize the mux once it's attached. It is expected that conn->mux_ctx
 * points to the existing conn_stream (for outgoing connections) or NULL (for
 * incoming ones). Returns < 0 on error.
 */
static int h1_init(struct connection *conn, struct proxy *proxy)
{
	struct h1c *h1c;
	struct task *t = NULL;

	h1c = pool_alloc(pool_head_h1c);
	if (!h1c)
		goto fail_h1c;
	h1c->conn = conn;
	h1c->px   = proxy;

	h1c->flags = H1C_F_NONE;
	h1c->ibuf  = BUF_NULL;
	h1c->obuf  = BUF_NULL;
	h1c->h1s   = NULL;

	t = task_new(tid_bit);
	if (!t)
		goto fail;
	h1c->task  = t;
	t->process = h1_timeout_task;
	t->context = h1c;
	t->expire  = TICK_ETERNITY;

	h1c->idle_exp = TICK_ETERNITY;
	h1c->http_exp = TICK_ETERNITY;

	LIST_INIT(&h1c->buf_wait.list);
	h1c->wait_event.task = tasklet_new();
	if (!h1c->wait_event.task)
		goto fail;
	h1c->wait_event.task->process = h1_io_cb;
	h1c->wait_event.task->context = h1c;
	h1c->wait_event.wait_reason   = 0;

	if (!(conn->flags & CO_FL_CONNECTED))
		h1c->flags |= H1C_F_CS_WAIT_CONN;

	/* Always Create a new H1S */
	if (!h1s_create(h1c, conn->mux_ctx))
		goto fail;

	conn->mux_ctx = h1c;
	task_wakeup(t, TASK_WOKEN_INIT);

	/* Try to read, if nothing is available yet we'll just subscribe */
	if (h1_recv(h1c))
		h1_process(h1c);

	/* mux->wake will be called soon to complete the operation */
	return 0;

  fail:
	if (t)
		task_free(t);
	if (h1c && h1c->wait_event.task)
		tasklet_free(h1c->wait_event.task);
	pool_free(pool_head_h1c, h1c);
 fail_h1c:
	return -1;
}


/* release function for a connection. This one should be called to free all
 * resources allocated to the mux.
 */
static void h1_release(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	LIST_DEL(&conn->list);

	if (h1c) {
		if (!LIST_ISEMPTY(&h1c->buf_wait.list)) {
			HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
			LIST_DEL(&h1c->buf_wait.list);
			LIST_INIT(&h1c->buf_wait.list);
			HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		}

		h1_release_buf(h1c, &h1c->ibuf);
		h1_release_buf(h1c, &h1c->obuf);

		if (h1c->task) {
			h1c->task->context = NULL;
			task_wakeup(h1c->task, TASK_WOKEN_OTHER);
			h1c->task = NULL;
		}
		if (h1c->wait_event.task)
			tasklet_free(h1c->wait_event.task);

		h1s_destroy(h1c->h1s);
		if (h1c->wait_event.wait_reason != 0)
			conn->xprt->unsubscribe(conn, h1c->wait_event.wait_reason,
			    &h1c->wait_event);
		pool_free(pool_head_h1c, h1c);
	}

	conn->mux = NULL;
	conn->mux_ctx = NULL;

	conn_stop_tracking(conn);
	conn_full_close(conn);
	if (conn->destroy_cb)
		conn->destroy_cb(conn);
	conn_free(conn);
}

/******************************************************/
/* functions below are for the H1 protocol processing */
/******************************************************/
/*
 * Set the appropriate error message. It first tries to get it from the proxy if
 * it exists. Otherwise, it falls back on default one.
 */
static void h1_cpy_error_message(struct h1c *h1c, struct buffer *dst, int status)
{
	const int msgnum = http_get_status_idx(status);
	const struct buffer *err;

	err = (h1c->px->errmsg[msgnum].area
	       ? &h1c->px->errmsg[msgnum]
	       : &http_err_chunks[msgnum]);
	b_putblk(dst, b_head(err), b_data(err));
}

/* Parse the request version and set H1_MF_VER_11 on <h1m> if the version is
 * greater or equal to 1.1
 */
static void h1_parse_req_vsn(struct h1m *h1m, const union htx_sl *sl)
{
	const char *p = sl->rq.l + sl->rq.m_len + sl->rq.u_len;

	if ((sl->rq.v_len == 8) &&
	    (*(p + 5) > '1' ||
	     (*(p + 5) == '1' && *(p + 7) >= '1')))
		h1m->flags |= H1_MF_VER_11;
}

/* Parse the response version and set H1_MF_VER_11 on <h1m> if the version is
 * greater or equal to 1.1
 */
static void h1_parse_res_vsn(struct h1m *h1m, const union htx_sl *sl)
{
	const char *p = sl->rq.l;

	if ((sl->st.v_len == 8) &&
	    (*(p + 5) > '1' ||
	     (*(p + 5) == '1' && *(p + 7) >= '1')))
		h1m->flags |= H1_MF_VER_11;
}

/*
 * Check the validity of the request version. If the version is valid, it
 * returns 1. Otherwise, it returns 0.
 */
static int h1_process_req_vsn(struct h1s *h1s, struct h1m *h1m, union h1_sl sl)
{
	struct h1c *h1c = h1s->h1c;

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (!(h1c->px->options2 & PR_O2_REQBUG_OK)) {
		if (sl.rq.v.len != 8)
			return 0;

		if (*(sl.rq.v.ptr + 4) != '/' ||
		    !isdigit((unsigned char)*(sl.rq.v.ptr + 5)) ||
		    *(sl.rq.v.ptr + 6) != '.' ||
		    !isdigit((unsigned char)*(sl.rq.v.ptr + 7)))
			return 0;
	}
	else if (!sl.rq.v.len) {
		/* try to convert HTTP/0.9 requests to HTTP/1.0 */

		/* RFC 1945 allows only GET for HTTP/0.9 requests */
		if (sl.rq.meth != HTTP_METH_GET)
			return 0;

		/* HTTP/0.9 requests *must* have a request URI, per RFC 1945 */
		if (!sl.rq.u.len)
			return 0;

		/* Add HTTP version */
		sl.rq.v = ist("HTTP/1.0");
	}
	return 1;
}

/*
 * Check the validity of the response version. If the version is valid, it
 * returns 1. Otherwise, it returns 0.
 */
static int h1_process_res_vsn(struct h1s *h1s, struct h1m *h1m, union h1_sl sl)
{
	struct h1c *h1c = h1s->h1c;

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (!(h1c->px->options2 & PR_O2_RSPBUG_OK)) {
		if (sl.st.v.len != 8)
			return 0;

		if (*(sl.st.v.ptr + 4) != '/' ||
		    !isdigit((unsigned char)*(sl.st.v.ptr + 5)) ||
		    *(sl.st.v.ptr + 6) != '.' ||
		    !isdigit((unsigned char)*(sl.st.v.ptr + 7)))
			return 0;
	}
	return 1;
}
/* Remove all "Connection:" headers from the HTX message <htx> */
static void h1_remove_conn_hdrs(struct h1m *h1m, struct htx *htx)
{
	struct ist hdr = {.ptr = "Connection", .len = 10};
	struct http_hdr_ctx ctx;

	while (http_find_header(htx, hdr, &ctx, 1))
		http_remove_header(htx, &ctx);

	h1m->flags &= ~(H1_MF_CONN_KAL|H1_MF_CONN_CLO);
}

/* Add a "Connection:" header with the value <value> into the HTX message
 * <htx>.
 */
static void h1_add_conn_hdr(struct h1m *h1m, struct htx *htx, struct ist value)
{
	struct ist hdr = {.ptr = "Connection", .len = 10};

	http_add_header(htx, hdr, value);
}

/* Deduce the connection mode of the client connection, depending on the
 * configuration and the H1 message flags. This function is called twice, the
 * first time when the request is parsed and the second time when the response
 * is parsed.
 */
static void h1_set_cli_conn_mode(struct h1s *h1s, struct h1m *h1m)
{
	struct proxy *fe = h1s->h1c->px;
	int flag = H1S_F_WANT_KAL; /* For client connection: server-close == keepalive */

	/* Tunnel mode can only by set on the frontend */
	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
		flag = H1S_F_WANT_TUN;
	else if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO)
		flag = H1S_F_WANT_CLO;

	/* flags order: CLO > SCL > TUN > KAL */
	if ((h1s->flags & H1S_F_WANT_MSK) < flag)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | flag;

	if (h1m->flags & H1_MF_RESP) {
		/* Either we've established an explicit tunnel, or we're
		 * switching the protocol. In both cases, we're very unlikely to
		 * understand the next protocols. We have to switch to tunnel
		 * mode, so that we transfer the request and responses then let
		 * this protocol pass unmodified. When we later implement
		 * specific parsers for such protocols, we'll want to check the
		 * Upgrade header which contains information about that protocol
		 * for responses with status 101 (eg: see RFC2817 about TLS).
		 */
		if ((h1s->meth == HTTP_METH_CONNECT && h1s->status == 200) ||
		    h1s->status == 101)
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_TUN;
		else if (!(h1m->flags & H1_MF_XFER_LEN)) /* no length known => close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
	}
	else {
		if (h1s->flags & H1S_F_WANT_KAL &&
		    (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) || /* no KA in HTTP/1.0 */
		     h1m->flags & H1_MF_CONN_CLO))                    /* explicit close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
	}

	/* If KAL, check if the frontend is stopping. If yes, switch in CLO mode */
	if (h1s->flags & H1S_F_WANT_KAL && fe->state == PR_STSTOPPED)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
}

/* Deduce the connection mode of the client connection, depending on the
 * configuration and the H1 message flags. This function is called twice, the
 * first time when the request is parsed and the second time when the response
 * is parsed.
 */
static void h1_set_srv_conn_mode(struct h1s *h1s, struct h1m *h1m)
{
	struct proxy *be = h1s->h1c->px;
	struct proxy *fe = strm_fe(si_strm(h1s->cs->data));
	int flag =  H1S_F_WANT_KAL;

	/* Tunnel mode can only by set on the frontend */
	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_TUN)
		flag = H1S_F_WANT_TUN;

	/* For the server connection: server-close == httpclose */
	if ((fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (be->options & PR_O_HTTP_MODE) == PR_O_HTTP_SCL ||
	    (fe->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO ||
	    (be->options & PR_O_HTTP_MODE) == PR_O_HTTP_CLO)
		flag = H1S_F_WANT_CLO;

	/* flags order: CLO > SCL > TUN > KAL */
	if ((h1s->flags & H1S_F_WANT_MSK) < flag)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | flag;

	if (h1m->flags & H1_MF_RESP) {
		/* Either we've established an explicit tunnel, or we're
		 * switching the protocol. In both cases, we're very unlikely to
		 * understand the next protocols. We have to switch to tunnel
		 * mode, so that we transfer the request and responses then let
		 * this protocol pass unmodified. When we later implement
		 * specific parsers for such protocols, we'll want to check the
		 * Upgrade header which contains information about that protocol
		 * for responses with status 101 (eg: see RFC2817 about TLS).
		 */
		if ((h1s->meth == HTTP_METH_CONNECT && h1s->status == 200) ||
		    h1s->status == 101)
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_TUN;
		else if (!(h1m->flags & H1_MF_XFER_LEN)) /* no length known => close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
		else if (h1s->flags & H1S_F_WANT_KAL &&
			 (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL)) || /* no KA in HTTP/1.0 */
			  h1m->flags & H1_MF_CONN_CLO))                    /* explicit close */
			h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
	}

	/* If KAL, check if the backend is stopping. If yes, switch in CLO mode */
	if (h1s->flags & H1S_F_WANT_KAL && be->state == PR_STSTOPPED)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;

	/* TODO: For now on the server-side, we disable keep-alive */
	if (h1s->flags & H1S_F_WANT_KAL)
		h1s->flags = (h1s->flags & ~H1S_F_WANT_MSK) | H1S_F_WANT_CLO;
}

static void h1_update_req_conn_hdr(struct h1s *h1s, struct h1m *h1m,
				   struct htx *htx, struct ist *conn_val)
{
	struct proxy *px = h1s->h1c->px;

	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		return;

	if (h1s->flags & H1S_F_WANT_KAL || px->options2 & PR_O2_FAKE_KA) {
		if (h1m->flags & H1_MF_CONN_CLO) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL))) {
			if (conn_val)
				*conn_val = ist("keep-alive");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("keep-alive"));
		}
	}
	else { /* H1S_F_WANT_CLO && !PR_O2_FAKE_KA */
		if (h1m->flags & H1_MF_CONN_KAL) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_VER_11) {
			if (conn_val)
				*conn_val = ist("close");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("close"));
		}
	}
}

static void h1_update_res_conn_hdr(struct h1s *h1s, struct h1m *h1m,
					 struct htx *htx, struct ist *conn_val)
{
	/* Don't update "Connection:" header in TUNNEL mode or if "Upgrage"
	 * token is found
	 */
	if (h1s->flags & H1S_F_WANT_TUN || h1m->flags & H1_MF_CONN_UPG)
		return;

	if (h1s->flags & H1S_F_WANT_KAL) {
		if (h1m->flags & H1_MF_CONN_CLO) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if (!(h1m->flags & (H1_MF_VER_11|H1_MF_CONN_KAL))) {
			if (conn_val)
				*conn_val = ist("keep-alive");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("keep-alive"));
		}
	}
	else { /* H1S_F_WANT_CLO */
		if (h1m->flags & H1_MF_CONN_KAL) {
			if (conn_val)
				*conn_val = ist("");
			if (htx)
				h1_remove_conn_hdrs(h1m, htx);
		}
		if ((h1m->flags & (H1_MF_VER_11|H1_MF_CONN_CLO)) == H1_MF_VER_11) {
			if (conn_val)
				*conn_val = ist("close");
			if (htx)
				h1_add_conn_hdr(h1m, htx, ist("close"));
		}
	}
}

/* Set the right connection mode and update "Connection:" header if
 * needed. <htx> and <conn_val> can be NULL. When <htx> is not NULL, the HTX
 * message is updated accordingly. When <conn_val> is not NULL, it is set with
 * the new header value.
 */
static void h1_process_conn_mode(struct h1s *h1s, struct h1m *h1m,
				 struct htx *htx, struct ist *conn_val)
{
	if (!conn_is_back(h1s->h1c->conn)) {
		h1_set_cli_conn_mode(h1s, h1m);
		if (h1m->flags & H1_MF_RESP)
			h1_update_res_conn_hdr(h1s, h1m, htx, conn_val);
	}
	else {
		h1_set_srv_conn_mode(h1s, h1m);
		if (!(h1m->flags & H1_MF_RESP))
			h1_update_req_conn_hdr(h1s, h1m, htx, conn_val);
	}
}

/*
 * Parse HTTP/1 headers. It returns the number of bytes parsed if > 0, or 0 if
 * it couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR
 * flag and filling h1s->err_pos and h1s->err_state fields. This functions is
 * responsibile to update the parser state <h1m>.
 */
static size_t h1_process_headers(struct h1s *h1s, struct h1m *h1m, struct htx *htx,
				 struct buffer *buf, size_t *ofs, size_t max)
{
	struct http_hdr hdrs[MAX_HTTP_HDR];
	union h1_sl sl;
	int ret = 0;

	/* Realing input buffer if necessary */
	if (b_head(buf) + b_data(buf) > b_wrap(buf))
		b_slow_realign(buf, trash.area, 0);

	ret = h1_headers_to_hdr_list(b_peek(buf, *ofs), b_peek(buf, *ofs) + max,
				     hdrs, sizeof(hdrs)/sizeof(hdrs[0]), h1m, &sl);
	if (ret <= 0) {
		/* Incomplete or invalid message. If the buffer is full, it's an
		 * error because headers are too large to be handled by the
		 * parser. */
		if (ret < 0 || (!ret && b_full(buf)))
			goto error;
		goto end;
	}

	/* messages headers fully parsed, do some checks to prepare the body
	 * parsing.
	 */

	/* Be sure to keep some space to do headers rewritting */
	if (ret > (b_size(buf) - global.tune.maxrewrite))
		goto error;

	/* Save the request's method or the response's status, check if the body
	 * length is known and check the VSN validity */
	if (!(h1m->flags & H1_MF_RESP)) {
		h1s->meth = sl.rq.meth;

		/* Request have always a known length */
		h1m->flags |= H1_MF_XFER_LEN;
		if (!(h1m->flags & H1_MF_CHNK) && !h1m->body_len)
			h1m->state = H1_MSG_DONE;

		if (!h1_process_req_vsn(h1s, h1m, sl)) {
			h1m->err_pos = sl.rq.v.ptr - b_head(buf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
	}
	else {
		h1s->status = sl.st.status;

		if ((h1s->meth == HTTP_METH_HEAD) ||
		    (h1s->status >= 100 && h1s->status < 200) ||
		    (h1s->status == 204) || (h1s->status == 304) ||
		    (h1s->meth == HTTP_METH_CONNECT && h1s->status == 200)) {
			h1m->flags &= ~(H1_MF_CLEN|H1_MF_CHNK);
			h1m->flags |= H1_MF_XFER_LEN;
			h1m->curr_len = h1m->body_len = 0;
			h1m->state = H1_MSG_DONE;
		}
		else if (h1m->flags & (H1_MF_CLEN|H1_MF_CHNK)) {
			h1m->flags |= H1_MF_XFER_LEN;
			if ((h1m->flags & H1_MF_CLEN) && !h1m->body_len)
				h1m->state = H1_MSG_DONE;
		}
		else
			h1m->state = H1_MSG_TUNNEL;

		if (!h1_process_res_vsn(h1s, h1m, sl)) {
			h1m->err_pos = sl.st.v.ptr - b_head(buf);
			h1m->err_state = h1m->state;
			goto vsn_error;
		}
	}

	if (!(h1m->flags & H1_MF_RESP)) {
		if (!htx_add_reqline(htx, sl) || !htx_add_all_headers(htx, hdrs))
			goto error;
	}
	else {
		if (!htx_add_resline(htx, sl) || !htx_add_all_headers(htx, hdrs))
			goto error;
	}
	if (h1m->state == H1_MSG_DONE)
		if (!htx_add_endof(htx, HTX_BLK_EOM))
			goto error;

	h1_process_conn_mode(h1s, h1m, htx, NULL);

	/* If body length cannot be determined, set htx->extra to
	 * ULLONG_MAX. This value is impossible in other cases.
	 */
	htx->extra = ((h1m->flags & H1_MF_XFER_LEN) ? h1m->curr_len : ULLONG_MAX);

	/* Recheck there is enough space to do headers rewritting */
	if (htx_used_space(htx) > b_size(buf) - global.tune.maxrewrite)
		goto error;

	*ofs += ret;
  end:
	return ret;

  error:
	h1m->err_state = h1m->state;
	h1m->err_pos = h1m->next;
  vsn_error:
	h1s->flags |= (!(h1m->flags & H1_MF_RESP) ? H1S_F_REQ_ERROR : H1S_F_RES_ERROR);
	ret = 0;
	goto end;
}

/*
 * Parse HTTP/1 body. It returns the number of bytes parsed if > 0, or 0 if it
 * couldn't proceed. Parsing errors are reported by setting H1S_F_*_ERROR flag
 * and filling h1s->err_pos and h1s->err_state fields. This functions is
 * responsibile to update the parser state <h1m>.
 */
static size_t h1_process_data(struct h1s *h1s, struct h1m *h1m, struct htx *htx,
			      struct buffer *buf, size_t *ofs, size_t max)
{
	uint32_t data_space = htx_free_data_space(htx);
	size_t total = 0;
	int ret = 0;

	if (h1m->flags & H1_MF_XFER_LEN) {
		if (h1m->flags & H1_MF_CLEN) {
			/* content-length: read only h2m->body_len */
			ret = max;
			if (ret > data_space)
				ret = data_space;
			if ((uint64_t)ret > h1m->curr_len)
				ret = h1m->curr_len;
			if (ret > b_contig_data(buf, *ofs))
				ret = b_contig_data(buf, *ofs);
			if (ret) {
				if (!htx_add_data(htx, ist2(b_peek(buf, *ofs), ret)))
					goto end;
				h1m->curr_len -= ret;
				*ofs += ret;
				total += ret;
			}

			if (!h1m->curr_len) {
				if (!htx_add_endof(htx, HTX_BLK_EOM))
					goto end;
				h1m->state = H1_MSG_DONE;
			}
		}
		else if (h1m->flags & H1_MF_CHNK) {
		  new_chunk:
			/* te:chunked : parse chunks */
			if (h1m->state == H1_MSG_CHUNK_CRLF) {
				ret = h1_skip_chunk_crlf(buf, *ofs, *ofs + max);
				if (ret <= 0)
					goto end;
				h1m->state = H1_MSG_CHUNK_SIZE;

				max -= ret;
				*ofs += ret;
				total += ret;
			}

			if (h1m->state == H1_MSG_CHUNK_SIZE) {
				unsigned int chksz;

				ret = h1_parse_chunk_size(buf, *ofs, *ofs + max, &chksz);
				if (ret <= 0)
					goto end;
				if (!chksz) {
					if (!htx_add_endof(htx, HTX_BLK_EOD))
						goto end;
					h1m->state = H1_MSG_TRAILERS;
				}
				else
					h1m->state = H1_MSG_DATA;

				h1m->curr_len  = chksz;
				h1m->body_len += chksz;
				max -= ret;
				*ofs += ret;
				total += ret;
			}

			if (h1m->state == H1_MSG_DATA) {
				ret = max;
				if (ret > data_space)
					ret = data_space;
				if ((uint64_t)ret > h1m->curr_len)
					ret = h1m->curr_len;
				if (ret > b_contig_data(buf, *ofs))
					ret = b_contig_data(buf, *ofs);
				if (ret) {
					if (!htx_add_data(htx, ist2(b_peek(buf, *ofs), ret)))
						goto end;
					h1m->curr_len -= ret;
					max -= ret;
					*ofs += ret;
					total += ret;
				}
				if (!h1m->curr_len) {
					h1m->state = H1_MSG_CHUNK_CRLF;
					goto new_chunk;
				}
				goto end;
			}

			if (h1m->state == H1_MSG_TRAILERS) {
				ret = h1_measure_trailers(buf, *ofs, *ofs + max);
				if (ret > data_space)
					ret = (htx_is_empty(htx) ? -1 : 0);
				if (ret <= 0)
					goto end;

				/* Realing input buffer if tailers wrap. For now
				 * this is a workaroung. Because trailers are
				 * not split on CRLF, like headers, there is no
				 * way to know where to split it when trailers
				 * wrap. This is a limitation of
				 * h1_measure_trailers.
				 */
				if (b_peek(buf, *ofs) > b_peek(buf, *ofs + ret))
					b_slow_realign(buf, trash.area, 0);

				if (!htx_add_trailer(htx, ist2(b_peek(buf, *ofs), ret)))
					goto end;

				max -= ret;
				*ofs += ret;
				total += ret;

				/* FIXME: if it fails here, this is a problem,
				 * because there is no way to return here. */
				if (!htx_add_endof(htx, HTX_BLK_EOM))
					goto end;
				h1m->state = H1_MSG_DONE;
			}
		}
		else {
			/* XFER_LEN is set but not CLEN nor CHNK, it means there
			 * is no body. Switch the message in DONE state
			 */
			if (!htx_add_endof(htx, HTX_BLK_EOM))
				goto end;
			h1m->state = H1_MSG_DONE;
		}
	}
	else {
		/* no content length, read till SHUTW */
		ret = max;
		if (ret > data_space)
			ret = data_space;
		if (ret > b_contig_data(buf, *ofs))
			ret = b_contig_data(buf, *ofs);
		if (ret) {
			if (!htx_add_data(htx, ist2(b_peek(buf, *ofs), ret)))
				goto end;

			*ofs += max;
			total = max;
		}
	}

  end:
	if (ret < 0) {
		h1s->flags |= (!(h1m->flags & H1_MF_RESP) ? H1S_F_REQ_ERROR : H1S_F_RES_ERROR);
		h1m->err_state = h1m->state;
		h1m->err_pos = *ofs + max + ret;
		return 0;
	}
	/* update htx->extra, only when the body length is known */
	if (h1m->flags & H1_MF_XFER_LEN)
		htx->extra = h1m->curr_len;
	return total;
}

/*
 * Synchronize the request and the response before reseting them. Except for 1xx
 * responses, we wait that the request and the response are in DONE state and
 * that all data are forwarded for both. For 1xx responses, only the response is
 * reset, waiting the final one. Many 1xx messages can be sent.
 */
static void h1_sync_messages(struct h1c *h1c)
{
	struct h1s *h1s = h1c->h1s;

	if (!h1s)
		return;

	if (h1s->res.state == H1_MSG_DONE &&
	    (h1s->status < 200 && (h1s->status == 100 || h1s->status >= 102)) &&
	    ((!conn_is_back(h1c->conn) && !b_data(&h1c->obuf)) || !b_data(&h1s->rxbuf))) {
		/* For 100-Continue response or any other informational 1xx
		 * response which is non-final, don't reset the request, the
		 * transaction is not finished. We take care the response was
		 * transferred before.
		 */
		h1m_init_res(&h1s->res);
		h1s->res.flags |= H1_MF_NO_PHDR;
	}
	else if (!b_data(&h1s->rxbuf) && !b_data(&h1c->obuf) &&
		 h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE) {
		if (h1s->flags & H1S_F_WANT_TUN) {
			h1m_init_req(&h1s->req);
			h1m_init_res(&h1s->res);
			h1s->req.state = H1_MSG_TUNNEL;
			h1s->res.state = H1_MSG_TUNNEL;
		}
	}
}

/*
 * Process incoming data. It parses data and transfer them from h1c->ibuf into
 * h1s->rxbuf. It returns the number of bytes parsed and transferred if > 0, or
 * 0 if it couldn't proceed.
 */
static size_t h1_process_input(struct h1c *h1c, struct buffer *buf, size_t count)
{
	struct h1s *h1s = NULL;
	struct h1m *h1m;
	struct htx *htx;
	size_t total = 0;
	size_t ret = 0;
	size_t max;
	int errflag;

	h1s = NULL;

	/* Create a new H1S without CS if not already done */
	if (!h1c->h1s && !h1s_create(h1c, NULL))
		goto err;
	h1s = h1c->h1s;

#if 0
	// FIXME: Use a proxy option to enable early creation of the CS
	/* Create the CS if not already attached to the H1S */
	if (!h1s->cs && !h1s_new_cs(h1s))
		goto err;
#endif

	if (!h1_get_buf(h1c, &h1s->rxbuf)) {
		h1c->flags |= H1C_F_RX_ALLOC;
		goto end;
	}
	htx = htx_from_buf(&h1s->rxbuf);

	if (!conn_is_back(h1c->conn)) {
		h1m = &h1s->req;
		errflag = H1S_F_REQ_ERROR;
	}
	else {
		h1m = &h1s->res;
		errflag = H1S_F_RES_ERROR;
	}

	max = count;
	while (!(h1s->flags & errflag) && max) {
		if (h1m->state <= H1_MSG_LAST_LF) {
			ret = h1_process_headers(h1s, h1m, htx, buf, &total, max);
			if (!ret)
				break;

			/* Reset request timeout */
			h1s->h1c->http_exp = TICK_ETERNITY;

			/* Create the CS if not already attached to the H1S */
			if (!h1s->cs && !h1s_new_cs(h1s))
				goto err;
		}
		else if (h1m->state <= H1_MSG_TRAILERS) {
			/* Do not parse the body if the header part is not yet
			 * transferred to the stream.
			 */
			if (!(h1s->flags & H1S_F_MSG_XFERED))
				break;
			ret = h1_process_data(h1s, h1m, htx, buf, &total, max);
			if (!ret)
				break;
		}
		else if (h1m->state == H1_MSG_DONE)
			break;
		else if (h1m->state == H1_MSG_TUNNEL) {
			ret = h1_process_data(h1s, h1m, htx, buf, &total, max);
			if (!ret)
				break;
		}
		else {
			h1s->flags |= errflag;
			break;
		}

		max -= ret;
	}

	if (h1s->flags & errflag) {
		if (conn_is_back(h1c->conn))
			goto err;

		// FIXME: Do following actions when an error is catched during
		// the request parsing:
		//
		//  * Do same than stream_inc_http_req_ctr,
		//    stream_inc_http_err_ctr and proxy_inc_fe_req_ctr
		//  * Capture bad message for snapshots
		//  * Increment fe->fe_counters.failed_req and
		//    listeners->counters->failed_req
		//
		// FIXME: Do following actions when an error is catched during
		// the response parsing:
		//
		//  * Capture bad message for snapshots
		//  * increment be->be_counters.failed_resp
		//  * increment srv->counters.failed_resp (if srv assigned)
		if (!h1_get_buf(h1c, &h1c->obuf)) {
			h1c->flags |= H1C_F_OUT_ALLOC;
			goto err;
		}
		h1_cpy_error_message(h1c, &h1c->obuf, 400);
		goto err;
	}

	b_del(buf, total);

	if (htx_is_not_empty(htx)) {
		b_set_data(&h1s->rxbuf, b_size(&h1s->rxbuf));
		if (!htx_free_data_space(htx))
			h1c->flags |= H1C_F_RX_FULL;

		if (h1s->recv_wait) {
			h1s->recv_wait->wait_reason &= ~SUB_CAN_RECV;
			tasklet_wakeup(h1s->recv_wait->task);
			h1s->recv_wait = NULL;
		}
	}
	else
		h1_release_buf(h1c, &h1s->rxbuf);

	ret = count - max;

  end:
	return ret;

  err:
	//h1s_destroy(h1s);
	h1c->flags |= H1C_F_CS_ERROR;
	if (!h1s || !h1s->cs)
		sess_log(h1c->conn->owner);
	return 0;
}

/*
 * Process outgoing data. It parses data and transfer them from the channel buffer into
 * h1c->obuf. It returns the number of bytes parsed and transferred if > 0, or
 * 0 if it couldn't proceed.
 */
static size_t h1_process_output(struct h1c *h1c, struct buffer *buf, size_t count)
{
	struct h1s *h1s = h1c->h1s;
	struct h1m *h1m;
	struct htx *chn_htx;
	struct htx_blk *blk;
	struct buffer *tmp;
	size_t total = 0;
	int errflag;

	chn_htx = htx_from_buf(buf);

	if (!h1_get_buf(h1c, &h1c->obuf)) {
		h1c->flags |= H1C_F_OUT_ALLOC;
		goto end;
	}

	if (!conn_is_back(h1c->conn)) {
		h1m = &h1s->res;
		errflag = H1S_F_RES_ERROR;
	}
	else {
		h1m = &h1s->req;
		errflag = H1S_F_REQ_ERROR;
	}


	tmp = get_trash_chunk();
	tmp->size = b_room(&h1c->obuf);

	blk = htx_get_head_blk(chn_htx);
	while (!(h1s->flags & errflag) && blk) {
		union htx_sl *sl;
		struct ist n, v;
		uint32_t sz = htx_get_blksz(blk);

		if (total + sz > count)
			goto copy;

		switch (htx_get_blk_type(blk)) {
			case HTX_BLK_UNUSED:
				break;

			case HTX_BLK_REQ_SL:
				sl = htx_get_blk_ptr(chn_htx, blk);
				h1s->meth = sl->rq.meth;
				h1_parse_req_vsn(h1m, sl);
				if (!htx_reqline_to_str(sl, tmp))
					goto copy;
				h1m->flags |= H1_MF_XFER_LEN;
				h1m->state = H1_MSG_HDR_FIRST;
				break;

			case HTX_BLK_RES_SL:
				sl = htx_get_blk_ptr(chn_htx, blk);
				h1s->status = sl->st.status;
				h1_parse_res_vsn(h1m, sl);
				if (!htx_stline_to_str(sl, tmp))
					goto copy;
				if (chn_htx->extra != ULLONG_MAX)
					h1m->flags |= H1_MF_XFER_LEN;
				h1m->state = H1_MSG_HDR_FIRST;
				break;

			case HTX_BLK_HDR:
				if (h1m->state == H1_MSG_HDR_FIRST) {
					struct http_hdr_ctx ctx;

					n = ist("Connection");
					v = ist("");

					/* If there is no "Connection:" header,
					 * process conn_mode now and add the
					 * right one.
					 */
					ctx.blk = blk;
					if (http_find_header(chn_htx, n, &ctx, 1))
						goto process_hdr;
					h1_process_conn_mode(h1s, h1m, NULL, &v);
					if (!v.len)
						goto process_hdr;

					if (!htx_hdr_to_str(n, v, tmp))
						goto copy;
				}
			  process_hdr:
				h1m->state = H1_MSG_HDR_NAME;
				n = htx_get_blk_name(chn_htx, blk);
				v = htx_get_blk_value(chn_htx, blk);

				if (isteqi(n, ist("transfer-encoding")))
					h1_parse_xfer_enc_header(h1m, v);
				else if (isteqi(n, ist("connection"))) {
					h1_parse_connection_header(h1m, v);
					h1_process_conn_mode(h1s, h1m, NULL, &v);
					if (!v.len)
						goto skip_hdr;
				}

				if (!htx_hdr_to_str(n, v, tmp))
					goto copy;
			  skip_hdr:
				h1m->state = H1_MSG_HDR_L2_LWS;
				break;

			case HTX_BLK_PHDR:
				/* not implemented yet */
				h1m->flags |= errflag;
				break;

			case HTX_BLK_EOH:
				h1m->state = H1_MSG_LAST_LF;
				if (!chunk_memcat(tmp, "\r\n", 2))
					goto copy;

				h1m->state = H1_MSG_DATA;
				break;

			case HTX_BLK_DATA:
				v = htx_get_blk_value(chn_htx, blk);
				if (!htx_data_to_str(v, tmp, !!(h1m->flags & H1_MF_CHNK)))
					goto copy;
				break;

			case HTX_BLK_EOD:
				if (!chunk_memcat(tmp, "0\r\n", 3))
					goto copy;
				h1m->state = H1_MSG_TRAILERS;
				break;

			case HTX_BLK_TLR:
				v = htx_get_blk_value(chn_htx, blk);
				if (!htx_trailer_to_str(v, tmp))
					goto copy;
				break;

			case HTX_BLK_EOM:
				/* if ((h1m->flags & H1_MF_CHNK) && !chunk_memcat(tmp, "\r\n", 2)) */
				/* 	goto copy; */
				h1m->state = H1_MSG_DONE;
				break;

			case HTX_BLK_OOB:
				v = htx_get_blk_value(chn_htx, blk);
				if (!chunk_memcat(tmp, v.ptr, v.len))
					goto copy;
				break;

			default:
				h1m->flags |= errflag;
				break;
		}
		total += sz;
		blk = htx_remove_blk(chn_htx, blk);
	}

  copy:
	b_putblk(&h1c->obuf, tmp->area, tmp->data);

	if (b_full(&h1c->obuf))
		h1c->flags |= H1C_F_OUT_FULL;
	if (htx_is_empty(chn_htx)) {
		htx_reset(chn_htx);
		b_set_data(buf, 0);
	}

  end:
	return total;
}

/*
 * Transfer data from h1s->rxbuf into the channel buffer. It returns the number
 * of bytes transferred.
 */
static size_t h1_xfer(struct h1s *h1s, struct buffer *buf, int flags)
{
	struct h1c *h1c = h1s->h1c;
	struct h1m *h1m;
	struct conn_stream *cs = h1s->cs;
	struct htx *mux_htx, *chn_htx;
	struct htx_ret htx_ret;
	size_t count, ret = 0;

	h1m = (!conn_is_back(h1c->conn) ? &h1s->req : &h1s->res);
	mux_htx = htx_from_buf(&h1s->rxbuf);

	if (htx_is_empty(mux_htx))
		goto end;

	chn_htx = htx_from_buf(buf);

	count = htx_free_space(chn_htx);
	if (flags & CO_RFL_KEEP_RSV) {
		if (count < global.tune.maxrewrite)
			goto end;
		count -= global.tune.maxrewrite;
	}

	// FIXME: if chn empty and count > htx => b_xfer !
	if (!(h1s->flags & H1S_F_MSG_XFERED)) {
		htx_ret = htx_xfer_blks(chn_htx, mux_htx, count,
					((h1m->state == H1_MSG_DONE) ? HTX_BLK_EOM : HTX_BLK_EOH));
		ret = htx_ret.ret;
		if (htx_ret.blk && htx_get_blk_type(htx_ret.blk) >= HTX_BLK_EOH)
			h1s->flags |= H1S_F_MSG_XFERED;
	}
	else {
		htx_ret = htx_xfer_blks(chn_htx, mux_htx, count, HTX_BLK_EOM);
		ret = htx_ret.ret;
	}
	chn_htx->extra = mux_htx->extra;
	if (h1m->flags & H1_MF_XFER_LEN)
		chn_htx->extra += mux_htx->data;

	if (htx_is_not_empty(chn_htx))
		b_set_data(buf, b_size(buf));

  end:
	if (h1c->flags & H1C_F_RX_FULL && htx_free_data_space(mux_htx)) {
		h1c->flags &= ~H1C_F_RX_FULL;
		tasklet_wakeup(h1c->wait_event.task);
	}

	if (htx_is_not_empty(mux_htx)) {
		cs->flags |= CS_FL_RCV_MORE;
	}
	else {
		h1c->flags &= ~H1C_F_RX_FULL;
		h1_release_buf(h1c, &h1s->rxbuf);
		h1_sync_messages(h1c);

		cs->flags &= ~CS_FL_RCV_MORE;
		if (!b_data(&h1c->ibuf) && (cs->flags & CS_FL_REOS))
			cs->flags |= CS_FL_EOS;
	}
	return ret;
}

/*********************************************************/
/* functions below are I/O callbacks from the connection */
/*********************************************************/
/*
 * Attempt to read data, and subscribe if none available
 */
static int h1_recv(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	size_t ret, max;
	int rcvd = 0;

	if (h1c->wait_event.wait_reason & SUB_CAN_RECV)
		return 0;

	if (!h1_recv_allowed(h1c)) {
		if (h1c->h1s && b_data(&h1c->h1s->rxbuf))
			rcvd = 1;
		goto end;
	}

	if (h1c->h1s && (h1c->h1s->flags & H1S_F_BUF_FLUSH)) {
		rcvd = 1;
		goto end;
	}

	if (!h1_get_buf(h1c, &h1c->ibuf)) {
		h1c->flags |= H1C_F_IN_ALLOC;
		goto end;
	}

	ret = 0;
	max = b_room(&h1c->ibuf);
	if (max) {
		h1c->flags &= ~H1C_F_IN_FULL;
		ret = conn->xprt->rcv_buf(conn, &h1c->ibuf, max, 0);
	}
	if (ret > 0)
		rcvd = 1;

	if (h1_recv_allowed(h1c))
		conn->xprt->subscribe(conn, SUB_CAN_RECV, &h1c->wait_event);

  end:
	if (!b_data(&h1c->ibuf))
		h1_release_buf(h1c, &h1c->ibuf);
	else if (b_full(&h1c->ibuf))
		h1c->flags |= H1C_F_IN_FULL;
	return rcvd;
}


/*
 * Try to send data if possible
 */
static int h1_send(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	unsigned int flags = 0;
	size_t ret;
	int sent = 0;

	if (conn->flags & CO_FL_ERROR)
		return 0;

	if (h1c->flags & H1C_F_CS_WAIT_CONN) {
		if (!(h1c->wait_event.wait_reason & SUB_CAN_SEND))
			conn->xprt->subscribe(conn, SUB_CAN_SEND, &h1c->wait_event);
		return 0;
	}

	if (!b_data(&h1c->obuf))
		goto end;

	if (h1c->flags & H1C_F_OUT_FULL)
		flags |= CO_SFL_MSG_MORE;

	ret = conn->xprt->snd_buf(conn, &h1c->obuf, b_data(&h1c->obuf), flags);
	if (ret > 0) {
		h1c->flags &= ~H1C_F_OUT_FULL;
		b_del(&h1c->obuf, ret);
		sent = 1;

		if (h1c->h1s && h1c->h1s->send_wait) {
			h1c->h1s->send_wait->wait_reason &= ~SUB_CAN_SEND;
			tasklet_wakeup(h1c->h1s->send_wait->task);
			h1c->h1s->send_wait = NULL;
		}
	}

  end:
	/* We're done, no more to send */
	if (!b_data(&h1c->obuf)) {
		h1_release_buf(h1c, &h1c->obuf);
		h1_sync_messages(h1c);
		if (h1c->flags & H1C_F_CS_SHUTW_NOW)
			h1_shutw_conn(conn);
	}
	else if (!(h1c->wait_event.wait_reason & SUB_CAN_SEND))
		conn->xprt->subscribe(conn, SUB_CAN_SEND, &h1c->wait_event);

	return sent;
}


static void h1_wake_stream(struct h1c *h1c)
{
	struct connection *conn = h1c->conn;
	struct h1s *h1s = h1c->h1s;
	uint32_t flags = 0;
	int dont_wake = 0;

	if (!h1s || !h1s->cs)
		return;

	if ((h1c->flags & H1C_F_CS_ERROR) || (conn->flags & CO_FL_ERROR))
		flags |= CS_FL_ERROR;
	if (conn_xprt_read0_pending(conn))
		flags |= CS_FL_REOS;

	h1s->cs->flags |= flags;
	if (h1s->recv_wait) {
		h1s->recv_wait->wait_reason &= ~SUB_CAN_RECV;
		tasklet_wakeup(h1s->recv_wait->task);
		h1s->recv_wait = NULL;
		dont_wake = 1;
	}
	if (h1s->send_wait) {
		h1s->send_wait->wait_reason &= ~SUB_CAN_SEND;
		tasklet_wakeup(h1s->send_wait->task);
		h1s->send_wait = NULL;
		dont_wake = 1;
	}
	if (!dont_wake && h1s->cs->data_cb->wake)
		h1s->cs->data_cb->wake(h1s->cs);
}

/* callback called on any event by the connection handler.
 * It applies changes and returns zero, or < 0 if it wants immediate
 * destruction of the connection.
 */
static int h1_process(struct h1c * h1c)
{
	struct connection *conn = h1c->conn;

	if (b_data(&h1c->ibuf) && !(h1c->flags & (H1C_F_CS_ERROR|H1C_F_RX_FULL|H1C_F_RX_ALLOC))) {
		size_t ret;

		ret = h1_process_input(h1c, &h1c->ibuf, b_data(&h1c->ibuf));
		if (ret > 0) {
			h1c->flags &= ~H1C_F_IN_FULL;
			if (!b_data(&h1c->ibuf))
				h1_release_buf(h1c, &h1c->ibuf);
		}
	}

	h1_send(h1c);

	if (!conn->mux_ctx)
		return -1;

	if (h1c->flags & H1C_F_CS_WAIT_CONN) {
		if (conn->flags & (CO_FL_CONNECTED|CO_FL_ERROR)) {
			h1c->flags &= ~H1C_F_CS_WAIT_CONN;
			h1_wake_stream(h1c);
		}
		return 0;
	}

	if ((h1c->flags & H1C_F_CS_ERROR) || (conn->flags & CO_FL_ERROR) || conn_xprt_read0_pending(conn)) {
		h1_wake_stream(h1c);
		if (!h1c->h1s || !h1c->h1s->cs) {
			h1_release(conn);
			return -1;
		}
	}

	/* If there is a stream attached to the mux, let it
	 * handle the timeout.
	 */
	if (h1c->h1s && h1c->h1s->cs)
		h1c->idle_exp = TICK_ETERNITY;
	else {
		int tout = (!conn_is_back(conn)
			    ? h1c->px->timeout.client
			    : h1c->px->timeout.server);
		h1c->idle_exp = tick_add_ifset(now_ms, tout);
	}
	h1c->task->expire = tick_first(h1c->http_exp, h1c->idle_exp);
	if (tick_isset(h1c->task->expire))
		task_queue(h1c->task);
	return 0;
}

static struct task *h1_io_cb(struct task *t, void *ctx, unsigned short status)
{
	struct h1c *h1c = ctx;
	int ret = 0;

	if (!(h1c->wait_event.wait_reason & SUB_CAN_SEND))
		ret = h1_send(h1c);
	if (!(h1c->wait_event.wait_reason & SUB_CAN_RECV))
		ret |= h1_recv(h1c);
	if (ret || b_data(&h1c->ibuf) || (h1c->h1s && b_data(&h1c->h1s->rxbuf)))
		h1_process(h1c);
	return NULL;
}


static int h1_wake(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	//return 0;
	return (h1_process(h1c));
}


/* Connection timeout management. The principle is that if there's no receipt
 * nor sending for a certain amount of time, the connection is closed.
 */
static struct task *h1_timeout_task(struct task *t, void *context, unsigned short state)
{
	struct h1c *h1c = context;
	int expired = tick_is_expired(t->expire, now_ms);

	if (!h1c)
		goto end;

	if (!expired) {
		t->expire = tick_first(t->expire, tick_first(h1c->idle_exp, h1c->http_exp));
		return t;
	}

	h1c->flags   |= H1C_F_CS_ERROR;
	h1c->idle_exp = TICK_ETERNITY;
	h1c->http_exp = TICK_ETERNITY;
	t->expire     = TICK_ETERNITY;

	/* Don't try send error message on the server-side */
	if (conn_is_back(h1c->conn))
		goto release;

	/* Don't send error message if no input data is pending _AND_ if null
	 * requests is ignored or it's not the first request.
	 */
	if (!b_data(&h1c->ibuf) && (h1c->px->options & PR_O_IGNORE_PRB ||
				    h1c->flags & H1C_F_WAIT_NEXT_REQ))
		goto release;

	/* Try to allocate output buffer to store the error message. If
	 * allocation fails, just go away.
	 */
	if (!h1_get_buf(h1c, &h1c->obuf))
		goto release;

	// FIXME: Do the following:
	//
	//  * Do same than stream_inc_http_req_ctr,
	//    stream_inc_http_err_ctr and proxy_inc_fe_req_ctr
	//  * Capture bad message for snapshots
	//  * Increment fe->fe_counters.failed_req and
	//    listeners->counters->failed_req
	h1_cpy_error_message(h1c, &h1c->obuf, 408);
	tasklet_wakeup(h1c->wait_event.task);
	sess_log(h1c->conn->owner);
	return t;

  release:
	if (h1c->h1s) {
		tasklet_wakeup(h1c->wait_event.task);
		return t;
	}
	h1c->task = NULL;
	h1_release(h1c->conn);
  end:
	task_delete(t);
	task_free(t);
	return NULL;
}

/*******************************************/
/* functions below are used by the streams */
/*******************************************/
/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *h1_attach(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;
	struct conn_stream *cs = NULL;
	struct h1s *h1s;

	if (h1c->flags & H1C_F_CS_ERROR)
		goto end;

	cs = cs_new(h1c->conn);
	if (!cs)
		goto end;

	h1s = h1s_create(h1c, cs);
	if (h1s == NULL)
		goto end;

	return cs;
  end:
	cs_free(cs);
	return NULL;
}

/* Retrieves a valid conn_stream from this connection, or returns NULL. For
 * this mux, it's easy as we can only store a single conn_stream.
 */
static const struct conn_stream *h1_get_first_cs(const struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;
	struct h1s *h1s = h1c->h1s;

	if (h1s)
		return h1s->cs;

	return NULL;
}

static void h1_destroy(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	if (!h1c->h1s)
		h1_release(conn);
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void h1_detach(struct conn_stream *cs)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;

	cs->ctx = NULL;
	if (!h1s)
		return;

	h1c = h1s->h1c;
	h1s->cs = NULL;

	h1s_destroy(h1s);

	/* We don't want to close right now unless the connection is in error */
	if ((h1c->flags & (H1C_F_CS_ERROR|H1C_F_CS_SHUTW)) ||
	    (h1c->conn->flags & CO_FL_ERROR))
		h1_release(h1c->conn);
	else
		tasklet_wakeup(h1c->wait_event.task);
}


static void h1_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return;

	if ((h1s->flags & H1S_F_WANT_KAL) && !(cs->flags & (CS_FL_REOS|CS_FL_EOS)))
		return;

	/* NOTE: Be sure to handle abort (cf. h2_shutr) */
	if (cs->flags & CS_FL_SHR)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutr)
		cs->conn->xprt->shutr(cs->conn, (mode == CS_SHR_DRAIN));
	if (cs->flags & CS_FL_SHW) {
		h1s->h1c->flags = (h1s->h1c->flags & ~H1C_F_CS_SHUTW_NOW) | H1C_F_CS_SHUTW;
		conn_full_close(cs->conn);
	}
}

static void h1_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;

	if (!h1s)
		return;
	h1c = h1s->h1c;

	if ((h1s->flags & H1S_F_WANT_KAL) &&
	    !(cs->flags & (CS_FL_REOS|CS_FL_EOS)) &&
	    h1s->req.state == H1_MSG_DONE && h1s->res.state == H1_MSG_DONE)
		return;

	h1c->flags |= H1C_F_CS_SHUTW_NOW;
	if ((cs->flags & CS_FL_SHW) || b_data(&h1c->obuf))
		return;

	h1_shutw_conn(cs->conn);
}

static void h1_shutw_conn(struct connection *conn)
{
	struct h1c *h1c = conn->mux_ctx;

	if (conn_xprt_ready(conn) && conn->xprt->shutw)
		conn->xprt->shutw(conn, 1);
	if (!(conn->flags & CO_FL_SOCK_RD_SH))
		conn_sock_shutw(conn, 1);
	else {
		h1c->flags = (h1c->flags & ~H1C_F_CS_SHUTW_NOW) | H1C_F_CS_SHUTW;
		conn_full_close(conn);
	}
}

/* Called from the upper layer, to unsubscribe to events */
static int h1_unsubscribe(struct conn_stream *cs, int event_type, void *param)
{
	struct wait_event *sw;
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return 0;

	if (event_type & SUB_CAN_RECV) {
		sw = param;
		if (h1s->recv_wait == sw) {
			sw->wait_reason &= ~SUB_CAN_RECV;
			h1s->recv_wait = NULL;
		}
	}
	if (event_type & SUB_CAN_SEND) {
		sw = param;
		if (h1s->send_wait == sw) {
			sw->wait_reason &= ~SUB_CAN_SEND;
			h1s->send_wait = NULL;
		}
	}
	return 0;
}

/* Called from the upper layer, to subscribe to events, such as being able to send */
static int h1_subscribe(struct conn_stream *cs, int event_type, void *param)
{
	struct wait_event *sw;
	struct h1s *h1s = cs->ctx;

	if (!h1s)
		return -1;

	switch (event_type) {
		case SUB_CAN_RECV:
			sw = param;
			if (!(sw->wait_reason & SUB_CAN_RECV)) {
				sw->wait_reason |= SUB_CAN_RECV;
				sw->handle = h1s;
				h1s->recv_wait = sw;
			}
			return 0;
		case SUB_CAN_SEND:
			sw = param;
			if (!(sw->wait_reason & SUB_CAN_SEND)) {
				sw->wait_reason |= SUB_CAN_SEND;
				sw->handle = h1s;
				h1s->send_wait = sw;
			}
			return 0;
		default:
			break;
	}
	return -1;
}

/* Called from the upper layer, to receive data */
static size_t h1_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h1s *h1s = cs->ctx;
	size_t ret = 0;

	if (!h1s)
		return ret;

	if (!(h1s->h1c->flags & H1C_F_RX_ALLOC))
		ret = h1_xfer(h1s, buf, flags);

	if (flags & CO_RFL_BUF_FLUSH)
		h1s->flags |= H1S_F_BUF_FLUSH;
	else if (ret > 0 || (h1s->flags & H1S_F_BUF_FLUSH)) {
		h1s->flags &= ~H1S_F_BUF_FLUSH;
		if (!(h1s->h1c->wait_event.wait_reason & SUB_CAN_RECV))
			tasklet_wakeup(h1s->h1c->wait_event.task);
	}
	return ret;
}


/* Called from the upper layer, to send data */
static size_t h1_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	struct h1s *h1s = cs->ctx;
	struct h1c *h1c;
	size_t ret = 0;

	if (!h1s)
		return ret;

	h1c = h1s->h1c;

	if (h1c->flags & H1C_F_CS_WAIT_CONN)
		return 0;

	if (!(h1c->flags & (H1C_F_OUT_FULL|H1C_F_OUT_ALLOC)) && b_data(buf))
		ret = h1_process_output(h1c, buf, count);
	if (ret > 0) {
		h1_send(h1c);

		/* We need to do that because of the infinite forwarding. */
		if (!b_data(buf))
			ret = count;
	}
	return ret;
}

#if defined(CONFIG_HAP_LINUX_SPLICE)
/* Send and get, using splicing */
static int h1_rcv_pipe(struct conn_stream *cs, struct pipe *pipe, unsigned int count)
{
	struct h1s *h1s = cs->ctx;
	struct h1m *h1m = (!conn_is_back(cs->conn) ? &h1s->req : &h1s->res);
	int ret = 0;

	if (b_data(&h1s->rxbuf) || b_data(&h1s->h1c->ibuf))
		goto end;
	if (h1m->state == H1_MSG_DATA && count > h1m->curr_len)
		count = h1m->curr_len;
	ret = cs->conn->xprt->rcv_pipe(cs->conn, pipe, count);
	if (h1m->state == H1_MSG_DATA && ret > 0)
		h1m->curr_len -= ret;
  end:
	return ret;

}

static int h1_snd_pipe(struct conn_stream *cs, struct pipe *pipe)
{
	struct h1s *h1s = cs->ctx;
	struct h1m *h1m = (!conn_is_back(cs->conn) ? &h1s->res : &h1s->req);
	int ret = 0;

	if (b_data(&h1s->h1c->obuf))
		goto end;

	ret = cs->conn->xprt->snd_pipe(cs->conn, pipe);
	if (h1m->state == H1_MSG_DATA && ret > 0)
		h1m->curr_len -= ret;
  end:
	return ret;
}
#endif

/****************************************/
/* MUX initialization and instanciation */
/****************************************/

/* The mux operations */
const struct mux_ops mux_h1_ops = {
	.init        = h1_init,
	.wake        = h1_wake,
	.attach      = h1_attach,
	.get_first_cs = h1_get_first_cs,
	.detach      = h1_detach,
	.destroy     = h1_destroy,
	.avail_streams = h1_avail_streams,
	.rcv_buf     = h1_rcv_buf,
	.snd_buf     = h1_snd_buf,
#if defined(CONFIG_HAP_LINUX_SPLICE)
	.rcv_pipe    = h1_rcv_pipe,
	.snd_pipe    = h1_snd_pipe,
#endif
	.subscribe   = h1_subscribe,
	.unsubscribe = h1_unsubscribe,
	.shutr       = h1_shutr,
	.shutw       = h1_shutw,
	.flags       = MX_FL_NONE,
	.name        = "h1",
};


/* this mux registers default HTX proto */
static struct mux_proto_list mux_proto_htx =
{ .token = IST(""), .mode = PROTO_MODE_HTX, .side = PROTO_SIDE_BOTH, .mux = &mux_h1_ops };

static void __h1_deinit(void)
{
	pool_destroy(pool_head_h1c);
	pool_destroy(pool_head_h1s);
}

__attribute__((constructor))
static void __h1_init(void)
{
	register_mux_proto(&mux_proto_htx);
	hap_register_post_deinit(__h1_deinit);
	pool_head_h1c = create_pool("h1c", sizeof(struct h1c), MEM_F_SHARED);
	pool_head_h1s = create_pool("h1s", sizeof(struct h1s), MEM_F_SHARED);
}
/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
