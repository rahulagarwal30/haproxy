/*
 * Pass-through mux-demux for connections
 *
 * Copyright 2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <proto/connection.h>
#include <proto/stream.h>

/* Initialize the mux once it's attached. It is expected that conn->mux_ctx
 * points to the existing conn_stream (for outgoing connections) or NULL (for
 * incoming ones, in which case one will be allocated and a new stream will be
 * instanciated). Returns < 0 on error.
 */
static int mux_pt_init(struct connection *conn, struct proxy *prx)
{
	struct conn_stream *cs = conn->mux_ctx;

	if (!cs) {
		cs = cs_new(conn);
		if (!cs)
			goto fail;

		if (stream_create_from_cs(cs) < 0)
			goto fail_free;

		conn->mux_ctx = cs;
	}
	return 0;

 fail_free:
	cs_free(cs);
 fail:
	return -1;
}

/* callback to be used by default for the pass-through mux. It calls the data
 * layer wake() callback if it is set otherwise returns 0.
 */
static int mux_pt_wake(struct connection *conn)
{
	struct conn_stream *cs = conn->mux_ctx;
	int ret;

	ret = cs->data_cb->wake ? cs->data_cb->wake(cs) : 0;

	if (ret < 0)
		return ret;

	/* If we had early data, and we're done with the handshake
	 * then whe know the data are safe, and we can remove the flag.
	 */
	if ((conn->flags & (CO_FL_EARLY_DATA | CO_FL_EARLY_SSL_HS | CO_FL_HANDSHAKE)) ==
	    CO_FL_EARLY_DATA)
		conn->flags &= ~CO_FL_EARLY_DATA;
	if (ret >= 0)
		cs_update_mux_polling(cs);
	return ret;
}

/* callback used to update the mux's polling flags after changing a cs' status.
 * The caller (cs_mux_update_poll) will take care of propagating any changes to
 * the transport layer.
 */
static void mux_pt_update_poll(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	int flags = 0;

	conn_refresh_polling_flags(conn);

	if (cs->flags & CS_FL_DATA_RD_ENA)
		flags |= CO_FL_XPRT_RD_ENA;
	if (cs->flags & CS_FL_DATA_WR_ENA)
		flags |= CO_FL_XPRT_WR_ENA;

	conn->flags = (conn->flags & ~(CO_FL_XPRT_RD_ENA | CO_FL_XPRT_WR_ENA)) | flags;
	conn_cond_update_xprt_polling(conn);
}

/*
 * Attach a new stream to a connection
 * (Used for outgoing connections)
 */
static struct conn_stream *mux_pt_attach(struct connection *conn)
{
	return NULL;
}

/*
 * Detach the stream from the connection and possibly release the connection.
 */
static void mux_pt_detach(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;

	LIST_DEL(&conn->list);
	conn_stop_tracking(conn);
	conn_full_close(conn);
	if (conn->destroy_cb)
		conn->destroy_cb(conn);
	conn_free(conn);
}

static void mux_pt_shutr(struct conn_stream *cs, enum cs_shr_mode mode)
{
	if (cs->flags & CS_FL_SHR)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutr)
		cs->conn->xprt->shutr(cs->conn, (mode == CS_SHR_DRAIN));
	if (cs->flags & CS_FL_SHW)
		conn_full_close(cs->conn);
}

static void mux_pt_shutw(struct conn_stream *cs, enum cs_shw_mode mode)
{
	if (cs->flags & CS_FL_SHW)
		return;
	if (conn_xprt_ready(cs->conn) && cs->conn->xprt->shutw)
		cs->conn->xprt->shutw(cs->conn, (mode == CS_SHW_NORMAL));
	if (!(cs->flags & CS_FL_SHR))
		conn_sock_shutw(cs->conn, (mode == CS_SHW_NORMAL));
	else
		conn_full_close(cs->conn);
}

/*
 * Called from the upper layer, to get more data
 */
static size_t mux_pt_rcv_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	size_t ret;

	ret = cs->conn->xprt->rcv_buf(cs->conn, buf, count, flags);
	if (conn_xprt_read0_pending(cs->conn))
		cs->flags |= CS_FL_EOS;
	if (cs->conn->flags & CO_FL_ERROR)
		cs->flags |= CS_FL_ERROR;
	return ret;
}

/* Called from the upper layer, to send data */
static size_t mux_pt_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	size_t ret = cs->conn->xprt->snd_buf(cs->conn, buf, count, flags);

	if (ret > 0)
		b_del(buf, ret);
	return ret;
}

/* Called from the upper layer, to subscribe to events */
static int mux_pt_subscribe(struct conn_stream *cs, int event_type, void *param)
{
	return (cs->conn->xprt->subscribe(cs->conn, event_type, param));
}

#if defined(CONFIG_HAP_LINUX_SPLICE)
/* Send and get, using splicing */
static int mux_pt_rcv_pipe(struct conn_stream *cs, struct pipe *pipe, unsigned int count)
{
	int ret;

	ret = cs->conn->xprt->rcv_pipe(cs->conn, pipe, count);
	if (conn_xprt_read0_pending(cs->conn))
		cs->flags |= CS_FL_EOS;
	if (cs->conn->flags & CO_FL_ERROR)
		cs->flags |= CS_FL_ERROR;
	return (ret);
}

static int mux_pt_snd_pipe(struct conn_stream *cs, struct pipe *pipe)
{
	return (cs->conn->xprt->snd_pipe(cs->conn, pipe));
}
#endif

/* The mux operations */
const struct mux_ops mux_pt_ops = {
	.init = mux_pt_init,
	.wake = mux_pt_wake,
	.update_poll = mux_pt_update_poll,
	.rcv_buf = mux_pt_rcv_buf,
	.snd_buf = mux_pt_snd_buf,
	.subscribe = mux_pt_subscribe,
#if defined(CONFIG_HAP_LINUX_SPLICE)
	.rcv_pipe = mux_pt_rcv_pipe,
	.snd_pipe = mux_pt_snd_pipe,
#endif
	.attach = mux_pt_attach,
	.detach = mux_pt_detach,
	.shutr = mux_pt_shutr,
	.shutw = mux_pt_shutw,
	.flags = MX_FL_NONE,
	.name = "PASS",
};

/* PROT selection : default mux has empty name */
static struct mux_proto_list mux_proto_pt =
	{ .token = IST(""), .mode = PROTO_MODE_ANY, .side = PROTO_SIDE_BOTH, .mux = &mux_pt_ops };

__attribute__((constructor))
static void __mux_pt_init(void)
{
	register_mux_proto(&mux_proto_pt);
}
