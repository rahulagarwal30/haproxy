/*
 * include/proto/connection.h
 * This file contains connection function prototypes
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_CONNECTION_H
#define _PROTO_CONNECTION_H

#include <common/config.h>
#include <types/connection.h>

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops. Returns 0.
 */
int conn_fd_handler(int fd);

/* Calls the close() function of the data layer if any */
static inline void conn_data_close(struct connection *conn)
{
	if (conn->data && conn->data->close)
		conn->data->close(conn);
}

/* Calls the snd_buf() function of the data layer if any, otherwise
 * returns 0.
 */
static inline int conn_data_snd_buf(struct connection *conn)
{
	if (!conn->data->snd_buf)
		return 0;
	return conn->data->snd_buf(conn);
}

/* set polling depending on the change between the CURR part of the
 * flags and the new flags in connection C. The connection flags are
 * updated with the new flags at the end of the operation. Only the bits
 * relevant to CO_FL_CURR_* from <flags> are considered.
 */
void conn_set_polling(struct connection *c, unsigned int new);

/* update polling depending on the change between the CURR part of the
 * flags and the DATA part of the flags in connection C. The connection
 * is assumed to already be in the data phase.
 */
static inline void conn_update_data_polling(struct connection *c)
{
	conn_set_polling(c, c->flags << 8);
}

/* update polling depending on the change between the CURR part of the
 * flags and the SOCK part of the flags in connection C. The connection
 * is assumed to already be in the handshake phase.
 */
static inline void conn_update_sock_polling(struct connection *c)
{
	conn_set_polling(c, c->flags << 4);
}

/* returns non-zero if data flags from c->flags changes from what is in the
 * current section of c->flags.
 */
static inline unsigned int conn_data_polling_changes(const struct connection *c)
{
	return ((c->flags << 8) ^ c->flags) & 0xF0000000;
}

/* returns non-zero if sock flags from c->flags changes from what is in the
 * current section of c->flags.
 */
static inline unsigned int conn_sock_polling_changes(const struct connection *c)
{
	return ((c->flags << 4) ^ c->flags) & 0xF0000000;
}

/* Automatically updates polling on connection <c> depending on the DATA flags
 * if no handshake is in progress.
 */
static inline void conn_cond_update_data_polling(struct connection *c)
{
	if (!(c->flags & CO_FL_POLL_SOCK) && conn_data_polling_changes(c))
		conn_update_data_polling(c);
}

/* Automatically updates polling on connection <c> depending on the SOCK flags
 * if a handshake is in progress.
 */
static inline void conn_cond_update_sock_polling(struct connection *c)
{
	if ((c->flags & CO_FL_POLL_SOCK) && conn_sock_polling_changes(c))
		conn_update_sock_polling(c);
}

/* Automatically update polling on connection <c> depending on the DATA and
 * SOCK flags, and on whether a handshake is in progress or not. This may be
 * called at any moment when there is a doubt about the effectiveness of the
 * polling state, for instance when entering or leaving the handshake state.
 */
static inline void conn_cond_update_polling(struct connection *c)
{
	if (!(c->flags & CO_FL_POLL_SOCK) && conn_data_polling_changes(c))
		conn_update_data_polling(c);
	else if ((c->flags & CO_FL_POLL_SOCK) && conn_sock_polling_changes(c))
		conn_update_sock_polling(c);
}

/***** Event manipulation primitives for use by DATA I/O callbacks *****/
/* The __conn_* versions do not propagate to lower layers and are only meant
 * to be used by handlers called by the connection handler. The other ones
 * may be used anywhere.
 */
static inline void __conn_data_want_recv(struct connection *c)
{
	c->flags |= CO_FL_DATA_RD_ENA;
}

static inline void __conn_data_stop_recv(struct connection *c)
{
	c->flags &= ~CO_FL_DATA_RD_ENA;
}

static inline void __conn_data_poll_recv(struct connection *c)
{
	c->flags |= CO_FL_DATA_RD_POL | CO_FL_DATA_RD_ENA;
}

static inline void __conn_data_want_send(struct connection *c)
{
	c->flags |= CO_FL_DATA_WR_ENA;
}

static inline void __conn_data_stop_send(struct connection *c)
{
	c->flags &= ~CO_FL_DATA_WR_ENA;
}

static inline void __conn_data_poll_send(struct connection *c)
{
	c->flags |= CO_FL_DATA_WR_POL | CO_FL_DATA_WR_ENA;
}

static inline void __conn_data_stop_both(struct connection *c)
{
	c->flags &= ~(CO_FL_DATA_WR_ENA | CO_FL_DATA_RD_ENA);
}

static inline void conn_data_want_recv(struct connection *c)
{
	__conn_data_want_recv(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_stop_recv(struct connection *c)
{
	__conn_data_stop_recv(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_poll_recv(struct connection *c)
{
	__conn_data_poll_recv(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_want_send(struct connection *c)
{
	__conn_data_want_send(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_stop_send(struct connection *c)
{
	__conn_data_stop_send(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_poll_send(struct connection *c)
{
	__conn_data_poll_send(c);
	conn_cond_update_data_polling(c);
}

static inline void conn_data_stop_both(struct connection *c)
{
	__conn_data_stop_both(c);
	conn_cond_update_data_polling(c);
}

/***** Event manipulation primitives for use by handshake I/O callbacks *****/
/* The __conn_* versions do not propagate to lower layers and are only meant
 * to be used by handlers called by the connection handler. The other ones
 * may be used anywhere.
 */
static inline void __conn_sock_want_recv(struct connection *c)
{
	c->flags |= CO_FL_SOCK_RD_ENA;
}

static inline void __conn_sock_stop_recv(struct connection *c)
{
	c->flags &= ~CO_FL_SOCK_RD_ENA;
}

static inline void __conn_sock_poll_recv(struct connection *c)
{
	c->flags |= CO_FL_SOCK_RD_POL | CO_FL_SOCK_RD_ENA;
}

static inline void __conn_sock_want_send(struct connection *c)
{
	c->flags |= CO_FL_SOCK_WR_ENA;
}

static inline void __conn_sock_stop_send(struct connection *c)
{
	c->flags &= ~CO_FL_SOCK_WR_ENA;
}

static inline void __conn_sock_poll_send(struct connection *c)
{
	c->flags |= CO_FL_SOCK_WR_POL | CO_FL_SOCK_WR_ENA;
}

static inline void __conn_sock_stop_both(struct connection *c)
{
	c->flags &= ~(CO_FL_SOCK_WR_ENA | CO_FL_SOCK_RD_ENA);
}

static inline void conn_sock_want_recv(struct connection *c)
{
	__conn_sock_want_recv(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_stop_recv(struct connection *c)
{
	__conn_sock_stop_recv(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_poll_recv(struct connection *c)
{
	__conn_sock_poll_recv(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_want_send(struct connection *c)
{
	__conn_sock_want_send(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_stop_send(struct connection *c)
{
	__conn_sock_stop_send(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_poll_send(struct connection *c)
{
	__conn_sock_poll_send(c);
	conn_cond_update_sock_polling(c);
}

static inline void conn_sock_stop_both(struct connection *c)
{
	__conn_sock_stop_both(c);
	conn_cond_update_sock_polling(c);
}

#endif /* _PROTO_CONNECTION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
