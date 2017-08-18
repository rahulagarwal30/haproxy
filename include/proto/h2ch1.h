/*
 * include/proto/h2ch1.h
 * This file contains HTTP/2 protocol definitions.
 *
 * Copyright (C) 2000-2017 Willy Tarreau - w@1wt.eu
 * Copyright 2017 HAProxy Technologies
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

#ifndef _PROTO_H2CH1_H
#define _PROTO_H2CH1_H

#include <common/config.h>
#include <types/h2common.h>
#include <types/h2ch1.h>
#include <types/stream.h>
#include <proto/channel.h>

#if defined(DEBUG_H2)
#define h2_fprintf fprintf
#define h2_hexdump debug_hexdump
#else
#define h2_fprintf(...) do { } while (0)
#define h2_hexdump(...) do { } while (0)
#endif

/* human-readable stream and connection state names */
extern const char *h2_cs_strings[H2_CS_ENTRIES];
extern const char *h2_ss_strings[H2_SS_ENTRIES];

/* dummy streams returned for idle and closed states */
extern const struct h2s *h2_closed_streams[4];
extern const struct h2s *h2_idle_stream;

int h2c_frt_init(struct stream *s);

/* returns a const string giving the name of connection state <state> */
static inline const char *h2_cs_str(int state)
{
	if (state >= H2_CS_ENTRIES)
		return "_UNKNOWN_";
	return h2_cs_strings[state];
}

/* returns a const string giving the name of stream state <state> */
static inline const char *h2_ss_str(int state)
{
	if (state >= H2_SS_ENTRIES)
		return "_UNKNOWN_";
	return h2_ss_strings[state];
}

/* returns true of the mux is currently busy */
static inline int h2c_mux_busy(const struct h2c *h2c)
{
	return h2c->msi >= 0;
}

/* sets the h2 connection to error state with the accompanying error code */
static inline void h2c_error(struct h2c *h2c, enum h2_err err)
{
	h2c->errcode = err;
	h2c->appctx->st0 = H2_CS_ERROR;
}

/* returns the stream associated with id <id> or NULL if not found */
static inline struct h2s *h2c_st_by_id(struct h2c *h2c, int id)
{
	struct eb32_node *node;
	struct h2s *h2s;

	if (id > h2c->max_id)
		return (struct h2s *)h2_idle_stream;

	node = eb32_lookup(&h2c->streams_by_id, id);
	if (!node)
		return (struct h2s *)h2_closed_streams[0];

	h2s = container_of(node, struct h2s, by_id);

	/* TEMP DEBUGGING CODE */
	if (h2s->id != id)
		fprintf(stderr, "%s:%d(%s): BUG!: h2c=%p id=%d ret=%p id=%d\n", __FILE__, __LINE__, __FUNCTION__, h2c, id, h2s, id);
	/* /DEBUG */

	return h2s;
}

/* initializes an H2 message */
static inline struct h2m *h2m_init(struct h2m *h2m, struct channel *chn)
{
	h2m->state = H2_MS_HDR0;
	h2m->flags = 0;
	h2m->curr_len = 0;
	h2m->body_len = 0;
	h2m->err_pos = 0;
	h2m->err_state = 0;
	h2m->chn = chn;
	return h2m;
}

#endif /* _PROTO_H2CH1_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
