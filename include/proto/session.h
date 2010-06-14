/*
 * include/proto/session.h
 * This file defines everything related to sessions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_SESSION_H
#define _PROTO_SESSION_H

#include <common/config.h>
#include <common/memory.h>
#include <types/session.h>
#include <proto/stick_table.h>

extern struct pool_head *pool2_session;
extern struct list sessions;

int session_accept(struct listener *l, int cfd, struct sockaddr_storage *addr);
void session_free(struct session *s);

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_session();

void session_process_counters(struct session *s);
void sess_change_server(struct session *sess, struct server *newsrv);
struct task *process_session(struct task *t);
void sess_set_term_flags(struct session *s);
void default_srv_error(struct session *s, struct stream_interface *si);
int parse_track_counters(char **args, int *arg,
			 int section_type, struct proxy *curpx,
			 struct track_ctr_prm *prm,
			 struct proxy *defpx, char *err, int errlen);

/* Remove the refcount from the session to the tracked counters, and clear the
 * pointer to ensure this is only performed once. The caller is responsible for
 * ensuring that the pointer is valid first.
 */
static inline void session_store_counters(struct session *s)
{
	s->tracked_counters->ref_cnt--;
	s->tracked_counters = NULL;
}

/* Enable tracking of session counters on stksess <ts>. The caller is
 * responsible for ensuring that <t> and <ts> are valid pointers and that no
 * previous tracked_counters was assigned to the session.
 */
static inline void session_track_counters(struct session *s, struct stktable *t, struct stksess *ts)
{
	ts->ref_cnt++;
	s->tracked_table = t;
	s->tracked_counters = ts;
}

static void inline trace_term(struct session *s, unsigned int code)
{
	s->term_trace <<= TT_BIT_SHIFT;
	s->term_trace |= code;
}

#endif /* _PROTO_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
