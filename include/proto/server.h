/*
 * include/proto/server.h
 * This file defines everything related to servers.
 *
 * Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_SERVER_H
#define _PROTO_SERVER_H

#include <unistd.h>

#include <common/config.h>
#include <common/time.h>
#include <types/proxy.h>
#include <types/queue.h>
#include <types/server.h>

#include <proto/queue.h>
#include <proto/log.h>
#include <proto/freq_ctr.h>

int srv_downtime(const struct server *s);
int srv_lastsession(const struct server *s);
int srv_getinter(const struct check *check);
int parse_server(const char *file, int linenum, char **args, struct proxy *curproxy, struct proxy *defproxy);

/* increase the number of cumulated connections on the designated server */
static void inline srv_inc_sess_ctr(struct server *s)
{
	s->counters.cum_sess++;
	update_freq_ctr(&s->sess_per_sec, 1);
	if (s->sess_per_sec.curr_ctr > s->counters.sps_max)
		s->counters.sps_max = s->sess_per_sec.curr_ctr;
}

/* set the time of last session on the designated server */
static void inline srv_set_sess_last(struct server *s)
{
	s->counters.last_sess = now.tv_sec;
}

#endif /* _PROTO_SERVER_H */

/*
 * Registers the server keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void srv_register_keywords(struct srv_kw_list *kwl);

/* Return a pointer to the server keyword <kw>, or NULL if not found. */
struct srv_kw *srv_find_kw(const char *kw);

/* Dumps all registered "server" keywords to the <out> string pointer. */
void srv_dump_kws(char **out);

/* Recomputes the server's eweight based on its state, uweight, the current time,
 * and the proxy's algorihtm. To be used after updating sv->uweight. The warmup
 * state is automatically disabled if the time is elapsed.
 */
void server_recalc_eweight(struct server *sv);

/* returns the current server throttle rate between 0 and 100% */
static inline unsigned int server_throttle_rate(struct server *sv)
{
	struct proxy *px = sv->proxy;

	/* when uweight is 0, we're in soft-stop so that cannot be a slowstart,
	 * thus the throttle is 100%.
	 */
	if (!sv->uweight)
		return 100;

	return (100U * px->lbprm.wmult * sv->eweight + px->lbprm.wdiv - 1) / (px->lbprm.wdiv * sv->uweight);
}

/*
 * Parses weight_str and configures sv accordingly.
 * Returns NULL on success, error message string otherwise.
 */
const char *server_parse_weight_change_request(struct server *sv,
					       const char *weight_str);

/*
 * Return true if the server has a zero user-weight, meaning it's in draining
 * mode (ie: not taking new non-persistent connections).
 */
static inline int server_is_draining(const struct server *s)
{
	return !s->uweight;
}

/* Shutdown all connections of a server. The caller must pass a termination
 * code in <why>, which must be one of SN_ERR_* indicating the reason for the
 * shutdown.
 */
void srv_shutdown_sessions(struct server *srv, int why);

/* Shutdown all connections of all backup servers of a proxy. The caller must
 * pass a termination code in <why>, which must be one of SN_ERR_* indicating
 * the reason for the shutdown.
 */
void srv_shutdown_backup_sessions(struct proxy *px, int why);

/* Appends some information to a message string related to a server going UP or
 * DOWN.  If both <forced> and <reason> are null and the server tracks another
 * one, a "via" information will be provided to know where the status came from.
 * If <reason> is non-null, the entire string will be appended after a comma and
 * a space (eg: to report some information from the check that changed the state).
 * If <xferred> is non-negative, some information about requeued sessions are
 * provided.
 */
void srv_append_status(struct chunk *msg, struct server *s, const char *reason, int xferred, int forced);

/* Puts server <s> into maintenance mode, and propagate that status down to all
 * tracking servers. This does the same action as the CLI's "disable server x".
 * A log is emitted for all servers that were not yet in maintenance mode.
 * Health checks are disabled but not agent checks. The server is marked as
 * being either forced into maintenance by having <mode> set to SRV_ADMF_FMAINT,
 * or as inheriting the maintenance status by having <mode> set to
 * SRV_ADMF_IMAINT. Nothing is done if neither flag is set.
 */
void srv_adm_set_maint(struct server *s, enum srv_admin mode);

/* Gets server <s> out of maintenance mode, and propagate that status down to
 * all tracking servers. This does the same action as the CLI's "enable server x".
 * A log is emitted for all servers that leave maintenance mode. Health checks
 * are possibly enabled again. The server is marked as leaving forced maintenance
 * when <mode> is set to SRV_ADMF_FMAINT, or as leaving inherited maintenance
 * when <mode> set to SRV_ADMF_IMAINT. Nothing is done if neither flag is set.
 */
void srv_adm_set_ready(struct server *s, enum srv_admin mode);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
