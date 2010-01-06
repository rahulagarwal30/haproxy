/*
 * Functions dedicated to statistics output
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
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
#include <pwd.h>
#include <grp.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/global.h>

#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/checks.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/pipe.h>
#include <proto/proto_uxst.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/server.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

const char stats_sock_usage_msg[] =
	"Unknown command. Please enter one of the following commands only :\n"
	"  clear counters : clear max statistics counters (add 'all' for all counters)\n"
	"  help           : this message\n"
	"  prompt         : toggle interactive mode with prompt\n"
	"  quit           : disconnect\n"
	"  show info      : report information about the running process\n"
	"  show stat      : report counters for each proxy and server\n"
	"  show errors    : report last request and response errors for each proxy\n"
	"  show sess      : report the list of current sessions\n"
	"  get weight     : report a server's current weight\n"
	"  set weight     : change a server's weight\n"
	"";

const char stats_permission_denied_msg[] =
	"Permission denied\n"
	"";

/* This function parses a "stats" statement in the "global" section. It returns
 * -1 if there is any error, otherwise zero. If it returns -1, it may write an
 * error message into ther <err> buffer, for at most <errlen> bytes, trailing
 * zero included. The trailing '\n' must not be written. The function must be
 * called with <args> pointing to the first word after "stats".
 */
static int stats_parse_global(char **args, int section_type, struct proxy *curpx,
			      struct proxy *defpx, char *err, int errlen)
{
	args++;
	if (!strcmp(args[0], "socket")) {
		struct sockaddr_un su;
		int cur_arg;

		if (*args[1] == 0) {
			snprintf(err, errlen, "'stats socket' in global section expects a path to a UNIX socket");
			return -1;
		}

		if (global.stats_sock.state != LI_NEW) {
			snprintf(err, errlen, "'stats socket' already specified in global section");
			return -1;
		}

		su.sun_family = AF_UNIX;
		strncpy(su.sun_path, args[1], sizeof(su.sun_path));
		su.sun_path[sizeof(su.sun_path) - 1] = 0;
		memcpy(&global.stats_sock.addr, &su, sizeof(su)); // guaranteed to fit

		if (!global.stats_fe) {
			if ((global.stats_fe = (struct proxy *)calloc(1, sizeof(struct proxy))) == NULL) {
				snprintf(err, errlen, "out of memory");
				return -1;
			}

			LIST_INIT(&global.stats_fe->pendconns);
			LIST_INIT(&global.stats_fe->acl);
			LIST_INIT(&global.stats_fe->block_cond);
			LIST_INIT(&global.stats_fe->redirect_rules);
			LIST_INIT(&global.stats_fe->mon_fail_cond);
			LIST_INIT(&global.stats_fe->switching_rules);
			LIST_INIT(&global.stats_fe->tcp_req.inspect_rules);

			/* Timeouts are defined as -1, so we cannot use the zeroed area
			 * as a default value.
			 */
			proxy_reset_timeouts(global.stats_fe);

			global.stats_fe->last_change = now.tv_sec;
			global.stats_fe->id = strdup("GLOBAL");
			global.stats_fe->cap = PR_CAP_FE;
		}

		global.stats_sock.state = LI_INIT;
		global.stats_sock.options = LI_O_NONE;
		global.stats_sock.accept = uxst_event_accept;
		global.stats_sock.handler = process_session;
		global.stats_sock.analysers = 0;
		global.stats_sock.nice = -64;  /* we want to boost priority for local stats */
		global.stats_sock.private = global.stats_fe; /* must point to the frontend */
		global.stats_sock.perm.ux.level = ACCESS_LVL_OPER; /* default access level */

		global.stats_fe->timeout.client = MS_TO_TICKS(10000); /* default timeout of 10 seconds */
		global.stats_sock.timeout = &global.stats_fe->timeout.client;

		global.stats_sock.next  = global.stats_fe->listen;
		global.stats_fe->listen = &global.stats_sock;

		cur_arg = 2;
		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "uid")) {
				global.stats_sock.perm.ux.uid = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "gid")) {
				global.stats_sock.perm.ux.gid = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "mode")) {
				global.stats_sock.perm.ux.mode = strtol(args[cur_arg + 1], NULL, 8);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "user")) {
				struct passwd *user;
				user = getpwnam(args[cur_arg + 1]);
				if (!user) {
					snprintf(err, errlen, "unknown user '%s' in 'global' section ('stats user')",
						 args[cur_arg + 1]);
					return -1;
				}
				global.stats_sock.perm.ux.uid = user->pw_uid;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "group")) {
				struct group *group;
				group = getgrnam(args[cur_arg + 1]);
				if (!group) {
					snprintf(err, errlen, "unknown group '%s' in 'global' section ('stats group')",
						 args[cur_arg + 1]);
					return -1;
				}
				global.stats_sock.perm.ux.gid = group->gr_gid;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "level")) {
				if (!strcmp(args[cur_arg+1], "user"))
					global.stats_sock.perm.ux.level = ACCESS_LVL_USER;
				else if (!strcmp(args[cur_arg+1], "operator"))
					global.stats_sock.perm.ux.level = ACCESS_LVL_OPER;
				else if (!strcmp(args[cur_arg+1], "admin"))
					global.stats_sock.perm.ux.level = ACCESS_LVL_ADMIN;
				else {
					snprintf(err, errlen, "'stats socket level' only supports 'user', 'operator', and 'admin'");
					return -1;
				}
				cur_arg += 2;
			}
			else {
				snprintf(err, errlen, "'stats socket' only supports 'user', 'uid', 'group', 'gid', 'level', and 'mode'");
				return -1;
			}
		}

		uxst_add_listener(&global.stats_sock);
		global.maxsock++;
	}
	else if (!strcmp(args[0], "timeout")) {
		unsigned timeout;
		const char *res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);

		if (res) {
			snprintf(err, errlen, "unexpected character '%c' in 'stats timeout' in 'global' section", *res);
			return -1;
		}

		if (!timeout) {
			snprintf(err, errlen, "a positive value is expected for 'stats timeout' in 'global section'");
			return -1;
		}
		global.stats_fe->timeout.client = MS_TO_TICKS(timeout);
	}
	else if (!strcmp(args[0], "maxconn")) {
		int maxconn = atol(args[1]);

		if (maxconn <= 0) {
			snprintf(err, errlen, "a positive value is expected for 'stats maxconn' in 'global section'");
			return -1;
		}
		global.maxsock -= global.stats_sock.maxconn;
		global.stats_sock.maxconn = maxconn;
		global.maxsock += global.stats_sock.maxconn;
	}
	else {
		snprintf(err, errlen, "'stats' only supports 'socket', 'maxconn' and 'timeout' in 'global' section");
		return -1;
	}
	return 0;
}

int print_csv_header(struct chunk *msg)
{
	return chunk_printf(msg,
			    "# pxname,svname,"
			    "qcur,qmax,"
			    "scur,smax,slim,stot,"
			    "bin,bout,"
			    "dreq,dresp,"
			    "ereq,econ,eresp,"
			    "wretr,wredis,"
			    "status,weight,act,bck,"
			    "chkfail,chkdown,lastchg,downtime,qlimit,"
			    "pid,iid,sid,throttle,lbtot,tracked,type,"
			    "rate,rate_lim,rate_max,"
			    "check_status,check_code,check_duration,"
			    "hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,"
			    "\n");
}

/* Processes the stats interpreter on the statistics socket. This function is
 * called from an applet running in a stream interface. The function returns 1
 * if the request was understood, otherwise zero. It sets si->st0 to a value
 * designating the function which will have to process the request, which can
 * also be the print function to display the return message set into cli.msg.
 */
int stats_sock_parse_request(struct stream_interface *si, char *line)
{
	struct session *s = si->private;
	char *args[MAX_STATS_ARGS + 1];
	int arg;

	while (isspace((unsigned char)*line))
		line++;

	arg = 0;
	args[arg] = line;

	while (*line && arg < MAX_STATS_ARGS) {
		if (isspace((unsigned char)*line)) {
			*line++ = '\0';

			while (isspace((unsigned char)*line))
				line++;

			args[++arg] = line;
			continue;
		}

		line++;
	}

	while (++arg <= MAX_STATS_ARGS)
		args[arg] = line;

	s->data_ctx.stats.flags = 0;
	if (strcmp(args[0], "show") == 0) {
		if (strcmp(args[1], "stat") == 0) {
			if (*args[2] && *args[3] && *args[4]) {
				s->data_ctx.stats.flags |= STAT_BOUND;
				s->data_ctx.stats.iid	= atoi(args[2]);
				s->data_ctx.stats.type	= atoi(args[3]);
				s->data_ctx.stats.sid	= atoi(args[4]);
			}

			s->data_ctx.stats.flags |= STAT_SHOW_STAT;
			s->data_ctx.stats.flags |= STAT_FMT_CSV;
			s->data_state = DATA_ST_INIT;
			si->st0 = STAT_CLI_O_INFO; // stats_dump_raw_to_buffer
		}
		else if (strcmp(args[1], "info") == 0) {
			s->data_ctx.stats.flags |= STAT_SHOW_INFO;
			s->data_ctx.stats.flags |= STAT_FMT_CSV;
			s->data_state = DATA_ST_INIT;
			si->st0 = STAT_CLI_O_INFO; // stats_dump_raw_to_buffer
		}
		else if (strcmp(args[1], "sess") == 0) {
			s->data_state = DATA_ST_INIT;
			if (s->listener->perm.ux.level < ACCESS_LVL_OPER) {
				s->data_ctx.cli.msg = stats_permission_denied_msg;
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}
			si->st0 = STAT_CLI_O_SESS; // stats_dump_sess_to_buffer
		}
		else if (strcmp(args[1], "errors") == 0) {
			if (s->listener->perm.ux.level < ACCESS_LVL_OPER) {
				s->data_ctx.cli.msg = stats_permission_denied_msg;
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}
			if (*args[2])
				s->data_ctx.errors.iid	= atoi(args[2]);
			else
				s->data_ctx.errors.iid	= -1;
			s->data_ctx.errors.px = NULL;
			s->data_state = DATA_ST_INIT;
			si->st0 = STAT_CLI_O_ERR; // stats_dump_errors_to_buffer
		}
		else { /* neither "stat" nor "info" nor "sess" nor "errors"*/
			return 0;
		}
	}
	else if (strcmp(args[0], "clear") == 0) {
		if (strcmp(args[1], "counters") == 0) {
			struct proxy *px;
			struct server *sv;
			struct listener *li;
			int clrall = 0;

			if (strcmp(args[2], "all") == 0)
				clrall = 1;

			/* check permissions */
			if (s->listener->perm.ux.level < ACCESS_LVL_OPER ||
			    (clrall && s->listener->perm.ux.level < ACCESS_LVL_ADMIN)) {
				s->data_ctx.cli.msg = stats_permission_denied_msg;
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}

			for (px = proxy; px; px = px->next) {
				if (clrall)
					memset(&px->counters, 0, sizeof(px->counters));
				else {
					px->counters.feconn_max = 0;
					px->counters.beconn_max = 0;
					px->counters.fe_sps_max = 0;
					px->counters.be_sps_max = 0;
					px->counters.nbpend_max = 0;
				}

				for (sv = px->srv; sv; sv = sv->next)
					if (clrall)
						memset(&sv->counters, 0, sizeof(sv->counters));
					else {
						sv->counters.cur_sess_max = 0;
						sv->counters.nbpend_max = 0;
						sv->counters.sps_max = 0;
					}

				for (li = px->listen; li; li = li->next)
					if (li->counters) {
						if (clrall)
							memset(li->counters, 0, sizeof(*li->counters));
						else
							li->counters->conn_max = 0;
					}
			}

			return 1;
		}
		else {
			return 0;
		}
	}
	else if (strcmp(args[0], "get") == 0) {
		if (strcmp(args[1], "weight") == 0) {
			struct proxy *px;
			struct server *sv;

			/* split "backend/server" and make <line> point to server */
			for (line = args[2]; *line; line++)
				if (*line == '/') {
					*line++ = '\0';
					break;
				}

			if (!*line) {
				s->data_ctx.cli.msg = "Require 'backend/server'.\n";
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				s->data_ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* return server's effective weight at the moment */
			snprintf(trash, sizeof(trash), "%d (initial %d)\n", sv->uweight, sv->iweight);
			buffer_feed(si->ib, trash);
			return 1;
		}
		else { /* not "get weight" */
			return 0;
		}
	}
	else if (strcmp(args[0], "set") == 0) {
		if (strcmp(args[1], "weight") == 0) {
			struct proxy *px;
			struct server *sv;
			int w;

			if (s->listener->perm.ux.level < ACCESS_LVL_ADMIN) {
				s->data_ctx.cli.msg = stats_permission_denied_msg;
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* split "backend/server" and make <line> point to server */
			for (line = args[2]; *line; line++)
				if (*line == '/') {
					*line++ = '\0';
					break;
				}

			if (!*line || !*args[3]) {
				s->data_ctx.cli.msg = "Require 'backend/server' and 'weight' or 'weight%'.\n";
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				s->data_ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* if the weight is terminated with '%', it is set relative to
			 * the initial weight, otherwise it is absolute.
			 */
			w = atoi(args[3]);
			if (strchr(args[3], '%') != NULL) {
				if (w < 0 || w > 100) {
					s->data_ctx.cli.msg = "Relative weight can only be set between 0 and 100% inclusive.\n";
					si->st0 = STAT_CLI_PRINT;
					return 1;
				}
				w = sv->iweight * w / 100;
			}
			else {
				if (w < 0 || w > 256) {
					s->data_ctx.cli.msg = "Absolute weight can only be between 0 and 256 inclusive.\n";
					si->st0 = STAT_CLI_PRINT;
					return 1;
				}
			}

			if (w && w != sv->iweight && !(px->lbprm.algo & BE_LB_PROP_DYN)) {
				s->data_ctx.cli.msg = "Backend is using a static LB algorithm and only accepts weights '0%' and '100%'.\n";
				si->st0 = STAT_CLI_PRINT;
				return 1;
			}

			sv->uweight = w;

			if (px->lbprm.algo & BE_LB_PROP_DYN) {
			/* we must take care of not pushing the server to full throttle during slow starts */
				if ((sv->state & SRV_WARMINGUP) && (px->lbprm.algo & BE_LB_PROP_DYN))
					sv->eweight = (BE_WEIGHT_SCALE * (now.tv_sec - sv->last_change) + sv->slowstart - 1) / sv->slowstart;
				else
					sv->eweight = BE_WEIGHT_SCALE;
				sv->eweight *= sv->uweight;
			} else {
				sv->eweight = sv->uweight;
			}

			/* static LB algorithms are a bit harder to update */
			if (px->lbprm.update_server_eweight)
				px->lbprm.update_server_eweight(sv);
			else if (sv->eweight)
				px->lbprm.set_server_status_up(sv);
			else
				px->lbprm.set_server_status_down(sv);

			return 1;
		}
		else { /* not "set weight" */
			return 0;
		}
	}
	else { /* not "show" nor "clear" nor "get" nor "set" */
		return 0;
	}
	return 1;
}

/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to processes I/O from/to the stats unix socket. The system relies on a
 * state machine handling requests and various responses. We read a request,
 * then we process it and send the response, and we possibly display a prompt.
 * Then we can read again. The state is stored in si->st0 and is one of the
 * STAT_CLI_* constants. si->st1 is used to indicate whether prompt is enabled
 * or not.
 */
void stats_io_handler(struct stream_interface *si)
{
	struct session *s = si->private;
	struct buffer *req = si->ob;
	struct buffer *res = si->ib;
	int reql;
	int len;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	while (1) {
		if (si->st0 == STAT_CLI_INIT) {
			/* Stats output not initialized yet */
			memset(&s->data_ctx.stats, 0, sizeof(s->data_ctx.stats));
			s->data_source = DATA_SRC_STATS;
			si->st0 = STAT_CLI_GETREQ;
		}
		else if (si->st0 == STAT_CLI_END) {
			/* Let's close for real now. We just close the request
			 * side, the conditions below will complete if needed.
			 */
			si->shutw(si);
			break;
		}
		else if (si->st0 == STAT_CLI_GETREQ) {
			/* ensure we have some output room left in the event we
			 * would want to return some info right after parsing.
			 */
			if (buffer_almost_full(si->ib))
				break;

			reql = buffer_si_peekline(si->ob, trash, sizeof(trash));
			if (reql <= 0) { /* closed or EOL not found */
				if (reql == 0)
					break;
				si->st0 = STAT_CLI_END;
				continue;
			}

			/* seek for a possible semi-colon. If we find one, we
			 * replace it with an LF and skip only this part.
			 */
			for (len = 0; len < reql; len++)
				if (trash[len] == ';') {
					trash[len] = '\n';
					reql = len + 1;
					break;
				}

			/* now it is time to check that we have a full line,
			 * remove the trailing \n and possibly \r, then cut the
			 * line.
			 */
			len = reql - 1;
			if (trash[len] != '\n') {
				si->st0 = STAT_CLI_END;
				continue;
			}

			if (len && trash[len-1] == '\r')
				len--;

			trash[len] = '\0';

			si->st0 = STAT_CLI_PROMPT;
			if (len) {
				if (strcmp(trash, "quit") == 0) {
					si->st0 = STAT_CLI_END;
					continue;
				}
				else if (strcmp(trash, "prompt") == 0)
					si->st1 = !si->st1;
				else if (strcmp(trash, "help") == 0 ||
					 !stats_sock_parse_request(si, trash)) {
					s->data_ctx.cli.msg = stats_sock_usage_msg;
					si->st0 = STAT_CLI_PRINT;
				}
				/* NB: stats_sock_parse_request() may have put
				 * another STAT_CLI_O_* into si->st0.
				 */
			}
			else if (!si->st1) {
				/* if prompt is disabled, print help on empty lines,
				 * so that the user at least knows how to enable
				 * prompt and find help.
				 */
				s->data_ctx.cli.msg = stats_sock_usage_msg;
				si->st0 = STAT_CLI_PRINT;
			}

			/* re-adjust req buffer */
			buffer_skip(si->ob, reql);
			req->flags |= BF_READ_DONTWAIT; /* we plan to read small requests */
		}
		else {	/* output functions: first check if the output buffer is closed then abort */
			if (res->flags & (BF_SHUTR_NOW|BF_SHUTR)) {
				si->st0 = STAT_CLI_END;
				continue;
			}

			switch (si->st0) {
			case STAT_CLI_PRINT:
				if (buffer_feed(si->ib, s->data_ctx.cli.msg) < 0)
					si->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_INFO:
				if (stats_dump_raw_to_buffer(s, res))
					si->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_SESS:
				if (stats_dump_sess_to_buffer(s, res))
					si->st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_ERR:	/* errors dump */
				if (stats_dump_errors_to_buffer(s, res))
					si->st0 = STAT_CLI_PROMPT;
				break;
			default: /* abnormal state */
				si->st0 = STAT_CLI_PROMPT;
				break;
			}

			/* The post-command prompt is either LF alone or LF + '> ' in interactive mode */
			if (si->st0 == STAT_CLI_PROMPT) {
				if (buffer_feed(si->ib, si->st1 ? "\n> " : "\n") < 0)
					si->st0 = STAT_CLI_GETREQ;
			}

			/* If the output functions are still there, it means they require more room. */
			if (si->st0 >= STAT_CLI_OUTPUT)
				break;

			/* Now we close the output if one of the writers did so,
			 * or if we're not in interactive mode and the request
			 * buffer is empty. This still allows pipelined requests
			 * to be sent in non-interactive mode.
			 */
			if ((res->flags & (BF_SHUTW|BF_SHUTW_NOW)) || (!si->st1 && !req->send_max)) {
				si->st0 = STAT_CLI_END;
				continue;
			}

			/* switch state back to GETREQ to read next requests */
			si->st0 = STAT_CLI_GETREQ;
		}
	}

	if ((res->flags & BF_SHUTR) && (si->state == SI_ST_EST) && (si->st0 != STAT_CLI_GETREQ)) {
		DPRINTF(stderr, "%s@%d: si to buf closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* Other size has closed, let's abort if we have no more processing to do
		 * and nothing more to consume. This is comparable to a broken pipe, so
		 * we forward the close to the request side so that it flows upstream to
		 * the client.
		 */
		si->shutw(si);
	}

	if ((req->flags & BF_SHUTW) && (si->state == SI_ST_EST) && (si->st0 < STAT_CLI_OUTPUT)) {
		DPRINTF(stderr, "%s@%d: buf to si closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* We have no more processing to do, and nothing more to send, and
		 * the client side has closed. So we'll forward this state downstream
		 * on the response buffer.
		 */
		si->shutr(si);
		res->flags |= BF_READ_NULL;
	}

	/* update all other flags and resync with the other side */
	si->update(si);

	/* we don't want to expire timeouts while we're processing requests */
	si->ib->rex = TICK_ETERNITY;
	si->ob->wex = TICK_ETERNITY;

 out:
	DPRINTF(stderr, "%s@%d: st=%d, rqf=%x, rpf=%x, rql=%d, rqs=%d, rl=%d, rs=%d\n",
		__FUNCTION__, __LINE__,
		si->state, req->flags, res->flags, req->l, req->send_max, res->l, res->send_max);

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
		/* check that we have released everything then unregister */
		stream_int_unregister_handler(si);
	}
}

/* This function is called to send output to the response buffer.
 * It dumps statistics onto the output buffer <rep> owned by session <s>.
 * s->data_ctx must have been zeroed first, and the flags properly set.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 * Some states are not used but it makes the code more similar to other
 * functions which handle stats too.
 */
int stats_dump_raw_to_buffer(struct session *s, struct buffer *rep)
{
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	chunk_init(&msg, trash, sizeof(trash));

	switch (s->data_state) {
	case DATA_ST_INIT:
		/* the function had not been called yet */
		s->data_state = DATA_ST_HEAD;
		/* fall through */

	case DATA_ST_HEAD:
		if (s->data_ctx.stats.flags & STAT_SHOW_STAT) {
			print_csv_header(&msg);
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_state = DATA_ST_INFO;
		/* fall through */

	case DATA_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);
		if (s->data_ctx.stats.flags & STAT_SHOW_INFO) {
			chunk_printf(&msg,
				     "Name: " PRODUCT_NAME "\n"
				     "Version: " HAPROXY_VERSION "\n"
				     "Release_date: " HAPROXY_DATE "\n"
				     "Nbproc: %d\n"
				     "Process_num: %d\n"
				     "Pid: %d\n"
				     "Uptime: %dd %dh%02dm%02ds\n"
				     "Uptime_sec: %d\n"
				     "Memmax_MB: %d\n"
				     "Ulimit-n: %d\n"
				     "Maxsock: %d\n"
				     "Maxconn: %d\n"
				     "Maxpipes: %d\n"
				     "CurrConns: %d\n"
				     "PipesUsed: %d\n"
				     "PipesFree: %d\n"
				     "Tasks: %d\n"
				     "Run_queue: %d\n"
				     "node: %s\n"
				     "description: %s\n"
				     "",
				     global.nbproc,
				     relative_pid,
				     pid,
				     up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60),
				     up,
				     global.rlimit_memmax,
				     global.rlimit_nofile,
				     global.maxsock, global.maxconn, global.maxpipes,
				     actconn, pipes_used, pipes_free,
				     nb_tasks_cur, run_queue_cur,
				     global.node, global.desc?global.desc:""
				     );
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px = proxy;
		s->data_ctx.stats.px_st = DATA_ST_PX_INIT;

		s->data_ctx.stats.sv = NULL;
		s->data_ctx.stats.sv_st = 0;

		s->data_state = DATA_ST_LIST;
		/* fall through */

	case DATA_ST_LIST:
		/* dump proxies */
		if (s->data_ctx.stats.flags & STAT_SHOW_STAT) {
			while (s->data_ctx.stats.px) {
				px = s->data_ctx.stats.px;
				/* skip the disabled proxies and non-networked ones */
				if (px->state != PR_STSTOPPED &&
				    (px->cap & (PR_CAP_FE | PR_CAP_BE))) {
					if (stats_dump_proxy(s, px, NULL) == 0)
						return 0;
				}

				s->data_ctx.stats.px = px->next;
				s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
			}
			/* here, we just have reached the last proxy */
		}

		s->data_state = DATA_ST_END;
		/* fall through */

	case DATA_ST_END:
		s->data_state = DATA_ST_FIN;
		/* fall through */

	case DATA_ST_FIN:
		return 1;

	default:
		/* unknown state ! */
		s->data_state = DATA_ST_FIN;
		return 1;
	}
}


/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to send HTTP stats over a TCP socket. The mechanism is very simple.
 * si->st0 becomes non-zero once the transfer is finished. The handler
 * automatically unregisters itself once transfer is complete.
 */
void http_stats_io_handler(struct stream_interface *si)
{
	struct session *s = si->private;
	struct buffer *req = si->ob;
	struct buffer *res = si->ib;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* check that the output is not closed */
	if (res->flags & (BF_SHUTW|BF_SHUTW_NOW))
		si->st0 = 1;

	if (!si->st0) {
		if (stats_dump_http(s, res, s->be->uri_auth)) {
			si->st0 = 1;
			si->shutw(si);
		}
	}

	if ((res->flags & BF_SHUTR) && (si->state == SI_ST_EST))
		si->shutw(si);

	if ((req->flags & BF_SHUTW) && (si->state == SI_ST_EST) && si->st0) {
		si->shutr(si);
		res->flags |= BF_READ_NULL;
	}

	/* update all other flags and resync with the other side */
	si->update(si);

	/* we don't want to expire timeouts while we're processing requests */
	si->ib->rex = TICK_ETERNITY;
	si->ob->wex = TICK_ETERNITY;

 out:
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
		/* check that we have released everything then unregister */
		stream_int_unregister_handler(si);
	}
}


/*
 * Produces statistics data for the session <s>. Expects to be called with
 * client socket shut down on input. It stops by itself by unsetting the
 * BF_HIJACK flag from the buffer, which it uses to keep on being called
 * when there is free space in the buffer, of simply by letting an empty buffer
 * upon return.s->data_ctx must have been zeroed before the first call, and the
 * flags set. It returns 0 if it had to stop writing data and an I/O is needed,
 * 1 if the dump is finished and the session must be closed, or -1 in case of
 * any error.
 */
int stats_dump_http(struct session *s, struct buffer *rep, struct uri_auth *uri)
{
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	chunk_init(&msg, trash, sizeof(trash));

	switch (s->data_state) {
	case DATA_ST_INIT:
		chunk_printf(&msg,
			     "HTTP/1.0 200 OK\r\n"
			     "Cache-Control: no-cache\r\n"
			     "Connection: close\r\n"
			     "Content-Type: %s\r\n",
			     (s->data_ctx.stats.flags & STAT_FMT_CSV) ? "text/plain" : "text/html");

		if (uri->refresh > 0 && !(s->data_ctx.stats.flags & STAT_NO_REFRESH))
			chunk_printf(&msg, "Refresh: %d\r\n",
				     uri->refresh);

		chunk_printf(&msg, "\r\n");

		s->txn.status = 200;
		if (buffer_feed_chunk(rep, &msg) >= 0)
			return 0;

		if (!(s->flags & SN_ERR_MASK))  // this is not really an error but it is
			s->flags |= SN_ERR_PRXCOND; // to mark that it comes from the proxy
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;

		if (s->txn.meth == HTTP_METH_HEAD) {
			/* that's all we return in case of HEAD request */
			s->data_state = DATA_ST_FIN;
			return 1;
		}

		s->data_state = DATA_ST_HEAD; /* let's start producing data */
		/* fall through */

	case DATA_ST_HEAD:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			/* WARNING! This must fit in the first buffer !!! */
			chunk_printf(&msg,
			     "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n"
			     "\"http://www.w3.org/TR/html4/loose.dtd\">\n"
			     "<html><head><title>Statistics Report for " PRODUCT_NAME "%s%s</title>\n"
			     "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n"
			     "<style type=\"text/css\"><!--\n"
			     "body {"
			     " font-family: arial, helvetica, sans-serif;"
			     " font-size: 12px;"
			     " font-weight: normal;"
			     " color: black;"
			     " background: white;"
			     "}\n"
			     "th,td {"
			     " font-size: 10px;"
			     "}\n"
			     "h1 {"
			     " font-size: x-large;"
			     " margin-bottom: 0.5em;"
			     "}\n"
			     "h2 {"
			     " font-family: helvetica, arial;"
			     " font-size: x-large;"
			     " font-weight: bold;"
			     " font-style: italic;"
			     " color: #6020a0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "h3 {"
			     " font-family: helvetica, arial;"
			     " font-size: 16px;"
			     " font-weight: bold;"
			     " color: #b00040;"
			     " background: #e8e8d0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "li {"
			     " margin-top: 0.25em;"
			     " margin-right: 2em;"
			     "}\n"
			     ".hr {margin-top: 0.25em;"
			     " border-color: black;"
			     " border-bottom-style: solid;"
			     "}\n"
			     ".titre	{background: #20D0D0;color: #000000; font-weight: bold; text-align: center;}\n"
			     ".total	{background: #20D0D0;color: #ffff80;}\n"
			     ".frontend	{background: #e8e8d0;}\n"
			     ".socket	{background: #d0d0d0;}\n"
			     ".backend	{background: #e8e8d0;}\n"
			     ".active0	{background: #ff9090;}\n"
			     ".active1	{background: #ffd020;}\n"
			     ".active2	{background: #ffffa0;}\n"
			     ".active3	{background: #c0ffc0;}\n"
			     ".active4	{background: #ffffa0;}\n"  /* NOLB state shows same as going down */
			     ".active5	{background: #a0e0a0;}\n"  /* NOLB state shows darker than up */
			     ".active6	{background: #e0e0e0;}\n"
			     ".backup0	{background: #ff9090;}\n"
			     ".backup1	{background: #ff80ff;}\n"
			     ".backup2	{background: #c060ff;}\n"
			     ".backup3	{background: #b0d0ff;}\n"
			     ".backup4	{background: #c060ff;}\n"  /* NOLB state shows same as going down */
			     ".backup5	{background: #90b0e0;}\n"  /* NOLB state shows same as going down */
			     ".backup6	{background: #e0e0e0;}\n"
			     ".rls      {letter-spacing: 0.2em; margin-right: 1px;}\n" /* right letter spacing (used for grouping digits) */
			     "\n"
			     "a.px:link {color: #ffff40; text-decoration: none;}"
			     "a.px:visited {color: #ffff40; text-decoration: none;}"
			     "a.px:hover {color: #ffffff; text-decoration: none;}"
			     "a.lfsb:link {color: #000000; text-decoration: none;}"
			     "a.lfsb:visited {color: #000000; text-decoration: none;}"
			     "a.lfsb:hover {color: #505050; text-decoration: none;}"
			     "\n"
			     "table.tbl { border-collapse: collapse; border-style: none;}\n"
			     "table.tbl td { text-align: right; border-width: 1px 1px 1px 1px; border-style: solid solid solid solid; padding: 2px 3px; border-color: gray; white-space: nowrap;}\n"
			     "table.tbl td.ac { text-align: center;}\n"
			     "table.tbl th { border-width: 1px; border-style: solid solid solid solid; border-color: gray;}\n"
			     "table.tbl th.pxname { background: #b00040; color: #ffff40; font-weight: bold; border-style: solid solid none solid; padding: 2px 3px; white-space: nowrap;}\n"
			     "table.tbl th.empty { border-style: none; empty-cells: hide; background: white;}\n"
			     "table.tbl th.desc { background: white; border-style: solid solid none solid; text-align: left; padding: 2px 3px;}\n"
			     "\n"
			     "table.lgd { border-collapse: collapse; border-width: 1px; border-style: none none none solid; border-color: black;}\n"
			     "table.lgd td { border-width: 1px; border-style: solid solid solid solid; border-color: gray; padding: 2px;}\n"
			     "table.lgd td.noborder { border-style: none; padding: 2px; white-space: nowrap;}\n"
			     "-->\n"
			     "</style></head>\n",
			     (uri->flags&ST_SHNODE) ? " on " : "",
			     (uri->flags&ST_SHNODE) ? (uri->node ? uri->node : global.node) : ""
			     );
		} else {
			print_csv_header(&msg);
		}
		if (buffer_feed_chunk(rep, &msg) >= 0)
			return 0;

		s->data_state = DATA_ST_INFO;
		/* fall through */

	case DATA_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);

		/* WARNING! this has to fit the first packet too.
			 * We are around 3.5 kB, add adding entries will
			 * become tricky if we want to support 4kB buffers !
			 */
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg,
			     "<body><h1><a href=\"" PRODUCT_URL "\" style=\"text-decoration: none;\">"
			     PRODUCT_NAME "%s</a></h1>\n"
			     "<h2>Statistics Report for pid %d%s%s%s%s</h2>\n"
			     "<hr width=\"100%%\" class=\"hr\">\n"
			     "<h3>&gt; General process information</h3>\n"
			     "<table border=0><tr><td align=\"left\" nowrap width=\"1%%\">\n"
			     "<p><b>pid = </b> %d (process #%d, nbproc = %d)<br>\n"
			     "<b>uptime = </b> %dd %dh%02dm%02ds<br>\n"
			     "<b>system limits:</b> memmax = %s%s; ulimit-n = %d<br>\n"
			     "<b>maxsock = </b> %d; <b>maxconn = </b> %d; <b>maxpipes = </b> %d<br>\n"
			     "current conns = %d; current pipes = %d/%d<br>\n"
			     "Running tasks: %d/%d<br>\n"
			     "</td><td align=\"center\" nowrap>\n"
			     "<table class=\"lgd\"><tr>\n"
			     "<td class=\"active3\">&nbsp;</td><td class=\"noborder\">active UP </td>"
			     "<td class=\"backup3\">&nbsp;</td><td class=\"noborder\">backup UP </td>"
			     "</tr><tr>\n"
			     "<td class=\"active2\"></td><td class=\"noborder\">active UP, going down </td>"
			     "<td class=\"backup2\"></td><td class=\"noborder\">backup UP, going down </td>"
			     "</tr><tr>\n"
			     "<td class=\"active1\"></td><td class=\"noborder\">active DOWN, going up </td>"
			     "<td class=\"backup1\"></td><td class=\"noborder\">backup DOWN, going up </td>"
			     "</tr><tr>\n"
			     "<td class=\"active0\"></td><td class=\"noborder\">active or backup DOWN &nbsp;</td>"
			     "<td class=\"active6\"></td><td class=\"noborder\">not checked </td>"
			     "</tr></table>\n"
			     "Note: UP with load-balancing disabled is reported as \"NOLB\"."
			     "</td>"
			     "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
			     "<b>Display option:</b><ul style=\"margin-top: 0.25em;\">"
			     "",
			     (uri->flags&ST_HIDEVER)?"":(STATS_VERSION_STRING),
			     pid, (uri->flags&ST_SHNODE) ? " on " : "", (uri->flags&ST_SHNODE) ? (uri->node ? uri->node : global.node) : "",
			     (uri->flags&ST_SHDESC)? ": " : "", (uri->flags&ST_SHDESC) ? (uri->desc ? uri->desc : global.desc) : "",
			     pid, relative_pid, global.nbproc,
			     up / 86400, (up % 86400) / 3600,
			     (up % 3600) / 60, (up % 60),
			     global.rlimit_memmax ? ultoa(global.rlimit_memmax) : "unlimited",
			     global.rlimit_memmax ? " MB" : "",
			     global.rlimit_nofile,
			     global.maxsock, global.maxconn, global.maxpipes,
			     actconn, pipes_used, pipes_used+pipes_free,
			     run_queue_cur, nb_tasks_cur
			     );

			if (s->data_ctx.stats.flags & STAT_HIDE_DOWN)
				chunk_printf(&msg,
				     "<li><a href=\"%s%s%s\">Show all servers</a><br>\n",
				     uri->uri_prefix,
				     "",
				     (s->data_ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");
			else
				chunk_printf(&msg,
				     "<li><a href=\"%s%s%s\">Hide 'DOWN' servers</a><br>\n",
				     uri->uri_prefix,
				     ";up",
				     (s->data_ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");

			if (uri->refresh > 0) {
				if (s->data_ctx.stats.flags & STAT_NO_REFRESH)
					chunk_printf(&msg,
					     "<li><a href=\"%s%s%s\">Enable refresh</a><br>\n",
					     uri->uri_prefix,
					     (s->data_ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
					     "");
				else
					chunk_printf(&msg,
					     "<li><a href=\"%s%s%s\">Disable refresh</a><br>\n",
					     uri->uri_prefix,
					     (s->data_ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
					     ";norefresh");
			}

			chunk_printf(&msg,
			     "<li><a href=\"%s%s%s\">Refresh now</a><br>\n",
			     uri->uri_prefix,
			     (s->data_ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			     (s->data_ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");

			chunk_printf(&msg,
			     "<li><a href=\"%s;csv%s\">CSV export</a><br>\n",
			     uri->uri_prefix,
			     (uri->refresh > 0) ? ";norefresh" : "");

			chunk_printf(&msg,
			     "</ul></td>"
			     "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
			     "<b>External ressources:</b><ul style=\"margin-top: 0.25em;\">\n"
			     "<li><a href=\"" PRODUCT_URL "\">Primary site</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_UPD "\">Updates (v" PRODUCT_BRANCH ")</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_DOC "\">Online manual</a><br>\n"
			     "</ul>"
			     "</td>"
			     "</tr></table>\n"
			     ""
			     );

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px = proxy;
		s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
		s->data_state = DATA_ST_LIST;
		/* fall through */

	case DATA_ST_LIST:
		/* dump proxies */
		while (s->data_ctx.stats.px) {
			if (buffer_almost_full(rep))
				return 0;
			px = s->data_ctx.stats.px;
			/* skip the disabled proxies and non-networked ones */
			if (px->state != PR_STSTOPPED && (px->cap & (PR_CAP_FE | PR_CAP_BE)))
				if (stats_dump_proxy(s, px, uri) == 0)
					return 0;

			s->data_ctx.stats.px = px->next;
			s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
		}
		/* here, we just have reached the last proxy */

		s->data_state = DATA_ST_END;
		/* fall through */

	case DATA_ST_END:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg, "</body></html>\n");
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_state = DATA_ST_FIN;
		/* fall through */

	case DATA_ST_FIN:
		return 1;

	default:
		/* unknown state ! */
		s->data_state = DATA_ST_FIN;
		return -1;
	}
}


/*
 * Dumps statistics for a proxy.
 * Returns 0 if it had to stop dumping data because of lack of buffer space,
 * ot non-zero if everything completed.
 */
int stats_dump_proxy(struct session *s, struct proxy *px, struct uri_auth *uri)
{
	struct buffer *rep = s->rep;
	struct server *sv, *svs;	/* server and server-state, server-state=server or server->tracked */
	struct listener *l;
	struct chunk msg;

	chunk_init(&msg, trash, sizeof(trash));

	switch (s->data_ctx.stats.px_st) {
	case DATA_ST_PX_INIT:
		/* we are on a new proxy */

		if (uri && uri->scope) {
			/* we have a limited scope, we have to check the proxy name */
			struct stat_scope *scope;
			int len;

			len = strlen(px->id);
			scope = uri->scope;

			while (scope) {
				/* match exact proxy name */
				if (scope->px_len == len && !memcmp(px->id, scope->px_id, len))
					break;

				/* match '.' which means 'self' proxy */
				if (!strcmp(scope->px_id, ".") && px == s->be)
					break;
				scope = scope->next;
			}

			/* proxy name not found : don't dump anything */
			if (scope == NULL)
				return 1;
		}

		if ((s->data_ctx.stats.flags & STAT_BOUND) && (s->data_ctx.stats.iid != -1) &&
			(px->uuid != s->data_ctx.stats.iid))
			return 1;

		s->data_ctx.stats.px_st = DATA_ST_PX_TH;
		/* fall through */

	case DATA_ST_PX_TH:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			/* print a new table */
			chunk_printf(&msg,
				     "<table class=\"tbl\" width=\"100%%\">\n"
				     "<tr class=\"titre\">"
				     "<th class=\"pxname\" width=\"10%%\"");

			if (uri->flags&ST_SHLGNDS) {
				/* cap, mode, id */
				chunk_printf(&msg, " title=\"cap: %s, mode: %s, id: %d",
					proxy_cap_str(px->cap), proxy_mode_str(px->mode),
					px->uuid);

				chunk_printf(&msg, "\"");
			}

			chunk_printf(&msg,
				     "><a name=\"%s\"></a>"
				     "<a class=px href=\"#%s\">%s</a></th>"
				     "<th class=\"%s\" width=\"90%%\">%s</th>"
				     "</tr>\n"
				     "</table>\n"
				     "<table class=\"tbl\" width=\"100%%\">\n"
				     "<tr class=\"titre\">"
				     "<th rowspan=2></th>"
				     "<th colspan=3>Queue</th>"
				     "<th colspan=3>Session rate</th><th colspan=5>Sessions</th>"
				     "<th colspan=2>Bytes</th><th colspan=2>Denied</th>"
				     "<th colspan=3>Errors</th><th colspan=2>Warnings</th>"
				     "<th colspan=9>Server</th>"
				     "</tr>\n"
				     "<tr class=\"titre\">"
				     "<th>Cur</th><th>Max</th><th>Limit</th>"
				     "<th>Cur</th><th>Max</th><th>Limit</th><th>Cur</th><th>Max</th>"
				     "<th>Limit</th><th>Total</th><th>LbTot</th><th>In</th><th>Out</th>"
				     "<th>Req</th><th>Resp</th><th>Req</th><th>Conn</th>"
				     "<th>Resp</th><th>Retr</th><th>Redis</th>"
				     "<th>Status</th><th>LastChk</th><th>Wght</th><th>Act</th>"
				     "<th>Bck</th><th>Chk</th><th>Dwn</th><th>Dwntme</th>"
				     "<th>Thrtle</th>\n"
				     "</tr>",
				     px->id, px->id, px->id,
				     px->desc ? "desc" : "empty", px->desc ? px->desc : "");

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_FE;
		/* fall through */

	case DATA_ST_PX_FE:
		/* print the frontend */
		if ((px->cap & PR_CAP_FE) &&
		    (!(s->data_ctx.stats.flags & STAT_BOUND) || (s->data_ctx.stats.type & (1 << STATS_TYPE_FE)))) {
			if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg,
				     /* name, queue */
				     "<tr class=\"frontend\"><td class=ac>"
				     "<a name=\"%s/Frontend\"></a>"
				     "<a class=lfsb href=\"#%s/Frontend\">Frontend</a></td><td colspan=3></td>"
				     /* sessions rate : current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     /* sessions: current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td"
				     "",
				     px->id, px->id,
				     U2H0(read_freq_ctr(&px->fe_sess_per_sec)),
				     U2H1(px->counters.fe_sps_max), LIM2A2(px->fe_sps_lim, "-"),
				     U2H3(px->feconn), U2H4(px->counters.feconn_max), U2H5(px->maxconn));

				/* http response (via td title): 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					chunk_printf(&msg, " title=\"rsp codes:");

					for (i = 1; i < 6; i++)
						chunk_printf(&msg, " %dxx=%lld,", i, px->counters.p.http.rsp[i]);

					chunk_printf(&msg, " other=%lld\"", px->counters.p.http.rsp[0]);
				}

				chunk_printf(&msg,
				     /* sessions: total, lbtot */
				     ">%s</td><td></td>"
				     /* bytes : in, out */
				     "<td>%s</td><td>%s</td>"
				     "",
				     U2H6(px->counters.cum_feconn), U2H7(px->counters.bytes_in), U2H8(px->counters.bytes_out));

				chunk_printf(&msg,
				     /* denied: req, resp */
				     "<td>%s</td><td>%s</td>"
				     /* errors : request, connect, response */
				     "<td>%s</td><td></td><td></td>"
				     /* warnings: retries, redispatches */
				     "<td></td><td></td>"
				     /* server status : reflect frontend status */
				     "<td class=ac>%s</td>"
				     /* rest of server: nothing */
				     "<td class=ac colspan=8></td></tr>"
				     "",
				     U2H0(px->counters.denied_req), U2H1(px->counters.denied_resp),
				     U2H2(px->counters.failed_req),
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP");
			} else {
				chunk_printf(&msg,
				     /* pxid, name, queue cur, queue max, */
				     "%s,FRONTEND,,,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors : request, connect, response */
				     "%lld,,,"
				     /* warnings: retries, redispatches */
				     ",,"
				     /* server status : reflect frontend status */
				     "%s,"
				     /* rest of server: nothing */
				     ",,,,,,,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,0,,,,%d,"
				     /* rate, rate_lim, rate_max */
				     "%u,%u,%u,"
				     /* check_status, check_code, check_duration */
				     ",,,",
				     px->id,
				     px->feconn, px->counters.feconn_max, px->maxconn, px->counters.cum_feconn,
				     px->counters.bytes_in, px->counters.bytes_out,
				     px->counters.denied_req, px->counters.denied_resp,
				     px->counters.failed_req,
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP",
				     relative_pid, px->uuid, STATS_TYPE_FE,
				     read_freq_ctr(&px->fe_sess_per_sec),
				     px->fe_sps_lim, px->counters.fe_sps_max);

				/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					for (i=1; i<6; i++)
						chunk_printf(&msg, "%lld,", px->counters.p.http.rsp[i]);

					chunk_printf(&msg, "%lld,", px->counters.p.http.rsp[0]);
				} else {
					chunk_printf(&msg, ",,,,,,");
				}

				/* failed health analyses */
				chunk_printf(&msg, ",");

				/* finish with EOL */
				chunk_printf(&msg, "\n");
			}

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.l = px->listen; /* may be NULL */
		s->data_ctx.stats.px_st = DATA_ST_PX_LI;
		/* fall through */

	case DATA_ST_PX_LI:
		/* stats.l has been initialized above */
		for (; s->data_ctx.stats.l != NULL; s->data_ctx.stats.l = l->next) {
			if (buffer_almost_full(rep))
				return 0;

			l = s->data_ctx.stats.l;
			if (!l->counters)
				continue;

			if (s->data_ctx.stats.flags & STAT_BOUND) {
				if (!(s->data_ctx.stats.type & (1 << STATS_TYPE_SO)))
					break;

				if (s->data_ctx.stats.sid != -1 && l->luid != s->data_ctx.stats.sid)
					continue;
			}

			if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg, "<tr class=socket><td class=ac");

					if (uri->flags&ST_SHLGNDS) {
						char str[INET6_ADDRSTRLEN], *fmt = NULL;
						int port;

						chunk_printf(&msg, " title=\"IP: ");

						port = (l->addr.ss_family == AF_INET6)
							? ntohs(((struct sockaddr_in6 *)(&l->addr))->sin6_port)
							: ntohs(((struct sockaddr_in *)(&l->addr))->sin_port);

						if (l->addr.ss_family == AF_INET) {
							if (inet_ntop(AF_INET,
							    (const void *)&((struct sockaddr_in *)&l->addr)->sin_addr,
							    str, sizeof(str)))
								fmt = "%s:%d";
						} else {
							if (inet_ntop(AF_INET6,
							    (const void *)&((struct sockaddr_in6 *)(&l->addr))->sin6_addr,
							    str, sizeof(str)))
								fmt = "[%s]:%d";
						}

						if (fmt)
							chunk_printf(&msg, fmt, str, port);
						else
							chunk_printf(&msg, "(%s)", strerror(errno));

						/* id */
						chunk_printf(&msg, ", id: %d", l->luid);

						chunk_printf(&msg, "\"");
					}

				chunk_printf(&msg,
				     /* name, queue */
				     "><a name=\"%s/+%s\"></a>"
				     "<a class=lfsb href=\"#%s/+%s\">%s</a></td><td colspan=3></td>"
				     /* sessions rate: current, max, limit */
				     "<td colspan=3>&nbsp;</td>"
				     /* sessions: current, max, limit, total, lbtot */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td>%s</td><td>&nbsp;</td>"
				     /* bytes: in, out */
				     "<td>%s</td><td>%s</td>"
				     "",
				     px->id, l->name, px->id, l->name, l->name,
				     U2H3(l->nbconn), U2H4(l->counters->conn_max), U2H5(l->maxconn),
				     U2H6(l->counters->cum_conn), U2H7(l->counters->bytes_in), U2H8(l->counters->bytes_out));

				chunk_printf(&msg,
				     /* denied: req, resp */
				     "<td>%s</td><td>%s</td>"
				     /* errors: request, connect, response */
				     "<td>%s</td><td></td><td></td>"
				     /* warnings: retries, redispatches */
				     "<td></td><td></td>"
				     /* server status: reflect listener status */
				     "<td class=ac>%s</td>"
				     /* rest of server: nothing */
				     "<td class=ac colspan=8></td></tr>"
				     "",
				     U2H0(l->counters->denied_req), U2H1(l->counters->denied_resp),
				     U2H2(l->counters->failed_req),
				     (l->nbconn < l->maxconn) ? "OPEN" : "FULL");
			} else {
				chunk_printf(&msg,
				     /* pxid, name, queue cur, queue max, */
				     "%s,%s,,,"
				     /* sessions: current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes: in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors: request, connect, response */
				     "%lld,,,"
				     /* warnings: retries, redispatches */
				     ",,"
				     /* server status: reflect listener status */
				     "%s,"
				     /* rest of server: nothing */
				     ",,,,,,,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,%d,,,,%d,"
				     /* rate, rate_lim, rate_max */
				     ",,,"
				     /* check_status, check_code, check_duration */
				     ",,,"
				     /* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				     ",,,,,,"
				     /* failed health analyses */
				     ","
				     "\n",
				     px->id, l->name,
				     l->nbconn, l->counters->conn_max,
				     l->maxconn, l->counters->cum_conn,
				     l->counters->bytes_in, l->counters->bytes_out,
				     l->counters->denied_req, l->counters->denied_resp,
				     l->counters->failed_req,
				     (l->nbconn < l->maxconn) ? "OPEN" : "FULL",
				     relative_pid, px->uuid, l->luid, STATS_TYPE_SO);
			}

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.sv = px->srv; /* may be NULL */
		s->data_ctx.stats.px_st = DATA_ST_PX_SV;
		/* fall through */

	case DATA_ST_PX_SV:
		/* stats.sv has been initialized above */
		for (; s->data_ctx.stats.sv != NULL; s->data_ctx.stats.sv = sv->next) {
			int sv_state; /* 0=DOWN, 1=going up, 2=going down, 3=UP, 4,5=NOLB, 6=unchecked */

			if (buffer_almost_full(rep))
				return 0;

			sv = s->data_ctx.stats.sv;

			if (s->data_ctx.stats.flags & STAT_BOUND) {
				if (!(s->data_ctx.stats.type & (1 << STATS_TYPE_SV)))
					break;

				if (s->data_ctx.stats.sid != -1 && sv->puid != s->data_ctx.stats.sid)
					continue;
			}

			if (sv->tracked)
				svs = sv->tracked;
			else
				svs = sv;

			/* FIXME: produce some small strings for "UP/DOWN x/y &#xxxx;" */
			if (!(svs->state & SRV_CHECKED))
				sv_state = 6;
			else if (svs->state & SRV_RUNNING) {
				if (svs->health == svs->rise + svs->fall - 1)
					sv_state = 3; /* UP */
				else
					sv_state = 2; /* going down */

				if (svs->state & SRV_GOINGDOWN)
					sv_state += 2;
			}
			else
				if (svs->health)
					sv_state = 1; /* going up */
				else
					sv_state = 0; /* DOWN */

			if ((sv_state == 0) && (s->data_ctx.stats.flags & STAT_HIDE_DOWN)) {
				/* do not report servers which are DOWN */
				s->data_ctx.stats.sv = sv->next;
				continue;
			}

			if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
				static char *srv_hlt_st[7] = { "DOWN", "DN %d/%d &uarr;",
							       "UP %d/%d &darr;", "UP",
							       "NOLB %d/%d &darr;", "NOLB",
							       "<i>no check</i>" };
				chunk_printf(&msg,
				     /* name */
				     "<tr class=\"%s%d\"><td class=ac",
				     (sv->state & SRV_BACKUP) ? "backup" : "active", sv_state);

				if (uri->flags&ST_SHLGNDS) {
					char str[INET6_ADDRSTRLEN];

					chunk_printf(&msg, " title=\"IP: ");

					/* IP */
					if (inet_ntop(sv->addr.sin_family, &sv->addr.sin_addr, str, sizeof(str)))
						chunk_printf(&msg, "%s:%d", str, htons(sv->addr.sin_port));
					else
						chunk_printf(&msg, "(%s)", strerror(errno));

					/* id */
					chunk_printf(&msg, ", id: %d", sv->puid);

					/* cookie */
					if (sv->cookie) {
						struct chunk src;

						chunk_printf(&msg, ", cookie: '");

						chunk_initlen(&src, sv->cookie, 0, strlen(sv->cookie));
						chunk_htmlencode(&msg, &src);

						chunk_printf(&msg, "'");
					}

					chunk_printf(&msg, "\"");
				}

				chunk_printf(&msg,
				     "><a name=\"%s/%s\"></a>"
				     "<a class=lfsb href=\"#%s/%s\">%s</a></td>"
				     /* queue : current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     /* sessions rate : current, max, limit */
				     "<td>%s</td><td>%s</td><td></td>"
				     /* sessions: current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td"
				     "",
				     px->id, sv->id, px->id, sv->id, sv->id,
				     U2H0(sv->nbpend), U2H1(sv->counters.nbpend_max), LIM2A2(sv->maxqueue, "-"),
				     U2H3(read_freq_ctr(&sv->sess_per_sec)), U2H4(sv->counters.sps_max),
				     U2H5(sv->cur_sess), U2H6(sv->counters.cur_sess_max), LIM2A7(sv->maxconn, "-"));

				/* http response (via td title): 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					chunk_printf(&msg, " title=\"rsp codes:");

					for (i = 1; i < 6; i++)
						chunk_printf(&msg, " %dxx=%lld,", i, sv->counters.p.http.rsp[i]);

					chunk_printf(&msg, " other=%lld\"", sv->counters.p.http.rsp[0]);
				}

				chunk_printf(&msg,
				     /* sessions: total, lbtot */
				     ">%s</td><td>%s</td>",
				     U2H0(sv->counters.cum_sess), U2H1(sv->counters.cum_lbconn));

				chunk_printf(&msg,
				     /* bytes : in, out */
				     "<td>%s</td><td>%s</td>"
				     /* denied: req, resp */
				     "<td></td><td>%s</td>"
				     /* errors : request, connect, response */
				     "<td></td><td>%s</td><td>%s</td>\n"
				     /* warnings: retries, redispatches */
				     "<td>%lld</td><td>%lld</td>"
				     "",
				     U2H0(sv->counters.bytes_in), U2H1(sv->counters.bytes_out),
				     U2H2(sv->counters.failed_secu),
				     U2H3(sv->counters.failed_conns), U2H4(sv->counters.failed_resp),
				     sv->counters.retries, sv->counters.redispatches);

				/* status, lest check */
				chunk_printf(&msg, "<td class=ac>");

				if (svs->state & SRV_CHECKED) {
					chunk_printf(&msg, "%s ",
						human_time(now.tv_sec - sv->last_change, 1));

					chunk_printf(&msg,
					     srv_hlt_st[sv_state],
					     (svs->state & SRV_RUNNING) ? (svs->health - svs->rise + 1) : (svs->health),
					     (svs->state & SRV_RUNNING) ? (svs->fall) : (svs->rise));
				}

				if (sv->state & SRV_CHECKED) {
					chunk_printf(&msg, "</td><td class=ac title=\"%s",
						get_check_status_description(sv->check_status));

					if (*sv->check_desc) {
						struct chunk src;

						chunk_printf(&msg, ": ");

						chunk_initlen(&src, sv->check_desc, 0, strlen(sv->check_desc));
						chunk_htmlencode(&msg, &src);
					}

					chunk_printf(&msg, "\"> %s%s",
						tv_iszero(&sv->check_start)?"":"* ",
						get_check_status_info(sv->check_status));

					if (sv->check_status >= HCHK_STATUS_L57DATA)
						chunk_printf(&msg, "/%d", sv->check_code);

					if (sv->check_status >= HCHK_STATUS_CHECKED && sv->check_duration >= 0)
					chunk_printf(&msg, " in %lums", sv->check_duration);
				} else
					chunk_printf(&msg, "</td><td>");

				chunk_printf(&msg,
				     /* weight */
				     "</td><td class=ac>%d</td>"
				     /* act, bck */
				     "<td class=ac>%s</td><td class=ac>%s</td>"
				     "",
				     (sv->eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     (sv->state & SRV_BACKUP) ? "-" : "Y",
				     (sv->state & SRV_BACKUP) ? "Y" : "-");

				/* check failures: unique, fatal, down time */
				if (sv->state & SRV_CHECKED) {
					chunk_printf(&msg, "<td title=\"Failed Health Checks%s\">%lld",
					     svs->observe?"/Health Analyses":"", svs->counters.failed_checks);

					if (svs->observe)
						chunk_printf(&msg, "/%lld", svs->counters.failed_hana);

					chunk_printf(&msg,
					     "</td>"
					     "<td>%lld</td><td>%s</td>"
					     "",
					     svs->counters.down_trans, human_time(srv_downtime(sv), 1));
				} else if (sv != svs)
					chunk_printf(&msg,
					     "<td class=ac colspan=3><a class=lfsb href=\"#%s/%s\">via %s/%s<a></td>",
							svs->proxy->id, svs->id, svs->proxy->id, svs->id);
				else
					chunk_printf(&msg,
					     "<td colspan=3></td>");

				/* throttle */
				if ((sv->state & SRV_WARMINGUP) &&
				    now.tv_sec < sv->last_change + sv->slowstart &&
				    now.tv_sec >= sv->last_change) {
					unsigned int ratio;
					ratio = MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart);
					chunk_printf(&msg,
						     "<td class=ac>%d %%</td></tr>\n", ratio);
				} else {
					chunk_printf(&msg,
						     "<td class=ac>-</td></tr>\n");
				}
			} else {
				static char *srv_hlt_st[7] = { "DOWN,", "DOWN %d/%d,",
							       "UP %d/%d,", "UP,",
							       "NOLB %d/%d,", "NOLB,",
							       "no check," };
				chunk_printf(&msg,
				     /* pxid, name */
				     "%s,%s,"
				     /* queue : current, max */
				     "%d,%d,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%s,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     ",%lld,"
				     /* errors : request, connect, response */
				     ",%lld,%lld,"
				     /* warnings: retries, redispatches */
				     "%lld,%lld,"
				     "",
				     px->id, sv->id,
				     sv->nbpend, sv->counters.nbpend_max,
				     sv->cur_sess, sv->counters.cur_sess_max, LIM2A0(sv->maxconn, ""), sv->counters.cum_sess,
				     sv->counters.bytes_in, sv->counters.bytes_out,
				     sv->counters.failed_secu,
				     sv->counters.failed_conns, sv->counters.failed_resp,
				     sv->counters.retries, sv->counters.redispatches);

				/* status */
				chunk_printf(&msg,
				     srv_hlt_st[sv_state],
				     (sv->state & SRV_RUNNING) ? (sv->health - sv->rise + 1) : (sv->health),
				     (sv->state & SRV_RUNNING) ? (sv->fall) : (sv->rise));

				chunk_printf(&msg,
				     /* weight, active, backup */
				     "%d,%d,%d,"
				     "",
				     (sv->eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     (sv->state & SRV_BACKUP) ? 0 : 1,
				     (sv->state & SRV_BACKUP) ? 1 : 0);

				/* check failures: unique, fatal; last change, total downtime */
				if (sv->state & SRV_CHECKED)
					chunk_printf(&msg,
					     "%lld,%lld,%d,%d,",
					     sv->counters.failed_checks, sv->counters.down_trans,
					     (int)(now.tv_sec - sv->last_change), srv_downtime(sv));
				else
					chunk_printf(&msg,
					     ",,,,");

				/* queue limit, pid, iid, sid, */
				chunk_printf(&msg,
				     "%s,"
				     "%d,%d,%d,",
				     LIM2A0(sv->maxqueue, ""),
				     relative_pid, px->uuid, sv->puid);

				/* throttle */
				if ((sv->state & SRV_WARMINGUP) &&
				    now.tv_sec < sv->last_change + sv->slowstart &&
				    now.tv_sec >= sv->last_change) {
					unsigned int ratio;
					ratio = MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart);
					chunk_printf(&msg, "%d", ratio);
				}

				/* sessions: lbtot */
				chunk_printf(&msg, ",%lld,", sv->counters.cum_lbconn);

				/* tracked */
				if (sv->tracked)
					chunk_printf(&msg, "%s/%s,",
						sv->tracked->proxy->id, sv->tracked->id);
				else
					chunk_printf(&msg, ",");

				/* type */
				chunk_printf(&msg, "%d,", STATS_TYPE_SV);

				/* rate */
				chunk_printf(&msg, "%u,,%u,",
					     read_freq_ctr(&sv->sess_per_sec),
					     sv->counters.sps_max);

				if (sv->state & SRV_CHECKED) {
					/* check_status */
					chunk_printf(&msg, "%s,", get_check_status_info(sv->check_status));

					/* check_code */
					if (sv->check_status >= HCHK_STATUS_L57DATA)
						chunk_printf(&msg, "%u,", sv->check_code);
					else
						chunk_printf(&msg, ",");

					/* check_duration */
					if (sv->check_status >= HCHK_STATUS_CHECKED)
						chunk_printf(&msg, "%lu,", sv->check_duration);
					else
						chunk_printf(&msg, ",");

				} else {
					chunk_printf(&msg, ",,,");
				}

				/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					for (i=1; i<6; i++)
						chunk_printf(&msg, "%lld,", sv->counters.p.http.rsp[i]);

					chunk_printf(&msg, "%lld,", sv->counters.p.http.rsp[0]);
				} else {
					chunk_printf(&msg, ",,,,,,");
				}

				/* failed health analyses */
				chunk_printf(&msg, "%lld,",  sv->counters.failed_hana);

				/* finish with EOL */
				chunk_printf(&msg, "\n");
			}
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		} /* for sv */

		s->data_ctx.stats.px_st = DATA_ST_PX_BE;
		/* fall through */

	case DATA_ST_PX_BE:
		/* print the backend */
		if ((px->cap & PR_CAP_BE) &&
		    (!(s->data_ctx.stats.flags & STAT_BOUND) || (s->data_ctx.stats.type & (1 << STATS_TYPE_BE)))) {
			if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg,
				     /* name */
				     "<tr class=\"backend\"><td class=ac");

				if (uri->flags&ST_SHLGNDS) {
					/* balancing */
					 chunk_printf(&msg, " title=\"balancing: %s",
						 backend_lb_algo_str(px->lbprm.algo & BE_LB_ALGO));

					/* cookie */
					if (px->cookie_name) {
						struct chunk src;

						chunk_printf(&msg, ", cookie: '");

						chunk_initlen(&src, px->cookie_name, 0, strlen(px->cookie_name));
						chunk_htmlencode(&msg, &src);

						chunk_printf(&msg, "'");
					}

					chunk_printf(&msg, "\"");

				}

				chunk_printf(&msg,
				     "><a name=\"%s/Backend\"></a>"
				     "<a class=lfsb href=\"#%s/Backend\">Backend</a></td>"
				     /* queue : current, max */
				     "<td>%s</td><td>%s</td><td></td>"
				     /* sessions rate : current, max, limit */
				     "<td>%s</td><td>%s</td><td></td>"
				     "",
				     px->id, px->id,
				     U2H0(px->nbpend) /* or px->totpend ? */, U2H1(px->counters.nbpend_max),
				     U2H2(read_freq_ctr(&px->be_sess_per_sec)), U2H3(px->counters.be_sps_max));

				chunk_printf(&msg,
				     /* sessions: current, max, limit */
				     "<td>%s</td><td>%s</td><td>%s</td>"
				     "<td"
				     "",
				     U2H2(px->beconn), U2H3(px->counters.beconn_max), U2H4(px->fullconn));

				/* http response (via td title): 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					chunk_printf(&msg, " title=\"rsp codes:");

					for (i = 1; i < 6; i++)
						chunk_printf(&msg, " %dxx=%lld", i, px->counters.p.http.rsp[i]);

					chunk_printf(&msg, " other=%lld\"", px->counters.p.http.rsp[0]);
				}

				chunk_printf(&msg,
				     /* sessions: total, lbtot */
				     ">%s</td><td>%s</td>"
				     /* bytes: in, out */
				     "<td>%s</td><td>%s</td>"
				     "",
				     U2H6(px->counters.cum_beconn), U2H7(px->counters.cum_lbconn),
				     U2H8(px->counters.bytes_in), U2H9(px->counters.bytes_out));

				chunk_printf(&msg,
				     /* denied: req, resp */
				     "<td>%s</td><td>%s</td>"
				     /* errors : request, connect, response */
				     "<td></td><td>%s</td><td>%s</td>\n"
				     /* warnings: retries, redispatches */
				     "<td>%lld</td><td>%lld</td>"
				     /* backend status: reflect backend status (up/down): we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Then we display the total weight, number of
				      * active and backups. */
				     "<td class=ac>%s %s</td><td class=ac>&nbsp;</td><td class=ac>%d</td>"
				     "<td class=ac>%d</td><td class=ac>%d</td>"
				     "",
				     U2H0(px->counters.denied_req), U2H1(px->counters.denied_resp),
				     U2H2(px->counters.failed_conns), U2H3(px->counters.failed_resp),
				     px->counters.retries, px->counters.redispatches,
				     human_time(now.tv_sec - px->last_change, 1),
				     (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" :
					     "<font color=\"red\"><b>DOWN</b></font>",
				     (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     px->srv_act, px->srv_bck);

				chunk_printf(&msg,
				     /* rest of backend: nothing, down transitions, total downtime, throttle */
				     "<td class=ac>&nbsp;</td><td>%d</td>"
				     "<td>%s</td>"
				     "<td></td>"
				     "</tr>",
				     px->down_trans,
				     px->srv?human_time(be_downtime(px), 1):"&nbsp;");
			} else {
				chunk_printf(&msg,
				     /* pxid, name */
				     "%s,BACKEND,"
				     /* queue : current, max */
				     "%d,%d,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors : request, connect, response */
				     ",%lld,%lld,"
				     /* warnings: retries, redispatches */
				     "%lld,%lld,"
				     /* backend status: reflect backend status (up/down): we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Then we display the total weight, number of
				      * active and backups. */
				     "%s,"
				     "%d,%d,%d,"
				     /* rest of backend: nothing, down transitions, last change, total downtime */
				     ",%d,%d,%d,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,0,,%lld,,%d,"
				     /* rate, rate_lim, rate_max, */
				     "%u,,%u,"
				     /* check_status, check_code, check_duration */
				     ",,,",
				     px->id,
				     px->nbpend /* or px->totpend ? */, px->counters.nbpend_max,
				     px->beconn, px->counters.beconn_max, px->fullconn, px->counters.cum_beconn,
				     px->counters.bytes_in, px->counters.bytes_out,
				     px->counters.denied_req, px->counters.denied_resp,
				     px->counters.failed_conns, px->counters.failed_resp,
				     px->counters.retries, px->counters.redispatches,
				     (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" : "DOWN",
				     (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     px->srv_act, px->srv_bck,
				     px->down_trans, (int)(now.tv_sec - px->last_change),
				     px->srv?be_downtime(px):0,
				     relative_pid, px->uuid,
				     px->counters.cum_lbconn, STATS_TYPE_BE,
				     read_freq_ctr(&px->be_sess_per_sec),
				     px->counters.be_sps_max);

				/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
				if (px->mode == PR_MODE_HTTP) {
					int i;

					for (i=1; i<6; i++)
						chunk_printf(&msg, "%lld,", px->counters.p.http.rsp[i]);

					chunk_printf(&msg, "%lld,", px->counters.p.http.rsp[0]);
				} else {
					chunk_printf(&msg, ",,,,,,");
				}

				/* failed health analyses */
				chunk_printf(&msg, ",");

				/* finish with EOL */
				chunk_printf(&msg, "\n");

			}
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_END;
		/* fall through */

	case DATA_ST_PX_END:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg, "</table><p>\n");

			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_FIN;
		/* fall through */

	case DATA_ST_PX_FIN:
		return 1;

	default:
		/* unknown state, we should put an abort() here ! */
		return 1;
	}
}


/* This function is called to send output to the response buffer.
 * It dumps the sessions states onto the output buffer <rep>.
 * Expects to be called with client socket shut down on input.
 * s->data_ctx must have been zeroed first, and the flags properly set.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 */
int stats_dump_sess_to_buffer(struct session *s, struct buffer *rep)
{
	struct chunk msg;

	if (unlikely(rep->flags & (BF_WRITE_ERROR|BF_SHUTW))) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last session being dumped.
		 */
		if (s->data_state == DATA_ST_LIST) {
			if (!LIST_ISEMPTY(&s->data_ctx.sess.bref.users)) {
				LIST_DEL(&s->data_ctx.sess.bref.users);
				LIST_INIT(&s->data_ctx.sess.bref.users);
			}
		}
		return 1;
	}

	chunk_init(&msg, trash, sizeof(trash));

	switch (s->data_state) {
	case DATA_ST_INIT:
		/* the function had not been called yet, let's prepare the
		 * buffer for a response. We initialize the current session
		 * pointer to the first in the global list. When a target
		 * session is being destroyed, it is responsible for updating
		 * this pointer. We know we have reached the end when this
		 * pointer points back to the head of the sessions list.
		 */
		LIST_INIT(&s->data_ctx.sess.bref.users);
		s->data_ctx.sess.bref.ref = sessions.n;
		s->data_state = DATA_ST_LIST;
		/* fall through */

	case DATA_ST_LIST:
		/* first, let's detach the back-ref from a possible previous session */
		if (!LIST_ISEMPTY(&s->data_ctx.sess.bref.users)) {
			LIST_DEL(&s->data_ctx.sess.bref.users);
			LIST_INIT(&s->data_ctx.sess.bref.users);
		}

		/* and start from where we stopped */
		while (s->data_ctx.sess.bref.ref != &sessions) {
			char pn[INET6_ADDRSTRLEN + strlen(":65535")];
			struct session *curr_sess;

			curr_sess = LIST_ELEM(s->data_ctx.sess.bref.ref, struct session *, list);

			chunk_printf(&msg,
				     "%p: proto=%s",
				     curr_sess,
				     curr_sess->listener->proto->name);

			switch (curr_sess->listener->proto->sock_family) {
			case AF_INET:
				inet_ntop(AF_INET,
					  (const void *)&((struct sockaddr_in *)&curr_sess->cli_addr)->sin_addr,
					  pn, sizeof(pn));

				chunk_printf(&msg,
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     ntohs(((struct sockaddr_in *)&curr_sess->cli_addr)->sin_port),
					     curr_sess->fe->id,
					     curr_sess->be->id,
					     curr_sess->srv ? curr_sess->srv->id : "<none>"
					     );
				break;
			case AF_INET6:
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&curr_sess->cli_addr))->sin6_addr,
					  pn, sizeof(pn));

				chunk_printf(&msg,
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     ntohs(((struct sockaddr_in6 *)&curr_sess->cli_addr)->sin6_port),
					     curr_sess->fe->id,
					     curr_sess->be->id,
					     curr_sess->srv ? curr_sess->srv->id : "<none>"
					     );

				break;
			case AF_UNIX:
				/* no more information to print right now */
				break;
			}

			chunk_printf(&msg,
				     " ts=%02x age=%s calls=%d",
				     curr_sess->task->state,
				     human_time(now.tv_sec - curr_sess->logs.tv_accept.tv_sec, 1),
				     curr_sess->task->calls);

			chunk_printf(&msg,
				     " rq[f=%06xh,l=%d,an=%02xh,rx=%s",
				     curr_sess->req->flags,
				     curr_sess->req->l,
				     curr_sess->req->analysers,
				     curr_sess->req->rex ?
				     human_time(TICKS_TO_MS(curr_sess->req->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",wx=%s",
				     curr_sess->req->wex ?
				     human_time(TICKS_TO_MS(curr_sess->req->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",ax=%s]",
				     curr_sess->req->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->req->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " rp[f=%06xh,l=%d,an=%02xh,rx=%s",
				     curr_sess->rep->flags,
				     curr_sess->rep->l,
				     curr_sess->rep->analysers,
				     curr_sess->rep->rex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",wx=%s",
				     curr_sess->rep->wex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     ",ax=%s]",
				     curr_sess->rep->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->rep->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " s0=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[0].state,
				     curr_sess->si[0].flags,
				     curr_sess->si[0].fd,
				     curr_sess->si[0].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[0].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " s1=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[1].state,
				     curr_sess->si[1].flags,
				     curr_sess->si[1].fd,
				     curr_sess->si[1].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[1].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg,
				     " exp=%s",
				     curr_sess->task->expire ?
				     human_time(TICKS_TO_MS(curr_sess->task->expire - now_ms),
						TICKS_TO_MS(1000)) : "");
			if (task_in_rq(curr_sess->task))
				chunk_printf(&msg, " run(nice=%d)", curr_sess->task->nice);

			chunk_printf(&msg, "\n");

			if (buffer_feed_chunk(rep, &msg) >= 0) {
				/* let's try again later from this session. We add ourselves into
				 * this session's users so that it can remove us upon termination.
				 */
				LIST_ADDQ(&curr_sess->back_refs, &s->data_ctx.sess.bref.users);
				return 0;
			}

			s->data_ctx.sess.bref.ref = curr_sess->list.n;
		}
		s->data_state = DATA_ST_FIN;
		/* fall through */

	default:
		s->data_state = DATA_ST_FIN;
		return 1;
	}
}

/* print a line of error buffer (limited to 70 bytes) to <out>. The format is :
 * <2 spaces> <offset=5 digits> <space or plus> <space> <70 chars max> <\n>
 * which is 60 chars per line. Non-printable chars \t, \n, \r and \e are
 * encoded in C format. Other non-printable chars are encoded "\xHH". Original
 * lines are respected within the limit of 70 output chars. Lines that are
 * continuation of a previous truncated line begin with "+" instead of " "
 * after the offset. The new pointer is returned.
 */
static int dump_error_line(struct chunk *out, struct error_snapshot *err,
				int *line, int ptr)
{
	int end;
	unsigned char c;

	end = out->len + 80;
	if (end > out->size)
		return ptr;

	chunk_printf(out, "  %05d%c ", ptr, (ptr == *line) ? ' ' : '+');

	while (ptr < err->len && ptr < sizeof(err->buf)) {
		c = err->buf[ptr];
		if (isprint(c) && isascii(c) && c != '\\') {
			if (out->len > end - 2)
				break;
			out->str[out->len++] = c;
		} else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\') {
			if (out->len > end - 3)
				break;
			out->str[out->len++] = '\\';
			switch (c) {
			case '\t': c = 't'; break;
			case '\n': c = 'n'; break;
			case '\r': c = 'r'; break;
			case '\e': c = 'e'; break;
			case '\\': c = '\\'; break;
			}
			out->str[out->len++] = c;
		} else {
			if (out->len > end - 5)
				break;
			out->str[out->len++] = '\\';
			out->str[out->len++] = 'x';
			out->str[out->len++] = hextab[(c >> 4) & 0xF];
			out->str[out->len++] = hextab[c & 0xF];
		}
		if (err->buf[ptr++] == '\n') {
			/* we had a line break, let's return now */
			out->str[out->len++] = '\n';
			*line = ptr;
			return ptr;
		}
	}
	/* we have an incomplete line, we return it as-is */
	out->str[out->len++] = '\n';
	return ptr;
}

/* This function is called to send output to the response buffer.
 * It dumps the errors logged in proxies onto the output buffer <rep>.
 * Expects to be called with client socket shut down on input.
 * s->data_ctx must have been zeroed first, and the flags properly set.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 */
int stats_dump_errors_to_buffer(struct session *s, struct buffer *rep)
{
	extern const char *monthname[12];
	struct chunk msg;

	if (unlikely(rep->flags & (BF_WRITE_ERROR|BF_SHUTW)))
		return 1;

	chunk_init(&msg, trash, sizeof(trash));

	if (!s->data_ctx.errors.px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		s->data_ctx.errors.px = proxy;
		s->data_ctx.errors.buf = 0;
		s->data_ctx.errors.bol = 0;
		s->data_ctx.errors.ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (s->data_ctx.errors.px) {
		struct error_snapshot *es;

		if (s->data_ctx.errors.buf == 0)
			es = &s->data_ctx.errors.px->invalid_req;
		else
			es = &s->data_ctx.errors.px->invalid_rep;

		if (!es->when.tv_sec)
			goto next;

		if (s->data_ctx.errors.iid >= 0 &&
		    s->data_ctx.errors.px->uuid != s->data_ctx.errors.iid &&
		    es->oe->uuid != s->data_ctx.errors.iid)
			goto next;

		if (s->data_ctx.errors.ptr < 0) {
			/* just print headers now */

			char pn[INET6_ADDRSTRLEN];
			struct tm tm;

			get_localtime(es->when.tv_sec, &tm);
			chunk_printf(&msg, "\n[%02d/%s/%04d:%02d:%02d:%02d.%03d]",
				     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
				     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(es->when.tv_usec/1000));


			if (es->src.ss_family == AF_INET)
				inet_ntop(AF_INET,
					  (const void *)&((struct sockaddr_in *)&es->src)->sin_addr,
					  pn, sizeof(pn));
			else
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&es->src))->sin6_addr,
					  pn, sizeof(pn));

			switch (s->data_ctx.errors.buf) {
			case 0:
				chunk_printf(&msg,
					     " frontend %s (#%d): invalid request\n"
					     "  src %s, session #%d, backend %s (#%d), server %s (#%d)\n"
					     "  request length %d bytes, error at position %d:\n\n",
					     s->data_ctx.errors.px->id, s->data_ctx.errors.px->uuid,
					     pn, es->sid, es->oe->id, es->oe->uuid,
					     es->srv ? es->srv->id : "<NONE>",
					     es->srv ? es->srv->puid : -1,
					     es->len, es->pos);
				break;
			case 1:
				chunk_printf(&msg,
					     " backend %s (#%d) : invalid response\n"
					     "  src %s, session #%d, frontend %s (#%d), server %s (#%d)\n"
					     "  response length %d bytes, error at position %d:\n\n",
					     s->data_ctx.errors.px->id, s->data_ctx.errors.px->uuid,
					     pn, es->sid, es->oe->id, es->oe->uuid,
					     es->srv ? es->srv->id : "<NONE>",
					     es->srv ? es->srv->puid : -1,
					     es->len, es->pos);
				break;
			}

			if (buffer_feed_chunk(rep, &msg) >= 0) {
				/* Socket buffer full. Let's try again later from the same point */
				return 0;
			}
			s->data_ctx.errors.ptr = 0;
			s->data_ctx.errors.sid = es->sid;
		}

		if (s->data_ctx.errors.sid != es->sid) {
			/* the snapshot changed while we were dumping it */
			chunk_printf(&msg,
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (buffer_feed_chunk(rep, &msg) >= 0)
				return 0;
			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (s->data_ctx.errors.ptr < es->len && s->data_ctx.errors.ptr < sizeof(es->buf)) {
			int newptr;
			int newline;

			newline = s->data_ctx.errors.bol;
			newptr = dump_error_line(&msg, es, &newline, s->data_ctx.errors.ptr);
			if (newptr == s->data_ctx.errors.ptr)
				return 0;

			if (buffer_feed_chunk(rep, &msg) >= 0) {
				/* Socket buffer full. Let's try again later from the same point */
				return 0;
			}
			s->data_ctx.errors.ptr = newptr;
			s->data_ctx.errors.bol = newline;
		};
	next:
		s->data_ctx.errors.bol = 0;
		s->data_ctx.errors.ptr = -1;
		s->data_ctx.errors.buf++;
		if (s->data_ctx.errors.buf > 1) {
			s->data_ctx.errors.buf = 0;
			s->data_ctx.errors.px = s->data_ctx.errors.px->next;
		}
	}

	/* dump complete */
	return 1;
}


static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "stats", stats_parse_global },
	{ 0, NULL, NULL },
}};

__attribute__((constructor))
static void __dumpstats_module_init(void)
{
	cfg_register_keywords(&cfg_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
