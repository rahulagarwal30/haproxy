/*
 * Functions dedicated to statistics output and the stats socket
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
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
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/compression.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/pipe.h>
#include <proto/listener.h>
#include <proto/proto_http.h>
#include <proto/proto_uxst.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/server.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif

static int stats_dump_info_to_buffer(struct stream_interface *si);
static int stats_dump_full_sess_to_buffer(struct stream_interface *si, struct session *sess);
static int stats_dump_sess_to_buffer(struct stream_interface *si);
static int stats_dump_errors_to_buffer(struct stream_interface *si);
static int stats_table_request(struct stream_interface *si, int show);
static int stats_dump_proxy_to_buffer(struct stream_interface *si, struct proxy *px, struct uri_auth *uri);
static int stats_dump_stat_to_buffer(struct stream_interface *si, struct uri_auth *uri);

/*
 * cli_io_handler()
 *     -> stats_dump_sess_to_buffer()     // "show sess"
 *     -> stats_dump_errors_to_buffer()   // "show errors"
 *     -> stats_dump_info_to_buffer()     // "show info"
 *     -> stats_dump_stat_to_buffer()     // "show stat"
 *        -> stats_dump_csv_header()
 *        -> stats_dump_proxy_to_buffer()
 *           -> stats_dump_fe_stats()
 *           -> stats_dump_li_stats()
 *           -> stats_dump_sv_stats()
 *           -> stats_dump_be_stats()
 *
 * http_stats_io_handler()
 *     -> stats_dump_stat_to_buffer()     // same as above, but used for CSV or HTML
 *        -> stats_dump_csv_header()      // emits the CSV headers (same as above)
 *        -> stats_dump_html_head()       // emits the HTML headers
 *        -> stats_dump_html_info()       // emits the equivalent of "show info" at the top
 *        -> stats_dump_proxy_to_buffer() // same as above, valid for CSV and HTML
 *           -> stats_dump_html_px_hdr()
 *           -> stats_dump_fe_stats()
 *           -> stats_dump_li_stats()
 *           -> stats_dump_sv_stats()
 *           -> stats_dump_be_stats()
 *           -> stats_dump_html_px_end()
 *        -> stats_dump_html_end()       // emits HTML trailer
 */

static struct si_applet cli_applet;

static const char stats_sock_usage_msg[] =
	"Unknown command. Please enter one of the following commands only :\n"
	"  clear counters : clear max statistics counters (add 'all' for all counters)\n"
	"  clear table    : remove an entry from a table\n"
	"  help           : this message\n"
	"  prompt         : toggle interactive mode with prompt\n"
	"  quit           : disconnect\n"
	"  show info      : report information about the running process\n"
	"  show stat      : report counters for each proxy and server\n"
	"  show errors    : report last request and response errors for each proxy\n"
	"  show sess [id] : report the list of current sessions or dump this session\n"
	"  show table [id]: report table usage stats or dump this table's contents\n"
	"  get weight     : report a server's current weight\n"
	"  set weight     : change a server's weight\n"
	"  set table [id] : update or create a table entry's data\n"
	"  set timeout    : change a timeout setting\n"
	"  set maxconn    : change a maxconn setting\n"
	"  set rate-limit : change a rate limiting value\n"
	"  disable        : put a server or frontend in maintenance mode\n"
	"  enable         : re-enable a server or frontend which is in maintenance mode\n"
	"  shutdown       : kill a session or a frontend (eg:to release listening ports)\n"
	"";

static const char stats_permission_denied_msg[] =
	"Permission denied\n"
	"";

/* data transmission states for the stats responses */
enum {
	STAT_ST_INIT = 0,
	STAT_ST_HEAD,
	STAT_ST_INFO,
	STAT_ST_LIST,
	STAT_ST_END,
	STAT_ST_FIN,
};

/* data transmission states for the stats responses inside a proxy */
enum {
	STAT_PX_ST_INIT = 0,
	STAT_PX_ST_TH,
	STAT_PX_ST_FE,
	STAT_PX_ST_LI,
	STAT_PX_ST_SV,
	STAT_PX_ST_BE,
	STAT_PX_ST_END,
	STAT_PX_ST_FIN,
};

extern const char *stat_status_codes[];

/* This function is called from the session-level accept() in order to instanciate
 * a new stats socket. It returns a positive value upon success, 0 if the connection
 * needs to be closed and ignored, or a negative value upon critical failure.
 */
static int stats_accept(struct session *s)
{
	/* we have a dedicated I/O handler for the stats */
	stream_int_register_handler(&s->si[1], &cli_applet);
	s->target = s->si[1].conn->target; // for logging only
	s->si[1].conn->xprt_ctx = s;
	s->si[1].applet.st1 = 0;
	s->si[1].applet.st0 = STAT_CLI_INIT;

	tv_zero(&s->logs.tv_request);
	s->logs.t_queue = 0;
	s->logs.t_connect = 0;
	s->logs.t_data = 0;
	s->logs.t_close = 0;
	s->logs.bytes_in = s->logs.bytes_out = 0;
	s->logs.prx_queue_size = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_size = 0; /* we will get this number soon */

	s->req->flags |= CF_READ_DONTWAIT; /* we plan to read small requests */

	if (s->listener->timeout) {
		s->req->rto = *s->listener->timeout;
		s->rep->wto = *s->listener->timeout;
	}
	return 1;
}

/* allocate a new stats frontend named <name>, and return it
 * (or NULL in case of lack of memory).
 */
static struct proxy *alloc_stats_fe(const char *name, const char *file, int line)
{
	struct proxy *fe;

	fe = (struct proxy *)calloc(1, sizeof(struct proxy));
	if (!fe)
		return NULL;

	init_new_proxy(fe);
	fe->next = proxy;
	proxy = fe;
	fe->last_change = now.tv_sec;
	fe->id = strdup("GLOBAL");
	fe->cap = PR_CAP_FE;
	fe->maxconn = 10;                 /* default to 10 concurrent connections */
	fe->timeout.client = MS_TO_TICKS(10000); /* default timeout of 10 seconds */
	fe->conf.file = strdup(file);
	fe->conf.line = line;
	fe->accept = stats_accept;

	/* the stats frontend is the only one able to assign ID #0 */
	fe->conf.id.key = fe->uuid = 0;
	eb32_insert(&used_proxy_id, &fe->conf.id);
	return fe;
}

/* This function parses a "stats" statement in the "global" section. It returns
 * -1 if there is any error, otherwise zero. If it returns -1, it will write an
 * error message into the <err> buffer which will be preallocated. The trailing
 * '\n' must not be written. The function must be called with <args> pointing to
 * the first word after "stats".
 */
static int stats_parse_global(char **args, int section_type, struct proxy *curpx,
                              struct proxy *defpx, const char *file, int line,
                              char **err)
{
	struct bind_conf *bind_conf;
	struct listener *l;

	if (!strcmp(args[1], "socket")) {
		int cur_arg;

		if (*args[2] == 0) {
			memprintf(err, "'%s %s' in global section expects an address or a path to a UNIX socket", args[0], args[1]);
			return -1;
		}

		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}

		bind_conf = bind_conf_alloc(&global.stats_fe->conf.bind, file, line, args[2]);
		bind_conf->level = ACCESS_LVL_OPER; /* default access level */

		if (!str2listener(args[2], global.stats_fe, bind_conf, file, line, err)) {
			memprintf(err, "parsing [%s:%d] : '%s %s' : %s\n",
			          file, line, args[0], args[1], err && *err ? *err : "error");
			return -1;
		}

		cur_arg = 3;
		while (*args[cur_arg]) {
			static int bind_dumped;
			struct bind_kw *kw;

			kw = bind_find_kw(args[cur_arg]);
			if (kw) {
				if (!kw->parse) {
					memprintf(err, "'%s %s' : '%s' option is not implemented in this version (check build options).",
						  args[0], args[1], args[cur_arg]);
					return -1;
				}

				if (kw->parse(args, cur_arg, curpx, bind_conf, err) != 0) {
					if (err && *err)
						memprintf(err, "'%s %s' : '%s'", args[0], args[1], *err);
					else
						memprintf(err, "'%s %s' : error encountered while processing '%s'",
						          args[0], args[1], args[cur_arg]);
					return -1;
				}

				cur_arg += 1 + kw->skip;
				continue;
			}

			if (!bind_dumped) {
				bind_dump_kws(err);
				indent_msg(err, 4);
				bind_dumped = 1;
			}

			memprintf(err, "'%s %s' : unknown keyword '%s'.%s%s",
			          args[0], args[1], args[cur_arg],
			          err && *err ? " Registered keywords :" : "", err && *err ? *err : "");
			return -1;
		}

		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			l->maxconn = global.stats_fe->maxconn;
			l->backlog = global.stats_fe->backlog;
			l->timeout = &global.stats_fe->timeout.client;
			l->accept = session_accept;
			l->handler = process_session;
			l->options |= LI_O_UNLIMITED; /* don't make the peers subject to global limits */
			l->nice = -64;  /* we want to boost priority for local stats */
			global.maxsock += l->maxconn;
		}
	}
	else if (!strcmp(args[1], "timeout")) {
		unsigned timeout;
		const char *res = parse_time_err(args[2], &timeout, TIME_UNIT_MS);

		if (res) {
			memprintf(err, "'%s %s' : unexpected character '%c'", args[0], args[1], *res);
			return -1;
		}

		if (!timeout) {
			memprintf(err, "'%s %s' expects a positive value", args[0], args[1]);
			return -1;
		}
		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}
		global.stats_fe->timeout.client = MS_TO_TICKS(timeout);
	}
	else if (!strcmp(args[1], "maxconn")) {
		int maxconn = atol(args[2]);

		if (maxconn <= 0) {
			memprintf(err, "'%s %s' expects a positive value", args[0], args[1]);
			return -1;
		}

		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}
		global.stats_fe->maxconn = maxconn;
	}
	else if (!strcmp(args[1], "bind-process")) {  /* enable the socket only on some processes */
		int cur_arg = 2;
		unsigned int set = 0;

		if (!global.stats_fe) {
			if ((global.stats_fe = alloc_stats_fe("GLOBAL", file, line)) == NULL) {
				memprintf(err, "'%s %s' : out of memory trying to allocate a frontend", args[0], args[1]);
				return -1;
			}
		}

		while (*args[cur_arg]) {
			unsigned int low, high;

			if (strcmp(args[cur_arg], "all") == 0) {
				set = 0;
				break;
			}
			else if (strcmp(args[cur_arg], "odd") == 0) {
				set |= 0x55555555;
			}
			else if (strcmp(args[cur_arg], "even") == 0) {
				set |= 0xAAAAAAAA;
			}
			else if (isdigit((int)*args[cur_arg])) {
				char *dash = strchr(args[cur_arg], '-');

				low = high = str2uic(args[cur_arg]);
				if (dash)
					high = str2uic(dash + 1);

				if (high < low) {
					unsigned int swap = low;
					low = high;
					high = swap;
				}

				if (low < 1 || high > 32) {
					memprintf(err, "'%s %s' supports process numbers from 1 to 32.\n",
					          args[0], args[1]);
					return -1;
				}

				while (low <= high)
					set |= 1 << (low++ - 1);
			}
			else {
				memprintf(err,
				          "'%s %s' expects 'all', 'odd', 'even', or a list of process ranges with numbers from 1 to 32.\n",
				          args[0], args[1]);
				return -1;
			}
			cur_arg++;
		}
		global.stats_fe->bind_proc = set;
	}
	else {
		memprintf(err, "'%s' only supports 'socket', 'maxconn', 'bind-process' and 'timeout' (got '%s')", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* Dumps the stats CSV header to the trash buffer which. The caller is responsible
 * for clearing it if needed.
 */
static void stats_dump_csv_header()
{
	chunk_appendf(&trash,
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
	              "req_rate,req_rate_max,req_tot,"
	              "cli_abrt,srv_abrt,"
	              "comp_in,comp_out,comp_byp,comp_rsp,"
	              "\n");
}

/* print a string of text buffer to <out>. The format is :
 * Non-printable chars \t, \n, \r and \e are * encoded in C format.
 * Other non-printable chars are encoded "\xHH". Space and '\' are also escaped.
 * Print stopped if null char or <bsize> is reached, or if no more place in the chunk.
 */
static int dump_text(struct chunk *out, const char *buf, int bsize)
{
	unsigned char c;
	int ptr = 0;

	while (buf[ptr] && ptr < bsize) {
		c = buf[ptr];
		if (isprint(c) && isascii(c) && c != '\\' && c != ' ') {
			if (out->len > out->size - 1)
				break;
			out->str[out->len++] = c;
		}
		else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\' || c == ' ') {
			if (out->len > out->size - 2)
				break;
			out->str[out->len++] = '\\';
			switch (c) {
			case ' ': c = ' '; break;
			case '\t': c = 't'; break;
			case '\n': c = 'n'; break;
			case '\r': c = 'r'; break;
			case '\e': c = 'e'; break;
			case '\\': c = '\\'; break;
			}
			out->str[out->len++] = c;
		}
		else {
			if (out->len > out->size - 4)
				break;
			out->str[out->len++] = '\\';
			out->str[out->len++] = 'x';
			out->str[out->len++] = hextab[(c >> 4) & 0xF];
			out->str[out->len++] = hextab[c & 0xF];
		}
		ptr++;
	}

	return ptr;
}

/* print a buffer in hexa.
 * Print stopped if <bsize> is reached, or if no more place in the chunk.
 */
static int dump_binary(struct chunk *out, const char *buf, int bsize)
{
	unsigned char c;
	int ptr = 0;

	while (ptr < bsize) {
		c = buf[ptr];

		if (out->len > out->size - 2)
			break;
		out->str[out->len++] = hextab[(c >> 4) & 0xF];
		out->str[out->len++] = hextab[c & 0xF];

		ptr++;
	}
	return ptr;
}

/* Dump the status of a table to a stream interface's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int stats_dump_table_head_to_buffer(struct chunk *msg, struct stream_interface *si,
					   struct proxy *proxy, struct proxy *target)
{
	struct session *s = si->conn->xprt_ctx;

	chunk_appendf(msg, "# table: %s, type: %s, size:%d, used:%d\n",
		     proxy->id, stktable_types[proxy->table.type].kw, proxy->table.size, proxy->table.current);

	/* any other information should be dumped here */

	if (target && s->listener->bind_conf->level < ACCESS_LVL_OPER)
		chunk_appendf(msg, "# contents not dumped due to insufficient privileges\n");

	if (bi_putchk(si->ib, msg) == -1)
		return 0;

	return 1;
}

/* Dump the a table entry to a stream interface's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int stats_dump_table_entry_to_buffer(struct chunk *msg, struct stream_interface *si,
					    struct proxy *proxy, struct stksess *entry)
{
	int dt;

	chunk_appendf(msg, "%p:", entry);

	if (proxy->table.type == STKTABLE_TYPE_IP) {
		char addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == STKTABLE_TYPE_IPV6) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == STKTABLE_TYPE_INTEGER) {
		chunk_appendf(msg, " key=%u", *(unsigned int *)entry->key.key);
	}
	else if (proxy->table.type == STKTABLE_TYPE_STRING) {
		chunk_appendf(msg, " key=");
		dump_text(msg, (const char *)entry->key.key, proxy->table.key_size);
	}
	else {
		chunk_appendf(msg, " key=");
		dump_binary(msg, (const char *)entry->key.key, proxy->table.key_size);
	}

	chunk_appendf(msg, " use=%d exp=%d", entry->ref_cnt - 1, tick_remain(now_ms, entry->expire));

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {
		void *ptr;

		if (proxy->table.data_ofs[dt] == 0)
			continue;
		if (stktable_data_types[dt].arg_type == ARG_T_DELAY)
			chunk_appendf(msg, " %s(%d)=", stktable_data_types[dt].name, proxy->table.data_arg[dt].u);
		else
			chunk_appendf(msg, " %s=", stktable_data_types[dt].name);

		ptr = stktable_data_ptr(&proxy->table, entry, dt);
		switch (stktable_data_types[dt].std_type) {
		case STD_T_SINT:
			chunk_appendf(msg, "%d", stktable_data_cast(ptr, std_t_sint));
			break;
		case STD_T_UINT:
			chunk_appendf(msg, "%u", stktable_data_cast(ptr, std_t_uint));
			break;
		case STD_T_ULL:
			chunk_appendf(msg, "%lld", stktable_data_cast(ptr, std_t_ull));
			break;
		case STD_T_FRQP:
			chunk_appendf(msg, "%d",
				     read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
							  proxy->table.data_arg[dt].u));
			break;
		}
	}
	chunk_appendf(msg, "\n");

	if (bi_putchk(si->ib, msg) == -1)
		return 0;

	return 1;
}

static void stats_sock_table_key_request(struct stream_interface *si, char **args, int action)
{
	struct session *s = si->conn->xprt_ctx;
	struct proxy *px = si->applet.ctx.table.target;
	struct stksess *ts;
	uint32_t uint32_key;
	unsigned char ip6_key[sizeof(struct in6_addr)];
	long long value;
	int data_type;
	void *ptr;
	struct freq_ctr_period *frqp;

	si->applet.st0 = STAT_CLI_OUTPUT;

	if (!*args[4]) {
		si->applet.ctx.cli.msg = "Key value expected\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	switch (px->table.type) {
	case STKTABLE_TYPE_IP:
		uint32_key = htonl(inetaddr_host(args[4]));
		static_table_key->key = &uint32_key;
		break;
	case STKTABLE_TYPE_IPV6:
		inet_pton(AF_INET6, args[4], ip6_key);
		static_table_key->key = &ip6_key;
		break;
	case STKTABLE_TYPE_INTEGER:
		{
			char *endptr;
			unsigned long val;
			errno = 0;
			val = strtoul(args[4], &endptr, 10);
			if ((errno == ERANGE && val == ULONG_MAX) ||
			    (errno != 0 && val == 0) || endptr == args[4] ||
			    val > 0xffffffff) {
				si->applet.ctx.cli.msg = "Invalid key\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return;
			}
			uint32_key = (uint32_t) val;
			static_table_key->key = &uint32_key;
			break;
		}
		break;
	case STKTABLE_TYPE_STRING:
		static_table_key->key = args[4];
		static_table_key->key_len = strlen(args[4]);
		break;
	default:
		switch (action) {
		case STAT_CLI_O_TAB:
			si->applet.ctx.cli.msg = "Showing keys from tables of type other than ip, ipv6, string and integer is not supported\n";
			break;
		case STAT_CLI_O_CLR:
			si->applet.ctx.cli.msg = "Removing keys from ip tables of type other than ip, ipv6, string and integer is not supported\n";
			break;
		default:
			si->applet.ctx.cli.msg = "Unknown action\n";
			break;
		}
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	/* check permissions */
	if (s->listener->bind_conf->level < ACCESS_LVL_OPER) {
		si->applet.ctx.cli.msg = stats_permission_denied_msg;
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	ts = stktable_lookup_key(&px->table, static_table_key);

	switch (action) {
	case STAT_CLI_O_TAB:
		if (!ts)
			return;
		chunk_reset(&trash);
		if (!stats_dump_table_head_to_buffer(&trash, si, px, px))
			return;
		stats_dump_table_entry_to_buffer(&trash, si, px, ts);
		return;

	case STAT_CLI_O_CLR:
		if (!ts)
			return;
		if (ts->ref_cnt) {
			/* don't delete an entry which is currently referenced */
			si->applet.ctx.cli.msg = "Entry currently in use, cannot remove\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return;
		}
		stksess_kill(&px->table, ts);
		break;

	case STAT_CLI_O_SET:
		if (strncmp(args[5], "data.", 5) != 0) {
			si->applet.ctx.cli.msg = "\"data.<type>\" followed by a value expected\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return;
		}

		data_type = stktable_get_data_type(args[5] + 5);
		if (data_type < 0) {
			si->applet.ctx.cli.msg = "Unknown data type\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return;
		}

		if (!px->table.data_ofs[data_type]) {
			si->applet.ctx.cli.msg = "Data type not stored in this table\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return;
		}

		if (!*args[6] || strl2llrc(args[6], strlen(args[6]), &value) != 0) {
			si->applet.ctx.cli.msg = "Require a valid integer value to store\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return;
		}

		if (ts)
			stktable_touch(&px->table, ts, 1);
		else {
			ts = stksess_new(&px->table, static_table_key);
			if (!ts) {
				/* don't delete an entry which is currently referenced */
				si->applet.ctx.cli.msg = "Unable to allocate a new entry\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return;
			}
			stktable_store(&px->table, ts, 1);
		}

		ptr = stktable_data_ptr(&px->table, ts, data_type);
		switch (stktable_data_types[data_type].std_type) {
		case STD_T_SINT:
			stktable_data_cast(ptr, std_t_sint) = value;
			break;
		case STD_T_UINT:
			stktable_data_cast(ptr, std_t_uint) = value;
			break;
		case STD_T_ULL:
			stktable_data_cast(ptr, std_t_ull) = value;
			break;
		case STD_T_FRQP:
			/* We set both the current and previous values. That way
			 * the reported frequency is stable during all the period
			 * then slowly fades out. This allows external tools to
			 * push measures without having to update them too often.
			 */
			frqp = &stktable_data_cast(ptr, std_t_frqp);
			frqp->curr_tick = now_ms;
			frqp->prev_ctr = 0;
			frqp->curr_ctr = value;
			break;
		}
		break;

	default:
		si->applet.ctx.cli.msg = "Unknown action\n";
		si->applet.st0 = STAT_CLI_PRINT;
		break;
	}
}

static void stats_sock_table_data_request(struct stream_interface *si, char **args, int action)
{
	if (action != STAT_CLI_O_TAB && action != STAT_CLI_O_CLR) {
		si->applet.ctx.cli.msg = "content-based lookup is only supported with the \"show\" and \"clear\" actions";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	/* condition on stored data value */
	si->applet.ctx.table.data_type = stktable_get_data_type(args[3] + 5);
	if (si->applet.ctx.table.data_type < 0) {
		si->applet.ctx.cli.msg = "Unknown data type\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	if (!((struct proxy *)si->applet.ctx.table.target)->table.data_ofs[si->applet.ctx.table.data_type]) {
		si->applet.ctx.cli.msg = "Data type not stored in this table\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	si->applet.ctx.table.data_op = get_std_op(args[4]);
	if (si->applet.ctx.table.data_op < 0) {
		si->applet.ctx.cli.msg = "Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}

	if (!*args[5] || strl2llrc(args[5], strlen(args[5]), &si->applet.ctx.table.value) != 0) {
		si->applet.ctx.cli.msg = "Require a valid integer value to compare against\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return;
	}
}

static void stats_sock_table_request(struct stream_interface *si, char **args, int action)
{
	si->applet.ctx.table.data_type = -1;
	si->conn->xprt_st = STAT_ST_INIT;
	si->applet.ctx.table.target = NULL;
	si->applet.ctx.table.proxy = NULL;
	si->applet.ctx.table.entry = NULL;
	si->applet.st0 = action;

	if (*args[2]) {
		si->applet.ctx.table.target = find_stktable(args[2]);
		if (!si->applet.ctx.table.target) {
			si->applet.ctx.cli.msg = "No such table\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return;
		}
	}
	else {
		if (action != STAT_CLI_O_TAB)
			goto err_args;
		return;
	}

	if (strcmp(args[3], "key") == 0)
		stats_sock_table_key_request(si, args, action);
	else if (strncmp(args[3], "data.", 5) == 0)
		stats_sock_table_data_request(si, args, action);
	else if (*args[3])
		goto err_args;

	return;

err_args:
	switch (action) {
	case STAT_CLI_O_TAB:
		si->applet.ctx.cli.msg = "Optional argument only supports \"data.<store_data_type>\" <operator> <value> and key <key>\n";
		break;
	case STAT_CLI_O_CLR:
		si->applet.ctx.cli.msg = "Required arguments: <table> \"data.<store_data_type>\" <operator> <value> or <table> key <key>\n";
		break;
	default:
		si->applet.ctx.cli.msg = "Unknown action\n";
		break;
	}
	si->applet.st0 = STAT_CLI_PRINT;
}

/* Expects to find a frontend named <arg> and returns it, otherwise displays various
 * adequate error messages and returns NULL. This function also expects the session
 * level to be admin.
 */
static struct proxy *expect_frontend_admin(struct session *s, struct stream_interface *si, const char *arg)
{
	struct proxy *px;

	if (s->listener->bind_conf->level < ACCESS_LVL_ADMIN) {
		si->applet.ctx.cli.msg = stats_permission_denied_msg;
		si->applet.st0 = STAT_CLI_PRINT;
		return NULL;
	}

	if (!*arg) {
		si->applet.ctx.cli.msg = "A frontend name is expected.\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return NULL;
	}

	px = findproxy(arg, PR_CAP_FE);
	if (!px) {
		si->applet.ctx.cli.msg = "No such frontend.\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return NULL;
	}
	return px;
}

/* Expects to find a backend and a server in <arg> under the form <backend>/<server>,
 * and returns the pointer to the server. Otherwise, display adequate error messages
 * and returns NULL. This function also expects the session level to be admin. Note:
 * the <arg> is modified to remove the '/'.
 */
static struct server *expect_server_admin(struct session *s, struct stream_interface *si, char *arg)
{
	struct proxy *px;
	struct server *sv;
	char *line;

	if (s->listener->bind_conf->level < ACCESS_LVL_ADMIN) {
		si->applet.ctx.cli.msg = stats_permission_denied_msg;
		si->applet.st0 = STAT_CLI_PRINT;
		return NULL;
	}

	/* split "backend/server" and make <line> point to server */
	for (line = arg; *line; line++)
		if (*line == '/') {
			*line++ = '\0';
			break;
		}

	if (!*line || !*arg) {
		si->applet.ctx.cli.msg = "Require 'backend/server'.\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return NULL;
	}

	if (!get_backend_server(arg, line, &px, &sv)) {
		si->applet.ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return NULL;
	}

	if (px->state == PR_STSTOPPED) {
		si->applet.ctx.cli.msg = "Proxy is disabled.\n";
		si->applet.st0 = STAT_CLI_PRINT;
		return NULL;
	}

	return sv;
}

/* Processes the stats interpreter on the statistics socket. This function is
 * called from an applet running in a stream interface. The function returns 1
 * if the request was understood, otherwise zero. It sets si->applet.st0 to a value
 * designating the function which will have to process the request, which can
 * also be the print function to display the return message set into cli.msg.
 */
static int stats_sock_parse_request(struct stream_interface *si, char *line)
{
	struct session *s = si->conn->xprt_ctx;
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

	si->applet.ctx.stats.flags = 0;
	if (strcmp(args[0], "show") == 0) {
		if (strcmp(args[1], "stat") == 0) {
			if (*args[2] && *args[3] && *args[4]) {
				si->applet.ctx.stats.flags |= STAT_BOUND;
				si->applet.ctx.stats.iid = atoi(args[2]);
				si->applet.ctx.stats.type = atoi(args[3]);
				si->applet.ctx.stats.sid = atoi(args[4]);
			}

			si->conn->xprt_st = STAT_ST_INIT;
			si->applet.st0 = STAT_CLI_O_STAT; // stats_dump_stat_to_buffer
		}
		else if (strcmp(args[1], "info") == 0) {
			si->conn->xprt_st = STAT_ST_INIT;
			si->applet.st0 = STAT_CLI_O_INFO; // stats_dump_info_to_buffer
		}
		else if (strcmp(args[1], "sess") == 0) {
			si->conn->xprt_st = STAT_ST_INIT;
			if (s->listener->bind_conf->level < ACCESS_LVL_OPER) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
			if (*args[2] && strcmp(args[2], "all") == 0)
				si->applet.ctx.sess.target = (void *)-1;
			else if (*args[2])
				si->applet.ctx.sess.target = (void *)strtoul(args[2], NULL, 0);
			else
				si->applet.ctx.sess.target = NULL;
			si->applet.ctx.sess.section = 0; /* start with session status */
			si->applet.ctx.sess.pos = 0;
			si->applet.st0 = STAT_CLI_O_SESS; // stats_dump_sess_to_buffer
		}
		else if (strcmp(args[1], "errors") == 0) {
			if (s->listener->bind_conf->level < ACCESS_LVL_OPER) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
			if (*args[2])
				si->applet.ctx.errors.iid	= atoi(args[2]);
			else
				si->applet.ctx.errors.iid	= -1;
			si->applet.ctx.errors.px = NULL;
			si->conn->xprt_st = STAT_ST_INIT;
			si->applet.st0 = STAT_CLI_O_ERR; // stats_dump_errors_to_buffer
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, STAT_CLI_O_TAB);
		}
		else { /* neither "stat" nor "info" nor "sess" nor "errors" nor "table" */
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
			if (s->listener->bind_conf->level < ACCESS_LVL_OPER ||
			    (clrall && s->listener->bind_conf->level < ACCESS_LVL_ADMIN)) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			for (px = proxy; px; px = px->next) {
				if (clrall) {
					memset(&px->be_counters, 0, sizeof(px->be_counters));
					memset(&px->fe_counters, 0, sizeof(px->fe_counters));
				}
				else {
					px->be_counters.conn_max = 0;
					px->be_counters.p.http.rps_max = 0;
					px->be_counters.sps_max = 0;
					px->be_counters.cps_max = 0;
					px->be_counters.nbpend_max = 0;

					px->fe_counters.conn_max = 0;
					px->fe_counters.p.http.rps_max = 0;
					px->fe_counters.sps_max = 0;
					px->fe_counters.cps_max = 0;
					px->fe_counters.nbpend_max = 0;
				}

				for (sv = px->srv; sv; sv = sv->next)
					if (clrall)
						memset(&sv->counters, 0, sizeof(sv->counters));
					else {
						sv->counters.cur_sess_max = 0;
						sv->counters.nbpend_max = 0;
						sv->counters.sps_max = 0;
					}

				list_for_each_entry(li, &px->conf.listeners, by_fe)
					if (li->counters) {
						if (clrall)
							memset(li->counters, 0, sizeof(*li->counters));
						else
							li->counters->conn_max = 0;
					}
			}

			global.cps_max = 0;
			return 1;
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, STAT_CLI_O_CLR);
			/* end of processing */
			return 1;
		}
		else {
			/* unknown "clear" argument */
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
				si->applet.ctx.cli.msg = "Require 'backend/server'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!get_backend_server(args[2], line, &px, &sv)) {
				si->applet.ctx.cli.msg = px ? "No such server.\n" : "No such backend.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			/* return server's effective weight at the moment */
			snprintf(trash.str, trash.size, "%d (initial %d)\n", sv->uweight, sv->iweight);
			bi_putstr(si->ib, trash.str);
			return 1;
		}
		else { /* not "get weight" */
			return 0;
		}
	}
	else if (strcmp(args[0], "set") == 0) {
		if (strcmp(args[1], "weight") == 0) {
			struct server *sv;
			const char *warning;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			warning = server_parse_weight_change_request(sv, args[3]);
			if (warning) {
				si->applet.ctx.cli.msg = warning;
				si->applet.st0 = STAT_CLI_PRINT;
			}
			return 1;
		}
		else if (strcmp(args[1], "timeout") == 0) {
			if (strcmp(args[2], "cli") == 0) {
				unsigned timeout;
				const char *res;

				if (!*args[3]) {
					si->applet.ctx.cli.msg = "Expects an integer value.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				res = parse_time_err(args[3], &timeout, TIME_UNIT_S);
				if (res || timeout < 1) {
					si->applet.ctx.cli.msg = "Invalid timeout value.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				s->req->rto = s->rep->wto = 1 + MS_TO_TICKS(timeout*1000);
				return 1;
			}
			else {
				si->applet.ctx.cli.msg = "'set timeout' only supports 'cli'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else if (strcmp(args[1], "maxconn") == 0) {
			if (strcmp(args[2], "frontend") == 0) {
				struct proxy *px;
				struct listener *l;
				int v;

				px = expect_frontend_admin(s, si, args[3]);
				if (!px)
					return 1;

				if (!*args[4]) {
					si->applet.ctx.cli.msg = "Integer value expected.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				v = atoi(args[4]);
				if (v < 0) {
					si->applet.ctx.cli.msg = "Value out of range.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				/* OK, the value is fine, so we assign it to the proxy and to all of
				 * its listeners. The blocked ones will be dequeued.
				 */
				px->maxconn = v;
				list_for_each_entry(l, &px->conf.listeners, by_fe) {
					l->maxconn = v;
					if (l->state == LI_FULL)
						resume_listener(l);
				}

				if (px->maxconn > px->feconn && !LIST_ISEMPTY(&s->fe->listener_queue))
					dequeue_all_listeners(&s->fe->listener_queue);

				return 1;
			}
			else if (strcmp(args[2], "global") == 0) {
				int v;

				if (s->listener->bind_conf->level < ACCESS_LVL_ADMIN) {
					si->applet.ctx.cli.msg = stats_permission_denied_msg;
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				if (!*args[3]) {
					si->applet.ctx.cli.msg = "Expects an integer value.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				v = atoi(args[3]);
				if (v > global.hardmaxconn) {
					si->applet.ctx.cli.msg = "Value out of range.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}

				/* check for unlimited values */
				if (v <= 0)
					v = global.hardmaxconn;

				global.maxconn = v;

				/* Dequeues all of the listeners waiting for a resource */
				if (!LIST_ISEMPTY(&global_listener_queue))
					dequeue_all_listeners(&global_listener_queue);

				return 1;
			}
			else {
				si->applet.ctx.cli.msg = "'set maxconn' only supports 'frontend' and 'global'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else if (strcmp(args[1], "rate-limit") == 0) {
			if (strcmp(args[2], "connections") == 0) {
				if (strcmp(args[3], "global") == 0) {
					int v;

					if (s->listener->bind_conf->level < ACCESS_LVL_ADMIN) {
						si->applet.ctx.cli.msg = stats_permission_denied_msg;
						si->applet.st0 = STAT_CLI_PRINT;
						return 1;
					}

					if (!*args[4]) {
						si->applet.ctx.cli.msg = "Expects an integer value.\n";
						si->applet.st0 = STAT_CLI_PRINT;
						return 1;
					}

					v = atoi(args[4]);
					if (v < 0) {
						si->applet.ctx.cli.msg = "Value out of range.\n";
						si->applet.st0 = STAT_CLI_PRINT;
						return 1;
					}

					global.cps_lim = v;

					/* Dequeues all of the listeners waiting for a resource */
					if (!LIST_ISEMPTY(&global_listener_queue))
						dequeue_all_listeners(&global_listener_queue);

					return 1;
				}
				else {
					si->applet.ctx.cli.msg = "'set rate-limit connections' only supports 'global'.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}
			}
			else if (strcmp(args[2], "http-compression") == 0) {
				if (strcmp(args[3], "global") == 0) {
					int v;

					if (!*args[4]) {
						si->applet.ctx.cli.msg = "Expects a maximum input byte rate in kB/s.\n";
						si->applet.st0 = STAT_CLI_PRINT;
						return 1;
					}

					v = atoi(args[4]);
					global.comp_rate_lim = v * 1024; /* Kilo to bytes. */
				}
				else {
					si->applet.ctx.cli.msg = "'set rate-limit http-compression' only supports 'global'.\n";
					si->applet.st0 = STAT_CLI_PRINT;
					return 1;
				}
			}
			else {
				si->applet.ctx.cli.msg = "'set rate-limit' supports 'connections' and 'http-compression'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else if (strcmp(args[1], "table") == 0) {
			stats_sock_table_request(si, args, STAT_CLI_O_SET);
		}
		else { /* unknown "set" parameter */
			return 0;
		}
	}
	else if (strcmp(args[0], "enable") == 0) {
		if (strcmp(args[1], "server") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			if (sv->state & SRV_MAINTAIN) {
				/* The server is really in maintenance, we can change the server state */
				if (sv->track) {
					/* If this server tracks the status of another one,
					* we must restore the good status.
					*/
					if (sv->track->state & SRV_RUNNING) {
						set_server_up(sv);
						sv->health = sv->rise;	/* up, but will fall down at first failure */
					} else {
						sv->state &= ~SRV_MAINTAIN;
						set_server_down(sv);
					}
				} else {
					set_server_up(sv);
					sv->health = sv->rise;	/* up, but will fall down at first failure */
				}
			}

			return 1;
		}
		else if (strcmp(args[1], "frontend") == 0) {
			struct proxy *px;

			px = expect_frontend_admin(s, si, args[2]);
			if (!px)
				return 1;

			if (px->state == PR_STSTOPPED) {
				si->applet.ctx.cli.msg = "Frontend was previously shut down, cannot enable.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (px->state != PR_STPAUSED) {
				si->applet.ctx.cli.msg = "Frontend is already enabled.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!resume_proxy(px)) {
				si->applet.ctx.cli.msg = "Failed to resume frontend, check logs for precise cause (port conflict?).\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
			return 1;
		}
		else { /* unknown "enable" parameter */
			si->applet.ctx.cli.msg = "'enable' only supports 'frontend' and 'server'.\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return 1;
		}
	}
	else if (strcmp(args[0], "disable") == 0) {
		if (strcmp(args[1], "server") == 0) {
			struct server *sv;

			sv = expect_server_admin(s, si, args[2]);
			if (!sv)
				return 1;

			if (! (sv->state & SRV_MAINTAIN)) {
				/* Not already in maintenance, we can change the server state */
				sv->state |= SRV_MAINTAIN;
				set_server_down(sv);
			}

			return 1;
		}
		else if (strcmp(args[1], "frontend") == 0) {
			struct proxy *px;

			px = expect_frontend_admin(s, si, args[2]);
			if (!px)
				return 1;

			if (px->state == PR_STSTOPPED) {
				si->applet.ctx.cli.msg = "Frontend was previously shut down, cannot disable.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (px->state == PR_STPAUSED) {
				si->applet.ctx.cli.msg = "Frontend is already disabled.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!pause_proxy(px)) {
				si->applet.ctx.cli.msg = "Failed to pause frontend, check logs for precise cause.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
			return 1;
		}
		else { /* unknown "disable" parameter */
			si->applet.ctx.cli.msg = "'disable' only supports 'frontend' and 'server'.\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return 1;
		}
	}
	else if (strcmp(args[0], "shutdown") == 0) {
		if (strcmp(args[1], "frontend") == 0) {
			struct proxy *px;

			px = expect_frontend_admin(s, si, args[2]);
			if (!px)
				return 1;

			if (px->state == PR_STSTOPPED) {
				si->applet.ctx.cli.msg = "Frontend was already shut down.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			Warning("Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				px->id, px->fe_counters.cum_conn, px->be_counters.cum_conn);
			send_log(px, LOG_WARNING, "Proxy %s stopped (FE: %lld conns, BE: %lld conns).\n",
				 px->id, px->fe_counters.cum_conn, px->be_counters.cum_conn);
			stop_proxy(px);
			return 1;
		}
		else if (strcmp(args[1], "session") == 0) {
			struct session *sess, *ptr;

			if (s->listener->bind_conf->level < ACCESS_LVL_ADMIN) {
				si->applet.ctx.cli.msg = stats_permission_denied_msg;
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			if (!*args[2]) {
				si->applet.ctx.cli.msg = "Session pointer expected (use 'show sess').\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			ptr = (void *)strtoul(args[2], NULL, 0);

			/* first, look for the requested session in the session table */
			list_for_each_entry(sess, &sessions, list) {
				if (sess == ptr)
					break;
			}

			/* do we have the session ? */
			if (sess != ptr) {
				si->applet.ctx.cli.msg = "No such session (use 'show sess').\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}

			session_shutdown(sess, SN_ERR_KILLED);
			return 1;
		}
		else if (strcmp(args[1], "sessions") == 0) {
			if (strcmp(args[2], "server") == 0) {
				struct server *sv;
				struct session *sess, *sess_bck;

				sv = expect_server_admin(s, si, args[3]);
				if (!sv)
					return 1;

				/* kill all the session that are on this server */
				list_for_each_entry_safe(sess, sess_bck, &sv->actconns, by_srv)
					if (sess->srv_conn == sv)
						session_shutdown(sess, SN_ERR_KILLED);

				return 1;
			}
			else {
				si->applet.ctx.cli.msg = "'shutdown sessions' only supports 'server'.\n";
				si->applet.st0 = STAT_CLI_PRINT;
				return 1;
			}
		}
		else { /* unknown "disable" parameter */
			si->applet.ctx.cli.msg = "'shutdown' only supports 'frontend', 'session' and 'sessions'.\n";
			si->applet.st0 = STAT_CLI_PRINT;
			return 1;
		}
	}
	else { /* not "show" nor "clear" nor "get" nor "set" nor "enable" nor "disable" */
		return 0;
	}
	return 1;
}

/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to processes I/O from/to the stats unix socket. The system relies on a
 * state machine handling requests and various responses. We read a request,
 * then we process it and send the response, and we possibly display a prompt.
 * Then we can read again. The state is stored in si->applet.st0 and is one of the
 * STAT_CLI_* constants. si->applet.st1 is used to indicate whether prompt is enabled
 * or not.
 */
static void cli_io_handler(struct stream_interface *si)
{
	struct channel *req = si->ob;
	struct channel *res = si->ib;
	int reql;
	int len;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	while (1) {
		if (si->applet.st0 == STAT_CLI_INIT) {
			/* Stats output not initialized yet */
			memset(&si->applet.ctx.stats, 0, sizeof(si->applet.ctx.stats));
			si->applet.st0 = STAT_CLI_GETREQ;
		}
		else if (si->applet.st0 == STAT_CLI_END) {
			/* Let's close for real now. We just close the request
			 * side, the conditions below will complete if needed.
			 */
			si_shutw(si);
			break;
		}
		else if (si->applet.st0 == STAT_CLI_GETREQ) {
			/* ensure we have some output room left in the event we
			 * would want to return some info right after parsing.
			 */
			if (buffer_almost_full(si->ib->buf))
				break;

			reql = bo_getline(si->ob, trash.str, trash.size);
			if (reql <= 0) { /* closed or EOL not found */
				if (reql == 0)
					break;
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			/* seek for a possible semi-colon. If we find one, we
			 * replace it with an LF and skip only this part.
			 */
			for (len = 0; len < reql; len++)
				if (trash.str[len] == ';') {
					trash.str[len] = '\n';
					reql = len + 1;
					break;
				}

			/* now it is time to check that we have a full line,
			 * remove the trailing \n and possibly \r, then cut the
			 * line.
			 */
			len = reql - 1;
			if (trash.str[len] != '\n') {
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			if (len && trash.str[len-1] == '\r')
				len--;

			trash.str[len] = '\0';

			si->applet.st0 = STAT_CLI_PROMPT;
			if (len) {
				if (strcmp(trash.str, "quit") == 0) {
					si->applet.st0 = STAT_CLI_END;
					continue;
				}
				else if (strcmp(trash.str, "prompt") == 0)
					si->applet.st1 = !si->applet.st1;
				else if (strcmp(trash.str, "help") == 0 ||
					 !stats_sock_parse_request(si, trash.str)) {
					si->applet.ctx.cli.msg = stats_sock_usage_msg;
					si->applet.st0 = STAT_CLI_PRINT;
				}
				/* NB: stats_sock_parse_request() may have put
				 * another STAT_CLI_O_* into si->applet.st0.
				 */
			}
			else if (!si->applet.st1) {
				/* if prompt is disabled, print help on empty lines,
				 * so that the user at least knows how to enable
				 * prompt and find help.
				 */
				si->applet.ctx.cli.msg = stats_sock_usage_msg;
				si->applet.st0 = STAT_CLI_PRINT;
			}

			/* re-adjust req buffer */
			bo_skip(si->ob, reql);
			req->flags |= CF_READ_DONTWAIT; /* we plan to read small requests */
		}
		else {	/* output functions: first check if the output buffer is closed then abort */
			if (res->flags & (CF_SHUTR_NOW|CF_SHUTR)) {
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			switch (si->applet.st0) {
			case STAT_CLI_PRINT:
				if (bi_putstr(si->ib, si->applet.ctx.cli.msg) != -1)
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_INFO:
				if (stats_dump_info_to_buffer(si))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_STAT:
				if (stats_dump_stat_to_buffer(si, NULL))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_SESS:
				if (stats_dump_sess_to_buffer(si))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_ERR:	/* errors dump */
				if (stats_dump_errors_to_buffer(si))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			case STAT_CLI_O_TAB:
			case STAT_CLI_O_CLR:
				if (stats_table_request(si, si->applet.st0))
					si->applet.st0 = STAT_CLI_PROMPT;
				break;
			default: /* abnormal state */
				si->applet.st0 = STAT_CLI_PROMPT;
				break;
			}

			/* The post-command prompt is either LF alone or LF + '> ' in interactive mode */
			if (si->applet.st0 == STAT_CLI_PROMPT) {
				if (bi_putstr(si->ib, si->applet.st1 ? "\n> " : "\n") != -1)
					si->applet.st0 = STAT_CLI_GETREQ;
			}

			/* If the output functions are still there, it means they require more room. */
			if (si->applet.st0 >= STAT_CLI_OUTPUT)
				break;

			/* Now we close the output if one of the writers did so,
			 * or if we're not in interactive mode and the request
			 * buffer is empty. This still allows pipelined requests
			 * to be sent in non-interactive mode.
			 */
			if ((res->flags & (CF_SHUTW|CF_SHUTW_NOW)) || (!si->applet.st1 && !req->buf->o)) {
				si->applet.st0 = STAT_CLI_END;
				continue;
			}

			/* switch state back to GETREQ to read next requests */
			si->applet.st0 = STAT_CLI_GETREQ;
		}
	}

	if ((res->flags & CF_SHUTR) && (si->state == SI_ST_EST) && (si->applet.st0 != STAT_CLI_GETREQ)) {
		DPRINTF(stderr, "%s@%d: si to buf closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* Other side has closed, let's abort if we have no more processing to do
		 * and nothing more to consume. This is comparable to a broken pipe, so
		 * we forward the close to the request side so that it flows upstream to
		 * the client.
		 */
		si_shutw(si);
	}

	if ((req->flags & CF_SHUTW) && (si->state == SI_ST_EST) && (si->applet.st0 < STAT_CLI_OUTPUT)) {
		DPRINTF(stderr, "%s@%d: buf to si closed. req=%08x, res=%08x, st=%d\n",
			__FUNCTION__, __LINE__, req->flags, res->flags, si->state);
		/* We have no more processing to do, and nothing more to send, and
		 * the client side has closed. So we'll forward this state downstream
		 * on the response buffer.
		 */
		si_shutr(si);
		res->flags |= CF_READ_NULL;
	}

	/* update all other flags and resync with the other side */
	si_update(si);

	/* we don't want to expire timeouts while we're processing requests */
	si->ib->rex = TICK_ETERNITY;
	si->ob->wex = TICK_ETERNITY;

 out:
	DPRINTF(stderr, "%s@%d: st=%d, rqf=%x, rpf=%x, rqh=%d, rqs=%d, rh=%d, rs=%d\n",
		__FUNCTION__, __LINE__,
		si->state, req->flags, res->flags, req->buf->i, req->buf->o, res->buf->i, res->buf->o);

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
		/* check that we have released everything then unregister */
		stream_int_unregister_handler(si);
	}
}

/* This function dumps information onto the stream interface's read buffer.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 * No state is used.
 */
static int stats_dump_info_to_buffer(struct stream_interface *si)
{
	unsigned int up = (now.tv_sec - start_date.tv_sec);

	chunk_printf(&trash,
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
	             "Hard_maxconn: %d\n"
	             "Maxpipes: %d\n"
	             "CurrConns: %d\n"
	             "PipesUsed: %d\n"
	             "PipesFree: %d\n"
	             "ConnRate: %d\n"
	             "ConnRateLimit: %d\n"
	             "MaxConnRate: %d\n"
	             "CompressBpsIn: %u\n"
	             "CompressBpsOut: %u\n"
	             "CompressBpsRateLim: %u\n"
#ifdef USE_ZLIB
	             "ZlibMemUsage: %ld\n"
	             "MaxZlibMemUsage: %ld\n"
#endif
	             "Tasks: %d\n"
	             "Run_queue: %d\n"
	             "Idle_pct: %d\n"
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
	             global.maxsock, global.maxconn, global.hardmaxconn, global.maxpipes,
	             actconn, pipes_used, pipes_free,
	             read_freq_ctr(&global.conn_per_sec), global.cps_lim, global.cps_max,
	             read_freq_ctr(&global.comp_bps_in), read_freq_ctr(&global.comp_bps_out),
	             global.comp_rate_lim,
#ifdef USE_ZLIB
	             zlib_used_memory, global.maxzlibmem,
#endif
	             nb_tasks_cur, run_queue_cur, idle_pct,
	             global.node, global.desc ? global.desc : ""
	             );

	if (bi_putchk(si->ib, &trash) == -1)
		return 0;

	return 1;
}

/* Dumps a frontend's line to the trash for the current proxy <px> and uses
 * the state from stream interface <si>. The caller is responsible for clearing
 * the trash if needed. Returns non-zero if it emits anything, zero otherwise.
 */
static int stats_dump_fe_stats(struct stream_interface *si, struct proxy *px)
{
	int i;

	if (!(px->cap & PR_CAP_FE))
		return 0;

	if ((si->applet.ctx.stats.flags & STAT_BOUND) && !(si->applet.ctx.stats.type & (1 << STATS_TYPE_FE)))
		return 0;

	if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
		chunk_appendf(&trash,
		              /* name, queue */
		              "<tr class=\"frontend\">");

		if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
			/* Column sub-heading for Enable or Disable server */
			chunk_appendf(&trash, "<td></td>");
		}

		chunk_appendf(&trash,
		              "<td class=ac>"
		              "<a name=\"%s/Frontend\"></a>"
		              "<a class=lfsb href=\"#%s/Frontend\">Frontend</a></td>"
		              "<td colspan=3></td>"
		              "",
		              px->id, px->id);

		chunk_appendf(&trash,
		              /* sessions rate : current */
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Current connection rate:</th><td>%s/s</td></tr>"
		              "<tr><th>Current session rate:</th><td>%s/s</td></tr>"
		              "",
		              U2H(read_freq_ctr(&px->fe_sess_per_sec)),
		              U2H(read_freq_ctr(&px->fe_conn_per_sec)),
		              U2H(read_freq_ctr(&px->fe_sess_per_sec)));

		if (px->mode == PR_MODE_HTTP)
			chunk_appendf(&trash,
			              "<tr><th>Current request rate:</th><td>%s/s</td></tr>",
			              U2H(read_freq_ctr(&px->fe_req_per_sec)));

		chunk_appendf(&trash,
		              "</table></div></u></td>"
		              /* sessions rate : max */
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Max connection rate:</th><td>%s/s</td></tr>"
		              "<tr><th>Max session rate:</th><td>%s/s</td></tr>"
		              "",
		              U2H(px->fe_counters.sps_max),
		              U2H(px->fe_counters.cps_max),
		              U2H(px->fe_counters.sps_max));

		if (px->mode == PR_MODE_HTTP)
			chunk_appendf(&trash,
			              "<tr><th>Max request rate:</th><td>%s/s</td></tr>",
			              U2H(px->fe_counters.p.http.rps_max));

		chunk_appendf(&trash,
		              "</table></div></u></td>"
		              /* sessions rate : limit */
		              "<td>%s</td>",
		              LIM2A(px->fe_sps_lim, "-"));

		chunk_appendf(&trash,
		              /* sessions: current, max, limit, total */
		              "<td>%s</td><td>%s</td><td>%s</td>"
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Cum. connections:</th><td>%s</td></tr>"
		              "<tr><th>Cum. sessions:</th><td>%s</td></tr>"
		              "",
		              U2H(px->feconn), U2H(px->fe_counters.conn_max), U2H(px->maxconn),
		              U2H(px->fe_counters.cum_sess),
		              U2H(px->fe_counters.cum_conn),
		              U2H(px->fe_counters.cum_sess));

		/* http response (via hover): 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (px->mode == PR_MODE_HTTP) {
			chunk_appendf(&trash,
			              "<tr><th>Cum. HTTP requests:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 1xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 2xx responses:</th><td>%s</td></tr>"
			              "<tr><th>&nbsp;&nbsp;Compressed 2xx:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 3xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 4xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 5xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- other responses:</th><td>%s</td></tr>"
			              "<tr><th>Intercepted requests:</th><td>%s</td></tr>"
			              "",
			              U2H(px->fe_counters.p.http.cum_req),
			              U2H(px->fe_counters.p.http.rsp[1]),
			              U2H(px->fe_counters.p.http.rsp[2]),
			              U2H(px->fe_counters.p.http.comp_rsp),
			              px->fe_counters.p.http.rsp[2] ?
			              (int)(100*px->fe_counters.p.http.comp_rsp/px->fe_counters.p.http.rsp[2]) : 0,
			              U2H(px->fe_counters.p.http.rsp[3]),
			              U2H(px->fe_counters.p.http.rsp[4]),
			              U2H(px->fe_counters.p.http.rsp[5]),
			              U2H(px->fe_counters.p.http.rsp[0]),
			              U2H(px->fe_counters.intercepted_req));
		}

		chunk_appendf(&trash,
		              "</table></div></u></td>"
		              /* sessions: lbtot */
		              "<td></td>"
		              /* bytes : in */
		              "<td>%s</td>"
		              "",
		              U2H(px->fe_counters.bytes_in));

		chunk_appendf(&trash,
			      /* bytes:out + compression stats (via hover): comp_in, comp_out, comp_byp */
		              "<td>%s%s<div class=tips>compression: in=%lld out=%lld bypassed=%lld savings=%d%%</div>%s</td>",
		              (px->fe_counters.comp_in || px->fe_counters.comp_byp) ? "<u>":"",
		              U2H(px->fe_counters.bytes_out),
		              px->fe_counters.comp_in, px->fe_counters.comp_out, px->fe_counters.comp_byp,
		              px->fe_counters.comp_in ?
		              (int)((px->fe_counters.comp_in - px->fe_counters.comp_out)*100/px->fe_counters.comp_in) : 0,
		              (px->fe_counters.comp_in || px->fe_counters.comp_byp) ? "</u>":"");

		chunk_appendf(&trash,
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
		              U2H(px->fe_counters.denied_req), U2H(px->fe_counters.denied_resp),
		              U2H(px->fe_counters.failed_req),
		              px->state == PR_STREADY ? "OPEN" :
		              px->state == PR_STFULL ? "FULL" : "STOP");
	}
	else { /* CSV mode */
		chunk_appendf(&trash,
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
		              px->feconn, px->fe_counters.conn_max, px->maxconn, px->fe_counters.cum_sess,
		              px->fe_counters.bytes_in, px->fe_counters.bytes_out,
		              px->fe_counters.denied_req, px->fe_counters.denied_resp,
		              px->fe_counters.failed_req,
		              px->state == PR_STREADY ? "OPEN" :
		              px->state == PR_STFULL ? "FULL" : "STOP",
		              relative_pid, px->uuid, STATS_TYPE_FE,
		              read_freq_ctr(&px->fe_sess_per_sec),
		              px->fe_sps_lim, px->fe_counters.sps_max);

		/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (px->mode == PR_MODE_HTTP) {
			for (i=1; i<6; i++)
				chunk_appendf(&trash, "%lld,", px->fe_counters.p.http.rsp[i]);
			chunk_appendf(&trash, "%lld,", px->fe_counters.p.http.rsp[0]);
		}
		else
			chunk_appendf(&trash, ",,,,,,");

		/* failed health analyses */
		chunk_appendf(&trash, ",");

		/* requests : req_rate, req_rate_max, req_tot, */
		chunk_appendf(&trash, "%u,%u,%lld,",
		              read_freq_ctr(&px->fe_req_per_sec),
		              px->fe_counters.p.http.rps_max, px->fe_counters.p.http.cum_req);

		/* errors: cli_aborts, srv_aborts */
		chunk_appendf(&trash, ",,");

		/* compression: in, out, bypassed */
		chunk_appendf(&trash, "%lld,%lld,%lld,",
		              px->fe_counters.comp_in, px->fe_counters.comp_out, px->fe_counters.comp_byp);

		/* compression: comp_rsp */
		chunk_appendf(&trash, "%lld,",
		              px->fe_counters.p.http.comp_rsp);

		/* finish with EOL */
		chunk_appendf(&trash, "\n");
	}
	return 1;
}

/* Dumps a line for listener <l> and proxy <px> to the trash and uses the state
 * from stream interface <si>, and stats flags <flags>. The caller is responsible
 * for clearing the trash if needed. Returns non-zero if it emits anything, zero
 * otherwise.
 */
static int stats_dump_li_stats(struct stream_interface *si, struct proxy *px, struct listener *l, int flags)
{
	if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
		chunk_appendf(&trash, "<tr class=socket>");
		if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
			/* Column sub-heading for Enable or Disable server */
			chunk_appendf(&trash, "<td></td>");
		}
		chunk_appendf(&trash,
		              /* frontend name, listener name */
		              "<td class=ac><a name=\"%s/+%s\"></a>%s"
		              "<a class=lfsb href=\"#%s/+%s\">%s</a>"
		              "",
		              px->id, l->name,
		              (flags & ST_SHLGNDS)?"<u>":"",
		              px->id, l->name, l->name);

		if (flags & ST_SHLGNDS) {
			char str[INET6_ADDRSTRLEN];
			int port;

			chunk_appendf(&trash, "<div class=tips>");

			port = get_host_port(&l->addr);
			switch (addr_to_str(&l->addr, str, sizeof(str))) {
			case AF_INET:
				chunk_appendf(&trash, "IPv4: %s:%d, ", str, port);
				break;
			case AF_INET6:
				chunk_appendf(&trash, "IPv6: [%s]:%d, ", str, port);
				break;
			case AF_UNIX:
				chunk_appendf(&trash, "unix, ");
				break;
			case -1:
				chunk_appendf(&trash, "(%s), ", strerror(errno));
				break;
			}

			/* id */
			chunk_appendf(&trash, "id: %d</div>", l->luid);
		}

		chunk_appendf(&trash,
			      /* queue */
		              "%s</td><td colspan=3></td>"
		              /* sessions rate: current, max, limit */
		              "<td colspan=3>&nbsp;</td>"
		              /* sessions: current, max, limit, total, lbtot */
		              "<td>%s</td><td>%s</td><td>%s</td>"
		              "<td>%s</td><td>&nbsp;</td>"
		              /* bytes: in, out */
		              "<td>%s</td><td>%s</td>"
		              "",
		              (flags & ST_SHLGNDS)?"</u>":"",
		              U2H(l->nbconn), U2H(l->counters->conn_max), U2H(l->maxconn),
		              U2H(l->counters->cum_conn), U2H(l->counters->bytes_in), U2H(l->counters->bytes_out));

		chunk_appendf(&trash,
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
		              U2H(l->counters->denied_req), U2H(l->counters->denied_resp),
		              U2H(l->counters->failed_req),
		              (l->nbconn < l->maxconn) ? (l->state == LI_LIMITED) ? "WAITING" : "OPEN" : "FULL");
	}
	else { /* CSV mode */
		chunk_appendf(&trash,
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
		              /* requests : req_rate, req_rate_max, req_tot, */
		              ",,,"
		              /* errors: cli_aborts, srv_aborts */
		              ",,"
		              /* compression: in, out, bypassed, comp_rsp */
		              ",,,,"
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
	return 1;
}

/* Dumps a line for server <sv> and proxy <px> to the trash and uses the state
 * from stream interface <si>, stats flags <flags>, and server state <state>.
 * The caller is responsible for clearing the trash if needed. Returns non-zero
 * if it emits anything, zero otherwise. The <state> parameter can take the
 * following values : 0=DOWN, 1=going up, 2=going down, 3=UP, 4,5=NOLB, 6=unchecked.
 */
static int stats_dump_sv_stats(struct stream_interface *si, struct proxy *px, int flags, struct server *sv, int state)
{
	struct server *ref = sv->track ? sv->track : sv;
	char str[INET6_ADDRSTRLEN];
	struct chunk src;
	int i;

	if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
		static char *srv_hlt_st[7] = {
			"DOWN",
			"DN %d/%d &uarr;",
			"UP %d/%d &darr;",
			"UP",
			"NOLB %d/%d &darr;",
			"NOLB",
			"<i>no check</i>"
		};

		if ((sv->state & SRV_MAINTAIN) || (ref->state & SRV_MAINTAIN))
			chunk_appendf(&trash, "<tr class=\"maintain\">");
		else if (sv->eweight == 0)
			chunk_appendf(&trash, "<tr class=\"softstop\">");
		else
			chunk_appendf(&trash,
			              "<tr class=\"%s%d\">",
			              (sv->state & SRV_BACKUP) ? "backup" : "active", state);

		if ((px->cap & PR_CAP_BE) && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN))
			chunk_appendf(&trash,
			              "<td><input type=\"checkbox\" name=\"s\" value=\"%s\"></td>",
			              sv->id);

		chunk_appendf(&trash,
		              "<td class=ac><a name=\"%s/%s\"></a>%s"
		              "<a class=lfsb href=\"#%s/%s\">%s</a>"
			      "",
		              px->id, sv->id,
		              (flags & ST_SHLGNDS) ? "<u>" : "",
		              px->id, sv->id, sv->id);

		if (flags & ST_SHLGNDS) {
			chunk_appendf(&trash, "<div class=tips>");

			switch (addr_to_str(&sv->addr, str, sizeof(str))) {
			case AF_INET:
				chunk_appendf(&trash, "IPv4: %s:%d, ", str, get_host_port(&sv->addr));
				break;
			case AF_INET6:
				chunk_appendf(&trash, "IPv6: [%s]:%d, ", str, get_host_port(&sv->addr));
				break;
			case AF_UNIX:
				chunk_appendf(&trash, "unix, ");
				break;
			case -1:
				chunk_appendf(&trash, "(%s), ", strerror(errno));
				break;
			default: /* address family not supported */
				break;
			}

			/* id */
			chunk_appendf(&trash, "id: %d", sv->puid);

			/* cookie */
			if (sv->cookie) {
				chunk_appendf(&trash, ", cookie: '");

				chunk_initlen(&src, sv->cookie, 0, strlen(sv->cookie));
				chunk_htmlencode(&trash, &src);

				chunk_appendf(&trash, "'");
			}

			chunk_appendf(&trash, "</div>");
		}

		chunk_appendf(&trash,
		              /* queue : current, max, limit */
		              "%s</td><td>%s</td><td>%s</td><td>%s</td>"
		              /* sessions rate : current, max, limit */
		              "<td>%s</td><td>%s</td><td></td>"
		              "",
		              (flags & ST_SHLGNDS) ? "</u>" : "",
		              U2H(sv->nbpend), U2H(sv->counters.nbpend_max), LIM2A(sv->maxqueue, "-"),
		              U2H(read_freq_ctr(&sv->sess_per_sec)), U2H(sv->counters.sps_max));


		chunk_appendf(&trash,
		              /* sessions: current, max, limit, total */
		              "<td>%s</td><td>%s</td><td>%s</td>"
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Cum. sessions:</th><td>%s</td></tr>"
		              "",
		              U2H(sv->cur_sess), U2H(sv->counters.cur_sess_max), LIM2A(sv->maxconn, "-"),
		              U2H(sv->counters.cum_sess),
		              U2H(sv->counters.cum_sess));

		/* http response (via hover): 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (px->mode == PR_MODE_HTTP) {
			unsigned long long tot;
			for (tot = i = 0; i < 6; i++)
				tot += sv->counters.p.http.rsp[i];

			chunk_appendf(&trash,
			              "<tr><th>Cum. HTTP responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 1xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 2xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 3xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 4xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 5xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- other responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "",
			              U2H(tot),
			              U2H(sv->counters.p.http.rsp[1]), tot ? (int)(100*sv->counters.p.http.rsp[1] / tot) : 0,
			              U2H(sv->counters.p.http.rsp[2]), tot ? (int)(100*sv->counters.p.http.rsp[2] / tot) : 0,
			              U2H(sv->counters.p.http.rsp[3]), tot ? (int)(100*sv->counters.p.http.rsp[3] / tot) : 0,
			              U2H(sv->counters.p.http.rsp[4]), tot ? (int)(100*sv->counters.p.http.rsp[4] / tot) : 0,
			              U2H(sv->counters.p.http.rsp[5]), tot ? (int)(100*sv->counters.p.http.rsp[5] / tot) : 0,
			              U2H(sv->counters.p.http.rsp[0]), tot ? (int)(100*sv->counters.p.http.rsp[0] / tot) : 0);
		}

		chunk_appendf(&trash,
		              "</table></div></u></td>"
		              /* sessions: lbtot */
		              "<td>%s</td>",
		              U2H(sv->counters.cum_lbconn));

		chunk_appendf(&trash,
		              /* bytes : in, out */
		              "<td>%s</td><td>%s</td>"
		              /* denied: req, resp */
		              "<td></td><td>%s</td>"
		              /* errors : request, connect */
		              "<td></td><td>%s</td>"
		              /* errors : response */
		              "<td><u>%s<div class=tips>Connection resets during transfers: %lld client, %lld server</div></u></td>"
		              /* warnings: retries, redispatches */
		              "<td>%lld</td><td>%lld</td>"
		              "",
		              U2H(sv->counters.bytes_in), U2H(sv->counters.bytes_out),
		              U2H(sv->counters.failed_secu),
		              U2H(sv->counters.failed_conns),
		              U2H(sv->counters.failed_resp),
		              sv->counters.cli_aborts,
		              sv->counters.srv_aborts,
		              sv->counters.retries, sv->counters.redispatches);

		/* status, lest check */
		chunk_appendf(&trash, "<td class=ac>");

		if (sv->state & SRV_MAINTAIN) {
			chunk_appendf(&trash, "%s ", human_time(now.tv_sec - sv->last_change, 1));
			chunk_appendf(&trash, "MAINT");
		}
		else if (ref != sv && ref->state & SRV_MAINTAIN) {
			chunk_appendf(&trash, "%s ", human_time(now.tv_sec - ref->last_change, 1));
			chunk_appendf(&trash, "MAINT(via)");
		}
		else if (ref->state & SRV_CHECKED) {
			chunk_appendf(&trash, "%s ", human_time(now.tv_sec - ref->last_change, 1));
			chunk_appendf(&trash,
			              srv_hlt_st[state],
			              (ref->state & SRV_RUNNING) ? (ref->health - ref->rise + 1) : (ref->health),
			              (ref->state & SRV_RUNNING) ? (ref->fall) : (ref->rise));
		}

		if (sv->state & SRV_CHECKED) {
			chunk_appendf(&trash,
			              "</td><td class=ac><u> %s%s",
			              (sv->state & SRV_CHK_RUNNING) ? "* " : "",
			              get_check_status_info(sv->check.status));

			if (sv->check.status >= HCHK_STATUS_L57DATA)
				chunk_appendf(&trash, "/%d", sv->check.code);

			if (sv->check.status >= HCHK_STATUS_CHECKED && sv->check.duration >= 0)
				chunk_appendf(&trash, " in %lums", sv->check.duration);

			chunk_appendf(&trash, "<div class=tips>%s",
				      get_check_status_description(sv->check.status));
			if (*sv->check.desc) {
				chunk_appendf(&trash, ": ");
				chunk_initlen(&src, sv->check.desc, 0, strlen(sv->check.desc));
				chunk_htmlencode(&trash, &src);
			}
			chunk_appendf(&trash, "</div></u>");
		}
		else
			chunk_appendf(&trash, "</td><td>");

		chunk_appendf(&trash,
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
			chunk_appendf(&trash, "<td><u>%lld", ref->counters.failed_checks);

			if (ref->observe)
				chunk_appendf(&trash, "/%lld", ref->counters.failed_hana);

			chunk_appendf(&trash,
			              "<div class=tips>Failed Health Checks%s</div></u></td>"
			              "<td>%lld</td><td>%s</td>"
			              "",
			              ref->observe ? "/Health Analyses" : "",
			              ref->counters.down_trans, human_time(srv_downtime(sv), 1));
		}
		else if (sv != ref)
			chunk_appendf(&trash,
			              "<td class=ac colspan=3><a class=lfsb href=\"#%s/%s\">via %s/%s<a></td>",
			              ref->proxy->id, ref->id, ref->proxy->id, ref->id);
		else
			chunk_appendf(&trash, "<td colspan=3></td>");

		/* throttle */
		if ((sv->state & SRV_WARMINGUP) &&
		    now.tv_sec < sv->last_change + sv->slowstart &&
		    now.tv_sec >= sv->last_change) {
			chunk_appendf(&trash, "<td class=ac>%d %%</td></tr>\n",
			              (int)MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart));
		}
		else
			chunk_appendf(&trash, "<td class=ac>-</td></tr>\n");
	}
	else { /* CSV mode */
		static char *srv_hlt_st[7] = {
			"DOWN,",
			"DOWN %d/%d,",
			"UP %d/%d,",
			"UP,",
			"NOLB %d/%d,",
			"NOLB,",
			"no check,"
		};

		chunk_appendf(&trash,
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
		              sv->cur_sess, sv->counters.cur_sess_max, LIM2A(sv->maxconn, ""), sv->counters.cum_sess,
		              sv->counters.bytes_in, sv->counters.bytes_out,
		              sv->counters.failed_secu,
		              sv->counters.failed_conns, sv->counters.failed_resp,
		              sv->counters.retries, sv->counters.redispatches);

		/* status */
		if (sv->state & SRV_MAINTAIN)
			chunk_appendf(&trash, "MAINT,");
		else if (ref != sv && ref->state & SRV_MAINTAIN)
			chunk_appendf(&trash, "MAINT(via),");
		else
			chunk_appendf(&trash,
			              srv_hlt_st[state],
			              (ref->state & SRV_RUNNING) ? (ref->health - ref->rise + 1) : (ref->health),
			              (ref->state & SRV_RUNNING) ? (ref->fall) : (ref->rise));

		chunk_appendf(&trash,
		              /* weight, active, backup */
		              "%d,%d,%d,"
		              "",
		              (sv->eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
		              (sv->state & SRV_BACKUP) ? 0 : 1,
		              (sv->state & SRV_BACKUP) ? 1 : 0);

		/* check failures: unique, fatal; last change, total downtime */
		if (sv->state & SRV_CHECKED)
			chunk_appendf(&trash,
			              "%lld,%lld,%d,%d,",
			              sv->counters.failed_checks, sv->counters.down_trans,
			              (int)(now.tv_sec - sv->last_change), srv_downtime(sv));
		else
			chunk_appendf(&trash, ",,,,");

		/* queue limit, pid, iid, sid, */
		chunk_appendf(&trash,
		              "%s,"
		              "%d,%d,%d,",
		              LIM2A(sv->maxqueue, ""),
		              relative_pid, px->uuid, sv->puid);

		/* throttle */
		if ((sv->state & SRV_WARMINGUP) &&
		    now.tv_sec < sv->last_change + sv->slowstart &&
		    now.tv_sec >= sv->last_change)
			chunk_appendf(&trash, "%d", (int)MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart));

		/* sessions: lbtot */
		chunk_appendf(&trash, ",%lld,", sv->counters.cum_lbconn);

		/* tracked */
		if (sv->track)
			chunk_appendf(&trash, "%s/%s,",
			              sv->track->proxy->id, sv->track->id);
		else
			chunk_appendf(&trash, ",");

		/* type */
		chunk_appendf(&trash, "%d,", STATS_TYPE_SV);

		/* rate */
		chunk_appendf(&trash, "%u,,%u,",
		              read_freq_ctr(&sv->sess_per_sec),
		              sv->counters.sps_max);

		if (sv->state & SRV_CHECKED) {
			/* check_status */
			chunk_appendf(&trash, "%s,", get_check_status_info(sv->check.status));

			/* check_code */
			if (sv->check.status >= HCHK_STATUS_L57DATA)
				chunk_appendf(&trash, "%u,", sv->check.code);
			else
				chunk_appendf(&trash, ",");

			/* check_duration */
			if (sv->check.status >= HCHK_STATUS_CHECKED)
				chunk_appendf(&trash, "%lu,", sv->check.duration);
			else
				chunk_appendf(&trash, ",");

		}
		else
			chunk_appendf(&trash, ",,,");

		/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (px->mode == PR_MODE_HTTP) {
			for (i=1; i<6; i++)
				chunk_appendf(&trash, "%lld,", sv->counters.p.http.rsp[i]);

			chunk_appendf(&trash, "%lld,", sv->counters.p.http.rsp[0]);
		}
		else
			chunk_appendf(&trash, ",,,,,,");

		/* failed health analyses */
		chunk_appendf(&trash, "%lld,",  sv->counters.failed_hana);

		/* requests : req_rate, req_rate_max, req_tot, */
		chunk_appendf(&trash, ",,,");

		/* errors: cli_aborts, srv_aborts */
		chunk_appendf(&trash, "%lld,%lld,",
		              sv->counters.cli_aborts, sv->counters.srv_aborts);

		/* compression: in, out, bypassed, comp_rsp */
		chunk_appendf(&trash, ",,,,");

		/* finish with EOL */
		chunk_appendf(&trash, "\n");
	}
	return 1;
}

/* Dumps a line for backend <px> to the trash for and uses the state from stream
 * interface <si> and stats flags <flags>. The caller is responsible for clearing
 * the trash if needed. Returns non-zero if it emits anything, zero otherwise.
 */
static int stats_dump_be_stats(struct stream_interface *si, struct proxy *px, int flags)
{
	struct chunk src;
	int i;

	if (!(px->cap & PR_CAP_BE))
		return 0;

	if ((si->applet.ctx.stats.flags & STAT_BOUND) && !(si->applet.ctx.stats.type & (1 << STATS_TYPE_BE)))
		return 0;

	if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
		chunk_appendf(&trash, "<tr class=\"backend\">");
		if (px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
			/* Column sub-heading for Enable or Disable server */
			chunk_appendf(&trash, "<td></td>");
		}
		chunk_appendf(&trash,
		              "<td class=ac>"
		              /* name */
		              "%s<a name=\"%s/Backend\"></a>"
		              "<a class=lfsb href=\"#%s/Backend\">Backend</a>"
		              "",
		              (flags & ST_SHLGNDS)?"<u>":"",
		              px->id, px->id);

		if (flags & ST_SHLGNDS) {
			/* balancing */
			chunk_appendf(&trash, "<div class=tips>balancing: %s",
			              backend_lb_algo_str(px->lbprm.algo & BE_LB_ALGO));

			/* cookie */
			if (px->cookie_name) {
				chunk_appendf(&trash, ", cookie: '");
				chunk_initlen(&src, px->cookie_name, 0, strlen(px->cookie_name));
				chunk_htmlencode(&trash, &src);
				chunk_appendf(&trash, "'");
			}
			chunk_appendf(&trash, "</div>");
		}

		chunk_appendf(&trash,
		              "%s</td>"
		              /* queue : current, max */
		              "<td>%s</td><td>%s</td><td></td>"
		              /* sessions rate : current, max, limit */
		              "<td>%s</td><td>%s</td><td></td>"
		              "",
		              (flags & ST_SHLGNDS)?"</u>":"",
		              U2H(px->nbpend) /* or px->totpend ? */, U2H(px->be_counters.nbpend_max),
		              U2H(read_freq_ctr(&px->be_sess_per_sec)), U2H(px->be_counters.sps_max));

		chunk_appendf(&trash,
		              /* sessions: current, max, limit, total */
		              "<td>%s</td><td>%s</td><td>%s</td>"
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Cum. sessions:</th><td>%s</td></tr>"
		              "",
		              U2H(px->beconn), U2H(px->be_counters.conn_max), U2H(px->fullconn),
		              U2H(px->be_counters.cum_conn),
		              U2H(px->be_counters.cum_conn));

		/* http response (via hover): 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (px->mode == PR_MODE_HTTP) {
			chunk_appendf(&trash,
			              "<tr><th>Cum. HTTP requests:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 1xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 2xx responses:</th><td>%s</td></tr>"
			              "<tr><th>&nbsp;&nbsp;Compressed 2xx:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 3xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 4xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 5xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- other responses:</th><td>%s</td></tr>"
			              "<tr><th>Intercepted requests:</th><td>%s</td></tr>"
			              "",
			              U2H(px->be_counters.p.http.cum_req),
			              U2H(px->be_counters.p.http.rsp[1]),
			              U2H(px->be_counters.p.http.rsp[2]),
			              U2H(px->be_counters.p.http.comp_rsp),
			              px->be_counters.p.http.rsp[2] ?
			              (int)(100*px->be_counters.p.http.comp_rsp/px->be_counters.p.http.rsp[2]) : 0,
			              U2H(px->be_counters.p.http.rsp[3]),
			              U2H(px->be_counters.p.http.rsp[4]),
			              U2H(px->be_counters.p.http.rsp[5]),
			              U2H(px->be_counters.p.http.rsp[0]),
			              U2H(px->be_counters.intercepted_req));
		}

		chunk_appendf(&trash,
		              "</table></div></u></td>"
		              /* sessions: lbtot */
		              "<td>%s</td>"
		              /* bytes: in */
		              "<td>%s</td>"
		              "",
		              U2H(px->be_counters.cum_lbconn),
		              U2H(px->be_counters.bytes_in));

		chunk_appendf(&trash,
			      /* bytes:out + compression stats (via hover): comp_in, comp_out, comp_byp */
		              "<td>%s%s<div class=tips>compression: in=%lld out=%lld bypassed=%lld savings=%d%%</div>%s</td>",
		              (px->be_counters.comp_in || px->be_counters.comp_byp) ? "<u>":"",
		              U2H(px->be_counters.bytes_out),
		              px->be_counters.comp_in, px->be_counters.comp_out, px->be_counters.comp_byp,
		              px->be_counters.comp_in ?
		              (int)((px->be_counters.comp_in - px->be_counters.comp_out)*100/px->be_counters.comp_in) : 0,
		              (px->be_counters.comp_in || px->be_counters.comp_byp) ? "</u>":"");

		chunk_appendf(&trash,
		              /* denied: req, resp */
		              "<td>%s</td><td>%s</td>"
		              /* errors : request, connect */
		              "<td></td><td>%s</td>"
		              /* errors : response */
		              "<td><u>%s<div class=tips>Connection resets during transfers: %lld client, %lld server</div></u></td>"
		              /* warnings: retries, redispatches */
		              "<td>%lld</td><td>%lld</td>"
		              /* backend status: reflect backend status (up/down): we display UP
		               * if the backend has known working servers or if it has no server at
		               * all (eg: for stats). Then we display the total weight, number of
		               * active and backups. */
		              "<td class=ac>%s %s</td><td class=ac>&nbsp;</td><td class=ac>%d</td>"
		              "<td class=ac>%d</td><td class=ac>%d</td>"
		              "",
		              U2H(px->be_counters.denied_req), U2H(px->be_counters.denied_resp),
		              U2H(px->be_counters.failed_conns),
		              U2H(px->be_counters.failed_resp),
		              px->be_counters.cli_aborts,
		              px->be_counters.srv_aborts,
		              px->be_counters.retries, px->be_counters.redispatches,
		              human_time(now.tv_sec - px->last_change, 1),
		              (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" :
		              "<font color=\"red\"><b>DOWN</b></font>",
		              (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
		              px->srv_act, px->srv_bck);

		chunk_appendf(&trash,
		              /* rest of backend: nothing, down transitions, total downtime, throttle */
		              "<td class=ac>&nbsp;</td><td>%d</td>"
		              "<td>%s</td>"
		              "<td></td>"
		              "</tr>",
		              px->down_trans,
		              px->srv?human_time(be_downtime(px), 1):"&nbsp;");
	}
	else { /* CSV mode */
		chunk_appendf(&trash,
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
		              px->nbpend /* or px->totpend ? */, px->be_counters.nbpend_max,
		              px->beconn, px->be_counters.conn_max, px->fullconn, px->be_counters.cum_conn,
		              px->be_counters.bytes_in, px->be_counters.bytes_out,
		              px->be_counters.denied_req, px->be_counters.denied_resp,
		              px->be_counters.failed_conns, px->be_counters.failed_resp,
		              px->be_counters.retries, px->be_counters.redispatches,
		              (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" : "DOWN",
		              (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
		              px->srv_act, px->srv_bck,
		              px->down_trans, (int)(now.tv_sec - px->last_change),
		              px->srv?be_downtime(px):0,
		              relative_pid, px->uuid,
		              px->be_counters.cum_lbconn, STATS_TYPE_BE,
		              read_freq_ctr(&px->be_sess_per_sec),
		              px->be_counters.sps_max);

		/* http response: 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (px->mode == PR_MODE_HTTP) {
			for (i=1; i<6; i++)
				chunk_appendf(&trash, "%lld,", px->be_counters.p.http.rsp[i]);
			chunk_appendf(&trash, "%lld,", px->be_counters.p.http.rsp[0]);
		}
		else
			chunk_appendf(&trash, ",,,,,,");

		/* failed health analyses */
		chunk_appendf(&trash, ",");

		/* requests : req_rate, req_rate_max, req_tot, */
		chunk_appendf(&trash, ",,,");

		/* errors: cli_aborts, srv_aborts */
		chunk_appendf(&trash, "%lld,%lld,",
			      px->be_counters.cli_aborts, px->be_counters.srv_aborts);

		/* compression: in, out, bypassed */
		chunk_appendf(&trash, "%lld,%lld,%lld,",
			      px->be_counters.comp_in, px->be_counters.comp_out, px->be_counters.comp_byp);

		/* compression: comp_rsp */
		chunk_appendf(&trash, "%lld,", px->be_counters.p.http.comp_rsp);

		/* finish with EOL */
		chunk_appendf(&trash, "\n");
	}
	return 1;
}

/* Dumps the HTML table header for proxy <px> to the trash for and uses the state from
 * stream interface <si> and per-uri parameters <uri>. The caller is responsible
 * for clearing the trash if needed.
 */
static void stats_dump_html_px_hdr(struct stream_interface *si, struct proxy *px, struct uri_auth *uri)
{
	char scope_txt[STAT_SCOPE_TXT_MAXLEN + sizeof STAT_SCOPE_PATTERN];

	if (px->cap & PR_CAP_BE && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
		/* A form to enable/disable this proxy servers */

		/* scope_txt = search pattern + search query, si->applet.ctx.stats.scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
		scope_txt[0] = 0;
		if (si->applet.ctx.stats.scope_len) {
			strcpy(scope_txt, STAT_SCOPE_PATTERN);
			memcpy(scope_txt + strlen(STAT_SCOPE_PATTERN), bo_ptr(si->ob->buf) + si->applet.ctx.stats.scope_str, si->applet.ctx.stats.scope_len);
			scope_txt[strlen(STAT_SCOPE_PATTERN) + si->applet.ctx.stats.scope_len] = 0;
		}

		chunk_appendf(&trash,
			      "<form action=\"%s%s%s%s\" method=\"post\">",
			      uri->uri_prefix,
			      (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			      (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			      scope_txt);
	}

	/* print a new table */
	chunk_appendf(&trash,
		      "<table class=\"tbl\" width=\"100%%\">\n"
		      "<tr class=\"titre\">"
		      "<th class=\"pxname\" width=\"10%%\">");

	chunk_appendf(&trash,
	              "<a name=\"%s\"></a>%s"
	              "<a class=px href=\"#%s\">%s</a>",
	              px->id,
	              (uri->flags & ST_SHLGNDS) ? "<u>":"",
	              px->id, px->id);

	if (uri->flags & ST_SHLGNDS) {
		/* cap, mode, id */
		chunk_appendf(&trash, "<div class=tips>cap: %s, mode: %s, id: %d",
		              proxy_cap_str(px->cap), proxy_mode_str(px->mode),
		              px->uuid);
		chunk_appendf(&trash, "</div>");
	}

	chunk_appendf(&trash,
	              "%s</th>"
	              "<th class=\"%s\" width=\"90%%\">%s</th>"
	              "</tr>\n"
	              "</table>\n"
	              "<table class=\"tbl\" width=\"100%%\">\n"
	              "<tr class=\"titre\">",
	              (uri->flags & ST_SHLGNDS) ? "</u>":"",
	              px->desc ? "desc" : "empty", px->desc ? px->desc : "");

	if ((px->cap & PR_CAP_BE) && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
		/* Column heading for Enable or Disable server */
		chunk_appendf(&trash, "<th rowspan=2 width=1></th>");
	}

	chunk_appendf(&trash,
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
	              "</tr>");
}

/* Dumps the HTML table trailer for proxy <px> to the trash for and uses the state from
 * stream interface <si>. The caller is responsible for clearing the trash if needed.
 */
static void stats_dump_html_px_end(struct stream_interface *si, struct proxy *px)
{
	chunk_appendf(&trash, "</table>");

	if ((px->cap & PR_CAP_BE) && px->srv && (si->applet.ctx.stats.flags & STAT_ADMIN)) {
		/* close the form used to enable/disable this proxy servers */
		chunk_appendf(&trash,
			      "Choose the action to perform on the checked servers : "
			      "<select name=action>"
			      "<option value=\"\"></option>"
			      "<option value=\"disable\">Disable</option>"
			      "<option value=\"enable\">Enable</option>"
			      "<option value=\"stop\">Soft Stop</option>"
			      "<option value=\"start\">Soft Start</option>"
			      "<option value=\"shutdown\">Kill Sessions</option>"
			      "</select>"
			      "<input type=\"hidden\" name=\"b\" value=\"#%d\">"
			      "&nbsp;<input type=\"submit\" value=\"Apply\">"
			      "</form>",
			      px->uuid);
	}

	chunk_appendf(&trash, "<p>\n");
}

/*
 * Dumps statistics for a proxy. The output is sent to the stream interface's
 * input buffer. Returns 0 if it had to stop dumping data because of lack of
 * buffer space, or non-zero if everything completed. This function is used
 * both by the CLI and the HTTP entry points, and is able to dump the output
 * in HTML or CSV formats. If the later, <uri> must be NULL.
 */
static int stats_dump_proxy_to_buffer(struct stream_interface *si, struct proxy *px, struct uri_auth *uri)
{
	struct session *s = si->conn->xprt_ctx;
	struct channel *rep = si->ib;
	struct server *sv, *svs;	/* server and server-state, server-state=server or server->track */
	struct listener *l;

	chunk_reset(&trash);

	switch (si->applet.ctx.stats.px_st) {
	case STAT_PX_ST_INIT:
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

		/* if the user has requested a limited output and the proxy
		 * name does not match, skip it.
		 */
		if (si->applet.ctx.stats.scope_len &&
		    strnistr(px->id, strlen(px->id), bo_ptr(si->ob->buf) + si->applet.ctx.stats.scope_str, si->applet.ctx.stats.scope_len) == NULL)
			return 1;

		if ((si->applet.ctx.stats.flags & STAT_BOUND) &&
		    (si->applet.ctx.stats.iid != -1) &&
		    (px->uuid != si->applet.ctx.stats.iid))
			return 1;

		si->applet.ctx.stats.px_st = STAT_PX_ST_TH;
		/* fall through */

	case STAT_PX_ST_TH:
		if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
			stats_dump_html_px_hdr(si, px, uri);
			if (bi_putchk(rep, &trash) == -1)
				return 0;
		}

		si->applet.ctx.stats.px_st = STAT_PX_ST_FE;
		/* fall through */

	case STAT_PX_ST_FE:
		/* print the frontend */
		if (stats_dump_fe_stats(si, px))
			if (bi_putchk(rep, &trash) == -1)
				return 0;

		si->applet.ctx.stats.l = px->conf.listeners.n;
		si->applet.ctx.stats.px_st = STAT_PX_ST_LI;
		/* fall through */

	case STAT_PX_ST_LI:
		/* stats.l has been initialized above */
		for (; si->applet.ctx.stats.l != &px->conf.listeners; si->applet.ctx.stats.l = l->by_fe.n) {
			if (buffer_almost_full(rep->buf))
				return 0;

			l = LIST_ELEM(si->applet.ctx.stats.l, struct listener *, by_fe);
			if (!l->counters)
				continue;

			if (si->applet.ctx.stats.flags & STAT_BOUND) {
				if (!(si->applet.ctx.stats.type & (1 << STATS_TYPE_SO)))
					break;

				if (si->applet.ctx.stats.sid != -1 && l->luid != si->applet.ctx.stats.sid)
					continue;
			}

			/* print the frontend */
			if (stats_dump_li_stats(si, px, l, uri ? uri->flags : 0))
				if (bi_putchk(rep, &trash) == -1)
					return 0;
		}

		si->applet.ctx.stats.sv = px->srv; /* may be NULL */
		si->applet.ctx.stats.px_st = STAT_PX_ST_SV;
		/* fall through */

	case STAT_PX_ST_SV:
		/* stats.sv has been initialized above */
		for (; si->applet.ctx.stats.sv != NULL; si->applet.ctx.stats.sv = sv->next) {
			int sv_state; /* 0=DOWN, 1=going up, 2=going down, 3=UP, 4,5=NOLB, 6=unchecked */

			if (buffer_almost_full(rep->buf))
				return 0;

			sv = si->applet.ctx.stats.sv;

			if (si->applet.ctx.stats.flags & STAT_BOUND) {
				if (!(si->applet.ctx.stats.type & (1 << STATS_TYPE_SV)))
					break;

				if (si->applet.ctx.stats.sid != -1 && sv->puid != si->applet.ctx.stats.sid)
					continue;
			}

			if (sv->track)
				svs = sv->track;
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

			if (((sv_state == 0) || (sv->state & SRV_MAINTAIN)) && (si->applet.ctx.stats.flags & STAT_HIDE_DOWN)) {
				/* do not report servers which are DOWN */
				si->applet.ctx.stats.sv = sv->next;
				continue;
			}

			if (stats_dump_sv_stats(si, px, uri ? uri->flags : 0, sv, sv_state))
				if (bi_putchk(rep, &trash) == -1)
					return 0;
		} /* for sv */

		si->applet.ctx.stats.px_st = STAT_PX_ST_BE;
		/* fall through */

	case STAT_PX_ST_BE:
		/* print the backend */
		if (stats_dump_be_stats(si, px, uri ? uri->flags : 0))
			if (bi_putchk(rep, &trash) == -1)
				return 0;

		si->applet.ctx.stats.px_st = STAT_PX_ST_END;
		/* fall through */

	case STAT_PX_ST_END:
		if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
			stats_dump_html_px_end(si, px);
			if (bi_putchk(rep, &trash) == -1)
				return 0;
		}

		si->applet.ctx.stats.px_st = STAT_PX_ST_FIN;
		/* fall through */

	case STAT_PX_ST_FIN:
		return 1;

	default:
		/* unknown state, we should put an abort() here ! */
		return 1;
	}
}

/* Dumps the HTTP stats head block to the trash for and uses the per-uri
 * parameters <uri>. The caller is responsible for clearing the trash if needed.
 */
static void stats_dump_html_head(struct uri_auth *uri)
{
	/* WARNING! This must fit in the first buffer !!! */
	chunk_appendf(&trash,
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
	              ".maintain	{background: #c07820;}\n"
	              ".softstop	{background: #0067FF;}\n"
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
	              "table.det { border-collapse: collapse; border-style: none; }\n"
	              "table.det th { text-align: left; border-width: 0px; padding: 0px 1px 0px 0px; font-style:normal;font-size:11px;font-weight:bold;font-family: sans-serif;}\n"
	              "table.det td { text-align: right; border-width: 0px; padding: 0px 0px 0px 4px; white-space: nowrap; font-style:normal;font-size:11px;font-weight:normal;font-family: monospace;}\n"
	              "u {text-decoration:none; border-bottom: 1px dotted black;}\n"
		      "div.tips {\n"
		      " display:block;\n"
		      " visibility:hidden;\n"
		      " z-index:2147483647;\n"
		      " position:absolute;\n"
		      " padding:2px 4px 3px;\n"
		      " background:#f0f060; color:#000000;\n"
		      " border:1px solid #7040c0;\n"
		      " white-space:nowrap;\n"
		      " font-style:normal;font-size:11px;font-weight:normal;\n"
		      " -moz-border-radius:3px;-webkit-border-radius:3px;border-radius:3px;\n"
		      " -moz-box-shadow:gray 2px 2px 3px;-webkit-box-shadow:gray 2px 2px 3px;box-shadow:gray 2px 2px 3px;\n"
		      "}\n"
		      "u:hover div.tips {visibility:visible;}\n"
	              "-->\n"
	              "</style></head>\n",
	              (uri->flags & ST_SHNODE) ? " on " : "",
	              (uri->flags & ST_SHNODE) ? (uri->node ? uri->node : global.node) : ""
	              );
}

/* Dumps the HTML stats information block to the trash for and uses the state from
 * stream interface <si> and per-uri parameters <uri>. The caller is responsible
 * for clearing the trash if needed.
 */
static void stats_dump_html_info(struct stream_interface *si, struct uri_auth *uri)
{
	unsigned int up = (now.tv_sec - start_date.tv_sec);
	char scope_txt[STAT_SCOPE_TXT_MAXLEN + sizeof STAT_SCOPE_PATTERN];

	/* WARNING! this has to fit the first packet too.
	 * We are around 3.5 kB, add adding entries will
	 * become tricky if we want to support 4kB buffers !
	 */
	chunk_appendf(&trash,
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
	              "current conns = %d; current pipes = %d/%d; conn rate = %d/sec<br>\n"
	              "Running tasks: %d/%d; idle = %d %%<br>\n"
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
	              "</tr><tr>\n"
	              "<td class=\"maintain\"></td><td class=\"noborder\" colspan=\"3\">active or backup DOWN for maintenance (MAINT) &nbsp;</td>"
	              "</tr><tr>\n"
	              "<td class=\"softstop\"></td><td class=\"noborder\" colspan=\"3\">active or backup SOFT STOPPED for maintenance &nbsp;</td>"
	              "</tr></table>\n"
	              "Note: UP with load-balancing disabled is reported as \"NOLB\"."
	              "</td>"
	              "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
	              "<b>Display option:</b><ul style=\"margin-top: 0.25em;\">"
	              "",
	              (uri->flags & ST_HIDEVER) ? "" : (STATS_VERSION_STRING),
	              pid, (uri->flags & ST_SHNODE) ? " on " : "",
		      (uri->flags & ST_SHNODE) ? (uri->node ? uri->node : global.node) : "",
	              (uri->flags & ST_SHDESC) ? ": " : "",
		      (uri->flags & ST_SHDESC) ? (uri->desc ? uri->desc : global.desc) : "",
	              pid, relative_pid, global.nbproc,
	              up / 86400, (up % 86400) / 3600,
	              (up % 3600) / 60, (up % 60),
	              global.rlimit_memmax ? ultoa(global.rlimit_memmax) : "unlimited",
	              global.rlimit_memmax ? " MB" : "",
	              global.rlimit_nofile,
	              global.maxsock, global.maxconn, global.maxpipes,
	              actconn, pipes_used, pipes_used+pipes_free, read_freq_ctr(&global.conn_per_sec),
	              run_queue_cur, nb_tasks_cur, idle_pct
	              );

	/* scope_txt = search query, si->applet.ctx.stats.scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
	memcpy(scope_txt, bo_ptr(si->ob->buf) + si->applet.ctx.stats.scope_str, si->applet.ctx.stats.scope_len);
	scope_txt[si->applet.ctx.stats.scope_len] = '\0';

	chunk_appendf(&trash,
		      "<li><form method=\"GET\" action=\"%s%s%s\">Scope : <input value=\"%s\" name=\"" STAT_SCOPE_INPUT_NAME "\" size=\"8\" maxlength=\"%d\" tabindex=\"1\"/></form>\n",
		      uri->uri_prefix,
		      (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
		      (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
		      (si->applet.ctx.stats.scope_len > 0) ? scope_txt : "",
		      STAT_SCOPE_TXT_MAXLEN);

	/* scope_txt = search pattern + search query, si->applet.ctx.stats.scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
	scope_txt[0] = 0;
	if (si->applet.ctx.stats.scope_len) {
		strcpy(scope_txt, STAT_SCOPE_PATTERN);
		memcpy(scope_txt + strlen(STAT_SCOPE_PATTERN), bo_ptr(si->ob->buf) + si->applet.ctx.stats.scope_str, si->applet.ctx.stats.scope_len);
		scope_txt[strlen(STAT_SCOPE_PATTERN) + si->applet.ctx.stats.scope_len] = 0;
	}

	if (si->applet.ctx.stats.flags & STAT_HIDE_DOWN)
		chunk_appendf(&trash,
		              "<li><a href=\"%s%s%s%s\">Show all servers</a><br>\n",
		              uri->uri_prefix,
		              "",
		              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			      scope_txt);
	else
		chunk_appendf(&trash,
		              "<li><a href=\"%s%s%s%s\">Hide 'DOWN' servers</a><br>\n",
		              uri->uri_prefix,
		              ";up",
		              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			      scope_txt);

	if (uri->refresh > 0) {
		if (si->applet.ctx.stats.flags & STAT_NO_REFRESH)
			chunk_appendf(&trash,
			              "<li><a href=\"%s%s%s%s\">Enable refresh</a><br>\n",
			              uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              "",
				      scope_txt);
		else
			chunk_appendf(&trash,
			              "<li><a href=\"%s%s%s%s\">Disable refresh</a><br>\n",
			              uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              ";norefresh",
				      scope_txt);
	}

	chunk_appendf(&trash,
	              "<li><a href=\"%s%s%s%s\">Refresh now</a><br>\n",
	              uri->uri_prefix,
	              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
	              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
		      scope_txt);

	chunk_appendf(&trash,
	              "<li><a href=\"%s;csv%s%s\">CSV export</a><br>\n",
	              uri->uri_prefix,
	              (uri->refresh > 0) ? ";norefresh" : "",
		      scope_txt);

	chunk_appendf(&trash,
	              "</ul></td>"
	              "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
	              "<b>External resources:</b><ul style=\"margin-top: 0.25em;\">\n"
	              "<li><a href=\"" PRODUCT_URL "\">Primary site</a><br>\n"
	              "<li><a href=\"" PRODUCT_URL_UPD "\">Updates (v" PRODUCT_BRANCH ")</a><br>\n"
	              "<li><a href=\"" PRODUCT_URL_DOC "\">Online manual</a><br>\n"
	              "</ul>"
	              "</td>"
	              "</tr></table>\n"
	              ""
	              );

	if (si->applet.ctx.stats.st_code) {
		switch (si->applet.ctx.stats.st_code) {
		case STAT_STATUS_DONE:
			chunk_appendf(&trash,
			              "<p><div class=active3>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Action processed successfully."
			              "</div>\n", uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_NONE:
			chunk_appendf(&trash,
			              "<p><div class=active2>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Nothing has changed."
			              "</div>\n", uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_PART:
			chunk_appendf(&trash,
			              "<p><div class=active2>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Action partially processed.<br>"
			              "Some server names are probably unknown or ambiguous (duplicated names in the backend)."
			              "</div>\n", uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_ERRP:
			chunk_appendf(&trash,
			              "<p><div class=active0>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Action not processed because of invalid parameters."
			              "<ul>"
			              "<li>The action is maybe unknown.</li>"
			              "<li>The backend name is probably unknown or ambiguous (duplicated names).</li>"
			              "<li>Some server names are probably unknown or ambiguous (duplicated names in the backend).</li>"
			              "</ul>"
			              "</div>\n", uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_EXCD:
			chunk_appendf(&trash,
			              "<p><div class=active0>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "<b>Action not processed : the buffer couldn't store all the data.<br>"
			              "You should retry with less servers at a time.</b>"
			              "</div>\n", uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_DENY:
			chunk_appendf(&trash,
			              "<p><div class=active0>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "<b>Action denied.</b>"
			              "</div>\n", uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		default:
			chunk_appendf(&trash,
			              "<p><div class=active6>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Unexpected result."
			              "</div>\n", uri->uri_prefix,
			              (si->applet.ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			              (si->applet.ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
		}
		chunk_appendf(&trash, "<p>\n");
	}
}

/* Dumps the HTML stats trailer block to the trash. The caller is responsible
 * for clearing the trash if needed.
 */
static void stats_dump_html_end()
{
	chunk_appendf(&trash, "</body></html>\n");
}

/* This function dumps statistics onto the stream interface's read buffer in
 * either CSV or HTML format. <uri> contains some HTML-specific parameters that
 * are ignored for CSV format (hence <uri> may be NULL there). The xprt_ctx must
 * have been zeroed first, and the flags properly set. It returns 0 if it had to
 * stop writing data and an I/O is needed, 1 if the dump is finished and the
 * session must be closed, or -1 in case of any error. This function is used by
 * both the CLI and the HTTP handlers.
 */
static int stats_dump_stat_to_buffer(struct stream_interface *si, struct uri_auth *uri)
{
	struct channel *rep = si->ib;
	struct proxy *px;

	chunk_reset(&trash);

	switch (si->conn->xprt_st) {
	case STAT_ST_INIT:
		si->conn->xprt_st = STAT_ST_HEAD; /* let's start producing data */
		/* fall through */

	case STAT_ST_HEAD:
		if (si->applet.ctx.stats.flags & STAT_FMT_HTML)
			stats_dump_html_head(uri);
		else
			stats_dump_csv_header();

		if (bi_putchk(rep, &trash) == -1)
			return 0;

		si->conn->xprt_st = STAT_ST_INFO;
		/* fall through */

	case STAT_ST_INFO:
		if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
			stats_dump_html_info(si, uri);
			if (bi_putchk(rep, &trash) == -1)
				return 0;
		}

		si->applet.ctx.stats.px = proxy;
		si->applet.ctx.stats.px_st = STAT_PX_ST_INIT;
		si->conn->xprt_st = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		/* dump proxies */
		while (si->applet.ctx.stats.px) {
			if (buffer_almost_full(rep->buf))
				return 0;

			px = si->applet.ctx.stats.px;
			/* skip the disabled proxies, global frontend and non-networked ones */
			if (px->state != PR_STSTOPPED && px->uuid > 0 && (px->cap & (PR_CAP_FE | PR_CAP_BE)))
				if (stats_dump_proxy_to_buffer(si, px, uri) == 0)
					return 0;

			si->applet.ctx.stats.px = px->next;
			si->applet.ctx.stats.px_st = STAT_PX_ST_INIT;
		}
		/* here, we just have reached the last proxy */

		si->conn->xprt_st = STAT_ST_END;
		/* fall through */

	case STAT_ST_END:
		if (si->applet.ctx.stats.flags & STAT_FMT_HTML) {
			stats_dump_html_end();
			if (bi_putchk(rep, &trash) == -1)
				return 0;
		}

		si->conn->xprt_st = STAT_ST_FIN;
		/* fall through */

	case STAT_ST_FIN:
		return 1;

	default:
		/* unknown state ! */
		si->conn->xprt_st = STAT_ST_FIN;
		return -1;
	}
}

/* This I/O handler runs as an applet embedded in a stream interface. It is
 * used to send HTTP stats over a TCP socket. The mechanism is very simple.
 * si->applet.st0 becomes non-zero once the transfer is finished. The handler
 * automatically unregisters itself once transfer is complete.
 */
static void http_stats_io_handler(struct stream_interface *si)
{
	struct session *s = si->conn->xprt_ctx;
	struct channel *req = si->ob;
	struct channel *res = si->ib;

	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* check that the output is not closed */
	if (res->flags & (CF_SHUTW|CF_SHUTW_NOW))
		si->applet.st0 = 1;

	if (!si->applet.st0) {
		if (stats_dump_stat_to_buffer(si, s->be->uri_auth)) {
			si->applet.st0 = 1;
			si_shutw(si);
		}
	}

	if ((res->flags & CF_SHUTR) && (si->state == SI_ST_EST))
		si_shutw(si);

	if ((req->flags & CF_SHUTW) && (si->state == SI_ST_EST) && si->applet.st0) {
		si_shutr(si);
		res->flags |= CF_READ_NULL;
	}

	/* update all other flags and resync with the other side */
	si_update(si);

	/* we don't want to expire timeouts while we're processing requests */
	si->ib->rex = TICK_ETERNITY;
	si->ob->wex = TICK_ETERNITY;

 out:
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
		/* check that we have released everything then unregister */
		stream_int_unregister_handler(si);
	}
}


static inline const char *get_conn_ctrl_name(const struct connection *conn)
{
	if (!conn->ctrl)
		return "NONE";
	return conn->ctrl->name;
}

static inline const char *get_conn_xprt_name(const struct connection *conn)
{
	static char ptr[17];

	if (!conn->xprt)
		return "NONE";

	if (conn->xprt == &raw_sock)
		return "RAW";

#ifdef USE_OPENSSL
	if (conn->xprt == &ssl_sock)
		return "SSL";
#endif
	snprintf(ptr, sizeof(ptr), "%p", conn->xprt);
	return ptr;
}

static inline const char *get_conn_data_name(const struct connection *conn)
{
	static char ptr[17];

	if (!conn->data)
		return "NONE";

	if (conn->data == &sess_conn_cb)
		return "SESS";

	if (conn->data == &si_conn_cb)
		return "STRM";

	if (conn->data == &check_conn_cb)
		return "CHCK";

	snprintf(ptr, sizeof(ptr), "%p", conn->data);
	return ptr;
}

/* This function dumps a complete session state onto the stream interface's
 * read buffer. The xprt_ctx must have been zeroed first, and the flags
 * properly set. The session has to be set in xprt_ctx.sess.target. It returns
 * 0 if the output buffer is full and it needs to be called again, otherwise
 * non-zero. It is designed to be called from stats_dump_sess_to_buffer() below.
 */
static int stats_dump_full_sess_to_buffer(struct stream_interface *si, struct session *sess)
{
	struct tm tm;
	extern const char *monthname[12];
	char pn[INET6_ADDRSTRLEN];

	chunk_reset(&trash);

	if (si->applet.ctx.sess.section > 0 && si->applet.ctx.sess.uid != sess->uniq_id) {
		/* session changed, no need to go any further */
		chunk_appendf(&trash, "  *** session terminated while we were watching it ***\n");
		if (bi_putchk(si->ib, &trash) == -1)
			return 0;
		si->applet.ctx.sess.uid = 0;
		si->applet.ctx.sess.section = 0;
		return 1;
	}

	switch (si->applet.ctx.sess.section) {
	case 0: /* main status of the session */
		si->applet.ctx.sess.uid = sess->uniq_id;
		si->applet.ctx.sess.section = 1;
		/* fall through */

	case 1:
		get_localtime(sess->logs.accept_date.tv_sec, &tm);
		chunk_appendf(&trash,
			     "%p: [%02d/%s/%04d:%02d:%02d:%02d.%06d] id=%u proto=%s",
			     sess,
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(sess->logs.accept_date.tv_usec),
			     sess->uniq_id,
			     sess->listener && sess->listener->proto->name ? sess->listener->proto->name : "?");

		switch (addr_to_str(&sess->si[0].conn->addr.from, pn, sizeof(pn))) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " source=%s:%d\n",
				     pn, get_host_port(&sess->si[0].conn->addr.from));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " source=unix:%d\n", sess->listener->luid);
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		chunk_appendf(&trash,
			     "  flags=0x%x, conn_retries=%d, srv_conn=%p, pend_pos=%p\n",
			     sess->flags, sess->si[1].conn_retries, sess->srv_conn, sess->pend_pos);

		chunk_appendf(&trash,
			     "  frontend=%s (id=%u mode=%s), listener=%s (id=%u)",
			     sess->fe->id, sess->fe->uuid, sess->fe->mode ? "http" : "tcp",
			     sess->listener ? sess->listener->name ? sess->listener->name : "?" : "?",
			     sess->listener ? sess->listener->luid : 0);

		conn_get_to_addr(sess->si[0].conn);
		switch (addr_to_str(&sess->si[0].conn->addr.to, pn, sizeof(pn))) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(&sess->si[0].conn->addr.to));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " addr=unix:%d\n", sess->listener->luid);
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		if (sess->be->cap & PR_CAP_BE)
			chunk_appendf(&trash,
				     "  backend=%s (id=%u mode=%s)",
				     sess->be->id,
				     sess->be->uuid, sess->be->mode ? "http" : "tcp");
		else
			chunk_appendf(&trash, "  backend=<NONE> (id=-1 mode=-)");

		conn_get_from_addr(sess->si[1].conn);
		switch (addr_to_str(&sess->si[1].conn->addr.from, pn, sizeof(pn))) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(&sess->si[1].conn->addr.from));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " addr=unix\n");
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		if (sess->be->cap & PR_CAP_BE)
			chunk_appendf(&trash,
				     "  server=%s (id=%u)",
				     objt_server(sess->target) ? objt_server(sess->target)->id : "<none>",
				     objt_server(sess->target) ? objt_server(sess->target)->puid : 0);
		else
			chunk_appendf(&trash, "  server=<NONE> (id=-1)");

		conn_get_to_addr(sess->si[1].conn);
		switch (addr_to_str(&sess->si[1].conn->addr.to, pn, sizeof(pn))) {
		case AF_INET:
		case AF_INET6:
			chunk_appendf(&trash, " addr=%s:%d\n",
				     pn, get_host_port(&sess->si[1].conn->addr.to));
			break;
		case AF_UNIX:
			chunk_appendf(&trash, " addr=unix\n");
			break;
		default:
			/* no more information to print right now */
			chunk_appendf(&trash, "\n");
			break;
		}

		chunk_appendf(&trash,
			     "  task=%p (state=0x%02x nice=%d calls=%d exp=%s%s",
			     sess->task,
			     sess->task->state,
			     sess->task->nice, sess->task->calls,
			     sess->task->expire ?
			             tick_is_expired(sess->task->expire, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(sess->task->expire - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     task_in_rq(sess->task) ? ", running" : "");

		chunk_appendf(&trash,
			     " age=%s)\n",
			     human_time(now.tv_sec - sess->logs.accept_date.tv_sec, 1));

		chunk_appendf(&trash,
			     "  txn=%p flags=0x%x meth=%d status=%d req.st=%s rsp.st=%s\n",
			     &sess->txn, sess->txn.flags, sess->txn.meth, sess->txn.status,
			     http_msg_state_str(sess->txn.req.msg_state), http_msg_state_str(sess->txn.rsp.msg_state));

		chunk_appendf(&trash,
			     "  si[0]=%p (state=%s flags=0x%02x conn0=%p exp=%s, et=0x%03x)\n",
			     &sess->si[0],
			     si_state_str(sess->si[0].state),
			     sess->si[0].flags,
			     sess->si[0].conn,
			     sess->si[0].exp ?
			             tick_is_expired(sess->si[0].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(sess->si[0].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->si[0].err_type);

		chunk_appendf(&trash,
			     "  si[1]=%p (state=%s flags=0x%02x conn1=%p exp=%s, et=0x%03x)\n",
			     &sess->si[1],
			     si_state_str(sess->si[1].state),
			     sess->si[1].flags,
			     sess->si[1].conn,
			     sess->si[1].exp ?
			             tick_is_expired(sess->si[1].exp, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(sess->si[1].exp - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->si[1].err_type);

		chunk_appendf(&trash,
		              "  co0=%p ctrl=%s xprt=%s data=%s target=%s:%p\n",
			      sess->si[0].conn,
			      get_conn_ctrl_name(sess->si[0].conn),
			      get_conn_xprt_name(sess->si[0].conn),
			      get_conn_data_name(sess->si[0].conn),
		              obj_type_name(sess->si[0].conn->target),
		              obj_base_ptr(sess->si[0].conn->target));

		chunk_appendf(&trash,
		              "      flags=0x%08x fd=%d fd_spec_e=%02x fd_spec_p=%d updt=%d\n",
		              sess->si[0].conn->flags,
		              sess->si[0].conn->t.sock.fd,
		              sess->si[0].conn->t.sock.fd >= 0 ? fdtab[sess->si[0].conn->t.sock.fd].spec_e : 0,
		              sess->si[0].conn->t.sock.fd >= 0 ? fdtab[sess->si[0].conn->t.sock.fd].spec_p : 0,
		              sess->si[0].conn->t.sock.fd >= 0 ? fdtab[sess->si[0].conn->t.sock.fd].updated : 0);

		chunk_appendf(&trash,
		              "  co1=%p ctrl=%s xprt=%s data=%s target=%s:%p\n",
			      sess->si[1].conn,
			      get_conn_ctrl_name(sess->si[1].conn),
			      get_conn_xprt_name(sess->si[1].conn),
			      get_conn_data_name(sess->si[1].conn),
		              obj_type_name(sess->si[1].conn->target),
		              obj_base_ptr(sess->si[1].conn->target));

		chunk_appendf(&trash,
		              "      flags=0x%08x fd=%d fd_spec_e=%02x fd_spec_p=%d updt=%d\n",
		              sess->si[1].conn->flags,
		              sess->si[1].conn->t.sock.fd,
		              sess->si[1].conn->t.sock.fd >= 0 ? fdtab[sess->si[1].conn->t.sock.fd].spec_e : 0,
		              sess->si[1].conn->t.sock.fd >= 0 ? fdtab[sess->si[1].conn->t.sock.fd].spec_p : 0,
		              sess->si[1].conn->t.sock.fd >= 0 ? fdtab[sess->si[1].conn->t.sock.fd].updated : 0);

		chunk_appendf(&trash,
			     "  req=%p (f=0x%06x an=0x%x pipe=%d tofwd=%d total=%lld)\n"
			     "      an_exp=%s",
			     sess->req,
			     sess->req->flags, sess->req->analysers,
			     sess->req->pipe ? sess->req->pipe->data : 0,
			     sess->req->to_forward, sess->req->total,
			     sess->req->analyse_exp ?
			     human_time(TICKS_TO_MS(sess->req->analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " rex=%s",
			     sess->req->rex ?
			     human_time(TICKS_TO_MS(sess->req->rex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " wex=%s\n"
			     "      buf=%p data=%p o=%d p=%d req.next=%d i=%d size=%d\n",
			     sess->req->wex ?
			     human_time(TICKS_TO_MS(sess->req->wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->req->buf,
			     sess->req->buf->data, sess->req->buf->o,
			     (int)(sess->req->buf->p - sess->req->buf->data),
			     sess->txn.req.next, sess->req->buf->i,
			     sess->req->buf->size);

		chunk_appendf(&trash,
			     "  res=%p (f=0x%06x an=0x%x pipe=%d tofwd=%d total=%lld)\n"
			     "      an_exp=%s",
			     sess->rep,
			     sess->rep->flags, sess->rep->analysers,
			     sess->rep->pipe ? sess->rep->pipe->data : 0,
			     sess->rep->to_forward, sess->rep->total,
			     sess->rep->analyse_exp ?
			     human_time(TICKS_TO_MS(sess->rep->analyse_exp - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " rex=%s",
			     sess->rep->rex ?
			     human_time(TICKS_TO_MS(sess->rep->rex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>");

		chunk_appendf(&trash,
			     " wex=%s\n"
			     "      buf=%p data=%p o=%d p=%d rsp.next=%d i=%d size=%d\n",
			     sess->rep->wex ?
			     human_time(TICKS_TO_MS(sess->rep->wex - now_ms),
					TICKS_TO_MS(1000)) : "<NEVER>",
			     sess->rep->buf,
			     sess->rep->buf->data, sess->rep->buf->o,
			     (int)(sess->rep->buf->p - sess->rep->buf->data),
			     sess->txn.rsp.next, sess->rep->buf->i,
			     sess->rep->buf->size);

		if (bi_putchk(si->ib, &trash) == -1)
			return 0;

		/* use other states to dump the contents */
	}
	/* end of dump */
	si->applet.ctx.sess.uid = 0;
	si->applet.ctx.sess.section = 0;
	return 1;
}

/* This function dumps all sessions' states onto the stream interface's
 * read buffer. The xprt_ctx must have been zeroed first, and the flags
 * properly set. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero. It is designed to be called
 * from stats_dump_sess_to_buffer() below.
 */
static int stats_dump_sess_to_buffer(struct stream_interface *si)
{
	if (unlikely(si->ib->flags & (CF_WRITE_ERROR|CF_SHUTW))) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last session being dumped.
		 */
		if (si->conn->xprt_st == STAT_ST_LIST) {
			if (!LIST_ISEMPTY(&si->applet.ctx.sess.bref.users)) {
				LIST_DEL(&si->applet.ctx.sess.bref.users);
				LIST_INIT(&si->applet.ctx.sess.bref.users);
			}
		}
		return 1;
	}

	chunk_reset(&trash);

	switch (si->conn->xprt_st) {
	case STAT_ST_INIT:
		/* the function had not been called yet, let's prepare the
		 * buffer for a response. We initialize the current session
		 * pointer to the first in the global list. When a target
		 * session is being destroyed, it is responsible for updating
		 * this pointer. We know we have reached the end when this
		 * pointer points back to the head of the sessions list.
		 */
		LIST_INIT(&si->applet.ctx.sess.bref.users);
		si->applet.ctx.sess.bref.ref = sessions.n;
		si->conn->xprt_st = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		/* first, let's detach the back-ref from a possible previous session */
		if (!LIST_ISEMPTY(&si->applet.ctx.sess.bref.users)) {
			LIST_DEL(&si->applet.ctx.sess.bref.users);
			LIST_INIT(&si->applet.ctx.sess.bref.users);
		}

		/* and start from where we stopped */
		while (si->applet.ctx.sess.bref.ref != &sessions) {
			char pn[INET6_ADDRSTRLEN];
			struct session *curr_sess;

			curr_sess = LIST_ELEM(si->applet.ctx.sess.bref.ref, struct session *, list);

			if (si->applet.ctx.sess.target) {
				if (si->applet.ctx.sess.target != (void *)-1 && si->applet.ctx.sess.target != curr_sess)
					goto next_sess;

				LIST_ADDQ(&curr_sess->back_refs, &si->applet.ctx.sess.bref.users);
				/* call the proper dump() function and return if we're missing space */
				if (!stats_dump_full_sess_to_buffer(si, curr_sess))
					return 0;

				/* session dump complete */
				LIST_DEL(&si->applet.ctx.sess.bref.users);
				LIST_INIT(&si->applet.ctx.sess.bref.users);
				if (si->applet.ctx.sess.target != (void *)-1) {
					si->applet.ctx.sess.target = NULL;
					break;
				}
				else
					goto next_sess;
			}

			chunk_appendf(&trash,
				     "%p: proto=%s",
				     curr_sess,
				     curr_sess->listener->proto->name);


			switch (addr_to_str(&curr_sess->si[0].conn->addr.from, pn, sizeof(pn))) {
			case AF_INET:
			case AF_INET6:
				chunk_appendf(&trash,
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     get_host_port(&curr_sess->si[0].conn->addr.from),
					     curr_sess->fe->id,
					     (curr_sess->be->cap & PR_CAP_BE) ? curr_sess->be->id : "<NONE>",
					     objt_server(curr_sess->target) ? objt_server(curr_sess->target)->id : "<none>"
					     );
				break;
			case AF_UNIX:
				chunk_appendf(&trash,
					     " src=unix:%d fe=%s be=%s srv=%s",
					     curr_sess->listener->luid,
					     curr_sess->fe->id,
					     (curr_sess->be->cap & PR_CAP_BE) ? curr_sess->be->id : "<NONE>",
					     objt_server(curr_sess->target) ? objt_server(curr_sess->target)->id : "<none>"
					     );
				break;
			}

			chunk_appendf(&trash,
				     " ts=%02x age=%s calls=%d",
				     curr_sess->task->state,
				     human_time(now.tv_sec - curr_sess->logs.tv_accept.tv_sec, 1),
				     curr_sess->task->calls);

			chunk_appendf(&trash,
				     " rq[f=%06xh,i=%d,an=%02xh,rx=%s",
				     curr_sess->req->flags,
				     curr_sess->req->buf->i,
				     curr_sess->req->analysers,
				     curr_sess->req->rex ?
				     human_time(TICKS_TO_MS(curr_sess->req->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",wx=%s",
				     curr_sess->req->wex ?
				     human_time(TICKS_TO_MS(curr_sess->req->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",ax=%s]",
				     curr_sess->req->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->req->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     " rp[f=%06xh,i=%d,an=%02xh,rx=%s",
				     curr_sess->rep->flags,
				     curr_sess->rep->buf->i,
				     curr_sess->rep->analysers,
				     curr_sess->rep->rex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",wx=%s",
				     curr_sess->rep->wex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     ",ax=%s]",
				     curr_sess->rep->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->rep->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     " s0=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[0].state,
				     curr_sess->si[0].flags,
				     curr_sess->si[0].conn->t.sock.fd,
				     curr_sess->si[0].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[0].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     " s1=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[1].state,
				     curr_sess->si[1].flags,
				     curr_sess->si[1].conn->t.sock.fd,
				     curr_sess->si[1].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[1].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_appendf(&trash,
				     " exp=%s",
				     curr_sess->task->expire ?
				     human_time(TICKS_TO_MS(curr_sess->task->expire - now_ms),
						TICKS_TO_MS(1000)) : "");
			if (task_in_rq(curr_sess->task))
				chunk_appendf(&trash, " run(nice=%d)", curr_sess->task->nice);

			chunk_appendf(&trash, "\n");

			if (bi_putchk(si->ib, &trash) == -1) {
				/* let's try again later from this session. We add ourselves into
				 * this session's users so that it can remove us upon termination.
				 */
				LIST_ADDQ(&curr_sess->back_refs, &si->applet.ctx.sess.bref.users);
				return 0;
			}

		next_sess:
			si->applet.ctx.sess.bref.ref = curr_sess->list.n;
		}

		if (si->applet.ctx.sess.target && si->applet.ctx.sess.target != (void *)-1) {
			/* specified session not found */
			if (si->applet.ctx.sess.section > 0)
				chunk_appendf(&trash, "  *** session terminated while we were watching it ***\n");
			else
				chunk_appendf(&trash, "Session not found.\n");

			if (bi_putchk(si->ib, &trash) == -1)
				return 0;

			si->applet.ctx.sess.target = NULL;
			si->applet.ctx.sess.uid = 0;
			return 1;
		}

		si->conn->xprt_st = STAT_ST_FIN;
		/* fall through */

	default:
		si->conn->xprt_st = STAT_ST_FIN;
		return 1;
	}
}

/* This is called when the stream interface is closed. For instance, upon an
 * external abort, we won't call the i/o handler anymore so we may need to
 * remove back references to the session currently being dumped.
 */
static void cli_release_handler(struct stream_interface *si)
{
	if (si->applet.st0 == STAT_CLI_O_SESS && si->conn->xprt_st == STAT_ST_LIST) {
		if (!LIST_ISEMPTY(&si->applet.ctx.sess.bref.users))
			LIST_DEL(&si->applet.ctx.sess.bref.users);
	}
}

/* This function is used to either dump tables states (when action is set
 * to STAT_CLI_O_TAB) or clear tables (when action is STAT_CLI_O_CLR).
 * The xprt_ctx must have been zeroed first, and the flags properly set.
 * It returns 0 if the output buffer is full and it needs to be called
 * again, otherwise non-zero.
 */
static int stats_table_request(struct stream_interface *si, int action)
{
	struct session *s = si->conn->xprt_ctx;
	struct ebmb_node *eb;
	int dt;
	int skip_entry;
	int show = action == STAT_CLI_O_TAB;

	/*
	 * We have 3 possible states in si->conn->xprt_st :
	 *   - STAT_ST_INIT : the first call
	 *   - STAT_ST_INFO : the proxy pointer points to the next table to
	 *     dump, the entry pointer is NULL ;
	 *   - STAT_ST_LIST : the proxy pointer points to the current table
	 *     and the entry pointer points to the next entry to be dumped,
	 *     and the refcount on the next entry is held ;
	 *   - STAT_ST_END : nothing left to dump, the buffer may contain some
	 *     data though.
	 */

	if (unlikely(si->ib->flags & (CF_WRITE_ERROR|CF_SHUTW))) {
		/* in case of abort, remove any refcount we might have set on an entry */
		if (si->conn->xprt_st == STAT_ST_LIST) {
			si->applet.ctx.table.entry->ref_cnt--;
			stksess_kill_if_expired(&si->applet.ctx.table.proxy->table, si->applet.ctx.table.entry);
		}
		return 1;
	}

	chunk_reset(&trash);

	while (si->conn->xprt_st != STAT_ST_FIN) {
		switch (si->conn->xprt_st) {
		case STAT_ST_INIT:
			si->applet.ctx.table.proxy = si->applet.ctx.table.target;
			if (!si->applet.ctx.table.proxy)
				si->applet.ctx.table.proxy = proxy;

			si->applet.ctx.table.entry = NULL;
			si->conn->xprt_st = STAT_ST_INFO;
			break;

		case STAT_ST_INFO:
			if (!si->applet.ctx.table.proxy ||
			    (si->applet.ctx.table.target &&
			     si->applet.ctx.table.proxy != si->applet.ctx.table.target)) {
				si->conn->xprt_st = STAT_ST_END;
				break;
			}

			if (si->applet.ctx.table.proxy->table.size) {
				if (show && !stats_dump_table_head_to_buffer(&trash, si, si->applet.ctx.table.proxy,
									     si->applet.ctx.table.target))
					return 0;

				if (si->applet.ctx.table.target &&
				    s->listener->bind_conf->level >= ACCESS_LVL_OPER) {
					/* dump entries only if table explicitly requested */
					eb = ebmb_first(&si->applet.ctx.table.proxy->table.keys);
					if (eb) {
						si->applet.ctx.table.entry = ebmb_entry(eb, struct stksess, key);
						si->applet.ctx.table.entry->ref_cnt++;
						si->conn->xprt_st = STAT_ST_LIST;
						break;
					}
				}
			}
			si->applet.ctx.table.proxy = si->applet.ctx.table.proxy->next;
			break;

		case STAT_ST_LIST:
			skip_entry = 0;

			if (si->applet.ctx.table.data_type >= 0) {
				/* we're filtering on some data contents */
				void *ptr;
				long long data;

				dt = si->applet.ctx.table.data_type;
				ptr = stktable_data_ptr(&si->applet.ctx.table.proxy->table,
							si->applet.ctx.table.entry,
							dt);

				data = 0;
				switch (stktable_data_types[dt].std_type) {
				case STD_T_SINT:
					data = stktable_data_cast(ptr, std_t_sint);
					break;
				case STD_T_UINT:
					data = stktable_data_cast(ptr, std_t_uint);
					break;
				case STD_T_ULL:
					data = stktable_data_cast(ptr, std_t_ull);
					break;
				case STD_T_FRQP:
					data = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
								    si->applet.ctx.table.proxy->table.data_arg[dt].u);
					break;
				}

				/* skip the entry if the data does not match the test and the value */
				if ((data < si->applet.ctx.table.value &&
				     (si->applet.ctx.table.data_op == STD_OP_EQ ||
				      si->applet.ctx.table.data_op == STD_OP_GT ||
				      si->applet.ctx.table.data_op == STD_OP_GE)) ||
				    (data == si->applet.ctx.table.value &&
				     (si->applet.ctx.table.data_op == STD_OP_NE ||
				      si->applet.ctx.table.data_op == STD_OP_GT ||
				      si->applet.ctx.table.data_op == STD_OP_LT)) ||
				    (data > si->applet.ctx.table.value &&
				     (si->applet.ctx.table.data_op == STD_OP_EQ ||
				      si->applet.ctx.table.data_op == STD_OP_LT ||
				      si->applet.ctx.table.data_op == STD_OP_LE)))
					skip_entry = 1;
			}

			if (show && !skip_entry &&
			    !stats_dump_table_entry_to_buffer(&trash, si, si->applet.ctx.table.proxy,
							      si->applet.ctx.table.entry))
			    return 0;

			si->applet.ctx.table.entry->ref_cnt--;

			eb = ebmb_next(&si->applet.ctx.table.entry->key);
			if (eb) {
				struct stksess *old = si->applet.ctx.table.entry;
				si->applet.ctx.table.entry = ebmb_entry(eb, struct stksess, key);
				if (show)
					stksess_kill_if_expired(&si->applet.ctx.table.proxy->table, old);
				else
					stksess_kill(&si->applet.ctx.table.proxy->table, old);
				si->applet.ctx.table.entry->ref_cnt++;
				break;
			}


			if (show)
				stksess_kill_if_expired(&si->applet.ctx.table.proxy->table, si->applet.ctx.table.entry);
			else if (!skip_entry && !si->applet.ctx.table.entry->ref_cnt)
				stksess_kill(&si->applet.ctx.table.proxy->table, si->applet.ctx.table.entry);

			si->applet.ctx.table.proxy = si->applet.ctx.table.proxy->next;
			si->conn->xprt_st = STAT_ST_INFO;
			break;

		case STAT_ST_END:
			si->conn->xprt_st = STAT_ST_FIN;
			break;
		}
	}
	return 1;
}

/* print a line of text buffer (limited to 70 bytes) to <out>. The format is :
 * <2 spaces> <offset=5 digits> <space or plus> <space> <70 chars max> <\n>
 * which is 60 chars per line. Non-printable chars \t, \n, \r and \e are
 * encoded in C format. Other non-printable chars are encoded "\xHH". Original
 * lines are respected within the limit of 70 output chars. Lines that are
 * continuation of a previous truncated line begin with "+" instead of " "
 * after the offset. The new pointer is returned.
 */
static int dump_text_line(struct chunk *out, const char *buf, int bsize, int len,
			  int *line, int ptr)
{
	int end;
	unsigned char c;

	end = out->len + 80;
	if (end > out->size)
		return ptr;

	chunk_appendf(out, "  %05d%c ", ptr, (ptr == *line) ? ' ' : '+');

	while (ptr < len && ptr < bsize) {
		c = buf[ptr];
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
		if (buf[ptr++] == '\n') {
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

/* This function dumps all captured errors onto the stream interface's
 * read buffer. The xprt_ctx must have been zeroed first, and the flags
 * properly set. It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
 */
static int stats_dump_errors_to_buffer(struct stream_interface *si)
{
	extern const char *monthname[12];

	if (unlikely(si->ib->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	if (!si->applet.ctx.errors.px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		struct tm tm;

		get_localtime(date.tv_sec, &tm);
		chunk_appendf(&trash, "Total events captured on [%02d/%s/%04d:%02d:%02d:%02d.%03d] : %u\n",
			     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
			     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(date.tv_usec/1000),
			     error_snapshot_id);

		if (bi_putchk(si->ib, &trash) == -1) {
			/* Socket buffer full. Let's try again later from the same point */
			return 0;
		}

		si->applet.ctx.errors.px = proxy;
		si->applet.ctx.errors.buf = 0;
		si->applet.ctx.errors.bol = 0;
		si->applet.ctx.errors.ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (si->applet.ctx.errors.px) {
		struct error_snapshot *es;

		if (si->applet.ctx.errors.buf == 0)
			es = &si->applet.ctx.errors.px->invalid_req;
		else
			es = &si->applet.ctx.errors.px->invalid_rep;

		if (!es->when.tv_sec)
			goto next;

		if (si->applet.ctx.errors.iid >= 0 &&
		    si->applet.ctx.errors.px->uuid != si->applet.ctx.errors.iid &&
		    es->oe->uuid != si->applet.ctx.errors.iid)
			goto next;

		if (si->applet.ctx.errors.ptr < 0) {
			/* just print headers now */

			char pn[INET6_ADDRSTRLEN];
			struct tm tm;
			int port;

			get_localtime(es->when.tv_sec, &tm);
			chunk_appendf(&trash, " \n[%02d/%s/%04d:%02d:%02d:%02d.%03d]",
				     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
				     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(es->when.tv_usec/1000));

			switch (addr_to_str(&es->src, pn, sizeof(pn))) {
			case AF_INET:
			case AF_INET6:
				port = get_host_port(&es->src);
				break;
			default:
				port = 0;
			}

			switch (si->applet.ctx.errors.buf) {
			case 0:
				chunk_appendf(&trash,
					     " frontend %s (#%d): invalid request\n"
					     "  backend %s (#%d)",
					     si->applet.ctx.errors.px->id, si->applet.ctx.errors.px->uuid,
					     (es->oe->cap & PR_CAP_BE) ? es->oe->id : "<NONE>",
					     (es->oe->cap & PR_CAP_BE) ? es->oe->uuid : -1);
				break;
			case 1:
				chunk_appendf(&trash,
					     " backend %s (#%d) : invalid response\n"
					     "  frontend %s (#%d)",
					     si->applet.ctx.errors.px->id, si->applet.ctx.errors.px->uuid,
					     es->oe->id, es->oe->uuid);
				break;
			}

			chunk_appendf(&trash,
				     ", server %s (#%d), event #%u\n"
				     "  src %s:%d, session #%d, session flags 0x%08x\n"
				     "  HTTP msg state %d, msg flags 0x%08x, tx flags 0x%08x\n"
				     "  HTTP chunk len %lld bytes, HTTP body len %lld bytes\n"
				     "  buffer flags 0x%08x, out %d bytes, total %lld bytes\n"
				     "  pending %d bytes, wrapping at %d, error at position %d:\n \n",
				     es->srv ? es->srv->id : "<NONE>", es->srv ? es->srv->puid : -1,
				     es->ev_id,
				     pn, port, es->sid, es->s_flags,
				     es->state, es->m_flags, es->t_flags,
				     es->m_clen, es->m_blen,
				     es->b_flags, es->b_out, es->b_tot,
				     es->len, es->b_wrap, es->pos);

			if (bi_putchk(si->ib, &trash) == -1) {
				/* Socket buffer full. Let's try again later from the same point */
				return 0;
			}
			si->applet.ctx.errors.ptr = 0;
			si->applet.ctx.errors.sid = es->sid;
		}

		if (si->applet.ctx.errors.sid != es->sid) {
			/* the snapshot changed while we were dumping it */
			chunk_appendf(&trash,
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (bi_putchk(si->ib, &trash) == -1)
				return 0;
			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (si->applet.ctx.errors.ptr < es->len && si->applet.ctx.errors.ptr < sizeof(es->buf)) {
			int newptr;
			int newline;

			newline = si->applet.ctx.errors.bol;
			newptr = dump_text_line(&trash, es->buf, sizeof(es->buf), es->len, &newline, si->applet.ctx.errors.ptr);
			if (newptr == si->applet.ctx.errors.ptr)
				return 0;

			if (bi_putchk(si->ib, &trash) == -1) {
				/* Socket buffer full. Let's try again later from the same point */
				return 0;
			}
			si->applet.ctx.errors.ptr = newptr;
			si->applet.ctx.errors.bol = newline;
		};
	next:
		si->applet.ctx.errors.bol = 0;
		si->applet.ctx.errors.ptr = -1;
		si->applet.ctx.errors.buf++;
		if (si->applet.ctx.errors.buf > 1) {
			si->applet.ctx.errors.buf = 0;
			si->applet.ctx.errors.px = si->applet.ctx.errors.px->next;
		}
	}

	/* dump complete */
	return 1;
}

/* parse the "level" argument on the bind lines */
static int bind_parse_level(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing level", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!strcmp(args[cur_arg+1], "user"))
		conf->level = ACCESS_LVL_USER;
	else if (!strcmp(args[cur_arg+1], "operator"))
		conf->level = ACCESS_LVL_OPER;
	else if (!strcmp(args[cur_arg+1], "admin"))
		conf->level = ACCESS_LVL_ADMIN;
	else {
		memprintf(err, "'%s' only supports 'user', 'operator', and 'admin' (got '%s')",
			  args[cur_arg], args[cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

struct si_applet http_stats_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<STATS>", /* used for logging */
	.fct = http_stats_io_handler,
	.release = NULL,
};

static struct si_applet cli_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<CLI>", /* used for logging */
	.fct = cli_io_handler,
	.release = cli_release_handler,
};

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "stats", stats_parse_global },
	{ 0, NULL, NULL },
}};

static struct bind_kw_list bind_kws = { "STAT", { }, {
	{ "level",    bind_parse_level,    1 }, /* set the unix socket admin level */
	{ NULL, NULL, 0 },
}};

__attribute__((constructor))
static void __dumpstats_module_init(void)
{
	cfg_register_keywords(&cfg_kws);
	bind_register_keywords(&bind_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
