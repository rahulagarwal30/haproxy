/*
  include/types/proxy.h
  This file defines everything related to proxies.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_PROXY_H
#define _TYPES_PROXY_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/appsession.h>
#include <common/config.h>
#include <common/ebtree.h>
#include <common/mini-clist.h>
#include <common/regex.h>
#include <common/sessionhash.h>
#include <common/tools.h>

#include <types/acl.h>
#include <types/buffers.h>
#include <types/httperr.h>
#include <types/protocols.h>
#include <types/session.h>
#include <types/server.h>

/* values for proxy->state */
#define PR_STNEW        0
#define PR_STIDLE       1
#define PR_STRUN        2
#define PR_STSTOPPED    3
#define PR_STPAUSED     4
#define PR_STERROR      5

/* values for proxy->mode */
#define PR_MODE_TCP     0
#define PR_MODE_HTTP    1
#define PR_MODE_HEALTH  2

/* values for proxy->lbprm.map.state */
#define PR_MAP_RECALC  (1 << 0)

/* flag values for proxy->cap. This is a bitmask of capabilities supported by the proxy */
#define PR_CAP_NONE    0x0000
#define PR_CAP_FE      0x0001
#define PR_CAP_BE      0x0002
#define PR_CAP_RS      0x0004
#define PR_CAP_LISTEN  (PR_CAP_FE|PR_CAP_BE|PR_CAP_RS)

/* bits for proxy->options */
#define PR_O_REDISP     0x00000001      /* allow reconnection to dispatch in case of errors */
#define PR_O_TRANSP     0x00000002      /* transparent mode : use original DEST as dispatch */
#define PR_O_COOK_RW    0x00000004      /* rewrite all direct cookies with the right serverid */
#define PR_O_COOK_IND   0x00000008      /* keep only indirect cookies */
#define PR_O_COOK_INS   0x00000010      /* insert cookies when not accessing a server directly */
#define PR_O_COOK_PFX   0x00000020      /* rewrite all cookies by prefixing the right serverid */
#define PR_O_COOK_ANY   (PR_O_COOK_RW | PR_O_COOK_IND | PR_O_COOK_INS | PR_O_COOK_PFX)
#define PR_O_SMTP_CHK   0x00000040      /* use SMTP EHLO check for server health - pvandijk@vision6.com.au */
#define PR_O_KEEPALIVE  0x00000080      /* follow keep-alive sessions */
#define PR_O_FWDFOR     0x00000100      /* insert x-forwarded-for with client address */
#define PR_O_BIND_SRC   0x00000200      /* bind to a specific source address when connect()ing */
#define PR_O_NULLNOLOG  0x00000400      /* a connect without request will not be logged */
#define PR_O_COOK_NOC   0x00000800      /* add a 'Cache-control' header with the cookie */
#define PR_O_COOK_POST  0x00001000      /* don't insert cookies for requests other than a POST */
#define PR_O_HTTP_CHK   0x00002000      /* use HTTP 'OPTIONS' method to check server health */
#define PR_O_PERSIST    0x00004000      /* server persistence stays effective even when server is down */
#define PR_O_LOGASAP    0x00008000      /* log as soon as possible, without waiting for the session to complete */
#define PR_O_HTTP_CLOSE 0x00010000      /* force 'connection: close' in both directions */
#define PR_O_CHK_CACHE  0x00020000      /* require examination of cacheability of the 'set-cookie' field */
#define PR_O_TCP_CLI_KA 0x00040000      /* enable TCP keep-alive on client-side sessions */
#define PR_O_TCP_SRV_KA 0x00080000      /* enable TCP keep-alive on server-side sessions */
#define PR_O_USE_ALL_BK 0x00100000      /* load-balance between backup servers */
#define PR_O_FORCE_CLO  0x00200000      /* enforce the connection close immediately after server response */
#define PR_O_TCP_NOLING 0x00400000      /* disable lingering on client and server connections */
#define PR_O_ABRT_CLOSE 0x00800000      /* immediately abort request when client closes */
#define PR_O_SSL3_CHK   0x01000000      /* use SSLv3 CLIENT_HELLO packets for server health */

/* TPXY: exclusive values */
#define PR_O_TPXY_ADDR  0x02000000	/* bind to this non-local address when connect()ing */
#define PR_O_TPXY_CIP	0x04000000	/* bind to the client's IP address when connect()ing */
#define PR_O_TPXY_CLI	0x06000000	/* bind to the client's IP+port when connect()ing */
#define PR_O_TPXY_MASK	0x06000000	/* bind to a non-local address when connect()ing */

#define PR_O_TCPSPLICE	0x08000000      /* delegate data transfer to linux kernel's tcp_splice */
#define PR_O_CONTSTATS	0x10000000	/* continous counters */

/* This structure is used to apply fast weighted round robin on a server group */
struct fwrr_group {
	struct eb_root curr;    /* tree for servers in "current" time range */
	struct eb_root t0, t1;  /* "init" and "next" servers */
	struct eb_root *init;   /* servers waiting to be placed */
	struct eb_root *next;   /* servers to be placed at next run */
	int curr_pos;           /* current position in the tree */
	int curr_weight;        /* total weight of the current time range */
	int next_weight;        /* total weight of the next time range */
}; 

struct proxy {
	struct listener *listen;		/* the listen addresses and sockets */
	struct in_addr mon_net, mon_mask;	/* don't forward connections from this net (network order) FIXME: should support IPv6 */
	int state;				/* proxy state */
	int options;				/* PR_O_REDISP, PR_O_TRANSP, ... */
	int mode;				/* mode = PR_MODE_TCP, PR_MODE_HTTP or PR_MODE_HEALTH */
	struct sockaddr_in dispatch_addr;	/* the default address to connect to */
	union {
		struct proxy *be;		/* default backend, or NULL if none set */
		char *name;			/* default backend name during config parse */
	} defbe;
	struct list acl;                        /* ACL declared on this proxy */
	struct list block_cond;                 /* early blocking conditions (chained) */
	struct list switching_rules;            /* content switching rules (chained) */
	struct server *srv;			/* known servers */
	int srv_act, srv_bck;			/* # of servers eligible for LB (UP|!checked) AND (enabled+weight!=0) */

	struct {
		int algo;			/* load balancing algorithm and variants: BE_LB_ALGO* */
		int tot_wact, tot_wbck;		/* total effective weights of active and backup servers */
		int tot_weight;			/* total effective weight of servers participating to LB */
		int tot_used;			/* total number of servers used for LB */
		int wmult;			/* ratio between user weight and effective weight */
		int wdiv;			/* ratio between effective weight and user weight */
		struct server *fbck;		/* first backup server when !PR_O_USE_ALL_BK, or NULL */
		struct {
			struct server **srv;	/* the server map used to apply weights */
			int rr_idx;		/* next server to be elected in round robin mode */
			int state;		/* PR_MAP_RECALC */
		} map;				/* LB parameters for map-based algorithms */
		struct {
			struct fwrr_group act;	/* weighted round robin on the active servers */
			struct fwrr_group bck;	/* weighted round robin on the backup servers */
		} fwrr;
		void (*update_server_eweight)(struct server *);/* if non-NULL, to be called after eweight change */
		void (*set_server_status_up)(struct server *);/* to be called after status changes to UP */
		void (*set_server_status_down)(struct server *);/* to be called after status changes to DOWN */
	} lbprm;				/* LB parameters for all algorithms */

	char *cookie_name;			/* name of the cookie to look for */
	int  cookie_len;			/* strlen(cookie_name), computed only once */
	char *url_param_name;			/* name of the URL parameter used for hashing */
	int  url_param_len;			/* strlen(url_param_name), computed only once */
	char *appsession_name;			/* name of the cookie to look for */
	int  appsession_name_len;		/* strlen(appsession_name), computed only once */
	int  appsession_len;			/* length of the appsession cookie value to be used */
	struct appsession_hash htbl_proxy;	/* Per Proxy hashtable */
	char *capture_name;			/* beginning of the name of the cookie to capture */
	int  capture_namelen;			/* length of the cookie name to match */
	int  capture_len;			/* length of the string to be captured */
	struct uri_auth *uri_auth;		/* if non-NULL, the (list of) per-URI authentications */
	char *monitor_uri;			/* a special URI to which we respond with HTTP/200 OK */
	int monitor_uri_len;			/* length of the string above. 0 if unused */
	struct timeval clitimeout;		/* client I/O timeout (in milliseconds) */
	struct timeval srvtimeout;		/* server I/O timeout (in milliseconds) */
	struct timeval contimeout;		/* connect timeout (in milliseconds) */
	struct timeval appsession_timeout;
	char *id;				/* proxy id */
	struct list pendconns;			/* pending connections with no server assigned yet */
	int nbpend, nbpend_max;			/* number of pending connections with no server assigned yet */
	int totpend;				/* total number of pending connections on this instance (for stats) */
	unsigned int feconn, feconn_max;	/* # of active frontend sessions */
	unsigned int beconn, beconn_max;	/* # of active backend sessions */
	unsigned int cum_feconn, cum_beconn;	/* cumulated number of processed sessions */
	unsigned int maxconn;			/* max # of active sessions on the frontend */
	unsigned int fullconn;			/* #conns on backend above which servers are used at full load */
	struct in_addr except_net, except_mask; /* don't x-forward-for for this address. FIXME: should support IPv6 */

	unsigned down_trans;			/* up-down transitions */
	unsigned down_time;			/* total time the proxy was down */
	time_t last_change;			/* last time, when the state was changed */

	unsigned failed_conns, failed_resp;	/* failed connect() and responses */
	unsigned retries, redispatches;		/* retried and redispatched connections */
	unsigned denied_req, denied_resp;	/* blocked requests/responses because of security concerns */
	unsigned failed_req;			/* failed requests (eg: invalid or timeout) */
	long long bytes_in;			/* number of bytes transferred from the client to the server */
	long long bytes_out;			/* number of bytes transferred from the server to the client */
	int conn_retries;			/* maximum number of connect retries */
	int cap;				/* supported capabilities (PR_CAP_*) */
	struct sockaddr_in source_addr;		/* the address to which we want to bind for connect() */
#ifdef CONFIG_HAP_CTTPROXY
	struct sockaddr_in tproxy_addr;		/* non-local address we want to bind to for connect() */
#endif
	struct proxy *next;
	struct sockaddr_in logsrv1, logsrv2;	/* 2 syslog servers */
	signed char logfac1, logfac2;		/* log facility for both servers. -1 = disabled */
	int loglev1, loglev2;			/* log level for each server, 7 by default */
	int to_log;				/* things to be logged (LW_*) */
	struct timeval stop_time;		/* date to stop listening, when stopping != 0 */
	int nb_reqadd, nb_rspadd;
	struct hdr_exp *req_exp;		/* regular expressions for request headers */
	struct hdr_exp *rsp_exp;		/* regular expressions for response headers */
	int nb_req_cap, nb_rsp_cap;		/* # of headers to be captured */
	struct cap_hdr *req_cap;		/* chained list of request headers to be captured */
	struct cap_hdr *rsp_cap;		/* chained list of response headers to be captured */
	struct pool_head *req_cap_pool,		/* pools of pre-allocated char ** used to build the sessions */
	                 *rsp_cap_pool;
	struct pool_head *hdr_idx_pool;         /* pools of pre-allocated int* used for headers indexing */
	char *req_add[MAX_NEWHDR], *rsp_add[MAX_NEWHDR]; /* headers to be added */
	int grace;				/* grace time after stop request */
	char *check_req;			/* HTTP or SSL request to use for PR_O_HTTP_CHK|PR_O_SSL3_CHK */
	int check_len;				/* Length of the HTTP or SSL3 request */
	struct chunk errmsg[HTTP_ERR_SIZE];	/* default or customized error messages for known errors */
	int uuid;				/* universally unique proxy ID, used for SNMP */
	int next_svid;				/* next server-id, used for SNMP */
};

struct switching_rule {
	struct list list;			/* list linked to from the proxy */
	struct acl_cond *cond;			/* acl condition to meet */
	union {
		struct proxy *backend;		/* target backend */
		char *name;			/* target backend name during config parsing */
	} be;
};

extern struct proxy *proxy;
extern int next_pxid;

#endif /* _TYPES_PROXY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
