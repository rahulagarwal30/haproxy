/*
  include/types/session.h
  This file defines everything related to sessions.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_SESSION_H
#define _TYPES_SESSION_H


#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/config.h>
#include <common/mini-clist.h>

#include <types/buffers.h>
#include <types/proxy.h>
#include <types/queue.h>
#include <types/server.h>
#include <types/task.h>
#include <types/hdr_idx.h>


/* various session flags, bits values 0x01 to 0x20 (shift 0) */
#define SN_DIRECT	0x00000001	/* connection made on the server matching the client cookie */
#define SN_CLDENY	0x00000002	/* a client header matches a deny regex */
#define SN_CLALLOW	0x00000004	/* a client header matches an allow regex */
#define SN_SVDENY	0x00000008	/* a server header matches a deny regex */
#define SN_SVALLOW	0x00000010	/* a server header matches an allow regex */
#define SN_BE_ASSIGNED	0x00000020	/* a backend was assigned. Conns are accounted. */

/* session flags dedicated to cookies : bits values 0x40, 0x80 (0-3 shift 6) */
#define	SN_CK_NONE	0x00000000	/* this session had no cookie */
#define	SN_CK_INVALID	0x00000040	/* this session had a cookie which matches no server */
#define	SN_CK_DOWN	0x00000080	/* this session had cookie matching a down server */
#define	SN_CK_VALID	0x000000C0	/* this session had cookie matching a valid server */
#define	SN_CK_MASK	0x000000C0	/* mask to get this session's cookie flags */
#define SN_CK_SHIFT	6		/* bit shift */

/* session termination conditions, bits values 0x100 to 0x700 (0-7 shift 8) */
#define SN_ERR_NONE     0x00000000
#define SN_ERR_CLITO	0x00000100	/* client time-out */
#define SN_ERR_CLICL	0x00000200	/* client closed (read/write error) */
#define SN_ERR_SRVTO	0x00000300	/* server time-out, connect time-out */
#define SN_ERR_SRVCL	0x00000400	/* server closed (connect/read/write error) */
#define SN_ERR_PRXCOND	0x00000500	/* the proxy decided to close (deny...) */
#define SN_ERR_RESOURCE	0x00000600	/* the proxy encountered a lack of a local resources (fd, mem, ...) */
#define SN_ERR_INTERNAL	0x00000700	/* the proxy encountered an internal error */
#define SN_ERR_MASK	0x00000700	/* mask to get only session error flags */
#define SN_ERR_SHIFT	8		/* bit shift */

/* session state at termination, bits values 0x1000 to 0x7000 (0-7 shift 12) */
#define SN_FINST_R	0x00001000	/* session ended during client request */
#define SN_FINST_C	0x00002000	/* session ended during server connect */
#define SN_FINST_H	0x00003000	/* session ended during server headers */
#define SN_FINST_D	0x00004000	/* session ended during data phase */
#define SN_FINST_L	0x00005000	/* session ended while pushing last data to client */
#define SN_FINST_Q	0x00006000	/* session ended while waiting in queue for a server slot */
#define SN_FINST_T	0x00007000	/* session ended tarpitted */
#define SN_FINST_MASK	0x00007000	/* mask to get only final session state flags */
#define	SN_FINST_SHIFT	12		/* bit shift */

/* cookie information, bits values 0x10000 to 0x80000 (0-8 shift 16) */
#define	SN_SCK_NONE	0x00000000	/* no set-cookie seen for the server cookie */
#define	SN_SCK_DELETED	0x00010000	/* existing set-cookie deleted or changed */
#define	SN_SCK_INSERTED	0x00020000	/* new set-cookie inserted or changed existing one */
#define	SN_SCK_SEEN	0x00040000	/* set-cookie seen for the server cookie */
#define	SN_SCK_MASK	0x00070000	/* mask to get the set-cookie field */
#define	SN_SCK_ANY	0x00080000	/* at least one set-cookie seen (not to be counted) */
#define	SN_SCK_SHIFT	16		/* bit shift */

/* cacheability management, bits values 0x100000 to 0x300000 (0-3 shift 20) */
#define	SN_CACHEABLE	0x00100000	/* at least part of the response is cacheable */
#define	SN_CACHE_COOK	0x00200000	/* a cookie in the response is cacheable */
#define	SN_CACHE_SHIFT	20		/* bit shift */

/* various other session flags, bits values 0x400000 and above */
#define SN_MONITOR	0x00400000	/* this session comes from a monitoring system */
#define SN_ASSIGNED	0x00800000	/* no need to assign a server to this session */
#define SN_ADDR_SET	0x01000000	/* this session's server address has been set */
#define SN_SELF_GEN	0x02000000	/* the proxy generates data for the client (eg: stats) */
#define SN_CLTARPIT	0x04000000	/* the session is tarpitted (anti-dos) */

typedef enum {
	HTTP_METH_NONE = 0,
	HTTP_METH_OPTIONS,
	HTTP_METH_GET,
	HTTP_METH_HEAD,
	HTTP_METH_POST,
	HTTP_METH_PUT,
	HTTP_METH_DELETE,
	HTTP_METH_TRACE,
	HTTP_METH_CONNECT,
	HTTP_METH_OTHER,
} http_meth_t;

/* FIXME-20070107: this should move out to another file when HTTP will not be
 * in the session anymore.
 */

/* This is an HTTP message, as described in RFC2616. It can be either a request
 * message or a response message.
 *
 * The values there are a little bit obscure, because their meaning can change
 * during the parsing :
 *
 *  - sor (Start of Request) : relative offset in the buffer of first byte of
 *                             the request being processed or parsed. Reset to
 *                             zero during accept().
 *  - eoh (End of Headers)   : relative offset in the buffer of first byte that
 *                             is not part of a completely processed header.
 *                             During parsing, it points to last header seen
 *                             for states after START.
 *  - eol (End of Line)      : relative offset in the buffer of the first byte
 *                             which marks the end of the line (LF or CRLF).
 */
struct http_msg {
	int hdr_state;                  /* where we are in the current header parsing */
	int sor, eoh;			/* Start Of Request and End Of Headers, relative to buffer */
	int eol;			/* end of line */
	char **cap;			/* array of captured request headers (may be NULL) */
};

/* This is an HTTP request, as described in RFC2616. It contains both a request
 * message and a response message (which can be empty).
 */
struct http_req {
	int req_state;                  /* what we are currently parsing */
	http_meth_t meth;		/* HTTP method */
	struct hdr_idx hdr_idx;         /* array of header indexes (max: MAX_HTTP_HDR) */
	struct chunk start;		/* points to first line, called "start line" in RFC2616 */
	struct chunk auth_hdr;		/* points to 'Authorization:' header */
	struct http_msg req, rsp;	/* HTTP request and response messages */
};

/* WARNING: if new fields are added, they must be initialized in event_accept()
 * and freed in session_free() !
 */
struct session {
	struct task *task;			/* the task associated with this session */
	/* application specific below */
	struct proxy *fe;			/* the proxy this session depends on for the client side */
	struct proxy *be;			/* the proxy this session depends on for the server side */
	int cli_fd;				/* the client side fd */
	int srv_fd;				/* the server side fd */
	int cli_state;				/* state of the client side */
	int srv_state;				/* state of the server side */
	int conn_retries;			/* number of connect retries left */
	int flags;				/* some flags describing the session */
	struct buffer *req;			/* request buffer */
	struct buffer *rep;			/* response buffer */
	struct sockaddr_storage cli_addr;	/* the client address */
	struct sockaddr_in srv_addr;		/* the address to connect to */
	struct server *srv;			/* the server being used */
	struct pendconn *pend_pos;		/* if not NULL, points to the position in the pending queue */
	char **rsp_cap;				/* array of captured response headers (may be NULL) */
	struct http_req hreq;			/* current HTTP request being processed. Should become a list. */
	struct {
		int logwait;			/* log fields waiting to be collected : LW_* */
		struct timeval tv_accept;	/* date of the accept() (beginning of the session) */
		long  t_request;		/* delay before the end of the request arrives, -1 if never occurs */
		long  t_queue;			/* delay before the session gets out of the connect queue, -1 if never occurs */
		long  t_connect;		/* delay before the connect() to the server succeeds, -1 if never occurs */
		long  t_data;			/* delay before the first data byte from the server ... */
		unsigned long  t_close;		/* total session duration */
		unsigned long srv_queue_size;	/* number of sessions waiting for a connect slot on this server at accept() time (in direct assignment) */
		unsigned long prx_queue_size;	/* overall number of sessions waiting for a connect slot on this instance at accept() time */
		char *uri;			/* first line if log needed, NULL otherwise */
		char *cli_cookie;		/* cookie presented by the client, in capture mode */
		char *srv_cookie;		/* cookie presented by the server, in capture mode */
		int status;			/* HTTP status from the server, negative if from proxy */
		long long bytes_in;		/* number of bytes transferred from the client to the server */
		long long bytes_out;		/* number of bytes transferred from the server to the client */
	} logs;
	short int data_source;			/* where to get the data we generate ourselves */
	short int data_state;			/* where to get the data we generate ourselves */
	union {
		struct {
			struct proxy *px;
			struct server *sv;
			short px_st, sv_st;	/* DATA_ST_INIT or DATA_ST_DATA */
		} stats;
	} data_ctx;				/* used by produce_content to dump the stats right now */
	unsigned int uniq_id;			/* unique ID used for the traces */
};


#define sizeof_session  sizeof(struct session)
extern void **pool_session;


#endif /* _TYPES_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
