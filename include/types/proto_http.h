/*
 * include/types/proto_http.h
 * This file contains HTTP protocol definitions.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_PROTO_HTTP_H
#define _TYPES_PROTO_HTTP_H

#include <common/buf.h>
#include <common/config.h>
#include <common/http.h>
#include <common/mini-clist.h>
#include <common/regex.h>

#include <types/channel.h>
#include <types/filters.h>
//#include <types/sample.h>

/* These are the flags that are found in txn->flags */

/* action flags */
#define TX_CLDENY	0x00000001	/* a client header matches a deny regex */
#define TX_CLALLOW	0x00000002	/* a client header matches an allow regex */
#define TX_SVDENY	0x00000004	/* a server header matches a deny regex */
#define TX_SVALLOW	0x00000008	/* a server header matches an allow regex */
#define TX_CLTARPIT	0x00000010	/* the transaction is tarpitted (anti-dos) */

/* transaction flags dedicated to cookies : bits values 0x20 to 0x80 (0-7 shift 5) */
#define TX_CK_NONE	0x00000000	/* this transaction had no cookie */
#define TX_CK_INVALID	0x00000020	/* this transaction had a cookie which matches no server */
#define TX_CK_DOWN	0x00000040	/* this transaction had cookie matching a down server */
#define TX_CK_VALID	0x00000060	/* this transaction had cookie matching a valid server */
#define TX_CK_EXPIRED	0x00000080	/* this transaction had an expired cookie (idle for too long) */
#define TX_CK_OLD	0x000000A0	/* this transaction had too old a cookie (offered too long ago) */
#define TX_CK_UNUSED	0x000000C0	/* this transaction had a cookie but it was not used (eg: use-server was preferred) */
#define TX_CK_MASK	0x000000E0	/* mask to get this transaction's cookie flags */
#define TX_CK_SHIFT	5		/* bit shift */

/* response cookie information, bits values 0x100 to 0x700 (0-7 shift 8) */
#define TX_SCK_NONE	0x00000000	/* no cookie found in the response */
#define TX_SCK_FOUND    0x00000100	/* a persistence cookie was found and forwarded */
#define TX_SCK_DELETED	0x00000200	/* an existing persistence cookie was deleted */
#define TX_SCK_INSERTED	0x00000300	/* a persistence cookie was inserted */
#define TX_SCK_REPLACED	0x00000400	/* a persistence cookie was present and rewritten */
#define TX_SCK_UPDATED	0x00000500	/* an expirable persistence cookie was updated */
#define TX_SCK_MASK	0x00000700	/* mask to get the set-cookie field */
#define TX_SCK_SHIFT	8		/* bit shift */

#define TX_SCK_PRESENT  0x00000800	/* a cookie was found in the server's response */

/* cacheability management, bits values 0x1000 to 0x3000 (0-3 shift 12) */
#define TX_CACHEABLE	0x00001000	/* at least part of the response is cacheable */
#define TX_CACHE_COOK	0x00002000	/* a cookie in the response is cacheable */
#define TX_CACHE_IGNORE 0x00004000	/* do not retrieve object from cache */
#define TX_CACHE_SHIFT	12		/* bit shift */

/* Unused: 0x8000 */

#define TX_WAIT_CLEANUP	0x0010000	/* this transaction is waiting for a clean up */

/* Unused: 0x20000, 0x80000 */


/* indicate how we *want* the connection to behave, regardless of what is in
 * the headers. We have 4 possible values right now :
 * - WANT_KAL : try to maintain keep-alive (default when nothing configured)
 * - WANT_TUN : will be a tunnel (CONNECT).
 * - WANT_SCL : enforce close on the server side
 * - WANT_CLO : enforce close on both sides
 */
#define TX_CON_WANT_KAL 0x00000000	/* note: it's important that it is 0 (init) */
#define TX_CON_WANT_TUN 0x00100000
#define TX_CON_WANT_SCL 0x00200000
#define TX_CON_WANT_CLO 0x00300000
#define TX_CON_WANT_MSK 0x00300000	/* this is the mask to get the bits */

#define TX_CON_CLO_SET  0x00400000	/* "connection: close" is now set */
#define TX_CON_KAL_SET  0x00800000	/* "connection: keep-alive" is now set */

/* unused: 0x01000000 */

#define TX_HDR_CONN_UPG 0x02000000	/* The "Upgrade" token was found in the "Connection" header */
#define TX_WAIT_NEXT_RQ	0x04000000	/* waiting for the second request to start, use keep-alive timeout */

#define TX_HDR_CONN_PRS	0x08000000	/* "connection" header already parsed (req or res), results below */
#define TX_HDR_CONN_CLO	0x10000000	/* "Connection: close" was present at least once */
#define TX_HDR_CONN_KAL	0x20000000	/* "Connection: keep-alive" was present at least once */
#define TX_USE_PX_CONN	0x40000000	/* Use "Proxy-Connection" instead of "Connection" */

/* used only for keep-alive purposes, to indicate we're on a second transaction */
#define TX_NOT_FIRST	0x80000000	/* the transaction is not the first one */
/* no more room for transaction flags ! */

/* The HTTP parser is more complex than it looks like, because we have to
 * support multi-line headers and any number of spaces between the colon and
 * the value.
 *
 * All those examples must work :

 Hdr1:val1\r\n
 Hdr1: val1\r\n
 Hdr1:\t val1\r\n
 Hdr1: \r\n
  val1\r\n
 Hdr1:\r\n
  val1\n
 \tval2\r\n
  val3\n

 *
 */

/*
 * HTTP message status flags (msg->flags)
 */
#define HTTP_MSGF_CNT_LEN     0x00000001  /* content-length was found in the message */
#define HTTP_MSGF_TE_CHNK     0x00000002  /* transfer-encoding: chunked was found */

/* if this flags is not set in either direction, we may be forced to complete a
 * connection as a half-way tunnel (eg if no content-length appears in a 1.1
 * response, but the request is correctly sized)
 */
#define HTTP_MSGF_XFER_LEN    0x00000004  /* message xfer size can be determined */
#define HTTP_MSGF_VER_11      0x00000008  /* the message is HTTP/1.1 or above */

/* If this flag is set, we don't process the body until the connect() is confirmed.
 * This is only used by the request forwarding function to protect the buffer
 * contents if something needs them during a redispatch.
 */
#define HTTP_MSGF_WAIT_CONN   0x00000010  /* Wait for connect() to be confirmed before processing body */
#define HTTP_MSGF_COMPRESSING 0x00000020  /* data compression is in progress */

#define HTTP_MSGF_BODYLESS    0x00000040  /* The message has no body (content-length = 0) */


/* Redirect flags */
enum {
	REDIRECT_FLAG_NONE = 0,
	REDIRECT_FLAG_DROP_QS = 1,	/* drop query string */
	REDIRECT_FLAG_APPEND_SLASH = 2,	/* append a slash if missing at the end */
};

/* Redirect types (location, prefix, extended ) */
enum {
	REDIRECT_TYPE_NONE = 0,         /* no redirection */
	REDIRECT_TYPE_LOCATION,         /* location redirect */
	REDIRECT_TYPE_PREFIX,           /* prefix redirect */
	REDIRECT_TYPE_SCHEME,           /* scheme redirect (eg: switch from http to https) */
};

/* Perist types (force-persist, ignore-persist) */
enum {
	PERSIST_TYPE_NONE = 0,          /* no persistence */
	PERSIST_TYPE_FORCE,             /* force-persist */
	PERSIST_TYPE_IGNORE,            /* ignore-persist */
};

/* final results for http-request rules */
enum rule_result {
	HTTP_RULE_RES_CONT = 0,  /* nothing special, continue rules evaluation */
	HTTP_RULE_RES_YIELD,     /* call me later because some data is missing. */
	HTTP_RULE_RES_STOP,      /* stopped processing on an accept */
	HTTP_RULE_RES_DENY,      /* deny (or tarpit if TX_CLTARPIT)  */
	HTTP_RULE_RES_ABRT,      /* abort request, msg already sent (eg: auth) */
	HTTP_RULE_RES_DONE,      /* processing done, stop processing (eg: redirect) */
	HTTP_RULE_RES_BADREQ,    /* bad request */
};

/* Legacy version of the HTTP/1 message state, used by the channels, should
 * ultimately be removed.
 */
enum h1_state {
	HTTP_MSG_RQBEFORE     =  0, // request: leading LF, before start line
	HTTP_MSG_RPBEFORE     =  1, // response: leading LF, before start line

	/* error state : must be before HTTP_MSG_BODY so that (>=BODY) always indicates
	 * that data are being processed.
	 */
	HTTP_MSG_ERROR        =  2, // an error occurred
	/* Body processing.
	 * The state HTTP_MSG_BODY is a delimiter to know if we're waiting for headers
	 * or body. All the sub-states below also indicate we're processing the body,
	 * with some additional information.
	 */
	HTTP_MSG_BODY         =  3, // parsing body at end of headers
	HTTP_MSG_DATA         =  4, // skipping data chunk / content-length data
	/* we enter this state when we've received the end of the current message */
	HTTP_MSG_ENDING       =  5, // message end received, wait that the filters end too
	HTTP_MSG_DONE         =  6, // message end received, waiting for resync or close
	HTTP_MSG_CLOSING      =  7, // shutdown_w done, not all bytes sent yet
	HTTP_MSG_CLOSED       =  8, // shutdown_w done, all bytes sent
	HTTP_MSG_TUNNEL       =  9, // tunneled data after DONE
} __attribute__((packed));


/* This is the state of an HTTP seen from the analyzers point of view. It can be
 * either a request message or a response message.
 */
struct http_msg {
	enum h1_state msg_state;               /* where we are in the current message parsing */
	enum h1_state err_state;               /* the state where the parsing error was detected, only is MSG_ERROR */
	unsigned char flags;                   /* flags describing the message (HTTP version, ...) */
	/* 5 bytes unused here */
	struct channel *chn;                   /* pointer to the channel transporting the message */
};

/* This is an HTTP transaction. It contains both a request message and a
 * response message (which can be empty).
 */
struct http_txn {
	struct http_msg rsp;            /* HTTP response message */
	struct http_msg req;            /* HTTP request message */
	unsigned int flags;             /* transaction flags */
	enum http_meth_t meth;          /* HTTP method */
	/* 1 unused byte here */
	short status;                   /* HTTP status from the server, negative if from proxy */

	char cache_hash[20];               /* Store the cache hash  */
	char *uri;                      /* first line if log needed, NULL otherwise */
	char *cli_cookie;               /* cookie presented by the client, in capture mode */
	char *srv_cookie;               /* cookie presented by the server, in capture mode */
	int cookie_first_date;          /* if non-zero, first date the expirable cookie was set/seen */
	int cookie_last_date;           /* if non-zero, last date the expirable cookie was set/seen */

	struct http_auth_data auth;	/* HTTP auth data */
};

extern struct pool_head *pool_head_http_txn;

#endif /* _TYPES_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
