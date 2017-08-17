/*
 * include/types/h2ch1.h
 * This file contains types and macros used for the HTTP/2 protocol
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

#ifndef _TYPES_H2CH1_H
#define _TYPES_H2CH1_H

#include <common/config.h>
#include <eb32tree.h>
#include <types/channel.h>
#include <types/hpack-hdr.h>
#include <types/stream.h>
#include <types/task.h>


/* H2 connection state, in h2c->appctx->st0 */
enum h2_cs {
	H2_CS_INIT,      // created, initialization in progress
	H2_CS_PREFACE,   // init done, waiting for connection preface
	H2_CS_SETTINGS1, // preface OK, waiting for first settings frame
	H2_CS_FRAME_H,   // first settings frame ok, waiting for frame header
	H2_CS_FRAME_P,   // frame header OK, waiting for frame payload
	H2_CS_FRAME_A,   // frame payload OK, trying to send ACK frame
	H2_CS_ERROR,     // send GOAWAY(errcode) and close the connection ASAP
	H2_CS_ERROR2,    // GOAWAY(errcode) sent, close the connection ASAP
	H2_CS_ENTRIES    // must be last
} __attribute__((packed));

/* Connection flags (32 bit), in h2c->flags */
#define H2_CF_NONE              0x00000000
#define H2_CF_BUFFER_FULL       0x00000001  // connection's buffer was full


/* H2 stream state, in h2s->st */
enum h2_ss {
	H2_SS_IDLE = 0, // idle
	H2_SS_INIT,     // allocation attempted (not part of the spec)
	H2_SS_RLOC,     // reserved(local)
	H2_SS_RREM,     // reserved(remote)
	H2_SS_OPEN,     // open
	H2_SS_HREM,     // half-closed(remote)
	H2_SS_HLOC,     // half-closed(local)
	H2_SS_CLOSED,   // closed
	H2_SS_ENTRIES   // must be last
} __attribute__((packed));

/* HTTP/2 stream flags (32 bit), in h2s->flags */
#define H2_SF_NONE              0x00000000
#define H2_SF_ES_RCVD           0x00000001
#define H2_SF_ES_SENT           0x00000002

/* H2 stream reset notifications, in h2s->rst */
#define H2_RST_NONE             0 // no RST exchanged
#define H2_RST_RECV             1 // received RST_STREAM
#define H2_RST_SENT             2 // sent RST_STREAM
#define H2_RST_BOTH             3 // sent and received RST_STREAM

/* H2 stream blocking reasons, in h2s->blocked */
enum h2s_blocked_reason {
	H2_BLK_NONE      = 0, // not blocked, not in any list
	H2_BLK_CANT      = 1, // can't send now ; in active list
	H2_BLK_FCTL_CONN = 2, // blocked by connection's fctl
	H2_BLK_FCTL_STRM = 3, // blocked by stream's fctl
} __attribute__((packed));


/* HTTP/2 message states */
enum h2_ms {
	H2_MS_HDR0 = 0, // before first HEADERS frame, HEADERS expected
	H2_MS_HDR1,     // non-final HEADERS frame seen, CONT expected
	H2_MS_BODY,     // final HEADERS frame seen, DATA expected (content-length / tunnel)
	H2_MS_BSIZE,    // H1->H2 body, chunk size expected
	H2_MS_BCHNK,    // H1->H2 body, chunk expected (creates a DATA frame)
	H2_MS_BCRLF,    // H1->H2 body, CRLF just after chunk
	H2_MS_TRL0,     // before non-final HEADERS frame, after DATA (trailers)
	H2_MS_TRL1,     // non-final HEADERS frame seen after DATA (trailers)
	H2_MS_TRL2,     // final HEADERS frame seen after DATA (trailers)
	H2_MS_ENTRIES   // must be last
} __attribute__((packed));

/* HTTP/2 message flags (32 bit), in h2m->flags */
#define H2_MF_NONE              0x00000000
#define H2_MF_CLEN              0x00000001 // content-length present
#define H2_MF_CHNK              0x00000002 // chunk present, exclusive with c-l


/* H2 connection descriptor */
struct h2c {
	struct appctx *appctx;
	struct eb_root streams_by_id; /* all active streams by their ID */
	struct list active_list; /* list of active streams currently blocked */
	int32_t max_id; /* highest ID known on this connection */
	uint32_t flags; /* connection flags: H2_CF_* */
	uint32_t rcvd_c; /* newly received data to ACK for the connection */
	uint32_t rcvd_s; /* newly received data to ACK for the current stream (dsi) */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */

	/* states for the demux direction */
	struct hpack_dht *ddht; /* demux dynamic header table */
	int dsi; /* demux stream ID (<0 = idle) */
	int dfl; /* demux frame length (if dsi >= 0) */
	int dft; /* demux frame type (+ flags) (if dsi >= 0) */
	int last_sid; /* last stream ID after a GOAWAY was sent (<0 = none) */

	/* states for the mux direction */
	int msi; /* mux stream ID (<0 = idle) */
	int mfl; /* mux frame length (if dsi >= 0) */
	int mft; /* mux frame type (+ flags) (if dsi >= 0) */
	int miw; /* mux initial window size for all new streams */
	int mws; /* mux window size. Can be negative. */
	int mfs; /* mux's max frame size */
};

/* H2 message descriptor */
struct h2m {
	enum h2_ms state;    // H2 message state (H2_MS_*)
	uint32_t flags;      // H2_MF_*
	uint64_t curr_len;   // content-length or last chunk length
	uint64_t body_len;   // total known size of the body length
	int err_pos;         // position in the byte stream of the first error (H1 or H2)
	int err_state;       // state where the first error was met (H1 or H2)
	struct channel *chn; // channel holding the clear-text HTTP message
};

/* H2 stream descriptor */
struct h2s {
	struct appctx *appctx;
	struct h2c *h2c;
	struct h2m req, res; /* request and response parser state */
	struct eb32_node by_id; /* place in h2c's streams_by_id */
	struct list list; /* position in active/blocked lists if blocked>0 */
	int32_t id; /* stream ID */
	uint32_t flags;      /* H2_SF_* */
	int mws;             /* mux window size for this stream */
	enum h2_err errcode; /* H2 err code (H2_ERR_*) */
	enum h2_ss st;
	uint8_t rst;
	enum h2s_blocked_reason blocked;
};

#endif /* _TYPES_H2CH1_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
