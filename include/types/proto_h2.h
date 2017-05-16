/*
 * include/types/proto_http.h
 * This file contains types and macros used for the HTTP/2 protocol
 *
 * Copyright (C) 2000-2016 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_PROTO_H2_H
#define _TYPES_PROTO_H2_H

#include <common/config.h>
#include <eb32tree.h>
#include <types/stream.h>
#include <types/task.h>


/* H2 connection state */
enum h2_cs {
	H2_CS_INIT,      // created, initialization in progress
	H2_CS_PREFACE,   // init done, waiting for connection preface
	H2_CS_SETTINGS1, // preface OK, waiting for first settings frame
	H2_CS_FRAME,     // first settings frame ok, waiting for regular frame
};

/* H2 stream state, in h2s->st */
enum h2_ss {
	H2_SS_IDLE = 0, // idle
	H2_SS_RLOC,     // reserved(local)
	H2_SS_RREM,     // reserved(remote)
	H2_SS_OPEN,     // open
	H2_SS_HREM,     // half-closed(remote)
	H2_SS_HLOC,     // half-closed(local)
	H2_SS_CLOSED,   // closed
	H2_SS_ENTRIES   // must be last
} __attribute__((packed));

/* H2 stream reset notifications, in h2s->rst */
#define H2_RST_NONE             0 // no RST exchanged
#define H2_RST_RECV             1 // received RST_STREAM
#define H2_RST_SENT             2 // sent RST_STREAM
#define H2_RST_BOTH             3 // sent and received RST_STREAM

enum h2_ft {
	H2_FT_DATA            = 0x00,     // RFC7540 #6.1
	H2_FT_HEADERS         = 0x01,     // RFC7540 #6.2
	H2_FT_PRIORITY        = 0x02,     // RFC7540 #6.3
	H2_FT_RST_STREAM      = 0x03,     // RFC7540 #6.4
	H2_FT_SETTINGS        = 0x04,     // RFC7540 #6.5
	H2_FT_PUSH_PROMISE    = 0x05,     // RFC7540 #6.6
	H2_FT_PING            = 0x06,     // RFC7540 #6.7
	H2_FT_GOAWAY          = 0x07,     // RFC7540 #6.8
	H2_FT_WINDOW_UPDATE   = 0x08,     // RFC7540 #6.9
	H2_FT_ENTRIES /* must be last */
};

/* flags defined for each frame type */

// RFC7540 #6.1
#define H2_F_DATA_END_STREAM 0x01
#define H2_F_DATA_PADDED     0x08

// RFC7540 #6.2
#define H2_F_HEADERS_END_STREAM  0x01
#define H2_F_HEADERS_END_HEADERS 0x04
#define H2_F_HEADERS_PADDED      0x08
#define H2_F_HEADERS_PRIORITY    0x20

// RFC7540 #6.3 : PRIORITY defines no flags
// RFC7540 #6.4 : RST_STREAM defines no flags
// RFC7540 #6.5
#define H2_F_SETTINGS_ACK   0x01

// RFC7540 #6.6
#define H2_F_PUSH_PROMISE_END_HEADERS 0x04
#define H2_F_PUSH_PROMISE_PADDED      0x08

// RFC7540 #6.7
#define H2_F_PING_ACK   0x01

// RFC7540 #6.8 : GOAWAY defines no flags
// RFC7540 #6.9 : WINDOW_UPDATE defines no flags

/* H2 connection descriptor */
struct h2c {
	struct appctx *appctx;
	struct eb_root streams_by_id; /* all active streams by their ID */
	int32_t max_id; /* highest ID known on this connection */

	/* states for the demux direction */
	int dsi; /* demux stream ID (<0 = idle) */
	int dfl; /* demux frame length (if dsi >= 0) */
	int dft; /* demux frame type (+ flags) (if dsi >= 0) */

	/* states for the mux direction */
	int msi; /* mux stream ID (<0 = idle) */
	int mfl; /* mux frame length (if dsi >= 0) */
	int mft; /* mux frame type (+ flags) (if dsi >= 0) */
};

/* H2 stream descriptor */
struct h2s {
	struct appctx *appctx;
	struct h2c *h2c;
	struct eb32_node by_id; /* place in h2c's streams_by_id */
	int32_t id; /* stream ID */
	enum h2_ss st;
	uint8_t rst;
	/* two unused bytes here */
};

#endif /* _TYPES_PROTO_H2_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
