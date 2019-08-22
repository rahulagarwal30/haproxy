/*
 * include/types/trace.h
 * This file provides definitions for runtime tracing
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_TRACE_H
#define _TYPES_TRACE_H

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/mini-clist.h>
#include <types/sink.h>

enum trace_state {
	TRACE_STATE_STOPPED = 0,  // completely disabled
	TRACE_STATE_WAITING,      // waiting for the start condition to happen
	TRACE_STATE_RUNNING,      // waiting for the stop or pause conditions
};

enum trace_level {
	TRACE_LEVEL_USER = 0,     // info useful to the end user
	TRACE_LEVEL_PAYLOAD,      // add info relevant to the payload
	TRACE_LEVEL_PROTO,        // add info relevant to the protocol
	TRACE_LEVEL_STATE,        // add info relevant to the state machine
	TRACE_LEVEL_DEVELOPER,    // add info useful only to the developer
};

enum trace_lockon {
	TRACE_LOCKON_NOTHING = 0, // don't lock on anything
	TRACE_LOCKON_THREAD,      // lock on the thread that started the trace
	TRACE_LOCKON_LISTENER,    // lock on the listener that started the trace
	TRACE_LOCKON_FRONTEND,    // lock on the frontend that started the trace
	TRACE_LOCKON_BACKEND,     // lock on the backend that started the trace
	TRACE_LOCKON_SERVER,      // lock on the server that started the trace
	TRACE_LOCKON_CONNECTION,  // lock on the connection that started the trace
	TRACE_LOCKON_SESSION,     // lock on the session that started the trace
	TRACE_LOCKON_STREAM,      // lock on the stream that started the trace
};

/* Each trace event maps a name to a mask in an uint64_t. Multiple bits are
 * permitted to have composite events. This is supposed to be stored into an
 * array terminated by mask 0 (name and desc are then ignored). Names "now",
 * "any" and "none" are reserved by the CLI parser for start/pause/stop
 * operations..
 */
struct trace_event {
	uint64_t mask;
	const char *name;
	const char *desc;
};

struct trace_source {
	/* source definition */
	const struct ist name;
	const char *desc;
	const struct trace_event *known_events;
	struct list source_link; // element in list of known trace sources
	/* trace configuration, adjusted by "trace <module>" on CLI */
	enum trace_lockon lockon;
	uint64_t start_events;   // what will start the trace. default: 0=nothing
	uint64_t pause_events;   // what will pause the trace. default: 0=nothing
	uint64_t stop_events;    // what will stop the trace. default: 0=nothing
	uint64_t report_events;  // mask of which events need to be reported.
	enum trace_level level;  // report traces up to this level of info
	int detail_level;        // report events with this level of detail (LOG_*)
	struct sink *sink;       // where to send the trace
	/* trace state part below */
	enum trace_state state;
	void *lockon_ptr;        // what to lockon when lockon is set
};

#endif /* _TYPES_TRACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
