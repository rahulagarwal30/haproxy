/*
  include/types/proto_http.h
  This file contains HTTP protocol definitions.

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

#ifndef _TYPES_PROTO_HTTP_H
#define _TYPES_PROTO_HTTP_H

#include <common/config.h>

/*
 * FIXME: break this into HTTP state and TCP socket state.
 * See server.h for the other end.
 */

/* different possible states for the client side */
#define CL_STHEADERS	0
#define CL_STDATA	1
#define CL_STSHUTR	2
#define CL_STSHUTW	3
#define CL_STCLOSE	4

/*
 * FIXME: break this into HTTP state and TCP socket state.
 * See client.h for the other end.
 */

/* different possible states for the server side */
#define SV_STIDLE	0
#define SV_STCONN	1
#define SV_STHEADERS	2
#define SV_STDATA	3
#define SV_STSHUTR	4
#define SV_STSHUTW	5
#define SV_STCLOSE	6


/* Possible states while parsing HTTP messages (request|response) */
#define HTTP_PA_EMPTY      0    /* leading LF, before start line */
#define HTTP_PA_START      1    /* inside start line */
#define HTTP_PA_STRT_LF    2    /* LF after start line */
#define HTTP_PA_HEADER     3    /* inside a header */
#define HTTP_PA_HDR_LF     4    /* LF after a header */
#define HTTP_PA_HDR_LWS    5    /* LWS after a header */
#define HTTP_PA_LFLF       6    /* after double LF/CRLF at the end of headers */
#define HTTP_PA_ERROR      7    /* syntax error in the message */
#define HTTP_PA_CR_SKIP 0x10    /* ORed with other values when a CR was skipped */
#define HTTP_PA_LF_EXP  0x20    /* ORed with other values when a CR is seen and
				 * an LF is expected before entering the
				 * designated state. */


#endif /* _TYPES_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
