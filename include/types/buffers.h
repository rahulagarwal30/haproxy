/*
  include/types/buffers.h
  Buffer management definitions, macros and inline functions.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_BUFFERS_H
#define _TYPES_BUFFERS_H

#include <common/config.h>
#include <common/memory.h>

/* The BF_* macros designate Buffer Flags, which may be ORed in the bit field
 * member 'flags' in struct buffer. Some of them are persistent (BF_SHUT*),
 * some of them (BF_EMPTY,BF_FULL) may only be set by the low-level read/write
 * functions as well as those who change the buffer's read limit.
 */
#define BF_EMPTY                1  /* buffer is empty */
#define BF_FULL                 2  /* buffer cannot accept any more data (l >= rlim-data) */

#define BF_SHUTR                4  /* producer has already shut down */
#define BF_SHUTW                8  /* consumer has already shut down */

#define BF_PARTIAL_READ        16
#define BF_COMPLETE_READ       32
#define BF_READ_ERROR          64
#define BF_READ_NULL          128
#define BF_READ_STATUS        (BF_PARTIAL_READ|BF_COMPLETE_READ|BF_READ_ERROR|BF_READ_NULL)
#define BF_CLEAR_READ         (~BF_READ_STATUS)

#define BF_PARTIAL_WRITE      256
#define BF_COMPLETE_WRITE     512
#define BF_WRITE_ERROR       1024
#define BF_WRITE_NULL        2048
#define BF_WRITE_STATUS      (BF_PARTIAL_WRITE|BF_COMPLETE_WRITE|BF_WRITE_ERROR|BF_WRITE_NULL)
#define BF_CLEAR_WRITE       (~BF_WRITE_STATUS)

#define BF_STREAMER          4096
#define BF_STREAMER_FAST     8192

#define BF_MAY_FORWARD      16384  /* consumer side is allowed to forward the data */
#define BF_READ_TIMEOUT     32768  /* timeout while waiting for producer */
#define BF_WRITE_TIMEOUT    65536  /* timeout while waiting for consumer */

/* When either BF_SHUTR_NOW or BF_HIJACK is set, it is strictly forbidden for
 * the stream interface to alter the buffer contents. When BF_SHUTW_NOW is set,
 * it is strictly forbidden for the stream interface to send anything from the
 * buffer.
 */
#define BF_SHUTR_NOW       131072  /* the producer must shut down for reads ASAP */
#define BF_SHUTW_NOW       262144  /* the consumer must shut down for writes ASAP */
#define BF_HIJACK          524288  /* the producer is temporarily replaced */


/* Analysers (buffer->analysers).
 * Those bits indicate that there are some processing to do on the buffer
 * contents. It will probably evolved into a linked list later. Those
 * analysers could be compared to higher level processors.
 * The field is blanked by buffer_init() and only by analysers themselves
 * afterwards.
 */
#define AN_REQ_INSPECT          0x00000001  /* inspect request contents */
#define AN_REQ_HTTP_HDR         0x00000002  /* inspect HTTP request headers */
#define AN_REQ_HTTP_BODY        0x00000004  /* inspect HTTP request body */
#define AN_REQ_HTTP_TARPIT      0x00000008  /* wait for end of HTTP tarpit */
#define AN_RTR_HTTP_HDR         0x00000010  /* inspect HTTP response headers */

/* describes a chunk of string */
struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int len;	/* size of the string from first to last char. <0 = uninit. */
};

struct buffer {
	unsigned int flags;             /* BF_* */
	int rex;                        /* expiration date for a read, in ticks */
	int wex;                        /* expiration date for a write or connect, in ticks */
	int rto;                        /* read timeout, in ticks */
	int wto;                        /* write timeout, in ticks */
	int cto;                        /* connect timeout, in ticks */
	unsigned int l;                 /* data length */
	char *r, *w, *lr;               /* read ptr, write ptr, last read */
	char *rlim;                     /* read limit, used for header rewriting */
	unsigned int analysers;         /* bit field indicating what to do on the buffer */
	int analyse_exp;                /* expiration date for current analysers (if set) */
	unsigned char xfer_large;       /* number of consecutive large xfers */
	unsigned char xfer_small;       /* number of consecutive small xfers */
	unsigned long long total;       /* total data read */
	struct stream_interface *prod;  /* producer attached to this buffer */
	struct stream_interface *cons;  /* consumer attached to this buffer */
	char data[BUFSIZE];
};


#endif /* _TYPES_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
