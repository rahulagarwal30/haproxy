/*
 * HPACK decompressor (RFC7541)
 *
 * Copyright (C) 2014-2017 Willy Tarreau <willy@haproxy.org>
 * Copyright (C) 2017 HAProxy Technologies
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/ist.h>
#include <proto/hpack-enc.h>
#include <proto/hpack-hdr.h>

#include <types/global.h>


/* Tries to encode header whose name is <n> and value <v> into the chunk <out>.
 * Returns non-zero on success, 0 on failure (buffer full).
 */
int hpack_encode_header(struct chunk *out, const struct ist n, const struct ist v)
{
	int len = out->len;
	int size = out->size;

	if (len >= size)
		return 0;

	if (isteq(n, ist("connection")) ||
	    isteq(n, ist("proxy-connection")) ||
	    isteq(n, ist("keep-alive")) ||
	    isteq(n, ist("upgrade")) ||
	    isteq(n, ist("transfer-encoding"))) {
		/* header doesn't exist in HTTP/2, simply skip it */
		return 1;
	}

	/* check a few very common response header fields to encode them using
	 * the static header table. The tests are sorted by size to help the
	 * compiler factor out the common sizes.
	 */
	if (isteq(n, ist("date")))
		out->str[len++] = 0x61; // literal with indexing -- name="date" (idx 33)
	else if (isteq(n, ist("etag")))
		out->str[len++] = 0x62; // literal with indexing -- name="etag" (idx 34)
	else if (isteq(n, ist("server")))
		out->str[len++] = 0x76; // literal with indexing -- name="server" (idx 54)
	else if (isteq(n, ist("location")))
		out->str[len++] = 0x6e; // literal with indexing -- name="location" (idx 46)
	else if (isteq(n, ist("content-type")))
		out->str[len++] = 0x5f; // literal with indexing -- name="content-type" (idx 31)
	else if (isteq(n, ist("last-modified")))
		out->str[len++] = 0x6c; // literal with indexing -- name="last-modified" (idx 44)
	else if (isteq(n, ist("accept-ranges")))
		out->str[len++] = 0x51; // literal with indexing -- name="accept-ranges" (idx 17)
	else if (isteq(n, ist("cache-control")))
		out->str[len++] = 0x58; // literal with indexing -- name="cache-control" (idx 24)
	else if (isteq(n, ist("content-length")))
		out->str[len++] = 0x5c; // literal with indexing -- name="content-length" (idx 28)
	else if (len + 1 + n.len < size) {
		/* FIXME: for now we're limited to 7 bits of length */
		out->str[len++] = 0x00;      /* literal without indexing -- new name */
		out->str[len++] = n.len;
		memcpy(out->str + len, n.ptr, n.len);
		len += n.len;
	}
	else {
		/* header too large for the buffer */
		return 0;
	}

	if (len + 1 + v.len < size) {
		/* FIXME: for now we're limited to 7 bits of length */
		out->str[len++] = v.len;
		memcpy(out->str + len, v.ptr, v.len);
		len += v.len;
	}
	else {
		return 0;
	}

	out->len = len;
	return 1;
}
