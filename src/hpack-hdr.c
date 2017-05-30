/*
 * HPACK header table management (RFC7541)
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
#include <proto/hpack-hdr.h>
#include <proto/hpack-huff.h>

#include <types/global.h>

/* static header table as in RFC7541 Appendix A. [0] unused. */
const struct hpack_hdr hpack_sht[62] = {
	[ 1] = { .n = { ":authority",                  10 }, .v = { "",               0 } },
	[ 2] = { .n = { ":method",                      7 }, .v = { "GET",            3 } },
	[ 3] = { .n = { ":method",                      7 }, .v = { "POST",           4 } },
	[ 4] = { .n = { ":path",                        5 }, .v = { "/",              1 } },
	[ 5] = { .n = { ":path",                        5 }, .v = { "/index.html",   11 } },
	[ 6] = { .n = { ":scheme",                      7 }, .v = { "http",           4 } },
	[ 7] = { .n = { ":scheme",                      7 }, .v = { "https",          5 } },
	[ 8] = { .n = { ":status",                      7 }, .v = { "200",            3 } },
	[ 9] = { .n = { ":status",                      7 }, .v = { "204",            3 } },
	[10] = { .n = { ":status",                      7 }, .v = { "206",            3 } },
	[11] = { .n = { ":status",                      7 }, .v = { "304",            3 } },
	[12] = { .n = { ":status",                      7 }, .v = { "400",            3 } },
	[13] = { .n = { ":status",                      7 }, .v = { "404",            3 } },
	[14] = { .n = { ":status",                      7 }, .v = { "500",            3 } },
	[15] = { .n = { "accept-charset",              14 }, .v = { "",               0 } },
	[16] = { .n = { "accept-encoding",             15 }, .v = { "gzip, deflate", 13 } },
	[17] = { .n = { "accept-language",             15 }, .v = { "",               0 } },
	[18] = { .n = { "accept-ranges",               13 }, .v = { "",               0 } },
	[19] = { .n = { "accept",                       6 }, .v = { "",               0 } },
	[20] = { .n = { "access-control-allow-origin", 27 }, .v = { "",               0 } },
	[21] = { .n = { "age",                          3 }, .v = { "",               0 } },
	[22] = { .n = { "allow",                        5 }, .v = { "",               0 } },
	[23] = { .n = { "authorization",               13 }, .v = { "",               0 } },
	[24] = { .n = { "cache-control",               13 }, .v = { "",               0 } },
	[25] = { .n = { "content-disposition",         19 }, .v = { "",               0 } },
	[26] = { .n = { "content-encoding",            16 }, .v = { "",               0 } },
	[27] = { .n = { "content-language",            16 }, .v = { "",               0 } },
	[28] = { .n = { "content-length",              14 }, .v = { "",               0 } },
	[29] = { .n = { "content-location",            16 }, .v = { "",               0 } },
	[30] = { .n = { "content-range",               13 }, .v = { "",               0 } },
	[31] = { .n = { "content-type",                12 }, .v = { "",               0 } },
	[32] = { .n = { "cookie",                       6 }, .v = { "",               0 } },
	[33] = { .n = { "date",                         4 }, .v = { "",               0 } },
	[34] = { .n = { "etag",                         4 }, .v = { "",               0 } },
	[35] = { .n = { "expect",                       6 }, .v = { "",               0 } },
	[36] = { .n = { "expires",                      7 }, .v = { "",               0 } },
	[37] = { .n = { "from",                         4 }, .v = { "",               0 } },
	[38] = { .n = { "host",                         4 }, .v = { "",               0 } },
	[39] = { .n = { "if-match",                     8 }, .v = { "",               0 } },
	[40] = { .n = { "if-modified-since",           17 }, .v = { "",               0 } },
	[41] = { .n = { "if-none-match",               13 }, .v = { "",               0 } },
	[42] = { .n = { "if-range",                     8 }, .v = { "",               0 } },
	[43] = { .n = { "if-unmodified-since",         19 }, .v = { "",               0 } },
	[44] = { .n = { "last-modified",               13 }, .v = { "",               0 } },
	[45] = { .n = { "link",                         4 }, .v = { "",               0 } },
	[46] = { .n = { "location",                     8 }, .v = { "",               0 } },
	[47] = { .n = { "max-forwards",                12 }, .v = { "",               0 } },
	[48] = { .n = { "proxy-authenticate",          18 }, .v = { "",               0 } },
	[49] = { .n = { "proxy-authorization",         19 }, .v = { "",               0 } },
	[50] = { .n = { "range",                        5 }, .v = { "",               0 } },
	[51] = { .n = { "referer",                      7 }, .v = { "",               0 } },
	[52] = { .n = { "refresh",                      7 }, .v = { "",               0 } },
	[53] = { .n = { "retry-after",                 11 }, .v = { "",               0 } },
	[54] = { .n = { "server",                       6 }, .v = { "",               0 } },
	[55] = { .n = { "set-cookie",                  10 }, .v = { "",               0 } },
	[56] = { .n = { "strict-transport-security",   25 }, .v = { "",               0 } },
	[57] = { .n = { "transfer-encoding",           17 }, .v = { "",               0 } },
	[58] = { .n = { "user-agent",                  10 }, .v = { "",               0 } },
	[59] = { .n = { "vary",                         4 }, .v = { "",               0 } },
	[60] = { .n = { "via",                          3 }, .v = { "",               0 } },
	[61] = { .n = { "www-authenticate",            16 }, .v = { "",               0 } },
};

/* returns the slot number of the oldest entry (tail). Must not be used on an
 * empty table.
 */
static inline unsigned int hpack_dht_get_tail(const struct hpack_dht *dht)
{
	return ((dht->head + 1U < dht->used) ? dht->wrap : 0) + dht->head + 1U - dht->used;
}

#ifdef DEBUG_HPACK
/* dump the whole dynamic header table */
static void hpack_dht_dump(const struct hpack_dht *dht)
{
	int i;
	unsigned int slot;
	char name[4096], value[4096];

	for (i = HPACK_SHT_SIZE + 1; i <= HPACK_SHT_SIZE + dht->used; i++) {
		slot = (hpack_get_dte(dht, i - HPACK_SHT_SIZE) - dht->dte);
		fprintf(stderr, "idx=%d slot=%u name=<%s> value=<%s> addr=%u-%u\n",
			i, slot,
			istpad(name, hpack_idx_to_name(dht, i)).ptr,
			istpad(value, hpack_idx_to_value(dht, i)).ptr,
			dht->dte[slot].addr, dht->dte[slot].addr+dht->dte[slot].nlen+dht->dte[slot].vlen-1);
	}
}

/* check for the whole dynamic header table consistency, abort on failures */
static void hpack_dht_check_consistency(const struct hpack_dht *dht)
{
	unsigned slot = hpack_dht_get_tail(dht);
	unsigned used2 = dht->used;
	unsigned total = 0;

	if (!dht->used)
		return;

	if (dht->front >= dht->wrap)
		abort();

	if (dht->used > dht->wrap)
		abort();

	if (dht->head >= dht->wrap)
		abort();

	while (used2--) {
		total += dht->dte[slot].nlen + dht->dte[slot].vlen;
		slot++;
		if (slot >= dht->wrap)
			slot = 0;
	}

	if (total != dht->total) {
		fprintf(stderr, "%d: total=%u dht=%u\n", __LINE__, total, dht->total);
		abort();
	}
}
#endif // DEBUG_HPACK

/* rebuild a new dynamic header table from <dht> with an unwrapped index and
 * contents at the end. The new table is returned, the caller must not use the
 * previous one anymore. NULL may be returned if no table could be allocated.
 */
static struct hpack_dht *hpack_dht_defrag(struct hpack_dht *dht)
{
	struct hpack_dht *alt_dht;
	uint16_t old, new;
	uint32_t addr;

	/* Note: for small tables we could use alloca() instead but
	 * portability especially for large tables can be problematic.
	 */
	alt_dht = hpack_dht_alloc(dht->size);
	if (!alt_dht)
		return NULL;

	alt_dht->total = dht->total;
	alt_dht->used = dht->used;
	alt_dht->wrap = dht->used;

	new = 0;
	addr = alt_dht->size;

	if (dht->used) {
		/* start from the tail */
		old = hpack_dht_get_tail(dht);
		do {
			alt_dht->dte[new].nlen = dht->dte[old].nlen;
			alt_dht->dte[new].vlen = dht->dte[old].vlen;
			addr -= dht->dte[old].nlen + dht->dte[old].vlen;
			alt_dht->dte[new].addr = addr;

			memcpy((void *)alt_dht + alt_dht->dte[new].addr,
			       (void *)dht + dht->dte[old].addr,
			       dht->dte[old].nlen + dht->dte[old].vlen);

			old++;
			if (old >= dht->wrap)
				old = 0;
			new++;
		} while (new < dht->used);
	}

	alt_dht->front = alt_dht->head = new - 1;

	memcpy(dht, alt_dht, dht->size);
	hpack_dht_free(alt_dht);

	return dht;
}

/* Purges table dht until a header field of <needed> bytes fits according to
 * the protocol (adding 32 bytes overhead). Returns non-zero on success, zero
 * on failure (ie: table empty but still not sufficient). It must only be
 * called when the table is not large enough to suit the new entry and there
 * are some entries left. In case of doubt, use dht_make_room() instead.
 */
int __hpack_dht_make_room(struct hpack_dht *dht, unsigned int needed)
{
	unsigned int used = dht->used;
	unsigned int wrap = dht->wrap;
	unsigned int tail;

	do {
		tail = ((dht->head + 1U < used) ? wrap : 0) + dht->head + 1U - used;
		dht->total -= dht->dte[tail].nlen + dht->dte[tail].vlen;
		if (tail == dht->front)
			dht->front = dht->head;
		used--;
	} while (used && used * 32 + dht->total + needed + 32 > dht->size);

	dht->used = used;

	/* realign if empty */
	if (!used)
		dht->front = dht->head = 0;

	/* pack the table if it doesn't wrap anymore */
	if (dht->head + 1U >= used)
		dht->wrap = dht->head + 1;

	/* no need to check for 'used' here as if it doesn't fit, used==0 */
	return needed + 32 <= dht->size;
}

/* tries to insert a new header <name>:<value> in front of the current head. A
 * negative value is returned on error.
 */
int hpack_dht_insert(struct hpack_dht *dht, struct ist name, struct ist value)
{
	unsigned int used;
	unsigned int head;
	unsigned int prev;
	unsigned int wrap;
	unsigned int tail;
	uint32_t headroom, tailroom;

	if (!hpack_dht_make_room(dht, name.len + value.len))
		return -1;

	used = dht->used;
	prev = head = dht->head;
	wrap = dht->wrap;
	tail = hpack_dht_get_tail(dht);

	/* Now there is enough room in the table, that's guaranteed by the
	 * protocol, but not necessarily where we need it.
	 */

	if (!used) {
		/* easy, the table was empty */
		dht->front = dht->head = 0;
		dht->wrap  = dht->used = 1;
		dht->total = 0;
		head = 0;
		dht->dte[head].addr = dht->size - (name.len + value.len);
		goto copy;
	}

	/* compute the new head, used and wrap position */
	used++;
	head++;

	if (head >= wrap) {
		/* head is leading the entries, we either need to push the
		 * table further or to loop back to released entries. We could
		 * force to loop back when at least half of the allocatable
		 * entries are free but in practice it never happens.
		 */
		if ((sizeof(*dht) + (wrap + 1) * sizeof(dht->dte[0]) <= dht->dte[dht->front].addr))
			wrap++;
		else if (head >= used) /* there's a hole at the beginning */
			head = 0;
		else {
			/* no more room, head hits tail and the index cannot be
			 * extended, we have to realign the whole table.
			 */
			if (!hpack_dht_defrag(dht))
				return -1;

			wrap = dht->wrap + 1;
			head = dht->head + 1;
			prev = head - 1;
			tail = 0;
		}
	}
	else if (used >= wrap) {
		/* we've hit the tail, we need to reorganize the index so that
		 * the head is at the end (but not necessarily move the data).
		 */
		if (!hpack_dht_defrag(dht))
			return -1;

		wrap = dht->wrap + 1;
		head = dht->head + 1;
		prev = head - 1;
		tail = 0;
	}

	/* Now we have updated head, used and wrap, we know that there is some
	 * available room at least from the protocol's perspective. This space
	 * is split in two areas :
	 *
	 *   1: if the previous head was the front cell, the space between the
	 *      end of the index table and the front cell's address.
	 *   2: if the previous head was the front cell, the space between the
	 *      end of the tail and the end of the table ; or if the previous
	 *      head was not the front cell, the space between the end of the
	 *      tail and the head's address.
	 */
	if (prev == dht->front) {
		/* the area was contiguous */
		headroom = dht->dte[dht->front].addr - (sizeof(*dht) + wrap * sizeof(dht->dte[0]));
		tailroom = dht->size - dht->dte[tail].addr - dht->dte[tail].nlen - dht->dte[tail].vlen;
	}
	else {
		/* it's already wrapped so we can't store anything in the headroom */
		headroom = 0;
		tailroom = dht->dte[prev].addr - dht->dte[tail].addr - dht->dte[tail].nlen - dht->dte[tail].vlen;
	}

	/* We can decide to stop filling the headroom as soon as there's enough
	 * room left in the tail to suit the protocol, but tests show that in
	 * practice it almost never happens in other situations so the extra
	 * test is useless and we simply fill the headroom as long as it's
	 * available.
	 */
	if (headroom >= name.len + value.len) {
		/* install upfront and update ->front */
		dht->dte[head].addr = dht->dte[dht->front].addr - (name.len + value.len);
		dht->front = head;
	}
	else if (tailroom >= name.len + value.len) {
		dht->dte[head].addr = dht->dte[tail].addr + dht->dte[tail].nlen + dht->dte[tail].vlen + tailroom - (name.len + value.len);
	}
	else {
		/* need to defragment the table before inserting upfront */
		dht = hpack_dht_defrag(dht);
		wrap = dht->wrap + 1;
		head = dht->head + 1;
		dht->dte[head].addr = dht->dte[dht->front].addr - (name.len + value.len);
		dht->front = head;
	}

	dht->wrap = wrap;
	dht->head = head;
	dht->used = used;

 copy:
	dht->total         += name.len + value.len;
	dht->dte[head].nlen = name.len;
	dht->dte[head].vlen = value.len;

	memcpy((void *)dht + dht->dte[head].addr, name.ptr, name.len);
	memcpy((void *)dht + dht->dte[head].addr + name.len, value.ptr, value.len);
	return 0;
}

