/*
 * HPACK header table management (RFC7541) - prototypes
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
#ifndef _PROTO_HPACK_HDR_H
#define _PROTO_HPACK_HDR_H

#include <stdint.h>
#include <common/chunk.h>
#include <common/config.h>
#include <common/ist.h>
#include <types/hpack-hdr.h>

#define HPACK_SHT_SIZE 61

/* static header table as in RFC7541 Appendix A. [0] unused. */
extern const struct hpack_hdr hpack_sht[62];

extern int __hpack_dht_make_room(struct hpack_dht *dht, unsigned int needed);
extern int hpack_dht_insert(struct hpack_dht *dht, struct ist name, struct ist value);

/* sets an hpack_hdr <hdr> to name <n> and value <v>. Useful to avoid casts in
 * immediate assignments.
 */
static inline void hpack_set_hdr(struct hpack_hdr *hdr, const struct ist n, const struct ist v)
{
	hdr->n = n;
	hdr->v = v;
}

/* return a pointer to the entry designated by index <idx> (starting at 1) or
 * NULL if this index is not there.
 */
static inline const struct hpack_dte *hpack_get_dte(const struct hpack_dht *dht, uint16_t idx)
{
	idx--;

	if (idx >= dht->used)
		return NULL;

	if (idx <= dht->head)
		idx = dht->head - idx;
	else
		idx = dht->head - idx + dht->wrap;

	return &dht->dte[idx];
}

/* return a pointer to the header name for entry <dte>. */
static inline struct ist hpack_get_name(const struct hpack_dht *dht, const struct hpack_dte *dte)
{
	struct ist ret = {
		.ptr = (void *)dht + dte->addr,
		.len = dte->nlen,
	};
	return ret;
}

/* return a pointer to the header value for entry <dte>. */
static inline struct ist hpack_get_value(const struct hpack_dht *dht, const struct hpack_dte *dte)
{
	struct ist ret = {
		.ptr = (void *)dht + dte->addr + dte->nlen,
		.len = dte->vlen,
	};
	return ret;
}

/* takes an idx, returns the associated name */
static inline struct ist hpack_idx_to_name(const struct hpack_dht *dht, int idx)
{
	const struct hpack_dte *dte;

	if (idx <= HPACK_SHT_SIZE)
		return hpack_sht[idx].n;

	dte = hpack_get_dte(dht, idx - HPACK_SHT_SIZE);
	if (!dte)
		return ist("### ERR ###"); // error

	return hpack_get_name(dht, dte);
}

/* takes an idx, returns the associated value */
static inline struct ist hpack_idx_to_value(const struct hpack_dht *dht, int idx)
{
	const struct hpack_dte *dte;

	if (idx <= HPACK_SHT_SIZE)
		return hpack_sht[idx].v;

	dte = hpack_get_dte(dht, idx - HPACK_SHT_SIZE);
	if (!dte)
		return ist("### ERR ###"); // error

	return hpack_get_value(dht, dte);
}

/* Purges table dht until a header field of <needed> bytes fits according to
 * the protocol (adding 32 bytes overhead). Returns non-zero on success, zero
 * on failure (ie: table empty but still not sufficient).
 */
static inline int hpack_dht_make_room(struct hpack_dht *dht, unsigned int needed)
{
	if (!dht->used || dht->used * 32 + dht->total + needed + 32 <= dht->size)
		return 1;

	return __hpack_dht_make_room(dht, needed);
}

/* allocate a dynamic headers table of <size> bytes and return it initialized */
static inline void hpack_dht_init(struct hpack_dht *dht, uint32_t size)
{
	dht->size = size;
	dht->total = 0;
	dht->used = 0;
}

/* allocate a dynamic headers table of <size> bytes and return it initialized */
static inline struct hpack_dht *hpack_dht_alloc(uint32_t size)
{
	struct hpack_dht *dht;

	dht = malloc(size);
	if (!dht)
		return dht;

	hpack_dht_init(dht, size);
	return dht;
}

/* free a dynamic headers table */
static inline void hpack_dht_free(struct hpack_dht *dht)
{
	free(dht);
}

#endif
