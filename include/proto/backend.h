/*
  include/proto/backend.h
  Functions prototypes for the backend.

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

#ifndef _PROTO_BACKEND_H
#define _PROTO_BACKEND_H


#include <types/backend.h>
#include <types/session.h>

#include <proto/queue.h>

int assign_server(struct session *s);
int assign_server_address(struct session *s);
int assign_server_and_queue(struct session *s);
int connect_server(struct session *s);
int srv_count_retry_down(struct session *t, int conn_err);
int srv_retryable_connect(struct session *t);
int srv_redispatch_connect(struct session *t);

void recount_servers(struct proxy *px);
void recalc_server_map(struct proxy *px);


/*
 * This function tries to find a running server with free connection slots for
 * the proxy <px> following the round-robin method.
 * If any server is found, it will be returned and px->srv_rr_idx will be updated
 * to point to the next server. If no valid server is found, NULL is returned.
 */
static inline struct server *get_server_rr_with_conns(struct proxy *px)
{
	int newidx;
	struct server *srv;

	if (px->srv_map_sz == 0)
		return NULL;

	if (px->srv_rr_idx < 0 || px->srv_rr_idx >= px->srv_map_sz)
		px->srv_rr_idx = 0;
	newidx = px->srv_rr_idx;

	do {
		srv = px->srv_map[newidx++];
		if (!srv->maxconn || srv->cur_sess < srv_dynamic_maxconn(srv)) {
			px->srv_rr_idx = newidx;
			return srv;
		}
		if (newidx == px->srv_map_sz)
			newidx = 0;
	} while (newidx != px->srv_rr_idx);

	return NULL;
}


/*
 * This function tries to find a running server for the proxy <px> following
 * the round-robin method.
 * If any server is found, it will be returned and px->srv_rr_idx will be updated
 * to point to the next server. If no valid server is found, NULL is returned.
 */
static inline struct server *get_server_rr(struct proxy *px)
{
	if (px->srv_map_sz == 0)
		return NULL;

	if (px->srv_rr_idx < 0 || px->srv_rr_idx >= px->srv_map_sz)
		px->srv_rr_idx = 0;
	return px->srv_map[px->srv_rr_idx++];
}


/*
 * This function tries to find a running server for the proxy <px> following
 * the source hash method. Depending on the number of active/backup servers,
 * it will either look for active servers, or for backup servers.
 * If any server is found, it will be returned. If no valid server is found,
 * NULL is returned.
 */
static inline struct server *get_server_sh(struct proxy *px, char *addr, int len)
{
	unsigned int h, l;

	if (px->srv_map_sz == 0)
		return NULL;

	l = h = 0;
	if (px->srv_act > 1 || (px->srv_act == 0 && px->srv_bck > 1)) {
		while ((l + sizeof (int)) <= len) {
			h ^= ntohl(*(unsigned int *)(&addr[l]));
			l += sizeof (int);
		}
		h %= px->srv_map_sz;
	}
	return px->srv_map[h];
}


#endif /* _PROTO_BACKEND_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
