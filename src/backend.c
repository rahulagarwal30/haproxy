/*
 * Backend variables and functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/time.h>

#include <types/buffers.h>
#include <types/global.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/session.h>

#include <proto/backend.h>
#include <proto/client.h>
#include <proto/fd.h>
#include <proto/httperr.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/queue.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

#ifdef CONFIG_HAP_CTTPROXY
#include <import/ip_tproxy.h>
#endif

#ifdef CONFIG_HAP_TCPSPLICE
#include <libtcpsplice.h>
#endif

/*
 * This function recounts the number of usable active and backup servers for
 * proxy <p>. These numbers are returned into the p->srv_act and p->srv_bck.
 * This function also recomputes the total active and backup weights.
 */
void recount_servers(struct proxy *px)
{
	struct server *srv;
	int first_bkw = 0;

	px->srv_act = px->srv_bck = 0;
	px->lbprm.tot_wact = px->lbprm.tot_wbck = 0;
	for (srv = px->srv; srv != NULL; srv = srv->next) {
		if (srv->state & SRV_RUNNING) {
			if (srv->state & SRV_BACKUP) {
				px->srv_bck++;
				px->lbprm.tot_wbck += srv->eweight;
				if (px->srv_bck == 1)
					first_bkw = srv->eweight;
			} else {
				px->srv_act++;
				px->lbprm.tot_wact += srv->eweight;
			}
		}
	}

	if (px->srv_act) {
		px->lbprm.tot_weight = px->lbprm.tot_wact;
		px->lbprm.tot_used   = px->srv_act;
	}
	else if (px->srv_bck) {
		if (px->options & PR_O_USE_ALL_BK) {
			px->lbprm.tot_weight = px->lbprm.tot_wbck;
			px->lbprm.tot_used   = px->srv_bck;
		}
		else {	/* the first backup server is enough */
			px->lbprm.tot_weight = first_bkw;
			px->lbprm.tot_used = 1;
		}
	}
	else {
		px->lbprm.tot_weight = 0;
		px->lbprm.tot_used = 0;
	}

}

/* This function recomputes the server map for proxy px. It relies on
 * px->lbprm.tot_wact, tot_wbck, tot_used, tot_weight, so it must be
 * called after recount_servers(). It also expects px->lbprm.map.srv
 * to be allocated with the largest size needed. It updates tot_weight.
 */
void recalc_server_map(struct proxy *px)
{
	int o, tot, flag;
	struct server *cur, *best;

	switch (px->lbprm.tot_used) {
	case 0:	/* no server */
		px->lbprm.map.state &= ~PR_MAP_RECALC;
		return;
	case 1: /* only one server, just fill first entry */
		tot = 1;
		break;
	default:
		tot = px->lbprm.tot_weight;
		break;
	}

	/* here we *know* that we have some servers */
	if (px->srv_act)
		flag = SRV_RUNNING;
	else
		flag = SRV_RUNNING | SRV_BACKUP;

	/* this algorithm gives priority to the first server, which means that
	 * it will respect the declaration order for equivalent weights, and
	 * that whatever the weights, the first server called will always be
	 * the first declared. This is an important asumption for the backup
	 * case, where we want the first server only.
	 */
	for (cur = px->srv; cur; cur = cur->next)
		cur->wscore = 0;

	for (o = 0; o < tot; o++) {
		int max = 0;
		best = NULL;
		for (cur = px->srv; cur; cur = cur->next) {
			if ((cur->state & (SRV_RUNNING | SRV_BACKUP)) == flag) {
				int v;

				/* If we are forced to return only one server, we don't want to
				 * go further, because we would return the wrong one due to
				 * divide overflow.
				 */
				if (tot == 1) {
					best = cur;
					/* note that best->wscore will be wrong but we don't care */
					break;
				}

				cur->wscore += cur->eweight;
				v = (cur->wscore + tot) / tot; /* result between 0 and 3 */
				if (best == NULL || v > max) {
					max = v;
					best = cur;
				}
			}
		}
		px->lbprm.map.srv[o] = best;
		best->wscore -= tot;
	}
	px->lbprm.map.state &= ~PR_MAP_RECALC;
}

/* This function is responsible of building the server MAP for map-based LB
 * algorithms, allocating the map, and setting p->lbprm.wmult to the GCD of the
 * weights if applicable. It should be called only once per proxy, at config
 * time.
 */
void init_server_map(struct proxy *p)
{
	struct server *srv;
	int pgcd;
	int act, bck;

	if (!p->srv)
		return;

	/* We will factor the weights to reduce the table,
	 * using Euclide's largest common divisor algorithm
	 */
	pgcd = p->srv->uweight;
	for (srv = p->srv->next; srv && pgcd > 1; srv = srv->next) {
		int w = srv->uweight;
		while (w) {
			int t = pgcd % w;
			pgcd = w;
			w = t;
		}
	}

	/* It is sometimes useful to know what factor to apply
	 * to the backend's effective weight to know its real
	 * weight.
	 */
	p->lbprm.wmult = pgcd;

	act = bck = 0;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->eweight = srv->uweight / pgcd;
		if (srv->state & SRV_BACKUP)
			bck += srv->eweight;
		else
			act += srv->eweight;
	}

	/* this is the largest map we will ever need for this servers list */
	if (act < bck)
		act = bck;

	p->lbprm.map.srv = (struct server **)calloc(act, sizeof(struct server *));
	/* recounts servers and their weights */
	p->lbprm.map.state = PR_MAP_RECALC;
	recount_servers(p);
	recalc_server_map(p);
}

/* 
 * This function tries to find a running server for the proxy <px> following
 * the URL parameter hash method. It looks for a specific parameter in the
 * URL and hashes it to compute the server ID. This is useful to optimize
 * performance by avoiding bounces between servers in contexts where sessions
 * are shared but cookies are not usable. If the parameter is not found, NULL
 * is returned. If any server is found, it will be returned. If no valid server
 * is found, NULL is returned.
 *
 */
struct server *get_server_ph(struct proxy *px, const char *uri, int uri_len)
{
	unsigned long hash = 0;
	char *p;
	int plen;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	if (px->lbprm.map.state & PR_MAP_RECALC)
		recalc_server_map(px);

	p = memchr(uri, '?', uri_len);
	if (!p)
		return NULL;
	p++;

	uri_len -= (p - uri);
	plen = px->url_param_len;

	if (uri_len <= plen)
		return NULL;

	while (uri_len > plen) {
		/* Look for the parameter name followed by an equal symbol */
		if (p[plen] == '=') {
			/* skip the equal symbol */
			uri = p;
			p += plen + 1;
			uri_len -= plen + 1;
			if (memcmp(uri, px->url_param_name, plen) == 0) {
				/* OK, we have the parameter here at <uri>, and
				 * the value after the equal sign, at <p>
				 */
				while (uri_len && *p != '&') {
					hash = *p + (hash << 6) + (hash << 16) - hash;
					uri_len--;
					p++;
				}
				return px->lbprm.map.srv[hash % px->lbprm.tot_weight];
			}
		}

		/* skip to next parameter */
		uri = p;
		p = memchr(uri, '&', uri_len);
		if (!p)
			return NULL;
		p++;
		uri_len -= (p - uri);
	}
	return NULL;
}

/*
 * This function marks the session as 'assigned' in direct or dispatch modes,
 * or tries to assign one in balance mode, according to the algorithm. It does
 * nothing if the session had already been assigned a server.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK. s->srv will be valid.
 *   SRV_STATUS_NOSRV    if no server is available. s->srv = NULL.
 *   SRV_STATUS_FULL     if all servers are saturated. s->srv = NULL.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ASSIGNED to indicate that it does
 * not need to be called anymore. This usually means that s->srv can be trusted
 * in balance and direct modes. This flag is not cleared, so it's to the caller
 * to clear it if required (eg: redispatch).
 *
 */

int assign_server(struct session *s)
{
#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server : s=%p\n",s);
#endif

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	if (!(s->flags & SN_ASSIGNED)) {
		if (s->be->options & PR_O_BALANCE) {
			int len;
		
			if (s->flags & SN_DIRECT) {
				s->flags |= SN_ASSIGNED;
				return SRV_STATUS_OK;
			}

			if (!s->be->srv_act && !s->be->srv_bck)
				return SRV_STATUS_NOSRV;

			switch (s->be->options & PR_O_BALANCE) {
			case PR_O_BALANCE_RR:
				s->srv = get_server_rr_with_conns(s->be);
				if (!s->srv)
					return SRV_STATUS_FULL;
				break;
			case PR_O_BALANCE_SH:
				if (s->cli_addr.ss_family == AF_INET)
					len = 4;
				else if (s->cli_addr.ss_family == AF_INET6)
					len = 16;
				else /* unknown IP family */
					return SRV_STATUS_INTERNAL;
		
				s->srv = get_server_sh(s->be,
						       (void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
						       len);
				break;
			case PR_O_BALANCE_UH:
				/* URI hashing */
				s->srv = get_server_uh(s->be,
						       s->txn.req.sol + s->txn.req.sl.rq.u,
						       s->txn.req.sl.rq.u_l);
				break;
			case PR_O_BALANCE_PH:
				/* URL Parameter hashing */
				s->srv = get_server_ph(s->be,
						       s->txn.req.sol + s->txn.req.sl.rq.u,
						       s->txn.req.sl.rq.u_l);
				if (!s->srv) {
					/* parameter not found, fall back to round robin */
					s->srv = get_server_rr_with_conns(s->be);
					if (!s->srv)
						return SRV_STATUS_FULL;
				}
				break;
			default:
				/* unknown balancing algorithm */
				return SRV_STATUS_INTERNAL;
			}
		}
		else if (!*(int *)&s->be->dispatch_addr.sin_addr &&
			 !(s->fe->options & PR_O_TRANSP)) {
			return SRV_STATUS_NOSRV;
		}
		s->flags |= SN_ASSIGNED;
	}
	return SRV_STATUS_OK;
}


/*
 * This function assigns a server address to a session, and sets SN_ADDR_SET.
 * The address is taken from the currently assigned server, or from the
 * dispatch or transparent address.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ADDR_SET is set. This flag is
 * not cleared, so it's to the caller to clear it if required.
 *
 */
int assign_server_address(struct session *s)
{
#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server_address : s=%p\n",s);
#endif

	if ((s->flags & SN_DIRECT) || (s->be->options & PR_O_BALANCE)) {
		/* A server is necessarily known for this session */
		if (!(s->flags & SN_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		s->srv_addr = s->srv->addr;

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if (s->srv->state & SRV_MAPPORTS) {
			if (!(s->fe->options & PR_O_TRANSP) && !(s->flags & SN_FRT_ADDR_SET))
				get_frt_addr(s);
			if (s->frt_addr.ss_family == AF_INET) {
				s->srv_addr.sin_port = htons(ntohs(s->srv_addr.sin_port) +
							     ntohs(((struct sockaddr_in *)&s->frt_addr)->sin_port));
			} else {
				s->srv_addr.sin_port = htons(ntohs(s->srv_addr.sin_port) +
							     ntohs(((struct sockaddr_in6 *)&s->frt_addr)->sin6_port));
			}
		}
	}
	else if (*(int *)&s->be->dispatch_addr.sin_addr) {
		/* connect to the defined dispatch addr */
		s->srv_addr = s->be->dispatch_addr;
	}
	else if (s->fe->options & PR_O_TRANSP) {
		/* in transparent mode, use the original dest addr if no dispatch specified */
		socklen_t salen = sizeof(s->srv_addr);

		if (get_original_dst(s->cli_fd, &s->srv_addr, &salen) == -1) {
			qfprintf(stderr, "Cannot get original server address.\n");
			return SRV_STATUS_INTERNAL;
		}
	}
	else {
		/* no server and no LB algorithm ! */
		return SRV_STATUS_INTERNAL;
	}

	s->flags |= SN_ADDR_SET;
	return SRV_STATUS_OK;
}


/* This function assigns a server to session <s> if required, and can add the
 * connection to either the assigned server's queue or to the proxy's queue.
 *
 * Returns :
 *
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_NOSRV    if no server is available. s->srv = NULL.
 *   SRV_STATUS_QUEUED   if the connection has been queued.
 *   SRV_STATUS_FULL     if the server(s) is/are saturated and the
 *                       connection could not be queued.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 */
int assign_server_and_queue(struct session *s)
{
	struct pendconn *p;
	int err;

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	if (s->flags & SN_ASSIGNED) {
		if (s->srv && s->srv->maxqueue > 0 && s->srv->nbpend >= s->srv->maxqueue) {
			s->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
			s->srv = NULL;
			http_flush_cookie_flags(&s->txn);
		} else {
			/* a server does not need to be assigned, perhaps because we're in
			 * direct mode, or in dispatch or transparent modes where the server
			 * is not needed.
			 */
			if (s->srv &&
			    s->srv->maxconn && s->srv->cur_sess >= srv_dynamic_maxconn(s->srv)) {
				p = pendconn_add(s);
				if (p)
					return SRV_STATUS_QUEUED;
				else
					return SRV_STATUS_FULL;
			}
			return SRV_STATUS_OK;
		}
	}

	/* a server needs to be assigned */
	err = assign_server(s);
	switch (err) {
	case SRV_STATUS_OK:
		/* in balance mode, we might have servers with connection limits */
		if (s->srv &&
		    s->srv->maxconn && s->srv->cur_sess >= srv_dynamic_maxconn(s->srv)) {
			p = pendconn_add(s);
			if (p)
				return SRV_STATUS_QUEUED;
			else
				return SRV_STATUS_FULL;
		}
		return SRV_STATUS_OK;

	case SRV_STATUS_FULL:
		/* queue this session into the proxy's queue */
		p = pendconn_add(s);
		if (p)
			return SRV_STATUS_QUEUED;
		else
			return SRV_STATUS_FULL;

	case SRV_STATUS_NOSRV:
	case SRV_STATUS_INTERNAL:
		return err;
	default:
		return SRV_STATUS_INTERNAL;
	}
}


/*
 * This function initiates a connection to the server assigned to this session
 * (s->srv, s->srv_addr). It will assign a server if none is assigned yet.
 * It can return one of :
 *  - SN_ERR_NONE if everything's OK
 *  - SN_ERR_SRVTO if there are no more servers
 *  - SN_ERR_SRVCL if the connection was refused by the server
 *  - SN_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SN_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SN_ERR_INTERNAL for any other purely internal errors
 * Additionnally, in the case of SN_ERR_RESOURCE, an emergency log will be emitted.
 */
int connect_server(struct session *s)
{
	int fd, err;

	if (!(s->flags & SN_ADDR_SET)) {
		err = assign_server_address(s);
		if (err != SRV_STATUS_OK)
			return SN_ERR_INTERNAL;
	}

	if ((fd = s->srv_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		qfprintf(stderr, "Cannot get a server socket.\n");

		if (errno == ENFILE)
			send_log(s->be, LOG_EMERG,
				 "Proxy %s reached system FD limit at %d. Please check system tunables.\n",
				 s->be->id, maxfd);
		else if (errno == EMFILE)
			send_log(s->be, LOG_EMERG,
				 "Proxy %s reached process FD limit at %d. Please check 'ulimit-n' and restart.\n",
				 s->be->id, maxfd);
		else if (errno == ENOBUFS || errno == ENOMEM)
			send_log(s->be, LOG_EMERG,
				 "Proxy %s reached system memory limit at %d sockets. Please check system tunables.\n",
				 s->be->id, maxfd);
		/* this is a resource error */
		return SN_ERR_RESOURCE;
	}
	
	if (fd >= global.maxsock) {
		/* do not log anything there, it's a normal condition when this option
		 * is used to serialize connections to a server !
		 */
		Alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
		close(fd);
		return SN_ERR_PRXCOND; /* it is a configuration limit */
	}

#ifdef CONFIG_HAP_TCPSPLICE
	if ((s->fe->options & s->be->options) & PR_O_TCPSPLICE) {
		/* TCP splicing supported by both FE and BE */
		tcp_splice_initfd(s->cli_fd, fd);
	}
#endif

	if ((fcntl(fd, F_SETFL, O_NONBLOCK)==-1) ||
	    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1)) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(fd);
		return SN_ERR_INTERNAL;
	}

	if (s->be->options & PR_O_TCP_SRV_KA)
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

	if (s->be->options & PR_O_TCP_NOLING)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));

	/* allow specific binding :
	 * - server-specific at first
	 * - proxy-specific next
	 */
	if (s->srv != NULL && s->srv->state & SRV_BIND_SRC) {
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));
		if (bind(fd, (struct sockaddr *)&s->srv->source_addr, sizeof(s->srv->source_addr)) == -1) {
			Alert("Cannot bind to source address before connect() for server %s/%s. Aborting.\n",
			      s->be->id, s->srv->id);
			close(fd);
			send_log(s->be, LOG_EMERG,
				 "Cannot bind to source address before connect() for server %s/%s.\n",
				 s->be->id, s->srv->id);
			return SN_ERR_RESOURCE;
		}
#ifdef CONFIG_HAP_CTTPROXY
		if (s->srv->state & SRV_TPROXY_MASK) {
			struct in_tproxy itp1, itp2;
			memset(&itp1, 0, sizeof(itp1));

			itp1.op = TPROXY_ASSIGN;
			switch (s->srv->state & SRV_TPROXY_MASK) {
			case SRV_TPROXY_ADDR:
				itp1.v.addr.faddr = s->srv->tproxy_addr.sin_addr;
				itp1.v.addr.fport = s->srv->tproxy_addr.sin_port;
				break;
			case SRV_TPROXY_CLI:
				itp1.v.addr.fport = ((struct sockaddr_in *)&s->cli_addr)->sin_port;
				/* fall through */
			case SRV_TPROXY_CIP:
				/* FIXME: what can we do if the client connects in IPv6 ? */
				itp1.v.addr.faddr = ((struct sockaddr_in *)&s->cli_addr)->sin_addr;
				break;
			}

			/* set connect flag on socket */
			itp2.op = TPROXY_FLAGS;
			itp2.v.flags = ITP_CONNECT | ITP_ONCE;

			if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp1, sizeof(itp1)) == -1 ||
			    setsockopt(fd, SOL_IP, IP_TPROXY, &itp2, sizeof(itp2)) == -1) {
				Alert("Cannot bind to tproxy source address before connect() for server %s/%s. Aborting.\n",
				      s->be->id, s->srv->id);
				close(fd);
				send_log(s->be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for server %s/%s.\n",
					 s->be->id, s->srv->id);
				return SN_ERR_RESOURCE;
			}
		}
#endif
	}
	else if (s->be->options & PR_O_BIND_SRC) {
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));
		if (bind(fd, (struct sockaddr *)&s->be->source_addr, sizeof(s->be->source_addr)) == -1) {
			Alert("Cannot bind to source address before connect() for proxy %s. Aborting.\n", s->be->id);
			close(fd);
			send_log(s->be, LOG_EMERG,
				 "Cannot bind to source address before connect() for server %s/%s.\n",
				 s->be->id, s->srv->id);
			return SN_ERR_RESOURCE;
		}
#ifdef CONFIG_HAP_CTTPROXY
		if (s->be->options & PR_O_TPXY_MASK) {
			struct in_tproxy itp1, itp2;
			memset(&itp1, 0, sizeof(itp1));

			itp1.op = TPROXY_ASSIGN;
			switch (s->be->options & PR_O_TPXY_MASK) {
			case PR_O_TPXY_ADDR:
				itp1.v.addr.faddr = s->srv->tproxy_addr.sin_addr;
				itp1.v.addr.fport = s->srv->tproxy_addr.sin_port;
				break;
			case PR_O_TPXY_CLI:
				itp1.v.addr.fport = ((struct sockaddr_in *)&s->cli_addr)->sin_port;
				/* fall through */
			case PR_O_TPXY_CIP:
				/* FIXME: what can we do if the client connects in IPv6 ? */
				itp1.v.addr.faddr = ((struct sockaddr_in *)&s->cli_addr)->sin_addr;
				break;
			}

			/* set connect flag on socket */
			itp2.op = TPROXY_FLAGS;
			itp2.v.flags = ITP_CONNECT | ITP_ONCE;

			if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp1, sizeof(itp1)) == -1 ||
			    setsockopt(fd, SOL_IP, IP_TPROXY, &itp2, sizeof(itp2)) == -1) {
				Alert("Cannot bind to tproxy source address before connect() for proxy %s. Aborting.\n",
				      s->be->id);
				close(fd);
				send_log(s->be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for server %s/%s.\n",
					 s->be->id, s->srv->id);
				return SN_ERR_RESOURCE;
			}
		}
#endif
	}
	
	if ((connect(fd, (struct sockaddr *)&s->srv_addr, sizeof(s->srv_addr)) == -1) &&
	    (errno != EINPROGRESS) && (errno != EALREADY) && (errno != EISCONN)) {

		if (errno == EAGAIN || errno == EADDRINUSE) {
			char *msg;
			if (errno == EAGAIN) /* no free ports left, try again later */
				msg = "no free ports";
			else
				msg = "local address already in use";

			qfprintf(stderr,"Cannot connect: %s.\n",msg);
			close(fd);
			send_log(s->be, LOG_EMERG,
				 "Connect() failed for server %s/%s: %s.\n",
				 s->be->id, s->srv->id, msg);
			return SN_ERR_RESOURCE;
		} else if (errno == ETIMEDOUT) {
			//qfprintf(stderr,"Connect(): ETIMEDOUT");
			close(fd);
			return SN_ERR_SRVTO;
		} else {
			// (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EACCES || errno == EPERM)
			//qfprintf(stderr,"Connect(): %d", errno);
			close(fd);
			return SN_ERR_SRVCL;
		}
	}

	fdtab[fd].owner = s->task;
	fdtab[fd].state = FD_STCONN; /* connection in progress */
	fdtab[fd].cb[DIR_RD].f = &stream_sock_read;
	fdtab[fd].cb[DIR_RD].b = s->rep;
	fdtab[fd].cb[DIR_WR].f = &stream_sock_write;
	fdtab[fd].cb[DIR_WR].b = s->req;

	fdtab[fd].peeraddr = (struct sockaddr *)&s->srv_addr;
	fdtab[fd].peerlen = sizeof(s->srv_addr);

	EV_FD_SET(fd, DIR_WR);  /* for connect status */
    
	fd_insert(fd);
	if (s->srv) {
		s->srv->cur_sess++;
		if (s->srv->cur_sess > s->srv->cur_sess_max)
			s->srv->cur_sess_max = s->srv->cur_sess;
	}

	if (!tv_add_ifset(&s->req->cex, &now, &s->be->contimeout))
		tv_eternity(&s->req->cex);
	return SN_ERR_NONE;  /* connection is OK */
}


/*
 * This function checks the retry count during the connect() job.
 * It updates the session's srv_state and retries, so that the caller knows
 * what it has to do. It uses the last connection error to set the log when
 * it expires. It returns 1 when it has expired, and 0 otherwise.
 */
int srv_count_retry_down(struct session *t, int conn_err)
{
	/* we are in front of a retryable error */
	t->conn_retries--;
	if (t->srv)
		t->srv->retries++;
	t->be->retries++;

	if (t->conn_retries < 0) {
		/* if not retryable anymore, let's abort */
		tv_eternity(&t->req->cex);
		srv_close_with_err(t, conn_err, SN_FINST_C,
				   503, error_message(t, HTTP_ERR_503));
		if (t->srv)
			t->srv->failed_conns++;
		t->be->failed_conns++;

		/* We used to have a free connection slot. Since we'll never use it,
		 * we have to inform the server that it may be used by another session.
		 */
		if (may_dequeue_tasks(t->srv, t->be))
			task_wakeup(t->srv->queue_mgt);
		return 1;
	}
	return 0;
}

    
/*
 * This function performs the retryable part of the connect() job.
 * It updates the session's srv_state and retries, so that the caller knows
 * what it has to do. It returns 1 when it breaks out of the loop, or 0 if
 * it needs to redispatch.
 */
int srv_retryable_connect(struct session *t)
{
	int conn_err;

	/* This loop ensures that we stop before the last retry in case of a
	 * redispatchable server.
	 */
	do {
		/* initiate a connection to the server */
		conn_err = connect_server(t);
		switch (conn_err) {
	
		case SN_ERR_NONE:
			//fprintf(stderr,"0: c=%d, s=%d\n", c, s);
			t->srv_state = SV_STCONN;
			return 1;
	    
		case SN_ERR_INTERNAL:
			tv_eternity(&t->req->cex);
			srv_close_with_err(t, SN_ERR_INTERNAL, SN_FINST_C,
					   500, error_message(t, HTTP_ERR_500));
			if (t->srv)
				t->srv->failed_conns++;
			t->be->failed_conns++;
			/* release other sessions waiting for this server */
			if (may_dequeue_tasks(t->srv, t->be))
				task_wakeup(t->srv->queue_mgt);
			return 1;
		}
		/* ensure that we have enough retries left */
		if (srv_count_retry_down(t, conn_err)) {
			return 1;
		}
	} while (t->srv == NULL || t->conn_retries > 0 || !(t->be->options & PR_O_REDISP));

	/* We're on our last chance, and the REDISP option was specified.
	 * We will ignore cookie and force to balance or use the dispatcher.
	 */
	/* let's try to offer this slot to anybody */
	if (may_dequeue_tasks(t->srv, t->be))
		task_wakeup(t->srv->queue_mgt);

	if (t->srv)
		t->srv->failed_conns++;
	t->be->redispatches++;

	t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
	t->srv = NULL; /* it's left to the dispatcher to choose a server */
	http_flush_cookie_flags(&t->txn);
	return 0;
}

    
/* This function performs the "redispatch" part of a connection attempt. It
 * will assign a server if required, queue the connection if required, and
 * handle errors that might arise at this level. It can change the server
 * state. It will return 1 if it encounters an error, switches the server
 * state, or has to queue a connection. Otherwise, it will return 0 indicating
 * that the connection is ready to use.
 */

int srv_redispatch_connect(struct session *t)
{
	int conn_err;

	/* We know that we don't have any connection pending, so we will
	 * try to get a new one, and wait in this state if it's queued
	 */
	conn_err = assign_server_and_queue(t);
	switch (conn_err) {
	case SRV_STATUS_OK:
		break;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that t->srv == NULL here */
		tv_eternity(&t->req->cex);
		srv_close_with_err(t, SN_ERR_SRVTO, SN_FINST_C,
				   503, error_message(t, HTTP_ERR_503));
		if (t->srv)
			t->srv->failed_conns++;
		t->be->failed_conns++;

		return 1;

	case SRV_STATUS_QUEUED:
		/* FIXME-20060503 : we should use the queue timeout instead */
		if (!tv_add_ifset(&t->req->cex, &now, &t->be->contimeout))
			tv_eternity(&t->req->cex);
		t->srv_state = SV_STIDLE;
		/* do nothing else and do not wake any other session up */
		return 1;

	case SRV_STATUS_FULL:
	case SRV_STATUS_INTERNAL:
	default:
		tv_eternity(&t->req->cex);
		srv_close_with_err(t, SN_ERR_INTERNAL, SN_FINST_C,
				   500, error_message(t, HTTP_ERR_500));
		if (t->srv)
			t->srv->failed_conns++;
		t->be->failed_conns++;

		/* release other sessions waiting for this server */
		if (may_dequeue_tasks(t->srv, t->be))
			task_wakeup(t->srv->queue_mgt);
		return 1;
	}
	/* if we get here, it's because we got SRV_STATUS_OK, which also
	 * means that the connection has not been queued.
	 */
	return 0;
}

int be_downtime(struct proxy *px) {
	if ((px->srv_act || px->srv_bck) && px->last_change < now.tv_sec)		// ignore negative time
		return px->down_time;

	return now.tv_sec - px->last_change + px->down_time;
}

/* This function parses a "balance" statement in a backend section describing
 * <curproxy>. It returns -1 if there is any error, otherwise zero. If it
 * returns -1, it may write an error message into ther <err> buffer, for at
 * most <errlen> bytes, trailing zero included. The trailing '\n' will not be
 * written. The function must be called with <args> pointing to the first word
 * after "balance".
 */
int backend_parse_balance(const char **args, char *err, int errlen, struct proxy *curproxy)
{
	if (!*(args[0])) {
		/* if no option is set, use round-robin by default */
		curproxy->options &= ~PR_O_BALANCE;
		curproxy->options |= PR_O_BALANCE_RR;
		return 0;
	}

	if (!strcmp(args[0], "roundrobin")) {
		curproxy->options &= ~PR_O_BALANCE;
		curproxy->options |= PR_O_BALANCE_RR;
	}
	else if (!strcmp(args[0], "source")) {
		curproxy->options &= ~PR_O_BALANCE;
		curproxy->options |= PR_O_BALANCE_SH;
	}
	else if (!strcmp(args[0], "uri")) {
		curproxy->options &= ~PR_O_BALANCE;
		curproxy->options |= PR_O_BALANCE_UH;
	}
	else if (!strcmp(args[0], "url_param")) {
		if (!*args[1]) {
			snprintf(err, errlen, "'balance url_param' requires an URL parameter name.");
			return -1;
		}
		curproxy->options &= ~PR_O_BALANCE;
		curproxy->options |= PR_O_BALANCE_PH;
		if (curproxy->url_param_name)
			free(curproxy->url_param_name);
		curproxy->url_param_name = strdup(args[1]);
		curproxy->url_param_len = strlen(args[1]);
	}
	else {
		snprintf(err, errlen, "'balance' only supports 'roundrobin', 'source', 'uri' and 'url_param' options.");
		return -1;
	}
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
