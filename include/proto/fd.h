/*
  include/proto/fd.h
  File descriptors states.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
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

#ifndef _PROTO_FD_H
#define _PROTO_FD_H

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/config.h>
#include <types/fd.h>

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd);

/* registers all known pollers */
void register_pollers();

/* disable the specified poller */
void disable_poller(const char *poller_name);

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 */
int init_pollers();

/*
 * Runs the polling loop
 */
void run_poller();


/* FIXME: dirty hack during code transition */
#define dir_StaticWriteEvent DIR_WR
#define dir_StaticReadEvent DIR_RD
#define dir_DIR_RD DIR_RD
#define dir_DIR_WR DIR_WR

#define MY_FD_SET(fd, ev) (cur_poller.set((fd), dir_##ev))
#define MY_FD_CLR(fd, ev) (cur_poller.clr((fd), dir_##ev))
#define MY_FD_ISSET(fd, ev) (cur_poller.isset((fd), dir_##ev))

#define EV_FD_SET(fd, ev)    (cur_poller.set((fd), dir_##ev))
#define EV_FD_CLR(fd, ev)    (cur_poller.clr((fd), dir_##ev))
#define EV_FD_ISSET(fd, ev)  (cur_poller.isset((fd), dir_##ev))
#define EV_FD_COND_S(fd, ev) (cur_poller.cond_s((fd), dir_##ev))
#define EV_FD_COND_C(fd, ev) (cur_poller.cond_c((fd), dir_##ev))
#define EV_FD_REM(fd)        (cur_poller.rem(fd))
#define EV_FD_CLO(fd)        (cur_poller.clo(fd))


/* recomputes the maxfd limit from the fd */
static inline void fd_insert(int fd)
{
	if (fd + 1 > maxfd)
		maxfd = fd + 1;
}


#endif /* _PROTO_FD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
