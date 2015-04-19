/*
 * Functions managing applets
 *
 * Copyright 2000-2015 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <proto/applet.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>

struct list applet_runq = LIST_HEAD_INIT(applet_runq);

void applet_run_active()
{
	struct appctx *curr, *back;
	struct stream_interface *si;

	list_for_each_entry_safe(curr, back, &applet_runq, runq) {
		si = curr->owner;

		/* now we'll need a buffer */
		if (!stream_alloc_recv_buffer(si_ic(si))) {
			si->flags |= SI_FL_WAIT_ROOM;
			LIST_DEL(&curr->runq);
			LIST_INIT(&curr->runq);
			continue;
		}

		curr->applet->fct(curr);
		/* must not dereference curr nor si now because it might have been freed */
	}
}
