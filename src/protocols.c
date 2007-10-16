/*
 * Protocol registration functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/protocols.h>

/* List head of all registered protocols */
static struct list protocols = LIST_HEAD_INIT(protocols);

/* Registers the protocol <proto> */
void protocol_register(struct protocol *proto)
{
	LIST_ADDQ(&protocols, &proto->list);
}

/* Unregisters the protocol <proto>. Note that all listeners must have
 * previously been unbound.
 */
void protocol_unregister(struct protocol *proto)
{
	LIST_DEL(&proto->list);
	LIST_INIT(&proto->list);
}

/* binds all listeneres of all registered protocols. Returns a composition
 * of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_bind_all(void)
{
	struct protocol *proto;
	int err;

	err = 0;
	list_for_each_entry(proto, &protocols, list) {
		if (proto->bind_all)
			err |= proto->bind_all(proto);
	}
	return err;
}

/* unbinds all listeners of all registered protocols. They are also closed.
 * This must be performed before calling exit() in order to get a chance to
 * remove file-system based sockets and pipes.
 * Returns a composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_unbind_all(void)
{
	struct protocol *proto;
	int err;

	err = 0;
	list_for_each_entry(proto, &protocols, list) {
		if (proto->unbind_all)
			err |= proto->unbind_all(proto);
	}
	return err;
}

/* enables all listeners of all registered protocols. This is intended to be
 * used after a fork() to enable reading on all file descriptors. Returns a
 * composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_enable_all(void)
{
	struct protocol *proto;
	int err;

	err = 0;
	list_for_each_entry(proto, &protocols, list) {
		if (proto->enable_all)
			err |= proto->enable_all(proto);
	}
	return err;
}

