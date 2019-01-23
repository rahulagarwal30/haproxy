/*
 * Peer synchro management.
 *
 * Copyright 2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/time.h>
#include <common/standard.h>
#include <common/hathreads.h>

#include <types/global.h>
#include <types/listener.h>
#include <types/obj_type.h>
#include <types/peers.h>

#include <proto/acl.h>
#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/fd.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/mux_pt.h>
#include <proto/peers.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/signal.h>
#include <proto/stick_table.h>
#include <proto/stream_interface.h>
#include <proto/task.h>


/*******************************/
/* Current peer learning state */
/*******************************/

/******************************/
/* Current peers section resync state */
/******************************/
#define	PEERS_F_RESYNC_LOCAL		0x00000001 /* Learn from local finished or no more needed */
#define	PEERS_F_RESYNC_REMOTE		0x00000002 /* Learn from remote finished or no more needed */
#define	PEERS_F_RESYNC_ASSIGN		0x00000004 /* A peer was assigned to learn our lesson */
#define	PEERS_F_RESYNC_PROCESS		0x00000008 /* The assigned peer was requested for resync */
#define	PEERS_F_DONOTSTOP		0x00010000 /* Main table sync task block process during soft stop
						      to push data to new process */

#define	PEERS_RESYNC_STATEMASK		(PEERS_F_RESYNC_LOCAL|PEERS_F_RESYNC_REMOTE)
#define	PEERS_RESYNC_FROMLOCAL		0x00000000
#define	PEERS_RESYNC_FROMREMOTE		PEERS_F_RESYNC_LOCAL
#define	PEERS_RESYNC_FINISHED		(PEERS_F_RESYNC_LOCAL|PEERS_F_RESYNC_REMOTE)

/***********************************/
/* Current shared table sync state */
/***********************************/
#define SHTABLE_F_TEACH_STAGE1		0x00000001 /* Teach state 1 complete */
#define SHTABLE_F_TEACH_STAGE2		0x00000002 /* Teach state 2 complete */

/******************************/
/* Remote peer teaching state */
/******************************/
#define	PEER_F_TEACH_PROCESS		0x00000001 /* Teach a lesson to current peer */
#define	PEER_F_TEACH_FINISHED		0x00000008 /* Teach conclude, (wait for confirm) */
#define	PEER_F_TEACH_COMPLETE		0x00000010 /* All that we know already taught to current peer, used only for a local peer */
#define	PEER_F_LEARN_ASSIGN		0x00000100 /* Current peer was assigned for a lesson */
#define	PEER_F_LEARN_NOTUP2DATE		0x00000200 /* Learn from peer finished but peer is not up to date */
#define	PEER_F_DWNGRD		        0x80000000 /* When this flag is enabled, we must downgrade the supported version announced during peer sessions. */

#define	PEER_TEACH_RESET		~(PEER_F_TEACH_PROCESS|PEER_F_TEACH_FINISHED) /* PEER_F_TEACH_COMPLETE should never be reset */
#define	PEER_LEARN_RESET		~(PEER_F_LEARN_ASSIGN|PEER_F_LEARN_NOTUP2DATE)

/*****************************/
/* Sync message class        */
/*****************************/
enum {
	PEER_MSG_CLASS_CONTROL = 0,
	PEER_MSG_CLASS_ERROR,
	PEER_MSG_CLASS_STICKTABLE = 10,
	PEER_MSG_CLASS_RESERVED = 255,
};

/*****************************/
/* control message types     */
/*****************************/
enum {
	PEER_MSG_CTRL_RESYNCREQ = 0,
	PEER_MSG_CTRL_RESYNCFINISHED,
	PEER_MSG_CTRL_RESYNCPARTIAL,
	PEER_MSG_CTRL_RESYNCCONFIRM,
};

/*****************************/
/* error message types       */
/*****************************/
enum {
	PEER_MSG_ERR_PROTOCOL = 0,
	PEER_MSG_ERR_SIZELIMIT,
};


/*******************************/
/* stick table sync mesg types */
/* Note: ids >= 128 contains   */
/* id message cotains data     */
/*******************************/
#define PEER_MSG_STKT_UPDATE           0x80
#define PEER_MSG_STKT_INCUPDATE        0x81
#define PEER_MSG_STKT_DEFINE           0x82
#define PEER_MSG_STKT_SWITCH           0x83
#define PEER_MSG_STKT_ACK              0x84
#define PEER_MSG_STKT_UPDATE_TIMED     0x85
#define PEER_MSG_STKT_INCUPDATE_TIMED  0x86

/**********************************/
/* Peer Session IO handler states */
/**********************************/

enum {
	PEER_SESS_ST_ACCEPT = 0,     /* Initial state for session create by an accept, must be zero! */
	PEER_SESS_ST_GETVERSION,     /* Validate supported protocol version */
	PEER_SESS_ST_GETHOST,        /* Validate host ID correspond to local host id */
	PEER_SESS_ST_GETPEER,        /* Validate peer ID correspond to a known remote peer id */
	/* after this point, data were possibly exchanged */
	PEER_SESS_ST_SENDSUCCESS,    /* Send ret code 200 (success) and wait for message */
	PEER_SESS_ST_CONNECT,        /* Initial state for session create on a connect, push presentation into buffer */
	PEER_SESS_ST_GETSTATUS,      /* Wait for the welcome message */
	PEER_SESS_ST_WAITMSG,        /* Wait for data messages */
	PEER_SESS_ST_EXIT,           /* Exit with status code */
	PEER_SESS_ST_ERRPROTO,       /* Send error proto message before exit */
	PEER_SESS_ST_ERRSIZE,        /* Send error size message before exit */
	PEER_SESS_ST_END,            /* Killed session */
};

/***************************************************/
/* Peer Session status code - part of the protocol */
/***************************************************/

#define	PEER_SESS_SC_CONNECTCODE	100 /* connect in progress */
#define	PEER_SESS_SC_CONNECTEDCODE	110 /* tcp connect success */

#define	PEER_SESS_SC_SUCCESSCODE	200 /* accept or connect successful */

#define	PEER_SESS_SC_TRYAGAIN		300 /* try again later */

#define	PEER_SESS_SC_ERRPROTO		501 /* error protocol */
#define	PEER_SESS_SC_ERRVERSION		502 /* unknown protocol version */
#define	PEER_SESS_SC_ERRHOST		503 /* bad host name */
#define	PEER_SESS_SC_ERRPEER		504 /* unknown peer */

#define PEER_SESSION_PROTO_NAME         "HAProxyS"
#define PEER_MAJOR_VER        2
#define PEER_MINOR_VER        1
#define PEER_DWNGRD_MINOR_VER 0

struct peers *cfg_peers = NULL;
static void peer_session_forceshutdown(struct appctx *appctx);

/* This function encode an uint64 to 'dynamic' length format.
   The encoded value is written at address *str, and the
   caller must assure that size after *str is large enought.
   At return, the *str is set at the next Byte after then
   encoded integer. The function returns then length of the
   encoded integer in Bytes */
int intencode(uint64_t i, char **str) {
	int idx = 0;
	unsigned char *msg;

	if (!*str)
		return 0;

	msg = (unsigned char *)*str;
	if (i < 240) {
		msg[0] = (unsigned char)i;
		*str = (char *)&msg[idx+1];
		return (idx+1);
	}

	msg[idx] =(unsigned char)i | 240;
	i = (i - 240) >> 4;
	while (i >= 128) {
		msg[++idx] = (unsigned char)i | 128;
		i = (i - 128) >> 7;
	}
	msg[++idx] = (unsigned char)i;
	*str = (char *)&msg[idx+1];
	return (idx+1);
}


/* This function returns the decoded integer or 0
   if decode failed
   *str point on the beginning of the integer to decode
   at the end of decoding *str point on the end of the
   encoded integer or to null if end is reached */
uint64_t intdecode(char **str, char *end)
{
	unsigned char *msg;
	uint64_t i;
	int shift;

	if (!*str)
		return 0;

	msg = (unsigned char *)*str;
	if (msg >= (unsigned char *)end)
		goto fail;

	i = *(msg++);
	if (i >= 240) {
		shift = 4;
		do {
			if (msg >= (unsigned char *)end)
				goto fail;
			i += (uint64_t)*msg << shift;
			shift += 7;
		} while (*(msg++) >= 128);
	}
	*str = (char *)msg;
	return i;

 fail:
	*str = NULL;
	return 0;
}

/* Set the stick-table UPDATE message type byte at <msg_type> address,
 * depending on <use_identifier> and <use_timed> boolean parameters.
 * Always successful.
 */
static inline void peer_set_update_msg_type(char *msg_type, int use_identifier, int use_timed)
{
	if (use_timed) {
		if (use_identifier)
			*msg_type = PEER_MSG_STKT_UPDATE_TIMED;
		else
			*msg_type = PEER_MSG_STKT_INCUPDATE_TIMED;
	}
	else {
		if (use_identifier)
			*msg_type = PEER_MSG_STKT_UPDATE;
		else
			*msg_type = PEER_MSG_STKT_INCUPDATE;
	}
}
/*
 * This prepare the data update message on the stick session <ts>, <st> is the considered
 * stick table.
 *  <msg> is a buffer of <size> to receive data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_updatemsg(struct stksess *ts, struct shared_table *st, char *msg, size_t size,
                                  unsigned int updateid, int use_identifier, int use_timed)
{
	uint32_t netinteger;
	unsigned short datalen;
	char *cursor, *datamsg;
	unsigned int data_type;
	void *data_ptr;

	cursor = datamsg = msg + 1 + 5;

	/* construct message */

	/* check if we need to send the update identifer */
	if (!st->last_pushed || updateid < st->last_pushed || ((updateid - st->last_pushed) != 1)) {
		use_identifier = 1;
	}

	/* encode update identifier if needed */
	if (use_identifier)  {
		netinteger = htonl(updateid);
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}

	if (use_timed) {
		netinteger = htonl(tick_remain(now_ms, ts->expire));
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}

	/* encode the key */
	if (st->table->type == SMP_T_STR) {
		int stlen = strlen((char *)ts->key.key);

		intencode(stlen, &cursor);
		memcpy(cursor, ts->key.key, stlen);
		cursor += stlen;
	}
	else if (st->table->type == SMP_T_SINT) {
		netinteger = htonl(*((uint32_t *)ts->key.key));
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}
	else {
		memcpy(cursor, ts->key.key, st->table->key_size);
		cursor += st->table->key_size;
	}

	HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
	/* encode values */
	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {

		data_ptr = stktable_data_ptr(st->table, ts, data_type);
		if (data_ptr) {
			switch (stktable_data_types[data_type].std_type) {
				case STD_T_SINT: {
					int data;

					data = stktable_data_cast(data_ptr, std_t_sint);
					intencode(data, &cursor);
					break;
				}
				case STD_T_UINT: {
					unsigned int data;

					data = stktable_data_cast(data_ptr, std_t_uint);
					intencode(data, &cursor);
					break;
				}
				case STD_T_ULL: {
					unsigned long long data;

					data = stktable_data_cast(data_ptr, std_t_ull);
					intencode(data, &cursor);
					break;
				}
				case STD_T_FRQP: {
					struct freq_ctr_period *frqp;

					frqp = &stktable_data_cast(data_ptr, std_t_frqp);
					intencode((unsigned int)(now_ms - frqp->curr_tick), &cursor);
					intencode(frqp->curr_ctr, &cursor);
					intencode(frqp->prev_ctr, &cursor);
					break;
				}
			}
		}
	}
	HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	peer_set_update_msg_type(&msg[1], use_identifier, use_timed);
	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * This prepare the switch table message to targeted share table <st>.
 *  <msg> is a buffer of <size> to receive data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_switchmsg(struct stksess *ts, struct shared_table *st, char *msg, size_t size,
                                  unsigned int param1, int param2, int param3)
{
	int len;
	unsigned short datalen;
	struct buffer *chunk;
	char *cursor, *datamsg, *chunkp, *chunkq;
	uint64_t data = 0;
	unsigned int data_type;

	cursor = datamsg = msg + 2 + 5;

	/* Encode data */

	/* encode local id */
	intencode(st->local_id, &cursor);

	/* encode table name */
	len = strlen(st->table->id);
	intencode(len, &cursor);
	memcpy(cursor, st->table->id, len);
	cursor += len;

	/* encode table type */

	intencode(st->table->type, &cursor);

	/* encode table key size */
	intencode(st->table->key_size, &cursor);

	chunk = get_trash_chunk();
	chunkp = chunkq = chunk->area;
	/* encode available known data types in table */
	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {
		if (st->table->data_ofs[data_type]) {
			switch (stktable_data_types[data_type].std_type) {
				case STD_T_SINT:
				case STD_T_UINT:
				case STD_T_ULL:
					data |= 1 << data_type;
					break;
				case STD_T_FRQP:
					data |= 1 << data_type;
					intencode(data_type, &chunkq);
					intencode(st->table->data_arg[data_type].u, &chunkq);
					break;
			}
		}
	}
	intencode(data, &cursor);

	/* Encode stick-table entries duration. */
	intencode(st->table->expire, &cursor);

	if (chunkq > chunkp) {
		chunk->data = chunkq - chunkp;
		memcpy(cursor, chunk->area, chunk->data);
		cursor += chunk->data;
	}

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	msg[1] = PEER_MSG_STKT_DEFINE;
	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * This prepare the acknowledge message on the stick session <ts>, <st> is the considered
 * stick table.
 *  <msg> is a buffer of <size> to receive data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_ackmsg(struct stksess *ts, struct shared_table *st, char *msg, size_t size,
                               unsigned int param1, int param2, int param3)
{
	unsigned short datalen;
	char *cursor, *datamsg;
	uint32_t netinteger;

	cursor = datamsg = msg + 2 + 5;

	intencode(st->remote_id, &cursor);
	netinteger = htonl(st->last_get);
	memcpy(cursor, &netinteger, sizeof(netinteger));
	cursor += sizeof(netinteger);

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	msg[1] = PEER_MSG_STKT_ACK;
	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * Callback to release a session with a peer
 */
static void peer_session_release(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct peer *peer = appctx->ctx.peers.ptr;
	struct peers *peers = strm_fe(s)->parent;

	/* appctx->ctx.peers.ptr is not a peer session */
	if (appctx->st0 < PEER_SESS_ST_SENDSUCCESS)
		return;

	/* peer session identified */
	if (peer) {
		if (appctx->st0 == PEER_SESS_ST_WAITMSG)
			HA_ATOMIC_SUB(&connected_peers, 1);
		HA_ATOMIC_SUB(&active_peers, 1);
		HA_SPIN_LOCK(PEER_LOCK, &peer->lock);
		if (peer->appctx == appctx) {
			/* Re-init current table pointers to force announcement on re-connect */
			peer->remote_table = peer->last_local_table = NULL;
			peer->appctx = NULL;
			if (peer->flags & PEER_F_LEARN_ASSIGN) {
				/* unassign current peer for learning */
				peer->flags &= ~(PEER_F_LEARN_ASSIGN);
				peers->flags &= ~(PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);

				/* reschedule a resync */
				peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(5000));
			}
			/* reset teaching and learning flags to 0 */
			peer->flags &= PEER_TEACH_RESET;
			peer->flags &= PEER_LEARN_RESET;
		}
		HA_SPIN_UNLOCK(PEER_LOCK, &peer->lock);
		task_wakeup(peers->sync_task, TASK_WOKEN_MSG);
	}
}

/* Retrieve the major and minor versions of peers protocol
 * announced by a remote peer. <str> is a null-terminated
 * string with the following format: "<maj_ver>.<min_ver>".
 */
static int peer_get_version(const char *str,
                            unsigned int *maj_ver, unsigned int *min_ver)
{
	unsigned int majv, minv;
	const char *pos, *saved;
	const char *end;

	saved = pos = str;
	end = str + strlen(str);

	majv = read_uint(&pos, end);
	if (saved == pos || *pos++ != '.')
		return -1;

	saved = pos;
	minv = read_uint(&pos, end);
	if (saved == pos || pos != end)
		return -1;

	*maj_ver = majv;
	*min_ver = minv;

	return 0;
}

/*
 * Parse a line terminated by an optional '\r' character, followed by a mandatory
 * '\n' character.
 * Returns 1 if succeeded or 0 if a '\n' character could not be found, and -1 if
 * a line could not be read because the communication channel is closed.
 */
static inline int peer_getline(struct appctx  *appctx)
{
	int n;
	struct stream_interface *si = appctx->owner;

	n = co_getline(si_oc(si), trash.area, trash.size);
	if (!n)
		return 0;

	if (n < 0 || trash.area[n - 1] != '\n') {
		appctx->st0 = PEER_SESS_ST_END;
		return -1;
	}

	if (n > 1 && (trash.area[n - 2] == '\r'))
		trash.area[n - 2] = 0;
	else
		trash.area[n - 1] = 0;

	co_skip(si_oc(si), n);

	return n;
}

/*
 * Send a message after having called <peer_prepare_msg> to build it.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_msg(struct shared_table *st, struct appctx *appctx,
                                int (*peer_prepare_msg)(struct stksess *, struct shared_table *,
                                                        char *, size_t,
                                                        unsigned int, int, int),
                                struct stksess *ts, unsigned int param1, int param2, int param3)
{
	int ret, msglen;
	struct stream_interface *si = appctx->owner;

	msglen = peer_prepare_msg(ts, st, trash.area, trash.size, param1, param2, param3);
	if (!msglen) {
		/* internal error: message does not fit in trash */
		appctx->st0 = PEER_SESS_ST_END;
		return 0;
	}

	/* message to buffer */
	ret = ci_putblk(si_ic(si), trash.area, msglen);
	if (ret <= 0) {
		if (ret == -1) {
			/* No more write possible */
			si_rx_room_blk(si);
			return -1;
		}
		appctx->st0 = PEER_SESS_ST_END;
	}

	return ret;
}

/*
 * Send a stick-table switch message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_switchmsg(struct shared_table *st, struct appctx *appctx)
{
	return peer_send_msg(st, appctx, peer_prepare_switchmsg, NULL, -1, -1, -1);
}

/*
 * Send a stick-table update acknowledgement message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_ackmsg(struct shared_table *st, struct appctx *appctx)
{
	return peer_send_msg(st, appctx, peer_prepare_ackmsg, NULL, -1, -1, -1);
}

/*
 * Send a stick-table update message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_updatemsg(struct shared_table *st, struct appctx *appctx, struct stksess *ts,
                                      unsigned int updateid, int use_identifier, int use_timed)
{
	return peer_send_msg(st, appctx, peer_prepare_updatemsg, ts, updateid, use_identifier, use_timed);
}


/*
 * Function used to lookup for recent stick-table updates associated with
 * <st> shared stick-table when a lesson must be taught a peer (PEER_F_LEARN_ASSIGN flag set).
 */
static inline struct stksess *peer_teach_process_stksess_lookup(struct shared_table *st)
{
	struct eb32_node *eb;

	eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
	if (!eb) {
		eb = eb32_first(&st->table->updates);
		if (!eb || ((int)(eb->key - st->last_pushed) <= 0)) {
			st->table->commitupdate = st->last_pushed = st->table->localupdate;
			return NULL;
		}
	}

	if ((int)(eb->key - st->table->localupdate) > 0) {
		st->table->commitupdate = st->last_pushed = st->table->localupdate;
		return NULL;
	}

	return eb32_entry(eb, struct stksess, upd);
}

/*
 * Function used to lookup for recent stick-table updates associated with
 * <st> shared stick-table during teach state 1 step.
 */
static inline struct stksess *peer_teach_stage1_stksess_lookup(struct shared_table *st)
{
	struct eb32_node *eb;

	eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
	if (!eb) {
		st->flags |= SHTABLE_F_TEACH_STAGE1;
		eb = eb32_first(&st->table->updates);
		if (eb)
			st->last_pushed = eb->key - 1;
		return NULL;
	}

	return eb32_entry(eb, struct stksess, upd);
}

/*
 * Function used to lookup for recent stick-table updates associated with
 * <st> shared stick-table during teach state 2 step.
 */
static inline struct stksess *peer_teach_stage2_stksess_lookup(struct shared_table *st)
{
	struct eb32_node *eb;

	eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
	if (!eb || eb->key > st->teaching_origin) {
		st->flags |= SHTABLE_F_TEACH_STAGE2;
		return NULL;
	}

	return eb32_entry(eb, struct stksess, upd);
}

/*
 * Generic function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p>.
 * <locked> must be set to 1 if the shared table <st> is already locked when entering
 * this function, 0 if not.
 *
 * This function temporary unlock/lock <st> when it sends stick-table updates or
 * when decrementing its refcount in case of any error when it sends this updates.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 * If it returns 0 or -1, this function leave <st> locked if already locked when entering this function
 * unlocked if not already locked when entering this function.
 */
static inline int peer_send_teachmsgs(struct appctx *appctx, struct peer *p,
                                      struct stksess *(*peer_stksess_lookup)(struct shared_table *),
                                      struct shared_table *st, int locked)
{
	int ret, new_pushed, use_timed;

	ret = 1;
	use_timed = 0;
	if (st != p->last_local_table) {
		ret = peer_send_switchmsg(st, appctx);
		if (ret <= 0)
			return ret;

		p->last_local_table = st;
	}

	if (peer_stksess_lookup != peer_teach_process_stksess_lookup)
		use_timed = !(p->flags & PEER_F_DWNGRD);

	/* We force new pushed to 1 to force identifier in update message */
	new_pushed = 1;

	if (!locked)
		HA_SPIN_LOCK(STK_TABLE_LOCK, &st->table->lock);

	while (1) {
		struct stksess *ts;
		unsigned updateid;

		/* push local updates */
		ts = peer_stksess_lookup(st);
		if (!ts)
			break;

		updateid = ts->upd.key;
		ts->ref_cnt++;
		HA_SPIN_UNLOCK(STK_TABLE_LOCK, &st->table->lock);

		ret = peer_send_updatemsg(st, appctx, ts, updateid, new_pushed, use_timed);
		if (ret <= 0) {
			HA_SPIN_LOCK(STK_TABLE_LOCK, &st->table->lock);
			ts->ref_cnt--;
			if (!locked)
				HA_SPIN_UNLOCK(STK_TABLE_LOCK, &st->table->lock);
			return ret;
		}

		HA_SPIN_LOCK(STK_TABLE_LOCK, &st->table->lock);
		ts->ref_cnt--;
		st->last_pushed = updateid;

		if (peer_stksess_lookup == peer_teach_process_stksess_lookup &&
		    (int)(st->last_pushed - st->table->commitupdate) > 0)
			st->table->commitupdate = st->last_pushed;

		/* identifier may not needed in next update message */
		new_pushed = 0;
	}

 out:
	if (!locked)
		HA_SPIN_UNLOCK(STK_TABLE_LOCK, &st->table->lock);
	return 1;
}

/*
 * Function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p> (PEER_F_LEARN_ASSIGN flag set).
 *
 * Note that <st> shared stick-table is locked when calling this function.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_teach_process_msgs(struct appctx *appctx, struct peer *p,
                                               struct shared_table *st)
{
	return peer_send_teachmsgs(appctx, p, peer_teach_process_stksess_lookup, st, 1);
}

/*
 * Function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p> during teach state 1 step.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_teach_stage1_msgs(struct appctx *appctx, struct peer *p,
                                              struct shared_table *st)
{
	return peer_send_teachmsgs(appctx, p, peer_teach_stage1_stksess_lookup, st, 0);
}

/*
 * Function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p> during teach state 1 step.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_teach_stage2_msgs(struct appctx *appctx, struct peer *p,
                                              struct shared_table *st)
{
	return peer_send_teachmsgs(appctx, p, peer_teach_stage2_stksess_lookup, st, 0);
}


/*
 * Function used to parse a stick-table update message after it has been received
 * by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * <exp> must be set if the stick-table entry expires.
 * <updt> must be set for  PEER_MSG_STKT_UPDATE or PEER_MSG_STKT_UPDATE_TIMED stick-table
 * messages, in this case the stick-table udpate message is received with a stick-table
 * update ID.
 * <totl> is the length of the stick-table update message computed upon receipt.
 */
static int peer_recv_updatemsg(struct appctx *appctx, struct peer *p, int updt, int exp,
                               char **msg_cur, char *msg_end, int msg_len, int totl)
{
	struct stream_interface *si = appctx->owner;
	struct shared_table *st = p->remote_table;
	struct stksess *ts, *newts;
	uint32_t update;
	int expire;
	unsigned int data_type;
	void *data_ptr;

	/* Here we have data message */
	if (!st)
		goto ignore_msg;

	expire = MS_TO_TICKS(st->table->expire);

	if (updt) {
		if (msg_len < sizeof(update)) {
			/* malformed message */
			appctx->st0 = PEER_SESS_ST_ERRPROTO;
			return 0;
		}
		memcpy(&update, *msg_cur, sizeof(update));
		*msg_cur += sizeof(update);
		st->last_get = htonl(update);
	}
	else {
		st->last_get++;
	}

	if (exp) {
		size_t expire_sz = sizeof expire;

		if (*msg_cur + expire_sz > msg_end) {
			appctx->st0 = PEER_SESS_ST_ERRPROTO;
			return 0;
		}
		memcpy(&expire, *msg_cur, expire_sz);
		*msg_cur += expire_sz;
		expire = ntohl(expire);
	}

	newts = stksess_new(st->table, NULL);
	if (!newts)
		goto ignore_msg;

	if (st->table->type == SMP_T_STR) {
		unsigned int to_read, to_store;

		to_read = intdecode(msg_cur, msg_end);
		if (!*msg_cur) {
			/* malformed message */
			stksess_free(st->table, newts);
			appctx->st0 = PEER_SESS_ST_ERRPROTO;
			return 0;
		}
		to_store = MIN(to_read, st->table->key_size - 1);
		if (*msg_cur + to_store > msg_end) {
			/* malformed message */
			stksess_free(st->table, newts);
			appctx->st0 = PEER_SESS_ST_ERRPROTO;
			return 0;
		}

		memcpy(newts->key.key, *msg_cur, to_store);
		newts->key.key[to_store] = 0;
		*msg_cur += to_read;
	}
	else if (st->table->type == SMP_T_SINT) {
		unsigned int netinteger;

		if (*msg_cur + sizeof(netinteger) > msg_end) {
			/* malformed message */
			stksess_free(st->table, newts);
			appctx->st0 = PEER_SESS_ST_ERRPROTO;
			return 0;
		}
		memcpy(&netinteger, *msg_cur, sizeof(netinteger));
		netinteger = ntohl(netinteger);
		memcpy(newts->key.key, &netinteger, sizeof(netinteger));
		*msg_cur += sizeof(netinteger);
	}
	else {
		if (*msg_cur + st->table->key_size > msg_end) {
			/* malformed message */
			stksess_free(st->table, newts);
			appctx->st0 = PEER_SESS_ST_ERRPROTO;
			return 0;
		}
		memcpy(newts->key.key, *msg_cur, st->table->key_size);
		*msg_cur += st->table->key_size;
	}

	/* lookup for existing entry */
	ts = stktable_set_entry(st->table, newts);
	if (ts != newts) {
		stksess_free(st->table, newts);
		newts = NULL;
	}

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {

		if (!((1 << data_type) & st->remote_data))
			continue;

		switch (stktable_data_types[data_type].std_type) {
		case STD_T_SINT: {
			int data;

			data = intdecode(msg_cur, msg_end);
			if (!*msg_cur) {
				/* malformed message */
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_remote(st->table, ts, 1);
				appctx->st0 = PEER_SESS_ST_ERRPROTO;
				return 0;
			}

			data_ptr = stktable_data_ptr(st->table, ts, data_type);
			if (data_ptr)
				stktable_data_cast(data_ptr, std_t_sint) = data;
			break;
		}
		case STD_T_UINT: {
			unsigned int data;

			data = intdecode(msg_cur, msg_end);
			if (!*msg_cur) {
				/* malformed message */
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_remote(st->table, ts, 1);
				appctx->st0 = PEER_SESS_ST_ERRPROTO;
				return 0;
			}

			data_ptr = stktable_data_ptr(st->table, ts, data_type);
			if (data_ptr)
				stktable_data_cast(data_ptr, std_t_uint) = data;
			break;
		}
		case STD_T_ULL: {
			unsigned long long  data;

			data = intdecode(msg_cur, msg_end);
			if (!*msg_cur) {
				/* malformed message */
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_remote(st->table, ts, 1);
				appctx->st0 = PEER_SESS_ST_ERRPROTO;
				return 0;
			}

			data_ptr = stktable_data_ptr(st->table, ts, data_type);
			if (data_ptr)
				stktable_data_cast(data_ptr, std_t_ull) = data;
			break;
		}
		case STD_T_FRQP: {
			struct freq_ctr_period data;

			/* First bit is reserved for the freq_ctr_period lock
			Note: here we're still protected by the stksess lock
			so we don't need to update the update the freq_ctr_period
			using its internal lock */

			data.curr_tick = tick_add(now_ms, -intdecode(msg_cur, msg_end)) & ~0x1;
			if (!*msg_cur) {
				/* malformed message */
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_remote(st->table, ts, 1);
				appctx->st0 = PEER_SESS_ST_ERRPROTO;
				return 0;
			}
			data.curr_ctr = intdecode(msg_cur, msg_end);
			if (!*msg_cur) {
				/* malformed message */
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_remote(st->table, ts, 1);
				appctx->st0 = PEER_SESS_ST_ERRPROTO;
				return 0;
			}
			data.prev_ctr = intdecode(msg_cur, msg_end);
			if (!*msg_cur) {
				/* malformed message */
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_remote(st->table, ts, 1);
				appctx->st0 = PEER_SESS_ST_ERRPROTO;
				return 0;
			}

			data_ptr = stktable_data_ptr(st->table, ts, data_type);
			if (data_ptr)
				stktable_data_cast(data_ptr, std_t_frqp) = data;
			break;
		}
		}
	}
	/* Force new expiration */
	ts->expire = tick_add(now_ms, expire);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
	stktable_touch_remote(st->table, ts, 1);
	return 1;

 ignore_msg:
	/* skip consumed message */
	co_skip(si_oc(si), totl);
	return 0;
}

/*
 * Function used to parse a stick-table update acknowledgement message after it
 * has been received by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being the position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * Return 1 if succeeded, 0 if not with the appctx state st0 set to PEER_SESS_ST_ERRPROTO.
 */
static inline int peer_treat_ackmsg(struct appctx *appctx, struct peer *p,
                                    char **msg_cur, char *msg_end)
{
	/* ack message */
	uint32_t table_id ;
	uint32_t update;
	struct shared_table *st;

	table_id = intdecode(msg_cur, msg_end);
	if (!*msg_cur || (*msg_cur + sizeof(update) > msg_end)) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	memcpy(&update, *msg_cur, sizeof(update));
	update = ntohl(update);

	for (st = p->tables; st; st = st->next) {
		if (st->local_id == table_id) {
			st->update = update;
			break;
		}
	}

	return 1;
}

/*
 * Function used to parse a stick-table switch message after it has been received
 * by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being the position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * Return 1 if succeeded, 0 if not with the appctx state st0 set to PEER_SESS_ST_ERRPROTO.
 */
static inline int peer_treat_switchmsg(struct appctx *appctx, struct peer *p,
                                      char **msg_cur, char *msg_end)
{
	struct shared_table *st;
	int table_id;

	table_id = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	p->remote_table = NULL;
	for (st = p->tables; st; st = st->next) {
		if (st->remote_id == table_id) {
			p->remote_table = st;
			break;
		}
	}

	return 1;
}

/*
 * Function used to parse a stick-table definition message after it has been received
 * by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being the position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * <totl> is the length of the stick-table update message computed upon receipt.
 * Return 1 if succeeded, 0 if not with the appctx state st0 set to PEER_SESS_ST_ERRPROTO.
 */
static inline int peer_treat_definemsg(struct appctx *appctx, struct peer *p,
                                      char **msg_cur, char *msg_end, int totl)
{
	struct stream_interface *si = appctx->owner;
	int table_id_len;
	struct shared_table *st;
	int table_type;
	int table_keylen;
	int table_id;
	uint64_t table_data;

	table_id = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	table_id_len = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	p->remote_table = NULL;
	if (!table_id_len || (*msg_cur + table_id_len) >= msg_end) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	for (st = p->tables; st; st = st->next) {
		/* Reset IDs */
		if (st->remote_id == table_id)
			st->remote_id = 0;

		if (!p->remote_table && (table_id_len == strlen(st->table->id)) &&
		    (memcmp(st->table->id, *msg_cur, table_id_len) == 0))
			p->remote_table = st;
	}

	if (!p->remote_table)
		goto ignore_msg;

	*msg_cur += table_id_len;
	if (*msg_cur >= msg_end) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	table_type = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	table_keylen = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	table_data = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	if (p->remote_table->table->type != table_type
		|| p->remote_table->table->key_size != table_keylen) {
		p->remote_table = NULL;
		goto ignore_msg;
	}

	p->remote_table->remote_data = table_data;
	p->remote_table->remote_id = table_id;
	return 1;

 ignore_msg:
	co_skip(si_oc(si), totl);
	return 0;
}

/*
 * IO Handler to handle message exchance with a peer
 */
static void peer_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct peers *curpeers = strm_fe(s)->parent;
	struct peer *curpeer = NULL;
	int reql = 0;
	int repl = 0;
	size_t proto_len = strlen(PEER_SESSION_PROTO_NAME);
	unsigned int maj_ver, min_ver;
	int prev_state;

	/* Check if the input buffer is available. */
	if (si_ic(si)->buf.size == 0)
		goto full;

	while (1) {
		prev_state = appctx->st0;
switchstate:
		maj_ver = min_ver = (unsigned int)-1;
		switch(appctx->st0) {
			case PEER_SESS_ST_ACCEPT:
				prev_state = appctx->st0;
				appctx->ctx.peers.ptr = NULL;
				appctx->st0 = PEER_SESS_ST_GETVERSION;
				/* fall through */
			case PEER_SESS_ST_GETVERSION:
				prev_state = appctx->st0;

				reql = peer_getline(appctx);
				if (!reql)
					goto out;

				if (reql < 0)
					goto switchstate;

				/* test protocol */
				if (strncmp(PEER_SESSION_PROTO_NAME " ", trash.area, proto_len + 1) != 0) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRPROTO;
					goto switchstate;
				}
				if (peer_get_version(trash.area + proto_len + 1, &maj_ver, &min_ver) == -1 ||
				    maj_ver != PEER_MAJOR_VER || min_ver > PEER_MINOR_VER) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRVERSION;
					goto switchstate;
				}

				appctx->st0 = PEER_SESS_ST_GETHOST;
				/* fall through */
			case PEER_SESS_ST_GETHOST:
				prev_state = appctx->st0;

				reql = peer_getline(appctx);
				if (!reql)
					goto out;

				if (reql < 0)
					goto switchstate;

				/* test hostname match */
				if (strcmp(localpeer, trash.area) != 0) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRHOST;
					goto switchstate;
				}

				appctx->st0 = PEER_SESS_ST_GETPEER;
				/* fall through */
			case PEER_SESS_ST_GETPEER: {
				char *p;

				prev_state = appctx->st0;

				reql = peer_getline(appctx);
				if (!reql)
					goto out;

				if (reql < 0)
					goto switchstate;

				/* parse line "<peer name> <pid> <relative_pid>" */
				p = strchr(trash.area, ' ');
				if (!p) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRPROTO;
					goto switchstate;
				}
				*p = 0;

				/* lookup known peer */
				for (curpeer = curpeers->remote; curpeer; curpeer = curpeer->next) {
					if (strcmp(curpeer->id, trash.area) == 0)
						break;
				}

				/* if unknown peer */
				if (!curpeer) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRPEER;
					goto switchstate;
				}

				HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
				if (curpeer->appctx && curpeer->appctx != appctx) {
					if (curpeer->local) {
						/* Local connection, reply a retry */
						appctx->st0 = PEER_SESS_ST_EXIT;
						appctx->st1 = PEER_SESS_SC_TRYAGAIN;
						goto switchstate;
					}

					/* we're killing a connection, we must apply a random delay before
					 * retrying otherwise the other end will do the same and we can loop
					 * for a while.
					 */
					curpeer->reconnect = tick_add(now_ms, MS_TO_TICKS(50 + random() % 2000));
					peer_session_forceshutdown(curpeer->appctx);
				}
				if (maj_ver != (unsigned int)-1 && min_ver != (unsigned int)-1) {
					if (min_ver == PEER_DWNGRD_MINOR_VER) {
						curpeer->flags |= PEER_F_DWNGRD;
					}
					else {
						curpeer->flags &= ~PEER_F_DWNGRD;
					}
				}
				curpeer->appctx = appctx;
				appctx->ctx.peers.ptr = curpeer;
				appctx->st0 = PEER_SESS_ST_SENDSUCCESS;
				HA_ATOMIC_ADD(&active_peers, 1);
				/* fall through */
			}
			case PEER_SESS_ST_SENDSUCCESS: {
				struct shared_table *st;

				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->ctx.peers.ptr;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}
				repl = snprintf(trash.area, trash.size,
						"%d\n",
						PEER_SESS_SC_SUCCESSCODE);
				repl = ci_putblk(si_ic(si), trash.area, repl);
				if (repl <= 0) {
					if (repl == -1)
						goto full;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}

				/* Register status code */
				curpeer->statuscode = PEER_SESS_SC_SUCCESSCODE;

				/* Awake main task */
				task_wakeup(curpeers->sync_task, TASK_WOKEN_MSG);

				/* Init confirm counter */
				curpeer->confirm = 0;

				/* Init cursors */
				for (st = curpeer->tables; st ; st = st->next) {
					st->last_get = st->last_acked = 0;
					st->teaching_origin = st->last_pushed = st->update;
				}

				/* reset teaching and learning flags to 0 */
				curpeer->flags &= PEER_TEACH_RESET;
				curpeer->flags &= PEER_LEARN_RESET;

				/* if current peer is local */
				if (curpeer->local) {
					/* if current host need resyncfrom local and no process assined  */
					if ((curpeers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMLOCAL &&
					    !(curpeers->flags & PEERS_F_RESYNC_ASSIGN)) {
						/* assign local peer for a lesson, consider lesson already requested */
						curpeer->flags |= PEER_F_LEARN_ASSIGN;
						curpeers->flags |= (PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);
					}

				}
				else if ((curpeers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE &&
				         !(curpeers->flags & PEERS_F_RESYNC_ASSIGN)) {
					/* assign peer for a lesson  */
					curpeer->flags |= PEER_F_LEARN_ASSIGN;
					curpeers->flags |= PEERS_F_RESYNC_ASSIGN;
				}


				/* switch to waiting message state */
				HA_ATOMIC_ADD(&connected_peers, 1);
				appctx->st0 = PEER_SESS_ST_WAITMSG;
				goto switchstate;
			}
			case PEER_SESS_ST_CONNECT: {
				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->ctx.peers.ptr;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}

				/* Send headers */
				repl = snprintf(trash.area, trash.size,
				                PEER_SESSION_PROTO_NAME " %u.%u\n%s\n%s %d %d\n",
				                PEER_MAJOR_VER,
				                (curpeer->flags & PEER_F_DWNGRD) ? PEER_DWNGRD_MINOR_VER : PEER_MINOR_VER,
				                curpeer->id,
				                localpeer,
				                (int)getpid(),
						relative_pid);

				if (repl >= trash.size) {
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}

				repl = ci_putblk(si_ic(si), trash.area, repl);
				if (repl <= 0) {
					if (repl == -1)
						goto full;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}

				/* switch to the waiting statuscode state */
				appctx->st0 = PEER_SESS_ST_GETSTATUS;
				/* fall through */
			}
			case PEER_SESS_ST_GETSTATUS: {
				struct shared_table *st;

				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->ctx.peers.ptr;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}

				if (si_ic(si)->flags & CF_WRITE_PARTIAL)
					curpeer->statuscode = PEER_SESS_SC_CONNECTEDCODE;

				reql = peer_getline(appctx);
				if (!reql)
					goto out;

				if (reql < 0)
					goto switchstate;

				/* Register status code */
				curpeer->statuscode = atoi(trash.area);

				/* Awake main task */
				task_wakeup(curpeers->sync_task, TASK_WOKEN_MSG);

				/* If status code is success */
				if (curpeer->statuscode == PEER_SESS_SC_SUCCESSCODE) {
					/* Init cursors */
					for (st = curpeer->tables; st ; st = st->next) {
						st->last_get = st->last_acked = 0;
						st->teaching_origin = st->last_pushed = st->update;
					}

					/* Init confirm counter */
					curpeer->confirm = 0;

					/* reset teaching and learning flags to 0 */
					curpeer->flags &= PEER_TEACH_RESET;
					curpeer->flags &= PEER_LEARN_RESET;

					/* If current peer is local */
					if (curpeer->local) {
						/* flag to start to teach lesson */
						curpeer->flags |= PEER_F_TEACH_PROCESS;

					}
					else if ((curpeers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE &&
					         !(curpeers->flags & PEERS_F_RESYNC_ASSIGN)) {
						/* If peer is remote and resync from remote is needed,
						   and no peer currently assigned */

						/* assign peer for a lesson */
						curpeer->flags |= PEER_F_LEARN_ASSIGN;
						curpeers->flags |= PEERS_F_RESYNC_ASSIGN;
					}

				}
				else {
					if (curpeer->statuscode == PEER_SESS_SC_ERRVERSION)
						curpeer->flags |= PEER_F_DWNGRD;
					/* Status code is not success, abort */
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				HA_ATOMIC_ADD(&connected_peers, 1);
				appctx->st0 = PEER_SESS_ST_WAITMSG;
				/* fall through */
			}
			case PEER_SESS_ST_WAITMSG: {
				uint32_t msg_len = 0;
				char *msg_cur = trash.area;
				char *msg_end = trash.area;
				unsigned char msg_head[7];
				int totl = 0;

				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->ctx.peers.ptr;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}

				reql = co_getblk(si_oc(si), (char *)msg_head, 2*sizeof(unsigned char), totl);
				if (reql <= 0) /* closed or EOL not found */
					goto incomplete;

				totl += reql;

				if (msg_head[1] >= 128) {
					/* Read and Decode message length */
					reql = co_getblk(si_oc(si), (char *)&msg_head[2], sizeof(unsigned char), totl);
					if (reql <= 0) /* closed */
						goto incomplete;

					totl += reql;

					if (msg_head[2] < 240) {
						msg_len = msg_head[2];
					}
					else {
						int i;
						char *cur;
						char *end;

						for (i = 3 ; i < sizeof(msg_head) ; i++) {
							reql = co_getblk(si_oc(si), (char *)&msg_head[i], sizeof(char), totl);
							if (reql <= 0) /* closed */
								goto incomplete;

							totl += reql;

							if (!(msg_head[i] & 0x80))
								break;
						}

						if (i == sizeof(msg_head)) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;

						}
						end = (char *)msg_head + sizeof(msg_head);
						cur = (char *)&msg_head[2];
						msg_len = intdecode(&cur, end);
						if (!cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}
					}


					/* Read message content */
					if (msg_len) {
						if (msg_len > trash.size) {
							/* Status code is not success, abort */
							appctx->st0 = PEER_SESS_ST_ERRSIZE;
							goto switchstate;
						}

						reql = co_getblk(si_oc(si),
								 trash.area,
								 msg_len,
								 totl);
						if (reql <= 0) /* closed */
							goto incomplete;
						totl += reql;

						msg_end += msg_len;
					}
				}

				if (msg_head[0] == PEER_MSG_CLASS_CONTROL) {
					if (msg_head[1] == PEER_MSG_CTRL_RESYNCREQ) {
						struct shared_table *st;
						/* Reset message: remote need resync */

						/* prepare tables fot a global push */
						for (st = curpeer->tables; st; st = st->next) {
							st->teaching_origin = st->last_pushed = st->table->update;
							st->flags = 0;
						}

						/* reset teaching flags to 0 */
						curpeer->flags &= PEER_TEACH_RESET;

						/* flag to start to teach lesson */
						curpeer->flags |= PEER_F_TEACH_PROCESS;
					}
					else if (msg_head[1] == PEER_MSG_CTRL_RESYNCFINISHED) {
						if (curpeer->flags & PEER_F_LEARN_ASSIGN) {
							curpeer->flags &= ~PEER_F_LEARN_ASSIGN;
							curpeers->flags &= ~(PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);
							curpeers->flags |= (PEERS_F_RESYNC_LOCAL|PEERS_F_RESYNC_REMOTE);
						}
						curpeer->confirm++;
					}
					else if (msg_head[1] == PEER_MSG_CTRL_RESYNCPARTIAL) {
						if (curpeer->flags & PEER_F_LEARN_ASSIGN) {
							curpeer->flags &= ~PEER_F_LEARN_ASSIGN;
							curpeers->flags &= ~(PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);

							curpeer->flags |= PEER_F_LEARN_NOTUP2DATE;
							curpeers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(5000));
							task_wakeup(curpeers->sync_task, TASK_WOKEN_MSG);
						}
						curpeer->confirm++;
					}
					else if (msg_head[1] == PEER_MSG_CTRL_RESYNCCONFIRM)  {
						struct shared_table *st;

						/* If stopping state */
						if (stopping) {
							/* Close session, push resync no more needed */
							curpeer->flags |= PEER_F_TEACH_COMPLETE;
							appctx->st0 = PEER_SESS_ST_END;
							goto switchstate;
						}
						for (st = curpeer->tables; st; st = st->next) {
							st->update = st->last_pushed = st->teaching_origin;
							st->flags = 0;
						}

						 /* reset teaching flags to 0 */
						curpeer->flags &= PEER_TEACH_RESET;
					}
				}
				else if (msg_head[0] == PEER_MSG_CLASS_STICKTABLE) {
					if (msg_head[1] == PEER_MSG_STKT_DEFINE) {
						if (!peer_treat_definemsg(appctx, curpeer, &msg_cur, msg_end, totl))
						    goto switchstate;
					}
					else if (msg_head[1] == PEER_MSG_STKT_SWITCH) {
						if (!peer_treat_switchmsg(appctx, curpeer, &msg_cur, msg_end))
							goto switchstate;
					}
					else if (msg_head[1] == PEER_MSG_STKT_UPDATE
						 || msg_head[1] == PEER_MSG_STKT_INCUPDATE
						 || msg_head[1] == PEER_MSG_STKT_UPDATE_TIMED
						 || msg_head[1] == PEER_MSG_STKT_INCUPDATE_TIMED) {
						int update, expire;

						update = msg_head[1] == PEER_MSG_STKT_UPDATE || msg_head[1] == PEER_MSG_STKT_UPDATE_TIMED;
						expire = msg_head[1] == PEER_MSG_STKT_UPDATE_TIMED || msg_head[1] == PEER_MSG_STKT_INCUPDATE_TIMED;
						if (!peer_recv_updatemsg(appctx, curpeer, update, expire,
						                          &msg_cur, msg_end, msg_len, totl))
							goto switchstate;

					}
					else if (msg_head[1] == PEER_MSG_STKT_ACK) {
						if (!peer_treat_ackmsg(appctx, curpeer, &msg_cur, msg_end))
							goto switchstate;
					}
				}
				else if (msg_head[0] == PEER_MSG_CLASS_RESERVED) {
					appctx->st0 = PEER_SESS_ST_ERRPROTO;
					goto switchstate;
				}

ignore_msg:
				/* skip consumed message */
				co_skip(si_oc(si), totl);
				/* loop on that state to peek next message */
				goto switchstate;

incomplete:
				/* we get here when a co_getblk() returns <= 0 in reql */

				if (reql < 0) {
					/* there was an error */
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}




				/* Need to request a resync */
				if ((curpeer->flags & PEER_F_LEARN_ASSIGN) &&
				    (curpeers->flags & PEERS_F_RESYNC_ASSIGN) &&
				    !(curpeers->flags & PEERS_F_RESYNC_PROCESS)) {
					unsigned char msg[2];

					/* Current peer was elected to request a resync */
					msg[0] = PEER_MSG_CLASS_CONTROL;
					msg[1] = PEER_MSG_CTRL_RESYNCREQ;

					/* message to buffer */
					repl = ci_putblk(si_ic(si), (char *)msg, sizeof(msg));
					if (repl <= 0) {
						/* no more write possible */
						if (repl == -1)
							goto full;
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
					curpeers->flags |= PEERS_F_RESYNC_PROCESS;
				}

				/* Nothing to read, now we start to write */
				if (curpeer->tables) {
					struct shared_table *st;
					struct shared_table *last_local_table;

					last_local_table = curpeer->last_local_table;
					if (!last_local_table)
						last_local_table = curpeer->tables;
					st = last_local_table->next;

					while (1) {
						if (!st)
							 st = curpeer->tables;

						/* It remains some updates to ack */
						if (st->last_get != st->last_acked) {
							repl = peer_send_ackmsg(st, appctx);
							if (repl <= 0) {
								if (repl == -1)
									goto out;
								goto switchstate;
							}
							st->last_acked = st->last_get;
						}

						if (!(curpeer->flags & PEER_F_TEACH_PROCESS)) {
							HA_SPIN_LOCK(STK_TABLE_LOCK, &st->table->lock);
							if (!(curpeer->flags & PEER_F_LEARN_ASSIGN) &&
							    ((int)(st->last_pushed - st->table->localupdate) < 0)) {

								repl = peer_send_teach_process_msgs(appctx, curpeer, st);
								if (repl <= 0) {
									HA_SPIN_UNLOCK(STK_TABLE_LOCK, &st->table->lock);
									if (repl == -1)
										goto out;
									goto switchstate;
								}
							}
							HA_SPIN_UNLOCK(STK_TABLE_LOCK, &st->table->lock);
						}
						else {
							if (!(st->flags & SHTABLE_F_TEACH_STAGE1)) {
								repl = peer_send_teach_stage1_msgs(appctx, curpeer, st);
								if (repl <= 0) {
									if (repl == -1)
										goto out;
									goto switchstate;
								}
							}

							if (!(st->flags & SHTABLE_F_TEACH_STAGE2)) {
								repl = peer_send_teach_stage2_msgs(appctx, curpeer, st);
								if (repl <= 0) {
									if (repl == -1)
										goto out;
									goto switchstate;
								}
							}
						}

						if (st == last_local_table)
							break;
						st = st->next;
					}
				}


				if ((curpeer->flags & PEER_F_TEACH_PROCESS) && !(curpeer->flags & PEER_F_TEACH_FINISHED)) {
					unsigned char msg[2];

					/* Current peer was elected to request a resync */
					msg[0] = PEER_MSG_CLASS_CONTROL;
					msg[1] = ((curpeers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FINISHED) ? PEER_MSG_CTRL_RESYNCFINISHED : PEER_MSG_CTRL_RESYNCPARTIAL;
					/* process final lesson message */
					repl = ci_putblk(si_ic(si), (char *)msg, sizeof(msg));
					if (repl <= 0) {
						/* no more write possible */
						if (repl == -1)
							goto full;
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
					/* flag finished message sent */
					curpeer->flags |= PEER_F_TEACH_FINISHED;
				}

				/* Confirm finished or partial messages */
				while (curpeer->confirm) {
					unsigned char msg[2];

					/* There is a confirm messages to send */
					msg[0] = PEER_MSG_CLASS_CONTROL;
					msg[1] = PEER_MSG_CTRL_RESYNCCONFIRM;

					/* message to buffer */
					repl = ci_putblk(si_ic(si), (char *)msg, sizeof(msg));
					if (repl <= 0) {
						/* no more write possible */
						if (repl == -1)
							goto full;
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
					curpeer->confirm--;
				}

				/* noting more to do */
				goto out;
			}
			case PEER_SESS_ST_EXIT:
				if (prev_state == PEER_SESS_ST_WAITMSG)
					HA_ATOMIC_SUB(&connected_peers, 1);
				prev_state = appctx->st0;
				repl = snprintf(trash.area, trash.size,
						"%d\n", appctx->st1);
				if (ci_putblk(si_ic(si), trash.area, repl) == -1)
					goto full;
				appctx->st0 = PEER_SESS_ST_END;
				goto switchstate;
			case PEER_SESS_ST_ERRSIZE: {
				unsigned char msg[2];

				if (prev_state == PEER_SESS_ST_WAITMSG)
					HA_ATOMIC_SUB(&connected_peers, 1);
				prev_state = appctx->st0;
				msg[0] = PEER_MSG_CLASS_ERROR;
				msg[1] = PEER_MSG_ERR_SIZELIMIT;

				if (ci_putblk(si_ic(si), (char *)msg, sizeof(msg)) == -1)
					goto full;
				appctx->st0 = PEER_SESS_ST_END;
				goto switchstate;
			}
			case PEER_SESS_ST_ERRPROTO: {
				unsigned char msg[2];

				if (prev_state == PEER_SESS_ST_WAITMSG)
					HA_ATOMIC_SUB(&connected_peers, 1);
				prev_state = appctx->st0;
				msg[0] = PEER_MSG_CLASS_ERROR;
				msg[1] = PEER_MSG_ERR_PROTOCOL;

				if (ci_putblk(si_ic(si), (char *)msg, sizeof(msg)) == -1)
					goto full;
				appctx->st0 = PEER_SESS_ST_END;
				prev_state = appctx->st0;
				/* fall through */
			}
			case PEER_SESS_ST_END: {
				if (prev_state == PEER_SESS_ST_WAITMSG)
					HA_ATOMIC_SUB(&connected_peers, 1);
				prev_state = appctx->st0;
				if (curpeer) {
					HA_SPIN_UNLOCK(PEER_LOCK, &curpeer->lock);
					curpeer = NULL;
				}
				si_shutw(si);
				si_shutr(si);
				si_ic(si)->flags |= CF_READ_NULL;
				goto out;
			}
		}
	}
out:
	si_oc(si)->flags |= CF_READ_DONTWAIT;

	if (curpeer)
		HA_SPIN_UNLOCK(PEER_LOCK, &curpeer->lock);
	return;
full:
	si_rx_room_blk(si);
	goto out;
}

static struct applet peer_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<PEER>", /* used for logging */
	.fct = peer_io_handler,
	.release = peer_session_release,
};

/*
 * Use this function to force a close of a peer session
 */
static void peer_session_forceshutdown(struct appctx *appctx)
{
	/* Note that the peer sessions which have just been created
	 * (->st0 == PEER_SESS_ST_CONNECT) must not
	 * be shutdown, if not, the TCP session will never be closed
	 * and stay in CLOSE_WAIT state after having been closed by
	 * the remote side.
	 */
	if (!appctx || appctx->st0 == PEER_SESS_ST_CONNECT)
		return;

	if (appctx->applet != &peer_applet)
		return;

	if (appctx->st0 == PEER_SESS_ST_WAITMSG)
		HA_ATOMIC_SUB(&connected_peers, 1);
	appctx->st0 = PEER_SESS_ST_END;
	appctx_wakeup(appctx);
}

/* Pre-configures a peers frontend to accept incoming connections */
void peers_setup_frontend(struct proxy *fe)
{
	fe->last_change = now.tv_sec;
	fe->cap = PR_CAP_FE | PR_CAP_BE;
	fe->maxconn = 0;
	fe->conn_retries = CONN_RETRIES;
	fe->timeout.client = MS_TO_TICKS(5000);
	fe->accept = frontend_accept;
	fe->default_target = &peer_applet.obj_type;
	fe->options2 |= PR_O2_INDEPSTR | PR_O2_SMARTCON | PR_O2_SMARTACC;
	fe->bind_proc = 0; /* will be filled by users */
}

/*
 * Create a new peer session in assigned state (connect will start automatically)
 */
static struct appctx *peer_session_create(struct peers *peers, struct peer *peer)
{
	struct proxy *p = peers->peers_fe; /* attached frontend */
	struct appctx *appctx;
	struct session *sess;
	struct stream *s;
	struct connection *conn;
	struct conn_stream *cs;

	peer->reconnect = tick_add(now_ms, MS_TO_TICKS(5000));
	peer->statuscode = PEER_SESS_SC_CONNECTCODE;
	s = NULL;

	appctx = appctx_new(&peer_applet, tid_bit);
	if (!appctx)
		goto out_close;

	appctx->st0 = PEER_SESS_ST_CONNECT;
	appctx->ctx.peers.ptr = (void *)peer;

	sess = session_new(p, NULL, &appctx->obj_type);
	if (!sess) {
		ha_alert("out of memory in peer_session_create().\n");
		goto out_free_appctx;
	}

	if ((s = stream_new(sess, &appctx->obj_type)) == NULL) {
		ha_alert("Failed to initialize stream in peer_session_create().\n");
		goto out_free_sess;
	}

	/* The tasks below are normally what is supposed to be done by
	 * fe->accept().
	 */
	s->flags = SF_ASSIGNED|SF_ADDR_SET;

	/* applet is waiting for data */
	si_cant_get(&s->si[0]);
	appctx_wakeup(appctx);

	/* initiate an outgoing connection */
	s->si[1].flags |= SI_FL_NOLINGER;
	si_set_state(&s->si[1], SI_ST_ASS);

	/* automatically prepare the stream interface to connect to the
	 * pre-initialized connection in si->conn.
	 */
	if (unlikely((conn = conn_new()) == NULL))
		goto out_free_strm;

	if (unlikely((cs = cs_new(conn)) == NULL))
		goto out_free_conn;

	conn->target = s->target = peer_session_target(peer, s);
	memcpy(&conn->addr.to, &peer->addr, sizeof(conn->addr.to));

	conn_prepare(conn, peer->proto, peer_xprt(peer));
	conn_install_mux(conn, &mux_pt_ops, cs, s->be, NULL);
	si_attach_cs(&s->si[1], cs);

	s->do_log = NULL;
	s->uniq_id = 0;

	s->res.flags |= CF_READ_DONTWAIT;

	peer->appctx = appctx;
	task_wakeup(s->task, TASK_WOKEN_INIT);
	HA_ATOMIC_ADD(&active_peers, 1);
	return appctx;

	/* Error unrolling */
 out_free_conn:
	conn_free(conn);
 out_free_strm:
	LIST_DEL(&s->list);
	pool_free(pool_head_stream, s);
 out_free_sess:
	session_free(sess);
 out_free_appctx:
	appctx_free(appctx);
 out_close:
	return NULL;
}

/*
 * Task processing function to manage re-connect and peer session
 * tasks wakeup on local update.
 */
static struct task *process_peer_sync(struct task * task, void *context, unsigned short state)
{
	struct peers *peers = context;
	struct peer *ps;
	struct shared_table *st;

	task->expire = TICK_ETERNITY;

	if (!peers->peers_fe) {
		/* this one was never started, kill it */
		signal_unregister_handler(peers->sighandler);
		task_delete(peers->sync_task);
		task_free(peers->sync_task);
		peers->sync_task = NULL;
		return NULL;
	}

	/* Acquire lock for all peers of the section */
	for (ps = peers->remote; ps; ps = ps->next)
		HA_SPIN_LOCK(PEER_LOCK, &ps->lock);

	if (!stopping) {
		/* Normal case (not soft stop)*/

		if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMLOCAL) &&
		     (!nb_oldpids || tick_is_expired(peers->resync_timeout, now_ms)) &&
		     !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
			/* Resync from local peer needed
			   no peer was assigned for the lesson
			   and no old local peer found
			       or resync timeout expire */

			/* flag no more resync from local, to try resync from remotes */
			peers->flags |= PEERS_F_RESYNC_LOCAL;

			/* reschedule a resync */
			peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(5000));
		}

		/* For each session */
		for (ps = peers->remote; ps; ps = ps->next) {
			/* For each remote peers */
			if (!ps->local) {
				if (!ps->appctx) {
					/* no active peer connection */
					if (ps->statuscode == 0 ||
					    ((ps->statuscode == PEER_SESS_SC_CONNECTCODE ||
					      ps->statuscode == PEER_SESS_SC_SUCCESSCODE ||
					      ps->statuscode == PEER_SESS_SC_CONNECTEDCODE) &&
					     tick_is_expired(ps->reconnect, now_ms))) {
						/* connection never tried
						 * or previous peer connection established with success
						 * or previous peer connection failed while connecting
						 * and reconnection timer is expired */

						/* retry a connect */
						ps->appctx = peer_session_create(peers, ps);
					}
					else if (!tick_is_expired(ps->reconnect, now_ms)) {
						/* If previous session failed during connection
						 * but reconnection timer is not expired */

						/* reschedule task for reconnect */
						task->expire = tick_first(task->expire, ps->reconnect);
					}
					/* else do nothing */
				} /* !ps->appctx */
				else if (ps->statuscode == PEER_SESS_SC_SUCCESSCODE) {
					/* current peer connection is active and established */
					if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE) &&
					    !(peers->flags & PEERS_F_RESYNC_ASSIGN) &&
					    !(ps->flags & PEER_F_LEARN_NOTUP2DATE)) {
						/* Resync from a remote is needed
						 * and no peer was assigned for lesson
						 * and current peer may be up2date */

						/* assign peer for the lesson */
						ps->flags |= PEER_F_LEARN_ASSIGN;
						peers->flags |= PEERS_F_RESYNC_ASSIGN;

						/* wake up peer handler to handle a request of resync */
						appctx_wakeup(ps->appctx);
					}
					else {
						/* Awake session if there is data to push */
						for (st = ps->tables; st ; st = st->next) {
							if ((int)(st->last_pushed - st->table->localupdate) < 0) {
								/* wake up the peer handler to push local updates */
								appctx_wakeup(ps->appctx);
								break;
							}
						}
					}
					/* else do nothing */
				} /* SUCCESSCODE */
			} /* !ps->peer->local */
		} /* for */

		/* Resync from remotes expired: consider resync is finished */
		if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE) &&
		    !(peers->flags & PEERS_F_RESYNC_ASSIGN) &&
		    tick_is_expired(peers->resync_timeout, now_ms)) {
			/* Resync from remote peer needed
			 * no peer was assigned for the lesson
			 * and resync timeout expire */

			/* flag no more resync from remote, consider resync is finished */
			peers->flags |= PEERS_F_RESYNC_REMOTE;
		}

		if ((peers->flags & PEERS_RESYNC_STATEMASK) != PEERS_RESYNC_FINISHED) {
			/* Resync not finished*/
			/* reschedule task to resync timeout if not expired, to ended resync if needed */
			if (!tick_is_expired(peers->resync_timeout, now_ms))
				task->expire = tick_first(task->expire, peers->resync_timeout);
		}
	} /* !stopping */
	else {
		/* soft stop case */
		if (state & TASK_WOKEN_SIGNAL) {
			/* We've just received the signal */
			if (!(peers->flags & PEERS_F_DONOTSTOP)) {
				/* add DO NOT STOP flag if not present */
				HA_ATOMIC_ADD(&jobs, 1);
				peers->flags |= PEERS_F_DONOTSTOP;
				ps = peers->local;
				for (st = ps->tables; st ; st = st->next)
					st->table->syncing++;
			}

			/* disconnect all connected peers */
			for (ps = peers->remote; ps; ps = ps->next) {
				/* we're killing a connection, we must apply a random delay before
				 * retrying otherwise the other end will do the same and we can loop
				 * for a while.
				 */
				ps->reconnect = tick_add(now_ms, MS_TO_TICKS(50 + random() % 2000));
				if (ps->appctx) {
					peer_session_forceshutdown(ps->appctx);
					ps->appctx = NULL;
				}
			}
		}

		ps = peers->local;
		if (ps->flags & PEER_F_TEACH_COMPLETE) {
			if (peers->flags & PEERS_F_DONOTSTOP) {
				/* resync of new process was complete, current process can die now */
				HA_ATOMIC_SUB(&jobs, 1);
				peers->flags &= ~PEERS_F_DONOTSTOP;
				for (st = ps->tables; st ; st = st->next)
					st->table->syncing--;
			}
		}
		else if (!ps->appctx) {
			/* If there's no active peer connection */
			if (ps->statuscode == 0 ||
			    ps->statuscode == PEER_SESS_SC_SUCCESSCODE ||
			    ps->statuscode == PEER_SESS_SC_CONNECTEDCODE ||
			    ps->statuscode == PEER_SESS_SC_TRYAGAIN) {
				/* connection never tried
				 * or previous peer connection was successfully established
				 * or previous tcp connect succeeded but init state incomplete
				 * or during previous connect, peer replies a try again statuscode */

				/* connect to the peer */
				peer_session_create(peers, ps);
			}
			else {
				/* Other error cases */
				if (peers->flags & PEERS_F_DONOTSTOP) {
					/* unable to resync new process, current process can die now */
					HA_ATOMIC_SUB(&jobs, 1);
					peers->flags &= ~PEERS_F_DONOTSTOP;
					for (st = ps->tables; st ; st = st->next)
						st->table->syncing--;
				}
			}
		}
		else if (ps->statuscode == PEER_SESS_SC_SUCCESSCODE ) {
			/* current peer connection is active and established
			 * wake up all peer handlers to push remaining local updates */
			for (st = ps->tables; st ; st = st->next) {
				if ((int)(st->last_pushed - st->table->localupdate) < 0) {
					appctx_wakeup(ps->appctx);
					break;
				}
			}
		}
	} /* stopping */

	/* Release lock for all peers of the section */
	for (ps = peers->remote; ps; ps = ps->next)
		HA_SPIN_UNLOCK(PEER_LOCK, &ps->lock);

	/* Wakeup for re-connect */
	return task;
}


/*
 * returns 0 in case of error.
 */
int peers_init_sync(struct peers *peers)
{
	struct peer * curpeer;
	struct listener *listener;

	for (curpeer = peers->remote; curpeer; curpeer = curpeer->next) {
		peers->peers_fe->maxconn += 3;
	}

	list_for_each_entry(listener, &peers->peers_fe->conf.listeners, by_fe)
		listener->maxconn = peers->peers_fe->maxconn;
	peers->sync_task = task_new(MAX_THREADS_MASK);
	if (!peers->sync_task)
		return 0;

	peers->sync_task->process = process_peer_sync;
	peers->sync_task->context = (void *)peers;
	peers->sighandler = signal_register_task(0, peers->sync_task, 0);
	task_wakeup(peers->sync_task, TASK_WOKEN_INIT);
	return 1;
}



/*
 * Function used to register a table for sync on a group of peers
 *
 */
void peers_register_table(struct peers *peers, struct stktable *table)
{
	struct shared_table *st;
	struct peer * curpeer;
	int id = 0;

	for (curpeer = peers->remote; curpeer; curpeer = curpeer->next) {
		st = calloc(1,sizeof(*st));
		st->table = table;
		st->next = curpeer->tables;
		if (curpeer->tables)
			id = curpeer->tables->local_id;
		st->local_id = id + 1;

		curpeer->tables = st;
	}

	table->sync_task = peers->sync_task;
}

