/*
 * shctx.c - shared context management functions for SSL
 *
 * Copyright (C) 2011-2012 EXCELIANCE
 *
 * Author: Emeric Brun - emeric@exceliance.fr
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <sys/mman.h>
#include <arpa/inet.h>
#include <ebmbtree.h>

#include <proto/shctx.h>
#include <proto/openssl-compat.h>

#include <types/global.h>
#include <types/shctx.h>

#if !defined (USE_PRIVATE_CACHE)
int use_shared_mem = 0;
#endif

/* List Macros */

#define shblock_unset(s)		(s)->n->p = (s)->p; \
					(s)->p->n = (s)->n;

static inline void shblock_set_free(struct shared_context *shctx,
				    struct shared_block *s)
{
	shblock_unset(s);
	(s)->n = &shctx->free;
	(s)->p = shctx->free.p;
	shctx->free.p->n = s;
	shctx->free.p = s;
}

static inline void shblock_set_active(struct shared_context *shctx,
				      struct shared_block *s)
{
	shblock_unset(s)
	(s)->n = &shctx->active;
	(s)->p = shctx->active.p;
	shctx->active.p->n = s;
	shctx->active.p = s;
}

/* Tree Macros */

#define shsess_tree_delete(s)	ebmb_delete(&(s)->key);

#define shsess_tree_insert(shctx, s)	(struct shared_session *)ebmb_insert(&shctx->active.data.session.key.node.branches, \
								     &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define shsess_tree_lookup(shctx, k)	(struct shared_session *)ebmb_lookup(&shctx->active.data.session.key.node.branches, \
								     (k), SSL_MAX_SSL_SESSION_ID_LENGTH);

/* shared session functions */

/* Free session blocks, returns number of freed blocks */
static int shsess_free(struct shared_context *shctx, struct shared_session *shsess)
{
	struct shared_block *block;
	int ret = 1;

	if (((struct shared_block *)shsess)->data_len <= sizeof(shsess->data)) {
		shblock_set_free(shctx, (struct shared_block *)shsess);
		return ret;
	}
	block = ((struct shared_block *)shsess)->n;
	shblock_set_free(shctx, (struct shared_block *)shsess);
	while (1) {
		struct shared_block *next;

		if (block->data_len <= sizeof(block->data)) {
			/* last block */
			shblock_set_free(shctx, block);
			ret++;
			break;
		}
		next = block->n;
		shblock_set_free(shctx, block);
		ret++;
		block = next;
	}
	return ret;
}

/* This function frees enough blocks to store a new session of data_len.
 * Returns a ptr on a free block if it succeeds, or NULL if there are not
 * enough blocks to store that session.
 */
static struct shared_session *shsess_get_next(struct shared_context *shctx, int data_len)
{
	int head = 0;
	struct shared_block *b;

	b = shctx->free.n;
	while (b != &shctx->free) {
		if (!head) {
			data_len -= sizeof(b->data.session.data);
			head = 1;
		}
		else
			data_len -= sizeof(b->data.data);
		if (data_len <= 0)
			return &shctx->free.n->data.session;
		b = b->n;
	}
	b = shctx->active.n;
	while (b != &shctx->active) {
		int freed;

		shsess_tree_delete(&b->data.session);
		freed = shsess_free(shctx, &b->data.session);
		if (!head)
			data_len -= sizeof(b->data.session.data) + (freed-1)*sizeof(b->data.data);
		else
			data_len -= freed*sizeof(b->data.data);
		if (data_len <= 0)
			return &shctx->free.n->data.session;
		b = shctx->active.n;
	}
	return NULL;
}

/* store a session into the cache
 * s_id : session id padded with zero to SSL_MAX_SSL_SESSION_ID_LENGTH
 * data: asn1 encoded session
 * data_len: asn1 encoded session length
 * Returns 1 id session was stored (else 0)
 */
static int shsess_store(struct shared_context *shctx, unsigned char *s_id, unsigned char *data, int data_len)
{
	struct shared_session *shsess, *oldshsess;

	shsess = shsess_get_next(shctx, data_len);
	if (!shsess) {
		/* Could not retrieve enough free blocks to store that session */
		return 0;
	}

	/* prepare key */
	memcpy(shsess->key_data, s_id, SSL_MAX_SSL_SESSION_ID_LENGTH);

	/* it returns the already existing node
           or current node if none, never returns null */
	oldshsess = shsess_tree_insert(shctx, shsess);
	if (oldshsess != shsess) {
		/* free all blocks used by old node */
		shsess_free(shctx, oldshsess);
		shsess = oldshsess;
	}

	((struct shared_block *)shsess)->data_len = data_len;
	if (data_len <= sizeof(shsess->data)) {
		/* Store on a single block */
		memcpy(shsess->data, data, data_len);
		shblock_set_active(shctx, (struct shared_block *)shsess);
	}
	else {
		unsigned char *p;
		/* Store on multiple blocks */
		int cur_len;

		memcpy(shsess->data, data, sizeof(shsess->data));
		p = data + sizeof(shsess->data);
		cur_len = data_len - sizeof(shsess->data);
		shblock_set_active(shctx, (struct shared_block *)shsess);
		while (1) {
			/* Store next data on free block.
			 * shsess_get_next guarantees that there are enough
			 * free blocks in queue.
			 */
			struct shared_block *block;

			block = shctx->free.n;
			if (cur_len <= sizeof(block->data)) {
				/* This is the last block */
				block->data_len = cur_len;
				memcpy(block->data.data, p, cur_len);
				shblock_set_active(shctx, block);
				break;
			}
			/* Intermediate block */
			block->data_len = cur_len;
			memcpy(block->data.data, p, sizeof(block->data));
			p += sizeof(block->data.data);
			cur_len -= sizeof(block->data.data);
			shblock_set_active(shctx, block);
		}
	}

	return 1;
}


/* SSL context callbacks */

/* SSL callback used on new session creation */
int shctx_new_cb(SSL *ssl, SSL_SESSION *sess)
{
	unsigned char encsess[SHSESS_MAX_DATA_LEN];           /* encoded session  */
	unsigned char encid[SSL_MAX_SSL_SESSION_ID_LENGTH];   /* encoded id */
	unsigned char *p;
	int data_len;
	unsigned int sid_length, sid_ctx_length;
	const unsigned char *sid_data;
	const unsigned char *sid_ctx_data;

	/* Session id is already stored in to key and session id is known
	 * so we dont store it to keep size.
	 */

	sid_data = SSL_SESSION_get_id(sess, &sid_length);
	sid_ctx_data = SSL_SESSION_get0_id_context(sess, &sid_ctx_length);
	SSL_SESSION_set1_id(sess, sid_data, 0);
	SSL_SESSION_set1_id_context(sess, sid_ctx_data, 0);

	/* check if buffer is large enough for the ASN1 encoded session */
	data_len = i2d_SSL_SESSION(sess, NULL);
	if (data_len > SHSESS_MAX_DATA_LEN)
		goto err;

	p = encsess;

	/* process ASN1 session encoding before the lock */
	i2d_SSL_SESSION(sess, &p);

	memcpy(encid, sid_data, sid_length);
	if (sid_length < SSL_MAX_SSL_SESSION_ID_LENGTH)
		memset(encid + sid_length, 0, SSL_MAX_SSL_SESSION_ID_LENGTH-sid_length);

	shared_context_lock(ssl_shctx);

	/* store to cache */
	shsess_store(ssl_shctx, encid, encsess, data_len);

	shared_context_unlock(ssl_shctx);

err:
	/* reset original length values */
	SSL_SESSION_set1_id(sess, sid_data, sid_length);
	SSL_SESSION_set1_id_context(sess, sid_ctx_data, sid_ctx_length);

	return 0; /* do not increment session reference count */
}

/* SSL callback used on lookup an existing session cause none found in internal cache */
SSL_SESSION *shctx_get_cb(SSL *ssl, __OPENSSL_110_CONST__ unsigned char *key, int key_len, int *do_copy)
{
	struct shared_session *shsess;
	unsigned char data[SHSESS_MAX_DATA_LEN], *p;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	int data_len;
	SSL_SESSION *sess;

	global.shctx_lookups++;

	/* allow the session to be freed automatically by openssl */
	*do_copy = 0;

	/* tree key is zeros padded sessionid */
	if (key_len < SSL_MAX_SSL_SESSION_ID_LENGTH) {
		memcpy(tmpkey, key, key_len);
		memset(tmpkey + key_len, 0, SSL_MAX_SSL_SESSION_ID_LENGTH - key_len);
		key = tmpkey;
	}

	/* lock cache */
	shared_context_lock(ssl_shctx);

	/* lookup for session */
	shsess = shsess_tree_lookup(ssl_shctx, key);
	if (!shsess) {
		/* no session found: unlock cache and exit */
		shared_context_unlock(ssl_shctx);
		global.shctx_misses++;
		return NULL;
	}

	data_len = ((struct shared_block *)shsess)->data_len;
	if (data_len <= sizeof(shsess->data)) {
		/* Session stored on single block */
		memcpy(data, shsess->data, data_len);
		shblock_set_active(ssl_shctx, (struct shared_block *)shsess);
	}
	else {
		/* Session stored on multiple blocks */
		struct shared_block *block;

		memcpy(data, shsess->data, sizeof(shsess->data));
		p = data + sizeof(shsess->data);
		block = ((struct shared_block *)shsess)->n;
		shblock_set_active(ssl_shctx, (struct shared_block *)shsess);
		while (1) {
			/* Retrieve data from next block */
			struct shared_block *next;

			if (block->data_len <= sizeof(block->data.data)) {
				/* This is the last block */
				memcpy(p, block->data.data, block->data_len);
				p += block->data_len;
				shblock_set_active(ssl_shctx, block);
				break;
			}
			/* Intermediate block */
			memcpy(p, block->data.data, sizeof(block->data.data));
			p += sizeof(block->data.data);
			next = block->n;
			shblock_set_active(ssl_shctx, block);
			block = next;
		}
	}

	shared_context_unlock(ssl_shctx);

	/* decode ASN1 session */
	p = data;
	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, data_len);
	/* Reset session id and session id contenxt */
	if (sess) {
		SSL_SESSION_set1_id(sess, key, key_len);
		SSL_SESSION_set1_id_context(sess, (const unsigned char *)SHCTX_APPNAME, strlen(SHCTX_APPNAME));
	}

	return sess;
}

/* SSL callback used to signal session is no more used in internal cache */
void shctx_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
	struct shared_session *shsess;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned int sid_length;
	const unsigned char *sid_data;
	(void)ctx;

	sid_data = SSL_SESSION_get_id(sess, &sid_length);
	/* tree key is zeros padded sessionid */
	if (sid_length < SSL_MAX_SSL_SESSION_ID_LENGTH) {
		memcpy(tmpkey, sid_data, sid_length);
		memset(tmpkey+sid_length, 0, SSL_MAX_SSL_SESSION_ID_LENGTH - sid_length);
		sid_data = tmpkey;
	}

	shared_context_lock(ssl_shctx);

	/* lookup for session */
	shsess = shsess_tree_lookup(ssl_shctx, sid_data);
	if (shsess) {
		/* free session */
		shsess_tree_delete(shsess);
		shsess_free(ssl_shctx, shsess);
	}

	/* unlock cache */
	shared_context_unlock(ssl_shctx);
}

/* Allocate shared memory context.
 * <size> is maximum cached sessions.
 * If <size> is set to less or equal to 0, ssl cache is disabled.
 * Returns: -1 on alloc failure, <size> if it performs context alloc,
 * and 0 if cache is already allocated.
 */
int shared_context_init(struct shared_context **orig_shctx, int size, int shared)
{
	int i;
	struct shared_context *shctx;
	int ret;
#ifndef USE_PRIVATE_CACHE
#ifdef USE_PTHREAD_PSHARED
	pthread_mutexattr_t attr;
#endif
#endif
	struct shared_block *prev,*cur;
	int maptype = MAP_PRIVATE;

	if (orig_shctx && *orig_shctx)
		return 0;

	if (size<=0)
		return 0;

	/* Increate size by one to reserve one node for lookup */
	size++;
#ifndef USE_PRIVATE_CACHE
	if (shared)
		maptype = MAP_SHARED;
#endif

	shctx = (struct shared_context *)mmap(NULL, sizeof(struct shared_context)+(size*sizeof(struct shared_block)),
	                                      PROT_READ | PROT_WRITE, maptype | MAP_ANON, -1, 0);
	if (!shctx || shctx == MAP_FAILED) {
		shctx = NULL;
		ret = SHCTX_E_ALLOC_CACHE;
		goto err;
	}

#ifndef USE_PRIVATE_CACHE
	if (maptype == MAP_SHARED) {
#ifdef USE_PTHREAD_PSHARED
		if (pthread_mutexattr_init(&attr)) {
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			ret = SHCTX_E_INIT_LOCK;
			goto err;
		}

		if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
			pthread_mutexattr_destroy(&attr);
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			ret = SHCTX_E_INIT_LOCK;
			goto err;
		}

		if (pthread_mutex_init(&shctx->mutex, &attr)) {
			pthread_mutexattr_destroy(&attr);
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			ret = SHCTX_E_INIT_LOCK;
			goto err;
		}
#else
		shctx->waiters = 0;
#endif
		use_shared_mem = 1;
	}
#endif

	memset(&shctx->active.data.session.key, 0, sizeof(struct ebmb_node));
	memset(&shctx->free.data.session.key, 0, sizeof(struct ebmb_node));

	/* No duplicate authorized in tree: */
	shctx->active.data.session.key.node.branches = EB_ROOT_UNIQUE;

	cur = &shctx->active;
	cur->n = cur->p = cur;

	cur = &shctx->free;
	for (i = 0 ; i < size ; i++) {
		prev = cur;
		cur++;
		prev->n = cur;
		cur->p = prev;
	}
	cur->n = &shctx->free;
	shctx->free.p = cur;

	ret = size;

err:
	*orig_shctx = shctx;
	return ret;
}


/* Set session cache mode to server and disable openssl internal cache.
 * Set shared cache callbacks on an ssl context.
 * Shared context MUST be firstly initialized */
void shared_context_set_cache(SSL_CTX *ctx)
{
	SSL_CTX_set_session_id_context(ctx, (const unsigned char *)SHCTX_APPNAME, strlen(SHCTX_APPNAME));

	if (!ssl_shctx) {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
		return;
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER |
	                                    SSL_SESS_CACHE_NO_INTERNAL |
	                                    SSL_SESS_CACHE_NO_AUTO_CLEAR);

	/* Set callbacks */
	SSL_CTX_sess_set_new_cb(ctx, shctx_new_cb);
	SSL_CTX_sess_set_get_cb(ctx, shctx_get_cb);
	SSL_CTX_sess_set_remove_cb(ctx, shctx_remove_cb);
}
