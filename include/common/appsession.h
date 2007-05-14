#ifndef _COMMON_APPSESS_H
#define _COMMON_APPSESS_H

#define TBLSIZ 10
#define TBLCHKINT 5000 /* The time between two calls of appsession_refresh in ms */

#include <sys/time.h>

#include <common/chtbl.h>
#include <common/config.h>
#include <common/hashpjw.h>
#include <common/list.h>
#include <common/memory.h>

#include <types/task.h>

typedef struct appsessions {
	char *sessid;
	char *serverid;
	struct timeval expire;		/* next expiration time for this application session */
	unsigned long int request_count;
} appsess;

extern struct pool_head *pool2_appsess;

struct app_pool {
	struct pool_head *sessid;
	struct pool_head *serverid;
};

extern struct app_pool apools;
extern int have_appsession;


/* Callback for hash_lookup */
int match_str(const void *key1, const void *key2);

/* Callback for destroy */
void destroy(void *data);

#if defined(DEBUG_HASH)
static void print_table(const CHTbl *htbl);
#endif

void appsession_refresh(struct task *t, struct timeval *next);
int appsession_task_init(void);
int appsession_init(void);
void appsession_cleanup(void);

#endif /* _COMMON_APPSESS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
