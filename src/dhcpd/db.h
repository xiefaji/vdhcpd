#ifndef _VRADIUSD_ZEROTRUST_DB_H
#define _VRADIUSD_ZEROTRUST_DB_H

#include "share/defines.h"
#include "share/types.h"
#include "share/mysql/mydbop.h"
#include "share/list/listdemo.h"
#include "public/rbtree_common.h"

enum db_process_type {
    DPF_NORMAL = (1 << 0),
} ;

typedef struct {
    struct list_head item_event;
    PMYDBOP pHANDLE;
    u32 flags;
    char *sql;
} db_event_t;
ALWAYS_INLINE db_event_t *db_event_init(const u32 flags)
{
    db_event_t *db_event = (db_event_t *)xmalloc(sizeof(db_event_t));
    BZERO(db_event, sizeof(db_event_t));
    db_event->flags = flags;
    return db_event;
}

ALWAYS_INLINE void db_event_release(void *p)
{
    db_event_t *db_event = (db_event_t *)p;
    if (db_event) {
        xfree(db_event->sql);
        xfree(db_event);
    }
}

struct db_process_t {
    struct list_head head_event;
#ifdef USE_SPIN_LOCK
    pthread_spinlock_t lock;
#else
    int mutex;// = 0;
#endif
};
#ifdef USE_SPIN_LOCK
#define db_process_init_lock(p) {pthread_spin_init(&(p)->lock,0);  }
#define db_process_destroy_lock(p) { pthread_spin_destroy(&(p)->lock); }
#define db_process_unlock(p)  { pthread_spin_unlock(&(p)->lock); }
#define db_process_lock(p)     { pthread_spin_lock(&(p)->lock); }
#else
#define db_process_init_lock(p) { (p)->mutex = 0;}
#define db_process_destroy_lock(p) {}
#define db_process_unlock(p)  {__sync_bool_compare_and_swap(&(p)->mutex,1,0);}
#define db_process_lock(p)     { while (!(__sync_bool_compare_and_swap (&(p)->mutex,0, 1) )) {sched_yield();} smp_rmb();}
#endif

ALWAYS_INLINE void db_process_init(struct db_process_t *db_process)
{
    BZERO(db_process, sizeof(struct db_process_t));
    db_process_init_lock(db_process);
    INIT_LIST_HEAD(&db_process->head_event);
}

ALWAYS_INLINE void db_process_destroy(struct db_process_t *db_process)
{
    db_event_t *db_event = NULL;
    list_for_each_entry(db_event, &db_process->head_event, item_event) {
        db_event_release(db_event);
    }
    db_process_destroy_lock(db_process);
}

ALWAYS_INLINE void db_process_push_event(struct db_process_t *db_process, db_event_t *db_event)
{
    assert(db_process && db_event);
    db_process_lock(db_process);
    list_add_tail(&db_event->item_event, &db_process->head_event);//插入尾部，list_add()插入首部
    db_process_unlock(db_process);
}

ALWAYS_INLINE db_event_t *db_process_pop_event(struct db_process_t *db_process)
{
    db_event_t *db_event = NULL;
    struct list_head* pos = NULL, * n = NULL;
    assert(db_process);
    db_process_lock(db_process);
    list_for_each_safe(pos, n, &db_process->head_event) {
        db_event = list_entry(pos, db_event_t, item_event);
        list_del(pos);
        break;
    }
    db_process_unlock(db_process);
    return db_event;
}

#endif
