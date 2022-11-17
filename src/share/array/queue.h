#ifndef _QUEUE_H
#define _QUEUE_H

#include <sched.h>
#include "share/rbtree/compiler.h"
#include "share/defines.h"

struct queue_node_t {
    struct queue_node_t *next;
    void *data;
};

typedef struct {
    unsigned long long count;
    struct queue_node_t *head;
    struct queue_node_t *tail;
    int mutex;//0
}queue_t;

#define queue_init_lock(p) { (p)->mutex = 0;}
#define queue_destroy_lock(p) {}
#define queue_lock(p)     { while (!(__sync_bool_compare_and_swap (&(p)->mutex,0, 1) )) {sched_yield();} smp_rmb();}
#define queue_unlock(p)  {__sync_bool_compare_and_swap(&(p)->mutex,1,0);}

PUBLIC_DATA void queue_init(queue_t *mqueue);
PUBLIC_DATA void queue_clear(queue_t *mqueue,void *freec(void *));
PUBLIC_DATA void queue_destory(queue_t *mqueue,void *freec(void *));
PUBLIC_DATA void queue_enqueue(queue_t *mqueue,void *data);
PUBLIC_DATA void *queue_dequeue(queue_t *mqueue);

#endif // _QUEUE_H
