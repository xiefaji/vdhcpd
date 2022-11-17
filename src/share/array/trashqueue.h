#ifndef _TRASHQUEUE_H
#define _TRASHQUEUE_H

#include <stdlib.h>
#include "share/defines.h"

struct trashnode_t {
    void *data;
    struct trashnode_t *next;
};            // 节点的结构

typedef struct {
    struct trashnode_t *head;
    struct trashnode_t *tail;
    struct trashnode_t *idle;
    unsigned long nums,nodes;
} trash_queue_t;          // 队列的结构

PUBLIC_DATA void init_trash_queue(trash_queue_t *hq);
PUBLIC_DATA void destroy_trash_queue(trash_queue_t *hq);

/*向队列的队尾插入一个元素x*/
PUBLIC_DATA int trash_queue_enqueue(trash_queue_t *hq,void *x);
PUBLIC_DATA void trash_queue_enqueue2(void *ptr,void *hq);

/* 清理列表节点 */
PUBLIC_DATA void clear_trash_queue(trash_queue_t *hq,void (*freec)(void *pdata));
PUBLIC_DATA void clear_trash_queue2(trash_queue_t *hq,void (*freec)(void *pdata));
PUBLIC_DATA void clear_trash_queue3(trash_queue_t *hq,void (*freec)(void *pdata));

#define SIMPLE_Queue    trash_queue_t
#define SIMPLE_InitQueue    init_trash_queue
#define SIMPLE_EnQueue  trash_queue_enqueue
#define SIMPLE_DestroyQueue   clear_trash_queue

#define TRASHQUEUENUM 2

#endif // _TRASHQUEUE_H

