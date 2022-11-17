#include <string.h>
#include <assert.h>
#include "share/defines.h"
#include "trashqueue.h"

/*1. 初始化链队列*/
// 其  初始化的 操作就是初始化队列的队头和队尾的两个标志位，
// 所以就有删除或是插入的时候，会判断有没有 队列为空的时候。
PUBLIC void init_trash_queue(trash_queue_t *hq)
{
    BZERO((void *)hq,sizeof(trash_queue_t));
    //    queue_eg->head = NULL; //队头标志位
    //    queue_eg->tail = NULL; //队尾标志位
    //    queue_eg->nums = 0;
    //    queue_eg->nodes = 0;
}

PUBLIC void destroy_trash_queue(trash_queue_t *hq)
{
    struct trashnode_t *p = hq->head;
    while (p != NULL) {
        hq->head = hq->head->next;
        xFREE(p);
        p = hq->head;
    }
    hq->tail = NULL;
    BZERO(hq,sizeof(trash_queue_t));
}

PUBLIC void trash_queue_enqueue2(void *ptr,void *hq)
{
    trash_queue_t *hqueue = (trash_queue_t *)hq;
    trash_queue_enqueue(hqueue,ptr);
}
/*2.向链队的队尾插入一个元素x*/
PUBLIC int trash_queue_enqueue(trash_queue_t *hq, void *x)
{
    if (hq->nodes < hq->nums) {
        if (hq->idle->data)
            return -1;
        hq->tail = hq->idle;
        hq->idle->data=x;
        hq->idle = hq->idle->next;
        hq->nodes++;
    } else {
        struct trashnode_t *new_p;
        new_p = (struct trashnode_t *)xMALLOC(sizeof(struct trashnode_t));
        assert(new_p);
        if (new_p == NULL )
            return -1;

        new_p->data = x;
        new_p->next = NULL;
        if (hq->head == NULL) {
            hq->head = new_p;
            hq->tail = new_p;
        } else {
            //hq->tail->data = x;
            hq->tail->next = new_p;
            hq->tail = new_p;
        }
        hq->nums++;
        hq->nodes++;
        hq->idle = NULL;
    }
    return 0;
}

PUBLIC void clear_trash_queue3(trash_queue_t *hq,void (*freec)(void *pdata))
{
    if (0==hq->nodes)
        return;
    struct trashnode_t * p ;
    struct trashnode_t *next=hq->head;
    while (next != NULL) {
        p = next;
        next = next->next;
        if (p->data) {
            freec(p->data);
            p->data = NULL;
        } else {
            p->next = NULL;
            break;
        }
    }

    while (NULL != next) {
        p = next;
        next = next->next;
        if (p->data) {
            freec(p->data);
            p->data = NULL;
        }
        --hq->nums;
        xFREE(p);
    }

    hq->tail = hq->idle = hq->head;
    hq->nodes=0;
    return;
}

PUBLIC void clear_trash_queue2(trash_queue_t *hq,void (*freec)(void *pdata))
{
    if (0==hq->nodes)
        return;
    struct trashnode_t * p ;
    struct trashnode_t *next=hq->head;
    while (next != NULL)
    {
        p = next;
        next = next->next;
        if (p->data) {
            freec(p->data);
            p->data = NULL;
        } else {
            break;
        }
    }

    hq->tail=hq->idle=hq->head;
    hq->nodes=0;
}

PUBLIC void clear_trash_queue(trash_queue_t *hq,void (*freec)(void *pdata))
{
    struct trashnode_t *p = hq->head;
    while (p != NULL)
    {
        hq->head = hq->head->next;
        if (p->data) {
            freec(p->data);
            p->data = NULL;
        }
        xFREE(p);
        p = hq->head;
    }
    BZERO(hq,sizeof(trash_queue_t));
}
