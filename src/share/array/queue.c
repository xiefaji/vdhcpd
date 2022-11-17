#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "share/xlog.h"
#include "queue.h"

PUBLIC void queue_init(queue_t *mqueue)
{
    BZERO(mqueue,sizeof(queue_t));
    queue_init_lock(mqueue);
}

PUBLIC void queue_clear(queue_t *mqueue,void *freec(void *))
{
    while (mqueue->head)
    {
        struct queue_node_t *node = (struct queue_node_t *)queue_dequeue(mqueue);
        freec(node->data);
        xFREE(node);
    }
}

PUBLIC void queue_destory(queue_t *mqueue,void *freec(void *))
{
    queue_clear(mqueue,freec);
    queue_destroy_lock(mqueue);
}

PUBLIC void queue_enqueue(queue_t *mqueue,void *data)
{
    struct queue_node_t *node = (struct queue_node_t *)xMALLOC(sizeof(struct queue_node_t));
    assert(node);
    BZERO(node,sizeof(struct queue_node_t));
    node->data = data;
    node->next = NULL;

    queue_lock(mqueue);
    ++mqueue->count;
    if (!mqueue->head) {
        mqueue->head = node;//加入队首
        mqueue->tail = node;
    } else if (mqueue->tail) {
        mqueue->tail->next = node;//加入队尾
        mqueue->tail = node;
    } else {
        x_log_warn("%s : enqueue maybe error.",__FUNCTION__);
    }
    queue_unlock(mqueue);
}

PUBLIC void *queue_dequeue(queue_t *mqueue)
{
    if (!mqueue->head) return NULL;

    struct queue_node_t *node=NULL;
    queue_lock(mqueue);
    --mqueue->count;
    node = mqueue->head;
    mqueue->head = node->next;
    node->next = NULL;
    queue_unlock(mqueue);
    return node;
}
