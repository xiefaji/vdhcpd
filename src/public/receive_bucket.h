#ifndef __RECEIVE_BUCKET_H
#define __RECEIVE_BUCKET_H

#include "share/defines.h"
#include "share/array/trashqueue.h"
#include "receive.h"

typedef struct {
    int count;//当前接收包个数
    struct receive receives;
} receive_bucket_t;

PUBLIC_DATA receive_bucket_t *receive_bucket_allocate(const int n_packets, const int per_buffer_size, int flags);
PUBLIC_DATA int receive_bucket_receive(int fd, receive_bucket_t *prbucket);
PUBLIC_DATA void receive_bucket_free(void *p);
PUBLIC_DATA void receive_bucket_recycle(void *p, trash_queue_t *pRecycleTrash);
#endif
