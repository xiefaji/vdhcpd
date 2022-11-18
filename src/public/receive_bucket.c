#include "public/receive_bucket.h"

PUBLIC receive_bucket_t *receive_bucket_allocate(const int n_packets, const int per_buffer_size, int flags)
{
    receive_bucket_t *prbucket = (receive_bucket_t *)xmalloc(sizeof(receive_bucket_t));
    BZERO(prbucket, sizeof(receive_bucket_t));

    prbucket->receives.n_packets = n_packets;
    prbucket->receives.addr_len = sizeof(struct sockaddr_in);
    prbucket->receives.buffer_len = per_buffer_size;
    prbucket->receives.control_len = 0;
    receive_allocate_buffer(&prbucket->receives, flags);

    return prbucket;
}

PUBLIC int receive_bucket_receive(int fd, receive_bucket_t *prbucket)
{
    prbucket->count = 0;
    receive_prepare(&prbucket->receives, -1, -1);
    return receive(fd, &prbucket->receives, prbucket->receives.n_packets, 0);
}

PUBLIC void receive_bucket_free(void *p)
{
    receive_bucket_t *prbucket = (receive_bucket_t *)p;
    if (prbucket) {
        receive_free_buffer(&prbucket->receives);
        xfree(prbucket);
    }
}

PUBLIC void receive_bucket_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    receive_bucket_t *prbucket = (receive_bucket_t *)p;
    if (prbucket) {
        if (prbucket->receives.packets) trash_queue_enqueue(pRecycleTrash, prbucket->receives.packets);
        prbucket->receives.packets = NULL;
        trash_queue_enqueue(pRecycleTrash, prbucket);
    }
}
