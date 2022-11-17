#include "dhcpd.h"

PRIVATE receive_bucket_t *receive_bucket = NULL;

PUBLIC int api_main_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    vdm->sockfd_api = create_udp_socket(DEFAULT_API_UDP_PORT, 1, 3, 0, NULL);
    if (vdm->sockfd_api < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    //申请数据包接收BUFFER
    receive_bucket = receive_bucket_allocate(4, MAXBUFFERLEN, 0);
    assert(receive_bucket);
    return 0;
}

PUBLIC int api_main_clean(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    receive_bucket_free(receive_bucket);//资源释放
    return 0;
}

PUBLIC int api_main_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    //接收数据包并处理
    receive_bucket->count = receive_bucket_receive(vdm->sockfd_api, receive_bucket);
    for (int idx = 0; idx < receive_bucket->count; ++idx) {
        struct mmsghdr *packets = &receive_bucket->receives.packets[idx];
        unsigned char *data = packets->msg_hdr.msg_iov->iov_base;
        unsigned int data_len = packets->msg_len;

    }
    return 0;
}
