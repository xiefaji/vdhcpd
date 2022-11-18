#include "api.h"
#include "dhcpd.h"

PRIVATE int process_api_message(int sockfd, const unsigned char *buffer, struct sockaddr_in *fromto);

PUBLIC int api_main_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    vdm->sockfd_api = create_udp_socket(DEFAULT_API_UDP_PORT, 1, 3, 0, NULL);
    if (vdm->sockfd_api < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    return 0;
}

PUBLIC int api_main_clean(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    return 0;
}

PUBLIC int api_main_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;
    unsigned char buffer[MINBUFFERLEN+1] = {0};

     struct sockaddr_in sin;
     socklen_t slen=sizeof(sin);
     int retlen = recvfrom(vdm->sockfd_api, buffer, MINBUFFERLEN, 0, (struct sockaddr *)&sin, &slen);
     if (retlen <= 0) {
         int err = errno;
         if (err != EAGAIN && err != EINTR)
             x_log_warn("%s : 数据接收失败:%s", __FUNCTION__, strerror(errno));
         return 0;
     }
     buffer[retlen] = '\0';

    return process_api_message(vdm->sockfd_api, buffer, &sin);
}

PRIVATE int process_api_message(int sockfd, const unsigned char *buffer, struct sockaddr_in *fromto)
{
    return 0;
}
