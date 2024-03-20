#include "api.h"
#include "dhcpd.h"

PRIVATE int process_api_message(int sockfd, const unsigned char *buffer, const size_t retlen, struct sockaddr_in *fromto);

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
             x_log_debug("%s : 数据接收失败:%s", __FUNCTION__, strerror(errno));
         return 0;
     }
     buffer[retlen] = '\0';

    return process_api_message(vdm->sockfd_api, buffer, retlen, &sin);
}

PRIVATE int api_main_response(int sockfd, const unsigned char *buffer, const size_t retlen, struct sockaddr_in *fromto)
{
    return sendto(sockfd, buffer, retlen, 0, (struct sockaddr *)fromto, sizeof(struct sockaddr_in));
}

PRIVATE int process_field_finger(int sockfd, const unsigned char *buffer, const size_t retlen, struct sockaddr_in *fromto);
PRIVATE int process_api_message(int sockfd, const unsigned char *buffer, const size_t retlen, struct sockaddr_in *fromto)
{
    ipcapi_hdr_t *ipcapi_hdr = (ipcapi_hdr_t *)buffer;
    switch (ipcapi_hdr->process) {
    case IPCAPI_PROCESS_FINGER:
        process_field_finger(sockfd, buffer, retlen, fromto);
        break;
    default:
        break;
    }
    return 0;
}

PRIVATE int process_field_finger(int sockfd, const unsigned char *buffer, const size_t retlen, struct sockaddr_in *fromto)
{
    if (retlen < sizeof(ipcapi_hdr_t) + sizeof(ipcapi_hdr_finger_t))
        return -1;

    ipcapi_hdr_t *ipcapi_hdr = (ipcapi_hdr_t *)buffer;
    ipcapi_hdr_finger_t *ipcapi_hdr_finger = (ipcapi_hdr_finger_t *)(buffer + sizeof(ipcapi_hdr_t));

    switch (ipcapi_hdr->action) {
    case IPCAPI_CODE_REQUEST: {
        realtime_info_t *realtime_info = realtime_search_macaddr(ipcapi_hdr_finger->macaddr);
        if (realtime_info) realtime_info_finger_md5(realtime_info, ipcapi_hdr_finger->finger4, sizeof(ipcapi_hdr_finger->finger4));
        ipcapi_hdr->action = IPCAPI_CODE_REPLY;
    } break;
    default:
        break;
    }
    api_main_response(sockfd, buffer, sizeof(ipcapi_hdr_t) + sizeof(ipcapi_hdr_finger_t), fromto);
    return 0;
}
