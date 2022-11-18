#include "dhcpd.h"

//filed
#define XSWEB_FIELD_DHCP_RELEASE_LEASE		1086   //IP释放
#define XSWEB_FIELD_DHCP_BIND_LEASE 1087  //(IP/MAC 静态绑定)
#define XSWEB_FIELD_DHCP_MAC_ACL 1088
//act
#define XSWEB_ACT_RELEASE_DHCPV4_LEASE  14   //DHCPV4 释放
#define XSWEB_ACT_RELEASE_DHCPV6_LEASE 16    //DHCPV6释放
#define XSWEB_ACT_BIND_DHCPV4_SPECIAL_LEASE 13   //DHCPV4 转静态
#define XSWEB_ACT_BIND_DHCPV4_NORMAL_LEASE 15   //DHCPV4 IP/MAC 开关
#define XSWEB_ACT_BIND_DHCPV6_SPECIAL_LEASE 19   //DHCPV6 转静态
#define XSWEB_ACT_BIND_DHCPV6_NORMAL_LEASE 20   //DHCPV6 IP/MAC 开关
#define XSWEB_ACT_DELETE_BIND_DHCPV4_LEASE 25// 删除DHCPV4静态绑定lease
#define XSWEB_ACT_DELETE_BIND_DHCPV6_LEASE 26// 删除DHCPV6静态绑定lease
#define XSWEB_ACT_UPDATE_MAC_ACL           30

PRIVATE int process_field_macacl(int act, cJSON *pROOT, cJSON *pRetRoot);

PUBLIC int webaction_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    vdm->sockfd_webaction = create_udp_socket(DEFAULT_WEBACTION_UDP_PORT, 1, 3, 0, NULL);
    if (vdm->sockfd_webaction < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    return 0;
}

PRIVATE int process_webaction_message(int sockfd, const unsigned char *buffer, struct sockaddr_in *fromto);

PUBLIC int webaction_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;
    unsigned char buffer[MAXBUFFERLEN+1] = {0};

     struct sockaddr_in sin;
     socklen_t slen=sizeof(sin);
     int retlen = recvfrom(vdm->sockfd_webaction, buffer, MINBUFFERLEN, 0, (struct sockaddr *)&sin, &slen);
     if (retlen <= 0) {
         int err = errno;
         if (err != EAGAIN && err != EINTR)
             x_log_warn("%s : 数据接收失败:%s", __FUNCTION__, strerror(errno));
         return 0;
     }
     buffer[retlen] = '\0';

     return process_webaction_message(vdm->sockfd_webaction, buffer, &sin);
}

PRIVATE int process_webaction_message(int sockfd, const unsigned char *buffer, struct sockaddr_in *fromto)
{
    cJSON *pROOT = cJSON_Parse((const char *)buffer);
    if (!pROOT)
        return -1;

    cJSON *pField,*pAction;
    cJSON *pRetRoot = cJSON_CreateObject();
    pField = cJSON_GetObjectItem(pROOT, "XSWEB_FIELD");
    if (!pField)
        goto _return;

    pAction = cJSON_GetObjectItem(pROOT, "XSWEB_ACT");
    if (!pAction)
        goto _return;

    switch (pField->valueuint) {
    case XSWEB_FIELD_DHCP_RELEASE_LEASE:
        break;
    case XSWEB_FIELD_DHCP_BIND_LEASE:
        break;
    case XSWEB_FIELD_DHCP_MAC_ACL:
        process_field_macacl(pAction->valueuint, pROOT, pRetRoot);
        break;
    default:
        break;
    }

_return:
    cJSON_Delete(pROOT);
    char *reply_message = cJSON_PrintUnformatted(pRetRoot);
    cJSON_Delete(pRetRoot);
    if (BCMP(reply_message, "{\n}", strlen("{\n}")))
        sendto(sockfd, reply_message, strlen(reply_message), 0, (struct sockaddr *)fromto, sizeof(struct sockaddr));
    xfree(reply_message);
    return 0;
}

PRIVATE int process_field_macacl(int act, cJSON *pROOT, cJSON *pRetRoot)
{
    int ret = -1;
    switch (act) {
    case XSWEB_ACT_UPDATE_MAC_ACL:
        vdhcpd_set_reload();
        cJSON_AddStringToObject(pRetRoot, "comment", "Success");
        break;
    default:
        cJSON_AddStringToObject(pRetRoot, "comment", "Fail");
        break;
    }
    return ret;
}
