#include <sys/un.h>
#include "dhcpd.h"
#include "share/xlog.h"

// filed
#define XSWEB_FIELD_DHCP_RELEASE_LEASE 1086 // IP释放
#define XSWEB_FIELD_DHCP_REBIND_LEASE 1087    //(IP/MAC 静态绑定)
#define XSWEB_FIELD_DHCP_MAC_ACL 1088       // MAC控制
#define XSWEB_FIELD_DHCP_RELOAD 1640        //重载

// act
#define XSWEB_ACT_RELEASE_DHCPV4_LEASE 14      // DHCPV4 释放
#define XSWEB_ACT_RELEASE_DHCPV6_LEASE 16      // DHCPV6 释放
#define XSWEB_ACT_BIND_DHCPV4_SPECIAL_LEASE 13 // DHCPV4 转静态
#define XSWEB_ACT_BIND_DHCPV4_NORMAL_LEASE 15  // DHCPV4 IP/MAC 开关
#define XSWEB_ACT_BIND_DHCPV6_SPECIAL_LEASE 19 // DHCPV6 转静态
#define XSWEB_ACT_BIND_DHCPV6_NORMAL_LEASE 31  // DHCPV6 IP/MAC 开关
#define XSWEB_ACT_DELETE_BIND_DHCPV4_LEASE 20  // 删除DHCPV4静态绑定lease
#define XSWEB_ACT_DELETE_BIND_DHCPV6_LEASE 26  // 删除DHCPV6静态绑定lease
#define XSWEB_ACT_UPDATE_MAC_ACL 30
#define XSWEB_ACT_DHCPV4_RELOAD 21 // DHCPV4 IP/MAC 开关

PRIVATE int process_field_release_lease(int act, cJSON *pROOT, cJSON *pRetRoot);
PRIVATE int process_field_rebind_staticlease(int act, cJSON *pROOT, cJSON *pRetRoot);
PRIVATE int process_field_macacl(int act, cJSON *pROOT, cJSON *pRetRoot);
PRIVATE int process_field_reload(int act, cJSON *pROOT, cJSON *pRetRoot);
PUBLIC int webaction_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

#ifndef VERSION_VNAAS
    vdm->sockfd_webaction = create_udp_socket(DEFAULT_WEBACTION_UDP_PORT, 1, 3, 0, NULL);
#else
    vdm->sockfd_webaction = create_unix_socket(VNAAS_DHCP_API_DGRAM_SOCK, 1, 3);
#endif
    if (vdm->sockfd_webaction < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    return 0;
}

#ifndef VERSION_VNAAS
PRIVATE int process_webaction_message(int sockfd, const unsigned char *buffer, struct sockaddr_in *fromto, socklen_t slen);
#else
PRIVATE int process_webaction_message(int sockfd, const unsigned char *buffer, struct sockaddr_un *fromto, socklen_t slen);
#endif

PUBLIC int webaction_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;
    unsigned char buffer[MAXBUFFERLEN + 1] = {0};

#ifndef VERSION_VNAAS
    struct sockaddr_in sin;
#else
    struct sockaddr_un sin;
#endif
    socklen_t slen = sizeof(sin);
    int retlen = recvfrom(vdm->sockfd_webaction, buffer, MAXBUFFERLEN, 0, (struct sockaddr *)&sin, &slen);
    if (retlen <= 0) {
        int err = errno;
        if (err != EAGAIN && err != EINTR)
            x_log_warn("%s : 数据接收失败:%s", __FUNCTION__, strerror(errno));
        return 0;
    }
    buffer[retlen] = '\0';

    return process_webaction_message(vdm->sockfd_webaction, buffer, &sin, slen);
}

#ifndef VERSION_VNAAS
PRIVATE int process_webaction_message(int sockfd, const unsigned char *buffer, struct sockaddr_in *fromto, socklen_t slen)
#else
PRIVATE int process_webaction_message(int sockfd, const unsigned char *buffer, struct sockaddr_un *fromto, socklen_t slen)
#endif
{
    cJSON *pROOT = cJSON_Parse((const char *)buffer);
    if (!pROOT)
        return 0;

    cJSON *pField, *pAction;
    cJSON *pRetRoot = cJSON_CreateObject();
    pField = cJSON_GetObjectItem(pROOT, "XSWEB_FIELD");
    if (!pField)
        goto _return;

    pAction = cJSON_GetObjectItem(pROOT, "XSWEB_ACT");
    if (!pAction)
        goto _return;

    switch (pField->valueuint) {
    case XSWEB_FIELD_DHCP_RELEASE_LEASE:
        process_field_release_lease(pAction->valueuint, pROOT, pRetRoot);
        break;
    case XSWEB_FIELD_DHCP_REBIND_LEASE:
        process_field_rebind_staticlease(pAction->valueuint, pROOT, pRetRoot);
        break;
    case XSWEB_FIELD_DHCP_RELOAD:
        process_field_reload(pAction->valueuint, pROOT, pRetRoot);

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
        sendto(sockfd, reply_message, strlen(reply_message), 0, (struct sockaddr *)fromto, slen);
    xfree(reply_message);
    return 0;
}
PRIVATE int process_field_rebind_staticlease(int act, cJSON *pROOT, cJSON *pRetRoot)
{
    int ret = -1;
    switch (act) {
    case XSWEB_ACT_DELETE_BIND_DHCPV4_LEASE:
    case XSWEB_ACT_DELETE_BIND_DHCPV6_LEASE: {
        cJSON *pLEASES = cJSON_GetObjectItem(pROOT, "dhcp");
        for (int idx = 0; idx < cJSON_GetArraySize(pLEASES); ++idx) {
            cJSON *pITEM = cJSON_GetArrayItem(pLEASES, idx);
            if (!pITEM) continue;

   
            mac_address_t macaddr;
            BZERO(&macaddr, sizeof(mac_address_t));
            cJSON *nLineID = cJSON_GetObjectItem(pITEM, "nLineID");
            cJSON *pnID = cJSON_GetObjectItem(pITEM, "nID");
 
            cJSON *nstack = cJSON_GetObjectItem(pITEM, "nstack");

            cJSON *pMACADDR = cJSON_GetObjectItem(pITEM, "mac");
            if (pMACADDR && pMACADDR->valuestring) macaddress_parse(&macaddr, pMACADDR->valuestring);

            cJSON *pIP = cJSON_GetObjectItem(pITEM, "IP");
            cJSON *pGATEWAYIP = cJSON_GetObjectItem(pITEM, "GATEWAYIP");


            if(XSWEB_ACT_DELETE_BIND_DHCPV4_LEASE){
                dhcpd_lease_main_rebind(nLineID->valueint, pnID->valueint,nstack->valueint);
                release_lease_by_mac(macaddr,4);
            }else if(XSWEB_ACT_DELETE_BIND_DHCPV6_LEASE){
                dhcpd_lease_main_rebind( nLineID->valueint,pnID->valueint,nstack->valueint);
                release_lease_by_mac(macaddr,6);
            }
        }
        cJSON_AddStringToObject(pRetRoot, "comment", "Success");
    } break;
    default:
        cJSON_AddStringToObject(pRetRoot, "comment", "Fail");
        break;
    }
    return ret;
}

PRIVATE int process_field_release_lease(int act, cJSON *pROOT, cJSON *pRetRoot)
{
    int ret = -1;
    switch (act) {
    case XSWEB_ACT_RELEASE_DHCPV4_LEASE:
    case XSWEB_ACT_RELEASE_DHCPV6_LEASE: {
        cJSON *pLEASES = cJSON_GetObjectItem(pROOT, "dhcp");
        for (int idx = 0; idx < cJSON_GetArraySize(pLEASES); ++idx) {
            cJSON *pITEM = cJSON_GetArrayItem(pLEASES, idx);
            if (!pITEM) continue;

            u32 serverid = 0;
            mac_address_t macaddr;
            BZERO(&macaddr, sizeof(mac_address_t));
            cJSON *pSERVICE = cJSON_GetObjectItem(pITEM, "lineid");
            if (pSERVICE) serverid = pSERVICE->valueuint;

            cJSON *pMACADDR = cJSON_GetObjectItem(pITEM, "mac");
            if (pMACADDR && pMACADDR->valuestring) macaddress_parse(&macaddr, pMACADDR->valuestring);

            dhcpd_server_stats_t *server_stats = server_stats_find(serverid);
            realtime_info_t *realtime_info = realtime_search_macaddr(macaddr);
            if (server_stats) server_stats_release_lease(server_stats, macaddr, (XSWEB_ACT_RELEASE_DHCPV4_LEASE == act) ? 1 : 0);
            if (realtime_info) realtime_info_release_lease(realtime_info, (XSWEB_ACT_RELEASE_DHCPV4_LEASE == act) ? 1 : 0);
        }
        cJSON_AddStringToObject(pRetRoot, "comment", "Success");
    } break;
    default:
        cJSON_AddStringToObject(pRetRoot, "comment", "Fail");
        break;
    }
    return ret;
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
PRIVATE int process_field_reload(int act, cJSON *pROOT, cJSON *pRetRoot)
{
    int ret = -1;
    switch (act) {
    case XSWEB_ACT_DHCPV4_RELOAD:
        vdhcpd_set_reload();
        cJSON_AddStringToObject(pRetRoot, "comment", "Success");
        break;
    default:
        cJSON_AddStringToObject(pRetRoot, "comment", "Fail");
        break;
    }
    return ret;
}
