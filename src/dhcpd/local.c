#include "dhcpd.h"

PRIVATE receive_bucket_t *receive_bucket = NULL;

PUBLIC int local_main_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    vdm->sockfd_main = create_udp_socket(DEFAULT_DHCP_UDP_PORT, 1, 1, 0, NULL);
    if (vdm->sockfd_main < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    vdm->sockfd_raw = create_raw_socket(1, 1, NULL);
    if (vdm->sockfd_raw < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN Raw].", __FUNCTION__, __LINE__);
        exit(0);
    }


    //申请数据包接收BUFFER
    receive_bucket = receive_bucket_allocate(1, MAXBUFFERLEN, 0);
    assert(receive_bucket);
    return 0;
}

PUBLIC int local_main_clean(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    receive_bucket_free(receive_bucket);//资源释放
    return 0;
}

PRIVATE int packet_parse(packet_process_t *packet_process);
PRIVATE int packet_match_server(packet_process_t *packet_process);
PRIVATE int packet_process4(packet_process_t *packet_process, trash_queue_t *pRecycleTrash);
PRIVATE int packet_process6(packet_process_t *packet_process, trash_queue_t *pRecycleTrash);

PUBLIC int local_main_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    PRIVATE u32 last_assignment;
    if (CMP_COUNTER(last_assignment, 3)) {
        SET_COUNTER(last_assignment);
        server_stats_main_maintain();
    }

    //接收数据包并处理
    receive_bucket->count = receive_bucket_receive(vdm->sockfd_main, receive_bucket);
    for (int idx = 0; idx < receive_bucket->count; ++idx) {
        packet_process_t packet_process;
        BZERO(&packet_process, sizeof(packet_process_t));
        struct mmsghdr *packets = &receive_bucket->receives.packets[idx];
        const ipcshare_hdr_t *ipcsharehdr = packet_process.ipcsharehdr = packets->msg_hdr.msg_iov->iov_base;
        packet_process.data_len = packets->msg_len;
        packet_process.vdm = vdm;

        packet_process.dhcpd_server = dhcpd_server_search_LineID(vdm->cfg_main, packet_process.ipcsharehdr->lineid);
        if (!packet_process.dhcpd_server)
            continue;//DHCP服务查找失败

        //报文基础解析
        if (packet_parse(&packet_process) < 0)
            continue;

        //DHCP服务参数匹配
        if (packet_match_server(&packet_process) < 0)
            continue;

        //报文处理
        switch (ipcsharehdr->process) {
        case DEFAULT_DHCPv4_PROCESS:
            packet_process4(&packet_process, pRecycleTrash);
            break;
        case DEFAULT_DHCPv6_PROCESS:
            packet_process6(&packet_process, pRecycleTrash);
            break;
        }
    }
    return 0;
}

//报文基础解析
PRIVATE int packet_parse(packet_process_t *packet_process)
{
    int retcode = 0;
    ipcshare_hdr_t *ipcsharehdr = packet_process->ipcsharehdr;
    dhcp_packet_t *request = &packet_process->request;
    request->ethhdr = &ipcsharehdr->ethhdr;

    switch (ipcsharehdr->process) {
    case DEFAULT_DHCPv4_PROCESS: {
        const u16 l3len = ipcsharehdr->datalen;
        struct iphdr *iphdr = request->iphdr = (struct iphdr *)ipcsharehdr->pdata;
        const u16 iphdr_len = iphdr->ihl * 4;
        struct udphdr *udphdr = request->udphdr = (struct udphdr *)(ipcsharehdr->pdata + iphdr_len);
        const u16 l4len = l3len - iphdr_len;

        request->l3len = ntohs(iphdr->tot_len);
        request->l4len = ntohs(udphdr->len);
        request->payload = (unsigned char *)(request->udphdr + 1);
        request->payload_len = l3len - iphdr_len - sizeof(struct udphdr);

        if (l3len != request->l3len || l4len != request->l4len || iphdr_len < 20 || ((l4len + iphdr_len) != l3len)) {
            x_log_warn("%s:%d 错误的报文[%u] l3len[%u/%u] l4len[%u/%u] iphdr_len[%u]", __FUNCTION__, __LINE__, DEFAULT_DHCPv4_PROCESS,
                      l3len, request->l3len, l4len, request->l4len, iphdr_len);
            retcode = -1;
        }
    } break;
    case DEFAULT_DHCPv6_PROCESS: {
        const u16 l3len = ipcsharehdr->datalen;
        struct ip6_hdr *ip6hdr = request->ip6hdr = (struct ip6_hdr *)ipcsharehdr->pdata;
        const u16 iphdr_len = sizeof(struct ip6_hdr);
        struct udphdr *udphdr = request->udphdr = (struct udphdr *)(ipcsharehdr->pdata + iphdr_len);
        const u16 l4len = l3len - iphdr_len;

        request->l3len = ntohs(ip6hdr->ip6_plen) + iphdr_len;
        request->l4len = ntohs(udphdr->len);
        request->payload = (unsigned char *)(request->udphdr + 1);
        request->payload_len = l3len - iphdr_len - sizeof(struct udphdr);

        if (l3len != request->l3len || l4len != request->l4len || iphdr_len < sizeof(struct ip6_hdr) || ((l4len + iphdr_len) != l3len)) {
            x_log_warn("%s:%d 错误的报文[%u] l3len[%u/%u] l4len[%u/%u] iphdr_len[%u]", __FUNCTION__, __LINE__, DEFAULT_DHCPv6_PROCESS,
                      l3len, request->l3len, l4len, request->l4len, iphdr_len);
            retcode = -1;
        }
    } break;
    default:
        retcode = -1;
        x_log_warn("%s:%d 未识别Processl数据类型[%u][%u].", __FUNCTION__, __LINE__, ipcsharehdr->process, errno);
        break;
    }
    return retcode;
}

//DHCP服务参数匹配
PRIVATE int packet_match_server(packet_process_t *packet_process)
{
    ipcshare_hdr_t *ipcsharehdr = packet_process->ipcsharehdr;
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;

    if (!dhcpd_server->nEnabled)
        return -1;//DHCP服务停用

    if (!ENABLE_DHCP_IPV4(dhcpd_server) && !ENABLE_DHCP_IPV6(dhcpd_server))
        return -1;//IPV4/IPV6模式均停用

    if (dhcpd_server->iface.driveid != ipcsharehdr->driveid)
        return -1;//监听物理网卡不匹配

    if (!BITMASK_ISSET(dhcpd_server->pVLAN, ipcsharehdr->outer_vlanid))
        return - 1;//监听外VLAN不匹配

    if (!BITMASK_ISSET(dhcpd_server->pQINQ, ipcsharehdr->inner_vlanid))
        return - 1;//监听内VLAN不匹配

    return 0;
}

PRIVATE int packet_deepin_parse4(packet_process_t *packet_process, trash_queue_t *pRecycleTrash)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcp_packet_t *request = &packet_process->request;
    struct dhcpv4_message *req = request->payload;

    if (request->payload_len < offsetof(struct dhcpv4_message, options) + 4 ||
            req->op != DHCPV4_BOOTREQUEST || req->hlen != ETH_ALEN)
        return -1;

    BCOPY(req->chaddr, &packet_process->macaddr, sizeof(mac_address_t));
    //存储终端信息
    realtime_info_t *realtime_info = packet_process->realtime_info = realtime_find(packet_process, pRecycleTrash);
    if (!realtime_info)
        return -1;

    char hostname[MAXNAMELEN+1]={0},reqopts[MAXNAMELEN+1]={0},clientidentifier[MAXNAMELEN+1]={0};
    char vendorname[MAXNAMELEN+1]={0},userclass[MAXNAMELEN+1]={0};
    u32 hostname_len = 0, reqopts_len = 0, vendorname_len = 0, clientidentifier_len = 0, userclass_len = 0;

    u8 *start = &req->options[4];
    u8 *end = ((u8 *)request->payload) + request->payload_len;
    struct dhcpv4_option *opt;
    dhcpv4_for_each_option(start, end, opt) {
        if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1) {//请求类型
            request->v4.msgcode = opt->data[0];
        } else if (opt->type == DHCPV4_OPT_REQOPTS && opt->len > 0) {//请求OPTIONS内容
            reqopts_len = opt->len;
            BCOPY(opt->data, reqopts, opt->len);
        } else if (opt->type == DHCPV4_OPT_HOSTNAME && opt->len > 0) {//终端主机名
            hostname_len = opt->len;
            BCOPY(opt->data, hostname, opt->len);
        } else if (opt->type == DHCPV4_OPT_VENDOR_CLASS_IDENTIFIER && opt->len > 0) {//厂商
            vendorname_len = opt->len;
            BCOPY(opt->data, vendorname, opt->len);
        } else if (opt->type == DHCPV4_OPT_CLIENT_IDENTIFIER && opt->len > 0) {
            clientidentifier_len = opt->len;
            BCOPY(opt->data, clientidentifier, opt->len);
        } else if (opt->type == DHCPV4_OPT_IPADDRESS && opt->len == 4) {//终端静态IP
            BCOPY(opt->data, &request->v4.reqaddr, 4);
        } else if (opt->type == DHCPV4_OPT_SERVERID && opt->len == 4) {//服务ID
            ip4_address_t ipaddr;
            BCOPY(opt->data, &ipaddr, sizeof(ip4_address_t));
            if (KEY_TREE_NODES(&dhcpd_server->key_serverid) && !key_rbsearch(&dhcpd_server->key_serverid, ipaddr.address))
                return -1;//存在服务ID列表，但匹配失败
        } else if (opt->type == DHCPV4_OPT_LEASETIME && opt->len == 4) {//租约时长
            BCOPY(opt->data, &request->v4.leasetime, 4);
        } else if (opt->type == DHCPV4_OPT_MAXMESSAGE_SIZE && opt->len == 2) {
            realtime_info->v4.max_message_size_len = 2;
            BCOPY(opt->data, &realtime_info->v4.max_message_size, 2);
        } else if (opt->type == DHCPV4_OPT_USER_CLASS && opt->len > 0) {
            userclass_len = opt->len;
            BCOPY(opt->data, userclass, opt->len);
        }
    }

    if (request->v4.msgcode == DHCPV4_MSG_DISCOVER) BZERO(&realtime_info->v4, sizeof(realtime_info->v4));
    if (hostname_len) { BCOPY(hostname, realtime_info->v4.hostname, MAXNAMELEN); realtime_info->v4.hostname_len = hostname_len; }
    if (reqopts_len) { BCOPY(reqopts, realtime_info->v4.reqopts, MAXNAMELEN); realtime_info->v4.reqopts_len = reqopts_len; }
    if (vendorname_len) { BCOPY(vendorname, realtime_info->v4.vendorname, MAXNAMELEN); realtime_info->v4.vendorname_len = vendorname_len; }
    if (clientidentifier_len) { BCOPY(clientidentifier, realtime_info->v4.clientidentifier, MAXNAMELEN); realtime_info->v4.clientidentifier_len = clientidentifier_len; }
    if (userclass_len) { BCOPY(userclass, realtime_info->v4.userclass, MAXNAMELEN); realtime_info->v4.userclass_len = userclass_len; }
    packet_save_log(packet_process, (struct dhcpv4_message *)request->payload, request->v4.msgcode, "接收报文[v4服务][C]");
    return 0;
}

PRIVATE int packet_process4(packet_process_t *packet_process, trash_queue_t *pRecycleTrash)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;

    if (!ENABLE_DHCP_IPV4(dhcpd_server))
        return -1;

    //报文深度解析
    if (packet_deepin_parse4(packet_process, pRecycleTrash))
        return -1;

    //黑/白名单匹配
    if (dhcpd_server_match_macaddr(dhcpd_server, packet_process->macaddr))
        return -1;

    //报文分业务处理
    if (ENABLE_IPV4_RELAY(dhcpd_server)) {//中继模式
        relay4_send_request_packet(packet_process);
    } else if (ENABLE_IPV4_SERVER(dhcpd_server)) {//服务器模式
        server4_process(packet_process);
    }
    return 0;
}

PRIVATE int packet_deepin_parse6(packet_process_t *packet_process, trash_queue_t *pRecycleTrash)
{
    dhcp_packet_t *request = &packet_process->request;

    //存储终端信息
    realtime_info_t *realtime_info = packet_process->realtime_info = realtime_find(packet_process, pRecycleTrash);
    if (!realtime_info)
        return -1;

    packet_save_log(packet_process, (struct dhcpv4_message *)request->payload, request->v4.msgcode, "接收报文[v6服务][C]");
    return 0;
}

PRIVATE int packet_process6(packet_process_t *packet_process, trash_queue_t *pRecycleTrash)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;

    if (!ENABLE_DHCP_IPV6(dhcpd_server))
        return -1;

    //报文深度解析
    if (packet_deepin_parse6(packet_process, pRecycleTrash))
        return -1;

    //黑/白名单匹配
    if (dhcpd_server_match_macaddr(dhcpd_server, packet_process->macaddr))
        return -1;

    //报文分业务处理
    if (ENABLE_IPV6_RELAY(dhcpd_server)) {//中继模式

    } else if (ENABLE_IPV6_SERVER(dhcpd_server)) {//服务器模式

    }
    return 0;
}
