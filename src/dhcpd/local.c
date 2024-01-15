#include "dhcpd.h"
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
PRIVATE receive_bucket_t *receive_bucket = NULL;

PUBLIC int local_main_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

#ifndef VERSION_VNAAS
    vdm->sockfd_main = create_udp_socket(DEFAULT_DHCP_UDP_PORT, 1, 1, 0, NULL);
#else
    vdm->sockfd_main = create_unix_socket(VNAAS_DHCP_IPC_DGRAM_SOCK, 1, 1);
#endif
    if (vdm->sockfd_main < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    vdm->sockfd_raw4 = create_raw_socket(1, 1, NULL);
    if (vdm->sockfd_raw4 < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN Raw 4].", __FUNCTION__, __LINE__);
        exit(0);
    }

    vdm->sockfd_raw6 = create_raw_socket6(1, 1, NULL);
    if (vdm->sockfd_raw6 < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN Raw 6].", __FUNCTION__, __LINE__);
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

PRIVATE int packet_do_dpi(packet_process_t *packet_process);
PRIVATE int packet_parse(packet_process_t *packet_process);
PRIVATE int packet_match_server(packet_process_t *packet_process);
PRIVATE int packet_process4(packet_process_t *packet_process, trash_queue_t *pRecycleTrash);
PRIVATE int packet_process6(packet_process_t *packet_process, trash_queue_t *pRecycleTrash);

PUBLIC int local_main_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    static u32 last_assignment;
    if (CMP_COUNTER(last_assignment, 3)) {
        SET_COUNTER(last_assignment);
        server_stats_main_maintain();
    }

    //接收数据包并处理
    receive_bucket->count = receive_bucket_receive(vdm->sockfd_main, receive_bucket);
    for (int idx = 0; idx < receive_bucket->count; ++idx) {
#ifdef CLIB_DEBUG
        x_log_warn("接收到报文");
#endif
        packet_process_t packet_process;
        BZERO(&packet_process, sizeof(packet_process_t));
        struct mmsghdr *packets = &receive_bucket->receives.packets[idx];
        packet_process.data = packets->msg_hdr.msg_iov->iov_base;
        packet_process.data_len = packets->msg_len;
        packet_process.vdm = vdm;

        packet_do_dpi(&packet_process);
        packet_process.dhcpd_server = dhcpd_server_search_LineID(vdm->cfg_main, packet_process.dpi.lineid);
        if (!packet_process.dhcpd_server){
            x_log_warn("DHCP服务查找失败");
            continue;//DHCP服务查找失败
            }

        //报文基础解析
        if (packet_parse(&packet_process) < 0){
            x_log_warn("报文基础解析失败");
            continue;}

        //DHCP服务参数匹配
        if (packet_match_server(&packet_process) < 0){
             x_log_warn("DHCP服务参数不匹配");
            continue;}

        //报文处理
        switch (packet_process.dpi.process) {
        case DEFAULT_DHCPv4_PROCESS:
            packet_process4(&packet_process, pRecycleTrash);
            x_log_warn("DHCPv4报文处理");
            break;
        case DEFAULT_DHCPv6_PROCESS:
            packet_process6(&packet_process, pRecycleTrash);
            break;
        }
    }
    return 0;
}

PRIVATE int packet_do_dpi(packet_process_t *packet_process)
{
    dhcp_packet_t *request = &packet_process->request;
#ifndef VERSION_VNAAS
    ipcshare_hdr_t *ipcsharehdr = (ipcshare_hdr_t *)packet_process->data;
    packet_process->dpi.process = ipcsharehdr->process;
    packet_process->dpi.driveid = ipcsharehdr->driveid;
    packet_process->dpi.lineid = ipcsharehdr->lineid;
    packet_process->dpi.sessionid = ipcsharehdr->session;
    packet_process->dpi.vlanid[0] = ipcsharehdr->outer_vlanid;
    packet_process->dpi.vlanid[1] = ipcsharehdr->inner_vlanid;
    packet_process->dpi.vlanproto[0] = 0;
    packet_process->dpi.vlanproto[1] = 0;
    packet_process->dpi.l3 = (unsigned char *)&ipcsharehdr->pdata[0];
    packet_process->dpi.l3len = ipcsharehdr->datalen;
    request->ethhdr = &ipcsharehdr->ethhdr;
#else
    uipc_task_t *ipctaskhdr = (uipc_task_t *)packet_process->data;
    dhcp_external_proc_hdr_t *ephdr = (dhcp_external_proc_hdr_t *)ipctaskhdr->byte;

    u32 process = 0;
    u16 vlanproto[2] = {0, 0};
    u16 vlanid[2] = {0, 0};
    u32 offset = 0;

    //原始报文解析[Layer2]
    unsigned int vlan_packet = 0;
    struct ether_header *ethhdr = (struct ether_header *)ephdr->data;
    const unsigned char *packet = (const unsigned char *)ethhdr;
    u16 protocoltype = ntohs(ethhdr->ether_type);
    offset += sizeof(struct ether_header);
    while ((ETH_P_IP!=protocoltype && ETH_P_IPV6!=protocoltype) && offset <= 64/*mbuf0->l3doff*/) {
        //报文解析[Layer2]
        switch (protocoltype) {
        case ETH_P_8021Q:
        case ETH_P_QINQ1:
        case ETH_P_QINQ2:
        case ETH_P_QINQ3:
            if (vlan_packet > 1)
                return -1;
            vlanproto[vlan_packet] = protocoltype;
            vlanid[vlan_packet] = ((packet[offset] << 8) + packet[offset+1]) & 0xFFF;
            protocoltype = (packet[offset+2] << 8) + packet[offset+3];
            offset += 4;
            vlan_packet++;
            break;
        case ETH_P_MPLS_UC:
        case ETH_P_MPLS_MC:{
            unsigned int label = ntohl(*((unsigned int*)&packet[offset]));
            protocoltype = ETH_P_IP, offset += 4;
            while ((label & 0x100) != 0x100 && offset<=128) {
                offset += 4;
                label = ntohl(*((unsigned int*)&packet[offset]));
            }
        } break;
        case ETH_P_ARP:
        case ETH_P_PPP_DISC:
        case ETH_P_PPP_SES:
        default:
            return -2;
            break;
        }
    }
    //设定DHCP类型[V4/V6]
    if (ETH_P_IP == protocoltype) process = DEFAULT_DHCPv4_PROCESS;
    else if (ETH_P_IPV6 == protocoltype) process = DEFAULT_DHCPv6_PROCESS;

    packet_process->dpi.process = process;
    packet_process->dpi.driveid = 0;
    packet_process->dpi.lineid = ephdr->sw_rx_dbid;
    packet_process->dpi.sessionid = 0;
    packet_process->dpi.vlanid[0] = vlanid[0];
    packet_process->dpi.vlanid[1] = vlanid[1];
    packet_process->dpi.vlanproto[0] = vlanproto[0];
    packet_process->dpi.vlanproto[1] = vlanproto[1];
    packet_process->dpi.l3 = (unsigned char *)&ephdr->data[offset];
    packet_process->dpi.l3len = ephdr->data_len - offset;
    request->ethhdr = ethhdr;
#endif
    return 0;
}

//报文基础解析
PRIVATE int packet_parse(packet_process_t *packet_process)
{
    int retcode = 0;
    dhcp_packet_t *request = &packet_process->request;

    unsigned char *l3 = packet_process->dpi.l3;
    const u16 l3len = packet_process->dpi.l3len;
    switch (packet_process->dpi.process) {
    case DEFAULT_DHCPv4_PROCESS: {
        struct iphdr *iphdr = request->iphdr = (struct iphdr *)l3;
        const u16 iphdr_len = iphdr->ihl * 4;
        struct udphdr *udphdr = request->udphdr = (struct udphdr *)(l3 + iphdr_len);
        const u16 l4len = l3len - iphdr_len;

        request->l3len = ntohs(iphdr->tot_len);
        request->l4len = ntohs(udphdr->len);
        request->payload = (unsigned char *)(request->udphdr + 1);
        request->payload_len = request->l3len - iphdr_len - sizeof(struct udphdr);

        if (l3len < request->l3len || l4len < request->l4len || iphdr_len < 20 || ((l4len + iphdr_len) != l3len)) {
            x_log_warn("%s:%d 错误的报文[%u] l3len[%u/%u] l4len[%u/%u] iphdr_len[%u]", __FUNCTION__, __LINE__, DEFAULT_DHCPv4_PROCESS,
                      l3len, request->l3len, l4len, request->l4len, iphdr_len);
            retcode = -1;
        }
    } break;
    case DEFAULT_DHCPv6_PROCESS: {
        struct ip6_hdr *ip6hdr = request->ip6hdr = (struct ip6_hdr *)l3;
        const u16 iphdr_len = sizeof(struct ip6_hdr);
        struct udphdr *udphdr = request->udphdr = (struct udphdr *)(l3 + iphdr_len);
        const u16 l4len = l3len - iphdr_len;

        request->l3len = ntohs(ip6hdr->ip6_plen) + iphdr_len;
        request->l4len = ntohs(udphdr->len);
        request->payload = (unsigned char *)(request->udphdr + 1);
        request->payload_len = request->l3len - iphdr_len - sizeof(struct udphdr);

        if (l3len < request->l3len || l4len < request->l4len || iphdr_len < sizeof(struct ip6_hdr) || ((l4len + iphdr_len) != l3len)) {
            x_log_warn("%s:%d 错误的报文[%u] l3len[%u/%u] l4len[%u/%u] iphdr_len[%u]", __FUNCTION__, __LINE__, DEFAULT_DHCPv6_PROCESS,
                      l3len, request->l3len, l4len, request->l4len, iphdr_len);
            retcode = -1;
        }
    } break;
    default:
        retcode = -1;
        x_log_warn("%s:%d 未识别Processl数据类型[%u][%u].", __FUNCTION__, __LINE__, packet_process->dpi.process, errno);
        break;
    }

    return retcode;
}

//DHCP服务参数匹配
PRIVATE int packet_match_server(packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;

    if (!dhcpd_server->nEnabled)
        return -1;//DHCP服务停用

    if (!ENABLE_DHCP_IPV4(dhcpd_server) && !ENABLE_DHCP_IPV6(dhcpd_server))
        return -1;//IPV4/IPV6模式均停用

#ifndef VERSION_VNAAS
    if (dhcpd_server->iface.driveid != packet_process->dpi.driveid)
        return -1;//监听物理网卡不匹配
#endif

    if (!xEXACTVLAN_Match(dhcpd_server->pEXACTVLAN, packet_process->dpi.vlanid[0], packet_process->dpi.vlanid[1]))
        return -1;//监听VLAN/QINQ不匹配

    return 0;
}

PRIVATE int packet_deepin_parse4(packet_process_t *packet_process, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = packet_process->vdm;
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

    if (vdm->filter_subnet) {
        if (request->v4.msgcode == DHCPV4_MSG_REQUEST && !iface_subnet_match(dhcpd_server, req->ciaddr))
            return -1;

        if (request->v4.msgcode != DHCPV4_MSG_DISCOVER && !iface_subnet_match(dhcpd_server, request->v4.reqaddr))
            return -1;
    }

    if (request->v4.msgcode == DHCPV4_MSG_DISCOVER) { BZERO(&realtime_info->v4, sizeof(realtime_info->v4)); SET_COUNTER(realtime_info->starttick); }
    if (hostname_len) { BCOPY(hostname, realtime_info->v4.hostname, MAXNAMELEN); realtime_info->v4.hostname_len = hostname_len; }
    if (reqopts_len) { BCOPY(reqopts, realtime_info->v4.reqopts, MAXNAMELEN); realtime_info->v4.reqopts_len = reqopts_len; }
    if (vendorname_len) { BCOPY(vendorname, realtime_info->v4.vendorname, MAXNAMELEN); realtime_info->v4.vendorname_len = vendorname_len; }
    if (clientidentifier_len) { BCOPY(clientidentifier, realtime_info->v4.clientidentifier, MAXNAMELEN); realtime_info->v4.clientidentifier_len = clientidentifier_len; }
    if (userclass_len) { BCOPY(userclass, realtime_info->v4.userclass, MAXNAMELEN); realtime_info->v4.userclass_len = userclass_len; }
    realtime_info_oth_update(realtime_info, 1);
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
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcp_packet_t *request = &packet_process->request;
    struct dhcpv6_client_header *req = request->payload;

    if (request->payload_len < offsetof(struct dhcpv6_client_header, options))
        return -1;

    char hostname[MAXNAMELEN+1]={0},reqopts[MAXNAMELEN+1]={0},clientidentifier[MAXNAMELEN+1]={0};
    char vendorname[MAXNAMELEN+1]={0},userclass[MAXNAMELEN+1]={0},duid[MAXNAMELEN+1]={0};
    u32 hostname_len = 0, reqopts_len = 0, vendorname_len = 0, clientidentifier_len = 0, userclass_len = 0, duid_len = 0;
    bool rapid_commit = false, ia_pd = false;
    u8 *start = (u8 *)&req->options[0];
    u8 *end = ((u8 *)request->payload) + request->payload_len;
    u16 otype, olen;
    u8 *odata;
    dhcpv6_for_each_option(start, end, otype, olen, odata) {
        if (otype == DHCPV6_OPT_CLIENTID) {
            if (olen == 14 && odata[0] == 0 && odata[1] == 1)
                BCOPY(&odata[8], &packet_process->macaddr, sizeof(mac_address_t));
            else if (olen == 10 && odata[0] == 0 && odata[1] == 3)
                BCOPY(&odata[4], &packet_process->macaddr, sizeof(mac_address_t));
            duid_len = olen;
            BCOPY(odata, duid, olen);
        }                                   /*else if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1) {//请求类型
                                              request->v4.msgcode = opt->data[0];
                                          }*/
        else if (otype == DHCPV6_OPT_ORO) { //请求OPTIONS内容
            reqopts_len = olen;
            BCOPY(odata, reqopts, olen);
        } else if (otype == DHCPV6_OPT_FQDN) { //终端主机名
            u8 fqdn_buf[MAXNAMELEN + 1] = {0};
            BCOPY(odata, fqdn_buf, olen);
            fqdn_buf[olen++] = 0;
            if (dn_expand(&fqdn_buf[1], &fqdn_buf[olen], &fqdn_buf[1], hostname, sizeof(hostname)) > 0)
                hostname_len = strcspn(hostname, ".");
        } else if (otype == DHCPV6_OPT_VENDOR_CLASS) { //厂商
            vendorname_len = olen;
            BCOPY(odata, vendorname, olen);
        } /*else if (opt->type == DHCPV4_OPT_SERVERID && opt->len == 4) {//服务ID
            ip4_address_t ipaddr;
            BCOPY(opt->data, &ipaddr, sizeof(ip4_address_t));
            if (KEY_TREE_NODES(&dhcpd_server->key_serverid) && !key_rbsearch(&dhcpd_server->key_serverid, ipaddr.address))
                return -1;//存在服务ID列表，但匹配失败
        }*/
        else if (otype == DHCPV6_OPT_IA_NA) {
            struct opt_ia_hdr *ia_hdr = (struct opt_ia_hdr *)(odata - 4);
            request->v6.iaid = ia_hdr->iaid;
            u32 offset = offsetof(struct opt_ia_hdr, u) - 4;
            if (olen > offset) {
                struct opt_ia_address *ia_addr = (struct opt_ia_address *)&odata[offset];
                BCOPY(&ia_addr->addr, &request->v6.reqaddr, sizeof(ip6_address_t));//终端静态IP
                request->v6.leasetime = ntohl(ia_addr->valid);//租约时长
                request->v6.preferred = ntohl(ia_addr->preferred);
            }
        } else if (otype == DHCPV6_OPT_IA_PD) {
            struct opt_ia_hdr *ia_hdr = (struct opt_ia_hdr *)(odata - 4);
            request->v6.iaid = ia_hdr->iaid;
            u32 offset = offsetof(struct opt_ia_hdr, u) - 4;
            if (olen > offset) {
                struct opt_ia_prefix *ia_prefix = (struct opt_ia_prefix *)&odata[offset];

            }
            ia_pd = true;
        } else if (otype == DHCPV6_OPT_USER_CLASS) {
            userclass_len = olen;
            BCOPY(odata, userclass, olen);
        } else if (otype == DHCPV6_OPT_RAPID_COMMIT) {
            rapid_commit = true;
        }
    }

    //存储终端信息
    BCOPY(request->ethhdr->ether_shost, &packet_process->macaddr, sizeof(mac_address_t));
    realtime_info_t *realtime_info = packet_process->realtime_info = realtime_find(packet_process, pRecycleTrash);
    if (!realtime_info)
        return -1;

    request->v6.msgcode = req->msg_type;
    if (request->v6.msgcode == DHCPV6_MSG_SOLICIT) { BZERO(&realtime_info->v6, sizeof(realtime_info->v6)); SET_COUNTER(realtime_info->starttick); }
    if (duid_len) { BCOPY(duid, realtime_info->v6.duid, MAXNAMELEN); realtime_info->v6.duid_len = duid_len; }
    if (hostname_len) { BCOPY(hostname, realtime_info->v6.hostname, MAXNAMELEN); realtime_info->v6.hostname_len = hostname_len; }
    if (reqopts_len) { BCOPY(reqopts, realtime_info->v6.reqopts, MAXNAMELEN); realtime_info->v6.reqopts_len = reqopts_len; }
    if (vendorname_len) { BCOPY(vendorname, realtime_info->v6.vendorname, MAXNAMELEN); realtime_info->v6.vendorname_len = vendorname_len; }
    if (clientidentifier_len) { BCOPY(clientidentifier, realtime_info->v6.clientidentifier, MAXNAMELEN); realtime_info->v6.clientidentifier_len = clientidentifier_len; }
    if (userclass_len) { BCOPY(userclass, realtime_info->v6.userclass, MAXNAMELEN); realtime_info->v6.userclass_len = userclass_len; }
    if (rapid_commit) { realtime_info->v6.rapid_commit = true; }
    if (ia_pd) { realtime_info->v6.ia_pd = true; }
    realtime_info_oth_update(realtime_info, 0);
    packet_save_log6(packet_process, (struct dhcpv6_client_header *)request->payload, request->v6.msgcode, "接收报文[v6服务][C]");
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
        relay6_send_request_packet(packet_process);
    } else if (ENABLE_IPV6_SERVER(dhcpd_server)) {//服务器模式
        server6_process(packet_process);//wuao
    }
    return 0;
}
