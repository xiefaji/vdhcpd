#include "dhcpd.h"

PRIVATE receive_bucket_t *receive_bucket = NULL;

PUBLIC int relay4_main_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    vdm->sockfd_relay4 = create_udp_socket(DHCPV4_SERVER_PORT, 0, 1, 0, NULL);
    if (vdm->sockfd_relay4 < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    socket_set_broadcast(vdm->sockfd_relay4);

    //申请数据包接收BUFFER
    receive_bucket = receive_bucket_allocate(1, MAXBUFFERLEN, 0);
    assert(receive_bucket);
    return 0;
}

PUBLIC int relay4_main_clean(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    receive_bucket_free(receive_bucket);//资源释放
    return 0;
}

PRIVATE int packet_deepin_parse(packet_process_t *packet_process);

PUBLIC int relay4_main_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    //接收数据包并处理
    receive_bucket->count = receive_bucket_receive(vdm->sockfd_relay4, receive_bucket);
    for (int idx = 0; idx < receive_bucket->count; ++idx) {
        packet_process_t packet_process;
        BZERO(&packet_process, sizeof(packet_process_t));
        struct mmsghdr *packets = &receive_bucket->receives.packets[idx];
        packet_process.data = packets->msg_hdr.msg_iov->iov_base;
        packet_process.data_len = packets->msg_len;
        packet_process.vdm = vdm;

        if (packet_deepin_parse(&packet_process) < 0)
            continue;

        packet_process.dhcpd_server = dhcpd_server_search_LineID(vdm->cfg_main, packet_process.realtime_info->lineid);
        if (!packet_process.dhcpd_server)
            continue;//DHCP服务查找失败

        //报文响应
        relay4_send_reply_packet(&packet_process);
    }
    return 0;
}

PRIVATE int packet_deepin_parse(packet_process_t *packet_process)
{
    dhcp_packet_t *request = &packet_process->request;
    request->payload = packet_process->data;
    request->payload_len = packet_process->data_len;
    struct dhcpv4_message *rep = request->payload;

    if (request->payload_len < offsetof(struct dhcpv4_message, options) + 4 ||
            rep->op != DHCPV4_BOOTREPLY || rep->hlen != ETH_ALEN)
        return -1;

    BCOPY(rep->chaddr, &packet_process->macaddr, sizeof(mac_address_t));
    //查找终端信息
    realtime_info_t *realtime_info = packet_process->realtime_info = realtime_search(packet_process);
    if (!realtime_info)
        return -1;

    u32 leasetime = 0;
    u8 *start = &rep->options[4];
    u8 *end = ((u8 *)request->payload) + request->payload_len;
    struct dhcpv4_option *opt;
    dhcpv4_for_each_option(start, end, opt) {
        if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1) {//请求类型
            request->v4.msgcode = opt->data[0];
        } else if (opt->type == DHCPV4_OPT_LEASETIME && opt->len == 4) {//租约时长
            BCOPY(opt->data, &leasetime, 4);
            leasetime = ntohl(leasetime);
        }
    }

    realtime_info->v4.leasetime = leasetime;
    realtime_info->v4.ipaddr = rep->yiaddr;
    if (request->v4.msgcode == DHCPV4_MSG_ACK) {
        realtime_info->flags |= RLTINFO_FLAGS_RELAY4;
        __sync_fetch_and_add(&realtime_info->update_db4, 1);
    }
    packet_save_log(packet_process, (struct dhcpv4_message *)request->payload, request->v4.msgcode, "接收报文[v4中继][S]");
    return 0;
}

//TX
PUBLIC int relay4_send_request_packet(packet_process_t *packet_process)
{
    ipcshare_hdr_t *ipcsharehdr = packet_process->ipcsharehdr;
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcp_packet_t *request = &packet_process->request;

    char buffer[MAXBUFFERLEN+1]={0};
    unsigned int offset = 0, length = 0;
    struct iphdr *pIPHeader = (struct iphdr *)&buffer[offset];
    offset += sizeof(struct iphdr);
    struct udphdr *pUDPHeader = (struct udphdr *)&buffer[offset];
    offset += sizeof(struct udphdr);
    struct dhcpv4_message *relay = (struct dhcpv4_message *)&buffer[offset];

    //DHCP报文封装
    BCOPY(request->payload, &buffer[offset], request->payload_len);//拷贝原始报文
    ++relay->hops;
    relay->giaddr = dhcpd_server->dhcprelay.v4.lineip;

    u8 *cookie = NULL;
    struct dhcpv4_option *opt = NULL;
    u8 *start = &relay->options[4];
    u8 *end = ((u8 *)&buffer[offset]) + request->payload_len;
    dhcpv4_for_each_option(start, end, opt) {
        if (opt->type == DHCPV4_OPT_END)
            cookie = (u8 *)opt;
    }
    if (!cookie) cookie = end - 1;
    //中继标识
    char agent_buffer[MINBUFFERLEN+1]={0};
    struct agent_infomation_t *agent_information = (struct agent_infomation_t *)agent_buffer;
    agent_information->opt_vlan.type = 1;
    agent_information->opt_vlan.len = sizeof(dhcpv4_option_vlan_t);
    agent_information->vlan.u.vlanid = htons(ipcsharehdr->outer_vlanid);
    agent_information->vlan.u.qinqid = htons(ipcsharehdr->inner_vlanid);
    agent_information->opt_subnet.type = 5;
    agent_information->opt_subnet.len = sizeof(ip4_address_t);
    agent_information->subnet = dhcpd_server->dhcprelay.v4.subnet;
    dhcpv4_put(relay, &cookie, DHCPV4_OPT_AGENT_INFORMATION, sizeof(struct agent_infomation_t), agent_information);//中继标识
    dhcpv4_put(relay, &cookie, DHCPV4_OPT_END, 0, NULL);
    length += PACKET_SIZE(relay, cookie);

    //封装UDP Header
    length += sizeof(struct udphdr);
    pUDPHeader->len = htons(length);
    pUDPHeader->dest = dhcpd_server->dhcprelay.v4.serverport;
    pUDPHeader->source = htons(DHCPV4_SERVER_PORT);
    pUDPHeader->check = 0;

    //封装IP Header
    length += sizeof(struct iphdr);
    pIPHeader->version = 0x4;
    pIPHeader->ihl = 0x5;
    pIPHeader->tos = 254;
    pIPHeader->tot_len = htons(length);
    pIPHeader->id = getpid();
    pIPHeader->frag_off = htons(0x4000);
    pIPHeader->ttl = 64;
    pIPHeader->protocol = IPPROTO_UDP;
    pIPHeader->check = 0;
    pIPHeader->saddr = dhcpd_server->dhcprelay.v4.lineip.address;
    pIPHeader->daddr = dhcpd_server->dhcprelay.v4.serverip.address;

    //计算校验和
    WinDivertHelperCalcChecksums(buffer, length, 0);

    struct sockaddr_in sto;
    sto.sin_family = AF_INET;
    sto.sin_addr.s_addr = dhcpd_server->dhcprelay.v4.serverip.address;
    sto.sin_port = dhcpd_server->dhcprelay.v4.serverport;
    packet_save_log(packet_process, (struct dhcpv4_message *)request->payload, request->v4.msgcode, "发送报文[v4中继][S]");
    return sendto(packet_process->vdm->sockfd_raw, buffer, length, 0, (struct sockaddr *)&sto, sizeof(struct sockaddr));
}

//RX
PUBLIC int relay4_send_reply_packet(packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcp_packet_t *request = &packet_process->request;
    struct dhcpv4_message *rep = request->payload;

    char buffer[MAXBUFFERLEN+1]={0};
    unsigned int offset = 0, length = 0;
    ipcshare_hdr_t *ipcsharehdr = (ipcshare_hdr_t *)buffer;
    struct iphdr *pIPHeader = (struct iphdr *)&ipcsharehdr->pdata[offset];
    offset += sizeof(struct iphdr);
    struct udphdr *pUDPHeader = (struct udphdr *)&ipcsharehdr->pdata[offset];
    offset += sizeof(struct udphdr);
    u8 *payload = (u8 *)&ipcsharehdr->pdata[offset];

    //DHCP报文封装
    BCOPY(request->payload, payload, request->payload_len);
    length += request->payload_len;

    //封装UDP Header
    length += sizeof(struct udphdr);
    pUDPHeader->len = htons(length);
    pUDPHeader->dest = htons(DHCPV4_CLIENT_PORT);
    pUDPHeader->source = htons(DHCPV4_SERVER_PORT);
    pUDPHeader->check = 0;

    //封装IP Header
    length += sizeof(struct iphdr);
    pIPHeader->version = 0x4;
    pIPHeader->ihl = 0x5;
    pIPHeader->tos = 254;
    pIPHeader->tot_len = htons(length);
    pIPHeader->id = getpid();
    pIPHeader->frag_off = htons(0x4000);
    pIPHeader->ttl = 64;
    pIPHeader->protocol = IPPROTO_UDP;
    pIPHeader->check = 0;
    pIPHeader->saddr = dhcpd_server->dhcpv4.gateway.address ? dhcpd_server->dhcpv4.gateway.address:dhcpd_server->iface.ipaddr.address;
    pIPHeader->daddr = rep->yiaddr.address;

    WinDivertHelperCalcChecksums(pIPHeader, length, 0);

    //封装IPC Header
    ipcsharehdr->process = DEFAULT_DHCPv4_PROCESS;
    ipcsharehdr->code = CODE_REPLY;//1
    ipcsharehdr->driveid = dhcpd_server->iface.driveid;
    ipcsharehdr->lineid = dhcpd_server->nLineID;
    ipcsharehdr->outer_vlanid = realtime_info->ovlanid;
    ipcsharehdr->inner_vlanid = realtime_info->ivlanid;
    ipcsharehdr->session = realtime_info->sessionid;
    ipcsharehdr->datalen = length;
    if (DHCPV4_FLAGS_BROADCAST(rep)) memset(ipcsharehdr->ethhdr.ether_dhost, 0xFF, ETH_ALEN);
    else BCOPY(realtime_info->key.u.macaddr.addr, ipcsharehdr->ethhdr.ether_dhost, ETH_ALEN);
    BCOPY(dhcpd_server->iface.macaddr.addr, ipcsharehdr->ethhdr.ether_shost, ETH_ALEN);
    ipcsharehdr->ethhdr.ether_type = htons(ETH_P_IP);

    struct sockaddr_in sin={0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(DEFAULT_CORE_UDP_PORT);
    sin.sin_addr.s_addr = 0x100007f;
    packet_save_log(packet_process, (struct dhcpv4_message *)request->payload, request->v4.msgcode, "发送报文[v4中继][C]");
    return sendto(packet_process->vdm->sockfd_main, buffer, sizeof(ipcshare_hdr_t) + length, 0, (struct sockaddr*)&sin, sizeof(sin));
}
