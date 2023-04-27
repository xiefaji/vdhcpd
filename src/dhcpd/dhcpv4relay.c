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
        SET_COUNTER(realtime_info->updatetick);
        realtime_info->flags |= RLTINFO_FLAGS_RELAY4;
        __sync_fetch_and_add(&realtime_info->update_db4, 1);
    }
    request->relay_payload = request->payload;
    request->relay_payload_len = request->payload_len;
    packet_save_log(packet_process, (struct dhcpv4_message *)request->payload, request->v4.msgcode, "接收报文[v4中继][S]");
    return 0;
}

//TX
PUBLIC int relay4_send_request_packet(packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcp_packet_t *request = &packet_process->request;

    unsigned char buffer[MAXBUFFERLEN+1]={0};
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
    agent_information->opt_circuitid.type = 1;
    agent_information->opt_circuitid.len = sizeof(dhcpv4_option_vlan_t);
    agent_information->circuitid.u.vlanid = htons(realtime_info->ovlanid);
    agent_information->circuitid.u.qinqid = htons(realtime_info->ivlanid);
    agent_information->opt_remoteid.type = 2;
    agent_information->opt_remoteid.len = sizeof(mac_address_t);
    BCOPY(&dhcpd_server->iface.macaddr, &agent_information->remoteid, sizeof(mac_address_t));
    agent_information->opt_linkselection.type = 5;
    agent_information->opt_linkselection.len = sizeof(ip4_address_t);
    agent_information->linkselection = dhcpd_server->dhcprelay.v4.subnet;
    dhcpv4_put(relay, &cookie, DHCPV4_OPT_AGENT_INFORMATION, sizeof(struct agent_infomation_t), agent_information);//中继标识
    dhcpv4_put(relay, &cookie, DHCPV4_OPT_END, 0, NULL);
    length += PACKET4_SIZE(relay, cookie);

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
    WinDivertHelperCalcChecksums(buffer, length, 0);//计算校验和

    struct sockaddr_in sto;
    sto.sin_family = AF_INET;
    sto.sin_addr.s_addr = dhcpd_server->dhcprelay.v4.serverip.address;
    sto.sin_port = dhcpd_server->dhcprelay.v4.serverport;
    packet_save_log(packet_process, (struct dhcpv4_message *)request->payload, request->v4.msgcode, "发送报文[v4中继][S]");
    return sendto(packet_process->vdm->sockfd_raw4, buffer, length, 0, (struct sockaddr *)&sto, sizeof(struct sockaddr));
}

//RX
PUBLIC int relay4_send_reply_packet(packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcp_packet_t *request = &packet_process->request;
    struct dhcpv4_message *rep = request->relay_payload;

    unsigned char buffer[MAXBUFFERLEN+1]={0};
    unsigned int offset = 0, length = 0;
#ifndef VERSION_VNAAS
    ipcshare_hdr_t *ipcsharehdr = (ipcshare_hdr_t *)buffer;
    struct iphdr *pIPHeader = (struct iphdr *)&ipcsharehdr->pdata[offset];
    offset += sizeof(struct iphdr);
    struct udphdr *pUDPHeader = (struct udphdr *)&ipcsharehdr->pdata[offset];
    offset += sizeof(struct udphdr);
    u8 *payload = (u8 *)&ipcsharehdr->pdata[offset];
#else
    uipc_task_t *ipctaskhdr = (uipc_task_t *)buffer;
    offset += sizeof(uipc_task_t);
    dhcp_external_proc_hdr_t *ephdr = (dhcp_external_proc_hdr_t *)&buffer[offset];
    offset += sizeof(dhcp_external_proc_hdr_t);
    struct ether_header *ethhdr = (struct ether_header *)&buffer[offset];
    offset += sizeof(struct ether_header);
    ethernet_vlan_header_next_tv_t *pOVLANHDR = NULL, *pIVLANHDR = NULL;
    if (realtime_info->ovlanid) {
        pOVLANHDR = (ethernet_vlan_header_next_tv_t *)&buffer[offset];
        offset += sizeof(ethernet_vlan_header_next_tv_t);
        if (realtime_info->ivlanid) {
            pIVLANHDR = (ethernet_vlan_header_next_tv_t *)&buffer[offset];
            offset += sizeof(ethernet_vlan_header_next_tv_t);
        }
    }
    struct iphdr *pIPHeader = (struct iphdr *)&buffer[offset];
    offset += sizeof(struct iphdr);
    struct udphdr *pUDPHeader = (struct udphdr *)&buffer[offset];
    offset += sizeof(struct udphdr);
    u8 *payload = (u8 *)&buffer[offset];
#endif

    //DHCP报文封装
    BCOPY(request->relay_payload, payload, request->relay_payload_len);
    length += request->relay_payload_len;

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
    pIPHeader->daddr = DHCPV4_FLAGS_BROADCAST(rep) ? INADDR_BROADCAST:rep->yiaddr.address;
    WinDivertHelperCalcChecksums(pIPHeader, length, 0);//计算校验和

#ifndef VERSION_VNAAS
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
    length += sizeof(ipcshare_hdr_t);
#else
    //封装Ether Header
    u16 l3_offset = 0;
    if (DHCPV4_FLAGS_BROADCAST(rep)) memset(ethhdr->ether_dhost, 0xFF, ETH_ALEN);
    else BCOPY(realtime_info->key.u.macaddr.addr, ethhdr->ether_dhost, ETH_ALEN);
    BCOPY(dhcpd_server->iface.macaddr.addr, ethhdr->ether_shost, ETH_ALEN);
    ethhdr->ether_type = htons(ETH_P_IP);
    length += sizeof(struct ether_header);
    l3_offset += sizeof(struct ether_header);
    if (pOVLANHDR) {
        ethhdr->ether_type = htons(realtime_info->vlanproto[0]);
        pOVLANHDR->priority_cfi_and_id = htons(realtime_info->ovlanid);
        pOVLANHDR->next_type = htons(ETH_P_IP);
        length += sizeof(ethernet_vlan_header_next_tv_t);
        l3_offset += sizeof(ethernet_vlan_header_next_tv_t);
        if (pIVLANHDR) {
            pOVLANHDR->next_type = htons(realtime_info->vlanproto[1]);
            pIVLANHDR->priority_cfi_and_id = htons(realtime_info->ivlanid);
            pIVLANHDR->next_type = htons(ETH_P_IP);
            length += sizeof(ethernet_vlan_header_next_tv_t);
            l3_offset += sizeof(ethernet_vlan_header_next_tv_t);
        }
    }

    //封装IPC Header
    ephdr->path.field = UIPC_FIELD_DHCP_SERVER;
    ephdr->path.act = UIPC_ACT_WORK_MSG;
    ephdr->sw_rx_dbid = dhcpd_server->nLineID;
    ephdr->sw_ser_dbid = dhcpd_server->nLineID;
    ephdr->l3_offset = l3_offset;
    ephdr->data_len = length;
    length += sizeof(dhcp_external_proc_hdr_t);
    ipctaskhdr->byte_len = length;
    length += sizeof(uipc_task_t);
#endif

    packet_save_log(packet_process, (struct dhcpv4_message *)request->relay_payload, request->v4.msgcode, "发送报文[v4中继][C]");
    ipc_send_data(packet_process, buffer, length);
}
