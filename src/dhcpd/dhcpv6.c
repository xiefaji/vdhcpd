#include "dhcpd.h"

PRIVATE int server6_send_reply_packet(packet_process_t *packet_process, dhcp_packet_t *packet, const struct sockaddr_in6 dest);

PUBLIC char *dhcpv6_msg_to_string(u8 reqmsg)
{
    switch (reqmsg) {
    case (DHCPV6_MSG_SOLICIT): return "DHCPV6_MSG_SOLICIT";
    case (DHCPV6_MSG_ADVERTISE): return "DHCPV6_MSG_ADVERTISE";
    case (DHCPV6_MSG_REQUEST): return "DHCPV6_MSG_REQUEST";
    case (DHCPV6_MSG_CONFIRM): return "DHCPV6_MSG_CONFIRM";
    case (DHCPV6_MSG_RENEW): return "DHCPV6_MSG_RENEW";
    case (DHCPV6_MSG_REBIND): return "DHCPV6_MSG_REBIND";
    case (DHCPV6_MSG_REPLY): return "DHCPV6_MSG_REPLY";
    case (DHCPV6_MSG_RELEASE): return "DHCPV6_MSG_RELEASE";
    case (DHCPV6_MSG_DECLINE): return "DHCPV6_MSG_DECLINE";
    case (DHCPV6_MSG_RECONFIGURE): return "DHCPV6_MSG_RECONFIGURE";
    case (DHCPV6_MSG_INFORMATION_REQUEST): return "DHCPV6_MSG_INFORMATION_REQUEST";
    case (DHCPV6_MSG_RELAY_FORW): return "DHCPV6_MSG_RELAY_FORW";
    case (DHCPV6_MSG_RELAY_REPL): return "DHCPV6_MSG_RELAY_REPL";
    case (DHCPV6_MSG_DHCPV4_QUERY): return "DHCPV6_MSG_DHCPV4_QUERY";
    case (DHCPV6_MSG_DHCPV4_RESPONSE): return "DHCPV6_MSG_DHCPV4_RESPONSE";
    default: return "UNKNOWN";
    }
}

PUBLIC void dhcpv6_put(struct dhcpv6_client_header *msg, u8 **cookie, u16 type, u16 len, const void *data)
{
    u8 *c = *cookie;
    u8 *end = (u8 *)msg + sizeof(*msg);
    struct dhcpv6_option *o = (struct dhcpv6_option *)c;
    int total_len = sizeof(struct dhcpv6_option) + len;

    if (*cookie + total_len > end)
        return;
    o->type = htons(type);
    o->len = htons(total_len);
    BCOPY(data, o->data, len);
    *cookie += total_len;
}

PUBLIC int server6_process(packet_process_t *packet_process)
{
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcp_packet_t *request = &packet_process->request;
    dhcp_packet_t *reply = &packet_process->reply;
    struct dhcpv6_client_header *req = request->payload;
    const u8 reqmsg = request->v6.msgcode;
    struct vdhcpd_assignment *a = NULL;

    struct dhcpv6_client_header rep;
    BZERO(&rep, sizeof(struct dhcpv6_client_header));
    u8 *cookie = &rep.options[0];

    int retcode = 0;
    switch (reqmsg) {
    case DHCPV6_MSG_SOLICIT:
        break;
    case DHCPV6_MSG_ADVERTISE:
        break;
    case DHCPV6_MSG_REQUEST:
        break;
    case DHCPV6_MSG_CONFIRM:
        break;
    case DHCPV6_MSG_RENEW:
        break;
    case DHCPV6_MSG_REBIND:
        break;
    case DHCPV6_MSG_REPLY:
        break;
    case DHCPV6_MSG_RELEASE:
        break;
    case DHCPV6_MSG_DECLINE:
        break;
    case DHCPV6_MSG_RECONFIGURE:
        break;
    case DHCPV6_MSG_INFORMATION_REQUEST:
        break;
    case DHCPV6_MSG_RELAY_FORW:
        break;
    case DHCPV6_MSG_RELAY_REPL:
        break;
    case DHCPV6_MSG_DHCPV4_QUERY:
        break;
    case DHCPV6_MSG_DHCPV4_RESPONSE:
            break;
    default:
        break;
    }

    struct sockaddr_in6 dest;
    dest.sin6_family = AF_INET6;
    dest.sin6_addr = request->ip6hdr->ip6_src;
    dest.sin6_port = htons(DHCPV6_CLIENT_PORT);

    rep.msg_type = reply->v6.msgcode;
    BCOPY(req->transaction_id, rep.transaction_id, 3);
    reply->payload = &rep;
    reply->payload_len = PACKET6_SIZE(&rep, cookie);
    return server6_send_reply_packet(packet_process, reply, dest);
}

PRIVATE int server6_send_reply_packet(packet_process_t *packet_process, dhcp_packet_t *packet, const struct sockaddr_in6 dest)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    realtime_info_t *realtime_info = packet_process->realtime_info;
    struct dhcpv6_client_header *rep = packet->payload;

    unsigned char buffer[MAXBUFFERLEN+1]={0};
    unsigned int offset = 0, length = 0;
#ifndef VERSION_VNAAS
    ipcshare_hdr_t *ipcsharehdr = (ipcshare_hdr_t *)buffer;
    struct ip6_hdr *pIP6Header = (struct ip6_hdr *)&ipcsharehdr->pdata[offset];
    offset += sizeof(struct ip6_hdr);
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
    struct ip6_hdr *pIP6Header = (struct ip6_hdr *)&buffer[offset];
    offset += sizeof(struct ip6_hdr);
    struct udphdr *pUDPHeader = (struct udphdr *)&buffer[offset];
    offset += sizeof(struct udphdr);
    u8 *payload = (u8 *)&buffer[offset];
#endif

    //DHCP报文封装
    BCOPY(packet->payload, payload, packet->payload_len);
    length += packet->payload_len;

    //封装UDP Header
    length += sizeof(struct udphdr);
    pUDPHeader->len = htons(length);
    pUDPHeader->dest = dest.sin6_port;
    pUDPHeader->source = htons(DHCPV6_SERVER_PORT);
    pUDPHeader->check = 0;

    //封装IP Header
    pIP6Header->ip6_vfc = 0x6e;
    pIP6Header->ip6_plen = htons(length);
    pIP6Header->ip6_nxt = IPPROTO_UDP;
    pIP6Header->ip6_hlim = 255;
    pIP6Header->ip6_src = dhcpd_server->dhcpv6.gateway.ip_u64[0] ? dhcpd_server->dhcpv6.gateway.addr:dhcpd_server->iface.ipaddr6.addr;
    pIP6Header->ip6_dst = dest.sin6_addr;
    length += sizeof(struct ip6_hdr);
    WinDivertHelperCalcChecksums(pIP6Header, length, 0);//计算校验和

#ifndef VERSION_VNAAS
    //封装IPC Header
    ipcsharehdr->process = DEFAULT_DHCPv6_PROCESS;
    ipcsharehdr->code = CODE_REPLY;//1
    ipcsharehdr->driveid = dhcpd_server->iface.driveid;
    ipcsharehdr->lineid = dhcpd_server->nLineID;
    ipcsharehdr->outer_vlanid = realtime_info->ovlanid;
    ipcsharehdr->inner_vlanid = realtime_info->ivlanid;
    ipcsharehdr->session = realtime_info->sessionid;
    ipcsharehdr->datalen = length;
    /*if (DHCPV4_FLAGS_BROADCAST(rep)) memset(ipcsharehdr->ethhdr.ether_dhost, 0xFF, ETH_ALEN);
    else */BCOPY(realtime_info->key.u.macaddr.addr, ipcsharehdr->ethhdr.ether_dhost, ETH_ALEN);
    BCOPY(dhcpd_server->iface.macaddr.addr, ipcsharehdr->ethhdr.ether_shost, ETH_ALEN);
    ipcsharehdr->ethhdr.ether_type = htons(ETH_P_IPV6);
    length += sizeof(ipcshare_hdr_t);
#else
    //封装Ether Header
    u16 l3_offset = 0;
    /*if (DHCPV4_FLAGS_BROADCAST(rep)) memset(ethhdr->ether_dhost, 0xFF, ETH_ALEN);
    else */BCOPY(realtime_info->key.u.macaddr.addr, ethhdr->ether_dhost, ETH_ALEN);
    BCOPY(dhcpd_server->iface.macaddr.addr, ethhdr->ether_shost, ETH_ALEN);
    ethhdr->ether_type = htons(ETH_P_IPV6);
    length += sizeof(struct ether_header);
    l3_offset += sizeof(struct ether_header);
    if (pOVLANHDR) {
        ethhdr->ether_type = htons(realtime_info->vlanproto[0]);
        pOVLANHDR->priority_cfi_and_id = htons(realtime_info->ovlanid);
        pOVLANHDR->next_type = htons(ETH_P_IPV6);
        length += sizeof(ethernet_vlan_header_next_tv_t);
        l3_offset += sizeof(ethernet_vlan_header_next_tv_t);
        if (pIVLANHDR) {
            pOVLANHDR->next_type = htons(realtime_info->vlanproto[1]);
            pIVLANHDR->priority_cfi_and_id = htons(realtime_info->ivlanid);
            pIVLANHDR->next_type = htons(ETH_P_IPV6);
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

    packet_save_log6(packet_process, (struct dhcpv6_client_header *)packet->payload, packet->v6.msgcode, "发送报文[v6服务][C]");
    return ipc_send_data(packet_process, buffer, length);
}
