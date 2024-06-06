#include "dhcpd.h"
#include "dhcpd/dhcppacket.h"
#include "dhcpd/dhcpv6.h"
#include "share/defines.h"
#include "share/xlog.h"
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>

PRIVATE receive_bucket_t *receive_bucket = NULL;

PUBLIC int relay6_main_init(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

#ifndef VERSION_VNAAS
    vdm->sockfd_relay6 = create_udp_socket6(DHCPV6_SERVER_PORT, 0, 1, 0, NULL);
    if (vdm->sockfd_relay6 < 0) {
        x_log_warn("%s:%d 创建SOCKET失败[MAIN].", __FUNCTION__, __LINE__);
        exit(0);
    }

    socket_set_broadcast(vdm->sockfd_relay6);
#else
    vdm->sockfd_relay6 = create_unix_socket(VNAAS_DHCP_RELAY6_IPC_DGRAM_SOCK, 1, 1);
#endif
    //申请数据包接收BUFFER
    receive_bucket = receive_bucket_allocate(1, MAXBUFFERLEN, 0);
    assert(receive_bucket);
    return 0;
}

PUBLIC int relay6_main_clean(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    receive_bucket_free(receive_bucket); //资源释放
    return 0;
}

PRIVATE int packet_deepin_parse(packet_process_t *packet_process);

PUBLIC int relay6_main_start(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;

    //接收数据包并处理
    receive_bucket->count = receive_bucket_receive(vdm->sockfd_relay6, receive_bucket);
    for (int idx = 0; idx < receive_bucket->count; ++idx) {
        dhcpd_server_t *dhcpd_server = NULL;
        packet_process_t packet_process;
        BZERO(&packet_process, sizeof(packet_process_t));
        struct mmsghdr *packets = &receive_bucket->receives.packets[idx];
        packet_process.data = packets->msg_hdr.msg_iov->iov_base;
        packet_process.data_len = packets->msg_len;
        packet_process.vdm = vdm;
        packet_do_dpi(&packet_process);
        if (packet_deepin_parse(&packet_process) < 0)
            continue;

        dhcpd_server = packet_process.dhcpd_server = dhcpd_server_search_LineID(vdm->cfg_main, packet_process.realtime_info->lineid);
        if (!packet_process.dhcpd_server)
            continue; // DHCP服务查找失败

        //报文响应
        relay6_send_reply_packet(&packet_process);
    }
    return 0;
}

PRIVATE int packet_deepin_parse(packet_process_t *packet_process)
{
    int retcode = 0;
    dhcp_packet_t *request = &packet_process->request;
#ifdef VERSION_VNAAS
    struct ip6_hdr *ip6hdr = request->ip6hdr = (struct ip6_hdr *)packet_process->dpi.l3;
    const u16 iphdr_len = sizeof(struct ip6_hdr);
    struct udphdr *udphdr = request->udphdr = (struct udphdr *)(packet_process->dpi.l3 + iphdr_len);
    struct  dhcpv6_relay_header *dhcpv6_relay_header=(struct  dhcpv6_relay_header *)(packet_process->dpi.l3 + iphdr_len+sizeof(struct udphdr));
    request->l4len=packet_process->dpi.l3len - iphdr_len;
    request->payload = dhcpv6_relay_header;
    request->payload_len = request->l4len-sizeof(struct udphdr);
#else
    request->payload = packet_process->data;
    request->payload_len = packet_process->data_len;
#endif

    struct dhcpv6_relay_header *rep = request->payload;

    if (request->payload_len < sizeof(struct dhcpv6_relay_header))
        return -1;

    u8 *start = ((u8 *)request->payload) + sizeof(struct dhcpv6_relay_header);
    u8 *end = ((u8 *)request->payload) + request->payload_len;
    u16 otype, olen;
    u8 *odata;

    //解析中继报文[V6]
    u8 duid[MAXNAMELEN + 1] = {0};
    u32 duid_len = 0;
    dhcpv6_for_each_option(start, end, otype, olen, odata)
    {
        switch (otype) {
        case DHCPV6_OPT_RELAY_MSG: {
            struct dhcpv6_client_header *relay_msg = (struct dhcpv6_client_header *)odata;
            u8 *reply_start = odata + offsetof(struct dhcpv6_client_header, options);
            u8 *reply_end = odata + olen;
            u16 reply_otype, reply_olen;
            u8 *reply_odata;

            //解析响应报文
            dhcpv6_for_each_option(reply_start, reply_end, reply_otype, reply_olen, reply_odata)
            {
                switch (reply_otype) {
                case DHCPV6_OPT_CLIENTID: {
                    if (reply_olen == 14 && reply_odata[0] == 0 && reply_odata[1] == 1)
                        BCOPY(&reply_odata[8], &packet_process->macaddr, sizeof(mac_address_t));
                    else if (reply_olen == 10 && reply_odata[0] == 0 && reply_odata[1] == 3)
                        BCOPY(&reply_odata[4], &packet_process->macaddr, sizeof(mac_address_t));
                    duid_len = reply_olen;
                    BCOPY(reply_odata, duid, reply_olen);
                } break;
                case DHCPV6_OPT_SERVERID: {
                } break;
                case DHCPV6_OPT_IA_NA: {
                    struct opt_ia_hdr *ia_hdr = (struct opt_ia_hdr *)(reply_odata - 4);
                    u32 offset = offsetof(struct opt_ia_hdr, u) - 4;
                    if (olen > offset) {
                        struct opt_ia_address *ia_addr = (struct opt_ia_address *)&reply_odata[offset];
                        BCOPY(&ia_addr->addr, &request->v6.ipaddr, sizeof(ip6_address_t)); //终端静态IP
                        request->v6.leasetime = ntohl(ia_addr->valid);                     //租约时长
                    }
                } break;
                case DHCPV6_OPT_IA_PD: {
                    struct opt_ia_hdr *ia_hdr = (struct opt_ia_hdr *)(reply_odata - 4);
                    u32 offset = offsetof(struct opt_ia_hdr, u) - 4;
                    if (olen > offset) {
                        struct opt_ia_prefix *ia_prefix = (struct opt_ia_prefix *)&odata[offset];
                    }
                } break;
                case DHCPV6_OPT_DNS_SERVERS: {
                } break;
                case DHCPV6_OPT_DNS_DOMAIN: {
                } break;
                default:
                    break;
                }
            }
            request->v6.msgcode = relay_msg->msg_type;
            request->relay_payload = odata;
            request->relay_payload_len = olen;
        } break;
        case DHCPV6_OPT_INTERFACE_ID: {
            request->v6.interfaceid_len = olen;
            BCOPY(odata, &request->v6.interfaceid, sizeof(struct interface_id_t));
        } break;
        default:
            break;
        }
    }

    //查找终端信息
    realtime_info_t *realtime_info = packet_process->realtime_info = realtime_search(packet_process);
    if (!realtime_info)
        realtime_info = packet_process->realtime_info = realtime_search_duid(duid, duid_len);
    if (!realtime_info)
        return -1;

    realtime_info->v6.leasetime = request->v6.leasetime;
    realtime_info->v6.ipaddr = request->v6.ipaddr;
    if (request->v6.msgcode == DHCPV6_MSG_REPLY) {
        SET_COUNTER(realtime_info->updatetick);
        realtime_info->flags |= RLTINFO_FLAGS_RELAY6;
        __sync_fetch_and_add(&realtime_info->update_db6, 1);
    }
    packet_save_log6(packet_process, (struct dhcpv6_client_header *)request->relay_payload, request->v6.msgcode, "接收报文[v6中继][S]");
    return 0;
}

// TX
PUBLIC int relay6_send_request_packet(packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcp_packet_t *request = &packet_process->request;

    unsigned char buffer[MAXBUFFERLEN + 1] = {0};
    unsigned int offset = 0, length = 0, opts_offset = 0;
    struct ip6_hdr *pIP6Header = (struct ip6_hdr *)&buffer[offset];
    offset += sizeof(struct ip6_hdr);
    struct udphdr *pUDPHeader = (struct udphdr *)&buffer[offset];
    offset += sizeof(struct udphdr);
    struct dhcpv6_relay_header *relay = (struct dhcpv6_relay_header *)&buffer[offset];

    // DHCP报文封装
    relay->msg_type = DHCPV6_MSG_RELAY_FORW;
    relay->hop_count = 0;
    relay->link_address = dhcpd_server->iface.ipaddr6;
    relay->peer_address.addr = request->ip6hdr->ip6_src /*dhcpd_server->iface.ipaddr6*/;
    // DHCP报文封装[原始报文]
    opts_offset += sizeof(struct dhcpv6_relay_header);
    struct dhcpv6_option *opts = (struct dhcpv6_option *)&buffer[offset + opts_offset]; // relay message
    opts->type = htons(DHCPV6_OPT_RELAY_MSG);
    opts->len = htons(request->payload_len);
    BCOPY(request->payload, opts->data, request->payload_len);
    opts_offset += request->payload_len + sizeof(struct dhcpv6_option);

    // DHCP报文封装[INTERFACE ID]
    struct interface_id_t interfaceid = {.ovlan = htons(packet_process->dpi.vlanid[0]), .ivlan = htons(packet_process->dpi.vlanid[1])};
    BCOPY(DHCPV6_RELAY_VERSION, interfaceid.version, sizeof(interfaceid.version));
    BCOPY(&packet_process->macaddr, &interfaceid.mac_addr, sizeof(mac_address_t));
    opts = (struct dhcpv6_option *)&buffer[offset + opts_offset]; // interface id
    opts->type = htons(DHCPV6_OPT_INTERFACE_ID);
    opts->len = htons(sizeof(struct interface_id_t));
    BCOPY(&interfaceid, opts->data, sizeof(struct interface_id_t));
    opts_offset += sizeof(struct interface_id_t) + sizeof(struct dhcpv6_option);

    length += opts_offset;

    //封装UDP Header
    length += sizeof(struct udphdr);
    pUDPHeader->len = htons(length);
    pUDPHeader->dest = dhcpd_server->dhcprelay.v6.serverport;
    pUDPHeader->source = htons(DHCPV6_SERVER_PORT);
    pUDPHeader->check = 0;

    //封装IP Header
    pIP6Header->ip6_vfc = 0x6e;
    pIP6Header->ip6_plen = htons(length);
    pIP6Header->ip6_nxt = IPPROTO_UDP;
    pIP6Header->ip6_hlim = 255;
#ifndef VERSION_VNAAS
#define DEFAULT_LCP_IP6 "fe80::0a7f:7afd"
    inet_pton(AF_INET6, DEFAULT_LCP_IP6, &pIP6Header->ip6_src);
#else
    pIP6Header->ip6_src = dhcpd_server->dhcprelay.v6.lineip.addr;
#endif
    pIP6Header->ip6_dst = dhcpd_server->dhcprelay.v6.serverip.addr;
    length += sizeof(struct ip6_hdr);
    WinDivertHelperCalcChecksums(buffer, length, 0); //计算校验和

    struct sockaddr_in6 sto;
    sto.sin6_family = AF_INET6;
    sto.sin6_addr = dhcpd_server->dhcprelay.v6.serverip.addr;
    sto.sin6_port = htons(IPPROTO_RAW);
    packet_save_log6(packet_process, (struct dhcpv6_client_header *)request->payload, request->v6.msgcode, "发送报文[v6中继][S]");
    int a = sendto(packet_process->vdm->sockfd_raw6, buffer, length, 0, (struct sockaddr_in6 *)&sto, sizeof(struct sockaddr_in6));
    if (a < 0) perror(strerror(errno));
    return 0;
}

// RX
PUBLIC int relay6_send_reply_packet(packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcp_packet_t *request = &packet_process->request;
    struct dhcpv6_relay_header *rep = request->payload;
    struct dhcpv6_client_header *relay_msg = request->relay_payload;

    unsigned char buffer[MAXBUFFERLEN + 1] = {0};
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

    // DHCP报文封装
    BCOPY(request->relay_payload, payload, request->relay_payload_len);
    length += request->relay_payload_len;

    //封装UDP Header
    length += sizeof(struct udphdr);
    pUDPHeader->len = htons(length);
    pUDPHeader->dest = htons(DHCPV6_CLIENT_PORT);
    pUDPHeader->source = htons(DHCPV6_SERVER_PORT);
    pUDPHeader->check = 0;

    //封装IP Header
    pIP6Header->ip6_vfc = 0x6e;
    pIP6Header->ip6_plen = htons(length);
    pIP6Header->ip6_nxt = IPPROTO_UDP;
    pIP6Header->ip6_hlim = 255;
    pIP6Header->ip6_src = dhcpd_server->iface.ipaddr6.addr;
    pIP6Header->ip6_dst = rep->peer_address.addr;
    length += sizeof(struct ip6_hdr);
    WinDivertHelperCalcChecksums(pIP6Header, length, 0); //计算校验和

#ifndef VERSION_VNAAS
    //封装IPC Header
    ipcsharehdr->process = DEFAULT_DHCPv6_PROCESS;
    ipcsharehdr->code = CODE_REPLY; // 1
    ipcsharehdr->driveid = dhcpd_server->iface.driveid;
    ipcsharehdr->lineid = dhcpd_server->nLineID;
    ipcsharehdr->outer_vlanid = realtime_info->ovlanid;
    ipcsharehdr->inner_vlanid = realtime_info->ivlanid;
    ipcsharehdr->session = realtime_info->sessionid;
    ipcsharehdr->datalen = length;
    BCOPY(realtime_info->key.u.macaddr.addr, ipcsharehdr->ethhdr.ether_dhost, ETH_ALEN);
    BCOPY(dhcpd_server->iface.macaddr.addr, ipcsharehdr->ethhdr.ether_shost, ETH_ALEN);
    ipcsharehdr->ethhdr.ether_type = htons(ETH_P_IPV6);
    length += sizeof(ipcshare_hdr_t);
#else
    //封装Ether Header
    u16 l3_offset = 0;
    BCOPY(realtime_info->key.u.macaddr.addr, ethhdr->ether_dhost, ETH_ALEN);
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
    char srcip[MINBUFFERLEN];
    char dstip[MINBUFFERLEN];
    inet_ntop(AF_INET6,&pIP6Header->ip6_src , srcip, MINNAMELEN);
    inet_ntop(AF_INET6, &pIP6Header->ip6_dst, dstip, MINNAMELEN);
    x_log_debug("发送中继报文,srcIP:%s,dstIP:%s,ovlan:%d,invlan:%d",srcip,dstip,realtime_info->ovlanid,realtime_info->ivlanid);
    packet_save_log6(packet_process, (struct dhcpv6_client_header *)request->relay_payload, request->v6.msgcode, "发送报文[v6中继][C]");
    return ipc_send_data(packet_process, buffer, length);
}
