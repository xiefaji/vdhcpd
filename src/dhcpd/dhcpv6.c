#include "dhcpd/dhcpv6.h"
#include "dhcpd.h"
#include "dhcpd/realtime.h"
#include "share/defines.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>

PRIVATE int server6_send_reply_packet(packet_process_t *packet_process, dhcp_packet_t *packet, const struct sockaddr_in6 dest);
PRIVATE int ip6_addr_equal(ip6_address_t a,ip6_address_t b){
    for (int i=0; i < 16; i++)
    {
        if (a.ip_u8[i]==b.ip_u8[i])
            continue;
        else if(a.ip_u8[i]<b.ip_u8[i])  
            return -1;
        else
            return 1;
    } 
    return 0;
}
PRIVATE ip6_address_t IPV6_HTONLLL(ip6_address_t address){
    for(int i=0;i<4;i++){
        address.ip_u32[i]=htonl(address.ip_u32[i]);
    }
    return address;
}
PRIVATE ip6_address_t IPV6_NTOHLLL(ip6_address_t address){
    for(int i=0;i<4;i++){
        address.ip_u32[i]=htonl(address.ip_u32[i]);
    }
    return address;
}
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
    o->len = htons(len);
    BCOPY(data, o->data, len);
    *cookie += total_len;
}

PRIVATE void generate_duid(u8 duid[], u8 mac[])
{
    time_t timestamp_value = vdhcpd_time();
    duid[0] = 0; // Type 1 (Link-layer address plus time)
    duid[1] = 3; // Hardware type (Ethernet)
    duid[2] = 0;
    duid[3] = 1; // Hardware type (Ethernet)

    // Copy MAC address to DUID
    for (int i = 0; i < 6; i++) {
        duid[4 + i] = mac[i];
        // 4Bit
    }
}

PRIVATE void generate_ia(struct opt_ia_hdr *ia_hdr, const u16 type, const u16 len, const u32 iaid/*netbit*/, const u32 leasetime)
{
    ia_hdr->type = htons(type);
    ia_hdr->len = htons(len + offsetof(struct opt_ia_hdr, u) - 4);
    ia_hdr->iaid = iaid;
    ia_hdr->t1 = htonl(leasetime);
    ia_hdr->t2 = htonl(leasetime * 2);
}

PRIVATE void generate_ia_na(struct opt_ia_hdr *ia_hdr, ip6_address_t *addr, packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    const u32 leasetime = dhcpd_server->leasetime;
    dhcp_packet_t *request = &packet_process->request;

    struct opt_ia_address *ia_addr = &ia_hdr->u.ia_addr;
    ia_addr->type = htons(DHCPV6_OPT_IA_ADDR);
    ia_addr->len = htons(sizeof(struct opt_ia_address) - 4);
    BCOPY(addr, &ia_addr->addr, sizeof(ip6_address_t));
    ia_addr->preferred = htonl(leasetime * 1.5);
    ia_addr->valid = htonl(leasetime * 10);
    generate_ia(ia_hdr, DHCPV6_OPT_IA_NA, sizeof(struct opt_ia_address), request->v6.iaid, leasetime);
}

PRIVATE void generate_ia_pd(struct opt_ia_hdr *ia_hdr, ip6_address_t *addr, packet_process_t *packet_process)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    const u32 leasetime = dhcpd_server->leasetime;
    dhcp_packet_t *request = &packet_process->request;

    struct opt_ia_prefix *ia_prefix = &ia_hdr->u.ia_prefix;
    ia_prefix->type = htons(DHCPV6_OPT_IA_PREFIX);
    ia_prefix->len = htons(sizeof(struct opt_ia_prefix) - 4);
    ia_prefix->preferred = htonl(leasetime * 1.5);
    ia_prefix->valid = htonl(leasetime * 10);
    ia_prefix->prefix =(dhcpd_server->dhcpv6.prefix) ;
    BCOPY(&dhcpd_server->dhcpv6.prefix_addr, &ia_prefix->addr, sizeof(ip6_address_t));
    generate_ia(ia_hdr, DHCPV6_OPT_IA_PD, sizeof(struct opt_ia_prefix), request->v6.iaid, leasetime);
}

//实时租约查找[MACADDR]
PRIVATE struct vdhcpd_assignment *find_assignment_by_macaddr(packet_process_t *packet_process, const mac_address_t macaddr)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    struct vdhcpd_assignment *a;
    list_for_each_entry(a, &server_stats->dhcpv6_assignments, head) {
        if (!BCMP(&a->macaddr, &macaddr, sizeof(mac_address_t)))
            return a;
    }
    return NULL;
}

//实时租约查找[IPADDR]
PRIVATE struct vdhcpd_assignment *find_assignment_by_ipaddr(packet_process_t *packet_process, const ip6_address_t ipaddr/*netbit*/)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    struct vdhcpd_assignment *a;
    list_for_each_entry(a, &server_stats->dhcpv6_assignments, head) {
        if (!BCMP(&a->addr6, &ipaddr, sizeof(ip6_address_t)))
            return a;
    }
    return NULL;
}

PRIVATE bool dhcpv6_insert_assignment(packet_process_t *packet_process, struct vdhcpd_assignment *a, const ip6_address_t addr/*netbit*/)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;

    struct vdhcpd_assignment *c;
    //c只是提供一个能够遍历的指针,存储虚拟 DHCP 分配的 IP 地址和配置信息的数据结构。

    // 检查是否有静态分配的 IP 地址与 MAC 地址匹配
    dhcpd_staticlease_t *staticlease = staticlease_search6_ipaddr(dhcpd_server->staticlease_main, addr);
    if (staticlease && BCMP(&staticlease->key.u.macaddr, &packet_process->macaddr, sizeof(mac_address_t)))
        return false;

    // 遍历已分配的列表，检查是否已有其他节点分配相同的 IP 地址
    //ist_for_each_entry(pos, head, member)
    list_for_each_entry(c, &server_stats->dhcpv6_assignments, head) {
        if (BCMP(&c->addr6, &addr, sizeof(ip6_address_t))==0)
            return false;//IP已被分配
    }
    /* Insert new node before c (might match list head) */
    BCOPY(&addr, &a->addr6, sizeof(ip6_address_t));
    dhcpd_server_stats_lock(server_stats);// 锁定服务器统计信息以进行插入操作
    list_add_tail(&a->head, &c->head);// 将新节点插入到分配列表的末尾 (new ,try-add)
    dhcpd_server_stats_unlock(server_stats);// 解锁服务器统计信息
    return true;// 成功插入分配节点
}

PRIVATE void dhcpv6_free_assignment(struct vdhcpd_assignment *a)
{
    //coolriolee
    //    if (a->fr_ip)
    //        dhcpv4_fr_stop(a);
}

PRIVATE bool dhcpv6_assign(packet_process_t *packet_process, struct vdhcpd_assignment *a, ip6_address_t *raddr/*netbit*/)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    struct vdhcpd_assignment *c;
    ip6_address_t start;
    ip6_address_t end;
    BCOPY(&dhcpd_server->dhcpv6.startip, &start, sizeof(ip6_address_t));
    BCOPY(&dhcpd_server->dhcpv6.endip, &end, sizeof(ip6_address_t));
    bool assigned;

    if (!IPv6_ZERO(&a->ipaddr6)) {
        assigned = dhcpv6_insert_assignment(packet_process, a, *raddr);/*静态租约*/
        if (assigned)
            return assigned;
    }
    //    assigned = dhcpv6_insert_assignment(packet_process, a, *raddr);
    //    if(assigned)
    //        return true;
    //如果分配信息中有预配置的IP地址（静态租约）
    if((ip6_addr_equal(start, *raddr)<=0)&&(ip6_addr_equal(end, *raddr)>=0)){
        if(find_assignment_by_ipaddr(packet_process, *raddr)){
                return true;
        }else{
            if(dhcpv6_insert_assignment(packet_process, a, *raddr))
                BCOPY(&start, &a->ipaddr6, sizeof(ip6_address_t));
        }
    }
    //生成新地址
    for (int count=0;count<100;count++) {
        srand(time(NULL));
        ip6_address_t new_add;
        BCOPY(&start, &new_add, sizeof(ip6_address_t));
        for (int i = 0; i < 16; i++) {
            if (start.ip_u8[i] == end.ip_u8[i])
                continue;
            else if (start.ip_u8[i] < end.ip_u8[i]) {
                for (int j = i;  j < 16; j++) { 
                    uint8_t u8_random_data = (uint8_t)(random()%(end.ip_u8[j] - start.ip_u8[j]));
                    new_add.ip_u8[j] +=u8_random_data;
                }
                break;
            }
        }
        assigned = dhcpv6_insert_assignment(packet_process, a, new_add);
        if (assigned) {
            BCOPY(&new_add, &a->ipaddr6, sizeof(ip6_address_t));
            return true;
        }
    }
    return false;
}

PRIVATE struct vdhcpd_assignment *dhcpv6_lease(packet_process_t *packet_process, enum dhcpv6_msg msgcode)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    dhcp_packet_t *request = &packet_process->request;

    struct vdhcpd_assignment *a = find_assignment_by_macaddr(packet_process, packet_process->macaddr);
    dhcpd_staticlease_t *staticlease = dhcpd_server_staticlease_search_macaddr(dhcpd_server, packet_process->macaddr, 6);
    time_t now = vdhcpd_time();
    // 主要是配置三个东西:ip,mac,租约
    if (!a) {
        a = alloc_assignment(dhcpd_server->server_stats, 0);
        assert(a);
        BZERO(a, sizeof(struct vdhcpd_assignment));
    }
    BCOPY(&packet_process->macaddr, &a->macaddr, sizeof(mac_address_t));

    if (staticlease || msgcode == DHCPV6_MSG_RELEASE ||
            msgcode == DHCPV6_MSG_DECLINE) {
        a->leasetime = 0;
        BCOPY(&request->v6.reqaddr, &a->ipaddr6, sizeof(ip6_address_t));
    }else{
        a->leasetime = dhcpd_server->leasetime;
        if (IPv6_ZERO(&a->ipaddr6))
            dhcpv6_assign(packet_process, a, &request->v6.reqaddr);
    }
    return a;
}

PUBLIC int server6_process(packet_process_t *packet_process)
{
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    dhcp_packet_t *request = &packet_process->request;
    dhcp_packet_t *reply = &packet_process->reply;
    struct dhcpv6_client_header *req = request->payload;
    const u8 reqmsg = request->v6.msgcode;
    struct vdhcpd_assignment *a = NULL;

    struct dhcpv6_client_header rep;
    BZERO(&rep, sizeof(struct dhcpv6_client_header));
    u8 *cookie = &rep.options[0];
    for (int i = 0; i < 3; i++) {
        rep.transaction_id[i] = req->transaction_id[i]; // DHCPv6事务ID=xid
    }

    ip6_address_t addr6, prefix6;
    BZERO(&addr6, sizeof(ip6_address_t));
    BZERO(&prefix6, sizeof(ip6_address_t));

    if (reqmsg != DHCPV6_MSG_INFORMATION_REQUEST) {
        a = dhcpv6_lease(packet_process, reqmsg);
        if (a) BCOPY(&a->ipaddr6, &addr6, sizeof(ip6_address_t));
    }

    struct opt_ia_hdr ia_na;
    struct opt_ia_hdr ia_pd;
    u8 server_duid[10] = {0};
    u8 domain_search_list[12] = {6, 97, 97, 98, 98, 99, 99, 3, 99, 0x6f, 0x6d, 0x0};
    generate_ia_na(&ia_na, &addr6, packet_process);
    generate_ia_pd(&ia_pd, &prefix6, packet_process);
    generate_duid(server_duid, dhcpd_server->iface.macaddr.addr);

    switch (reqmsg) {
    case DHCPV6_MSG_SOLICIT: {
        reply->v6.msgcode = realtime_info->v6.rapid_commit ? DHCPV6_MSG_REPLY:DHCPV6_MSG_ADVERTISE;
    } break;
    case DHCPV6_MSG_REQUEST: {
        reply->v6.msgcode = DHCPV6_MSG_REPLY;
    } break;
    case DHCPV6_MSG_CONFIRM: {
        reply->v6.msgcode = DHCPV6_MSG_REPLY;
    } break;
    case DHCPV6_MSG_RENEW: {
        reply->v6.msgcode = (a && a->leasetime) ? DHCPV6_MSG_REPLY:DHCPV6_MSG_RECONFIGURE;
    } break;
    case DHCPV6_MSG_REBIND: {
        reply->v6.msgcode = (a && a->leasetime) ? DHCPV6_MSG_REPLY:DHCPV6_MSG_RECONFIGURE;
    } break;
    case DHCPV6_MSG_RELEASE: {
        reply->v6.msgcode = DHCPV6_MSG_REPLY;
    } break;
    case DHCPV6_MSG_DECLINE: {
        reply->v6.msgcode = DHCPV6_MSG_REPLY;
    } break;
    case DHCPV6_MSG_RECONFIGURE:
        break;
    case DHCPV6_MSG_INFORMATION_REQUEST:
        reply->v6.msgcode = DHCPV6_MSG_REPLY;
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

    dhcpv6_put(&rep, &cookie, DHCPV6_OPT_CLIENTID, realtime_info->v6.duid_len, realtime_info->v6.duid);
    dhcpv6_put(&rep, &cookie, DHCPV6_OPT_SERVERID, sizeof(server_duid), server_duid);
    if (realtime_info->v6.ia_pd) dhcpv6_put(&rep, &cookie, ntohs(ia_pd.type), ntohs(ia_pd.len), ((u8 *)&ia_pd) + 4);
    else dhcpv6_put(&rep, &cookie, ntohs(ia_na.type), ntohs(ia_na.len), ((u8 *)&ia_na) + 4);
    if (realtime_info->v6.rapid_commit) dhcpv6_put(&rep, &cookie, DHCPV6_OPT_RAPID_COMMIT, 0, 0);
    for (u32 i = 1; i < realtime_info->v6.reqopts_len; i += 2) {
        if (realtime_info->v6.reqopts[i] == DHCPV6_OPT_DNS_SERVERS)
            dhcpv6_put(&rep, &cookie, DHCPV6_OPT_DNS_SERVERS, 32, dhcpd_server->dhcpv6.dns);
        else if (realtime_info->v6.reqopts[i] == DHCPV6_OPT_DNS_DOMAIN)
            dhcpv6_put(&rep, &cookie, DHCPV6_OPT_DNS_DOMAIN, 12, &domain_search_list);
        else if (realtime_info->v6.reqopts[i] == DHCPV6_OPT_RAPID_COMMIT) {
            reply->v6.msgcode = DHCPV6_MSG_REPLY;
            dhcpv6_put(&rep, &cookie, DHCPV6_OPT_RAPID_COMMIT, 0, 0);
        }
    }
    if(reqmsg==DHCPV6_MSG_INFORMATION_REQUEST)
        dhcpv6_put(&rep, &cookie, DHCPV6_OPT_LIFETIME, 4,& a->leasetime);

    if (a) {
        BCOPY(&a->ipaddr6, &realtime_info->v6.ipaddr, sizeof(ip6_address_t));
        realtime_info->v6.leasetime = a->leasetime;
    }
    SET_COUNTER(realtime_info->updatetick);
    realtime_info->flags |= RLTINFO_FLAGS_SERVER6;
    if (realtime_info->v6.hostname_len == 0) {
        char hostname[MAXNAMELEN + 1] = "UNKNOW"; // 12
        BCOPY(&hostname, &realtime_info->v6.hostname, 6);
        realtime_info->v6.hostname_len = 6;
    }
    __sync_fetch_and_add(&realtime_info->update_db6, 1);

    if (a && (reply->v6.msgcode == DHCPV6_MSG_RECONFIGURE || reqmsg == DHCPV6_MSG_RELEASE || reqmsg == DHCPV6_MSG_DECLINE))
        free_assignment(a);

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
