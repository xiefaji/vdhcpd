#include <resolv.h>
#include "dhcpd.h"

PRIVATE int server4_send_reply_packet(packet_process_t *packet_process, dhcp_packet_t *packet, const struct sockaddr_in dest);

PUBLIC char *dhcpv4_msg_to_string(u8 reqmsg)
{
    switch (reqmsg) {
    case (DHCPV4_MSG_DISCOVER): return "DHCPV4_MSG_DISCOVER";
    case (DHCPV4_MSG_OFFER): return "DHCPV4_MSG_OFFER";
    case (DHCPV4_MSG_REQUEST): return "DHCPV4_MSG_REQUEST";
    case (DHCPV4_MSG_DECLINE): return "DHCPV4_MSG_DECLINE";
    case (DHCPV4_MSG_ACK): return "DHCPV4_MSG_ACK";
    case (DHCPV4_MSG_NAK): return "DHCPV4_MSG_NAK";
    case (DHCPV4_MSG_RELEASE): return "DHCPV4_MSG_RELEASE";
    case (DHCPV4_MSG_INFORM): return "DHCPV4_MSG_INFORM";
    case (DHCPV4_MSG_FORCERENEW): return "DHCPV4_MSG_FORCERENEW";
    default: return "UNKNOWN";
    }
}

PUBLIC void dhcpv4_put(struct dhcpv4_message *msg, u8 **cookie, u8 type, u8 len, const void *data)
{
    u8 *c = *cookie;
    u8 *end = (u8 *)msg + sizeof(*msg);
    bool tag_only = type == DHCPV4_OPT_PAD || type == DHCPV4_OPT_END;
    int total_len = tag_only ? 1 : 2 + len;

    if (*cookie + total_len > end)
        return;

    *cookie += total_len;
    *c++ = type;

    if (tag_only)
        return;

    *c++ = len;
    BCOPY(data, c, len);
}

PRIVATE void dhcpv4_free_assignment(struct vdhcpd_assignment *a)
{
    //coolriolee
    //    if (a->fr_ip)
    //        dhcpv4_fr_stop(a);
}

PRIVATE bool dhcpv4_insert_assignment(packet_process_t *packet_process, struct vdhcpd_assignment *a, const ip4_address_t addr/*netbit*/)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;

    u32 h_addr = IPV4_NTOHL(addr);
    struct vdhcpd_assignment *c;

    dhcpd_staticlease_t *staticlease = staticlease_search4_ipaddr(dhcpd_server->staticlease_main, addr);
    if (staticlease && BCMP(&staticlease->key.u.macaddr, &packet_process->macaddr, sizeof(mac_address_t)))
        return false;

    list_for_each_entry(c, &server_stats->dhcpv4_assignments, head) {
        u32 c_addr = IPV4_NTOHL(c->addr);
        if (c_addr == h_addr)
            return false;//IP已被分配
        //        if (c_addr > h_addr)
        //            break;
    }

    /* Insert new node before c (might match list head) */
    a->addr = addr;
    dhcpd_server_stats_lock(server_stats);
    list_add_tail(&a->head, &c->head);
    dhcpd_server_stats_unlock(server_stats);
    return true;
}

//实时租约查找[MACADDR]
PRIVATE struct vdhcpd_assignment *find_assignment_by_macaddr(packet_process_t *packet_process, const mac_address_t macaddr)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    struct vdhcpd_assignment *a;
    list_for_each_entry(a, &server_stats->dhcpv4_assignments, head) {
        if (!BCMP(&a->macaddr, &macaddr, sizeof(mac_address_t)))
            return a;
    }
    return NULL;
}

//实时租约查找[IPADDR]
PRIVATE struct vdhcpd_assignment *find_assignment_by_ipaddr(packet_process_t *packet_process, const ip4_address_t ipaddr/*netbit*/)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    struct vdhcpd_assignment *a;
    list_for_each_entry(a, &server_stats->dhcpv4_assignments, head) {
        if (!BCMP(&a->addr, &ipaddr, sizeof(ip4_address_t)))
            return a;
    }
    return NULL;
}

//租约分配
PRIVATE bool dhcpv4_assign(packet_process_t *packet_process, struct vdhcpd_assignment *a, const ip4_address_t raddr/*netbit*/)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    u32 start = IPV4_NTOHL(dhcpd_server->dhcpv4.startip);
    u32 end = IPV4_NTOHL(dhcpd_server->dhcpv4.endip);
    u32 count = end - start + 1;
    u32 seed = 0;
    bool assigned;

    /* Preconfigured IP address by static lease */
    if (a->ipaddr.address) {
        assigned = dhcpv4_insert_assignment(packet_process, a, a->ipaddr);/*静态租约*/
        if (assigned) x_log_debug("接入服务[分配地址]: 静态租约 "IPV4FMT".", IPV4BYTES(a->addr));
        return assigned;
    }

    /* try to assign the IP the client asked for */
    if (start <= IPV4_NTOHL(raddr) && IPV4_NTOHL(raddr) <= end && !find_assignment_by_ipaddr(packet_process, raddr)) {
        assigned = dhcpv4_insert_assignment(packet_process, a, raddr);/*固定IP地址*/
        if (assigned) {
            x_log_debug("接入服务[分配地址]: 固定IP地址 "IPV4FMT".", IPV4BYTES(a->addr));
            return true;
        }
    }

    /* Seed RNG with checksum of hwaddress */
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        /* Knuth's multiplicative method */
        u8 o = a->macaddr.addr[i];
        seed += (o*2654435761) % UINT32_MAX;
    }
    srand(seed);

    for (u32 i = 0, try0 = (((u32)rand()) % count) + start; i < count; ++i, try0 = (((try0 - start) + 1) % count) + start) {
        ip4_address_t n_try = {.addr = {htonl(try0)}};

        if (find_assignment_by_ipaddr(packet_process, n_try))
            continue;

        assigned = dhcpv4_insert_assignment(packet_process, a, n_try);/*动态IP*/
        if (assigned) {
            x_log_debug("接入服务[分配地址]: 动态IP地址 "IPV4FMT" (try %u of %u).", IPV4BYTES(a->addr), i + 1, count);
            return true;
        }
    }

    return false;
}

PRIVATE struct vdhcpd_assignment *dhcpv4_lease(packet_process_t *packet_process, enum dhcpv4_msg msgcode)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    dhcpd_server_stats_t *server_stats = dhcpd_server->server_stats;
    dhcp_packet_t *request = &packet_process->request;

    struct vdhcpd_assignment *a = find_assignment_by_macaddr(packet_process, packet_process->macaddr);
    dhcpd_staticlease_t *staticlease = dhcpd_server_staticlease_search_macaddr(dhcpd_server, packet_process->macaddr, 4);
    time_t now = vdhcpd_time();

    if (staticlease && a && BCMP(&staticlease->u.v4.ipaddr, &a->ipaddr, sizeof(ip4_address_t))) {
        free_assignment(a);
        a = NULL;
    }

    //coolriolee
    //    if (a && (a->flags & OAF_BOUND) && a->fr_ip) {
    //        *fr_serverid = a->fr_ip->addr.addr.in.s_addr;
    //        dhcpv4_fr_stop(a);
    //    }

    if (msgcode == DHCPV4_MSG_DISCOVER || msgcode == DHCPV4_MSG_REQUEST) {//租约申请/续租
        bool assigned = !!a;

        if (!a) {
            if (1/*!iface->no_dynamic_dhcp*/ || staticlease) {
                /* Create new binding */
                a = alloc_assignment(dhcpd_server->server_stats, 0);
                assert(a);
                BCOPY(&packet_process->macaddr, &a->macaddr, sizeof(mac_address_t));
                /* Set valid time to 0 for static lease indicating */
                /* infinite lifetime otherwise current time        */
                a->leasetime = dhcpd_server->leasetime;
                a->valid_until = now;
                a->dhcp_free_cb = dhcpv4_free_assignment;
                a->flags = OAF_DHCPV4;
                if (staticlease) {
                    a->flags |= OAF_STATIC;
                    a->ipaddr = staticlease->u.v4.ipaddr;
                    a->gateway = staticlease->u.v4.gateway;
                    a->valid_until = 0;//静态租约
                    //if (staticlease->leasetime)
                    //    a->leasetime = staticlease->leasetime;
                }

                assigned = dhcpv4_assign(packet_process, a, request->v4.reqaddr);
            }
        } else if ((IPv4_SUBNET(&a->addr, &dhcpd_server->dhcpv4.netmask) != IPv4_SUBNET(&dhcpd_server->dhcpv4.startip, &dhcpd_server->dhcpv4.netmask)) && !(a->flags & OAF_STATIC)) {
            //动态租约终端且与接入服务网段不匹配
            dhcpd_server_stats_lock(server_stats);
            list_del_init(&a->head);
            dhcpd_server_stats_unlock(server_stats);
            a->addr.address = INADDR_ANY;
            assigned = dhcpv4_assign(packet_process, a, request->v4.reqaddr);
        }

        if (assigned) {
            u32 my_leasetime = a->leasetime ? a->leasetime:dhcpd_server->leasetime;
            if ((request->v4.leasetime == 0) || (my_leasetime < request->v4.leasetime))
                request->v4.leasetime = my_leasetime;

            if (msgcode == DHCPV4_MSG_DISCOVER) {
                a->flags &= ~OAF_BOUND;
                request->v4.incl_fr_opt = request->v4.accept_fr_nonce;
                a->valid_until = now + MIN_RELEASE_INTERVAL;
            } else {
                if (!(a->flags & OAF_BOUND)) {
                    a->accept_fr_nonce = request->v4.accept_fr_nonce;
                    request->v4.incl_fr_opt = request->v4.accept_fr_nonce;
                    vdhcpd_urandom(a->key, sizeof(a->key));
                    a->flags |= OAF_BOUND;
                } else
                    request->v4.incl_fr_opt = false;

                a->valid_until = ((request->v4.leasetime == UINT32_MAX) ? 0 : (time_t)(now + request->v4.leasetime));
            }
        } else if (!assigned && a) {
            /* Cleanup failed assignment */
            free_assignment(a);
            a = NULL;
        }
    } else if (msgcode == DHCPV4_MSG_RELEASE && a) {//租约释放
        a->flags &= ~OAF_BOUND;
        a->valid_until = now + MIN_RELEASE_INTERVAL;
    } else if (msgcode == DHCPV4_MSG_DECLINE && a) {//租约拒绝
        a->flags &= ~OAF_BOUND;
        if (!(a->flags & OAF_STATIC) || !IPv4_IS_EQUAL(&a->ipaddr, &a->addr)) {//分配的IP与静态租约不符
            BZERO(&a->macaddr, sizeof(mac_address_t));
            a->valid_until = now + 3600; /* Block address for 1h */
        } else
            a->valid_until = now + MIN_RELEASE_INTERVAL;
    }

    return a;
}

PUBLIC int server4_process(packet_process_t *packet_process)
{
    realtime_info_t *realtime_info = packet_process->realtime_info;
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    ip4_address_t serverid = dhcpd_server->dhcpv4.gateway;
    dhcp_packet_t *request = &packet_process->request;
    dhcp_packet_t *reply = &packet_process->reply;
    struct dhcpv4_message *req = request->payload;
    const u8 reqmsg = request->v4.msgcode;
    struct vdhcpd_assignment *a = NULL;

    struct dhcpv4_message rep = {
        .op = DHCPV4_BOOTREPLY,
                .htype = req->htype,
                .hlen = req->hlen,
                .hops = 0,
                .xid = req->xid,
                .secs = 0,
                .flags = req->flags,
                .ciaddr = {.addr = {INADDR_ANY}},
                .giaddr = req->giaddr,
                .siaddr = dhcpd_server->dhcpv4.gateway,
    };
    BCOPY(req->chaddr, rep.chaddr, sizeof(rep.chaddr));
    rep.options[0] = 0x63;
    rep.options[1] = 0x82;
    rep.options[2] = 0x53;
    rep.options[3] = 0x63;
    u8 *cookie = &rep.options[4];
    reply->v4.msgcode = DHCPV4_MSG_ACK;

    if (reqmsg != DHCPV4_MSG_DISCOVER && reqmsg != DHCPV4_MSG_REQUEST && reqmsg != DHCPV4_MSG_INFORM
            && reqmsg != DHCPV4_MSG_DECLINE && reqmsg != DHCPV4_MSG_RELEASE)
        return -1;

    //租约校验/分配
    if (reqmsg != DHCPV4_MSG_INFORM)
        a = dhcpv4_lease(packet_process, reqmsg);

    if (!a) {
        if (reqmsg == DHCPV4_MSG_REQUEST) reply->v4.msgcode = DHCPV4_MSG_NAK;
        else if (reqmsg == DHCPV4_MSG_DISCOVER) return -1;
    } else if (reqmsg == DHCPV4_MSG_DISCOVER) {
        reply->v4.msgcode = DHCPV4_MSG_OFFER;
    } else if (reqmsg == DHCPV4_MSG_REQUEST && ((request->v4.reqaddr.address && !IPv4_IS_EQUAL(&request->v4.reqaddr, &a->addr)) ||
              (req->ciaddr.address && !IPv4_IS_EQUAL(&req->ciaddr, &a->addr)))) {
        reply->v4.msgcode = DHCPV4_MSG_NAK;
        /*
         * DHCP client requested an IP which we can't offer to him. Probably the
         * client changed the network or the network has been changed. The reply
         * type is set to DHCPV4_MSG_NAK, because the client should not use that IP.
         *
         * For modern devices we build an answer that includes a valid IP, like
         * a DHCPV4_MSG_ACK. The client will use that IP and doesn't need to
         * perform additional DHCP round trips.
         *
         */

        /*
         *
         * Buggy clients do serverid checking in nack messages; therefore set the
         * serverid in nack messages triggered by a previous force renew equal to
         * the server id in use at that time by the server
         *
         */
        if (request->v4.fr_serverid.address)
            serverid = request->v4.fr_serverid;

        //请求地址与子网不匹配
        if (req->ciaddr.address && (IPv4_SUBNET(&dhcpd_server->dhcpv4.startip, &dhcpd_server->dhcpv4.netmask) != IPv4_SUBNET(&req->ciaddr, &dhcpd_server->dhcpv4.netmask)))
            req->ciaddr.address = INADDR_ANY;
    }

    if (reqmsg == DHCPV4_MSG_DECLINE || reqmsg == DHCPV4_MSG_RELEASE)
        return 0;//

    //响应报文
    dhcpv4_put(&rep, &cookie, DHCPV4_OPT_MESSAGE, 1, &reply->v4.msgcode);
    dhcpv4_put(&rep, &cookie, DHCPV4_OPT_SERVERID, 4, &serverid);

    if (a) {
        u32 val;
        rep.yiaddr = a->addr;
        val = htonl(request->v4.leasetime);
        dhcpv4_put(&rep, &cookie, DHCPV4_OPT_LEASETIME, 4, &val);

        if (request->v4.leasetime != UINT32_MAX) {
            val = htonl(500 * request->v4.leasetime / 1000);
            dhcpv4_put(&rep, &cookie, DHCPV4_OPT_RENEW, 4, &val);

            val = htonl(875 * request->v4.leasetime / 1000);
            dhcpv4_put(&rep, &cookie, DHCPV4_OPT_REBIND, 4, &val);
        }

        dhcpv4_put(&rep, &cookie, DHCPV4_OPT_HOSTNAME, realtime_info->v4.hostname_len, realtime_info->v4.hostname);//设备主机名称

        realtime_info->v4.leasetime = request->v4.leasetime;
        realtime_info->v4.ipaddr = rep.yiaddr;
        if (reply->v4.msgcode == DHCPV4_MSG_ACK) {
            SET_COUNTER(realtime_info->updatetick);
            realtime_info->flags |= RLTINFO_FLAGS_SERVER4;
            if (a->flags & OAF_STATIC) realtime_info->flags |= RLTINFO_FLAGS_STATIC4;
            else realtime_info->flags |= ~RLTINFO_FLAGS_STATIC4;
            __sync_fetch_and_add(&realtime_info->update_db4, 1);
        }
    }

    if (dhcpd_server->iface.mtu) {
        u16 mtu = htons(dhcpd_server->iface.mtu);
        dhcpv4_put(&rep, &cookie, DHCPV4_OPT_MTU, 2, &mtu);//MTU
    }

    dhcpv4_put(&rep, &cookie, DHCPV4_OPT_ROUTER, 4, &dhcpd_server->dhcpv4.gateway);//网关地址

    dhcpv4_put(&rep, &cookie, DHCPV4_OPT_NETMASK, 4, &dhcpd_server->dhcpv4.netmask);//子网掩码地址

    if (dhcpd_server->dhcpv4.broadcast.address != INADDR_ANY)
        dhcpv4_put(&rep, &cookie, DHCPV4_OPT_BROADCAST, 4, &dhcpd_server->dhcpv4.broadcast);//局域网广播地址

    dhcpv4_put(&rep, &cookie, DHCPV4_OPT_DNSSERVER, 8, &dhcpd_server->dhcpv4.dns);//DNS服务器地址

    dhcpv4_put(&rep, &cookie, DHCPV4_OPT_END, 0, NULL);

    struct sockaddr_in dest = { .sin_family = AF_INET,
                .sin_addr.s_addr = request->iphdr->saddr,
                .sin_port = request->udphdr->source,};
    if (req->giaddr.address) {
        /* relay agent is configured, send reply to the agent */
        dest.sin_addr = req->giaddr.addr;
        dest.sin_port = htons(DHCPV4_SERVER_PORT);
    } else if (req->ciaddr.address && req->ciaddr.address != dest.sin_addr.s_addr) {
        /* client has existing configuration (ciaddr is set) AND this address is not the address it used for the dhcp message */
        dest.sin_addr = req->ciaddr.addr;
        dest.sin_port = htons(DHCPV4_CLIENT_PORT);
    } else if (DHCPV4_FLAGS_BROADCAST(req) || req->hlen != rep.hlen || !rep.yiaddr.address) {
        /* client requests a broadcast reply OR we can't offer an IP */
        dest.sin_addr.s_addr = INADDR_BROADCAST;
        dest.sin_port = htons(DHCPV4_CLIENT_PORT);
    } else if (!req->ciaddr.address && reply->v4.msgcode == DHCPV4_MSG_NAK) {
        /* client has no previous configuration -> no IP, so we need to reply with a broadcast packet */
        dest.sin_addr.s_addr = INADDR_BROADCAST;
        dest.sin_port = htons(DHCPV4_CLIENT_PORT);
    } else {
//        struct arpreq arp = {.arp_flags = ATF_COM};
        /* send reply to the newly (in this proccess) allocated IP */
        dest.sin_addr = rep.yiaddr.addr;
        dest.sin_port = htons(DHCPV4_CLIENT_PORT);
//        memcpy(arp.arp_ha.sa_data, req->chaddr, 6);
//        memcpy(&arp.arp_pa, &dest, sizeof(arp.arp_pa));
//        memcpy(arp.arp_dev, iface->ifname, sizeof(arp.arp_dev));
//        if (ioctl(sock, SIOCSARP, &arp) < 0)
//            syslog(LOG_ERR, "ioctl(SIOCSARP): %m");
    }

    reply->payload = &rep;
    reply->payload_len = PACKET4_SIZE(&rep, cookie);
    return server4_send_reply_packet(packet_process, reply, dest);
}

PRIVATE int server4_send_reply_packet(packet_process_t *packet_process, dhcp_packet_t *packet, const struct sockaddr_in dest)
{
    dhcpd_server_t *dhcpd_server = packet_process->dhcpd_server;
    realtime_info_t *realtime_info = packet_process->realtime_info;
    struct dhcpv4_message *rep = packet->payload;

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
    BCOPY(packet->payload, payload, packet->payload_len);
    length += packet->payload_len;

    //封装UDP Header
    length += sizeof(struct udphdr);
    pUDPHeader->len = htons(length);
    pUDPHeader->dest = dest.sin_port;
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
    pIPHeader->daddr = dest.sin_addr.s_addr;
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

    packet_save_log(packet_process, (struct dhcpv4_message *)packet->payload, packet->v4.msgcode, "发送报文[v4服务][C]");
    ipc_send_data(packet_process, buffer, length);
}
