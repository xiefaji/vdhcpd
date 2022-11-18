#ifndef _dhcp_dhcppacket_h
#define _dhcp_dhcppacket_h

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "share/defines.h"
#include "share/types.h"

typedef struct {
    struct ether_header *ethhdr;
    struct iphdr *iphdr;
    struct ip6_hdr *ip6hdr;
    struct udphdr *udphdr;
    void *payload;
    u16 l3len,l4len,payload_len;

    struct {
        enum dhcpv4_msg reqmsg;
        ip4_address_t reqaddr;//客户端请求的固定IP地址
        ip4_address_t badipaddr;//被占用地址 netbit
        u32 leasetime;//客户端请求的租约时长
        bool accept_fr_nonce;
        bool incl_fr_opt;
        ip4_address_t fr_serverid;
    } v4;
    struct {

    } v6;

} dhcp_packet_t;

#endif
