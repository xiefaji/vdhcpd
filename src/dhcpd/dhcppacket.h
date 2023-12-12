#ifndef _dhcp_dhcppacket_h
#define _dhcp_dhcppacket_h

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdbool.h>

#include "dhcpd/dhcpv4.h"
#include "dhcpd/dhcpv6.h"
#include "share/defines.h"
#include "share/types.h"

struct interface_id_t {
    u16 driveid;
    u16 lineid;
    u32 serverid;
} __attribute__((packed));

typedef struct {
    struct ether_header *ethhdr;
    struct iphdr *iphdr;
    struct ip6_hdr *ip6hdr;
    struct udphdr *udphdr;
    void *payload;//原始报文
    void *relay_payload;//中继响应负载[V4/V6][响应给客户端内容]
    u16 l3len,l4len,payload_len,relay_payload_len;

    union {
        struct {
            enum dhcpv4_msg msgcode;
            ip4_address_t reqaddr;//客户端请求的固定IP地址
            ip4_address_t badipaddr;//被占用地址 netbit
            u32 leasetime;//客户端请求的租约时长
            bool accept_fr_nonce;
            bool incl_fr_opt;
            ip4_address_t fr_serverid;
        } v4;
        struct {
            enum dhcpv6_msg msgcode;
            struct interface_id_t interfaceid;
            ip6_address_t reqaddr;//客户端请求的固定IP地址
            ip6_address_t ipaddr;//分配给客户端的IP地址
            u32 leasetime;//客户端请求的租约时长
            u32 preferred;//hostbit
            u32 iaid;//netbit
        } v6;
    };
} dhcp_packet_t;

#endif
