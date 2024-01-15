#ifndef _VDHCPD_V4_H
#define _VDHCPD_V4_H

#pragma once
#include "share/defines.h"
#include "share/types.h"

#define DHCPV4_CLIENT_PORT 68
#define DHCPV4_SERVER_PORT 67

#define DHCPV4_FLAG_BROADCAST  0x8000
#define DHCPV4_MIN_PACKET_SIZE 300
//租约默认释放延迟
#define MIN_RELEASE_INTERVAL 30

enum dhcpv4_op {
    DHCPV4_BOOTREQUEST = 1,
    DHCPV4_BOOTREPLY = 2
};

enum dhcpv4_msg {
    DHCPV4_MSG_DISCOVER = 1,
    DHCPV4_MSG_OFFER = 2,
    DHCPV4_MSG_REQUEST = 3,
    DHCPV4_MSG_DECLINE = 4,
    DHCPV4_MSG_ACK = 5,
    DHCPV4_MSG_NAK = 6,
    DHCPV4_MSG_RELEASE = 7,
    DHCPV4_MSG_INFORM = 8,
    DHCPV4_MSG_FORCERENEW = 9,
};

enum dhcpv4_opt {
    DHCPV4_OPT_PAD = 0,
    DHCPV4_OPT_NETMASK = 1,
    DHCPV4_OPT_ROUTER = 3,
    DHCPV4_OPT_DNSSERVER = 6,
    DHCPV4_OPT_HOSTNAME = 12,
    DHCPV4_OPT_DOMAIN = 15,
    DHCPV4_OPT_REQUEST = 17,
    DHCPV4_OPT_MTU = 26,
    DHCPV4_OPT_BROADCAST = 28,
    DHCPV4_OPT_NTPSERVER = 42,
    DHCPV4_OPT_IPADDRESS = 50,
    DHCPV4_OPT_LEASETIME = 51,
    DHCPV4_OPT_MESSAGE = 53,
    DHCPV4_OPT_SERVERID = 54,
    DHCPV4_OPT_REQOPTS = 55,
    DHCPV4_OPT_MAXMESSAGE_SIZE = 57,
    DHCPV4_OPT_RENEW = 58,
    DHCPV4_OPT_REBIND = 59,
    DHCPV4_OPT_VENDOR_CLASS_IDENTIFIER = 60,
    DHCPV4_OPT_CLIENT_IDENTIFIER = 61,
    DHCPV4_OPT_USER_CLASS = 77,
    DHCPV4_OPT_CLIENT_FULLY_QUALIFIED_DOMAIN_NAME = 81,
    DHCPV4_OPT_AGENT_INFORMATION = 82,
    DHCPV4_OPT_AUTHENTICATION = 90,
    DHCPV4_OPT_SEARCH_DOMAIN = 119,
    DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE = 145,
    DHCPV4_OPT_END = 255,
};

struct dhcpv4_message {
    u8 op;
    u8 htype;
    u8 hlen;
    u8 hops;
    u32 xid;
    u16 secs;
    u16 flags;
    ip4_address_t ciaddr;//客户端请求IP
    ip4_address_t yiaddr;//服务器分配给客户端IP
    ip4_address_t siaddr;//服务器地址
    ip4_address_t giaddr;//中继服务器地址
    u8 chaddr[16];
    char sname[64];
    char file[128];
    u8 options[312];
};
#define DHCPV4_FLAGS_BROADCAST(p) (ntohs((p)->flags) & DHCPV4_FLAG_BROADCAST)
//struct dhcpv4_auth_forcerenew {
//    u8 protocol;
//    u8 algorithm;
//    u8 rdm;
//    u32 replay[2];
//    u8 type;
//    u8 key[16];
//} __attribute__((packed));

struct dhcpv4_option {
    u8 type;
    u8 len;
    u8 data[0];
};


#define dhcpv4_for_each_option(start, end, opt)\
    for (opt = (struct dhcpv4_option *)(start); \
    &opt[1] <= (struct dhcpv4_option *)(end) && \
    &opt->data[opt->len] <= (end); \
    opt = (struct dhcpv4_option *)&opt->data[opt->len])

typedef union {
    u32 value;
    struct {
        u16 qinqid;
        u16 vlanid;
    } u;
} dhcpv4_option_vlan_t;

#endif
