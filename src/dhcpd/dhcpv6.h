#ifndef _VDHCPD_V6_H
#define _VDHCPD_V6_H

#pragma once
#include "share/defines.h"
#include "share/types.h"

#define ALL_DHCPV6_RELAYS "ff02::1:2"

#define ALL_DHCPV6_SERVERS "ff05::1:3"

#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

#define DHCPV6_MIN_PACKET_SIZE 100

enum dhcpv6_msg {
    DHCPV6_MSG_SOLICIT=1,
    DHCPV6_MSG_ADVERTISE=2,
    DHCPV6_MSG_REQUEST=3,
    DHCPV6_MSG_CONFIRM=4,
    DHCPV6_MSG_RENEW=5,
    DHCPV6_MSG_REBIND=6,
    DHCPV6_MSG_REPLY=7,
    DHCPV6_MSG_RELEASE=8,
    DHCPV6_MSG_DECLINE=9,
    DHCPV6_MSG_RECONFIGURE=10,
    DHCPV6_MSG_INFORMATION_REQUEST=11,
    DHCPV6_MSG_RELAY_FORW=12,
    DHCPV6_MSG_RELAY_REPL=13,
    DHCPV6_MSG_DHCPV4_QUERY=20,
    DHCPV6_MSG_DHCPV4_RESPONSE=21
};

#define DHCPV6_OPT_CLIENTID 1
#define DHCPV6_OPT_SERVERID 2
#define DHCPV6_OPT_IA_NA 3
#define DHCPV6_OPT_IA_ADDR 5
#define DHCPV6_OPT_ORO 6
#define DHCPV6_OPT_STATUS 13
#define DHCPV6_OPT_RELAY_MSG 9
#define DHCPV6_OPT_AUTH 11
#define DHCPV6_OPT_RAPID_COMMIT 14
#define DHCPV6_OPT_USER_CLASS 15
#define DHCPV6_OPT_VENDOR_CLASS 16
#define DHCPV6_OPT_INTERFACE_ID 18
#define DHCPV6_OPT_RECONF_MSG 19
#define DHCPV6_OPT_RECONF_ACCEPT 20
#define DHCPV6_OPT_DNS_SERVERS 23
#define DHCPV6_OPT_DNS_DOMAIN 24
#define DHCPV6_OPT_IA_PD 25
#define DHCPV6_OPT_IA_PREFIX 26
#define DHCPV6_OPT_SNTP_SERVERS 31
#define DHCPV6_OPT_LIFETIME 32
#define DHCPV6_OPT_REMOTE_ID 37
#define DHCPV6_OPT_FQDN 39
#define DHCPV6_OPT_NTP_SERVERS 56
#define DHCPV6_OPT_SOL_MAX_RT 82
#define DHCPV6_OPT_INF_MAX_RT 83
#define DHCPV6_OPT_DHCPV4_MSG 87
#define DHCPV6_OPT_4O6_SERVER 88

#define DHCPV6_DUID_VENDOR 2

#define DHCPV6_STATUS_OK 0
#define DHCPV6_STATUS_NOADDRSAVAIL 2
#define DHCPV6_STATUS_NOBINDING 3
#define DHCPV6_STATUS_NOTONLINK 4
#define DHCPV6_STATUS_USEMULTICAST 5
#define DHCPV6_STATUS_NOPREFIXAVAIL 6

// I just remembered I have an old one lying around...
#define DHCPV6_ENT_NO  30462
#define DHCPV6_ENT_TYPE 1


#define DHCPV6_HOP_COUNT_LIMIT 32

#define DHCPV6_REC_TIMEOUT	2000 /* msec */
#define DHCPV6_REC_MAX_RC	8

struct dhcpv6_client_header {
    u8 msg_type;
    u8 transaction_id[3];
    u8 options[312];
} __attribute__((packed));

struct dhcpv6_relay_header {
    u8 msg_type;
    u8 hop_count;
    ip6_address_t link_address;
    ip6_address_t peer_address;
    u8 options[];
} __attribute__((packed));

struct dhcpv6_relay_forward_envelope {
    u8 msg_type;
    u8 hop_count;
    ip6_address_t link_address;
    ip6_address_t peer_address;
    u16 interface_id_type;
    u16 interface_id_len;
    u32 interface_id_data;
    u16 relay_message_type;
    u16 relay_message_len;
} __attribute__((packed));

struct dhcpv6_auth_reconfigure {
    u16 type;
    u16 len;
    u8 protocol;
    u8 algorithm;
    u8 rdm;
    u32 replay[2];
    u8 reconf_type;
    u8 key[16];
} __attribute__((packed));

/* DHCPV6_OPT_IA_PREFIX */
struct opt_ia_prefix {
    u16 type;
    u16 len;
    u32 preferred;
    u32 valid;
    u8 prefix;
    ip6_address_t addr;
} __attribute__((packed));

/* DHCPV6_OPT_IA_ADDR */
struct opt_ia_address {
    u16 type;
    u16 len;
    ip6_address_t addr;
    u32 preferred;
    u32 valid;
} __attribute__((packed));

/* DHCPV6_OPT_IA_NA/DHCPV6_OPT_IA_PD */
struct opt_ia_hdr {
    u16 type;
    u16 len;
    u32 iaid;
    u32 t1;
    u32 t2;
    union {
        struct opt_ia_prefix ia_prefix;
        struct opt_ia_address ia_addr;
    } u;
} __attribute__((packed));

struct opt_cer_id {
    u16 type;
    u16 len;
    u16 reserved;
    u16 auth_type;
    u8 auth[16];
    ip6_address_t addr;
};

struct dhcpv6_option {
    u16 type;
    u16 len;
    u8 data[0];
} __attribute__((packed));

struct domian_search_list {
   u8 list_entry[12];
};

#define dhcpv6_for_each_option(start, end, otype, olen, odata)\
    for (u8 *_o = (u8 *)(start); _o + 4 <= (end) &&\
    ((otype) = _o[0] << 8 | _o[1]) && ((odata) = (void *)&_o[4]) &&\
    ((olen) = _o[2] << 8 | _o[3]) + (odata) <= (end); \
    _o += 4 + (_o[2] << 8 | _o[3]))

#endif
