#ifndef _dhcp_staticlease_h
#define _dhcp_staticlease_h

#include "share/defines.h"
#include "share/types.h"
#include "share/array/trashqueue.h"

typedef union {
    struct {
        mac_address_t macaddr;
        u16 reserve;
    } u;
    u64 key_value;
} lease_key_t;

//静态租约
typedef struct {
    u32 nID;
    u32 nLineID;
    lease_key_t key;
    char szName[MINNAMELEN+1];
    union {
        struct {
            ip4_address_t ipaddr;
            ip4_address_t gateway;
        } v4;//netbit

        struct {
            ip6_address_t ipaddr;
            ip6_address_t gateway;
        } v6;//netbit
    } u;
} dhcpd_staticlease_t;
PUBLIC_DATA dhcpd_staticlease_t *dhcpd_staticlease_init();
PUBLIC_DATA void dhcpd_staticlease_release(void *p);
PUBLIC_DATA void dhcpd_staticlease_recycle(void *p, trash_queue_t *pRecycleTrash);

typedef struct {
    struct key_tree key_staticlease4;//静态租约[ipv4]
    struct key_tree key_staticlease4_ip;
    struct key_tree key_staticlease4_mac;
    struct key_tree key_staticlease6;//静态租约[ipv6]
    struct key_tree key_staticlease6_mac;
} dhcpd_lease_main_t;
PUBLIC_DATA dhcpd_lease_main_t *dhcpd_lease_main_init();
PUBLIC_DATA void dhcpd_lease_main_release(void *p);
PUBLIC_DATA void dhcpd_lease_main_recycle(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA void dhcpd_lease_main_reload(dhcpd_lease_main_t *staticlease_main, const u32 serverid);
PUBLIC_DATA void dhcpd_lease_main_check(dhcpd_lease_main_t *staticlease_main);
PUBLIC_DATA void dhcpd_lease_main_rebind(u16 nLineID,u32 lineid,int stack);
PUBLIC_DATA dhcpd_staticlease_t *staticlease_search4_macaddr(dhcpd_lease_main_t *staticlease_main, const mac_address_t macaddr);
PUBLIC_DATA dhcpd_staticlease_t *staticlease_search4_ipaddr(dhcpd_lease_main_t *staticlease_main, const ip4_address_t ipaddr/*netbit*/);
PUBLIC_DATA dhcpd_staticlease_t *staticlease_search6_macaddr(dhcpd_lease_main_t *staticlease_main, const mac_address_t macaddr);
PUBLIC_DATA dhcpd_staticlease_t *staticlease_search6_ipaddr(dhcpd_lease_main_t *staticlease_main, const ip6_address_t ipaddr/*netbit*/);
#endif
