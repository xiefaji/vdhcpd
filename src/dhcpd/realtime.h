#ifndef _dhcp_realtimie_h
#define _dhcp_realtimie_h

#include "share/defines.h"
#include "share/types.h"

typedef union {
    u64 key_value;
    struct {
        mac_address_t macaddr;//终端MAC地址
        u16 reserve;
    } u;
} realtime_key_t;

typedef struct {
    realtime_key_t key;//61
    u32 lineid;
    u16 ovlanid,ivlanid;//VLAN/QINQ hostbit
    u16 sessionid;
    struct {
        ip4_address_t ipaddr;//客户端IP地址 netbit
        char hostname[MAXNAMELEN+1];//12
        char reqopts[MAXNAMELEN+1];//55
        char vendorname[MAXNAMELEN+1];//60
        char clientidentifier[MAXNAMELEN+1];//61
        char userclass[MAXNAMELEN+1];//77
        u32 hostname_len,reqopts_len,vendorname_len,clientidentifier_len,userclass_len;
        u16 max_message_size;//57 netbit
        u16 max_message_size_len;
        u32 leasetime;//租约时长
    } v4;
    struct {
        ip6_address_t ipaddr;//客户端IP地址 netbit
        char duid[MAXNAMELEN+1];
        char hostname[MAXNAMELEN+1];//12
        char reqopts[MAXNAMELEN+1];//55
        char vendorname[MAXNAMELEN+1];//60
        char clientidentifier[MAXNAMELEN+1];//61
        char userclass[MAXNAMELEN+1];//77
        u32 duid_len,hostname_len,reqopts_len,vendorname_len,clientidentifier_len,userclass_len;
        u16 max_message_size;//57 netbit
        u16 max_message_size_len;
        u32 leasetime;//租约时长
    } v6;

    time_t starttime;
#define RLTINFO_FLAGS_RELAY4 (1 << 0)
#define RLTINFO_FLAGS_RELAY6 (1 << 1)
#define RLTINFO_FLAGS_SERVER4 (1 << 2)
#define RLTINFO_FLAGS_SERVER6 (1 << 3)
#define RLTINFO_FLAGS_STATIC4 (1 << 4)
#define RLTINFO_FLAGS_STATIC6 (1 << 5)
    u32 flags;
    u32 update_db4,update_db6;
    u32 warning;
    struct key_tree key_tickcount;
} realtime_info_t;
#define RLTINFO_IS_RELAY4(r) (((r)->flags & RLTINFO_FLAGS_RELAY4) ? 1:0)
#define RLTINFO_IS_RELAY6(r) (((r)->flags & RLTINFO_FLAGS_RELAY6) ? 1:0)
#define RLTINFO_IS_SERVER4(r) (((r)->flags & RLTINFO_FLAGS_SERVER4) ? 1:0)
#define RLTINFO_IS_SERVER6(r) (((r)->flags & RLTINFO_FLAGS_SERVER6) ? 1:0)
#define RLTINFO_IS_STATIC4(r) (((r)->flags & RLTINFO_FLAGS_STATIC4) ? 1:0)
#define RLTINFO_IS_STATIC6(r) (((r)->flags & RLTINFO_FLAGS_STATIC6) ? 1:0)
#define RLTINFO_EXPIRETIME4(r) (u32)((r)->v4.leasetime ? ((r)->v4.leasetime + (u32)time(NULL)):0)
#define RLTINFO_EXPIRETIME6(r) (u32)((r)->v6.leasetime ? ((r)->v6.leasetime + (u32)time(NULL)):0)
PUBLIC_DATA void realtime_info_oth_update(realtime_info_t *realtime_info, const int ipv4);
PUBLIC_DATA realtime_info_t *realtime_search(void *p);
PUBLIC_DATA realtime_info_t *realtime_search_macaddr(const mac_address_t macaddr);
PUBLIC_DATA realtime_info_t *realtime_search_duid(const u8 *clientidentifier, const u32 len);
PUBLIC_DATA realtime_info_t *realtime_find(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA size_t realtime_info_finger(realtime_info_t *realtime_info, char *finger, const size_t size);
PUBLIC_DATA size_t realtime_info_finger_md5(realtime_info_t *realtime_info, char *finger_md5, const size_t size);

ALWAYS_INLINE int realtime_info_duid_cmp(const void *a, const void *b)
{
    realtime_info_t *pA = (realtime_info_t *)a;
    realtime_info_t *pB = (realtime_info_t *)b;
    return BCMP(pA->v6.duid, pB->v6.duid, MAXNAMELEN);
}

typedef struct {
    struct key_tree key_realtime;//实时信息
    struct set_tree set_realtime_duid;//DUID[ipv6]
} vdhcpd_stats_t;
PUBLIC_DATA void stats_main_init(vdhcpd_stats_t *stats_main);
PUBLIC_DATA void stats_main_release(vdhcpd_stats_t *stats_main);
PUBLIC_DATA void stats_main_maintain(vdhcpd_stats_t *stats_main, trash_queue_t *pRecycleTrash);
#endif
