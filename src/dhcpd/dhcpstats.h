#ifndef _dhcp_stats_h
#define _dhcp_stats_h

#include "share/defines.h"
#include "share/types.h"
#include "share/list/listdemo.h"
#include "public/rbtree_common.h"

#define INFINITE_VALID(x) ((x) == 0)

//服务状态列表
typedef struct {
    u32 serverid;
    //实时租约信息
    struct list_head dhcpv4_assignments;
    struct list_head dhcpv6_assignments;
#ifdef USE_SPIN_LOCK
    pthread_spinlock_t lock;
#else
    int mutex;// = 0;
#endif
} dhcpd_server_stats_t;
#ifdef USE_SPIN_LOCK
#define dhcpd_server_stats_init_lock(p) {pthread_spin_init(&(p)->lock,0);  }
#define dhcpd_server_stats_destroy_lock(p) { pthread_spin_destroy(&(p)->lock); }
#define dhcpd_server_stats_unlock(p)  { pthread_spin_unlock(&(p)->lock); }
#define dhcpd_server_stats_lock(p)     { pthread_spin_lock(&(p)->lock); }
#else
#define dhcpd_server_stats_init_lock(p) { (p)->mutex = 0;}
#define dhcpd_server_stats_destroy_lock(p) {}
#define dhcpd_server_stats_unlock(p)  {__sync_bool_compare_and_swap(&(p)->mutex,1,0);}
#define dhcpd_server_stats_lock(p)     { while (!(__sync_bool_compare_and_swap (&(p)->mutex,0, 1) )) {sched_yield();} smp_rmb();}
#endif

enum vdhcpd_assignment_flags {
    OAF_TENTATIVE		= (1 << 0),
    OAF_BOUND		= (1 << 1),
    OAF_STATIC		= (1 << 2),
    OAF_BROKEN_HOSTNAME	= (1 << 3),
    OAF_DHCPV4		= (1 << 4),
    OAF_DHCPV6_NA		= (1 << 5),
    OAF_DHCPV6_PD		= (1 << 6),
};

struct vdhcpd_assignment {
    struct list_head head;
    dhcpd_server_stats_t *server_stats;

    //基础参数
    mac_address_t macaddr;//终端物理地址
    ip4_address_t ipaddr;//主机地址[netbit]
    ip4_address_t netmask;//子网掩码[netbit]
    ip4_address_t gateway;//网关地址[netbit]
    ip4_address_t broadcast;//广播地址[netbit]

    ip6_address_t ipaddr6;//请求的静态ip
    u64 hostid;//静态租约[V6]
    u32 nAreaID;//当前接入区域节点ID
    u16 vlanid,qinqid;//终端VLAN/QINQ hostbit

    void (*dhcp_free_cb)(struct vdhcpd_assignment *a);

    struct sockaddr_in6 peer;
    volatile time_t valid_until;//
    volatile time_t preferred_until;

//#define fr_timer	reconf_timer
//    struct uloop_timeout reconf_timer;
#define accept_fr_nonce accept_reconf
    bool accept_reconf;
//#define fr_cnt		reconf_cnt
//    int reconf_cnt;
    u8 key[16];
//    struct odhcpd_ref_ip *fr_ip;

    //实际终端IP[IPv4/IPv6]
    ip4_address_t addr;
    ip6_address_t addr6;
    union {
        u64 assigned_host_id;
        u32 assigned_subnet_id;
    };
    u32 iaid;
    u8 length; // length == 128 -> IA_NA, length <= 64 -> IA_PD

//    struct odhcpd_ipaddr *managed;
    ssize_t managed_size;
//    struct ustream_fd managed_sock;

    u32 flags;
    u32 leasetime;
    char *hostname;
    char *reqopts;
//#define hwaddr		mac
//    u8 mac[ETH_ALEN];

    u16 clid_len;
    u8 clid_data[];
};

ALWAYS_INLINE struct vdhcpd_assignment *alloc_assignment(dhcpd_server_stats_t *server_stats, size_t extra_len)
{
    struct vdhcpd_assignment *a = calloc(1, sizeof(struct vdhcpd_assignment) + extra_len);
    if (!a) return NULL;
    INIT_LIST_HEAD(&a->head);
    a->server_stats = server_stats;
    a->addr.address = INADDR_ANY;
    return a;
}

ALWAYS_INLINE void free_assignment(void *p)
{
    struct vdhcpd_assignment *a = (struct vdhcpd_assignment *)p;
    if (a) {
        dhcpd_server_stats_lock(a->server_stats);
        list_del(&a->head);
        dhcpd_server_stats_unlock(a->server_stats);
        if (a->dhcp_free_cb) a->dhcp_free_cb(a);
        xfree(a->hostname);
        xfree(a->reqopts);
        xfree(a);
    }
}

ALWAYS_INLINE void recycle_assignment(void *p, trash_queue_t *pRecycleTrash)
{
    struct vdhcpd_assignment *a = (struct vdhcpd_assignment *)p;
    if (a) {
        dhcpd_server_stats_lock(a->server_stats);
        list_del(&a->head);
        dhcpd_server_stats_unlock(a->server_stats);
        if (a->dhcp_free_cb) a->dhcp_free_cb(a);
        if (a->hostname) trash_queue_enqueue(pRecycleTrash, a->hostname);
        if (a->reqopts) trash_queue_enqueue(pRecycleTrash,a->reqopts);
        trash_queue_enqueue(pRecycleTrash, a);
    }
}

PUBLIC_DATA void server_stats_main_init();
PUBLIC_DATA void server_stats_main_release();
PUBLIC_DATA void server_stats_main_maintain();
PUBLIC_DATA dhcpd_server_stats_t *server_stats_find(const u32 serverid);
PUBLIC_DATA void server_stats_release_lease(dhcpd_server_stats_t *server_stats, const mac_address_t macaddr, const int ipv4);

#endif
