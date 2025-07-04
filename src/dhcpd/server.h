#ifndef _dhcp_server_h
#define _dhcp_server_h

#include "share/defines.h"
#include "share/rbtree/key_elem.h"
#include "share/types.h"
#include "share/bitmap/bitmap_exactvlan.h" 
#include "share/array/trashqueue.h"
#include "acl.h"
#include "staticlease.h"

//服务模式
typedef enum {
    MODE_IPV4_RELAY = (1<<0),
    MODE_IPV6_RELAY = (1<<1),
    MODE_IPV4_SERVER = (1<<4),
    MODE_IPV6_SERVER = (1<<6),
    MODE_IPV6_SLAAC = (1<<7),
    MODE_IPV6_PD =(1<<10)
} dhcpd_mode_t;

//DHCP服务配置
typedef struct {
    u32 nID;
    u32 nLineID;
    u32 nEnabled;
    u32 leasetime;//租约时长 单位：秒
    dhcpd_mode_t mode;
    u8  exactvlan[MAXNAMELEN+1];
    PEXACTVLAN pEXACTVLAN;//精确VLAN匹配

    //线路配置信息
    struct {
        u32 driveid;
        char ifname[MINNAMELEN+1];
        u16 mtu;
        mac_address_t macaddr;
        ip4_address_t ipaddr;
        ip6_address_t ipaddr6;
        ip6_address_t ipaddr6_local;
        struct key_tree *key_all_lineip4;
    } iface;

    //DHCPV4配置
    struct {
        ip4_address_t startip;//IP分配范围：启始IP netbit
        ip4_address_t endip;//IP分配范围：结束IP netbit
        ip4_address_t gateway;//网关地址 netbit
        ip4_address_t netmask;//子网掩码 netbit
        ip4_address_t broadcast;//广播地址 netbit
        ip4_address_t dns[2];//DNS地址 netbit 
        ip4_address_t windns[2];//WINDNS地址 netbit
    } dhcpv4;

    //DHCPV6配置
    struct {
        ip6_address_t startip;//IP分配范围：启始IP netbit
        ip6_address_t endip;//IP分配范围：结束IP netbit
        ip6_address_t gateway;//网关地址 netbit
        u16 prefix;
        ip6_address_t dns[2];//DNS地址 netbit
        ip6_address_t prefix_addr;
    } dhcpv6;

    //DHCP中继配置
    struct {
        struct {
            ip4_address_t subnet;//子网识别 netbit
            ip4_address_t serverip;//服务器地址 netbit
            u16 serverport;//服务器端口 netbit
            u32 lineid;//出口线路ID
            volatile ip4_address_t lineip;//出口线路IP netbit
        } v4;
        struct {
            ip6_address_t serverip;//服务器地址 netbit
            u16 serverport;//服务器端口 netbit
            u32 lineid;//出口线路ID
            volatile ip6_address_t lineip;//出口线路IP netbit
        } v6;
        char identifier[MINNAMELEN+1];//中继标识
    } dhcprelay;
    struct {
        ip6_address_t gateway;
        u16 prefix;
        ip6_address_t dns[2];
        ip6_address_t prefix_addr;
        u32 leasetime;
    }SLAAC;
    //MAC控制
    struct {
        dhcpd_acl_t aclmode;
#define DEFAULT_ACLGROUP_SIZE 12
        u32 aclgroup[DEFAULT_ACLGROUP_SIZE];
    } macctl;

    //服务ID过滤
    struct key_tree key_serverid;
    dhcpd_lease_main_t *staticlease_main;//本服务静态租约
    void *cfg_main;//
    void *server_stats;//服务相关状态[实时租约信息]
} dhcpd_server_t;
#define ENABLE_IPV4_RELAY(s) ((s)->mode & MODE_IPV4_RELAY)
#define ENABLE_IPV6_RELAY(s) ((s)->mode & MODE_IPV6_RELAY)
#define ENABLE_IPV6_SLAAC(s) ((s)->mode & MODE_IPV6_SLAAC)
#define ENABLE_IPV6_PD(s)    ((s)->mode & MODE_IPV6_PD)
#define ENABLE_RELAY(s) (ENABLE_IPV4_RELAY(s) || ENABLE_IPV6_RELAY(s))
#define ENABLE_IPV4_SERVER(s) ((s)->mode & MODE_IPV4_SERVER)
#define ENABLE_IPV6_SERVER(s) (((s)->mode & MODE_IPV6_SERVER)||ENABLE_IPV6_SLAAC(s)||ENABLE_IPV6_PD(s))
#define ENABLE_SERVER(s) (ENABLE_IPV4_SERVER(s) || ENABLE_IPV6_SERVER(s))
#define ENABLE_DHCP_IPV4(s) (ENABLE_IPV4_RELAY(s) || ENABLE_IPV4_SERVER(s))
#define ENABLE_DHCP_IPV6(s) (ENABLE_IPV6_RELAY(s) || ENABLE_IPV6_SERVER(s)||ENABLE_IPV6_SLAAC(s)||ENABLE_IPV6_PD(s))
#define ENABLE_ACL_BLACK(s) ((s)->macctl.aclmode & ACL_MODE_BLACK)
#define ENABLE_ACL_WHITE(s) ((s)->macctl.aclmode & ACL_MODE_WHITE)

PUBLIC_DATA dhcpd_server_t *dhcpd_server_init();
PUBLIC_DATA void dhcpd_server_release(void *p);
PUBLIC_DATA void dhcpd_server_recycle(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA void dhcpd_server_reload(void *cfg);
PUBLIC_DATA void dhcpd_server_check(void *cfg);
PUBLIC_DATA void dhcpd_server_update(void *cfg, trash_queue_t *pRecycleTrash,int sockfd_main); 
PUBLIC_DATA int iface_subnet_match(dhcpd_server_t *dhcpd_server, const ip4_address_t ipaddr);

PUBLIC_DATA dhcpd_server_t *dhcpd_server_search(void *cfg, const u32 nID);
PUBLIC_DATA dhcpd_server_t *dhcpd_server_search_LineID(void *cfg, const u32 nLineID);
PUBLIC_DATA int dhcpd_server_match_macaddr(dhcpd_server_t *dhcpd_server, const mac_address_t macaddr);
PUBLIC_DATA dhcpd_staticlease_t *dhcpd_server_staticlease_search_macaddr(dhcpd_server_t *dhcpd_server, const mac_address_t macaddr, const int ipstack/*4/6*/);

#endif
