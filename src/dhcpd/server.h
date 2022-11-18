#ifndef _dhcp_server_h
#define _dhcp_server_h

#include "share/defines.h"
#include "share/types.h"
#include "share/bitmap/bitmap_vlan.h"
#include "share/array/trashqueue.h"
#include "acl.h"
#include "staticlease.h"

//服务模式
typedef enum {
    MODE_IPV4_RELAY = (1<<0),
    MODE_IPV6_RELAY = (1<<1),
    MODE_IPV4_SERVER = (1<<4),
    MODE_IPV6_SERVER = (1<<6),
} dhcpd_mode_t;

//DHCP服务配置
typedef struct {
    u32 nID;
    u32 nLineID;
    u32 nEnabled;
    u32 leasetime;//租约时长 单位：秒
    dhcpd_mode_t mode;
    xVLANBITMAP *pVLAN;
    xVLANBITMAP *pQINQ;

    //线路配置信息
    struct {
        u32 driveid;
        char ifname[MINNAMELEN+1];
        u32 networkcard;
        u16 groupid;
        u16 kind;
        u16 mtu;
        mac_address_t macaddr;
        ip4_address_t ipaddr;
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
        } v6;
        char identifier[MINNAMELEN+1];//中继标识
    } dhcprelay;

    //MAC控制
    struct {
        dhcpd_acl_t aclmode;
#define DEFAULT_ACLGROUP_SIZE 12
        u32 aclgroup[DEFAULT_ACLGROUP_SIZE];
    } macctl;

    //静态租约
    dhcpd_lease_main_t *staticlease_main;
    void *cfg_main;
} dhcpd_server_t;
#define ENABLE_IPV4_RELAY(s) ((s)->mode & MODE_IPV4_RELAY)
#define ENABLE_IPV6_RELAY(s) ((s)->mode & MODE_IPV6_RELAY)
#define ENABLE_RELAY(s) (ENABLE_IPV4_RELAY(s) || ENABLE_IPV6_RELAY(s))
#define ENABLE_IPV4_SERVER(s) ((s)->mode & MODE_IPV4_SERVER)
#define ENABLE_IPV6_SERVER(s) ((s)->mode & MODE_IPV6_SERVER)
#define ENABLE_SERVER(s) (ENABLE_IPV4_SERVER(s) || ENABLE_IPV6_SERVER(s))
#define ENABLE_DHCP_IPV4(s) (ENABLE_IPV4_RELAY(s) || ENABLE_IPV4_SERVER(s))
#define ENABLE_DHCP_IPV6(s) (ENABLE_IPV6_RELAY(s) || ENABLE_IPV6_SERVER(s))
#define ENABLE_ACL_BLACK(s) ((s)->macctl.aclmode & ACL_MODE_BLACK)
#define ENABLE_ACL_WHITE(s) ((s)->macctl.aclmode & ACL_MODE_WHITE)

PUBLIC_DATA dhcpd_server_t *dhcpd_server_init();
PUBLIC_DATA void dhcpd_server_release(void *p);
PUBLIC_DATA void dhcpd_server_recycle(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA void dhcpd_server_reload(void *cfg);
PUBLIC_DATA void dhcpd_server_check(void *cfg);
PUBLIC_DATA void dhcpd_server_update(void *cfg);

PUBLIC_DATA dhcpd_server_t *dhcpd_server_search(void *cfg, const u32 nID);
PUBLIC_DATA dhcpd_server_t *dhcpd_server_search_LineID(void *cfg, const u32 nLineID);
PUBLIC_DATA int dhcpd_server_match_macaddr(dhcpd_server_t *dhcpd_server, const mac_address_t macaddr);
PUBLIC_DATA dhcpd_staticlease_t *dhcpd_server_staticlease_search_macaddr(dhcpd_server_t *dhcpd_server, const mac_address_t macaddr, const int ipstack/*4/6*/);

#endif
