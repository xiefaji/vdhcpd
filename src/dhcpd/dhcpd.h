#ifndef _dhcp_dhcpd_h
#define _dhcp_dhcpd_h

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "share/defines.h"
#include "share/hash.h"
#include "share/magic.h"
#include "share/md5.h"
#include "share/misc.h"
#include "share/types.h"
#include "share/windivert.h"
#include "share/xlog.h"
#include "share/array/trashqueue.h"
#include "share/bitmap/bitmap_vlan.h"
#include "share/cjson/cjson.h"
#include "share/inifile/inifile.h"
#include "share/mysql/mydbop.h"
#include "share/rbtree/key_elem.h"
#include "share/rbtree/set_elem.h"

#include "public/xthread.h"
#include "public/rbtree_common.h"
#include "public/receive_bucket.h"

#include "config.h"
#include "db.h"
#include "ipcshare.h"
#include "dhcpstats.h"
#include "dhcpv4.h"
#include "dhcpv6.h"
#include "dhcppacket.h"
#include "realtime.h"
#include "server.h"

typedef struct {
    struct key_tree key_servers;//DHCP服务
    struct key_tree key_servers_line;//DHCP服务
    struct key_tree key_macaddr_group;//MAC地址控制
} vdhcpd_cfg_t;

typedef struct {
    int sockfd_raw;//原始套接字[用于发送中继报文]
    int sockfd_main;//
    int sockfd_relay4;//中继[ipv4]
    int sockfd_relay6;//中继[ipv6]
    int sockfd_api;//
    int sockfd_webaction;

    xTHREAD relay4Thread;
    xTHREAD relay6Thread;
    xTHREAD mThread;
    xTHREAD mtThread;
    xTHREAD apiThread;
    xTHREAD webThread;

    //数据库记录
    struct db_process_t db_process;
    xTHREAD dbThread;

    volatile int reload_vdhcpd;
    vdhcpd_cfg_t *cfg_main;//配置
    struct key_tree *filter_tree;//流水日志过滤
    vdhcpd_stats_t stats_main;
} vdhcpd_main_t;
PUBLIC_DATA vdhcpd_main_t vdhcpd_main;
PUBLIC_DATA time_t global_time;

PUBLIC_DATA time_t vdhcpd_time(void);
PUBLIC_DATA int vdhcpd_urandom(void *data, size_t len);
PUBLIC_DATA int vdhcpd_init();
PUBLIC_DATA int vdhcpd_release();
PUBLIC_DATA int vdhcpd_shutdown();
PUBLIC_DATA int vdhcpd_start();
ALWAYS_INLINE void vdhcpd_set_reload()
{
    __sync_fetch_and_add(&vdhcpd_main.reload_vdhcpd, 1);
}

typedef struct {
    vdhcpd_main_t *vdm;
    dhcpd_server_t *dhcpd_server;//DHCP服务
    realtime_info_t *realtime_info;

    union {
        unsigned char *data;
        ipcshare_hdr_t *ipcsharehdr;
    };
    u32 data_len;
    dhcp_packet_t request, reply;//请求报文/响应报文
    mac_address_t macaddr;//客户端MAC地址
} packet_process_t;

//local.c
PUBLIC_DATA int local_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int local_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int local_main_start(void *p, trash_queue_t *pRecycleTrash);
//api.c
PUBLIC_DATA int api_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int api_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int api_main_start(void *p, trash_queue_t *pRecycleTrash);
//webaction.c
PUBLIC_DATA int webaction_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int webaction_start(void *p, trash_queue_t *pRecycleTrash);

//dhcpv4.c
#define PACKET_SIZE(start, end) (((u8 *)end - (u8 *)start) < DHCPV4_MIN_PACKET_SIZE ? \
    DHCPV4_MIN_PACKET_SIZE : (u8 *)end - (u8 *)start)
PUBLIC_DATA char *dhcpv4_msg_to_string(u8 reqmsg);
PUBLIC_DATA void dhcpv4_put(struct dhcpv4_message *msg, u8 **cookie, u8 type, u8 len, const void *data);
PUBLIC_DATA int server4_process(packet_process_t *packet_process);

//dhcpv4relay.c
struct agent_infomation_t {
    struct dhcpv4_option opt_circuitid;
    dhcpv4_option_vlan_t circuitid;
    struct dhcpv4_option opt_remoteid;
    mac_address_t remoteid;
    struct dhcpv4_option opt_linkselection;
    ip4_address_t linkselection;
} __attribute__ ((packed));
PUBLIC_DATA int relay4_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int relay4_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int relay4_main_start(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int relay4_send_request_packet(packet_process_t *packet_process);
PUBLIC_DATA int relay4_send_reply_packet(packet_process_t *packet_process);
//dhcpv6relay.c
PUBLIC_DATA int relay6_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int relay6_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int relay6_main_start(void *p, trash_queue_t *pRecycleTrash);

ALWAYS_INLINE void packet_save_log(packet_process_t *packet_process, struct dhcpv4_message *dhcp_packet, enum dhcpv4_msg msgcode, const char *direction)
{
    vdhcpd_main_t *vdm = packet_process->vdm;
    if (!macaddr_filter_match(vdm->filter_tree, packet_process->macaddr))
        return;

    realtime_info_t *realtime_info = packet_process->realtime_info;
    x_log_warn("%s "MACADDRFMT" 类型[%s] 包ID[%u] 所属线路[%u] VLAN[%u/%u] CIP["IPV4FMT"] YIP["IPV4FMT"] NIP["IPV4FMT"] RIP["IPV4FMT"] 租约时长[%u]",
               direction, MACADDRBYTES(packet_process->macaddr), dhcpv4_msg_to_string(msgcode), dhcp_packet->xid,
               realtime_info->lineid, realtime_info->ovlanid, realtime_info->ivlanid, IPV4BYTES(dhcp_packet->ciaddr), IPV4BYTES(dhcp_packet->yiaddr),
               IPV4BYTES(dhcp_packet->siaddr), IPV4BYTES(dhcp_packet->giaddr), realtime_info->v4.leasetime);
}
#endif
