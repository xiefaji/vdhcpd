#ifndef _dhcp_ipcshare_h
#define _dhcp_ipcshare_h

#include <net/ethernet.h>
#include "share/types.h"

#define DEFAULT_CORE_UDP_PORT 6668/*xspeeder*/
#define DEFAULT_DHCP_UDP_PORT 6667/**/
#define DEFAULT_API_UDP_PORT 12000
#define DEFAULT_WEBACTION_UDP_PORT 20000

#define DEFAULT_DHCPv4_PROCESS  2101
#define DEFAULT_DHCPv6_PROCESS  2102

#define CODE_REQUEST    0
#define CODE_REPLY  1

typedef struct {
    u32 process;//对端进程代号
    u16 code;//操作类型
    u8 driveid;  //dpdk接收网卡
    union {
        u32 lineid; // 线路ID
        struct {
            u16 line1;
            u16 line2;
        };
    };
    u16 session;
    union {
        u16 flag[2];
        struct {
            u16 outer_vlanid:12,dir:1,r1:3;
            u16 inner_vlanid:12,r2:4;
        };//hostbit
    };
    struct ether_header ethhdr;
    u16 datalen;
    unsigned char pdata[0];
} ipcshare_hdr_t;

#endif
