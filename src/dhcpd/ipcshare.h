#ifndef _dhcp_ipcshare_h
#define _dhcp_ipcshare_h

#include <net/ethernet.h>
#include "share/types.h"

#define DEFAULT_DHCPv4_PROCESS  2101
#define DEFAULT_DHCPv6_PROCESS  2102
#define DEFAULT_API_UDP_PORT 12000

#ifndef VERSION_VNAAS
#define DEFAULT_CORE_UDP_PORT 6668/*主程序*/
#define DEFAULT_DHCP_UDP_PORT 6667/*DHCPD*/
#define DEFAULT_WEBACTION_UDP_PORT 20000
#define CODE_REQUEST    0
#define CODE_REPLY  1
#else
#define VNAAS_POP_IPC_DGRAM_SOCK "/run/vnaas_pop_ipc.socket"
#define VNAAS_DHCP_IPC_DGRAM_SOCK "/run/vnaas_dhcp_ipc.socket"
#define VNAAS_DHCP_API_DGRAM_SOCK "/run/vnaas_dhcp_api.socket"
#endif

#ifndef VERSION_VNAAS
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
#else
/* VLAN with ethertype first and vlan id second */
typedef struct {
  /* 3 bit priority, 1 bit CFI and 12 bit vlan id. */
  u16 priority_cfi_and_id;

  /* next proto type */
  u16 next_type;
} ethernet_vlan_header_next_tv_t;

#define UIPC_FIELD_DHCP_SERVER 1000
#define UIPC_ACT_WORK_MSG 10

typedef union uipc_command_path_t {
    u64 key;
    struct {
        u32 field;
        u32 act;
    };
} uipc_command_path_t;

typedef struct uipc_tag {
    u16 byte_len;
    u8 byte[0];
} __attribute__((packed)) uipc_task_t;

typedef struct {
    uipc_command_path_t path;
    u32 sw_rx_dbid;
    u32 sw_ser_dbid;
    u16 l3_offset;
    u16 data_len;
    u8 data[0];
} __attribute__((packed)) dhcp_external_proc_hdr_t;
#endif

#endif
