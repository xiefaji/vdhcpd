#ifndef _dhcp_api_h
#define _dhcp_api_h

#include "share/defines.h"
#include "share/types.h"
 

#define IPCAPI_PROCESS_FINGER 1

#define IPCAPI_CODE_REQUEST 1
#define IPCAPI_CODE_REPLY 2

typedef struct {
    u16 process;
    u16 action;
} __attribute__((packed)) ipcapi_hdr_t;

typedef struct {
    mac_address_t macaddr;
    char finger4[32];//MD5 string
    char finger6[32];//MD5 string
} __attribute__((packed)) ipcapi_hdr_finger_t;
#endif
