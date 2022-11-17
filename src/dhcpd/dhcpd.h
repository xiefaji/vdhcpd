#ifndef _dhcp_dhcpd_h
#define _dhcp_dhcpd_h

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "share/defines.h"
#include "share/hash.h"
#include "share/magic.h"
#include "share/misc.h"
#include "share/types.h"
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
#include "ipcshare.h"
#include "dhcpv4.h"
#include "dhcpv6.h"

typedef struct {
    int sockfd_main;//
    int sockfd_relay4;//中继[ipv4]
    int sockfd_relay6;//中继[ipv6]
    int sockfd_api;//

    xTHREAD relay4Thread;
    xTHREAD relay6Thread;
    xTHREAD mThread;
    xTHREAD mtThread;
    xTHREAD apiThread;
} vdhcpd_main_t;
PUBLIC_DATA vdhcpd_main_t vdhcpd_main;
PUBLIC_DATA time_t global_time;

PUBLIC_DATA int vdhcpd_init();
PUBLIC_DATA int vdhcpd_release();
PUBLIC_DATA int vdhcpd_shutdown();
PUBLIC_DATA int vdhcpd_start();

//local.c
PUBLIC int local_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int local_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int local_main_start(void *p, trash_queue_t *pRecycleTrash);
//api.c
PUBLIC int api_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int api_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int api_main_start(void *p, trash_queue_t *pRecycleTrash);
//relay4.c
PUBLIC int relay4_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int relay4_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int relay4_main_start(void *p, trash_queue_t *pRecycleTrash);
//relay6.c
PUBLIC int relay6_main_init(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int relay6_main_clean(void *p, trash_queue_t *pRecycleTrash);
PUBLIC int relay6_main_start(void *p, trash_queue_t *pRecycleTrash);

#endif
