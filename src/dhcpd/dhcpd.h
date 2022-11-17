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

#include "config.h"

typedef struct {

} vdhcpd_main_t;
PUBLIC_DATA vdhcpd_main_t vdhcpd_main;
PUBLIC_DATA time_t global_time;

PUBLIC_DATA int vdhcpd_init();
PUBLIC_DATA int vdhcpd_release();
PUBLIC_DATA int vdhcpd_shutdown();
PUBLIC_DATA int vdhcpd_start();

#endif
