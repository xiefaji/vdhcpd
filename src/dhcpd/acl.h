#ifndef _dhcp_acl_h
#define _dhcp_acl_h

#include "share/defines.h"
#include "share/types.h"
#include "share/array/trashqueue.h"

typedef enum {
    ACL_MODE_NONE,//无操作
    ACL_MODE_BLACK,//黑名单
    ACL_MODE_WHITE,//白名单
} dhcpd_acl_t;

//MAC地址条目
typedef struct {
    union {
        u64 key_value;
        mac_address_t macaddr;
    } key;
    char szName[MINNAMELEN+1];
} macaddr_item_t;
PUBLIC_DATA macaddr_item_t *macaddr_item_init();
PUBLIC_DATA void macaddr_item_release(void *p);
PUBLIC_DATA void macaddr_item_recycle(void *p, trash_queue_t *pRecycleTrash);

//MAC地址群组
typedef struct {
    u32 nID;
    char szName[MINNAMELEN+1];
    struct key_tree key_macaddrlist;
} macaddr_group_t;
PUBLIC_DATA macaddr_group_t *macaddr_group_init();
PUBLIC_DATA void macaddr_group_release(void *p);
PUBLIC_DATA void macaddr_group_recycle(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA macaddr_group_t *macaddr_group_search(void *cfg, const u32 nID);

PUBLIC_DATA void macaddr_acl_reload(void *cfg);
PUBLIC_DATA void macaddr_acl_check(void *cfg);
PUBLIC_DATA int macaddr_match(void *cfg, const u32 nID, const mac_address_t macaddr);
PUBLIC_DATA int macaddr_match_str(void *cfg, const u32 nID, const char *macaddr_str);

//通信数据过滤
PUBLIC_DATA struct key_tree *macaddr_filter_init(const char *filename);
PUBLIC_DATA void macaddr_filter_release(void *p);
PUBLIC_DATA void macaddr_filter_recycle(void *p, trash_queue_t *pRecycleTrash);
PUBLIC_DATA int macaddr_filter_match(struct key_tree *filter_tree, const mac_address_t macaddr);
#endif
