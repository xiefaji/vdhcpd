#include "dhcpd.h"

PUBLIC macaddr_item_t *macaddr_item_init()
{
    macaddr_item_t *macaddr_item = (macaddr_item_t *)xmalloc(sizeof(macaddr_item_t));
    BZERO(macaddr_item, sizeof(macaddr_item_t));
    return macaddr_item;
}

PUBLIC void macaddr_item_release(void *p)
{
    macaddr_item_t *macaddr_item = (macaddr_item_t *)p;
    if (macaddr_item) xfree(macaddr_item);
}

PUBLIC void macaddr_item_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    macaddr_item_t *macaddr_item = (macaddr_item_t *)p;
    if (macaddr_item) trash_queue_enqueue(pRecycleTrash, macaddr_item);
}

PUBLIC macaddr_group_t *macaddr_group_init()
{
    macaddr_group_t *macaddr_group = (macaddr_group_t *)xmalloc(sizeof(macaddr_group_t));
    BZERO(macaddr_group, sizeof(macaddr_group_t));
    key_tree_init(&macaddr_group->key_macaddrlist);
    return macaddr_group;
}

PUBLIC void macaddr_group_release(void *p)
{
    macaddr_group_t *macaddr_group = (macaddr_group_t *)p;
    if (macaddr_group) {
        key_tree_destroy2(&macaddr_group->key_macaddrlist, macaddr_item_release);
        xfree(macaddr_group);
    }
}

PUBLIC void macaddr_group_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    macaddr_group_t *macaddr_group = (macaddr_group_t *)p;
    if (macaddr_group) {
        key_tree_nodes_recycle(&macaddr_group->key_macaddrlist, pRecycleTrash, macaddr_item_recycle);
        trash_queue_enqueue(pRecycleTrash, macaddr_group);
    }
}

//MAC群组查找
PUBLIC macaddr_group_t *macaddr_group_search(void *cfg, const u32 nID)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_rbsearch(&cfg_main->key_macaddr_group, nID);
    return (knode && knode->data) ? knode->data:NULL;
}

//加载MAC地址群组
PUBLIC void macaddr_acl_reload(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpmacaclgroup;");

    PMYDBOP pDBHandle = &xHANDLE_Mysql;
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, pDBHandle->m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        macaddr_group_t *macaddr_group = macaddr_group_init();
        CSqlRecorDset_GetFieldValue_U32(&Query, "id", &macaddr_group->nID);
        CSqlRecorDset_GetFieldValue_String(&Query, "name", macaddr_group->szName, MINNAMELEN);

        struct key_node *knode = key_rbinsert(&cfg_main->key_macaddr_group, macaddr_group->nID, macaddr_group);
        if (knode) {
            x_log_err("加载MAC地址群组失败, ID冲突[%d].", macaddr_group->nID);
            macaddr_group_release(macaddr_group);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
}

//加载群组MAC地址
PRIVATE void macaddr_item_reload(macaddr_group_t *macaddr_group)
{
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpmac WHERE groupid=%u;", macaddr_group->nID);

    PMYDBOP pDBHandle = &xHANDLE_Mysql;
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, pDBHandle->m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        char macaddr[MINNAMELEN+1]={0};
        macaddr_item_t *macaddr_item = macaddr_item_init();
        CSqlRecorDset_GetFieldValue_String(&Query, "mac", macaddr, MINNAMELEN);
        macaddress_parse(&macaddr_item->key.macaddr, macaddr);
        CSqlRecorDset_GetFieldValue_String(&Query, "comment", macaddr_item->szName, MINNAMELEN);

        struct key_node *knode = key_rbinsert(&macaddr_group->key_macaddrlist, macaddr_item->key.key_value, macaddr_item);
        if (knode) {
            x_log_err("加载MAC地址失败, MAC冲突["MACADDRFMT"].", MACADDRBYTES(macaddr_item->key.macaddr));
            macaddr_item_release(macaddr_item);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
}

PUBLIC void macaddr_acl_check(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_first(&cfg_main->key_macaddr_group);
    while (knode && knode->data) {
        macaddr_group_t *macaddr_group = (macaddr_group_t *)knode->data;
        macaddr_item_reload(macaddr_group);
        knode = key_next(knode);
    }
}

//MAC地址群组匹配
PUBLIC int macaddr_match(void *cfg, const u32 nID, const mac_address_t macaddr)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    macaddr_group_t *macaddr_group = macaddr_group_search(cfg_main, nID);
    if (!macaddr_group)
        return 0;

    macaddr_item_t tmp;
    BZERO(&tmp, sizeof(macaddr_item_t));
    BCOPY(&macaddr, &tmp.key.macaddr, sizeof(macaddr_item_t));
    struct key_node *knode = key_rbsearch(&macaddr_group->key_macaddrlist, tmp.key.key_value);
    return (knode && knode->data) ? 1:0;
}

PUBLIC int macaddr_match_str(void *cfg, const u32 nID, const char *macaddr_str)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    mac_address_t macaddr;
    BZERO(&macaddr, sizeof(mac_address_t));
    macaddress_parse(&macaddr, macaddr_str);
    return macaddr_match(cfg_main, nID, macaddr);
}
