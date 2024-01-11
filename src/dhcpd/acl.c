#include "dhcpd.h"
#include "share/xlog.h"

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
// MAC地址控制
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

// MAC群组查找
PUBLIC macaddr_group_t *macaddr_group_search(void *cfg, const u32 nID)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_rbsearch(&cfg_main->key_macaddr_group, nID);
    return (knode && knode->data) ? knode->data : NULL;
}

//加载MAC地址群组
PUBLIC void macaddr_acl_reload(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    char sql[MINBUFFERLEN + 1] = {0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM %s;", DBTABLE_DHCP_MACACL_GROUP);

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0) {
        MyDBOp_CloseDB(&DBHandle);
        x_log_err("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname);
        return;
    }
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
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
    MyDBOp_CloseDB(&DBHandle);
}

//加载群组MAC地址
PRIVATE void macaddr_item_reload(macaddr_group_t *macaddr_group)
{
    char sql[MINBUFFERLEN + 1] = {0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpmac WHERE groupid=%u;", macaddr_group->nID);

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0) {
        MyDBOp_CloseDB(&DBHandle);
        x_log_err("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname);
        return;
    }
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        char macaddr[MINNAMELEN + 1] = {0};
        macaddr_item_t *macaddr_item = macaddr_item_init();
        CSqlRecorDset_GetFieldValue_String(&Query, "mac", macaddr, MINNAMELEN);
        macaddress_parse(&macaddr_item->key.macaddr, macaddr);
        CSqlRecorDset_GetFieldValue_String(&Query, "comment", macaddr_item->szName, MINNAMELEN);

        struct key_node *knode = key_rbinsert(&macaddr_group->key_macaddrlist, macaddr_item->key.key_value, macaddr_item);
        if (knode) {
            x_log_err("加载MAC地址失败, MAC冲突[" MACADDRFMT "].", MACADDRBYTES(macaddr_item->key.macaddr));
            macaddr_item_release(macaddr_item);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
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

// MAC地址群组匹配
PUBLIC int macaddr_match(void *cfg, const u32 nID, const mac_address_t macaddr)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    macaddr_group_t *macaddr_group = macaddr_group_search(cfg_main, nID);
    if (!macaddr_group)
        return 0;

    macaddr_item_t tmp;
    BZERO(&tmp, sizeof(macaddr_item_t));
    BCOPY(&macaddr, &tmp.key.macaddr, sizeof(mac_address_t));
    struct key_node *knode = key_rbsearch(&macaddr_group->key_macaddrlist, tmp.key.key_value);
    return (knode && knode->data) ? 1 : 0;
}

PUBLIC int macaddr_match_str(void *cfg, const u32 nID, const char *macaddr_str)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    mac_address_t macaddr;
    BZERO(&macaddr, sizeof(mac_address_t));
    macaddress_parse(&macaddr, macaddr_str);
    return macaddr_match(cfg_main, nID, macaddr);
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
//通信数据过滤
PRIVATE void macaddr_filter_reload(struct key_tree *filter_tree, const char *filename)
{
    FILE *pFILE = fopen(filename, "r");
    if (!pFILE) {
        x_log_warn("%s:%d 文件[%s]打开失败[%s].", __FUNCTION__, __LINE__, filename, strerror(errno));
        return;
    }

    char buffer[MINNAMELEN + 1] = {0};
    while (fgets(buffer, MINNAMELEN, pFILE)) {
        macaddr_item_t temp_item;
        BZERO(&temp_item, sizeof(macaddr_item_t));
        macaddress_parse(&temp_item.key.macaddr, buffer);
        if (!temp_item.key.key_value)
            continue;

        macaddr_item_t *macaddr_item = macaddr_item_init();
        macaddr_item->key.key_value = temp_item.key.key_value;
        sprintf(macaddr_item->szName, "MAC地址日志过滤");
        struct key_node *knode = key_rbinsert(filter_tree, macaddr_item->key.key_value, macaddr_item);
        if (knode) macaddr_item_release(macaddr_item);
    }

    fclose(pFILE);
}

PUBLIC struct key_tree *macaddr_filter_init(const char *filename)
{
    struct key_tree *filter_tree = (struct key_tree *)xmalloc(sizeof(struct key_tree));
    key_tree_init(filter_tree);
    macaddr_filter_reload(filter_tree, filename);
    return filter_tree;
}

PUBLIC void macaddr_filter_release(void *p)
{
    struct key_tree *filter_tree = (struct key_tree *)p;
    if (filter_tree) {
        key_tree_destroy2(filter_tree, macaddr_item_release);
        xfree(filter_tree);
    }
}

PUBLIC void macaddr_filter_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    struct key_tree *filter_tree = (struct key_tree *)p;
    if (filter_tree) {
        key_tree_nodes_recycle(filter_tree, pRecycleTrash, macaddr_item_recycle);
        trash_queue_enqueue(pRecycleTrash, filter_tree);
    }
}

PUBLIC int macaddr_filter_match(struct key_tree *filter_tree, const mac_address_t macaddr)
{
    if (!filter_tree)
        return 0;
    macaddr_item_t tmp;
    BZERO(&tmp, sizeof(macaddr_item_t));
    BCOPY(&macaddr, &tmp.key.macaddr, sizeof(mac_address_t));
    struct key_node *knode = key_rbsearch(filter_tree, tmp.key.key_value);
    return (knode && knode->data) ? 1 : 0;
}
