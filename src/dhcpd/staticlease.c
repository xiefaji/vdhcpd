#include "dhcpd.h"
PRIVATE void staticlease_reload4(dhcpd_lease_main_t *staticlease_main, const u32 serverid);
PRIVATE void staticlease_reload6(dhcpd_lease_main_t *staticlease_main, const u32 serverid);

PUBLIC dhcpd_staticlease_t *dhcpd_staticlease_init()
{
    dhcpd_staticlease_t *dhcpd_staticlease = (dhcpd_staticlease_t *)xmalloc(sizeof(dhcpd_staticlease_t));
    BZERO(dhcpd_staticlease, sizeof(dhcpd_staticlease_t));
    return dhcpd_staticlease;
}

PUBLIC void dhcpd_staticlease_release(void *p)
{
    dhcpd_staticlease_t *dhcpd_staticlease = (dhcpd_staticlease_t *)p;
    if (dhcpd_staticlease) {
        xfree(dhcpd_staticlease);
    }
}

PUBLIC void dhcpd_staticlease_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    dhcpd_staticlease_t *dhcpd_staticlease = (dhcpd_staticlease_t *)p;
    if (dhcpd_staticlease) {
        trash_queue_enqueue(pRecycleTrash, dhcpd_staticlease);
    }
}

PUBLIC dhcpd_lease_main_t *dhcpd_lease_main_init()
{
    dhcpd_lease_main_t *staticlease_main = (dhcpd_lease_main_t *)xmalloc(sizeof(dhcpd_lease_main_t));
    BZERO(staticlease_main, sizeof(dhcpd_lease_main_t));
    key_tree_init(&staticlease_main->key_staticlease4);
    key_tree_init(&staticlease_main->key_staticlease4_ip);
    key_tree_init(&staticlease_main->key_staticlease4_mac);
    key_tree_init(&staticlease_main->key_staticlease6);
    key_tree_init(&staticlease_main->key_staticlease6_mac);

    return staticlease_main;
}

PUBLIC void dhcpd_lease_main_release(void *p)
{
    dhcpd_lease_main_t *staticlease_main = (dhcpd_lease_main_t *)p;
    if (staticlease_main) {
        key_tree_destroy2(&staticlease_main->key_staticlease4_ip, NULL);
        key_tree_destroy2(&staticlease_main->key_staticlease4_mac, NULL);
        key_tree_destroy2(&staticlease_main->key_staticlease4, dhcpd_staticlease_release);
        key_tree_destroy2(&staticlease_main->key_staticlease6_mac, NULL);
        key_tree_destroy2(&staticlease_main->key_staticlease6, dhcpd_staticlease_release);
        xfree(staticlease_main);
    }
}

PUBLIC void dhcpd_lease_main_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    dhcpd_lease_main_t *staticlease_main = (dhcpd_lease_main_t *)p;
    if (staticlease_main) {
        key_tree_nodes_recycle(&staticlease_main->key_staticlease4_ip, pRecycleTrash, NULL);
        key_tree_nodes_recycle(&staticlease_main->key_staticlease4_mac, pRecycleTrash, NULL);
        key_tree_nodes_recycle(&staticlease_main->key_staticlease4, pRecycleTrash, dhcpd_staticlease_recycle);
        key_tree_nodes_recycle(&staticlease_main->key_staticlease6_mac, pRecycleTrash, NULL);
        key_tree_nodes_recycle(&staticlease_main->key_staticlease6, pRecycleTrash, dhcpd_staticlease_recycle);
        trash_queue_enqueue(pRecycleTrash, staticlease_main);
    }
}

PUBLIC void dhcpd_lease_main_reload(dhcpd_lease_main_t *staticlease_main, const u32 serverid)
{
    staticlease_reload4(staticlease_main, serverid);
    staticlease_reload6(staticlease_main, serverid);
}

PUBLIC void dhcpd_lease_main_check(dhcpd_lease_main_t *staticlease_main)
{
    struct key_node *knode4 = key_first(&staticlease_main->key_staticlease4);
    while (knode4 && knode4->data) {
        dhcpd_staticlease_t *dhcpd_staticlease = (dhcpd_staticlease_t *)knode4->data;
        //插入查询树
        key_rbinsert(&staticlease_main->key_staticlease4_mac, dhcpd_staticlease->key.key_value, dhcpd_staticlease);
        key_rbinsert(&staticlease_main->key_staticlease4_ip, dhcpd_staticlease->u.v4.ipaddr.address, dhcpd_staticlease);
        knode4 = key_next(knode4);
    }

    struct key_node *knode6 = key_first(&staticlease_main->key_staticlease6);
    while (knode6 && knode6->data) {
        dhcpd_staticlease_t *dhcpd_staticlease = (dhcpd_staticlease_t *)knode6->data;
        //插入查询树
        key_rbinsert(&staticlease_main->key_staticlease6_mac, dhcpd_staticlease->key.key_value, dhcpd_staticlease);
        knode6 = key_next(knode6);
    }
}

PRIVATE void staticlease_reload4(dhcpd_lease_main_t *staticlease_main, const u32 serverid/*lineid*/)
{
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpfixed WHERE lineid=%u;", serverid);

    MYDBOP DBHandle;
    // MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0) {
        MyDBOp_CloseDB(&DBHandle);
        x_log_err("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname);
        return;
    }
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        char ipaddr[MINNAMELEN+1]={0};
        char macaddr[MINNAMELEN+1]={0};
        dhcpd_staticlease_t *dhcpd_staticlease = dhcpd_staticlease_init();
        CSqlRecorDset_GetFieldValue_U32(&Query, "id", &dhcpd_staticlease->nID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "lineid", &dhcpd_staticlease->nLineID);
        CSqlRecorDset_GetFieldValue_String(&Query, "hardware", macaddr, MINNAMELEN);
        macaddress_parse(&dhcpd_staticlease->key.u.macaddr, macaddr);
        CSqlRecorDset_GetFieldValue_String(&Query, "sComment", dhcpd_staticlease->szName, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_String(&Query, "fixedip", ipaddr, MINNAMELEN);
        inet_pton(AF_INET, ipaddr, &dhcpd_staticlease->u.v4.ipaddr);
        CSqlRecorDset_GetFieldValue_String(&Query, "fixedgateway", ipaddr, MINNAMELEN);
        inet_pton(AF_INET, ipaddr, &dhcpd_staticlease->u.v4.gateway);

        struct key_node *knode = key_rbinsert(&staticlease_main->key_staticlease4, dhcpd_staticlease->nID, dhcpd_staticlease);
        if (knode) {
            x_log_err("加载静态租约配置[v4]失败, ID冲突[%d].", dhcpd_staticlease->nID);
            dhcpd_staticlease_release(dhcpd_staticlease);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

PRIVATE void staticlease_reload6(dhcpd_lease_main_t *staticlease_main, const u32 serverid/*lineid*/)
{
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpfixed6 WHERE lineid=%u;", serverid);

    MYDBOP DBHandle;
    // MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0) {
        MyDBOp_CloseDB(&DBHandle);
        x_log_err("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname);
        return;
    }
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        char ipaddr[MINNAMELEN+1]={0};
        char macaddr[MINNAMELEN+1]={0};
        dhcpd_staticlease_t *dhcpd_staticlease = dhcpd_staticlease_init();
        CSqlRecorDset_GetFieldValue_U32(&Query, "id", &dhcpd_staticlease->nID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "lineid", &dhcpd_staticlease->nLineID);
        CSqlRecorDset_GetFieldValue_String(&Query, "hardware", macaddr, MINNAMELEN);
        macaddress_parse(&dhcpd_staticlease->key.u.macaddr, macaddr);
        CSqlRecorDset_GetFieldValue_String(&Query, "sComment", dhcpd_staticlease->szName, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_String(&Query, "fixed_address6", ipaddr, MINNAMELEN);
        inet_pton(AF_INET6, ipaddr, &dhcpd_staticlease->u.v6.ipaddr);
        CSqlRecorDset_GetFieldValue_String(&Query, "fixed_gateway6", ipaddr, MINNAMELEN);
        inet_pton(AF_INET6, ipaddr, &dhcpd_staticlease->u.v6.gateway);

        struct key_node *knode = key_rbinsert(&staticlease_main->key_staticlease6, dhcpd_staticlease->nID, dhcpd_staticlease);
        if (knode) {
            x_log_err("加载静态租约配置[v6]失败, ID冲突[%d].", dhcpd_staticlease->nID);
            dhcpd_staticlease_release(dhcpd_staticlease);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//静态租约查询
PUBLIC dhcpd_staticlease_t *staticlease_search4_macaddr(dhcpd_lease_main_t *staticlease_main, const mac_address_t macaddr)
{
    lease_key_t key;
    BZERO(&key, sizeof(lease_key_t));
    BCOPY(&macaddr, &key.u.macaddr, sizeof(mac_address_t));
    struct key_node *knode = key_rbsearch(&staticlease_main->key_staticlease4_mac, key.key_value);
    return (knode && knode->data) ? knode->data:NULL;
}

PUBLIC dhcpd_staticlease_t *staticlease_search4_ipaddr(dhcpd_lease_main_t *staticlease_main, const ip4_address_t ipaddr)
{
    struct key_node *knode = key_rbsearch(&staticlease_main->key_staticlease4_ip, ipaddr.address);
    return (knode && knode->data) ? knode->data:NULL;
}

PUBLIC dhcpd_staticlease_t *staticlease_search6_macaddr(dhcpd_lease_main_t *staticlease_main, const mac_address_t macaddr)
{
    lease_key_t key;
    BZERO(&key, sizeof(lease_key_t));
    BCOPY(&macaddr, &key.u.macaddr, sizeof(mac_address_t));
    struct key_node *knode = key_rbsearch(&staticlease_main->key_staticlease6_mac, key.key_value);
    return (knode && knode->data) ? knode->data:NULL;
}

PUBLIC dhcpd_staticlease_t *staticlease_search6_ipaddr(dhcpd_lease_main_t *staticlease_main, const ip6_address_t ipaddr)
{
    return NULL;
}
