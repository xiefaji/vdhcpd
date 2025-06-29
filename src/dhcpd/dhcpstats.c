#include "share/defines.h"
#include "share/rbtree/key_elem.h"
#include "share/xlog.h"
#include "dhcpstats.h"
#include "dhcpd.h"

typedef struct {
    struct key_tree key_server_stats;
} server_stats_main_t;
PRIVATE server_stats_main_t server_stats_main;

PRIVATE dhcpd_server_stats_t *server_stats_init()
{
    dhcpd_server_stats_t *server_stats = (dhcpd_server_stats_t *)xmalloc(sizeof(dhcpd_server_stats_t));
    BZERO(server_stats, sizeof(dhcpd_server_stats_t));
    INIT_LIST_HEAD(&server_stats->dhcpv4_assignments);
    INIT_LIST_HEAD(&server_stats->dhcpv6_assignments);
    dhcpd_server_stats_init_lock(server_stats);
    return server_stats;
}

PRIVATE void server_stats_release(void *p)
{
    dhcpd_server_stats_t *server_stats = (dhcpd_server_stats_t *)p;
    if (server_stats) {
        struct vdhcpd_assignment *a = NULL;
        struct list_head *pos = NULL, *n = NULL;
        list_for_each_safe(pos, n, &server_stats->dhcpv4_assignments)
        {
            a = list_entry(pos, struct vdhcpd_assignment, head);
            free_assignment(a);
        }
        list_for_each_safe(pos, n, &server_stats->dhcpv6_assignments)
        {
            a = list_entry(pos, struct vdhcpd_assignment, head);
            free_assignment(a);
        }
        dhcpd_server_stats_destroy_lock(server_stats);
        xfree(server_stats);
    }
}

PRIVATE void server_stats_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    dhcpd_server_stats_t *server_stats = (dhcpd_server_stats_t *)p;
    if (server_stats) {
        struct vdhcpd_assignment *a = NULL;
        struct list_head *pos = NULL, *n = NULL;
        list_for_each_safe(pos, n, &server_stats->dhcpv4_assignments)
        {
            a = list_entry(pos, struct vdhcpd_assignment, head);
            recycle_assignment(a, pRecycleTrash);
        }
        list_for_each_safe(pos, n, &server_stats->dhcpv6_assignments)
        {
            a = list_entry(pos, struct vdhcpd_assignment, head);
            recycle_assignment(a, pRecycleTrash);
        }
        dhcpd_server_stats_destroy_lock(server_stats);
        trash_queue_enqueue(pRecycleTrash, server_stats);
    }
}

PUBLIC void server_stats_main_init()
{
    server_stats_main_t *sm = &server_stats_main;
    BZERO(sm, sizeof(server_stats_main_t));
    key_tree_init(&sm->key_server_stats);
}

PUBLIC void server_stats_main_release()
{
    server_stats_main_t *sm = &server_stats_main;
    key_tree_destroy2(&sm->key_server_stats, server_stats_release);
}

PUBLIC void server_stats_main_maintain()
{
    time_t now = vdhcpd_time();
    server_stats_main_t *sm = &server_stats_main;

    struct key_node *knode = key_first(&sm->key_server_stats);
    while (knode && knode->data) {
        dhcpd_server_stats_t *server_stats = (dhcpd_server_stats_t *)knode->data;
        struct vdhcpd_assignment *a, *n;

        // IPv4实时租约
        list_for_each_entry_safe(a, n, &server_stats->dhcpv4_assignments, head)
        {
            if ((!INFINITE_VALID(a->valid_until)) && a->valid_until < now) {
                x_log_debug("释放租约");
                free_assignment(a);
            }
        }

        // IPv6实时租约
        list_for_each_entry_safe(a, n, &server_stats->dhcpv6_assignments, head)
        {
            if ((!INFINITE_VALID(a->valid_until)) && a->valid_until < now)
                free_assignment(a);
        }

        knode = key_next(knode);
    }
}

PUBLIC dhcpd_server_stats_t *server_stats_find(const u32 serverid)
{
    server_stats_main_t *sm = &server_stats_main;
    struct key_node *knode = key_rbsearch(&sm->key_server_stats, serverid);
    if (knode && knode->data) {
        return (knode && knode->data) ? knode->data : NULL;
    } else {
        dhcpd_server_stats_t *server_stats = server_stats_init();
        server_stats->serverid = serverid;
        key_tree_lock(&sm->key_server_stats);
        knode = key_rbinsert(&sm->key_server_stats, serverid, server_stats);
        key_tree_unlock(&sm->key_server_stats);
        if (knode) server_stats_release(server_stats);
        return knode ? knode->data : server_stats;
    }
}

// 租约释放
PUBLIC void server_stats_release_lease(dhcpd_server_stats_t *server_stats, const mac_address_t macaddr, const int ipv4)
{
    time_t now = vdhcpd_time();
    struct list_head *lists = ipv4 ? &server_stats->dhcpv4_assignments : &server_stats->dhcpv6_assignments;

    struct vdhcpd_assignment *a, *n;
    list_for_each_entry_safe(a, n, lists, head)
    {
        if (!BCMP(&a->macaddr, &macaddr, sizeof(mac_address_t)))
            a->valid_until = now;
    }
}

PUBLIC bool release_lease_by_mac(const mac_address_t macaddr, const int ipvsersion)
{
    time_t now = vdhcpd_time();
    server_stats_main_t *sm = &server_stats_main;

    struct key_node *knode = key_first(&sm->key_server_stats);
    while (knode && knode->data) {
        dhcpd_server_stats_t *server_stats = (dhcpd_server_stats_t *)knode->data;
        struct vdhcpd_assignment *a, *n;
        if (ipvsersion == 4) {
            // IPv4实时租约
            list_for_each_entry_safe(a, n, &server_stats->dhcpv4_assignments, head)
            {
                if (!BCMP(&a->macaddr, &macaddr, sizeof(mac_address_t))) {
                    a->valid_until = now;
                    return 1;
                }
            }
        } else if (ipvsersion == 6) {
            // IPv6实时租约
            list_for_each_entry_safe(a, n, &server_stats->dhcpv6_assignments, head)
            {
                if (!BCMP(&a->macaddr, &macaddr, sizeof(mac_address_t))) {
                    a->valid_until = now;
                    return 1;
                }
            }
        }
        knode = key_next(knode);
    }
    return -1;
}
PUBLIC int search_lease_by_mac(mac_address_t mac_addr, int ipversion)
{
    struct key_tree key_dhcplease;
    key_tree_init(&key_dhcplease);
    time_t now = vdhcpd_time();
    server_stats_main_t *sm = &server_stats_main;

    struct key_node *knode = key_first(&sm->key_server_stats);
    while (knode && knode->data) {
        dhcpd_server_stats_t *server_stats = (dhcpd_server_stats_t *)knode->data;
        struct vdhcpd_assignment *a, *n;
        if (ipversion == 4) {
            // IPv4实时租约
            list_for_each_entry_safe(a, n, &server_stats->dhcpv4_assignments, head)
            {
                if (!BCMP(&a->macaddr, &mac_addr, sizeof(mac_address_t))) {
                    return 1;
                }
            }
        } else if (ipversion == 6) {
            // IPv6实时租约
            list_for_each_entry_safe(a, n, &server_stats->dhcpv6_assignments, head)
            {
                if (!BCMP(&a->macaddr, &mac_addr, sizeof(mac_address_t)))
                    return 1;
            }
        }
        knode = key_next(knode);
    }
    return -1;
}
PRIVATE void delet_dhcplease(MYDBOP DBHandle, mac_address_t mac_addr, int ipversion)
{
    char sql[MINBUFFERLEN + 1] = {0};
    snprintf(sql, MINBUFFERLEN, "DELETE FROM tbdhcplease6 WHERE `mac`='" MACADDRFMT "' AND `ipversion`=%d", MACADDRBYTES(mac_addr), ipversion);
    x_log_debug("删除的MAC:'" MACADDRFMT "'", MACADDRBYTES(mac_addr));
    MyDBOp_ExecSQL(&DBHandle, sql);
}

PUBLIC void maint_dhcplease_stats()
{
    char sql[MINBUFFERLEN + 1] = {0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcplease6;");

    MYDBOP DBHandle;
    u16 ipversion;
    char buff[MINBUFFERLEN];
    mac_address_t mac_addr;
    // MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0) {
        MyDBOp_Destroy(&DBHandle);
        x_log_debug("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname);
        return;
    }
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        CSqlRecorDset_GetFieldValue_String(&Query, "mac", buff, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_U16(&Query, "ipversion", &ipversion);
        macaddress_parse(&mac_addr, buff);
        if (search_lease_by_mac(mac_addr, ipversion) < 0) {
            delet_dhcplease(DBHandle, mac_addr, ipversion);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_Destroy(&DBHandle);
}