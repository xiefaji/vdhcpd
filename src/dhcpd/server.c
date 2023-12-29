#include "dhcpd.h"
#include "share/defines.h"
#include "share/xlog.h"

PRIVATE void dhcpd_update_config(dhcpd_server_t *dhcpd_server);
PRIVATE void dhcpd_upate_iface(dhcpd_server_t *dhcpd_server);
PRIVATE void dhcpd_upate_iface_lineip(dhcpd_server_t *dhcpd_server);
PRIVATE void dhcpd_upate_iface_lineip_all(dhcpd_server_t *dhcpd_server, trash_queue_t *pRecycleTrash);
PRIVATE void dhcpd_upate_iface_lineip6(dhcpd_server_t *dhcpd_server);
PRIVATE void dhcpd_upate_relay4_iface(dhcpd_server_t *dhcpd_server);
PRIVATE void dhcpd_upate_relay6_iface(dhcpd_server_t *dhcpd_server); 
PUBLIC dhcpd_server_t *dhcpd_server_init()
{
    dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)xmalloc(sizeof(dhcpd_server_t));
    BZERO(dhcpd_server, sizeof(dhcpd_server_t));
    dhcpd_server->staticlease_main = dhcpd_lease_main_init();
    key_tree_init(&dhcpd_server->key_serverid);
    return dhcpd_server;
}

PUBLIC void dhcpd_server_release(void *p)
{
    dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)p;
    if (dhcpd_server) {
        xEXACTVLAN_Free(dhcpd_server->pEXACTVLAN);
        dhcpd_lease_main_release(dhcpd_server->staticlease_main);
        key_tree_destroy2(&dhcpd_server->key_serverid, NULL);
        xfree(dhcpd_server);
    }
}

PUBLIC void dhcpd_server_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)p;
    if (dhcpd_server) {
        xEXACTVLAN_Recycle(dhcpd_server->pEXACTVLAN, pRecycleTrash);
        dhcpd_lease_main_recycle(dhcpd_server->staticlease_main, pRecycleTrash);
        key_tree_nodes_recycle(&dhcpd_server->key_serverid, pRecycleTrash, NULL);
        trash_queue_enqueue(pRecycleTrash, dhcpd_server);
    }
}

//服务配置
PUBLIC void dhcpd_server_reload(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    char sql[MINBUFFERLEN + 1] = {0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM %s;", DBTABLE_DHCP_SERVER);

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        u16 val16;
        u32 val32;
        char tmpbuffer[MAXNAMELEN + 1] = {0}, exactvlan[MAXNAMELEN + 1] = {0};

        dhcpd_server_t *dhcpd_server = dhcpd_server_init();
        dhcpd_server->cfg_main = cfg_main;

        //基础配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_U32(&Query, "id", &dhcpd_server->nID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "lineid", &dhcpd_server->nLineID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "enable", &dhcpd_server->nEnabled);
        CSqlRecorDset_GetFieldValue_String(&Query, "exactvlan", exactvlan, MAXNAMELEN);
        dhcpd_server->pEXACTVLAN = xEXACTVLAN_init(exactvlan, 1);
        CSqlRecorDset_GetFieldValue_U32(&Query, "stack", &dhcpd_server->mode);
        CSqlRecorDset_GetFieldValue_U32(&Query, "leasetime", &dhcpd_server->leasetime);
#else
        CSqlRecorDset_GetFieldValue_U32(&Query, "nID", &dhcpd_server->nID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nSwID", &dhcpd_server->nLineID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nEnable", &dhcpd_server->nEnabled);
        CSqlRecorDset_GetFieldValue_String(&Query, "exactvlan", exactvlan, MAXNAMELEN);
        dhcpd_server->pEXACTVLAN = xEXACTVLAN_init(exactvlan, 1);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nStack", &dhcpd_server->mode);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nLeaseTime", &dhcpd_server->leasetime);
#endif

        // DHCPV4服务器配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_U32(&Query, "ip_low", &val32);
        dhcpd_server->dhcpv4.startip.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "ip_up", &val32);
        dhcpd_server->dhcpv4.endip.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "gateway", &val32);
        dhcpd_server->dhcpv4.gateway.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "mask", &val32);
        dhcpd_server->dhcpv4.netmask.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "broadcast", &val32);
        dhcpd_server->dhcpv4.broadcast.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "dns1", &val32);
        dhcpd_server->dhcpv4.dns[0].address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "dns2", &val32);
        dhcpd_server->dhcpv4.dns[1].address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "wins1", &val32);
        dhcpd_server->dhcpv4.windns[0].address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "wins2", &val32);
        dhcpd_server->dhcpv4.windns[1].address = htonl(val32);
#else
        CSqlRecorDset_GetFieldValue_String(&Query, "szIPLow", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.startip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szIPUp", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.endip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szGateWay", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.gateway);
        CSqlRecorDset_GetFieldValue_String(&Query, "szMask", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.netmask);
        // CSqlRecorDset_GetFieldValue_U32(&Query, "broadcast", &val32);
        // dhcpd_server->dhcpv4.broadcast.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.dns[1]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szWins1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.windns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szWins2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.windns[1]);
#endif

        // DHCPV6服务器配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_String(&Query, "ip6_low", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.startip);
        CSqlRecorDset_GetFieldValue_String(&Query, "ip6_up", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.endip);
        CSqlRecorDset_GetFieldValue_String(&Query, "dhcp6gateway", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.gateway);
        CSqlRecorDset_GetFieldValue_U16(&Query, "prefix6", &dhcpd_server->dhcpv6.prefix);
        CSqlRecorDset_GetFieldValue_String(&Query, "dhcp6dns1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "dhcp6dns2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[1]);
#else
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP6Low", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.startip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP6Up", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.endip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szGateWay6", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.gateway);
        CSqlRecorDset_GetFieldValue_U16(&Query, "szPrefix", &dhcpd_server->dhcpv6.prefix);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns6_1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns6_2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[1]);
#endif

        // DHCP中继配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_String(&Query, "identifier", dhcpd_server->dhcprelay.identifier, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_U32(&Query, "subnet", &val32);
        dhcpd_server->dhcprelay.v4.subnet.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "upstream_ip", &val32);
        dhcpd_server->dhcprelay.v4.serverip.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U16(&Query, "upstream_port", &val16);
        dhcpd_server->dhcprelay.v4.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "outerlineid", &dhcpd_server->dhcprelay.v4.lineid);
        CSqlRecorDset_GetFieldValue_String(&Query, "upstream_ip_v6", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcprelay.v6.serverip);
        CSqlRecorDset_GetFieldValue_U16(&Query, "upstream_port_v6", &val16);
        dhcpd_server->dhcprelay.v6.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "outerlineid_v6", &dhcpd_server->dhcprelay.v6.lineid);
#else
        // CSqlRecorDset_GetFieldValue_String(&Query, "identifier", dhcpd_server->dhcprelay.identifier, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSubnet", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcprelay.v4.subnet);
        CSqlRecorDset_GetFieldValue_String(&Query, "szProxySerIP4", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcprelay.v4.serverip);
        CSqlRecorDset_GetFieldValue_U16(&Query, "szProxySerIP4", &val16);
        dhcpd_server->dhcprelay.v4.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nTxSw4ID", &dhcpd_server->dhcprelay.v4.lineid);
        CSqlRecorDset_GetFieldValue_String(&Query, "szProxySerIP4", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcprelay.v4.serverip);
        CSqlRecorDset_GetFieldValue_U16(&Query, "nProxySerPort6", &val16);
        dhcpd_server->dhcprelay.v6.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nTxSw6ID", &dhcpd_server->dhcprelay.v6.lineid);
#endif

        // MAC控制
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_U32(&Query, "aclmode", &dhcpd_server->macctl.aclmode);
        CSqlRecorDset_GetFieldValue_String(&Query, "macgroup", tmpbuffer, MINNAMELEN);
        ParseUIntNums(tmpbuffer, dhcpd_server->macctl.aclgroup, DEFAULT_ACLGROUP_SIZE, 0);
#else
        CSqlRecorDset_GetFieldValue_U32(&Query, "nAclMode", &dhcpd_server->macctl.aclmode);
        CSqlRecorDset_GetFieldValue_String(&Query, "szMacGroups", tmpbuffer, MINNAMELEN);
        ParseUIntNums(tmpbuffer, dhcpd_server->macctl.aclgroup, DEFAULT_ACLGROUP_SIZE, 0);
#endif

        //SLAAC
        CSqlRecorDset_GetFieldValue_U16(&Query, "szSlaacPrefix", &dhcpd_server->SLAAC.prefix);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSlaacGateWay", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->SLAAC.gateway);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSlaacDns1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->SLAAC.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSlaacDns2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->SLAAC.dns[1]);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nSlaacLeaseTime", &dhcpd_server->SLAAC.leasetime);

        for (int i = 0; i < 15; i++) {
            if (i < dhcpd_server->dhcpv6.prefix / 8)
                dhcpd_server->dhcpv6.prefix_addr.ip_u8[i] = dhcpd_server->dhcpv6.gateway.ip_u8[i];
            else
                dhcpd_server->dhcpv6.prefix_addr.ip_u8[i] = 0;
        }
        struct key_node *knode = key_rbinsert(&cfg_main->key_servers, dhcpd_server->nID, dhcpd_server);
        if (knode) {
            x_log_err("加载DHCP服务配置失败, ID冲突[%d].", dhcpd_server->nID);
            dhcpd_server_release(dhcpd_server);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

PRIVATE void dhcpd_server_reload_serverid(struct key_tree *key_serverid, const u32 nID)
{
    char sql[MINBUFFERLEN + 1] = {0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpserverfilter WHERE nID=%u;", nID);

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        char ipaddr_string[MINNAMELEN + 1] = {0};
        ip4_address_t ipaddr;
        CSqlRecorDset_GetFieldValue_String(&Query, "szServerIP", ipaddr_string, MINNAMELEN);
        inet_pton(AF_INET, ipaddr_string, &ipaddr);

        key_rbinsert_u(key_serverid, ipaddr.address, ipaddr.address);

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//参数校验[]
PUBLIC void dhcpd_server_check(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_first(&cfg_main->key_servers);
    while (knode && knode->data) {
        dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)knode->data;
        struct key_node *try_knode = key_rbinsert(&cfg_main->key_servers_line, dhcpd_server->nLineID, dhcpd_server);
        assert(!try_knode);
        //加载静态租约
        dhcpd_lease_main_reload(dhcpd_server->staticlease_main, dhcpd_server->nLineID);
        dhcpd_lease_main_check(dhcpd_server->staticlease_main);
        dhcpd_server->server_stats = server_stats_find(dhcpd_server->nID);
        dhcpd_server_reload_serverid(&dhcpd_server->key_serverid, dhcpd_server->nID);
        knode = key_next(knode);
    }
}

//配置热更新
PUBLIC void dhcpd_server_update(void *cfg, trash_queue_t *pRecycleTrash)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_first(&cfg_main->key_servers);
    while (knode && knode->data) {
        dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)knode->data;
        dhcpd_update_config(dhcpd_server);
        dhcpd_upate_iface(dhcpd_server); //
        dhcpd_upate_iface_lineip(dhcpd_server);
        dhcpd_upate_iface_lineip_all(dhcpd_server, pRecycleTrash);
        dhcpd_upate_iface_lineip6(dhcpd_server);
        dhcpd_upate_relay4_iface(dhcpd_server);
        dhcpd_upate_relay6_iface(dhcpd_server);
        knode = key_next(knode);
    }
}

PRIVATE void dhcpd_update_config(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN + 1] = {0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpserver  where nid =%d;", dhcpd_server->nID);

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (CSqlRecorDset_GetRecordCount(&Query)) {
        u16 val16;
        u32 val32;
        char tmpbuffer[MAXNAMELEN + 1] = {0}, exactvlan[MAXNAMELEN + 1] = {0};

        //基础配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_U32(&Query, "id", &dhcpd_server->nID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "lineid", &dhcpd_server->nLineID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "enable", &dhcpd_server->nEnabled);
        CSqlRecorDset_GetFieldValue_String(&Query, "exactvlan", exactvlan, MAXNAMELEN);
        dhcpd_server->pEXACTVLAN = xEXACTVLAN_init(exactvlan, 1);
        CSqlRecorDset_GetFieldValue_U32(&Query, "stack", &dhcpd_server->mode);
        CSqlRecorDset_GetFieldValue_U32(&Query, "leasetime", &dhcpd_server->leasetime);
#else
        CSqlRecorDset_GetFieldValue_U32(&Query, "nID", &dhcpd_server->nID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nSwID", &dhcpd_server->nLineID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nEnable", &dhcpd_server->nEnabled);
        CSqlRecorDset_GetFieldValue_String(&Query, "exactvlan", exactvlan, MAXNAMELEN);
        dhcpd_server->pEXACTVLAN = xEXACTVLAN_init(exactvlan, 1);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nStack", &dhcpd_server->mode);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nLeaseTime", &dhcpd_server->leasetime);
#endif

        // DHCPV4服务器配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_U32(&Query, "ip_low", &val32);
        dhcpd_server->dhcpv4.startip.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "ip_up", &val32);
        dhcpd_server->dhcpv4.endip.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "gateway", &val32);
        dhcpd_server->dhcpv4.gateway.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "mask", &val32);
        dhcpd_server->dhcpv4.netmask.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "broadcast", &val32);
        dhcpd_server->dhcpv4.broadcast.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "dns1", &val32);
        dhcpd_server->dhcpv4.dns[0].address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "dns2", &val32);
        dhcpd_server->dhcpv4.dns[1].address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "wins1", &val32);
        dhcpd_server->dhcpv4.windns[0].address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "wins2", &val32);
        dhcpd_server->dhcpv4.windns[1].address = htonl(val32);
#else
        CSqlRecorDset_GetFieldValue_String(&Query, "szIPLow", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.startip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szIPUp", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.endip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szGateWay", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.gateway);
        CSqlRecorDset_GetFieldValue_String(&Query, "szMask", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.netmask);
        // CSqlRecorDset_GetFieldValue_U32(&Query, "broadcast", &val32);
        // dhcpd_server->dhcpv4.broadcast.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.dns[1]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szWins1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.windns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szWins2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcpv4.windns[1]);
#endif

        // DHCPV6服务器配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_String(&Query, "ip6_low", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.startip);
        CSqlRecorDset_GetFieldValue_String(&Query, "ip6_up", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.endip);
        CSqlRecorDset_GetFieldValue_String(&Query, "dhcp6gateway", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.gateway);
        CSqlRecorDset_GetFieldValue_U16(&Query, "prefix6", &dhcpd_server->dhcpv6.prefix);
        CSqlRecorDset_GetFieldValue_String(&Query, "dhcp6dns1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "dhcp6dns2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[1]);
#else
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP6Low", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.startip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP6Up", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.endip);
        CSqlRecorDset_GetFieldValue_String(&Query, "szGateWay6", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.gateway);
        CSqlRecorDset_GetFieldValue_U16(&Query, "szPrefix", &dhcpd_server->dhcpv6.prefix);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns6_1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szDns6_2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcpv6.dns[1]);
#endif

        // DHCP中继配置
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_String(&Query, "identifier", dhcpd_server->dhcprelay.identifier, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_U32(&Query, "subnet", &val32);
        dhcpd_server->dhcprelay.v4.subnet.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "upstream_ip", &val32);
        dhcpd_server->dhcprelay.v4.serverip.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U16(&Query, "upstream_port", &val16);
        dhcpd_server->dhcprelay.v4.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "outerlineid", &dhcpd_server->dhcprelay.v4.lineid);
        CSqlRecorDset_GetFieldValue_String(&Query, "upstream_ip_v6", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcprelay.v6.serverip);
        CSqlRecorDset_GetFieldValue_U16(&Query, "upstream_port_v6", &val16);
        dhcpd_server->dhcprelay.v6.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "outerlineid_v6", &dhcpd_server->dhcprelay.v6.lineid);
#else
        // CSqlRecorDset_GetFieldValue_String(&Query, "identifier", dhcpd_server->dhcprelay.identifier, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSubnet", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcprelay.v4.subnet);
        CSqlRecorDset_GetFieldValue_String(&Query, "szProxySerIP4", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET, tmpbuffer, &dhcpd_server->dhcprelay.v4.serverip);
        CSqlRecorDset_GetFieldValue_U16(&Query, "szProxySerIP4", &val16);
        dhcpd_server->dhcprelay.v4.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nTxSw4ID", &dhcpd_server->dhcprelay.v4.lineid);
        CSqlRecorDset_GetFieldValue_String(&Query, "szProxySerIP4", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->dhcprelay.v4.serverip);
        CSqlRecorDset_GetFieldValue_U16(&Query, "nProxySerPort6", &val16);
        dhcpd_server->dhcprelay.v6.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nTxSw6ID", &dhcpd_server->dhcprelay.v6.lineid);
#endif

        // MAC控制
#ifndef VERSION_VNAAS
        CSqlRecorDset_GetFieldValue_U32(&Query, "aclmode", &dhcpd_server->macctl.aclmode);
        CSqlRecorDset_GetFieldValue_String(&Query, "macgroup", tmpbuffer, MINNAMELEN);
        ParseUIntNums(tmpbuffer, dhcpd_server->macctl.aclgroup, DEFAULT_ACLGROUP_SIZE, 0);
#else
        CSqlRecorDset_GetFieldValue_U32(&Query, "nAclMode", &dhcpd_server->macctl.aclmode);
        CSqlRecorDset_GetFieldValue_String(&Query, "szMacGroups", tmpbuffer, MINNAMELEN);
        ParseUIntNums(tmpbuffer, dhcpd_server->macctl.aclgroup, DEFAULT_ACLGROUP_SIZE, 0);
#endif
        //SLAAC
        CSqlRecorDset_GetFieldValue_U16(&Query, "szSlaacPrefix", &dhcpd_server->SLAAC.prefix);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSlaacGateWay", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->SLAAC.gateway);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSlaacDns1", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->SLAAC.dns[0]);
        CSqlRecorDset_GetFieldValue_String(&Query, "szSlaacDns2", tmpbuffer, MINNAMELEN);
        inet_pton(AF_INET6, tmpbuffer, &dhcpd_server->SLAAC.dns[1]);
        CSqlRecorDset_GetFieldValue_U32(&Query, "nSlaacLeaseTime", &dhcpd_server->SLAAC.leasetime);
        for (int i = 0; i < 15; i++) {
            if (i < dhcpd_server->dhcpv6.prefix / 8)
                dhcpd_server->dhcpv6.prefix_addr.ip_u8[i] = dhcpd_server->dhcpv6.gateway.ip_u8[i];
            else
                dhcpd_server->dhcpv6.prefix_addr.ip_u8[i] = 0;
        }
        #ifdef DEBUG
        x_log_debug("配置更新完毕");
        #endif // DEBUG
    }

    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//读取线路配置
PRIVATE void dhcpd_upate_iface(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN + 1] = {0};
#ifndef VERSION_VNAAS
    snprintf(sql, MINBUFFERLEN, "SELECT a.driveid,b.name,b.networkcard,b.mtu,b.vmac FROM tbinterface a JOIN tbinterfaceline b "
                                "WHERE a.id = b.networkcard and b.lineid = %u;",
             dhcpd_server->nLineID);
#else
    snprintf(sql, MINBUFFERLEN, "SELECT a.nSwID AS lineid,a.nHwDevID AS driveid,a.szName AS name,b.nMtu AS mtu,b.szVMac AS vmac FROM tbsw_if a JOIN tbsw_if_eth b "
                                "WHERE a.nSwID = b.nSwID AND a.nSwID = %u;",
             dhcpd_server->nLineID);
#endif

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (CSqlRecorDset_GetRecordCount(&Query)) {
        u32 val32;
        char ifname[MINNAMELEN + 1];
        char macaddr[MINNAMELEN + 1];

        CSqlRecorDset_GetFieldValue_U32(&Query, "driveid", &val32);
        dhcpd_server->iface.driveid = val32;
        CSqlRecorDset_GetFieldValue_String(&Query, "name", ifname, MINNAMELEN);
        BCOPY(ifname, (char *)dhcpd_server->iface.ifname, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_U32(&Query, "mtu", &val32);
        dhcpd_server->iface.mtu = val32;
        CSqlRecorDset_GetFieldValue_String(&Query, "vmac", macaddr, MINNAMELEN);
        macaddress_parse(&dhcpd_server->iface.macaddr, macaddr);

        dhcpd_server->iface.ipaddr6_local.ip_u8[0] = 0xFE;
        dhcpd_server->iface.ipaddr6_local.ip_u8[1] = 0x80;
        dhcpd_server->iface.ipaddr6_local.ip_u8[8] = dhcpd_server->iface.macaddr.addr[0];
        dhcpd_server->iface.ipaddr6_local.ip_u8[9] = dhcpd_server->iface.macaddr.addr[1];
        dhcpd_server->iface.ipaddr6_local.ip_u8[10] = dhcpd_server->iface.macaddr.addr[2];
        dhcpd_server->iface.ipaddr6_local.ip_u8[11] = 0xFE;
        dhcpd_server->iface.ipaddr6_local.ip_u8[12] = 0x80;
        dhcpd_server->iface.ipaddr6_local.ip_u8[13] = dhcpd_server->iface.macaddr.addr[3];
        dhcpd_server->iface.ipaddr6_local.ip_u8[14] = dhcpd_server->iface.macaddr.addr[4];
        dhcpd_server->iface.ipaddr6_local.ip_u8[15] = dhcpd_server->iface.macaddr.addr[5];
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//读取线路网关IP[v4]
PRIVATE void dhcpd_upate_iface_lineip(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN + 1] = {0};
#ifndef VERSION_VNAAS
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbinterfacelineip a WHERE a.nLineid = %u and nIPver = 4;", dhcpd_server->nLineID);
#else
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbsw_more_ip a WHERE a.nSwID = %u AND nIPVer = 4;", dhcpd_server->nLineID);
#endif

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (!CSqlRecorDset_GetRecordCount(&Query)) {
        BZERO(sql, sizeof(sql));
#ifndef VERSION_VNAAS
        snprintf(sql, MINBUFFERLEN, "SELECT INET_NTOA(a.ip) AS szIP FROM tbinterfaceline a WHERE a.lineid = %u;", dhcpd_server->nLineID);
#else
        snprintf(sql, MINBUFFERLEN, "SELECT a.szIP AS szIP FROM tbsw_more_ip a WHERE a.nSwID = %u AND a.nIPVer = 4;", dhcpd_server->nLineID);
#endif
        CSqlRecorDset_ExecSQL(&Query, sql);
    }

    if (CSqlRecorDset_GetRecordCount(&Query)) {
        char ipaddr[MINNAMELEN + 1] = {0};
        ip4_address_t lineip;
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP", ipaddr, MINNAMELEN);
        inet_pton(AF_INET, ipaddr, &lineip);
        dhcpd_server->iface.ipaddr = lineip;
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//读取线路网关IP[v4] ALL
typedef struct {
    ip4_address_t gateway;
    ip4_address_t netmask;
} ip4_gateway_t;

PRIVATE ip4_gateway_t *ip4_gateway_init(const char *szIP, const int nPrefix)
{
    ip4_gateway_t *ip4_gateway = (ip4_gateway_t *)xmalloc(sizeof(ip4_gateway_t));
    BZERO(ip4_gateway, sizeof(ip4_gateway_t));
    inet_pton(AF_INET, szIP, &ip4_gateway->gateway);
    ip4_gateway->netmask.address = get_netmask(nPrefix);
    return ip4_gateway;
}

PRIVATE void ip4_gateway_release(void *p)
{
    ip4_gateway_t *ip4_gateway = (ip4_gateway_t *)p;
    if (ip4_gateway) xfree(ip4_gateway);
}

PRIVATE void ip4_gateway_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    ip4_gateway_t *ip4_gateway = (ip4_gateway_t *)p;
    if (ip4_gateway) trash_queue_enqueue(pRecycleTrash, ip4_gateway);
}

PUBLIC int iface_subnet_match(dhcpd_server_t *dhcpd_server, const ip4_address_t ipaddr)
{
    int retcode = 0;
    if (!dhcpd_server->iface.key_all_lineip4 || !ipaddr.address)
        return 1; //默认放行

    struct key_node *knode = key_first(dhcpd_server->iface.key_all_lineip4);
    while (knode && knode->data) {
        ip4_gateway_t *ip4_gateway = (ip4_gateway_t *)knode->data;
        if (IPv4_SUBNET(&ipaddr, &ip4_gateway->netmask) == IPv4_SUBNET(&ip4_gateway->gateway, &ip4_gateway->netmask)) {
            retcode = 1;
            break;
        }
        knode = key_next(knode);
    }
    return retcode;
}

PRIVATE void dhcpd_upate_iface_lineip_all(dhcpd_server_t *dhcpd_server, trash_queue_t *pRecycleTrash)
{
    char sql[MINBUFFERLEN + 1] = {0};
#ifndef VERSION_VNAAS
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP, a.nPrefix FROM tbinterfacelineip a WHERE a.nLineid = %u and nIPver = 4;", dhcpd_server->nLineID);
#else
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP, a.nPrefix FROM tbsw_more_ip a WHERE a.nSwID = %u AND nIPVer = 4;", dhcpd_server->nLineID);
#endif

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);

    struct key_tree *temp = dhcpd_server->iface.key_all_lineip4;
    struct key_tree *key_all_lineip4 = (struct key_tree *)xmalloc(sizeof(struct key_tree));
    key_tree_init(key_all_lineip4);

    for (int idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        char szIP[MINNAMELEN + 1] = {0};
        int nPrefix;
        CSqlRecorDset_GetFieldValue_I32(&Query, "nPrefix", &nPrefix);
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP", szIP, MINNAMELEN);
        ip4_gateway_t *ip4_gateway = ip4_gateway_init(szIP, nPrefix);
        struct key_node *knode = key_rbinsert(key_all_lineip4, ip4_gateway->gateway.address, ip4_gateway);
        if (knode) ip4_gateway_release(ip4_gateway);
        CSqlRecorDset_MoveNext(&Query);
    }

    dhcpd_server->iface.key_all_lineip4 = key_all_lineip4;
    if (temp) {
        if (pRecycleTrash) {
            key_tree_nodes_recycle(temp, pRecycleTrash, ip4_gateway_recycle);
            trash_queue_enqueue(pRecycleTrash, temp);
        } else {
            key_tree_destroy2(temp, ip4_gateway_release);
            xfree(temp);
        }
    }

    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//读取线路网关IP[v6]
PRIVATE void dhcpd_upate_iface_lineip6(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN + 1] = {0};
#ifndef VERSION_VNAAS
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbinterfacelineip a WHERE a.nLineid = %u and nIPver = 6;", dhcpd_server->nLineID);
#else
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbsw_more_ip a WHERE a.nSwID = %u AND nIPVer = 6;", dhcpd_server->nLineID);
#endif

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (!CSqlRecorDset_GetRecordCount(&Query)) {
        BZERO(sql, sizeof(sql));
#ifndef VERSION_VNAAS
        snprintf(sql, MINBUFFERLEN, "SELECT a.ipv6 AS szIP FROM tbinterfaceline a WHERE a.lineid = %u;", dhcpd_server->nLineID);
#else
        snprintf(sql, MINBUFFERLEN, "SELECT a.szIP AS szIP FROM tbsw_more_ip a WHERE a.nSwID = %u AND a.nIPVer = 6;", dhcpd_server->nLineID);
#endif
        CSqlRecorDset_ExecSQL(&Query, sql);
    }

    if (CSqlRecorDset_GetRecordCount(&Query)) {
        char ipaddr[MINNAMELEN + 1] = {0};
        ip6_address_t lineip;
        char *p, *next = NULL;
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP", ipaddr, MINNAMELEN);
        p = stok(ipaddr, "/", &next);
        if (p) inet_pton(AF_INET6, p, &lineip);
        dhcpd_server->iface.ipaddr6 = lineip;
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//读取中继线路[出口]配置[v4]
PRIVATE void dhcpd_upate_relay4_iface(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN + 1] = {0};
#ifndef VERSION_VNAAS
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbinterfacelineip a WHERE a.nLineid = %u and nIPver = 4 "
                                "AND INET_ATON(a.szIP) & (0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF = %u &  "
                                "(0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF;",
             dhcpd_server->dhcprelay.v4.lineid, ntohl(dhcpd_server->dhcprelay.v4.serverip.address));
#else
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbsw_more_ip a WHERE a.nSwID = %u AND nIPver = 4 "
                                "AND INET_ATON(a.szIP) & (0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF = %u &  "
                                "(0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF;",
             dhcpd_server->dhcprelay.v4.lineid, ntohl(dhcpd_server->dhcprelay.v4.serverip.address));
#endif

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (!CSqlRecorDset_GetRecordCount(&Query)) {
        BZERO(sql, sizeof(sql));
#ifndef VERSION_VNAAS
        snprintf(sql, MINBUFFERLEN, "SELECT INET_NTOA(a.ip) AS szIP FROM tbinterfaceline a WHERE a.lineid = %u;", dhcpd_server->dhcprelay.v4.lineid);
#else
        snprintf(sql, MINBUFFERLEN, "SELECT a.szIP AS szIP FROM tbsw_more_ip a WHERE a.nSwID = %u AND a.nIPVer = 4;", dhcpd_server->dhcprelay.v4.lineid);
#endif
        CSqlRecorDset_ExecSQL(&Query, sql);
    }

    if (CSqlRecorDset_GetRecordCount(&Query)) {
        char ipaddr[MINNAMELEN + 1] = {0};
        ip4_address_t lineip;
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP", ipaddr, MINNAMELEN);
        inet_pton(AF_INET, ipaddr, &lineip);
        dhcpd_server->dhcprelay.v4.lineip = lineip;
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

//读取中继线路[出口]配置[v6]
PRIVATE void dhcpd_upate_relay6_iface(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN + 1] = {0};
    //    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbinterfacelineip a WHERE a.nLineid = %u and nIPver = 6 "
    //                                "AND INET_ATON(a.szIP) & (0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF = %u &  "
    //                                "(0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF;",
    //             dhcpd_server->dhcprelay.v6.lineid, ntohl(dhcpd_server->dhcprelay.v6.serverip.address));

    MYDBOP DBHandle;
    MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, cfg_mysql.dbname) < 0)
        return;
    MYSQLRECORDSET Query = {0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, DBHandle.m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (!CSqlRecorDset_GetRecordCount(&Query)) {
        BZERO(sql, sizeof(sql));
#ifndef VERSION_VNAAS
        snprintf(sql, MINBUFFERLEN, "SELECT a.ipv6 AS szIP FROM tbinterfaceline a WHERE a.lineid = %u;", dhcpd_server->dhcprelay.v6.lineid);
#else
        snprintf(sql, MINBUFFERLEN, "SELECT a.szIP AS szIP FROM tbsw_more_ip a WHERE a.nSwID = %u AND a.nIPVer = 6;", dhcpd_server->dhcprelay.v6.lineid);
#endif
        CSqlRecorDset_ExecSQL(&Query, sql);
    }

    if (CSqlRecorDset_GetRecordCount(&Query)) {
        char ipaddr[MINNAMELEN + 1] = {0};
        ip6_address_t lineip;
        char *p, *next = NULL;
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP", ipaddr, MINNAMELEN);
        p = stok(ipaddr, "/", &next);
        if (p) inet_pton(AF_INET6, p, &lineip);
        dhcpd_server->dhcprelay.v6.lineip = lineip;
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    MyDBOp_CloseDB(&DBHandle);
}

// DHCP服务查找
PUBLIC dhcpd_server_t *dhcpd_server_search(void *cfg, const u32 nID)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_rbsearch(&cfg_main->key_servers, nID);
    return (knode && knode->data) ? knode->data : NULL;
}

PUBLIC dhcpd_server_t *dhcpd_server_search_LineID(void *cfg, const u32 nLineID)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_rbsearch(&cfg_main->key_servers_line, nLineID);
    return (knode && knode->data) ? knode->data : NULL;
}

//黑/白名单匹配
PUBLIC int dhcpd_server_match_macaddr(dhcpd_server_t *dhcpd_server, const mac_address_t macaddr)
{
    int dodrop;
    switch (dhcpd_server->macctl.aclmode) {
    case ACL_MODE_BLACK:
        dodrop = 0;
        for (int idx = 0; idx < DEFAULT_ACLGROUP_SIZE; ++idx) {
            const u32 groupid = dhcpd_server->macctl.aclgroup[idx];
            dodrop = macaddr_match(dhcpd_server->cfg_main, groupid, macaddr) ? 1 : 0;
            if (dodrop) break;
        }
        break;
    case ACL_MODE_WHITE:
        dodrop = 1;
        for (int idx = 0; idx < DEFAULT_ACLGROUP_SIZE; ++idx) {
            const u32 groupid = dhcpd_server->macctl.aclgroup[idx];
            dodrop = macaddr_match(dhcpd_server->cfg_main, groupid, macaddr) ? 0 : 1;
            if (!dodrop) break;
        }
        break;
    default:
        dodrop = 0;
        break;
    }
    return dodrop;
}

PUBLIC dhcpd_staticlease_t *dhcpd_server_staticlease_search_macaddr(dhcpd_server_t *dhcpd_server, const mac_address_t macaddr, const int ipstack)
{
    switch (ipstack) {
    case 4: return staticlease_search4_macaddr(dhcpd_server->staticlease_main, macaddr);
    case 6: return staticlease_search6_macaddr(dhcpd_server->staticlease_main, macaddr);
    default: return NULL;
    }
}
