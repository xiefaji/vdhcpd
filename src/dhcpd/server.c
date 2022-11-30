#include "dhcpd.h"

PRIVATE void dhcpd_upate_iface(dhcpd_server_t *dhcpd_server);
PRIVATE void dhcpd_upate_iface_lineip(dhcpd_server_t *dhcpd_server);
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
        xfree(dhcpd_server->pVLAN);
        xfree(dhcpd_server->pQINQ);
        dhcpd_lease_main_release(dhcpd_server->staticlease_main);
        key_tree_destroy2(&dhcpd_server->key_serverid, NULL);
        xfree(dhcpd_server);
    }
}

PUBLIC void dhcpd_server_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)p;
    if (dhcpd_server) {
        trash_queue_enqueue(pRecycleTrash, dhcpd_server->pVLAN);
        trash_queue_enqueue(pRecycleTrash, dhcpd_server->pQINQ);
        dhcpd_lease_main_recycle(dhcpd_server->staticlease_main, pRecycleTrash);
        key_tree_nodes_recycle(&dhcpd_server->key_serverid, pRecycleTrash, NULL);
        trash_queue_enqueue(pRecycleTrash, dhcpd_server);
    }
}

//服务配置
PUBLIC void dhcpd_server_reload(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpconfig;");

    PMYDBOP pDBHandle = &xHANDLE_Mysql;
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, pDBHandle->m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        u16 val16;
        u32 val32;
        char VLAN[MAXNAMELEN+1]={0},QINQ[MAXNAMELEN+1]={0};
        char tmpbuffer[MAXNAMELEN+1]={0};

        dhcpd_server_t *dhcpd_server = dhcpd_server_init();
        dhcpd_server->cfg_main = cfg_main;
        CSqlRecorDset_GetFieldValue_U32(&Query, "id", &dhcpd_server->nID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "lineid", &dhcpd_server->nLineID);
        CSqlRecorDset_GetFieldValue_U32(&Query, "enable", &dhcpd_server->nEnabled);
        CSqlRecorDset_GetFieldValue_String(&Query, "outervlan", VLAN, MAXNAMELEN);
        CSqlRecorDset_GetFieldValue_String(&Query, "innervlan", QINQ, MAXNAMELEN);
        dhcpd_server->pVLAN = GetVLAN_BITMASK(VLAN, strlen(VLAN), 0);
        dhcpd_server->pQINQ = GetVLAN_BITMASK(QINQ, strlen(QINQ), 0);
        CSqlRecorDset_GetFieldValue_U32(&Query, "stack", &dhcpd_server->mode);
        CSqlRecorDset_GetFieldValue_U32(&Query, "leasetime", &dhcpd_server->leasetime);

        //DHCPV4配置
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

        //DHCPV6配置

        //DHCP中继配置
        CSqlRecorDset_GetFieldValue_String(&Query, "identifier", dhcpd_server->dhcprelay.identifier, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_U32(&Query, "subnet", &val32);
        dhcpd_server->dhcprelay.v4.subnet.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U32(&Query, "upstream_ip", &val32);
        dhcpd_server->dhcprelay.v4.serverip.address = htonl(val32);
        CSqlRecorDset_GetFieldValue_U16(&Query, "upstream_port", &val16);
        dhcpd_server->dhcprelay.v4.serverport = htons(val16);
        CSqlRecorDset_GetFieldValue_U32(&Query, "outerlineid", &dhcpd_server->dhcprelay.v4.lineid);

        //MAC控制
        CSqlRecorDset_GetFieldValue_U32(&Query, "aclmode", &dhcpd_server->macctl.aclmode);
        CSqlRecorDset_GetFieldValue_String(&Query, "macgroup", tmpbuffer, MINNAMELEN);
        ParseUIntNums(tmpbuffer, dhcpd_server->macctl.aclgroup, DEFAULT_ACLGROUP_SIZE, 0);

        struct key_node *knode = key_rbinsert(&cfg_main->key_servers, dhcpd_server->nID, dhcpd_server);
        if (knode) {
            x_log_err("加载DHCP服务配置失败, ID冲突[%d].", dhcpd_server->nID);
            dhcpd_server_release(dhcpd_server);
        }

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
}

PRIVATE void dhcpd_server_reload_serverid(struct key_tree *key_serverid, const u32 nID)
{
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT * FROM tbdhcpserverfilter WHERE nID=%u;", nID);

    PMYDBOP pDBHandle = &xHANDLE_Mysql;
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, pDBHandle->m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    for (i32 idx = 0; idx < CSqlRecorDset_GetRecordCount(&Query); ++idx) {
        char ipaddr_string[MINNAMELEN+1]={0};
        ip4_address_t ipaddr;
        CSqlRecorDset_GetFieldValue_String(&Query, "szServerIP", ipaddr_string, MINNAMELEN);
        inet_pton(AF_INET, ipaddr_string, &ipaddr);

        key_rbinsert_u(key_serverid, ipaddr.address, ipaddr.address);

        CSqlRecorDset_MoveNext(&Query);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
}

//参数校验[]
PUBLIC void dhcpd_server_check(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_first(&cfg_main->key_servers);
    while (knode && knode->data) {
        dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)knode->data;
        assert(!key_rbinsert(&cfg_main->key_servers_line, dhcpd_server->nLineID, dhcpd_server));
        //加载静态租约
        dhcpd_lease_main_reload(dhcpd_server->staticlease_main, dhcpd_server->nLineID);
        dhcpd_lease_main_check(dhcpd_server->staticlease_main);
        dhcpd_server->server_stats = server_stats_find(dhcpd_server->nID);
        dhcpd_server_reload_serverid(&dhcpd_server->key_serverid, dhcpd_server->nID);
        knode = key_next(knode);
    }
}

//配置热更新
PUBLIC void dhcpd_server_update(void *cfg)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_first(&cfg_main->key_servers);
    while (knode && knode->data) {
        dhcpd_server_t *dhcpd_server = (dhcpd_server_t *)knode->data;
        dhcpd_upate_iface(dhcpd_server);//
        dhcpd_upate_iface_lineip(dhcpd_server);
        dhcpd_upate_relay4_iface(dhcpd_server);
        dhcpd_upate_relay6_iface(dhcpd_server);
        knode = key_next(knode);
    }
}

//读取线路配置
PRIVATE void dhcpd_upate_iface(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT a.driveid,b.name,b.networkcard,b.groupid,b.kind,b.mtu,b.vmac FROM tbinterface a JOIN tbinterfaceline b "
                                "WHERE a.id = b.networkcard and b.lineid=%u;", dhcpd_server->nLineID);

    PMYDBOP pDBHandle = &xHANDLE_Mysql;
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, pDBHandle->m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (CSqlRecorDset_GetRecordCount(&Query)) {
        u16 val16;
        u32 val32;
        char ifname[MINNAMELEN+1];
        char macaddr[MINNAMELEN+1];

        CSqlRecorDset_GetFieldValue_U32(&Query, "driveid", &val32);
        dhcpd_server->iface.driveid = val32;
        CSqlRecorDset_GetFieldValue_String(&Query, "name", ifname, MINNAMELEN);
        BCOPY(ifname, (char *)dhcpd_server->iface.ifname, MINNAMELEN);
        CSqlRecorDset_GetFieldValue_U32(&Query, "networkcard", &val32);
        dhcpd_server->iface.networkcard = val32;
        CSqlRecorDset_GetFieldValue_U16(&Query, "groupid", &val16);
        dhcpd_server->iface.groupid = val16;
        CSqlRecorDset_GetFieldValue_U32(&Query, "kind", &val32);
        dhcpd_server->iface.kind = val32;
        CSqlRecorDset_GetFieldValue_U32(&Query, "mtu", &val32);
        dhcpd_server->iface.mtu = val32;
        CSqlRecorDset_GetFieldValue_String(&Query, "vmac", macaddr, MINNAMELEN);
        macaddress_parse(&dhcpd_server->iface.macaddr, macaddr);
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
}

//读取线路IP[v4]
PRIVATE void dhcpd_upate_iface_lineip(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbinterfacelineip a WHERE a.nLineid=%u;", dhcpd_server->nLineID);

    PMYDBOP pDBHandle = &xHANDLE_Mysql;
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, pDBHandle->m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (!CSqlRecorDset_GetRecordCount(&Query)) {
        BZERO(sql, sizeof(sql));
        snprintf(sql, MINBUFFERLEN, "SELECT INET_NTOA(a.ip) AS szIP FROM tbinterfaceline a WHERE a.lineid=%u;", dhcpd_server->nLineID);
        CSqlRecorDset_ExecSQL(&Query, sql);
    }

    if (CSqlRecorDset_GetRecordCount(&Query)) {
        char ipaddr[MINNAMELEN+1]={0};
        ip4_address_t lineip;
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP", ipaddr, MINNAMELEN);
        inet_pton(AF_INET, ipaddr, &lineip);
        dhcpd_server->iface.ipaddr = lineip;
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
}

//读取中继线路配置[v4]
PRIVATE void dhcpd_upate_relay4_iface(dhcpd_server_t *dhcpd_server)
{
    char sql[MINBUFFERLEN+1]={0};
    snprintf(sql, MINBUFFERLEN, "SELECT a.szIP FROM tbinterfacelineip a WHERE a.nLineid=%u "
                                "AND INET_ATON(a.szIP) & (0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF = %u &  "
                                "(0xFFFFFFFF << (32 - nPrefix)) & 0xFFFFFFFF;",
             dhcpd_server->dhcprelay.v4.lineid, ntohl(dhcpd_server->dhcprelay.v4.serverip.address));

    PMYDBOP pDBHandle = &xHANDLE_Mysql;
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query, pDBHandle->m_pDB);
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_ExecSQL(&Query, sql);
    if (!CSqlRecorDset_GetRecordCount(&Query)) {
        BZERO(sql, sizeof(sql));
        snprintf(sql, MINBUFFERLEN, "SELECT INET_NTOA(a.ip) AS szIP FROM tbinterfaceline a WHERE a.lineid=%u;", dhcpd_server->dhcprelay.v4.lineid);
        CSqlRecorDset_ExecSQL(&Query, sql);
    }

    if (CSqlRecorDset_GetRecordCount(&Query)) {
        char ipaddr[MINNAMELEN+1]={0};
        ip4_address_t lineip;
        CSqlRecorDset_GetFieldValue_String(&Query, "szIP", ipaddr, MINNAMELEN);
        inet_pton(AF_INET, ipaddr, &lineip);
        dhcpd_server->dhcprelay.v4.lineip = lineip;
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
}

//读取中继线路配置[v6]
PRIVATE void dhcpd_upate_relay6_iface(dhcpd_server_t *dhcpd_server)
{

}

//DHCP服务查找
PUBLIC dhcpd_server_t *dhcpd_server_search(void *cfg, const u32 nID)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_rbsearch(&cfg_main->key_servers, nID);
    return (knode && knode->data) ? knode->data:NULL;
}

PUBLIC dhcpd_server_t *dhcpd_server_search_LineID(void *cfg, const u32 nLineID)
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)cfg;
    struct key_node *knode = key_rbsearch(&cfg_main->key_servers_line, nLineID);
    return (knode && knode->data) ? knode->data:NULL;
}

//黑/白名单匹配
PUBLIC int dhcpd_server_match_macaddr(dhcpd_server_t *dhcpd_server, const mac_address_t macaddr)
{
    int dodrop;
    switch (dhcpd_server->macctl.aclmode) {
    case ACL_MODE_BLACK:
        dodrop = 0;
        for (int idx=0; idx < DEFAULT_ACLGROUP_SIZE; ++idx) {
            const u32 groupid = dhcpd_server->macctl.aclgroup[idx];
            dodrop = macaddr_match(dhcpd_server->cfg_main, groupid, macaddr) ? 1:0;
            if (dodrop) break;
        }
        break;
    case ACL_MODE_WHITE:
        dodrop = 1;
        for (int idx=0; idx < DEFAULT_ACLGROUP_SIZE; ++idx) {
            const u32 groupid = dhcpd_server->macctl.aclgroup[idx];
            dodrop = macaddr_match(dhcpd_server->cfg_main, groupid, macaddr) ? 0:1;
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
