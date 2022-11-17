#include "dhcpd.h"

PUBLIC vdhcpd_main_t vdhcpd_main;
PUBLIC time_t global_time;
PRIVATE int vdhcpd_maintain(void *p, trash_queue_t *pRecycleTrash);
PRIVATE vdhcpd_cfg_t *vdhcpd_cfg_reload();
PRIVATE void vdhcpd_cfg_release(vdhcpd_cfg_t *cfg_main);
PRIVATE void vdhcpd_cfg_recycle(vdhcpd_cfg_t *cfg_main, trash_queue_t *pRecycleTrash);

PRIVATE void database_connect()
{
    MyDBOp_Init(&xHANDLE_Mysql);
    vradiusd_cfg_mysql_t cfg_mysql;
    vradiusd_cfg_get_mysql(&cfg_mysql);
    if (!MyDBOp_OpenDB(&xHANDLE_Mysql, cfg_mysql.user, cfg_mysql.pass, cfg_mysql.dbname, cfg_mysql.ip, cfg_mysql.port)) {
        x_log_err("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname);
        exit(0);
    }
    x_log_info("%s:%d 数据库连接成功.", __FUNCTION__, __LINE__);
    MyDBOp_ExecSQL_1(&xHANDLE_Mysql, "set names utf8");
}

PUBLIC int vdhcpd_init()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    BZERO(vdm, sizeof(vdhcpd_main_t));

    database_connect();

    vdm->sockfd_main = -1;
    vdm->sockfd_relay4 = -1;
    vdm->sockfd_relay6 = -1;
    vdm->sockfd_api = -1;
    return 0;
}

PUBLIC int vdhcpd_release()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;

    if (vdm->sockfd_main > 0) close(vdm->sockfd_main);
    vdm->sockfd_main = -1;
    if (vdm->sockfd_relay4 > 0) close(vdm->sockfd_relay4);
    vdm->sockfd_relay4 = -1;
    if (vdm->sockfd_relay6 > 0) close(vdm->sockfd_relay6);
    vdm->sockfd_relay6 = -1;
    if (vdm->sockfd_api  > 0) close(vdm->sockfd_api);
    vdm->sockfd_api = -1;

    vdhcpd_cfg_release(vdm->cfg_main);

    MyDBOp_Destroy(&xHANDLE_Mysql);
    return 0;
}

PUBLIC int vdhcpd_shutdown()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    shutdown(vdm->sockfd_main, SHUT_RDWR);
    shutdown(vdm->sockfd_relay4, SHUT_RDWR);
    shutdown(vdm->sockfd_relay6, SHUT_RDWR);
    shutdown(vdm->sockfd_api, SHUT_RDWR);
    return 0;
}

PUBLIC int vdhcpd_start()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;

    //初始化配置
    vdm->cfg_main = vdhcpd_cfg_reload();
    assert(vdm->cfg_main);

    x_log_warn("%s Start. version[%s] pid[%d]...", PACKAGE_NAME"["PACKAGE_MODULES"]", PACKAGE_VERSION, getpid());

    xthread_create(&vdm->mtThread, "Maintain", vdm, NULL, vdhcpd_maintain, NULL, 0, 0);
    xthread_create(&vdm->apiThread, "API", vdm, api_main_init, api_main_start, api_main_clean, 0, 0);
    xthread_create(&vdm->relay4Thread, "Relay4", vdm, relay4_main_init, relay4_main_start, relay4_main_clean, 0, 0);
    xthread_create(&vdm->relay6Thread, "Relay6", vdm, relay6_main_init, relay6_main_start, relay6_main_clean, 0, 0);
    xthread_create(&vdm->mThread, "Main", vdm, local_main_init, local_main_start, local_main_clean, 1, 0);
    return 0;
}

PRIVATE int vdhcpd_maintain(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;
    PRIVATE unsigned int lasttick_mysql,last_rotate,last_update;

    //数据库连接保活
    if (CMP_COUNTER(lasttick_mysql, 60)) {
        MyDBOp_Ping(&xHANDLE_Mysql);
        SET_COUNTER(lasttick_mysql);
    }

    //日志文件句柄保活
    if (CMP_COUNTER(last_rotate, 60)) {
        xlog_rotate(NULL);
        SET_COUNTER(last_rotate);
    }

    if (vdm->reload_vdhcpd) {//配置重载
        __sync_fetch_and_and(&vdm->reload_vdhcpd, 0);
        vdhcpd_cfg_t *cfg_main = vdhcpd_cfg_reload();
        vdhcpd_cfg_recycle(vdm->cfg_main, pRecycleTrash);
        vdm->cfg_main = cfg_main;
    } else if (CMP_COUNTER(last_update, 30)) {//局部参数动态更新
        dhcpd_server_update(vdm->cfg_main);
        SET_COUNTER(last_update);
    }

    return xTHREAD_DEFAULT_INTERVAL;
}

//配置加载
PRIVATE vdhcpd_cfg_t *vdhcpd_cfg_reload()
{
    vdhcpd_cfg_t *cfg_main = (vdhcpd_cfg_t *)xmalloc(sizeof(vdhcpd_cfg_t));
    BZERO(cfg_main, sizeof(vdhcpd_cfg_t));
    key_tree_init(&cfg_main->key_servers);
    key_tree_init(&cfg_main->key_servers_line);
    key_tree_init(&cfg_main->key_macaddr_group);

    //加载DHCP服务
    dhcpd_server_reload(cfg_main);
    dhcpd_server_check(cfg_main);
    dhcpd_server_update(cfg_main);
    //加载MAC地址列表
    macaddr_acl_reload(cfg_main);
    macaddr_acl_check(cfg_main);
    return cfg_main;
}

PRIVATE void vdhcpd_cfg_release(vdhcpd_cfg_t *cfg_main)
{
    key_tree_destroy2(&cfg_main->key_servers_line, NULL);
    key_tree_destroy2(&cfg_main->key_servers, dhcpd_server_release);
    key_tree_destroy2(&cfg_main->key_macaddr_group, macaddr_group_release);
    xfree(cfg_main);
}

PRIVATE void vdhcpd_cfg_recycle(vdhcpd_cfg_t *cfg_main, trash_queue_t *pRecycleTrash)
{
    key_tree_nodes_recycle(&cfg_main->key_servers_line, pRecycleTrash, NULL);
    key_tree_nodes_recycle(&cfg_main->key_servers, pRecycleTrash, dhcpd_server_recycle);
    key_tree_nodes_recycle(&cfg_main->key_macaddr_group, pRecycleTrash, macaddr_group_recycle);
    trash_queue_enqueue(pRecycleTrash, cfg_main);
}
