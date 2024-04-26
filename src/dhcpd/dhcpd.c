#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "dhcpd.h"
#include "share/xlog.h"

PUBLIC vdhcpd_main_t vdhcpd_main;
PUBLIC time_t global_time;
PUBLIC cfg_mysql_t cfg_mysql;
PRIVATE int urandom_fd = -1;
PRIVATE void vdhcpd_starttime(vdhcpd_main_t *vdm);
PRIVATE int vdhcpd_maintain(void *p, trash_queue_t *pRecycleTrash);
PRIVATE int vdhcpd_db_start(void *p, trash_queue_t *pRecycleTrassh);
PRIVATE vdhcpd_cfg_t *vdhcpd_cfg_reload();
PRIVATE void vdhcpd_cfg_release(vdhcpd_cfg_t *cfg_main);
PRIVATE void vdhcpd_cfg_recycle(vdhcpd_cfg_t *cfg_main, trash_queue_t *pRecycleTrash);

PUBLIC int database_init()
{
    cfg_get_mysql(&cfg_mysql);
    return 0;
}

PUBLIC int database_connect(PMYDBOP pDBHandle, const char *dbname)
{
    MyDBOp_Init(pDBHandle);
    if (!MyDBOp_OpenDB(pDBHandle, cfg_mysql.user, cfg_mysql.pass, dbname, cfg_mysql.ip, cfg_mysql.port)) { 
        // x_log_debug("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname);  
        return -1;
    } 
    MyDBOp_ExecSQL_1(pDBHandle, "set names utf8");

    return 0;
}

PUBLIC time_t vdhcpd_time(void)
{
    //    struct timespec ts;
    //    clock_gettime(CLOCK_MONOTONIC, &ts);
    //    return ts.tv_sec;
    return global_time;
}

PUBLIC int vdhcpd_urandom(void *data, size_t len)
{
    return read(urandom_fd, data, len);
}

PRIVATE void vdhcpd_urandom_init()
{
    if ((urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC)) < 0)
        x_log_warn("%s:%d [%s].", __FUNCTION__, __LINE__, strerror(errno));
}

PRIVATE void vdhcpd_urandom_release()
{
    if (urandom_fd > 0) close(urandom_fd);
    urandom_fd = -1;
}

PUBLIC int vdhcpd_init()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    BZERO(vdm, sizeof(vdhcpd_main_t));

    vdm->sockfd_main = -1;
    vdm->sockfd_raw4 = -1;
    vdm->sockfd_raw6 = -1;
    vdm->sockfd_relay4 = -1;
    vdm->sockfd_relay6 = -1;
    vdm->sockfd_api = -1;
    vdm->sockfd_webaction = -1;
    vdm->filter_subnet = filter_subnet;
    stats_main_init(&vdm->stats_main);
    db_process_init(&vdm->db_process);
    server_stats_main_init();
    vdm->filter_tree = macaddr_filter_init(path_cfg.filterfile);
    vdhcpd_urandom_init();
    return 0;
}

PUBLIC int vdhcpd_release()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;

    if (vdm->sockfd_main > 0) close(vdm->sockfd_main);
    vdm->sockfd_main = -1;
    if (vdm->sockfd_raw4 > 0) close(vdm->sockfd_raw4);
    vdm->sockfd_raw4 = -1;
    if (vdm->sockfd_raw6 > 0) close(vdm->sockfd_raw6);
    vdm->sockfd_raw6 = -1;
    if (vdm->sockfd_relay4 > 0) close(vdm->sockfd_relay4);
    vdm->sockfd_relay4 = -1;
    if (vdm->sockfd_relay6 > 0) close(vdm->sockfd_relay6);
    vdm->sockfd_relay6 = -1;
    if (vdm->sockfd_api > 0) close(vdm->sockfd_api);
    vdm->sockfd_api = -1;
    if (vdm->sockfd_webaction > 0) close(vdm->sockfd_webaction);
    vdm->sockfd_webaction = -1;

    vdhcpd_cfg_release(vdm->cfg_main);
    stats_main_release(&vdm->stats_main);
    db_process_destroy(&vdm->db_process);
    server_stats_main_release();
    macaddr_filter_release(vdm->filter_tree);
    vdhcpd_urandom_release();
#ifdef VERSION_VNAAS
    unlink(VNAAS_DHCP_IPC_DGRAM_SOCK);
    unlink(VNAAS_DHCP_API_DGRAM_SOCK);
#endif
    return 0;
}

PUBLIC int vdhcpd_shutdown()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    shutdown(vdm->sockfd_main, SHUT_RDWR);
    shutdown(vdm->sockfd_relay4, SHUT_RDWR);
    shutdown(vdm->sockfd_relay6, SHUT_RDWR);
    shutdown(vdm->sockfd_api, SHUT_RDWR);
    shutdown(vdm->sockfd_webaction, SHUT_RDWR);
    return 0;
}

PRIVATE void vdhcpd_starttime(vdhcpd_main_t *vdm)
{
    char sql[MINBUFFERLEN + 1] = {0};
    char *dbname = NULL;
#ifndef VERSION_VNAAS
    int len = snprintf(sql, MINBUFFERLEN, "INSERT INTO tbserverinfo (`server`,`ver`,`start`,`pid`) "
                                          "VALUES ('xsdhcp','" PACKAGE_VERSION "',%u,%u) "
                                          "ON DUPLICATE KEY UPDATE `ver`='" PACKAGE_VERSION "',`start`=%u,`pid`=%u;",
                       (u32)time(NULL), getpid(), (u32)time(NULL), getpid());
    dbname = cfg_mysql.dbname;
#else
    int len = snprintf(sql, MINBUFFERLEN, "INSERT INTO tbservice_info (`szService`,`szVersion`,`dStart`,`nPid`) "
                                          "VALUES ('vnass_dhcpd','" PACKAGE_VERSION "',now(),%u) "
                                          "ON CONFLICT(szService) DO UPDATE SET `szVersion`='" PACKAGE_VERSION "',`dStart`=now(),`nPid`=%u;",
                       getpid(), getpid());
    dbname = "sxzinfo";
#endif
    MYDBOP DBHandle;
    // MyDBOp_Init(&DBHandle);
    if (database_connect(&DBHandle, dbname) < 0) {
        MyDBOp_Destroy(&DBHandle);
        x_log_debug("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, dbname);
        return;
    }
    MyDBOp_ExecSQL(&DBHandle, sql);
    MyDBOp_Destroy(&DBHandle);
}

PUBLIC int vdhcpd_start()
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
  
    //初始化配置
    vdm->cfg_main = vdhcpd_cfg_reload();
    assert(vdm->cfg_main);

    x_log_warn("%s Start. version[%s] pid[%d]...", PACKAGE_NAME "[" PACKAGE_MODULES "]", PACKAGE_VERSION, getpid());
    vdhcpd_starttime(vdm);
     
    xthread_create(&vdm->mtThread, "Maintain", vdm, NULL, vdhcpd_maintain, NULL, 0, 0);
    xthread_create(&vdm->dbThread, "DB", vdm, NULL, vdhcpd_db_start, NULL, 0, 0);
    xthread_create(&vdm->webThread, "WEB", vdm, webaction_init, webaction_start, NULL, 0, 0);
    xthread_create(&vdm->apiThread, "API", vdm, api_main_init, api_main_start, api_main_clean, 0, 0);
    xthread_create(&vdm->relay4Thread, "Relay4", vdm, relay4_main_init, relay4_main_start, relay4_main_clean, 0, 0);
    xthread_create(&vdm->relay6Thread, "Relay6", vdm, relay6_main_init, relay6_main_start, relay6_main_clean, 0, 0);
    xthread_create(&vdm->mThread, "Main", vdm, local_main_init, local_main_start, local_main_clean, 1, 0);
    return 0;
}

PRIVATE int vdhcpd_maintain(void *p, trash_queue_t *pRecycleTrash)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;
    PRIVATE u32 last_rotate, last_update,last_assignment,last_lease;
    PRIVATE u32 last_modifytime; 

    //日志文件句柄保活
    if (CMP_COUNTER(last_rotate, 60)) {
        xlog_rotate(NULL);
        SET_COUNTER(last_rotate);
    }
    if (CMP_COUNTER(last_assignment, 5)) { 
        server_stats_main_maintain(); 
        SET_COUNTER(last_assignment);
    }
    if (CMP_COUNTER(last_lease, 10)) { 
        maint_dhcplease_stats();
        SET_COUNTER(last_lease);
    }
    if (vdm->reload_vdhcpd) { //配置重载
        __sync_fetch_and_and(&vdm->reload_vdhcpd, 0);
        vdhcpd_cfg_t *cfg_main = vdhcpd_cfg_reload();
        vdhcpd_cfg_recycle(vdm->cfg_main ,pRecycleTrash);
        vdm->cfg_main = cfg_main;
    } else if (CMP_COUNTER(last_update, 8)) { //局部参数动态更新
      
        dhcpd_server_update(vdm->cfg_main, pRecycleTrash,vdm->sockfd_main);
        SET_COUNTER(last_update);
 
    }

    //通信数据过滤[MAC地址重载]
    u32 current_modifytime = 0;
    get_file_modifytime(path_cfg.filterfile, &current_modifytime);
    if (current_modifytime != last_modifytime) {
        last_modifytime = current_modifytime;
        struct key_tree *recycle_tree = vdm->filter_tree;
        vdm->filter_tree = macaddr_filter_init(path_cfg.filterfile);
        macaddr_filter_recycle(recycle_tree, pRecycleTrash);
    }

    stats_main_maintain(&vdm->stats_main, pRecycleTrash); //需要控制在每秒执行

    return xTHREAD_DEFAULT_SECOND_INTERVAL;
}

PRIVATE int vdhcpd_db_start(void *p, trash_queue_t *pRecycleTrassh)
{
    vdhcpd_main_t *vdm = (vdhcpd_main_t *)p;
 
    MYDBOP DBHandle;
    int dbsuccess = (0 == database_connect(&DBHandle, cfg_mysql.dbname)) ? 1 : 0;
    if (!dbsuccess) {
        #ifdef CLIB_DEBUG
        x_log_err("%s:%d 数据库[%s:%d %s]连接失败.", __FUNCTION__, __LINE__, cfg_mysql.ip, cfg_mysql.port, cfg_mysql.dbname); 
        #endif // DEBUG 
        return -1;
    }
    u32 stattime; //确保不一直执行SQL
    SET_COUNTER(stattime);
    db_event_t *db_event = NULL;
    while (dbsuccess && NULL != (db_event = db_process_pop_event(&vdm->db_process)) && !CMP_COUNTER(stattime, MIN_RELEASE_INTERVAL / 3)) {
#ifdef CHECK_PERFORMANCE
        struct timeval ticktime;
        gettimeofday(&ticktime, NULL);
#endif

        if (db_event->sql) MyDBOp_ExecSQL(&DBHandle, db_event->sql);

        db_event_release(db_event);
#ifdef CHECK_PERFORMANCE
        x_log_debug("%s : 性能测试[DB] delay[%.3f ms].", __FUNCTION__, get_delay(&ticktime));
#endif
    }
    MyDBOp_Destroy(&DBHandle);
    return xTHREAD_DEFAULT_SECOND_INTERVAL;
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
    dhcpd_server_update(cfg_main, NULL,0); 
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

PUBLIC int ipc_send_data(packet_process_t *packet_process, const unsigned char *buffer, const size_t length)
{
#ifndef VERSION_VNAAS
    struct sockaddr_in sin;
    BZERO(&sin, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(DEFAULT_CORE_UDP_PORT);
    sin.sin_addr.s_addr = 0x100007f;
    return sendto(packet_process->vdm->sockfd_main, buffer, length, 0, (struct sockaddr *)&sin, sizeof(sin));
#else
#include <sys/un.h>
    struct sockaddr_un sin;
    BZERO(&sin, sizeof(struct sockaddr_un));
    sin.sun_family = AF_UNIX;
    strcpy(sin.sun_path, VNAAS_POP_IPC_DGRAM_SOCK);
    return sendto(packet_process->vdm->sockfd_main, buffer, length, 0, (struct sockaddr *)&sin, sizeof(sin));
#endif
}
