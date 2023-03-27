#ifndef _dhcp_config_h
#define _dhcp_config_h
#define PACKAGE_NAME "DHCP Daemon"
#define PACKAGE_VERSION "2023032701"
#define PACKAGE_MODULES "DHCP服务端"

//默认配置路径
#define PATH_LOGFILE  "/var/log/vdhcpd.log"
#define PATH_LOCKFILE "/var/run/xsdhcp.lock"
#define PATH_PIDFILE "/var/run/xsdhcp.pid"
#define PATH_FINGERFILE "/opt/dhcpd.finger"
#ifndef VERSION_VNAAS
#define PATH_CONFILE  "/xspeeder/vdhcpd.conf"
#define PATH_FILTERFILE "/xspeeder/dhcpd.filter"
#else
#define PATH_CONFILE  "/vrouter/vdhcpd.conf"
#define PATH_FILTERFILE "/vrouter/dhcpd.filter"
#endif

//数据库定义
#ifndef VERSION_VNAAS
#define DEFAULT_DBNAME "xspeeder"
#define DBTABLE_DHCP_SERVER "tbdhcpconfig"
#else
#define DEFAULT_DBNAME "vnaaspop"
#define DBTABLE_DHCP_SERVER "tbdhcpserver"
#endif

#include "share/defines.h"
#include "share/types.h"
#include "share/inifile/inifile.h"

typedef struct {
    char cfgfile[MAXNAMELEN+1];//运行配置文件路径
    char logfile[MAXNAMELEN+1];//运行日志文件路径
    char pidfile[MAXNAMELEN+1];//运行PID文件路径
    char lockfile[MAXNAMELEN+1];//运行LOCK文件路径
    char nasfile[MAXNAMELEN+1];//实时NAS配置[更新频率:60s]
    char acctinfofile[MAXNAMELEN+1];//实时在线终端记录[更新频率:5s]
    char leasefile[MAXNAMELEN+1];//接入服务实时租约信息[更新频率:5s]
    char filterfile[MAXNAMELEN+1];//日志过滤文件
    char fingerfile[MAXNAMELEN+1];//终端指纹[更新频率:10s]
} path_cfg_t;
PUBLIC_DATA path_cfg_t path_cfg;
ALWAYS_INLINE void path_cfg_init(const char *cfgfile)
{
    PRIVATE int already_load = 0;
    if (!already_load) {
        already_load = 1;
        BZERO(&path_cfg, sizeof(path_cfg_t));
        read_profile_string("path", "cfgfile", path_cfg.cfgfile, MAXNAMELEN, PATH_CONFILE, cfgfile);
        read_profile_string("path", "logfile", path_cfg.logfile, MAXNAMELEN, PATH_LOGFILE, cfgfile);
        read_profile_string("path", "pidfile", path_cfg.pidfile, MAXNAMELEN, PATH_PIDFILE, cfgfile);
        read_profile_string("path", "lockfile", path_cfg.lockfile, MAXNAMELEN, PATH_LOCKFILE, cfgfile);
        read_profile_string("path", "filterfile", path_cfg.filterfile, MAXNAMELEN, PATH_FILTERFILE, cfgfile);
        read_profile_string("path", "fingerfile", path_cfg.fingerfile, MAXNAMELEN, PATH_FINGERFILE, cfgfile);
    }
}

typedef struct {
    char ip[MINNAMELEN+1];
    u16 port;//hostbit
    char user[MINNAMELEN+1];
    char pass[MINNAMELEN+1];
    char dbname[MINNAMELEN+1];
} vradiusd_cfg_mysql_t;
ALWAYS_INLINE void vradiusd_cfg_get_mysql(vradiusd_cfg_mysql_t *cfg_mysql)
{
    BZERO(cfg_mysql, sizeof(vradiusd_cfg_mysql_t));
    read_profile_string("mysql", "ip", cfg_mysql->ip, MINNAMELEN, "127.0.0.1", path_cfg.cfgfile);
    cfg_mysql->port = read_profile_int("mysql", "port", 8306, path_cfg.cfgfile);
    read_profile_string("mysql", "user", cfg_mysql->user, MINNAMELEN, "root", path_cfg.cfgfile);
    read_profile_string("mysql", "pass", cfg_mysql->pass, MINNAMELEN, "tXkj-8002-vErygood", path_cfg.cfgfile);
    read_profile_string("mysql", "dbname", cfg_mysql->dbname, MINNAMELEN, DEFAULT_DBNAME, path_cfg.cfgfile);
}
#endif
