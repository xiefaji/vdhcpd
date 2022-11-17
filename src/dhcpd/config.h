#ifndef _dhcp_config_h
#define _dhcp_config_h
#define PACKAGE_NAME "DHCP Daemon"
#define PACKAGE_VERSION "2022111502"
#define PACKAGE_MODULES "DHCP服务端"

//默认配置路径
#define PATH_CONFILE  "/xspeeder/vdhcpd.conf"
#define PATH_LOGFILE  "/var/log/xs/vdhcpd.log"
#define PATH_LOCKFILE "/var/run/xsdhcp.lock"
#define PATH_PIDFILE "/var/run/xsdhcp.pid"

#include "share/defines.h"
#include "share/inifile/inifile.h"

typedef struct {
    char cfgfile[MAXNAMELEN+1];//运行配置文件路径
    char logfile[MAXNAMELEN+1];//运行日志文件路径
    char pidfile[MAXNAMELEN+1];//运行PID文件路径
    char lockfile[MAXNAMELEN+1];//运行LOCK文件路径
    char nasfile[MAXNAMELEN+1];//实时NAS配置[更新频率:60s]
    char acctinfofile[MAXNAMELEN+1];//实时在线终端记录[更新频率:5s]
    char leasefile[MAXNAMELEN+1];//接入服务实时租约信息[更新频率:5s]
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
    }
}

#endif
