#include <stdio.h>
#include <getopt.h>

#include "dhcpd/dhcpd.h"

PUBLIC volatile unsigned int g_counter;
PRIVATE int g_daemon_mode;
PRIVATE int g_verbose = LOG_WARNING;
PUBLIC int filter_subnet = 0;
PUBLIC path_cfg_t path_cfg;

// 运行参数说明
PRIVATE void usage()
{
    fprintf(stdout, "%s\n", PACKAGE_NAME "[" PACKAGE_MODULES "]");
    fprintf(stdout, "Version:%s\n", PACKAGE_VERSION);
    fprintf(stdout, "    options[]\n");
    fprintf(stdout, "-c      config file path. default[%s]\n", PATH_CONFILE);
    fprintf(stdout, "-d      daemon mode\n");
    fprintf(stdout, "-v      <verbose level>\n");
    fprintf(stdout, "-v      <verbose level>\n");
    fprintf(stdout, "-10      reload config\n");
    fprintf(stdout, "-12      open cmd log \n");
    exit(0);
}

// 运行参数解析
PRIVATE int parse_options(int argc, char **argv)
{
    int c = 0;
    while ((c = getopt(argc, argv, "dfv:c:")) != -1) {
        switch (c) {
        case 'd':
            g_daemon_mode = 1;
            break;
        case 'f':
            filter_subnet = 1;
            break;
        case 'v':
            g_verbose = atoi(optarg);
            break;
        case 'c':
            path_cfg_init(optarg);
            break;
        default:
            usage();
            break;
        }
    }
    return 0;
}

// 信号注册回调
PRIVATE void signal_callback(int num)
{
    switch (num) {
    case SIGALRM:
        ++g_counter;
        global_time = time(0);
        alarm(1);
        break;
    case SIGINT:
    case SIGTERM:
        x_log_warn("End %s 正常退出. version [%s] signal[%d]..", PACKAGE_NAME "[" PACKAGE_MODULES "]", PACKAGE_VERSION, num);
        xthread_shutdown();
        vdhcpd_shutdown();
        sleep(3);

        // 资源释放
        vdhcpd_release();
        closexlog(xlog_default);
        exit(-1);
        break;
    case SIGUSR1:
        vdhcpd_set_reload();
        break;
    case SIGUSR2:
        xlog_set_level(NULL, xLOG_DEST_STDOUT, LOG_DEBUG);
        x_log_debug("LOG命令行输出模式");
        break;
    default:
        break;
    }
}

int main(int argc, char *argv[])
{
    // 解析参数
    if (parse_options(argc, argv) < 0)
        return -1;

    path_cfg_init(PATH_CONFILE);
    // daemon启动
    if (g_daemon_mode) {
        int r __attribute__((unused)) = daemon(0, 0);
    }
    if (already_running(path_cfg.lockfile))
        return -1;
    write_pidfile(path_cfg.pidfile);

    // 注册信号处理函数
    //    signal(SIGINT, signal_callback);
    //    signal(SIGTERM, signal_callback);
    signal(SIGALRM, signal_callback);
    signal(SIGUSR1, signal_callback);
    signal(SIGUSR2, signal_callback);
    //    signal(SIGPIPE, SIG_IGN);
    g_counter = getpid(); //
    alarm(1);
    srand(time(0));

    // 程序日志句柄注册
    xlog_default = openxlog(PACKAGE_NAME "[" PACKAGE_MODULES "]", xLOG_DEFAULT, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    xlog_set_level(NULL, xLOG_DEST_SYSLOG, LOG_ERR);
    // xlog_set_level(NULL, xLOG_DEST_STDOUT, g_verbose);
    // xlog_set_level(NULL, xLOG_DEST_STDOUT, LOG_DEBUG);
    xlog_set_file(NULL, path_cfg.logfile, LOG_WARNING);
#ifdef CLIB_DEBUG
    xlog_set_level(NULL, xLOG_DEST_STDOUT, LOG_DEBUG);
#endif // DEBUG
    database_init();

    vdhcpd_init();

    vdhcpd_start();

    vdhcpd_release();

    closexlog(xlog_default);

    return 0;
}
