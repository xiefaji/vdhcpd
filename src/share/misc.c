#include <string.h>
#include <iconv.h>
#include <net/if.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/statvfs.h>

#include "misc.h"
#include "xlog.h"

PUBLIC int socket_set_nonblocking(int sock)
{
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFD, 0)|O_NONBLOCK) == -1) {
        x_log_warn("%s : 设置非阻塞失败[%d:%s].",__FUNCTION__,sock,strerror(errno));
        return -1;
    }
    return 0;
}
///获取磁盘可用空间百分比
/// \brief get_disk_free_capcity
/// \param path
/// \return 失败返回-1
///
PUBLIC double get_disk_free_capcity(char* path)
{
    struct statvfs stat = { 0 };
    double ret = statvfs(path, &stat);
    if(-1 == ret)return -1;
    ret = (stat.f_bavail * 100.0 / stat.f_blocks);
    //    printf("free blocks [%lu] percent [%f]\n", stat.f_bfree, (stat.f_bavail * 100.0 / stat.f_blocks));
    return ret;
}

PUBLIC int socket_set_bind_interface(int sock,const char *ifname)
{
    assert(ifname);
    struct ifreq interface;
    BZERO(&interface,sizeof(interface));
    strcpy(interface.ifr_name,ifname);
    if (-1==setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char*)&interface,sizeof(interface))){
        x_log_warn("%s : 设置绑定接口失败[%d:%s].interface[%s]",__FUNCTION__,sock,strerror(errno),ifname);
        return -1;
    }
    return 0;
}

PUBLIC void socket_set_buffer(int sock,const size_t buffersize,int nocheck)
{
    if (-1==setsockopt(sock,SOL_SOCKET,SO_RCVBUF,(void *)&buffersize,sizeof(buffersize)))
        x_log_warn("%s : 设置Recv Buffer失败[%d:%s].",__FUNCTION__,sock,strerror(errno));
    if (-1==setsockopt(sock,SOL_SOCKET,SO_SNDBUF,(void *)&buffersize,sizeof(buffersize)))
        x_log_warn("%s : 设置Send Buffer失败[%d:%s].",__FUNCTION__,sock,strerror(errno));

    if (nocheck) setsockopt(sock,SOL_SOCKET,SO_NO_CHECK,(const void *)&nocheck,sizeof(nocheck));
}

PUBLIC void socket_set_broadcast(int sock)
{
    int val = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));
}

PUBLIC void socket_set_timeout(int sock, int sendtimeout, int recvtimeout)
{
    if (sendtimeout) {
        struct timeval tv;
        tv.tv_sec = sendtimeout;
        tv.tv_usec=0;
        if (-1==setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
            x_log_warn("%s : 设置Send Timeout失败[%d:%s].", __FUNCTION__, sock, strerror(errno));
    }

    if (recvtimeout) {
        struct timeval tv;
        tv.tv_sec = recvtimeout;
        tv.tv_usec=0;
        if (-1==setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
            x_log_warn("%s : 设置Recv Timeout失败[%d:%s].", __FUNCTION__, sock, strerror(errno));
    }
}

PUBLIC void socket_set_timeout2(int sock,int sendtimeout,int recvtimeout, int us_timeout)
{
    if (sendtimeout) {
        struct timeval tv;
        tv.tv_sec = sendtimeout;
        tv.tv_usec= us_timeout;
        if (-1==setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv)))
            x_log_warn("%s : 设置Send Timeout失败[%d:%s].",__FUNCTION__,sock,strerror(errno));
    }

    if (recvtimeout) {
        struct timeval tv;
        tv.tv_sec = recvtimeout;
        tv.tv_usec= us_timeout;
        if (-1==setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)))
            x_log_warn("%s : 设置Recv Timeout失败[%d:%s].",__FUNCTION__,sock,strerror(errno));
    }
}

PUBLIC int create_udp_socket(const unsigned short listenport, int local, int timeout, int reuseport, const char *ifname)
{
    int sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (sock < 0) {
        x_log_warn("%s : 创建socket失败[%s].", __FUNCTION__, strerror(errno));
        return -1;
    }

    int one = 1;
    int r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    if (r < 0) x_log_warn("%s : REUSEADDR失败[%s].", __FUNCTION__, strerror(errno));

    if (reuseport) {
        one = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&one, sizeof(one));
        if (r < 0) x_log_warn("%s : REUSEPORT失败[%s].", __FUNCTION__,strerror(errno));
    }

    if (listenport) {
        struct sockaddr_in sin={0};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = local ? 0x100007f:htonl(INADDR_ANY);
        sin.sin_port = htons(listenport);
        if (-1 == bind(sock,(struct sockaddr *)&sin, sizeof(sin))) {
            close(sock);
            x_log_warn("%s : 设置绑定端口失败[%s]. port[%d]", __FUNCTION__, strerror(errno), listenport);
            return -1;
        }
    }

    //设置绑定接口
    if (ifname) socket_set_bind_interface(sock, ifname);

    //设置接收/发送超时
    socket_set_timeout(sock, timeout, timeout);
    return sock;
}

PUBLIC int create_udp_socket6(const unsigned short listenport, int local, int timeout, int reuseport, const char *ifname)
{
    int sock=socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP);
    if (sock < 0) {
        x_log_warn("%s : 创建socket失败[%s].", __FUNCTION__, strerror(errno));
        return -1;
    }

    int one = 1;
    int r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    if (r < 0) x_log_warn("%s : REUSEADDR失败[%s].", __FUNCTION__, strerror(errno));

    if (reuseport) {
        one = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&one, sizeof(one));
        if (r < 0) x_log_warn("%s : REUSEPORT失败[%s].", __FUNCTION__,strerror(errno));
    }

    if (listenport) {
        struct sockaddr_in6 sin = {AF_INET6, htons(listenport), 0, IN6ADDR_ANY_INIT, 0};
        if (-1 == bind(sock,(struct sockaddr *)&sin, sizeof(sin))) {
            close(sock);
            x_log_warn("%s : 设置绑定端口失败[%s]. port[%d]", __FUNCTION__, strerror(errno), listenport);
            return -1;
        }
    }

    //设置绑定接口
    if (ifname) socket_set_bind_interface(sock, ifname);

    //设置接收/发送超时
    socket_set_timeout(sock, timeout, timeout);
    return sock;
}

PUBLIC int create_raw_socket(int timeout, int reuseport, const char *ifname)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        x_log_warn("%s : 创建socket失败[%s].", __FUNCTION__, strerror(errno));
        return -1;
    }

    int one = 1;
    int r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    if (r < 0) x_log_warn("%s : REUSEADDR失败[%s].", __FUNCTION__, strerror(errno));

    if (reuseport) {
        one = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&one, sizeof(one));
        if (r < 0) x_log_warn("%s : REUSEPORT失败[%s].", __FUNCTION__, strerror(errno));
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        printf("Set IP_HDRINCL failed\n");
    }

    //设置绑定接口
    if (ifname) socket_set_bind_interface(sock, ifname);

    //设置接收/发送超时
    socket_set_timeout(sock, timeout, timeout);
    return sock;
}

PUBLIC int create_raw_socket6(int timeout, int reuseport, const char *ifname)
{
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        x_log_warn("%s : 创建socket失败[%s].", __FUNCTION__, strerror(errno));
        return -1;
    }

    int one = 1;
    int r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    if (r < 0) x_log_warn("%s : REUSEADDR失败[%s].", __FUNCTION__, strerror(errno));

    if (reuseport) {
        one = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&one, sizeof(one));
        if (r < 0) x_log_warn("%s : REUSEPORT失败[%s].", __FUNCTION__, strerror(errno));
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IP_HDRINCL, &on, sizeof(on)) < 0) {
        printf("Set IP_HDRINCL failed\n");
    }

    //设置绑定接口
    if (ifname) socket_set_bind_interface(sock, ifname);

    //设置接收/发送超时
    socket_set_timeout(sock, timeout, timeout);
    return sock;
}

//PUBLIC int create_udp_socket2(const unsigned short listenport, int local, int timeout, int us_timeout,int reuseport, const char *ifname)
//{
//    int sock=socket(AF_INET,SOCK_DGRAM,0);
//    if (sock < 0) {
//        x_log_warn("%s : 创建socket失败[%s].", __FUNCTION__, strerror(errno));
//        return -1;
//    }

//    int one = 1;
//    int r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
//    if (r < 0) x_log_warn("%s : REUSEADDR失败[%s].", __FUNCTION__, strerror(errno));

//    if (reuseport) {
//        one = 1;
//        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&one, sizeof(one));
//        if (r < 0) x_log_warn("%s : REUSEPORT失败[%s].", __FUNCTION__,strerror(errno));
//    }

//    if (listenport) {
//        struct sockaddr_in sin={0};
//        sin.sin_family = AF_INET;
//        sin.sin_addr.s_addr = local ? 0x100007f:htonl(INADDR_ANY);
//        sin.sin_port = htons(listenport);
//        if (-1 == bind(sock,(struct sockaddr *)&sin, sizeof(sin))) {
//            close(sock);
//            x_log_warn("%s : 设置绑定端口失败[%s]. port[%d]", __FUNCTION__, strerror(errno), listenport);
//            return -1;
//        }
//    }

//    //设置绑定接口
//    if (ifname) socket_set_bind_interface(sock, ifname);

//    //设置接收/发送超时
//    socket_set_timeout2(sock, timeout, timeout, us_timeout);
//    return sock;
//}

PRIVATE int code_convert(const char *from_charset,const char *to_charset,const char *inbuf,size_t inlen,char *outbuf,size_t outlen)
{
    iconv_t cd;
    size_t rc=0;
    char **pin = (char **)&inbuf;
    char **pout = &outbuf;
    cd = iconv_open(to_charset,from_charset);
    if (cd==0)
        return -1;
    BZERO(outbuf,outlen);
    if ((rc=iconv(cd,pin,&inlen,pout,&outlen)) != 0){
        iconv_close(cd);
        return -1;
    }
    iconv_close(cd);
    return 0;
}

PUBLIC int u2g(const char *inbuf,size_t inlen,char *outbuf,size_t outlen)
{
    return code_convert("utf-8","gbk",inbuf,inlen,outbuf,outlen);
}

PUBLIC int g2u(const char *inbuf,size_t inlen,char *outbuf,size_t outlen)
{
    return code_convert("gbk","utf-8",inbuf,inlen,outbuf,outlen);
}

PUBLIC void clean_quotes_to_blank(const char *src)
{
    char *current = (char *)src;
    while (*current)
    {
        switch (*current) {
        case '\'':
        case '\"':
        case '\r':
        case '\n':
            current[0] = ' ';
            break;
        default:
            break;
        }
        current++;
    }
}

PUBLIC void clean_quotes_to_blank2(const char *src, const size_t len)
{
    char *current = (char *)src;
    size_t i=0;
    while (i < len)
    {
        switch (current[i]) {
        case '\"':
            current[i] = '\'';
            break;
        case '\r':
        case '\n':
            current[i] = ' ';
            break;
        default:
            break;
        }
        ++i;
    }
}

PUBLIC char *stok(char *str, const char *delim, char **last)
{
    char *start, *end;
    size_t i;

    start = str ? str : *last;
    if (start == 0) {
        *last = 0;
        return 0;
    }
    i = strspn(start, delim);
    start += i;
    if (*start == '\0') {
        *last = 0;
        return 0;
    }
    end = strpbrk(start, delim);
    if (end) {
        *end++ = '\0';
        i = strspn(end, delim);
        end += i;
    }
    *last = end;
    return start;
}

PRIVATE int lockfile(int fd)
{
    struct flock fl;

    fl.l_type = F_WRLCK;  /* write lock */
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;  //lock the whole file

    return(fcntl(fd, F_SETLK, &fl));
}

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
PUBLIC int already_running(const char *filename)
{
    int fd;
    char buf[16]={0};

    fd = open(filename, O_RDWR | O_CREAT, LOCKMODE);
    if (fd < 0) {
        fprintf(stderr,"can't open %s: %m\n", filename);
        exit(1);
    }

    /* 先获取文件锁 */
    if (lockfile(fd) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            fprintf(stderr,"file: %s already locked\n", filename);
            close(fd);
            return 1;
        }
        fprintf(stderr,"can't lock %s: %m\n", filename);
        exit(1);
    }
    /* 写入运行实例的pid */
    ftruncate(fd, 0);
    snprintf(buf,sizeof(buf)-1, "%ld\n", (long)getpid());
    write(fd, buf, strlen(buf) + 1);
    return 0;
}

PUBLIC int write_pidfile(const char *pidfile)
{
    int fd;
    char buf[16]={0};
    unlink (pidfile);
    fd = open(pidfile, O_RDWR | O_CREAT, 0640);
    if (fd < 0) {
        printf("can't open %s: %m\n", pidfile);
        return -1;
    }

    snprintf(buf,sizeof(buf)-1, "%ld\n", (long)getpid());
    int len = strlen(buf)+1;
    /* 写入运行实例的pid */
    ftruncate(fd, len);
    write(fd, buf, len);
    close(fd);
    return 0;
}

PUBLIC double get_delay(struct timeval* ptv)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    long long sub_sec, sub_usec;
    sub_sec = now.tv_sec - ptv->tv_sec;
    sub_usec = now.tv_usec - ptv->tv_usec;
    double delay = sub_sec * 1000.0 + (sub_usec ? (sub_usec / 1000.0) : (0));
    return delay;
}

PUBLIC int MyMakeDir(const char *sPathName, int mode)
{
    char DirName[256]={0};
    snprintf(DirName, sizeof(DirName)-1, "%s", sPathName);
    int i,len = strlen(DirName);
    if (DirName[len-1]!='/')
        strncat(DirName,   "/",1);
    len = strlen(DirName);
    for (i = 1; i < len; i++)
    {
        if (DirName[i]=='/') {
            DirName[i]   =   0;
            if (access(DirName, F_OK)!=0 ) {
                if (mkdir(DirName, mode /*0755*/)==-1) {
                    perror("mkdir   error");
                    return -1;
                }
            }
            DirName[i] = '/';
        }
    }
    return   0;
}


PUBLIC void dfs_remove_dir()
{
    DIR *cur_dir = opendir(".");
    struct dirent *ent = NULL;
    struct stat st;

    if (!cur_dir) {
        perror("opendir:");
        return;
    }

    while ((ent = readdir(cur_dir)) != NULL)
    {
        stat(ent->d_name, &st);

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        {
            continue;
        }

        if (S_ISDIR(st.st_mode))
        {
            chdir(ent->d_name);
            dfs_remove_dir();
            chdir("..");
        }

        remove(ent->d_name);
    }

    closedir(cur_dir);
}

PUBLIC void remove_dir(const char *path_raw)
{
    char old_path[255];
    getcwd(old_path, 255);

    if (chdir(path_raw) == -1)
    {
        fprintf(stderr, "not a dir or access error\n");
        return;
    }

    dfs_remove_dir();
    chdir(old_path);

    /*
       如果你想删除该目录本身的话,取消注释
       unlink(old_path);
     */
}

PUBLIC void get_localtime(struct tm *st, time_t t)
{
    localtime_r(&t,st);
    st->tm_year += 1900;
    st->tm_mon += 1;
}

PUBLIC int standard_to_stamp(const char *str_time)
{
    if (!strlen(str_time))
        return 0;
    struct tm stm;
    int iY, iM, iD, iH, iMin, iS;
    BZERO(&stm, sizeof(stm));
    iY = atoi(str_time);
    iM = atoi(str_time + 5);
    iD = atoi(str_time + 8);
    iH = atoi(str_time + 11);
    iMin = atoi(str_time + 14);
    iS = atoi(str_time + 17);
    stm.tm_year = iY - 1900;
    stm.tm_mon = iM - 1;
    stm.tm_mday = iD;
    stm.tm_hour = iH;
    stm.tm_min = iMin;
    stm.tm_sec = iS;
    //printf("%d-%0d-%0d %0d:%0d:%0d\n", iY, iM, iD, iH, iMin, iS);   //标准时间格式例如：2016:08:02 12:12:30
    return (int)mktime(&stm);
}

PUBLIC int do_simple_command(char *cmd)
{
    FILE *fp = NULL;
    if ((fp = popen(cmd, "r")) == NULL) {
        fprintf(stderr, "%s : popen fail[%s].\n",__FUNCTION__,strerror(errno));
        return -1;
    }
    pclose(fp);
    return 0;
}

PUBLIC int create_interface_tun(const char *interface, int flags)
{
    struct ifreq ifr;
    int fd, err;
    assert(interface != NULL);
    if ((fd = open("/dev/net/tun",O_RDWR)) < 0) {
        perror("创建虚拟接口失败");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags |= flags;

    if (*interface != '\0')
        strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);
        return err;
    }

    long long sockbufflen = 32*1024*1024;
    if ((err = ioctl(fd, TUNSETSNDBUF, (void *)&sockbufflen)))
        perror("设置虚拟接口发送缓冲区失败.");

    int ncheck = 1;
    if ((err = ioctl(fd, TUNSETNOCSUM, (void*)&ncheck)))
        perror("设置虚拟接口不检验校验和失败.");

//    /* 进程退出 tap0不消失 如果想删除则设置为0 */
//    if(ioctl(fd, TUNSETPERSIST, persist) < 0){
//        perror("enabling TUNSETPERSIST");
//    }
    return fd;
}

PUBLIC int set_interface_up(const char *interface)
{
    int fd;
    if ((fd = socket(PF_INET,SOCK_STREAM,0)) < 0) {
        perror("创建Socket失败.");
        return -1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name,interface,IFNAMSIZ);

    short flag;
    flag = IFF_UP;
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("设置接口ifup失败[1].");
        close(fd);
        return -1;
    }

    ifr.ifr_ifru.ifru_flags |= flag;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("设置接口ifup失败[2].");
        close(fd);
        return -1;
    }
    return 0;
}

PUBLIC int get_file_modifytime(const char *filename, unsigned int *modifytime)
{
    struct stat stats;
    int result = stat(filename, &stats);
    if (result != 0) {
        //perror( "显示文件状态信息出错");
        return -1;
    } else {
//        printf("文件创建时间: %s", ctime(&stats.st_ctime));
//        printf("访问日期: %s", ctime(&stats.st_atime));
//        printf("最后修改日期: %s", ctime(&stats.st_mtime));
        *modifytime = stats.st_mtime;
        return 0;
    }
}

PUBLIC size_t hex2string(const unsigned char *src, const size_t src_len, char *dest, const size_t size, const char *default_value)
{
    if (src_len) {
        size_t offset_src = 0, offset_dest = 0;
        while (offset_src < src_len)
            offset_dest += snprintf(&dest[offset_dest], size - offset_dest, "%02x", src[offset_src++]);
        return offset_dest;
    } else {
        return snprintf(dest, size, "%s", default_value);
    }
}
