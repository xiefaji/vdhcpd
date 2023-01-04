#ifndef _MISC_H
#define _MISC_H

#include <time.h>
#include "defines.h"


PUBLIC_DATA double get_disk_free_capcity(char* path);
PUBLIC_DATA int socket_set_nonblocking(int sock);
PUBLIC_DATA int socket_set_bind_interface(int sock,const char *ifname);
PUBLIC_DATA void socket_set_buffer(int sock,const size_t buffersize,int nocheck);
PUBLIC_DATA void socket_set_broadcast(int sock);
PUBLIC_DATA void socket_set_timeout(int sock,int sendtimeout,int recvtimeout);
PUBLIC_DATA int create_udp_socket(const unsigned short listenport, int local, int timeout, int reuseport, const char *ifname);
PUBLIC_DATA int create_udp_socket6(const unsigned short listenport, int local, int timeout, int reuseport, const char *ifname);
PUBLIC_DATA int create_raw_socket(int timeout, int reuseport, const char *ifname);
PUBLIC_DATA int create_raw_socket6(int timeout, int reuseport, const char *ifname);
//PUBLIC_DATA int create_udp_socket2(const unsigned short listenport, int local, int timeout, int us_timeout,int reuseport, const char *ifname);
PUBLIC_DATA int set_interface_up(const char *interface);
PUBLIC_DATA int create_interface_tun(const char *interface, int flags);

PUBLIC_DATA int g2u(const char *inbuf,size_t inlen,char *outbuf,size_t outlen);
PUBLIC_DATA int u2g(const char *inbuf,size_t inlen,char *outbuf,size_t outlen);
PUBLIC_DATA u_int32_t get_netmask(const int pre);
PUBLIC_DATA void clean_quotes_to_blank(const char *src);
PUBLIC_DATA void clean_quotes_to_blank2(const char *src, const size_t len);
PUBLIC_DATA char *stok(char *str, const char *delim, char **last);

PUBLIC_DATA int already_running(const char *filename);
PUBLIC_DATA int write_pidfile(const char *pidfile);
PUBLIC_DATA double get_delay(struct timeval* ptv);
PUBLIC_DATA int MyMakeDir(const char *sPathName, int mode);
PUBLIC_DATA void dfs_remove_dir();
PUBLIC_DATA void remove_dir(const char *path_raw);
PUBLIC_DATA void get_localtime(struct tm *st, time_t t);
PUBLIC_DATA int standard_to_stamp(const char *str_time);
PUBLIC_DATA int do_simple_command(char *cmd);
PUBLIC_DATA int get_file_modifytime(const char *filename, unsigned int *modifytime);
PUBLIC_DATA size_t hex2string(const unsigned char *src, const size_t src_len, char *dest, const size_t size, const char *default_value);
#endif // _MISC_H
