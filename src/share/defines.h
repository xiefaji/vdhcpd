#ifndef _SHARE_DEFINES_H
#define _SHARE_DEFINES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <assert.h>

#include "share/types.h"

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

#define CALCMINNAMELEN  32
#define CALCMAXNAMELEN  128
#define SAMAXNAMELEN  255
#define SAMINBUFFERLEN  512
#define MINNAMELEN  64
#define MAXNAMELEN	256	/* max length of hostname or name for auth */
#define MAXSECRETLEN    256	/* max length of password or secret */
#define MINBUFFERLEN    512
#define MAXBUFFERLEN    2048
#define BIGBUFFERLEN    65535
#define MAX_PATH_LEN 255
#define MAXURLLEN 255
#define VECTORLEN   16
#define MAXDTTAKS 128

#ifndef BCOPY
#define BCOPY(s,d,l)    memcpy(d,s,l)
#endif
#ifndef BZERO
#define BZERO(s,n)      memset(s,0,n)
#endif
#ifndef BCMP
#define BCMP(s1,s2,l)   memcmp(s1,s2,l)
#endif
#ifndef BMOVE
#define BMOVE(s,d,l)    memmove(d,s,l)
#endif
#define ARRAYSIZE(array)    (sizeof(array)/sizeof(array[0]))

#undef PUBLIC
#undef PUBLIC_DATA
#undef PRIVATE
#define PUBLIC
#define PUBLIC_DATA extern
#define PRIVATE     static

#undef FILE_LINE
#define FILE_LINE   __FILE__,__LINE__

#define INLINE inline
#define ALWAYS_INLINE static inline
//#define UNUSED __attribute__((unused))
#define ALIGNED __attribute__((aligned))
#define PACKED __attribute__((packed))

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~union~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
PUBLIC_DATA volatile unsigned int g_counter;//内置时间计数器[不再使用time(0)]
#define SUB_COUNTER(lasktick) ((u32)(g_counter - (lasktick)))
#define CMP_COUNTER(lasktick, value) ((SUB_COUNTER(lasktick) >= (value)) ? 1:0)
#define SET_COUNTER(lasktick) ((lasktick) = g_counter)

/*IPv4地址*/
typedef union {
    struct in_addr addr;
    unsigned int address;
    unsigned char addr_u8[4];
} ip4_address_t;
#undef IPV4FMT
#undef IPV4BYTES
#undef IPv4_BYTES
#define IPV4FMT "%u.%u.%u.%u"
#define IPV4BYTES(ip4) (ip4).addr_u8[0],(ip4).addr_u8[1],(ip4).addr_u8[2],(ip4).addr_u8[3]
#define IPv4_BYTES(addr) \
    (u8) (((addr) ) & 0xFF),\
    (u8) (((addr) >> 8) & 0xFF),\
    (u8) (((addr) >> 16) & 0xFF),\
    (u8) (((addr) >> 24) & 0xFF)
#define IPv4_IS_EQUAL(a, b) ((a)->address == (b)->address)
#define IPv4_SUBNET(a, n) ((a)->address & (n)->address)

#define HTONL(ip) htonl((ip))
#define NTOHL(ip) ntohl((ip))
#define IPV4_HTONL(ip4) HTONL((ip4).address)
#define IPV4_NTOHL(ip4) NTOHL((ip4).address)
#define IPv4_ZERO(ip4) ((ip4)->address ? 0:1)
#define IPv4_BROADCAST(ip4) (((ip4)->addr_u8[0] & (ip4)->addr_u8[1] & (ip4)->addr_u8[2] & (ip4)->addr_u8[3]) == 0xFF)

typedef union {
    struct in6_addr addr;
    unsigned long long ip_u64[2];
    struct {
        unsigned int rc[3];
        union {
            ip4_address_t ip4;
            unsigned int u_ip;
        };
    };
    unsigned int ip_u32[4];
    unsigned short ip_u16[8];
    unsigned char ip_u8[16];
}__attribute__((packed)) ip6_address_t;
#define IPv6_ZERO(ip6) (((ip6)->ip_u64[0] | (ip6)->ip_u64[1]) ? 0:1)

ALWAYS_INLINE unsigned long long byte_swap_u64 (unsigned long long x)
{
#if defined (__x86_64__)
 if (!__builtin_constant_p (x))
   {
     asm volatile ("bswapq %0":"=r" (x):"0" (x));
     return x;
   }
#elif defined (__aarch64__)
 if (!__builtin_constant_p (x))
   {
   __asm__ ("rev %0, %0":"+r" (x));
     return x;
   }
#endif
#define _(x,n,i) \
 ((((x) >> (8*(i))) & 0xff) << (8*((n)-(i)-1)))
 return (_(x, 8, 0) | _(x, 8, 1)
     | _(x, 8, 2) | _(x, 8, 3)
     | _(x, 8, 4) | _(x, 8, 5) | _(x, 8, 6) | _(x, 8, 7));
#undef _
}

ALWAYS_INLINE unsigned long long ntohll(unsigned long long val)
{
    if (__BYTE_ORDER==__LITTLE_ENDIAN) {
        return byte_swap_u64(val);//(((unsigned long long)htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
    } else if (__BYTE_ORDER==__BIG_ENDIAN) {
        return val;
    }
}

ALWAYS_INLINE unsigned long long htonll(unsigned long long val)
{
    if (__BYTE_ORDER == __LITTLE_ENDIAN) {
        return byte_swap_u64(val);//(((unsigned long long )htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
    } else if (__BYTE_ORDER == __BIG_ENDIAN) {
        return val;
    }
}

typedef struct {
    u16 ipstack;
    union {
        ip4_address_t ipaddr4;
        ip6_address_t ipaddr6;
    } __attribute__((packed)) u;
} __attribute__((packed)) ip46_address_t;

ALWAYS_INLINE void ip46address_format(char *dst, const size_t size, const ip46_address_t ipaddr46)
{
    if (4 == ipaddr46.ipstack) {
        inet_ntop(AF_INET, &ipaddr46.u.ipaddr4, dst, size);
    } else {
        inet_ntop(AF_INET6, &ipaddr46.u.ipaddr6, dst, size);
    }
}

ALWAYS_INLINE void ip46address_parse(ip46_address_t *ipaddr46, const char *ipaddr)
{
    if (strstr(ipaddr, "::ffff:")) {
        ipaddr46->ipstack = 4;
        ip6_address_t ipaddr6;
        BZERO(&ipaddr6, sizeof(ip6_address_t));
        inet_pton(AF_INET6, ipaddr, &ipaddr6);
        ipaddr46->u.ipaddr4.address = ipaddr6.ip_u32[3];
    } else if (strstr(ipaddr, ".")) {
        ipaddr46->ipstack = 4;
        inet_pton(AF_INET, ipaddr, &ipaddr46->u.ipaddr4);
    } else if (strstr(ipaddr, ":")) {
        ipaddr46->ipstack = 6;
        inet_pton(AF_INET6, ipaddr, &ipaddr46->u.ipaddr6);
    }
}

typedef union {
    unsigned char addr[ETH_ALEN]; 
} mac_address_t;

#undef MACADDRFMT
#undef MACADDRBYTES
#define MACADDRFMT1  "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACADDRFMT2  "%02x-%02x-%02x-%02x-%02x-%02x"
#define MACADDRFMT MACADDRFMT1
#define MACADDRBYTES(mac) (mac).addr[0],(mac).addr[1],(mac).addr[2],(mac).addr[3],(mac).addr[4],(mac).addr[5]
#ifndef ETH_BYTES
#define ETH_BYTES(addr) \
    addr[0],\
    addr[1],\
    addr[2],\
    addr[3],\
    addr[4],\
    addr[5]
#endif
#define ZERO_MACADDR(e) ((e[0] | e[1] | e[2] | e[3] | e[4] | e[5]) == 0x00)

ALWAYS_INLINE void macaddress_parse(mac_address_t *macaddr,const char *src)
{
    unsigned int a,b,c,d,e,f;
    if ((sscanf(src,MACADDRFMT1,&a,&b,&c,&d,&e,&f)==6) && a<256 && b<256 && c<256 && d<256 && e<256 && f<256) {
        macaddr->addr[0]=(unsigned char )a;
        macaddr->addr[1]=(unsigned char )b;
        macaddr->addr[2]=(unsigned char )c;
        macaddr->addr[3]=(unsigned char )d;
        macaddr->addr[4]=(unsigned char )e;
        macaddr->addr[5]=(unsigned char )f;
    } else if ((sscanf(src,MACADDRFMT2,&a,&b,&c,&d,&e,&f)==6) && a<256 && b<256 && c<256 && d<256 && e<256 && f<256) {
        macaddr->addr[0]=(unsigned char )a;
        macaddr->addr[1]=(unsigned char )b;
        macaddr->addr[2]=(unsigned char )c;
        macaddr->addr[3]=(unsigned char )d;
        macaddr->addr[4]=(unsigned char )e;
        macaddr->addr[5]=(unsigned char )f;
    }
}

ALWAYS_INLINE void macaddress_format(char *dst, const size_t size, const mac_address_t *macaddr)
{
    BZERO(dst, size);
    snprintf(dst, size, MACADDRFMT, ETH_BYTES(macaddr->addr));
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~struct~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

ALWAYS_INLINE void *xmalloc(const size_t sz)
{
    void *b = malloc(sz);
    assert(b);
    return b;
}

ALWAYS_INLINE void xfree(void *ptr)
{
    if (ptr) free(ptr);
}

#define xMALLOC(sz) xmalloc(sz)
#define xFREE(ptr) xfree(ptr)

#endif // _SHARE_DEFINES_H
