#include <stdlib.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "share/defines.h"
#include "windivert.h"

/*IPv4 Defines*/
#define WINDIVERT_IPHDR_GET_FRAGOFF(hdr)    (((hdr)->frag_off) & 0xFF1F)
#define WINDIVERT_IPHDR_GET_MF(hdr)         ((((hdr)->frag_off) & 0x0020) != 0)
#define WINDIVERT_IPHDR_GET_DF(hdr)         ((((hdr)->frag_off) & 0x0040) != 0)
#define WINDIVERT_IPHDR_GET_RESERVED(hdr)   ((((hdr)->frag_off) & 0x0080) != 0)
#define WINDIVERT_IPHDR_SET_FRAGOFF(hdr, val)               \
    do                                                      \
    {                                                       \
        (hdr)->frag_off = (((hdr)->frag_off) & 0x00E0) |    \
            ((val) & 0xFF1F);                               \
    }                                                       \
    while (false)
#define WINDIVERT_IPHDR_SET_MF(hdr, val)                    \
    do                                                      \
    {                                                       \
        (hdr)->frag_off = (((hdr)->frag_off) & 0xFFDF) |    \
            (((val) & 0x0001) << 5);                        \
    }                                                       \
    while (false)
#define WINDIVERT_IPHDR_SET_DF(hdr, val)                    \
    do                                                      \
    {                                                       \
        (hdr)->frag_off = (((hdr)->frag_off) & 0xFFBF) |    \
            (((val) & 0x0001) << 6);                        \
    }                                                       \
    while (false)
#define WINDIVERT_IPHDR_SET_RESERVED(hdr, val)              \
    do                                                      \
    {                                                       \
        (hdr)->frag_off = (((hdr)->frag_off) & 0xFF7F) |    \
            (((val) & 0x0001) << 7);                        \
    }                                                       \
    while (false)

/*IPv6 Defines*/
/*
#define WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(hdr)     ((((hdr)->TrafficClass0) << 4) | ((hdr)->TrafficClass1))
#define WINDIVERT_IPV6HDR_GET_FLOWLABEL(hdr)        ((((unsigned int)(hdr)->FlowLabel0) << 16) | ((unsigned int)(hdr)->FlowLabel1))
#define WINDIVERT_IPV6HDR_SET_TRAFFICCLASS(hdr, val)        \
    do                                                      \
    {                                                       \
        (hdr)->TrafficClass0 = ((unsigned char)(val) >> 4);         \
        (hdr)->TrafficClass1 = (unsigned char)(val);                \
    }                                                       \
    while (false)
#define WINDIVERT_IPV6HDR_SET_FLOWLABEL(hdr, val)           \
    do                                                      \
    {                                                       \
        (hdr)->FlowLabel0 = (unsigned char)((val) >> 16);           \
        (hdr)->FlowLabel1 = (unsigned short)(val);                  \
    }                                                       \
    while (false)
*/

/*IPv6 fragment header.*/
typedef struct {
    unsigned char NextHdr;
    unsigned char Reserved;
    unsigned short FragOff0;
    unsigned int Id;
} WINDIVERT_IPV6FRAGHDR,*PWINDIVERT_IPV6FRAGHDR;
#define WINDIVERT_IPV6FRAGHDR_GET_FRAGOFF(hdr)  (((hdr)->FragOff0) & 0xF8FF)
#define WINDIVERT_IPV6FRAGHDR_GET_MF(hdr)       ((((hdr)->FragOff0) & 0x0100) != 0)

/*IPv4/IPv6 pseudo headers.*/
typedef struct {
    unsigned int SrcAddr;
    unsigned int DstAddr;
    unsigned char Zero;
    unsigned char Protocol;
    unsigned short Length;
} WINDIVERT_PSEUDOHDR, *PWINDIVERT_PSEUDOHDR;

typedef struct {
    unsigned int SrcAddr[4];
    unsigned int DstAddr[4];
    unsigned int Length;
    unsigned int Zero:24;
    unsigned int NextHdr:8;
} WINDIVERT_PSEUDOV6HDR, *PWINDIVERT_PSEUDOV6HDR;

/*Packet info.*/
typedef struct {
    unsigned int HeaderLength:17;
    unsigned int FragOff:13;
    unsigned int Fragment:1;
    unsigned int MF:1;
    unsigned int PayloadLength:16;
    unsigned int Protocol:8;
    unsigned int Truncated:1;
    unsigned int Extended:1;
    unsigned int Reserved1:6;
    struct iphdr *IPHeader;
    struct ip6_hdr *IPv6Header;
    struct icmphdr *ICMPHeader;
    struct icmp6_hdr *ICMPv6Header;
    struct tcphdr *TCPHeader;
    struct udphdr *UDPHeader;
    unsigned char *Payload;
} WINDIVERT_PACKET,*PWINDIVERT_PACKET;

/*Generic checksum computation.*/
PRIVATE unsigned short WinDivertCalcChecksum(void *pseudo_header,unsigned short pseudo_header_len,void *data,unsigned int len)
{
    register const unsigned short *data16 = (const unsigned short *)pseudo_header;
    register size_t len16 = pseudo_header_len >> 1;
    register unsigned int sum = 0;
    size_t i;

    // Pseudo header:
    for (i = 0; i < len16; i++)
        sum += (unsigned int)data16[i];

    // Main data:
    data16 = (const unsigned short *)data;
    len16 = len >> 1;
    for (i = 0; i < len16; i++)
        sum += (unsigned int)data16[i];

    if (len & 0x1) {
        const unsigned char *data8 = (const unsigned char *)data;
        sum += (unsigned short)data8[len-1];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    sum = ~sum;
    return (unsigned short)sum;
}

/*Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.*/
PRIVATE bool WinDivertHelperParsePacketEx(const void *pPacket,unsigned int packetLen,PWINDIVERT_PACKET pInfo)
{
    struct iphdr *ip_header = NULL;
    struct ip6_hdr *ipv6_header = NULL;
    struct icmphdr *icmp_header = NULL;
    struct icmp6_hdr *icmpv6_header = NULL;
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    PWINDIVERT_IPV6FRAGHDR frag_header;
    unsigned char protocol = 0;
    unsigned char *data = NULL;
    unsigned int packet_len, total_len, header_len, data_len = 0, frag_off = 0;
    bool MF = false, fragment = false, is_ext_header;

    if (pPacket == NULL || packetLen < sizeof(struct iphdr))
        return false;

    data = (unsigned char *)pPacket;
    data_len = packetLen;

    ip_header = (struct iphdr *)data;
    switch (ip_header->version) {
        case 4:
            if (packetLen < sizeof(struct iphdr) || ip_header->ihl < 5)
                return false;

            total_len  = (unsigned int)ntohs(ip_header->tot_len);
            protocol   = ip_header->protocol;
            header_len = ip_header->ihl * sizeof(unsigned int);
            if (total_len < header_len || packetLen < header_len)
                return false;

            frag_off   = ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header));
            MF         = (WINDIVERT_IPHDR_GET_MF(ip_header) != 0);
            fragment   = (MF || frag_off != 0);
            packet_len = (total_len < packetLen? total_len: packetLen);
            data      += header_len;
            data_len   = packet_len - header_len;
            break;

        case 6:
            ip_header   = NULL;
            ipv6_header = (struct ip6_hdr *)data;
            if (packetLen < sizeof(struct ip6_hdr))
                return false;

            protocol   = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            total_len  = (unsigned int)ntohs(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);
            packet_len = (total_len < packetLen? total_len: packetLen);
            data      += sizeof(struct ip6_hdr);
            data_len   = packet_len - sizeof(struct ip6_hdr);

            while (frag_off == 0 && data_len >= 2)
            {
                header_len = (unsigned int)data[1];
                is_ext_header = true;
                switch (protocol) {
                    case IPPROTO_FRAGMENT:
                        header_len = 8;
                        if (fragment || data_len < header_len) {
                            is_ext_header = false;
                            break;
                        }
                        frag_header = (PWINDIVERT_IPV6FRAGHDR)data;
                        frag_off    = ntohs(WINDIVERT_IPV6FRAGHDR_GET_FRAGOFF(frag_header));
                        MF          = WINDIVERT_IPV6FRAGHDR_GET_MF(frag_header);
                        fragment    = true;
                        break;
                    case IPPROTO_AH:
                        header_len += 2;
                        header_len *= 4;
                        break;
                    case IPPROTO_HOPOPTS:
                    case IPPROTO_DSTOPTS:
                    case IPPROTO_ROUTING:
//                    case IPPROTO_MH:
                        header_len++;
                        header_len *= 8;
                        break;
                    default:
                        is_ext_header = false;
                        break;
                }
                if (!is_ext_header || data_len < header_len)
                    break;

                protocol  = data[0];
                data     += header_len;
                data_len -= header_len;
            }
            break;

        default:
            return false;
    }

    if (frag_off != 0)
        goto WinDivertHelperParsePacketExit;

    switch (protocol) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)data;
            if (data_len < sizeof(struct tcphdr) || tcp_header->doff < 5) {
                tcp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            header_len = tcp_header->doff * sizeof(unsigned int);
            header_len = (header_len > data_len? data_len: header_len);
            break;
        case IPPROTO_UDP:
            if (data_len < sizeof(struct udphdr))
                goto WinDivertHelperParsePacketExit;
            udp_header = (struct udphdr *)data;
            header_len = sizeof(struct udphdr);
            break;
        case IPPROTO_ICMP:
            if (ip_header == NULL || data_len < sizeof(struct icmphdr))
                goto WinDivertHelperParsePacketExit;
            icmp_header = (struct icmphdr *)data;
            header_len  = sizeof(struct icmphdr);
            break;
        case IPPROTO_ICMPV6:
            if (ipv6_header == NULL || data_len < sizeof(struct icmp6_hdr))
                goto WinDivertHelperParsePacketExit;
            icmpv6_header = (struct icmp6_hdr *)data;
            header_len    = sizeof(struct icmp6_hdr);
            break;
        default:
            goto WinDivertHelperParsePacketExit;
    }
    data     += header_len;
    data_len -= header_len;

WinDivertHelperParsePacketExit:
    if (pInfo == NULL)
        return true;

    data                 = (data_len == 0? NULL: data);
    pInfo->Protocol      = (unsigned int)protocol;
    pInfo->Fragment      = (fragment? 1: 0);
    pInfo->MF            = (MF? 1: 0);
    pInfo->FragOff       = (unsigned int)frag_off;
    pInfo->Truncated     = (total_len > packetLen? 1: 0);
    pInfo->Extended      = (total_len < packetLen? 1: 0);
    pInfo->Reserved1     = 0;
    pInfo->IPHeader      = ip_header;
    pInfo->IPv6Header    = ipv6_header;
    pInfo->ICMPHeader    = icmp_header;
    pInfo->ICMPv6Header  = icmpv6_header;
    pInfo->TCPHeader     = tcp_header;
    pInfo->UDPHeader     = udp_header;
    pInfo->Payload       = data;
    pInfo->HeaderLength  = (unsigned int)(packet_len - data_len);
    pInfo->PayloadLength = (unsigned int)data_len;
    return true;
}

/*Initialize the IP/IPv6 pseudo header*/
PRIVATE unsigned short WinDivertInitPseudoHeader(struct iphdr *ip_header,struct ip6_hdr *ipv6_header,
                                        unsigned char protocol,unsigned int len,void *pseudo_header)
{
    if (ip_header != NULL) {
        PWINDIVERT_PSEUDOHDR pseudo_header_v4 = (PWINDIVERT_PSEUDOHDR)pseudo_header;
        pseudo_header_v4->SrcAddr  = ip_header->saddr;
        pseudo_header_v4->DstAddr  = ip_header->daddr;
        pseudo_header_v4->Zero     = 0;
        pseudo_header_v4->Protocol = protocol;
        pseudo_header_v4->Length   = htons((unsigned short)len);
        return sizeof(WINDIVERT_PSEUDOHDR);
    } else {
        PWINDIVERT_PSEUDOV6HDR pseudo_header_v6 = (PWINDIVERT_PSEUDOV6HDR)pseudo_header;
        memcpy(pseudo_header_v6->SrcAddr,ipv6_header->ip6_src.s6_addr32,sizeof(pseudo_header_v6->SrcAddr));
        memcpy(pseudo_header_v6->DstAddr,ipv6_header->ip6_dst.s6_addr32,sizeof(pseudo_header_v6->DstAddr));
        pseudo_header_v6->Length  = htonl((unsigned int)len);
        pseudo_header_v6->NextHdr = protocol;
        pseudo_header_v6->Zero    = 0;
        return sizeof(WINDIVERT_PSEUDOV6HDR);
    }
}

/*Calculate IPv4/IPv6/ICMP/ICMPv6/TCP/UDP checksums.*/
PUBLIC bool WinDivertHelperCalcChecksums(void *pPacket,unsigned int packetLen,unsigned long long flags)
{
    unsigned char pseudo_header[MAX(sizeof(WINDIVERT_PSEUDOHDR),sizeof(WINDIVERT_PSEUDOV6HDR))];
    unsigned short pseudo_header_len;
    struct iphdr *ip_header;
    struct ip6_hdr *ipv6_header;
    struct icmphdr *icmp_header;
    struct icmp6_hdr *icmpv6_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    WINDIVERT_PACKET info;
    unsigned int payload_len, checksum_len;
    bool truncated;

    if (!WinDivertHelperParsePacketEx(pPacket,packetLen,&info))
        return false;

    ip_header = info.IPHeader;
    if (ip_header != NULL && !(flags & WINDIVERT_HELPER_NO_IP_CHECKSUM)) {
        ip_header->check = 0;
        ip_header->check = WinDivertCalcChecksum(NULL,0,ip_header,ip_header->ihl * sizeof(unsigned int));
    }

    payload_len = info.PayloadLength;
    truncated   = (info.Truncated || info.MF || info.FragOff != 0);

    icmp_header = info.ICMPHeader;
    if (icmp_header != NULL) {
        if ((flags & WINDIVERT_HELPER_NO_ICMP_CHECKSUM) != 0)
            return true;
        if (truncated)
            return false;
        icmp_header->checksum = 0;
        icmp_header->checksum = WinDivertCalcChecksum(NULL,0,icmp_header,payload_len + sizeof(struct icmphdr));
        return true;
    }

    icmpv6_header = info.ICMPv6Header;
    if (icmpv6_header != NULL) {
        if ((flags & WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM) != 0)
            return true;
        if (truncated)
            return false;
        ipv6_header = info.IPv6Header;
        checksum_len = payload_len + sizeof(struct icmp6_hdr);
        pseudo_header_len = WinDivertInitPseudoHeader(NULL,ipv6_header,IPPROTO_ICMPV6,checksum_len,pseudo_header);
        icmpv6_header->icmp6_cksum = 0;
        icmpv6_header->icmp6_cksum = WinDivertCalcChecksum(pseudo_header,pseudo_header_len,icmpv6_header,checksum_len);
        return true;
    }

    tcp_header = info.TCPHeader;
    if (tcp_header != NULL) {
        if ((flags & WINDIVERT_HELPER_NO_TCP_CHECKSUM) != 0)
            return true;
        if (truncated)
            return false;
        checksum_len = payload_len + tcp_header->doff * sizeof(unsigned int);
        ipv6_header = info.IPv6Header;
        pseudo_header_len = WinDivertInitPseudoHeader(ip_header,ipv6_header,IPPROTO_TCP,checksum_len,pseudo_header);
        tcp_header->check = 0;
        tcp_header->check = WinDivertCalcChecksum(pseudo_header,pseudo_header_len,tcp_header,checksum_len);
        return true;
    }

    udp_header = info.UDPHeader;
    if (udp_header != NULL) {
        if ((flags & WINDIVERT_HELPER_NO_UDP_CHECKSUM) != 0)
            return true;
        if (truncated)
            return false;
        // Full UDP checksum
        checksum_len = payload_len + sizeof(struct udphdr);
        ipv6_header = info.IPv6Header;
        pseudo_header_len = WinDivertInitPseudoHeader(ip_header,ipv6_header,IPPROTO_UDP,checksum_len,pseudo_header);
        udp_header->check = 0;
        udp_header->check = WinDivertCalcChecksum(pseudo_header,pseudo_header_len,udp_header,checksum_len);
        if (udp_header->check == 0)
            udp_header->check = 0xFFFF;
        return true;
    }

    return true;
}
