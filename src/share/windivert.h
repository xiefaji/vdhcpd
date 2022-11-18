#ifndef _WINDIVERT_H
#define _WINDIVERT_H
#include <stdbool.h>
/*Flags for WinDivertHelperCalcChecksums()*/
#define WINDIVERT_HELPER_NO_IP_CHECKSUM                     1
#define WINDIVERT_HELPER_NO_ICMP_CHECKSUM                   2
#define WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM                 4
#define WINDIVERT_HELPER_NO_TCP_CHECKSUM                    8
#define WINDIVERT_HELPER_NO_UDP_CHECKSUM                    16

extern bool WinDivertHelperCalcChecksums(void *pPacket,unsigned int packetLen,unsigned long long flags);

#endif // _WINDIVERT_H
