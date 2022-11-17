#ifndef _HASH_H
#define _HASH_H

#include "defines.h"

typedef unsigned long long hashkey64;
typedef unsigned int hashkey32;

PUBLIC_DATA unsigned int APHash(const char *str, unsigned int len);
PUBLIC_DATA unsigned int FNVHash(const char *str, unsigned int len);
PUBLIC_DATA unsigned int BKDRHash(const char *str, unsigned int len);
PUBLIC_DATA unsigned int CRC32(unsigned char *pbyte,unsigned int len);
PUBLIC_DATA unsigned long long CRC64(const unsigned char *pbyte,unsigned long long len);
PUBLIC_DATA unsigned long long CRC64_Ex(unsigned long long crc,const unsigned char *pbyte,unsigned long long len);

#endif // _HASH_H
