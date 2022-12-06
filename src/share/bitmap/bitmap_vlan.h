#ifndef _BITMAP_VLAN_H
#define _BITMAP_VLAN_H

#include <stdio.h>
#include "bitmap.h"

#define VLAN_NUM_FDS_BITS   HOWMANYBITS(4094+1, BITMASK_BITS)
typedef struct {
    bitmap_t fds_bits[VLAN_NUM_FDS_BITS];
} xVLANBITMAP;

ALWAYS_INLINE void xVLANBIAMAP_Combine(xVLANBITMAP *pDst,const xVLANBITMAP *pS1,const xVLANBITMAP *pS2)
{
    for (unsigned int i=0;i<VLAN_NUM_FDS_BITS;i++)
        pDst->fds_bits[i] = pS1->fds_bits[i] | pS2->fds_bits[i];
}

ALWAYS_INLINE int xVLANBITMAP_Duplicate_Detection(const xVLANBITMAP *a,const xVLANBITMAP *b)
{
    for (unsigned int i=0; i<VLAN_NUM_FDS_BITS; i++)
    {
        bitmap_t bit = a->fds_bits[i] & b->fds_bits[i];
        if (bit) {
            for (unsigned int j=0;j<BITMASK_BITS;j++)
            {
                if ((bit>>j) & 1) return i*BITMASK_BITS + j;
            }
        }
    }
    return -1;
}

ALWAYS_INLINE int ParseUIntNums(const char *InBuf,unsigned int dataArry[],const unsigned int ArrySize,const unsigned int MaxValue)
{
    int nID=0;
    if (InBuf[0]==0)
        return 0;

    unsigned int count = 0;
    char *p2 = (char *)InBuf;
    char *p1 = (char *)InBuf;//strstr(p2,",");
    int nlen=0;
    while (p1)
    {
        char szCon[32]={0};
        char szStart[16]={0};
        char szEnd[16]={0};
        p1=strstr(p2,",");
        if (p1) {
            nlen=p1-p2;
            if (nlen>18)
                return -1;
            strncpy(szCon,p2,nlen);
            p2=p1+1;
        } else {
            /*p1 = strstr(p2,"-");
            if (!p1) {
                nlen=strlen(p2);
                if (nlen>32) {
                    printf("config error!\n");
                    return -1;
                } else if(0==nlen) {
                    return n;
                }
                strncpy(szCon,p2,sizeof(szCon));
            } else */{
                nlen = strlen(p2);
                if (nlen>=(int)sizeof(szCon)) {
                    printf("config error!\n");
                    return -1;
                }
                strncpy(szCon,p2,nlen);
            }
            p2 += nlen;
        }

        char *p=strstr(szCon,"-");
        if (p) {
            int tmp_len = p - szCon;
            if (tmp_len>=(int)sizeof(szStart))
                tmp_len = sizeof(szStart) - 1;
            strncpy(szStart,szCon,tmp_len);
            strncpy(szEnd,p+1,sizeof(szEnd));
            unsigned int start=atoi(szStart);
            unsigned int end=atoi(szEnd);
            if (start>end||end<=0) {
                printf("config error!\n");
                continue;
            }

            if (MaxValue && (start>MaxValue|| end>MaxValue))
                continue;

            for (/*start*/;start<=end;start++) {
                if (count>=ArrySize)
                    return count;

                dataArry[count++]=start;
            }
        } else {
            nID=atoi(szCon);
            if (nID<0) continue;
            if (MaxValue && (unsigned int)nID>MaxValue) continue;
            if (count>=ArrySize) return count;
            dataArry[count++]=nID;
        }
    }
    return count;
}

#define MAX_VLAN_ID 4094
ALWAYS_INLINE xVLANBITMAP *GetVLAN_BITMASK(const char *pVLANBuffer,const size_t buflen,int default_vlan)
{
    xVLANBITMAP *vlan_bitmask = (xVLANBITMAP*)xMALLOC(sizeof(xVLANBITMAP));
    if (strstr(pVLANBuffer,"any") || !default_vlan) {
        BITMASK_ONE(vlan_bitmask);//all
        return vlan_bitmask;
    }

    unsigned int vlanid_array[MAX_VLAN_ID+2]={0};
    int ret = ParseUIntNums(pVLANBuffer,vlanid_array,MAX_VLAN_ID+1,MAX_VLAN_ID);
    if (ret<=0) {
        BITMASK_ZERO(vlan_bitmask);//limit all vlan
        BITMASK_SET(vlan_bitmask, default_vlan);
        return vlan_bitmask;
    }

    BZERO(vlan_bitmask,sizeof(xVLANBITMAP));
    for (int index=0;index<ret;index++)
    {
        unsigned int value = vlanid_array[index];
        if (value > MAX_VLAN_ID)
            continue;
        BITMASK_SET(vlan_bitmask,value);
    }
    return vlan_bitmask;
}


#endif // _BITMAP_VLAN_H
