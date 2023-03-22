#ifndef __bitmap_exact_vlan_h
#define __bitmap_exact_vlan_h

#include <stdio.h>
#include "share/array/trashqueue.h"
#include "share/bitmap/bitmap_vlan.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define ARRAY_LENGTH(array)    (sizeof(array)/sizeof(array[0]))

#ifndef HOWMANYBITS
#define HOWMANYBITS(x, y)   (((x)/(y)) + 1)
#endif

#define MIN_VLANID 1
#define MAX_VLANID 4094

#ifndef VLAN_NUM_FDS_BITS
#define VLAN_NUM_FDS_BITS   HOWMANYBITS(MAX_VLANID+1, BITMASK_BITS)

typedef struct {
    xs_bitmask fds_bits[VLAN_NUM_FDS_BITS];
} xVLANBITMAP;
#endif

typedef struct {
    unsigned short match_vlanid, match_qinqid;//是否匹配位图
    unsigned short ovlanid,ivlanid:12,open_qinq:4;//hostbit
    xVLANBITMAP *pIVLAN[MAX_VLANID+1];
} xEXACTVLAN,*PEXACTVLAN;
static inline void xEXACTVLAN_Parse(PEXACTVLAN pEXACTVLAN, const char *buffer);
static inline void xEXACTVLAN_Parse_VLAN_QINQ(PEXACTVLAN pEXACTVLAN, const char *buffer);

static inline char *stok_vlan(char *str, const char *delim, char **last)
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

static inline size_t xEXACTVLAN_Parse_VLANID(unsigned short id[], size_t size, const char *buffer)
{
    size_t count = 0;
    char *p = NULL, *next = (char *)buffer;
    while ((p = stok_vlan(next, ",", &next)))
    {
        unsigned short startid = 0, endid = 0;
        char *start = NULL, *end = NULL;
        start = stok_vlan(p, "-", &end);

        if (!strcmp(p, "any")) {
            startid = 0, endid = MAX_VLANID;
        } else if (start && end) {
            startid = MIN(atoi(start), MAX_VLANID);
            endid = MIN(atoi(end), MAX_VLANID);
        } else if (start) {
            startid = endid = MIN(atoi(start), MAX_VLANID);
        }

        //fprintf(stdout, "start[%d] end[%d]\r\n", startid, endid);
        for (; /*startid &&*/ startid <= endid; ++startid)
            id[count++] = startid;
    }
    return count;
}

static inline void xEXACTVLAN_Parse(PEXACTVLAN pEXACTVLAN, const char *buffer)
{
    char *p = NULL, *next = (char *)buffer;
    while ((p = stok_vlan(next, ";", &next)))
        xEXACTVLAN_Parse_VLAN_QINQ(pEXACTVLAN, p);
}

static inline void xEXACTVLAN_Parse_VLAN_QINQ(PEXACTVLAN pEXACTVLAN, const char *buffer)
{
    char *vlan = NULL, *qinq = (char *)buffer;
    size_t count_vlanid=0,count_qinqid=0;
    unsigned short vlanid[MAX_VLANID+1] = {0};
    unsigned short qinqid[MAX_VLANID+1] = {0};

    vlan = stok_vlan(qinq, "/", &qinq);

    if (!vlan || !qinq)
        return ;
    //fprintf(stdout, "VLAN[%s] QINQ[%s]\r\n", vlan, qinq);
    count_vlanid = xEXACTVLAN_Parse_VLANID(vlanid, ARRAY_LENGTH(vlanid), vlan);
    count_qinqid = xEXACTVLAN_Parse_VLANID(qinqid, ARRAY_LENGTH(qinqid), qinq);

    for (unsigned int idx = 0; idx < count_vlanid; ++idx)
    {
        pEXACTVLAN->match_vlanid = 1;
        if (!pEXACTVLAN->ovlanid || !idx) pEXACTVLAN->ovlanid = vlanid[idx];

        xVLANBITMAP *pIVLAN = pEXACTVLAN->pIVLAN[vlanid[idx]];
        if (!pIVLAN) {
            pIVLAN = (xVLANBITMAP *)malloc(sizeof(xVLANBITMAP));
            BITMASK_ZERO(pIVLAN);
            pEXACTVLAN->pIVLAN[vlanid[idx]] = pIVLAN;
        }

        for (unsigned int jdx = 0; jdx < count_qinqid; ++jdx) {
            pEXACTVLAN->match_qinqid = 1;
            if (!pEXACTVLAN->ivlanid || !jdx) pEXACTVLAN->ivlanid = qinqid[jdx];
            BITMASK_SET(pIVLAN, qinqid[jdx]);
        }
    }
}

static inline PEXACTVLAN xEXACTVLAN_init(const char *buffer, const int open_qinq)
{
    PEXACTVLAN pEXACTVLAN = (PEXACTVLAN)malloc(sizeof(xEXACTVLAN));
    memset(pEXACTVLAN, 0, sizeof(xEXACTVLAN));
    pEXACTVLAN->open_qinq = open_qinq ? 1:0;
    xEXACTVLAN_Parse(pEXACTVLAN, buffer);
    return pEXACTVLAN;
}

static inline PEXACTVLAN xEXACTVLAN_Dup(PEXACTVLAN pEXACTVLAN)
{
    PEXACTVLAN pDuplicate = (PEXACTVLAN)malloc(sizeof(xEXACTVLAN));
    memset(pDuplicate, 0, sizeof(xEXACTVLAN));
    pDuplicate->open_qinq = pEXACTVLAN->open_qinq;
    pDuplicate->match_vlanid = pEXACTVLAN->match_vlanid;
    pDuplicate->match_qinqid = pEXACTVLAN->match_qinqid;
    pDuplicate->ovlanid = pEXACTVLAN->ovlanid;
    pDuplicate->ivlanid = pEXACTVLAN->ivlanid;

    for (unsigned int idx = 0; idx < ARRAY_LENGTH(pEXACTVLAN->pIVLAN); ++idx) {
        xVLANBITMAP *pIVLAN = pEXACTVLAN->pIVLAN[idx];
        if (!pIVLAN) continue;
        xVLANBITMAP *p = (xVLANBITMAP *)malloc(sizeof(xVLANBITMAP));
        memcpy(p, pIVLAN, sizeof(xVLANBITMAP));
        pDuplicate->pIVLAN[idx] = p;
    }

    return pDuplicate;
}

static inline int xEXACTVLAN_Cmp(PEXACTVLAN pA, PEXACTVLAN pB)
{
    if (pA->ovlanid != pB->ovlanid)
        return 1;
    if (pA->ivlanid != pB->ivlanid)
        return 1;
    if (pA->open_qinq != pB->open_qinq)
        return 1;

    for (unsigned int idx = 0; idx < ARRAY_LENGTH(pA->pIVLAN); ++idx) {
        xVLANBITMAP *pIVLANA = pA->pIVLAN[idx];
        xVLANBITMAP *pIVLANB = pB->pIVLAN[idx];
        if (pIVLANA && pIVLANB) {
            if (memcmp(pIVLANA, pIVLANB, sizeof(xVLANBITMAP)))
                return 1;
        } else if ((pIVLANA && !pIVLANB) || (!pIVLANA && pIVLANB)) {
            return 1;
        } else {
            continue;
        }
    }

    return 0;
}

static inline int xEXACTVLAN_Cmp_vlanid(PEXACTVLAN pA/*对照*/, PEXACTVLAN pB)
{
    for (unsigned int idx = 0; idx < ARRAY_LENGTH(pA->pIVLAN); ++idx) {
        xVLANBITMAP *pIVLANA = pA->pIVLAN[idx];
        xVLANBITMAP *pIVLANB = pB->pIVLAN[idx];
        if (pIVLANB && pIVLANA) return 1;
    }
    return 0;
}

static inline int xEXACTVLAN_Conflict(PEXACTVLAN pA, PEXACTVLAN pB)
{
    for (unsigned int idx = 0; idx < ARRAY_LENGTH(pA->pIVLAN); ++idx) {
        xVLANBITMAP *pIVLANA = pA->pIVLAN[idx];
        xVLANBITMAP *pIVLANB = pB->pIVLAN[idx];
        if (pIVLANA && pIVLANB) {
            for (unsigned int jdx = 0; jdx < VLAN_NUM_FDS_BITS; ++jdx) {
                bitmap_t bits = pIVLANA->fds_bits[jdx] & pIVLANB->fds_bits[jdx];
                if (bits) return 1;
            }
        } else { /*不冲突*/ }
    }
    return 0;
}

static inline void xEXACTVLAN_Free(PEXACTVLAN pEXACTVLAN)
{
    if (pEXACTVLAN) {
        for (unsigned int idx = 0; idx < ARRAY_LENGTH(pEXACTVLAN->pIVLAN); ++idx) {
            if (pEXACTVLAN->pIVLAN[idx]) free(pEXACTVLAN->pIVLAN[idx]);
            pEXACTVLAN->pIVLAN[idx] = NULL;
        }
        free(pEXACTVLAN);
    }
}

static inline void xEXACTVLAN_Recycle(PEXACTVLAN pEXACTVLAN, trash_queue_t *pRecycleTrash)
{
    if (pEXACTVLAN) {
        for (unsigned int idx = 0; idx < ARRAY_LENGTH(pEXACTVLAN->pIVLAN); ++idx) {
            if (pEXACTVLAN->pIVLAN[idx]) trash_queue_enqueue(pRecycleTrash, pEXACTVLAN->pIVLAN[idx]);
            pEXACTVLAN->pIVLAN[idx] = NULL;
        }
        trash_queue_enqueue(pRecycleTrash, pEXACTVLAN);
    }
}

static inline int xEXACTVLAN_Match(PEXACTVLAN pEXACTVLAN, const unsigned short vlanid, const unsigned short qinqid)
{
    xVLANBITMAP *pIVLAN = NULL;
    if (!pEXACTVLAN)
        return 0;

    if (pEXACTVLAN->match_vlanid) {
        pIVLAN = pEXACTVLAN->pIVLAN[vlanid];
        if (!pIVLAN) return 0;//VLAN匹配失败

        if (pEXACTVLAN->open_qinq) {
            if (pEXACTVLAN->match_qinqid) return BITMASK_ISSET(pIVLAN, qinqid) ? 1:0;
            else if (pEXACTVLAN->ivlanid == qinqid) return 1;
            else return 0;
        } else {
            return qinqid ? 0:1;//不需要匹配QINQ
        }
    } else {
        if (pEXACTVLAN->ovlanid == vlanid && pEXACTVLAN->ivlanid == qinqid) return 1;
        else return 0;
    }
}

static inline int xEXACTVLAN_Match_vlanid(PEXACTVLAN pEXACTVLAN, const unsigned short vlanid)
{
    xVLANBITMAP *pIVLAN = NULL;
    if (!pEXACTVLAN)
        return 0;

    if (pEXACTVLAN->match_vlanid) {
        pIVLAN = pEXACTVLAN->pIVLAN[vlanid];
        if (!pIVLAN) return 0;//VLAN匹配失败
        return 1;
    } else {
        if (pEXACTVLAN->ovlanid == vlanid) return 1;
        else return 0;
    }
}

#endif
