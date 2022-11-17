#include <assert.h>
#include "bitmap.h"

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
PUBLIC xBITMASKPOOL *xBITMASKPOOL_Malloc(const unsigned int start,const unsigned int end,const unsigned int inorder)
{
    xBITMASKPOOL *pBITMASKPOOL = (xBITMASKPOOL *)xMALLOC(sizeof(xBITMASKPOOL));
    assert(pBITMASKPOOL);
    BZERO(pBITMASKPOOL,sizeof(xBITMASKPOOL));
    assert(start<=end);
    pBITMASKPOOL->start = start;
    pBITMASKPOOL->end = end;
    pBITMASKPOOL->total = (end - start) + 1;//计算可分配总数
    pBITMASKPOOL->inorder = inorder;
    pBITMASKPOOL->leases = pBITMASKPOOL->nextpos = 0;

    bitmap_init_lock(pBITMASKPOOL);

    unsigned int size = HOWMANYBITS(pBITMASKPOOL->total,BITMASK_BITS);
    size = size * sizeof(bitmap_t);
    pBITMASKPOOL->fds_bits =(bitmap_t *)xMALLOC(size);
    assert(pBITMASKPOOL->fds_bits);
    BZERO(pBITMASKPOOL->fds_bits,size);
    return pBITMASKPOOL;
}

PUBLIC int xBITMASKPOOL_Malloc_Position(xBITMASKPOOL *pBITMASKPOOL,unsigned int *value/*hostbit*/,int cmp(const unsigned int/*value(hostbit)*/))
{
    int result = -1;
    assert(pBITMASKPOOL);

    unsigned int pos = 0;
    bitmap_lock(pBITMASKPOOL);
    if (pBITMASKPOOL->nextpos >= pBITMASKPOOL->total)
        pBITMASKPOOL->nextpos = 0;//Reset
    for (pos=pBITMASKPOOL->nextpos;pos<pBITMASKPOOL->total;++pos)
    {
        if (!BITMASK_ISSET(pBITMASKPOOL,pos)) {//BIT位未设置
            unsigned int value_position = pBITMASKPOOL->start + pos;
            if (cmp && cmp(value_position))
                continue;//不分配此BIT位

            BITMASK_SET(pBITMASKPOOL,pos);//分配成功
            ++pBITMASKPOOL->leases;
            *value = value_position;
            result = 0;
            if (!pBITMASKPOOL->inorder) pBITMASKPOOL->nextpos = pos + 1;
            break;
        }
    }
    bitmap_unlock(pBITMASKPOOL);
    return result;
}

PRIVATE int xBITMASKPOOL_Check_Value(xBITMASKPOOL *pBITMASKPOOL,const unsigned int value)
{
    if (pBITMASKPOOL->start <= value && value <= pBITMASKPOOL->end)
        return 1;
    return 0;
}

PUBLIC int xBITMASKPOOL_Set_Position(xBITMASKPOOL *pBITMASKPOOL,const unsigned int value/*hostbit*/)
{
    int result = -1;
    assert(pBITMASKPOOL);

    unsigned int pos = value - pBITMASKPOOL->start;
    bitmap_lock(pBITMASKPOOL);
    if (xBITMASKPOOL_Check_Value(pBITMASKPOOL,value) && !BITMASK_ISSET(pBITMASKPOOL,pos)) {//BIT位未设置
        BITMASK_SET(pBITMASKPOOL,pos);
        ++pBITMASKPOOL->leases;
        result = 0;
    }
    bitmap_unlock(pBITMASKPOOL);
    return result;
}

PUBLIC int xBITMASKPOOL_Free_Position(xBITMASKPOOL *pBITMASKPOOL,const unsigned int value/*hostbit*/)
{
    int result = -1;
    assert(pBITMASKPOOL);

    unsigned int pos = value - pBITMASKPOOL->start;
    bitmap_lock(pBITMASKPOOL);
    if (xBITMASKPOOL_Check_Value(pBITMASKPOOL,value) && BITMASK_ISSET(pBITMASKPOOL,pos)) {//BIT位已设置
        BITMASK_CLR(pBITMASKPOOL,pos);
        --pBITMASKPOOL->leases;
        result = 0;
    }
    bitmap_unlock(pBITMASKPOOL);
    return result;
}

PUBLIC void xBITMASKPOOL_Free(xBITMASKPOOL *pBITMASKPOOL)
{
    if (pBITMASKPOOL) {
        xFREE(pBITMASKPOOL->fds_bits);
        bitmap_destroy_lock(pBITMASKPOOL);
        xFREE(pBITMASKPOOL);
    }
    pBITMASKPOOL = NULL;
}

#ifdef DEBUG
PRIVATE void test_bitmap()
{
    xBITMASKPOOL *pBITMASKPOOL = xBITMASKPOOL_Malloc(1,65535,0);
    unsigned int count = 0;
    while (1)
    {
        unsigned int value=0;
        int result1 = xBITMASKPOOL_Malloc_Position(pBITMASKPOOL,&value,NULL);
        int result2 = xBITMASKPOOL_Free_Position(pBITMASKPOOL,value);
        fprintf(stdout,"value=[%u]. total[%u] retult1[%d] result2[%d]\n",value,++count,result1,result2);
        usleep(100);
    }
}
#endif

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
