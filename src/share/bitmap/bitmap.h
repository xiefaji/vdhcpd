#ifndef _BITMASK_H
#define _BITMASK_H
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include "share/rbtree/compiler.h"
#include "share/defines.h"

typedef unsigned int bitmap_t;

#define BITMASK_BITS /* 32 */ (sizeof(bitmap_t) * 8 /* number of bits in a byte */)        /* bits per mask */
#define HOWMANYBITS(x, y)   (((x)/(y)) + 1)

#define BITMASK_SET(p, n)    (((p)->fds_bits[(n)/BITMASK_BITS]) |= (1 << (((unsigned int)n) % BITMASK_BITS)))
#define BITMASK_CLR(p, n)    (((p)->fds_bits[(n)/BITMASK_BITS]) &= ~(1 << (((unsigned int)n) % BITMASK_BITS)))
#define BITMASK_ISSET(p, n)  (((p)->fds_bits[(n)/BITMASK_BITS]) & (1 << (((unsigned int)n) % BITMASK_BITS)))
#define BITMASK_ZERO(p)      memset((char *)(p), 0, sizeof(*(p)))
#define BITMASK_ONE(p)       memset((char *)(p), 0xFF, sizeof(*(p)))

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
typedef struct {
    int mutex;//0
    unsigned int start,end;//hostbit
    unsigned int total,leases;//总可分配数/已分配数
    unsigned int inorder;//是否顺序分配(从首个空BIT位分配)(1:是 0:否)
    unsigned int nextpos;//下一个分配位置
    bitmap_t *fds_bits;
}xBITMASKPOOL;

#define bitmap_init_lock(p) { (p)->mutex = 0;}
#define bitmap_destroy_lock(p) {}
#define bitmap_lock(p)     { while (!(__sync_bool_compare_and_swap (&(p)->mutex,0, 1) )) {sched_yield();} smp_rmb();}
#define bitmap_unlock(p)  {__sync_bool_compare_and_swap(&(p)->mutex,1,0);}

/**
 * @申请并初始化BITMASKPOOL
 * @start 启始值
 * @end 结束值
 * @inorder 是否顺序分配 1：是 0：否
 * @return 返回初始化成功的BITMASKPOOL
*/
PUBLIC_DATA xBITMASKPOOL *xBITMASKPOOL_Malloc(const unsigned int start,const unsigned int end,const unsigned int inorder);

/**
 * @申请BITMASKPOOL资源
 * @pBITMASKPOOL BITMASKPOOL
 * @value 分配值
 * @cmp 分配值比较函数，用于特殊取值
 * @return 执行结果 0:分配成功
*/
PUBLIC_DATA int xBITMASKPOOL_Malloc_Position(xBITMASKPOOL *pBITMASKPOOL,unsigned int *value/*hostbit*/,int cmp(const unsigned int/*value(hostbit)*/));

/**
 * @设置BITMASKPOOL资源
 * @pBITMASKPOOL BITMASKPOOL
 * @value 分配值
 * @return 执行结果 0:分配成功
*/
PUBLIC_DATA int xBITMASKPOOL_Set_Position(xBITMASKPOOL *pBITMASKPOOL,const unsigned int value/*hostbit*/);

/**
 * @释放BITMASKPOOL资源
 * @pBITMASKPOOL BITMASKPOOL
 * @value 分配值
 * @return 执行结果 0:分配成功
*/
PUBLIC_DATA int xBITMASKPOOL_Free_Position(xBITMASKPOOL *pBITMASKPOOL,const unsigned int value/*hostbit*/);

/**
 * @释放BITMASKPOOL
 * @pBITMASKPOOL BITMASKPOOL
*/
PUBLIC_DATA void xBITMASKPOOL_Free(xBITMASKPOOL *pBITMASKPOOL);

#endif // _BITMASK_H

