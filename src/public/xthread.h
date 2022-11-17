#ifndef _XTHREAD_H
#define _XTHREAD_H

#include "share/array/trashqueue.h"

typedef enum {
    xTHREADPHASE_PRE_INIT=0,
    xTHREADPHASE_INIT,
    xTHREADPHASE_START
}xTHREADPHASE;

#define xTHREAD_DEFAULT_INTERVAL 1000
#define xTHREAD_DEFAULT_SECOND_INTERVAL 1000*1000

typedef struct {
    xTHREADPHASE phase;
    int thread_id;
    unsigned char set_cpu_affinity;//设置CPU亲和性
    unsigned char cpu_core_index;//
    void *p;
    int (*xthread_do_init)(void *,trash_queue_t *);
    int (*xthread_do_start)(void *,trash_queue_t *);
    int (*xthread_do_clean)(void *,trash_queue_t *);
    char *threadname;
    int trash_index;
    unsigned int clear_trash_tick;
    trash_queue_t trashqueue[TRASHQUEUENUM];
} xTHREAD;

PUBLIC_DATA void xthread_init();
PUBLIC_DATA int xthread_create(void *thread, const char *threadname, void *p,
                               int (*xthread_do_init)(void *, trash_queue_t *),
                               int (*xthread_do_start)(void *, trash_queue_t *),
                               int (*xthread_do_clean)(void *, trash_queue_t *),
                               int block, int set_cpu_affinity);
PUBLIC_DATA int xthread_shutdown();

#endif // _XTHREAD_H
