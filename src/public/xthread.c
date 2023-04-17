#include <string.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "share/xlog.h"
#include "xthread.h"

PRIVATE int do_shutdown=0;
PRIVATE int corenum=0;
PRIVATE volatile int core_count=0;

PRIVATE void xthread_trash_clean(xTHREAD *pXTHREAD)
{
    if (pXTHREAD->xthread_do_clean)
        pXTHREAD->xthread_do_clean(pXTHREAD->p, &pXTHREAD->trashqueue[0]);

    for (int i=0;i<TRASHQUEUENUM;++i)
        clear_trash_queue(&pXTHREAD->trashqueue[i], xfree);
    x_log_notice("xThread[%s] Exit.", pXTHREAD->threadname);
    xFREE(pXTHREAD->threadname);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

PUBLIC void xthread_init()
{
    do_shutdown = 0;
    core_count = 0;
    corenum = sysconf(_SC_NPROCESSORS_CONF);
}

PUBLIC pid_t gettid()
{
    return syscall(SYS_gettid);
}

PRIVATE int thread_phase_preinitial(xTHREAD *pXTHREAD, trash_queue_t *pRecycleTrash)
{
    //Thread Init
    assert(pXTHREAD->threadname);
    assert(pXTHREAD->p);
    pXTHREAD->thread_id = gettid();
    pXTHREAD->trash_index=0;
    pXTHREAD->clear_trash_tick = g_counter;
    for (int i=0;i<TRASHQUEUENUM;++i)
        init_trash_queue(&pXTHREAD->trashqueue[i]);
    pXTHREAD->phase = xTHREADPHASE_INIT;
    prctl(PR_SET_NAME,pXTHREAD->threadname);

    if (pXTHREAD->set_cpu_affinity) {
        pXTHREAD->cpu_core_index = (++core_count) % corenum;

        cpu_set_t cpu_set;//CPU核的集合
        cpu_set_t cpu_get;//获取在集合中的CPU
        CPU_ZERO(&cpu_set);
        CPU_ZERO(&cpu_get);

        CPU_SET(pXTHREAD->cpu_core_index, &cpu_set);//设置亲和力值
        if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) == -1)//设置线程CPU亲和力
            x_log_warn("could not set CPU affinity, continuing...");

        if (sched_getaffinity(0, sizeof(cpu_get), &cpu_get) == -1)//获取线程CPU亲和力
            x_log_warn("cound not get thread affinity, continuing...");

        for (int i=0; i < corenum; ++i)
        {
            if (CPU_ISSET(i, &cpu_get))//判断线程与哪个CPU有亲和力
                x_log_warn("%s[%d] is running processor : %d", pXTHREAD->threadname, pXTHREAD->thread_id, i);
        }
    }
    return 0;
}

PRIVATE int thread_phase_initial(xTHREAD *pXTHREAD, void *p, trash_queue_t *pRecycleTrash)
{
    int retcode = 0;
    if (pXTHREAD->xthread_do_init)
        retcode = pXTHREAD->xthread_do_init(p, pRecycleTrash);
    if (!retcode) {
        pXTHREAD->phase = xTHREADPHASE_START;
        x_log_notice("xThread[%s : %d] Start.", pXTHREAD->threadname, pXTHREAD->thread_id);
    } else {
        sleep(3);
    }
    return 0;
}

PRIVATE int thread_phase_start(xTHREAD *pXTHREAD, void *p, trash_queue_t *pRecycleTrash)
{
    int interval = 0;
    if (pXTHREAD->xthread_do_start)
        interval = pXTHREAD->xthread_do_start(p,pRecycleTrash);
    else
        interval = xTHREAD_DEFAULT_SECOND_INTERVAL;
    if (interval > 0) usleep(interval);
    return 0;
}

PRIVATE int xthread_run(void *thread)
{
    xTHREAD *pXTHREAD = (xTHREAD *)thread;
    //clear trash;
    if (xTHREADPHASE_START == pXTHREAD->phase) {
        unsigned int sub = g_counter - pXTHREAD->clear_trash_tick;
        if (sub >= 1) {
            unsigned int index = (pXTHREAD->trash_index+1)%TRASHQUEUENUM;
            clear_trash_queue(&pXTHREAD->trashqueue[index], xfree);
            pXTHREAD->trash_index = index;
            pXTHREAD->clear_trash_tick = g_counter;
        }
    }
    trash_queue_t *pRecycleTrash = &pXTHREAD->trashqueue[pXTHREAD->trash_index];

    switch (pXTHREAD->phase) {
    case xTHREADPHASE_PRE_INIT:
        thread_phase_preinitial(pXTHREAD, pRecycleTrash);
        break;
    case xTHREADPHASE_INIT:
        thread_phase_initial(pXTHREAD, pXTHREAD->p, pRecycleTrash);
        break;
    case xTHREADPHASE_START:
        thread_phase_start(pXTHREAD, pXTHREAD->p, pRecycleTrash);
        break;
    default:
        x_log_warn("%s : 未识别线程Phase [%s:%d].",__FUNCTION__,pXTHREAD->threadname,pXTHREAD->phase);
        break;
    }
    return 0;
}

PRIVATE void *xthread_enter(void *thread)
{
    xTHREAD *pXTHREAD = (xTHREAD *)thread;

    do {
        while (!do_shutdown)
        {
            xthread_run(pXTHREAD);
        }
        xthread_trash_clean(pXTHREAD);
    } while(0);
    return NULL;
}

PUBLIC int xthread_create(void *thread, const char *threadname, void *p,
                          int (*xthread_do_init)(void *, trash_queue_t *),
                          int (*xthread_do_start)(void *, trash_queue_t *),
                          int (*xthread_do_clean)(void *, trash_queue_t *),
                          int block, int set_cpu_affinity)
{
    xTHREAD *pXTHREAD = (xTHREAD *)thread;
    BZERO(pXTHREAD,sizeof(xTHREAD));
    pXTHREAD->threadname = strdup(threadname);
    pXTHREAD->p = p;
    pXTHREAD->xthread_do_init = xthread_do_init;
    pXTHREAD->xthread_do_start = xthread_do_start;
    pXTHREAD->xthread_do_clean = xthread_do_clean;
    pXTHREAD->set_cpu_affinity = set_cpu_affinity;

    pthread_t t;
    pthread_create(&t,NULL,xthread_enter,pXTHREAD);
    if (block) pthread_join(t,NULL);
    else pthread_detach(t);
    return 0;
}

PUBLIC int xthread_shutdown()
{
    do_shutdown = 1;
    return 0;
}
