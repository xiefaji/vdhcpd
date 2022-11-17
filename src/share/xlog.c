#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "xlog.h"

static int logfile_fd = -1;	/* Used in signal handler. */
pthread_rwlock_t xlog_lock;
struct xlog *xlog_default = NULL;

char *xlog_proto_names[] =
{
    "NONE",
    "DEFAULT",
    NULL
};

const char *xlog_priority[] =
{
    "emergencies",
    "alerts",
    "critical",
    "errors",
    "warnings",
    "notifications",
    "informational",
    "debugging",
    NULL,
};

const char *c_safe_strerror(int errnum);
size_t log_timestamp(int timestamp_precision,char *buf, size_t buflen);

void *Xcalloc(size_t sz)
{
    void *b;
    b = calloc(1, sz);
    assert(b);

    return b;
}

void Xfree(void *ptr)
{
    free(ptr);
}

#define XCALLOC(type, sz)  Xcalloc(sz)
#define XFREE(type, ptr) Xfree(ptr)

/* For time string format. */
size_t log_timestamp(int timestamp_precision, char *buf, size_t buflen)
{
    static struct {
        time_t last;
        size_t len;
        char buf[28];
    } cache;
    struct timeval clock;

    /* would it be sufficient to use global 'recent_time' here?  I fear not... */
    gettimeofday(&clock, NULL);

    /* first, we update the cache if the time has changed */
    if (cache.last != clock.tv_sec)
    {
        struct tm *tm;
        cache.last = clock.tv_sec;
        tm = localtime(&cache.last);
        cache.len = strftime(cache.buf, sizeof(cache.buf),"%Y/%m/%d %H:%M:%S", tm);
    }
    /* note: it's not worth caching the subsecond part, because
     chances are that back-to-back calls are not sufficiently close together
     for the clock not to have ticked forward */

    if (buflen > cache.len)
    {
        memcpy(buf, cache.buf, cache.len);
        if ((timestamp_precision > 0) &&
                (buflen > cache.len+1+timestamp_precision))
        {
            /* should we worry about locale issues? */
            static const int divisor[] = {0, 100000, 10000, 1000, 100, 10, 1};
            int prec;
            char *p = buf+cache.len+1+(prec = timestamp_precision);
            *p-- = '\0';
            while (prec > 6)
                /* this is unlikely to happen, but protect anyway */
            {
                *p-- = '0';
                prec--;
            }
            clock.tv_usec /= divisor[prec];
            do
            {
                *p-- = '0'+(clock.tv_usec % 10);
                clock.tv_usec /= 10;
            }
            while (--prec > 0);
            *p = '.';
            return cache.len+1+timestamp_precision;
        }
        buf[cache.len] = '\0';
        return cache.len;
    }
    if (buflen > 0)
        buf[0] = '\0';
    return 0;
}

/* Utility routine for current time printing. */
static void time_print(FILE *fp, struct ctimestamp_control *ctl)
{
    if (!ctl->already_rendered)
    {
        ctl->len = log_timestamp(ctl->precision, ctl->buf, sizeof(ctl->buf));
        ctl->already_rendered = 1;
    }
    fprintf(fp, "%s ", ctl->buf);
}

/* va_list version of xlog. */
static void vxlog (struct xlog *xl, int priority, const char *format, va_list args)
{
    struct ctimestamp_control tsctl;
    tsctl.already_rendered = 0;

    /* If xlog is not specified, use default one. */
    if (xl == NULL)
        xl = xlog_default;

    /* When xlog_default is also NULL, use stderr for logging. */
    if (xl == NULL)
    {
        tsctl.precision = 0;
        time_print(stderr, &tsctl);
        fprintf (stderr, "%s: ", "unknown");
        vfprintf (stderr, format, args);
        fprintf (stderr, "\n");
        fflush (stderr);

        /* In this case we return at here. */
        return;
    }

    pthread_rwlock_wrlock(&xlog_lock);

    tsctl.precision = xl->timestamp_precision;

    /* Syslog output */
    if (priority <= xl->xloglmt[xLOG_DEST_SYSLOG].maxlvl
            && xl->xloglmt[xLOG_DEST_SYSLOG].currentcount <= xl->xloglmt[xLOG_DEST_SYSLOG].maxcount)
    {
        ++xl->xloglmt[xLOG_DEST_SYSLOG].currentcount;
        va_list ac;
        va_copy(ac, args);
        vsyslog (priority|xlog_default->facility, format, ac);
        va_end(ac);
    }

    /* File output. */
    if ((priority <= xl->xloglmt[xLOG_DEST_FILE].maxlvl) && xl->fp
            && xl->xloglmt[xLOG_DEST_FILE].currentcount <= xl->xloglmt[xLOG_DEST_FILE].maxcount)
    {
        ++xl->xloglmt[xLOG_DEST_FILE].currentcount;
        va_list ac;
        time_print (xl->fp, &tsctl);
        if (xl->record_priority)
            fprintf (xl->fp, "%s: ", xlog_priority[priority]);
        fprintf (xl->fp, "%s: ", xlog_proto_names[xl->protocol]);
        va_copy(ac, args);
        vfprintf (xl->fp, format, ac);
        va_end(ac);
        fprintf (xl->fp, "\n");
        fflush (xl->fp);
    }

    /* stdout output. */
    if (priority <= xl->xloglmt[xLOG_DEST_STDOUT].maxlvl)
    {
        va_list ac;
        time_print (stdout, &tsctl);
        if (xl->record_priority)
            fprintf (stdout, "%s: ", xlog_priority[priority]);
        fprintf (stdout, "%s: ", xlog_proto_names[xl->protocol]);
        va_copy(ac, args);
        vfprintf (stdout, format, ac);
        va_end(ac);
        fprintf (stdout, "\n");
        fflush (stdout);
    }

    pthread_rwlock_unlock(&xlog_lock);
    /* Terminal monitor. */
    //  if (priority <= xl->maxlvl[xLOG_DEST_MONITOR])
    //    vty_log ((xl->record_priority ? xlog_priority[priority] : NULL),
    //	     xlog_proto_names[xl->protocol], format, &tsctl, args);
}

void x_log (struct xlog *xl, int priority, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vxlog (xl, priority, format, args);
    va_end (args);
}

#define xLOG_FUNC(FUNCNAME,PRIORITY) \
    void \
    FUNCNAME(const char *format, ...) \
{ \
    va_list args; \
    va_start(args, format); \
    vxlog (NULL, PRIORITY, format, args); \
    va_end(args); \
    }

xLOG_FUNC(x_log_err, LOG_ERR)
xLOG_FUNC(x_log_warn, LOG_WARNING)
xLOG_FUNC(x_log_info, LOG_INFO)
xLOG_FUNC(x_log_notice, LOG_NOTICE)
xLOG_FUNC(x_log_debug, LOG_DEBUG)
#undef xLOG_FUNC

/* Open log stream */
struct xlog *openxlog (const char *progname, xlog_proto_t protocol,int syslog_flags, int syslog_facility)
{
    struct xlog *xl;
    unsigned int i;

    xl = XCALLOC(MTYPE_xLOG, sizeof (struct xlog));

    xl->ident = progname;
    xl->protocol = protocol;
    xl->facility = syslog_facility;
    xl->syslog_options = syslog_flags;

    /* Set default logging levels. */
    for (i = 0; i < sizeof(xl->xloglmt)/sizeof(xl->xloglmt[0]); i++) {
        xl->xloglmt[i].maxlvl = xLOG_DISABLED;
        xl->xloglmt[i].currentcount=0;
        xl->xloglmt[i].maxcount = xLOG_MAX_COUNT;
    }
    xl->default_lvl = LOG_DEBUG;

    openlog (progname, syslog_flags, xl->facility);

    pthread_rwlock_init(&xlog_lock, NULL);

    return xl;
}

void closexlog (struct xlog *xl)
{
    closelog();

    if (xl->fp != NULL)
        fclose (xl->fp);

    if (xl->filename != NULL)
        XFREE (MTYPE_xLOG, xl->filename);

    XFREE (MTYPE_xLOG, xl);
}

/* Called from command.c. */
void xlog_set_level (struct xlog *xl, xlog_dest_t dest, int log_level)
{
    if (xl == NULL)
        xl = xlog_default;

    xl->xloglmt[dest].maxlvl = log_level;
}

void xlog_set_name (struct xlog *xl, xlog_proto_t protocol, char *name)
{
    if (xl == NULL)
        xl = xlog_default;

    if (protocol < sizeof(xlog_proto_names)/sizeof(xlog_proto_names[0]))
        xlog_proto_names[protocol] = name;
}

int xlog_set_file (struct xlog *xl, const char *filename, int log_level)
{
    FILE *fp;
    mode_t oldumask;

    /* There is opend file.  */
    xlog_reset_file (xl);

    /* Set default xl. */
    if (xl == NULL)
        xl = xlog_default;

    /* Open file. */
    oldumask = umask (0777 & ~LOGFILE_MASK);
    fp = fopen (filename, "a");
    umask(oldumask);
    if (fp == NULL)
        return 0;

    /* Set flags. */
    xl->filename = strdup (filename);
    xl->xloglmt[xLOG_DEST_FILE].maxlvl = log_level;
    xl->xloglmt[xLOG_DEST_FILE].currentcount = 0;
    xl->xloglmt[xLOG_DEST_FILE].maxcount = xLOG_MAX_COUNT;
    xl->fp = fp;
    logfile_fd = fileno(fp);

    return 1;
}

/* Reset opend file. */
int xlog_reset_file (struct xlog *xl)
{
    if (xl == NULL)
        xl = xlog_default;

    if (xl->fp)
        fclose (xl->fp);
    xl->fp = NULL;
    logfile_fd = -1;
    xl->xloglmt[xLOG_DEST_FILE].maxlvl = xLOG_DISABLED;
    xl->xloglmt[xLOG_DEST_FILE].currentcount = 0;

    if (xl->filename)
        XFREE (MTYPE_xLOG, xl->filename);
    xl->filename = NULL;

    return 1;
}

/* Reopen log file. */
int xlog_rotate (struct xlog *xl)
{
    int level;

    if (xl == NULL)
        xl = xlog_default;
    pthread_rwlock_wrlock(&xlog_lock);
    if (xl->fp)
        fclose (xl->fp);
    xl->fp = NULL;
    logfile_fd = -1;
    level = xl->xloglmt[xLOG_DEST_FILE].maxlvl;
    xl->xloglmt[xLOG_DEST_FILE].maxlvl = xLOG_DISABLED;

    if (xl->filename)
    {
        mode_t oldumask;
        int save_errno;

        oldumask = umask (0777 & ~LOGFILE_MASK);
        xl->fp = fopen (xl->filename, "a");
        save_errno = errno;
        umask(oldumask);
        if (xl->fp == NULL)
        {
            x_log_err("Log rotate failed : cannot open file %s for append: %s",xl->filename, c_safe_strerror(save_errno));
            pthread_rwlock_unlock(&xlog_lock);
            return -1;
        }
        logfile_fd = fileno(xl->fp);
        xl->xloglmt[xLOG_DEST_FILE].maxlvl = level;
    }
    pthread_rwlock_unlock(&xlog_lock);
    return 1;
}

/* Wrapper around strerror to handle case where it returns NULL. */
const char *c_safe_strerror(int errnum)
{
    const char *s = strerror(errnum);
    return (s != NULL) ? s : "Unknown error";
}

