#ifndef _XLOG_H
#define _XLOG_H

#include <stdio.h>
#include <syslog.h>

typedef enum {
    xLOG_NONE,
    xLOG_DEFAULT,
    xLOG_EX
} xlog_proto_t;

/* If maxlvl is set to xLOG_DISABLED, then no messages will be sent to that logging destination. */
#define xLOG_DISABLED	(LOG_EMERG-1)

typedef enum {
    xLOG_DEST_SYSLOG = 0,
    xLOG_DEST_STDOUT,
    xLOG_DEST_FILE
} xlog_dest_t;
#define xLOG_NUM_DESTS		(xLOG_DEST_FILE+1)

typedef struct  {
    int maxlvl;//最大日志等级
    int currentcount;//当前记录条数
    int maxcount;//最大记录条数
} xlog_limit;
#define xLOG_MAX_COUNT 20000

struct xlog {
    const char *ident;	/* daemon name (first arg to openlog) */
    xlog_proto_t protocol;
    xlog_limit xloglmt[xLOG_NUM_DESTS];
    int default_lvl;	/* maxlvl to use if none is specified */
    FILE *fp;
    char *filename;
    int facility;		/* as per syslog facility */
    int record_priority;	/* should messages logged through stdio include the priority of the message? */
    int syslog_options;	/* 2nd arg to openlog */
    int timestamp_precision;	/* # of digits of subsecond precision */
};

/* Default logging strucutre. */
extern struct xlog *xlog_default;

/* Open/Close xlog function */
extern struct xlog *openxlog (const char *progname, xlog_proto_t protocol,int syslog_options, int syslog_facility);
extern void closexlog (struct xlog *xl);

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define xPRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define xPRINTF_ATTRIBUTE(a,b)
#endif /* __GNUC__ */

/* Generic function for xlog. */
extern void x_log (struct xlog *xl, int priority, const char *format, ...)xPRINTF_ATTRIBUTE(3, 4);

/* Handy xlog functions. */
extern void x_log_err (const char *format, ...) xPRINTF_ATTRIBUTE(1, 2);
extern void x_log_warn (const char *format, ...) xPRINTF_ATTRIBUTE(1, 2);
extern void x_log_info (const char *format, ...) xPRINTF_ATTRIBUTE(1, 2);
extern void x_log_notice (const char *format, ...) xPRINTF_ATTRIBUTE(1, 2);
extern void x_log_debug (const char *format, ...) xPRINTF_ATTRIBUTE(1, 2);

/* Set logging level for the given destination.  If the log_level
   argument is xLOG_DISABLED, then the destination is disabled.
   This function should not be used for file logging (use xlog_set_file
   or xlog_reset_file instead). */
extern void xlog_set_level (struct xlog *xl, xlog_dest_t, int log_level);
extern void xlog_set_name (struct xlog *xl, xlog_proto_t protocol, char *name);

/* Set logging to the given filename at the specified level. */
extern int xlog_set_file (struct xlog *xl, const char *filename, int log_level);
/* Disable file logging. */
extern int xlog_reset_file (struct xlog *xl);

/* Rotate log. */
extern int xlog_rotate (struct xlog *);

extern const char *xlog_priority[];
extern char *xlog_proto_names[];

/* Puts a current timestamp in buf and returns the number of characters
   written (not including the terminating NUL).  The purpose of
   this function is to avoid calls to localtime appearing all over the code.
   It caches the most recent localtime result and can therefore
   avoid multiple calls within the same second.  If buflen is too small,
   *buf will be set to '\0', and 0 will be returned. */
extern size_t log_timestamp(int timestamp_precision /* # subsecond digits */,char *buf, size_t buflen);

/* structure useful for avoiding repeated rendering of the same timestamp */
struct ctimestamp_control {
    size_t len;		/* length of rendered timestamp */
    int precision;	/* configuration parameter */
    int already_rendered; /* should be initialized to 0 */
    char buf[40];	/* will contain the rendered timestamp */
};

#define LOGFILE_MASK 0600

#endif //_XLOG_H
