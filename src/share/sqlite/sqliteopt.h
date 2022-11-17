#ifndef _SQLITEOPT_H
#define _SQLITEOPT_H

#include <stdlib.h>
#include <sqlite3.h>

struct sqliterecordest {
    char **szResult;
    char **szField;
    char **szRow;
    int nrow_idx;
    int nrow ;
    int ncolumn;
    char *szErrMsg;
};

extern sqlite3 *xsqlite_open(const char *dbpath);
extern void xsqlite_close(sqlite3 *db);
extern int xsqlite_recordest_select(sqlite3 *db, struct sqliterecordest *Query, const char *sql, const int timeout_ms);
extern int xsqlite_recordest_next(struct sqliterecordest *Query);
extern int xsqlite_recordest_close(struct sqliterecordest *Query);
extern int xsqlite_recordest_getcount(struct sqliterecordest *Query);

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

extern int xsqlite_recordest_getfieldvalues_I64(struct sqliterecordest *Query, const char *strField, long long *nValue);
extern int xsqlite_recordest_getfieldvalues_U32(struct sqliterecordest *Query, const char *strField, unsigned int *nValue);
extern int xsqlite_recordest_getfieldvalues_U16(struct sqliterecordest *Query, const char *strField, unsigned short *nValue);
extern int xsqlite_recordest_getfieldvalues_Str(struct sqliterecordest *Query, const char *strField, char * strValue, unsigned int size);

#endif // _SQLITEOPT_H
