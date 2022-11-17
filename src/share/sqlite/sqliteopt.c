#include <string.h>
#include "sqliteopt.h"

#ifdef __linux__
#define strnicmp(a,b,n)     strncasecmp(a,b,n)
#define stricmp(a,b)         strcasecmp(a,b)
#endif

sqlite3 *xsqlite_open(const char *dbpath)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open(dbpath,&db);
    if (rc) return NULL;
    return db;
}

void xsqlite_close(sqlite3 *db)
{
    if (!db) return;
    sqlite3_close(db);
}

int xsqlite_recordest_select(sqlite3 *db, struct sqliterecordest *Query, const char *sql,const int timeout_ms)
{
    if (timeout_ms>0) sqlite3_busy_timeout(db,timeout_ms);

    sqlite3_get_table(db,sql,&Query->szResult,&Query->nrow,&Query->ncolumn,&Query->szErrMsg);
    if (!Query->ncolumn)
        return -1;
    Query->szField = Query->szResult;
    Query->szRow = &(Query->szResult[Query->ncolumn]);
    return Query->nrow;
}

int xsqlite_recordest_next(struct sqliterecordest *Query)
{
    Query->nrow_idx++;
    return Query->nrow_idx;
}

int xsqlite_recordest_close(struct sqliterecordest *Query)
{
    if (Query->szResult) sqlite3_free_table(Query->szResult);
    return 0;
}

int xsqlite_recordest_getcount(struct sqliterecordest *Query)
{
    return Query->nrow;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

int xsqlite_recordest_getfieldvalues_I64(struct sqliterecordest *Query, const char *strField, long long *nValue)
{
    if (!Query->szField || !Query->szRow)
        return -1;

    int i;
    int idx = -1;
    for (i=0;i<Query->ncolumn;i++)
    {
        if (0==stricmp(Query->szField[i],strField)) {
            idx = i;
            break;
        }
    }

    if (-1==idx)
        return -1;
    idx = Query->nrow_idx * Query->ncolumn + idx;
    char *p = Query->szRow[idx];
    if (p) {
        (*nValue) = atoll(p);
        return 0;
    }
    return -1;
}

int xsqlite_recordest_getfieldvalues_U32(struct sqliterecordest *Query, const char *strField, unsigned int *nValue)
{
    if (!Query->szField || !Query->szRow)
        return -1;

    int i;
    int idx = -1;
    for (i=0;i<Query->ncolumn;i++)
    {
        if (0==stricmp(Query->szField[i],strField)) {
            idx = i;
            break;
        }
    }

    if (-1==idx)
        return -1;

    idx = Query->nrow_idx * Query->ncolumn + idx;
    char *p = Query->szRow[idx];
    if (p) {
        (*nValue) = atoll(p);
        return 0;
    }
    return -1;
}

int xsqlite_recordest_getfieldvalues_U16(struct sqliterecordest *Query, const char *strField, unsigned short *nValue)
{
    if (!Query->szField || !Query->szRow)
        return -1;

    int i;
    int idx = -1;
    for (i=0;i<Query->ncolumn;i++)
    {
        if (0==stricmp(Query->szField[i],strField)) {
            idx = i;
            break;
        }
    }

    if (-1==idx)
        return -1;

    idx = Query->nrow_idx * Query->ncolumn + idx;
    char *p = Query->szRow[idx];
    if (p) {
        (*nValue) = atoi(p);
        return 0;
    }
    return -1;
}

int xsqlite_recordest_getfieldvalues_Str(struct sqliterecordest *Query, const char *strField, char * strValue, unsigned int size)
{
    if (!Query->szField || !Query->szRow)
        return -1;

    int i;
    int idx = -1;
    for (i=0;i<Query->ncolumn;i++)
    {
        if (0==stricmp(Query->szField[i],strField)) {
            idx = i;
            break;
        }
    }

    if(-1==idx)
        return -1;

    idx = Query->nrow_idx * Query->ncolumn + idx;
    char *p = Query->szRow[idx];
    if (p) {
        unsigned int len = strlen(p);
        if (len > size)
            return -1;
        strncpy(strValue,p,len);
        if (len<size)
            strValue[len] = '\0';
        return len;
    }
    return -1;
}
