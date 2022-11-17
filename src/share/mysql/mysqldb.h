#ifndef _MYSQLDB_H
#define _MYSQLDB_H

#include <mysql/mysql.h>
#include <stdbool.h>
#include <pthread.h>
#include "share/defines.h"

typedef struct {
    int conn_status;
    bool has_init;
    MYSQL *m_con;
    pthread_mutex_t m_cs;
}MYSQLBASE,*PMYSQLBASE;

typedef struct {
    MYSQL_RES *m_res;//结果集
    MYSQL_FIELD *m_field;//字段名
    int m_lies;//列
    int m_rows;//行
    MYSQL_ROW m_row;//当前行
    bool m_isEndOf;
    MYSQL *m_con;
    PMYSQLBASE m_pDB;
}MYSQLRECORDSET,*PMYSQLRECORDSET;

PUBLIC_DATA bool MysqlBase_OpenDB(PMYSQLBASE pDB,const char *username,const char *password,const char *dbname,const char *serverip,const unsigned short port);
PUBLIC_DATA void MysqlBase_CloseDB(PMYSQLBASE pDB);
PUBLIC_DATA void CSqlRecorDset_Init(PMYSQLRECORDSET pRecor);
PUBLIC_DATA void CSqlRecorDset_Destroy(PMYSQLRECORDSET pRecor);
PUBLIC_DATA bool CSqlRecorDset_SetConn(PMYSQLRECORDSET pRecor,PMYSQLBASE pDB);
PUBLIC_DATA int CSql_Transaction_Start(PMYSQLRECORDSET pRecor);
PUBLIC_DATA int CSql_Transaction_Query(PMYSQLRECORDSET pRecor,const char *sql);
PUBLIC_DATA int CSql_Transaction_Committ(PMYSQLRECORDSET pRecor);
PUBLIC_DATA bool CSqlRecorDset_ExecSQL(PMYSQLRECORDSET pRecor,const char *sql);
PUBLIC_DATA bool CSqlRecorDset_CloseRec(PMYSQLRECORDSET pRecor);
PUBLIC_DATA bool CSqlRecorDset_MoveNext(PMYSQLRECORDSET pRecor);
PUBLIC_DATA bool CSqlRecorDset_MoveFirst(PMYSQLRECORDSET pRecor);
PUBLIC_DATA bool CSqlRecorDset_IsEndEOF(PMYSQLRECORDSET pRecor);
PUBLIC_DATA int CSqlRecorDset_GetRecordCount(PMYSQLRECORDSET pRecor);

PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_I16(PMYSQLRECORDSET pRecor,const char *strField,short *nValue);
PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_U16(PMYSQLRECORDSET pRecor,const char *strField,unsigned short *nValue);
PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_I32(PMYSQLRECORDSET pRecor,const char *strField,int *nValue);
PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_U32(PMYSQLRECORDSET pRecor,const char *strField,unsigned int *nValue);
PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_I64(PMYSQLRECORDSET pRecor,const char *strField,long long  *nValue);
PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_U64(PMYSQLRECORDSET pRecor,const char *strField,unsigned long long *nValue);
PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_Double(PMYSQLRECORDSET pRecor,const char *strField,double *nValue);
PUBLIC_DATA bool CSqlRecorDset_GetFieldValue_String(PMYSQLRECORDSET pRecor,const char *strField,char * strValue,const size_t size);

#endif //_MYSQLDB_H
