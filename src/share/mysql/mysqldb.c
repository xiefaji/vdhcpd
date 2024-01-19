#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "share/xlog.h"
#include "mysqldb.h"

#ifdef __linux__
#define strnicmp(a,b,n)     strncasecmp(a,b,n)
#define stricmp(a,b)         strcasecmp(a,b)
#endif

uint real_connext_mutex = 0;
#define real_mutex_unlock()  {__sync_bool_compare_and_swap(&real_connext_mutex,1,0); }
#define real_mutex_lock()    { while (!(__sync_bool_compare_and_swap (&real_connext_mutex,0, 1) )) {sched_yield();}}

 
long long atoll (const char *p)
{
    int minus = 0;
    long long value = 0;
    if (*p == '-') {
        minus ++;
        p ++;
    }

    while (*p >= '0' && *p <= '9')
    {
        value *= 10;
        value += *p - '0';
        p ++;
    }
    return minus ? 0 - value : value;
}

PUBLIC bool MysqlBase_OpenDB(PMYSQLBASE pDB,const char *username,const char *password,const char *dbname,const char *serverip,const unsigned short port)
{
    real_mutex_lock();
    pDB->m_con = mysql_init((MYSQL*) 0);
    if (!pDB->m_con) {
        real_mutex_unlock();
        x_log_warn("%s : 数据库句柄初始化失败[%s].",__FUNCTION__,mysql_error(pDB->m_con));
        return false;
    }

    //mysql_options(m_con, MYSQL_OPT_CONNECT_TIMEOUT , "10");
    if (!mysql_real_connect(pDB->m_con,serverip,username,password,dbname,port,NULL,0)) {
        mysql_thread_end();
        real_mutex_unlock();
        x_log_warn("%s : 数据库连接失败[%s].",__FUNCTION__,mysql_error(pDB->m_con));
        return false;
    }
    real_mutex_unlock();
    //mysql_options(m_con, MYSQL_OPT_RECONNECT, "1");
    pthread_mutex_init(&pDB->m_cs,NULL);//InitializeCriticalSection(&m_cs);
    pDB->has_init=true;
    return true;
}

PUBLIC void MysqlBase_CloseDB(PMYSQLBASE pDB)
{
    if (pDB->m_con!=NULL) {
        mysql_close(pDB->m_con);
        pDB->m_con= NULL;
        pthread_mutex_destroy(&pDB->m_cs);
        real_mutex_lock();
        mysql_thread_end();
        mysql_library_end();
        real_mutex_unlock();
    }
}

PUBLIC void CSqlRecorDset_Init(PMYSQLRECORDSET pRecor)
{
    memset(pRecor,0,sizeof(MYSQLRECORDSET));
    // pRecor->m_con = NULL;
    // pRecor->m_res = NULL;
    // pRecor->m_field = NULL;
    // pRecor->m_lies = 0;
    // pRecor->m_rows = 0;
    // pRecor->m_isEndOf = true;
}

PUBLIC void CSqlRecorDset_Destroy(PMYSQLRECORDSET pRecor)
{
    if (pRecor->m_res!=NULL) {
        mysql_free_result(pRecor->m_res);
        pRecor->m_res = NULL;
    }
}

PUBLIC bool CSqlRecorDset_SetConn(PMYSQLRECORDSET pRecor, PMYSQLBASE pDB)
{
    if (!pDB || pDB->m_con==NULL)
        return false;
    pRecor->m_pDB = pDB;
    pRecor->m_con = pDB->m_con;
    return true;
}

PUBLIC int CSql_Transaction_Start(PMYSQLRECORDSET pRecor)
{
    PMYSQLBASE m_pDB=pRecor->m_pDB;
    pthread_mutex_lock(&m_pDB->m_cs);//EnterCriticalSection(&m_pDB->m_cs);

    //执行语句
    if (mysql_query(pRecor->m_con, "START TRANSACTION ")) {
        pthread_mutex_unlock(&m_pDB->m_cs);
        return -1;
    }
    return 0;
}

PUBLIC int CSql_Transaction_Query(PMYSQLRECORDSET pRecor,const char *sql)
{
    //执行语句
    if (mysql_query(pRecor->m_con, sql))
        return -1;
    return 0;
}

PUBLIC int CSql_Transaction_Committ(PMYSQLRECORDSET pRecor)
{
    PMYSQLBASE m_pDB=pRecor->m_pDB;
    mysql_query(pRecor->m_con,"COMMIT");
    pthread_mutex_unlock(&m_pDB->m_cs);
    return 0;
}

//执行mysql 除查询外的操作 如插入 删除等
PUBLIC bool CSqlRecorDset_ExecSQL(PMYSQLRECORDSET pRecor,const char *sql)
{
    PMYSQLBASE m_pDB=pRecor->m_pDB;
    if (!m_pDB || 0 != m_pDB->conn_status)
        return false;
    pthread_mutex_lock(&m_pDB->m_cs);//EnterCriticalSection(&m_pDB->m_cs);
    if (pRecor->m_res!=NULL) {//先关闭以前的结果集
        mysql_free_result(pRecor->m_res);
        pRecor->m_res = NULL;
    }

    //执行语句
    if (mysql_query(pRecor->m_con, sql)) {
        //fprintf(stderr, "%s %s\n", sql,mysql_error(m_con));
        pthread_mutex_unlock(&m_pDB->m_cs);//LeaveCriticalSection(&m_pDB->m_cs);
        return false;
    }

    //判断是否需要结果集
    if (strnicmp(sql,"select",6)==0 || strnicmp(sql,"repair",6)==0 || strnicmp(sql,"show",4)==0 || strnicmp(sql,"check",4)==0) {
        pRecor->m_res=mysql_store_result(pRecor->m_con);
        if (pRecor->m_res==NULL) {
            pRecor->m_isEndOf = true;
            pthread_mutex_unlock(&m_pDB->m_cs);//LeaveCriticalSection(&m_pDB->m_cs);
            return false;
        }
        pRecor->m_rows = mysql_num_rows(pRecor->m_res);

        pRecor->m_field = mysql_fetch_fields(pRecor->m_res);
        if (pRecor->m_field == NULL) {
            pRecor->m_lies = 0;
        }  else {
            pRecor->m_lies = mysql_num_fields(pRecor->m_res);
        }

        pRecor->m_row = mysql_fetch_row(pRecor->m_res);//取得第一行
        if (pRecor->m_row != NULL) {
            pRecor->m_isEndOf = false;
        }  else  {
            pRecor->m_isEndOf = true;
        }
    }  else  {
        pRecor->m_isEndOf = true;
    }
    pthread_mutex_unlock(&m_pDB->m_cs);//LeaveCriticalSection(&m_pDB->m_cs);
    return true;
}

PUBLIC bool CSqlRecorDset_CloseRec(PMYSQLRECORDSET pRecor)
{
    if (pRecor->m_res!=NULL) {//先关闭以前的结果集
        mysql_free_result(pRecor->m_res);
        pRecor->m_res = NULL;
    }
    pRecor->m_isEndOf = true;
    return true;
}

PUBLIC bool CSqlRecorDset_MoveNext(PMYSQLRECORDSET pRecor)
{
    if (pRecor->m_res == NULL)
        return false;
    pRecor->m_row = mysql_fetch_row(pRecor->m_res);
    if (pRecor->m_row==NULL) {
        pRecor->m_isEndOf = true;
        return false;
    } else {
        return true;
    }
}

PUBLIC bool CSqlRecorDset_MoveFirst(PMYSQLRECORDSET pRecor)
{
    if (pRecor->m_res == NULL)
        return false;

    mysql_data_seek(pRecor->m_res,0);
    pRecor->m_row = mysql_fetch_row(pRecor->m_res);
    if (pRecor->m_row==NULL) {
        pRecor->m_isEndOf = true;
        return false;
    } else {
        pRecor->m_isEndOf = false;
        return true;
    }
}

PUBLIC bool CSqlRecorDset_IsEndEOF(PMYSQLRECORDSET pRecor)
{
    return pRecor->m_isEndOf;
}

PUBLIC int CSqlRecorDset_GetRecordCount(PMYSQLRECORDSET pRecor)
{
    return pRecor->m_rows;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

//bool CSqlRecorDset_GetFieldValue_I8(PMYSQLRECORDSET pRecor,char *strField,int8_t *nValue)
//{
//    if(pRecor->m_field == NULL || pRecor->m_res == NULL) {
//        return 0;
//    }
//    int i = 0;
//    for(;i<pRecor->m_lies;i++) {
//        if(stricmp(pRecor->m_field[i].name,strField)==0)
//            break;
//    }
//    if(i>=pRecor->m_lies) {
//        return 0;
//    } else {
//        if(pRecor->m_row!=NULL) {
//            if(pRecor->m_row[i]==NULL) {
//                return 0;
//            }
//            if(strlen(pRecor->m_row[i])==0) {
//                return 0;
//            }
//            (*nValue) =pRecor->m_row[i][0];
//            return 1;
//        } else {
//            return 0;
//        }
//    }
//}

PUBLIC bool CSqlRecorDset_GetFieldValue_I16(PMYSQLRECORDSET pRecor,const char *strField,short *nValue)
{
    int i = 0;
    *nValue = 0;//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL)
        return 0;

    for (;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if (i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
            (*nValue) =atoi(pRecor->m_row[i]);
            return 1;
        } else {
            return 0;
        }
    }
}

PUBLIC bool CSqlRecorDset_GetFieldValue_U16(PMYSQLRECORDSET pRecor,const char *strField,unsigned short *nValue)
{
    int i = 0;
    *nValue = 0;//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL)
        return 0;

    for (;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if (i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
            (*nValue) =atoi(pRecor->m_row[i]);
            return 1;
        } else {
            return 0;
        }
    }
}

PUBLIC bool CSqlRecorDset_GetFieldValue_I32(PMYSQLRECORDSET pRecor,const char *strField,int *nValue)
{
    int i = 0;
    *nValue = 0;//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL)
        return 0;

    for (;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if (i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
            (*nValue) =atol(pRecor->m_row[i]);
            return 1;
        } else {
            return 0;
        }
    }
}

PUBLIC bool CSqlRecorDset_GetFieldValue_U32(PMYSQLRECORDSET pRecor,const char *strField,unsigned int *nValue)
{
    int i = 0;
    *nValue = 0;//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL)
        return 0;

    for (;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if(i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
            (*nValue) = atoll(pRecor->m_row[i]);
            return 1;
        } else {
            return 0;
        }
    }
}

PUBLIC bool CSqlRecorDset_GetFieldValue_I64(PMYSQLRECORDSET pRecor,const char *strField,long long *nValue)
{
    int i = 0;
    *nValue = 0;//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL)
        return 0;

    for(;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if (i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
            (*nValue) = atoll(pRecor->m_row[i]);
            return 1;
        } else {
            return 0;
        }
    }
}

PUBLIC bool CSqlRecorDset_GetFieldValue_U64(PMYSQLRECORDSET pRecor,const char *strField,unsigned long long *nValue)
{
    int i = 0;
    *nValue = 0;//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL)
        return 0;

    for (;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if (i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
            (*nValue) = strtoull(pRecor->m_row[i],NULL,10);
            return 1;
        } else {
            return 0;
        }
    }
}

PUBLIC bool CSqlRecorDset_GetFieldValue_Double(PMYSQLRECORDSET pRecor,const char *strField,double *nValue)
{
    int i = 0;
    *nValue = 0;//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL) {
        return 0;
    }

    for (;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if (i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
            (*nValue) = atof(pRecor->m_row[i]);
            return 1;
        } else {
            return 0;
        }
    }
}

PUBLIC bool CSqlRecorDset_GetFieldValue_String(PMYSQLRECORDSET pRecor,const char *strField,char *strValue,const size_t size)
{
    int i = 0;
    memset(strValue, 0, size);//Reset
    if (pRecor->m_field == NULL || pRecor->m_res == NULL)
        return 0;

    for (;i<pRecor->m_lies;i++) {
        if (stricmp(pRecor->m_field[i].name,strField)==0) break;
    }

    if (i>=pRecor->m_lies) {
        return 0;
    } else {
        if (pRecor->m_row!=NULL) {
            if (pRecor->m_row[i]==NULL) return 0;
            if (strlen(pRecor->m_row[i])==0) return 0;
//            if (strlen(pRecor->m_row[i])+1>size) return 0;
            strncpy(strValue, pRecor->m_row[i], MIN(strlen(pRecor->m_row[i]),size));
            return 1;
        } else {
            return 0;
        }
    }
}
