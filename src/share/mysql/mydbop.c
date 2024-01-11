#include <string.h>
#include "share/defines.h"
#include "share/xlog.h"
#include "mydbop.h"

PUBLIC void MyDBOp_Init(PMYDBOP pMyDB)
{
    memset(pMyDB, 0, sizeof(MYDBOP));
    pMyDB->m_pDB = NULL;
    CSqlRecorDset_Init(&pMyDB->m_Query);
    pMyDB->m_nAlreadyInit=1;
}

PUBLIC void MyDBOp_Destroy(PMYDBOP pMyDB)
{
    MyDBOp_CloseDB(pMyDB);
}

PUBLIC bool MyDBOp_ReOpenDB(PMYDBOP pMyDB)
{
    MyDBOp_CloseDB(pMyDB);
    bool bRet = MyDBOp_OpenDB(pMyDB,pMyDB->username,pMyDB->password,pMyDB->dbname,pMyDB->serverip,pMyDB->serverport);
    return bRet;
}

PUBLIC bool MyDBOp_OpenDB(PMYDBOP pMyDB,const char *username,const char *password,const char *dbname,const char *serverip,const unsigned short serverport)
{
    pMyDB->m_pDB = (PMYSQLBASE)xMALLOC(sizeof(MYSQLBASE));//new CSqlDataBase;
    memset(pMyDB->m_pDB, 0, sizeof(MYSQLBASE));
    bool bRet = MysqlBase_OpenDB(pMyDB->m_pDB,username,password,dbname,serverip,serverport);//m_pDB->OpenDB(pUser,pPassword,pDBName,pSvrIP,nPort);
    if (bRet) {
        CSqlRecorDset_SetConn(&pMyDB->m_Query,pMyDB->m_pDB);//m_Query.InitConn(m_pDB);
        CSqlRecorDset_ExecSQL(&pMyDB->m_Query,"set names utf8");//m_Query.ExecSQL("set names gbk");
    }
 
    // BCOPY(username, pMyDB->username, strlen(username)); 
    // BCOPY(password, pMyDB->password, strlen(password)); 
    // BCOPY(dbname, pMyDB->dbname, strlen(dbname)); 
    // BCOPY(serverip, pMyDB->serverip, strlen(serverip));
    // pMyDB->serverport = serverport;
    return bRet;
}

PUBLIC bool MyDBOp_CloseDB(PMYDBOP pMyDB)
{
    if (pMyDB->m_pDB) {
        MysqlBase_CloseDB(pMyDB->m_pDB);//m_pDB->CloseDB();
        xFREE(pMyDB->m_pDB);
        pMyDB->m_pDB = NULL;
    } 
    return true;
}

PUBLIC bool MyDBOp_ExecSQL(PMYDBOP pMyDB,const char *sql)
{
    MYSQLRECORDSET Query={0};
    CSqlRecorDset_Init(&Query);
    CSqlRecorDset_SetConn(&Query,pMyDB->m_pDB);//Query.InitConn(m_pDB);

    if (!CSqlRecorDset_ExecSQL(&Query,sql)) {
        CSqlRecorDset_CloseRec(&Query);
        CSqlRecorDset_Destroy(&Query);
        x_log_warn("%s : 执行SQL失败[ %s ].",__FUNCTION__,sql);
        return false;
    }
    CSqlRecorDset_CloseRec(&Query);
    CSqlRecorDset_Destroy(&Query);
    return true;
}

PUBLIC bool MyDBOp_ExecSQL_1(PMYDBOP pMyDB,const char *sql)
{
    if (!CSqlRecorDset_ExecSQL(&pMyDB->m_Query,sql)) {
        x_log_warn("%s : 执行SQL失败[%s].",__FUNCTION__,sql);
        return false;
    }
    return true;
}

PUBLIC void MyDBOp_Ping(PMYDBOP pMyDB)
{
    PMYSQLBASE m_pDB=pMyDB->m_pDB;
    if (!m_pDB || !m_pDB->m_con) {
        MyDBOp_ReOpenDB(pMyDB);
        return;
    }

    pthread_mutex_lock(&m_pDB->m_cs);//EnterCriticalSection(&m_pDB->m_cs);
    int ret = mysql_ping(m_pDB->m_con);
    m_pDB->conn_status = ret;
    pthread_mutex_unlock(&m_pDB->m_cs);//EnterCriticalSection(&m_pDB->m_cs);
    if (0 != m_pDB->conn_status) {
        MyDBOp_ReOpenDB(pMyDB);
        return;
    }
}
