#ifndef _MYDBOP_H_
#define _MYDBOP_H_

#include <stdio.h>
#include <stdlib.h>
#include "mysqldb.h"
#include "share/defines.h"

typedef struct {
    PMYSQLBASE m_pDB;
    MYSQLRECORDSET m_Query;
    char username[MAXNAMELEN];
    char password[MAXNAMELEN];
    char dbname[MAXNAMELEN];
    char serverip[MAXNAMELEN];
    unsigned short serverport;
    int m_nAlreadyInit;
}MYDBOP,*PMYDBOP;

PUBLIC_DATA void MyDBOp_Init(PMYDBOP pMyDB);
PUBLIC_DATA void MyDBOp_Destroy(PMYDBOP pMyDB);
PUBLIC_DATA bool MyDBOp_OpenDB(PMYDBOP pMyDB,const char *username,const char *password,const char *dbname,const char *serverip,const unsigned short serverport);
PUBLIC_DATA bool MyDBOp_ReOpenDB(PMYDBOP pMyDB);
PUBLIC_DATA bool MyDBOp_CloseDB(PMYDBOP pMyDB);
//void MyDBOp_Repair(PMYDBOP pMyDB);
PUBLIC_DATA bool MyDBOp_ExecSQL(PMYDBOP pMyDB,const char *sql);
PUBLIC_DATA bool MyDBOp_ExecSQL_1(PMYDBOP pMyDB,const char *sql);
PUBLIC_DATA void MyDBOp_Ping(PMYDBOP pMyDB);

#endif //_MYDBOP_H_
