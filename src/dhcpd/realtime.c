#include "dhcpd.h"

//统计报文并发
PRIVATE u32 randnum;
typedef union {
    u64 key_value;
    struct {
        u32 ticktime;
        u32 randnum;
    } u;
} realtime_tick_t;
PRIVATE void realtime_tick_init(realtime_tick_t *realtime_tick)
{
    BZERO(realtime_tick, sizeof(realtime_tick_t));
    SET_COUNTER(realtime_tick->u.ticktime);
    realtime_tick->u.randnum = __sync_fetch_and_add(&randnum, 1);
}

PRIVATE realtime_tick_t *realtime_tick_init2()
{
    realtime_tick_t *realtime_tick = (realtime_tick_t *)xmalloc(sizeof(realtime_tick_t));
    SET_COUNTER(realtime_tick->u.ticktime);
    realtime_tick->u.randnum = __sync_fetch_and_add(&randnum, 1);
    return realtime_tick;
}

PRIVATE void realtime_tick_release(void *p)
{
    realtime_tick_t *realtime_tick = (realtime_tick_t *)p;
    if (realtime_tick) xfree(realtime_tick);
}

PRIVATE void realtime_tick_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    realtime_tick_t *realtime_tick = (realtime_tick_t *)p;
    if (realtime_tick) trash_queue_enqueue(pRecycleTrash, realtime_tick);
}

PRIVATE void realtime_tick_update(realtime_info_t *realtime_info)
{
    realtime_tick_t realtime_tick;
    realtime_tick_init(&realtime_tick);
    key_tree_lock(&realtime_info->key_tickcount);
    key_rbinsert_u(&realtime_info->key_tickcount, realtime_tick.key_value, realtime_tick.key_value);
    key_tree_unlock(&realtime_info->key_tickcount);
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

PRIVATE realtime_info_t *realtime_info_init(const packet_process_t *packet_process)
{
    const ipcshare_hdr_t *ipcsharehdr = packet_process->ipcsharehdr;
    realtime_info_t *realtime_info = (realtime_info_t *)xmalloc(sizeof(realtime_info_t));
    BZERO(realtime_info, sizeof(realtime_info_t));
    BCOPY(&packet_process->macaddr, &realtime_info->key.u.macaddr, sizeof(mac_address_t));
    realtime_info->lineid = ipcsharehdr->lineid;
    realtime_info->ovlanid = ipcsharehdr->outer_vlanid;
    realtime_info->ivlanid = ipcsharehdr->inner_vlanid;
    realtime_info->sessionid = ipcsharehdr->session;
    realtime_info->starttime = time(NULL);
    key_tree_init(&realtime_info->key_tickcount);
    return realtime_info;
}

PRIVATE void realtime_info_update(realtime_info_t *realtime_info, realtime_info_t *realtime_tmp)
{
    realtime_info->lineid = realtime_tmp->lineid;
    realtime_info->ovlanid = realtime_tmp->ovlanid;
    realtime_info->ivlanid = realtime_tmp->ivlanid;
    realtime_info->sessionid = realtime_tmp->sessionid;
}

PRIVATE void realtime_info_update2(const packet_process_t *packet_process, realtime_info_t *realtime_info)
{
    const ipcshare_hdr_t *ipcsharehdr = packet_process->ipcsharehdr;
    realtime_info->lineid = ipcsharehdr->lineid;
    realtime_info->ovlanid = ipcsharehdr->outer_vlanid;
    realtime_info->ivlanid = ipcsharehdr->inner_vlanid;
    realtime_info->sessionid = ipcsharehdr->session;
}

PRIVATE void realtime_info_release(void *p)
{
    realtime_info_t *realtime_info = (realtime_info_t *)p;
    if (realtime_info) {
        key_tree_destroy2(&realtime_info->key_tickcount, NULL/*realtime_tick_release*/);
        xfree(realtime_info);
    }
}

PRIVATE void realtime_info_recycle(void *p, trash_queue_t *pRecycleTrash)
{
    realtime_info_t *realtime_info = (realtime_info_t *)p;
    if (realtime_info) {
        key_tree_nodes_recycle(&realtime_info->key_tickcount, pRecycleTrash, NULL/*realtime_tick_recycle*/);
        trash_queue_enqueue(pRecycleTrash, realtime_info);
    }
}

PUBLIC size_t realtime_info_finger(realtime_info_t *realtime_info, char *finger, const size_t size)
{
    char hex_hostname[MINBUFFERLEN+1]={0};
    char hex_reqopts[MINBUFFERLEN+1]={0};
    char hex_maxreqsize[MINNAMELEN+1]={0};
    char hex_vendorname[MINBUFFERLEN+1]={0};
    char hex_macaddr[MINNAMELEN+1]={0};
    char hex_userclass[MINBUFFERLEN+1]={0};

    hex2string((unsigned char *)realtime_info->v4.hostname, realtime_info->v4.hostname_len, hex_hostname, MINBUFFERLEN, "0");
    hex2string((unsigned char *)realtime_info->v4.reqopts, realtime_info->v4.reqopts_len, hex_reqopts, MINBUFFERLEN, "0");
    hex2string((unsigned char *)&realtime_info->v4.max_message_size, sizeof(u16), hex_maxreqsize, MINBUFFERLEN, "0");
    hex2string((unsigned char *)realtime_info->v4.vendorname, realtime_info->v4.vendorname_len, hex_vendorname, MINBUFFERLEN, "0");
    hex2string((unsigned char *)&realtime_info->key.u.macaddr, ETH_ALEN, hex_macaddr, MINNAMELEN, "0");
    hex2string((unsigned char *)realtime_info->v4.userclass, realtime_info->v4.userclass_len, hex_userclass, MINBUFFERLEN, "0");

    return snprintf(finger, size, "%s%s%s%s%s%s", hex_hostname, hex_reqopts, hex_maxreqsize, hex_vendorname, hex_macaddr, hex_userclass);
}

PUBLIC size_t realtime_info_finger_md5(realtime_info_t *realtime_info, char *finger_md5, const size_t size)
{
    char buffer[MAXBUFFERLEN+1]={0};
    size_t finger_len = realtime_info_finger(realtime_info, buffer, MAXBUFFERLEN);
    unsigned char md5sun[VECTORLEN]={0};

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, (unsigned char *)buffer, finger_len);
    MD5_Final(md5sun, &ctx);
    return hex2string(md5sun, VECTORLEN, finger_md5, size, "MD5SUM");
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

PUBLIC void stats_main_init(vdhcpd_stats_t *stats_main)
{
    BZERO(stats_main, sizeof(vdhcpd_stats_t));
    key_tree_init(&stats_main->key_realtime);
}

PUBLIC void stats_main_release(vdhcpd_stats_t *stats_main)
{
    BZERO(stats_main, sizeof(vdhcpd_stats_t));
    key_tree_destroy2(&stats_main->key_realtime, realtime_info_release);
}

PUBLIC realtime_info_t *realtime_search(void *p)
{
    packet_process_t *packet_process = (packet_process_t *)p;
    vdhcpd_stats_t *stats_main = &packet_process->vdm->stats_main;
    realtime_key_t key;
    BZERO(&key, sizeof(realtime_key_t));
    BCOPY(&packet_process->macaddr, &key.u.macaddr, sizeof(mac_address_t));

    struct key_node *knode = key_rbsearch(&stats_main->key_realtime, key.key_value);
    return (knode && knode->data) ? knode->data:NULL;
}

PUBLIC realtime_info_t *realtime_search_macaddr(const mac_address_t macaddr)
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    vdhcpd_stats_t *stats_main = &vdm->stats_main;
    realtime_key_t key;
    BZERO(&key, sizeof(realtime_key_t));
    BCOPY(&macaddr, &key.u.macaddr, sizeof(mac_address_t));

    struct key_node *knode = key_rbsearch(&stats_main->key_realtime, key.key_value);
    return (knode && knode->data) ? knode->data:NULL;
}

PUBLIC realtime_info_t *realtime_find(void *p, trash_queue_t *pRecycleTrash)
{
    packet_process_t *packet_process = (packet_process_t *)p;
    vdhcpd_stats_t *stats_main = &packet_process->vdm->stats_main;

    realtime_info_t *realtime_info = realtime_search(packet_process);
    if (!realtime_info) {
        if (KEY_TREE_NODES(&stats_main->key_realtime) >= 500000) {
            x_log_warn("%s:%d 实时终端数量超限.", __FUNCTION__, __LINE__);
            return NULL;
        }
        realtime_info = realtime_info_init(packet_process);
        key_tree_lock(&stats_main->key_realtime);
        struct key_node *knode = key_rbinsert(&stats_main->key_realtime, realtime_info->key.key_value, realtime_info);
        key_tree_unlock(&stats_main->key_realtime);
        if (knode && knode->data) {
            realtime_info_update(knode->data, realtime_info);
            realtime_info_recycle(realtime_info, pRecycleTrash);
            realtime_info = knode->data;//数据更新
        }
    } else {
        realtime_info_update2(packet_process, realtime_info);
    }
    realtime_tick_update(realtime_info);//更新并发统计
    return realtime_info;
}

PRIVATE void realtime_info_warning(realtime_info_t *realtime_info, const char *describe)
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    db_event_t *db_event = db_event_init(DPF_NORMAL);
    char sql[MAXBUFFERLEN+1]={0};
    int len = snprintf(sql, MAXBUFFERLEN, "INSERT INTO tbdhcpalarm (`mac`,`time`,`msg`) VALUES ('"MACADDRFMT"',%u,'%s');",
                       MACADDRBYTES(realtime_info->key.u.macaddr), (u32)time(NULL), describe);
    db_event->sql = strndup(sql, len);
    db_process_push_event(&vdm->db_process, db_event);
}

PRIVATE void realtime_info_maintain_tick(realtime_info_t *realtime_info, trash_queue_t *pRecycleTrash)
{
    struct key_node *knode = key_first(&realtime_info->key_tickcount);
    while (knode && knode->data) {
        realtime_tick_t realtime_tick = {.key_value = knode->second};
        if (CMP_COUNTER(realtime_tick.u.ticktime, 1) || realtime_info->warning) {
            key_tree_lock(&realtime_info->key_tickcount);
            knode = key_rberase_EX(&realtime_info->key_tickcount, knode, pRecycleTrash, trash_queue_enqueue2);
            key_tree_unlock(&realtime_info->key_tickcount);
        } else {
            knode = key_next(knode);
        }
    }
    realtime_info->warning = 0;
    if (KEY_TREE_NODES(&realtime_info->key_tickcount) > 5) {
        realtime_info_warning(realtime_info, "DHCP请求并发超限.");//并发过高告警
        realtime_info->warning = 1;
    }
}

PRIVATE void realtime_info_update_lease4(realtime_info_t *realtime_info)
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    db_event_t *db_event = db_event_init(DPF_NORMAL);
    char sql[MAXBUFFERLEN+1]={0};
    int len = snprintf(sql, MAXBUFFERLEN, "INSERT INTO tbdhcplease (`ip`,`mac`,`hostname`,`start`,`expire`,`flag`,`lineid`,`innervlan`,`outervlan`,`isProbe`,`GMname`,`vendor`,`isRelay`) "
                                          "VALUES (%u,'"MACADDRFMT"','%s',%u,%u,%u,%u,%u,%u,%u,'%s','%s',%u) "
                                          "ON DUPLICATE KEY UPDATE `mac`='"MACADDRFMT"',`hostname`='%s',`start`=%u,`expire`=%u,`flag`=%u,`lineid`=%u,`innervlan`=%u,`outervlan`=%u,"
                                          "`isProbe`=%u,`GMname`='%s',`vendor`='%s',`isRelay`=%u;",
                       ntohl(realtime_info->v4.ipaddr.address), MACADDRBYTES(realtime_info->key.u.macaddr), realtime_info->v4.hostname, (u32)realtime_info->starttime, RLTINFO_EXPIRETIME4(realtime_info),
                       0/*是否静态IP*/, realtime_info->lineid, realtime_info->ivlanid, realtime_info->ovlanid, 0, "NULL", realtime_info->v4.vendorname, RLTINFO_IS_RELAY4(realtime_info),
                       MACADDRBYTES(realtime_info->key.u.macaddr), realtime_info->v4.hostname, (u32)realtime_info->starttime, RLTINFO_EXPIRETIME4(realtime_info),
                       0/*是否静态IP*/, realtime_info->lineid, realtime_info->ivlanid, realtime_info->ovlanid, 0, "NULL", realtime_info->v4.vendorname, RLTINFO_IS_RELAY4(realtime_info));
    db_event->sql = strndup(sql, len);
    db_process_push_event(&vdm->db_process, db_event);
}

PRIVATE void realtime_info_update_lease6(realtime_info_t *realtime_info)
{
    vdhcpd_main_t *vdm = &vdhcpd_main;
    db_event_t *db_event = db_event_init(DPF_NORMAL);

    db_process_push_event(&vdm->db_process, db_event);
}

PRIVATE void realtime_info_save_finger(realtime_info_t *realtime_info, FILE *pFILE)
{
    if (pFILE) {
        char finger4[MINNAMELEN+1] = {0};
        char finger6[MINNAMELEN+1] = {0};

        if ((RLTINFO_IS_RELAY4(realtime_info) || RLTINFO_IS_SERVER4(realtime_info)))
            realtime_info_finger_md5(realtime_info, finger4, MINNAMELEN);

        if ((RLTINFO_IS_RELAY6(realtime_info) || RLTINFO_IS_SERVER6(realtime_info))) {

        }

        fprintf(pFILE, "{\"macaddr\":\""MACADDRFMT"\",\"finger4\":\"%s\",\"finger6\":\"%s\"}\r\n", MACADDRBYTES(realtime_info->key.u.macaddr), finger4, finger6);
    }
}

PUBLIC void stats_main_maintain(vdhcpd_stats_t *stats_main, trash_queue_t *pRecycleTrash)
{
    PRIVATE u32 last_finger = 0;
    FILE *pFILE = NULL;
    char filename[MAXNAMELEN+1]={0};
    if (CMP_COUNTER(last_finger, 10)) {
        snprintf(filename, MAXNAMELEN, "%s.bak", path_cfg.fingerfile);
        pFILE = fopen(filename, "w");
        SET_COUNTER(last_finger);
    }

    struct key_node *knode = key_first(&stats_main->key_realtime);
    while (knode && knode->data) {
        realtime_info_t *realtime_info = (realtime_info_t *)knode->data;
        if (realtime_info->update_db4) {
            __sync_fetch_and_and(&realtime_info->update_db4, 0);
            realtime_info_update_lease4(realtime_info);
        }

        if (realtime_info->update_db6) {
            __sync_fetch_and_and(&realtime_info->update_db6, 0);
            realtime_info_update_lease6(realtime_info);
        }

        realtime_info_maintain_tick(realtime_info, pRecycleTrash);//并发统计

        realtime_info_save_finger(realtime_info, pFILE);//指纹存储

        knode = key_next(knode);
    }

    if (pFILE) { fflush(pFILE); fclose(pFILE); rename(filename, path_cfg.fingerfile); }
}
