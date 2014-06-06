#include "password.h"
#include "pairs.h"
#include "protocol.h"
#include <xcopy.h>
#include <tcpcopy.h>

#define COM_STMT_PREPARE 22
#define COM_STMT_EXECUTE 23
#define COM_QUERY 3
#define MAX_SP_SIZE 256
#define ENCRYPT_LEN 16
#define SEED_323_LENGTH  8

typedef struct {
    uint32_t sec_auth_checked:1;
    uint32_t sec_auth_not_yet_done:1;
    uint32_t first_auth_sent:1;
    char     scramble[SCRAMBLE_LENGTH + 1];
    char     seed323[SEED_323_LENGTH + 1];
    char     password[MAX_PASSWORD_LEN];
} tc_mysql_session;


typedef struct {
    link_list *list;
    int tot_cont_len;
} mysql_table_item_t;


typedef struct {
    tc_pool_t      *pool;
    hash_table     *table;
    hash_table     *fir_auth_table;
    hash_table     *sec_auth_table;
} tc_mysql_ctx_t;

/* TODO allocate it on heap */
static tc_mysql_ctx_t ctx;

static int 
init_mysql_module(void *clt_settings)
{

    ctx.pool = tc_create_pool(SESS_TABLE_POOL_SIZE, 0);

    if (ctx.pool) {

        ctx.table = hash_create(ctx.pool, 65536);
        if (ctx.table == NULL) {
            return TC_ERR;
        }

        ctx.fir_auth_table = hash_create(ctx.pool, 65536);
        if (ctx.fir_auth_table == NULL) {
            return TC_ERR;
        }

        ctx.sec_auth_table = hash_create(ctx.pool, 65536);
        if (ctx.sec_auth_table == NULL) {
            return TC_ERR;
        }

        return TC_OK;

    } 

    return TC_ERR;
}


static void 
exit_mysql_module(void *clt_settings) 
{
    tc_destroy_pool(ctx.pool);
    ctx.table = NULL;
    ctx.fir_auth_table = NULL;
    ctx.sec_auth_table = NULL;
    ctx.pool  = NULL;
}


static bool
check_renew_session(tc_iph_t *ip, tc_tcph_t *tcp)
{
    void           *value;
    uint16_t        size_ip, size_tcp, tot_len, cont_len;
    uint64_t        key;
    unsigned char  *payload, command, pack_number;

    key   = get_key(ip->saddr, tcp->source);
    value = hash_find(ctx.fir_auth_table, key);
    if (value == NULL) {
        return false;
    }

    size_ip  = ip->ihl << 2;
    size_tcp = tcp->doff << 2;
    tot_len  = ntohs(ip->tot_len);
    cont_len = tot_len - size_tcp - size_ip;

    if (cont_len > 0) {
        payload = (unsigned char *) ((char *) tcp + size_tcp);
        /* skip packet length */
        payload = payload + 3;
        /* retrieve packet number */
        pack_number = payload[0];
        /* if it is the second authenticate_user, skip it */
        if (pack_number != 0) {
            return false;
        }
        /* skip packet number */
        payload = payload + 1;

        command = payload[0];
        tc_log_debug1(LOG_DEBUG, 0, "mysql command:%u", command);
        if (command == COM_QUERY || command == COM_STMT_EXECUTE) {
            return true;
        }
    }

    return false;
}
        

static bool 
check_pack_needed_for_recons(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    uint16_t            size_tcp;
    p_link_node         ln;
    unsigned char      *payload, command, *pkt;
    mysql_table_item_t *item;

    if (s->cur_pack.cont_len > 0) {

        size_tcp = tcp->doff << 2;
        payload = (unsigned char *) ((char *) tcp + size_tcp);
        /* skip packet length */
        payload  = payload + 3;
        /* skip packet number */
        payload  = payload + 1;
        command  = payload[0];

        if (command != COM_STMT_PREPARE) {
            return false;
        }

        item = hash_find(ctx.table, s->hash_key);
        if (!item) {
            item = tc_pcalloc(ctx.pool, sizeof(mysql_table_item_t));
            if (item != NULL) {
                item->list = link_list_create(ctx.pool);
                if (item->list != NULL) {
                    hash_add(ctx.table, ctx.pool, s->hash_key, item);
                } else {
                    tc_log_info(LOG_ERR, 0, "list create err");
                    return false;
                }
            } else {
                tc_log_info(LOG_ERR, 0, "mysql item create err");
                return false;
            }
        }

        if (item->list->size > MAX_SP_SIZE) {
            return false;
        }

        tc_log_debug1(LOG_INFO, 0, "push packet:%u", ntohs(s->src_port));

        pkt = (unsigned char *) cp_fr_ip_pack(ctx.pool, ip);
        ln  = link_node_malloc(ctx.pool, pkt);
        ln->key = ntohl(tcp->seq);
        link_list_append_by_order(item->list, ln);
        item->tot_cont_len += s->cur_pack.cont_len;

        return true;
    }

    return false;
}


static int
mysql_dispose_auth(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    int               auth_success;
    void             *value;
    char              encryption[ENCRYPT_LEN];
    uint16_t          size_tcp, cont_len;
    unsigned char    *payload;
    tc_mysql_session *mysql_sess;

    mysql_sess = s->data;

    size_tcp = tcp->doff << 2;
    cont_len = s->cur_pack.cont_len;

    if (!mysql_sess->first_auth_sent) {

        payload = (unsigned char *) ((char *) tcp + size_tcp);
        tc_log_debug1(LOG_INFO, 0, "change fir auth:%u", ntohs(s->src_port));
        auth_success = change_clt_auth_content(payload, (int) cont_len, 
                mysql_sess->password, mysql_sess->scramble);

        if (!auth_success) {
            s->sm.sess_over  = 1; 
            tc_log_info(LOG_WARN, 0, "change fir auth unsuccessful");
            return TC_ERR;
        }
        mysql_sess->first_auth_sent = 1;
        value = hash_find(ctx.fir_auth_table, s->hash_key);
        if (value != NULL) {
            tc_pfree(ctx.pool, value);
            tc_log_info(LOG_INFO, 0, "free for fir auth:%llu", s->hash_key);
        }

        value = (void *) cp_fr_ip_pack(ctx.pool, ip);
        hash_add(ctx.fir_auth_table, ctx.pool, s->hash_key, value);

    } else if (mysql_sess->first_auth_sent && mysql_sess->sec_auth_not_yet_done)
    {
        payload = (unsigned char *) ((char *) tcp + size_tcp);

        tc_memzero(encryption, ENCRYPT_LEN);
        tc_memzero(mysql_sess->seed323, SEED_323_LENGTH + 1);
        memcpy(mysql_sess->seed323, mysql_sess->scramble, SEED_323_LENGTH);
        new_crypt(encryption, mysql_sess->password, mysql_sess->seed323);

        tc_log_debug1(LOG_INFO, 0, "change sec auth:%u", ntohs(s->src_port));
        change_clt_second_auth_content(payload, cont_len, encryption);
        mysql_sess->sec_auth_not_yet_done = 0;

        value = hash_find(ctx.sec_auth_table, s->hash_key);
        if (value != NULL) {
            tc_pfree(ctx.pool, value);
            tc_log_info(LOG_INFO, 0, "free for sec auth:%llu", s->hash_key);
        }
        value = (void *) cp_fr_ip_pack(ctx.pool, ip);
        hash_add(ctx.sec_auth_table, ctx.pool, s->hash_key, value);
    }

    return TC_OK;
}



static int 
prepare_for_renew_session(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    uint16_t            size_ip, t_cont_len, fir_clen, sec_clen;
    uint32_t            tot_clen, base_seq;
    uint64_t            key;
    tc_iph_t           *fir_ip, *t_ip, *sec_ip;
    tc_tcph_t          *fir_tcp, *t_tcp, *sec_tcp;
    p_link_node         ln;
    unsigned char      *p;
    mysql_table_item_t *item;

    sec_ip = NULL;
    sec_tcp = NULL;
    s->sm.need_rep_greet = 1;

    key = get_key(ip->saddr, tcp->source);

    p = (unsigned char *) hash_find(ctx.fir_auth_table, key);
    fir_ip   = (tc_iph_t *) (p + ETHERNET_HDR_LEN);
    size_ip  = fir_ip->ihl << 2;
    fir_tcp  = (tc_tcph_t *) ((char *) fir_ip + size_ip);
    fir_clen = TCP_PAYLOAD_LENGTH(fir_ip, fir_tcp);
    tot_clen = fir_clen;

    p = (unsigned char *) hash_find(ctx.sec_auth_table, key);
    if (p != NULL) {
        sec_ip    = (tc_iph_t *) (p + ETHERNET_HDR_LEN);
        size_ip   = sec_ip->ihl << 2;
        sec_tcp   = (tc_tcph_t *) ((char *) sec_ip + size_ip);
        sec_clen  = TCP_PAYLOAD_LENGTH(sec_ip, sec_tcp);
        tot_clen += sec_clen;
    } else {
        sec_clen  = 0;
        tc_log_debug1(LOG_INFO, 0, "no sec auth:%u", ntohs(s->src_port));
    }

    item = hash_find(ctx.table, s->hash_key);
    if (item) {
        tot_clen += item->tot_cont_len;
    }

    tc_log_debug2(LOG_INFO, 0, "total len subtracted:%u,p:%u", tot_clen,
            ntohs(s->src_port));

    tcp->seq     = htonl(ntohl(tcp->seq) - tot_clen);
    fir_tcp->seq = htonl(ntohl(tcp->seq) + 1);
    tc_save_pack(s, s->slide_win_packs, fir_ip, fir_tcp);  

    if (sec_tcp != NULL) {
        sec_tcp->seq = htonl(ntohl(fir_tcp->seq) + fir_clen);
        tc_save_pack(s, s->slide_win_packs, sec_ip, sec_tcp);
        tc_log_debug1(LOG_INFO, 0, "add sec auth:%u", ntohs(s->src_port));
    }

    base_seq = ntohl(fir_tcp->seq) + fir_clen + sec_clen;

    if (item) {
        ln = link_list_first(item->list); 
        while (ln) {
            p = (unsigned char *) ln->data;
            t_ip  = (tc_iph_t *) (p + ETHERNET_HDR_LEN);
            t_tcp = (tc_tcph_t *) ((char *) t_ip + size_ip);
            t_tcp->seq = htonl(base_seq);
            tc_save_pack(s, s->slide_win_packs, t_ip, t_tcp);  
            base_seq += TCP_PAYLOAD_LENGTH(t_ip, t_tcp);
            ln = link_list_get_next(item->list, ln);
        }
    }

    return TC_OK;
}


static int 
proc_when_sess_created(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    uint64_t          key;
    tc_mysql_session *data;
    
    data = (tc_mysql_session *) tc_pcalloc(s->pool, sizeof(tc_mysql_session));

    if (data) {
        s->data = data;
    }

    return TC_OK;
}


static int
proc_greet(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    int               ret; 
    uint16_t          size_tcp, cont_len; 
    unsigned char    *payload;
    tc_mysql_session *mysql_sess;

    mysql_sess = s->data;
    tc_log_debug1(LOG_INFO, 0, "recv greet from back:%u", ntohs(s->src_port));
    size_tcp = tcp->doff << 2;
    mysql_sess->sec_auth_checked  = 0;
    payload = (unsigned char *) ((char *) tcp + size_tcp);
    tc_memzero(mysql_sess->scramble, SCRAMBLE_LENGTH + 1);

    cont_len = s->cur_pack.cont_len;

    ret = parse_handshake_init_cont(payload, cont_len, mysql_sess->scramble);
    if (!ret) {
        if (cont_len > 11) {
            tc_log_info(LOG_WARN, 0, "port:%u,payload:%s",
                    ntohs(s->src_port), (char *) (payload + 11));
        }
        s->sm.sess_over = 1;
        return PACK_STOP;
    }

    return PACK_CONTINUE;
}


static int 
check_needed_for_sec_auth(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    uint16_t          size_tcp;
    unsigned char    *payload;
    tc_mysql_session *mysql_sess;

    mysql_sess = s->data;
    if (mysql_sess->sec_auth_checked == 0) {
        size_tcp = tcp->doff << 2;
        payload = (unsigned char *) ((char *) tcp + size_tcp);
        if (is_last_data_packet(payload)) {
            tc_log_debug1(LOG_INFO, 0, "needs sec auth:%u", ntohs(s->src_port));
            mysql_sess->sec_auth_not_yet_done = 1;
        }
        mysql_sess->sec_auth_checked = 1;
    }

    return TC_OK;
}


static int 
proc_auth(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    uint16_t        size_tcp;
    unsigned char  *p, *payload, pack_number;

    if (!s->sm.rcv_rep_greet) {
        return PACK_STOP;
    }

    if (mysql_dispose_auth(s, ip, tcp) == TC_ERR) {
        return PACK_STOP;
    }

    return PACK_CONTINUE;
}


static int
mysql_parse_user_info(tc_conf_t *cf, tc_cmd_t *cmd)
{
    char       pass[MAX_PASSWORD_LEN];
    tc_str_t  *user_password;

    user_password = cf->args->elts;

    tc_memzero(pass, MAX_PASSWORD_LEN);
    memcpy(pass, user_password[1].data, user_password[1].len);

    if (retrieve_mysql_user_pwd_info(cf->pool, pass) == -1) {
        tc_log_info(LOG_ERR, 0, "wrong -u argument");
        return TC_ERR;
    }

    return TC_OK;
}


static tc_cmd_t  mysql_commands[] = {
    { tc_string("user"),
        0,
        0,
        TC_CONF_TAKE1,
        mysql_parse_user_info,
        NULL
    }
};


tc_module_t tc_mysql_module = {
    &ctx,
    mysql_commands,
    init_mysql_module,
    exit_mysql_module,
    check_renew_session,
    prepare_for_renew_session,
    check_pack_needed_for_recons,
    proc_when_sess_created,
    NULL,
    proc_greet,
    proc_auth,
    check_needed_for_sec_auth,
    NULL
};

