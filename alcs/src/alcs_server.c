#include "alcs_api_internal.h"
#include "json_parser.h"
#include "CoAPPlatform.h"
#include "CoAPResource.h"
#include "utils_hmac.h"
#include "utils_base64.h"
#include "utils_md5.h"

#ifndef ALCS_MAX_SERVER_AUTHCODE_COUNT
#define ALCS_MAX_SERVER_AUTHCODE_COUNT KEY_MAXCOUNT
#endif
#define RES_FORMAT "{\"id\":\"%.*s\",\"code\":%d,\"data\":{%s}}"

#ifdef ALCSSERVER
int sessionid_seed = 0xff;
static int default_heart_expire = 120000;

void alcs_rec_auth_select (CoAPContext *ctx, const char *paths, NetworkAddr* from, CoAPMessage* resMsg)
{
    int seqlen = 0, datalen = 0;
    char *seq, *data;
    char* targetKey = "";
    int targetLen = 0;
    //int res_code = 200;
    COAP_DEBUG ("receive data:%.*s", resMsg->payloadlen, resMsg->payload);

    do {
        if (!req_payload_parser((const char *)resMsg->payload, resMsg->payloadlen, &seq, &seqlen, &data, &datalen) || !datalen) {
            break;
        }

        device_auth_list *dev_lst = get_device (ctx);
        auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;

        if (!lst) {
            break;
        }
        char* accesskeys;
        int keylen;
        accesskeys = alcs_json_get_value_by_name(data, datalen, "accessKeys", &keylen, NULL);
        if (!accesskeys || !keylen) {
            break;
        }
        //COAP_DEBUG ("accessKeys:%.*s", keylen, accesskeys);
        char back;
        char *str_pos, *entry;
        int entry_len, type;

        backup_json_str_last_char (accesskeys, keylen, back);
        json_array_for_each_entry(accesskeys, keylen, str_pos, entry, entry_len, type) {
            COAP_DEBUG ("entry:%.*s", entry_len, entry);
            svr_key_item *node = NULL, *next = NULL;

            HAL_MutexLock(dev_lst->list_mutex);
            list_for_each_entry_safe(node, next, &lst->lst_svr, lst, svr_key_item) {
                COAP_DEBUG ("keyprefix:%s", node->keyInfo.keyprefix);
                if (strstr(entry, node->keyInfo.keyprefix) == entry) {
                    COAP_DEBUG ("target keyprefix:%s", entry);
                    targetKey = entry;
                    targetLen = entry_len;
                    break;
                }
            }
            HAL_MutexUnlock(dev_lst->list_mutex);

            if (targetKey) {
                break;
            }

            svr_group_item *gnode = NULL, *gnext = NULL;

            HAL_MutexLock(dev_lst->list_mutex);
            list_for_each_entry_safe(gnode, gnext, &lst->lst_svr_group, lst, svr_group_item) {
                //COAP_DEBUG ("keyprefix:%s", gnode->keyInfo.keyprefix);
                if (strstr(entry, gnode->keyInfo.keyprefix) == entry) {
                    COAP_DEBUG ("target keyprefix:%s", entry);
                    targetKey = entry;
                    targetLen = entry_len;
                    break;
                }
            }
            HAL_MutexUnlock(dev_lst->list_mutex);

            if (targetKey) {
                break;
            }
        }
        restore_json_str_last_char (accesskeys, keylen, back);

    } while (0);

    COAP_DEBUG ("key:%s", targetKey);

    CoAPMessage msg;
    char keybuf[32];
    HAL_Snprintf(keybuf, sizeof(keybuf), "\"accessKey\":\"%.*s\"", targetLen, targetKey);
    char payloadbuf[512];
    HAL_Snprintf (payloadbuf, sizeof(payloadbuf), RES_FORMAT, seqlen, seq, targetKey? 200 : COAP_MSG_CODE_401_UNAUTHORIZED, keybuf);
    CoAPLenString payload = {strlen(payloadbuf), (unsigned char *)payloadbuf};

    alcs_msg_init (ctx, &msg, COAP_MSG_CODE_205_CONTENT, COAP_MESSAGE_TYPE_ACK, 0, &payload, NULL);
    CoAPLenString token = {resMsg->header.tokenlen,resMsg->token};
    alcs_sendrsp (ctx, from, &msg, 1, resMsg->header.msgid, &token);
}

svr_key_info* is_legal_key(CoAPContext *ctx, const char* keyprefix, int prefixlen, const char* keyseq, int seqlen, int* res_code)
{
    COAP_DEBUG ("islegal prefix:%.*s, seq:%.*s", prefixlen, keyprefix, seqlen, keyseq);

    device_auth_list *dev_lst = get_device (ctx);
    auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;
    if (lst) {
        COAP_DEBUG ("find devices");
        HAL_MutexLock(dev_lst->list_mutex);

        if (lst->revocation) {
            int len = strlen(lst->revocation);
            int i;
            for (i = 0; i < len; i += KEYSEQ_LEN) {
                if (strncmp(keyseq, lst->revocation + i, seqlen) == 0) {
                    HAL_MutexUnlock(dev_lst->list_mutex);
                    *res_code = ALCS_AUTH_REVOCATE;
                    COAP_INFO ("accesskey is revocated");
                    return NULL;
                }
            }
        }

        if (list_empty(&lst->lst_svr)) {
            *res_code = ALCS_AUTH_AUTHLISTEMPTY;
        } else {
            svr_key_item *node = NULL, *next = NULL;
            list_for_each_entry_safe(node, next, &lst->lst_svr, lst, svr_key_item) {
                //COAP_DEBUG ("node prefix:%s", node->keyInfo.keyprefix);
                if (strlen(node->keyInfo.keyprefix) == prefixlen && strncmp (keyprefix, node->keyInfo.keyprefix, prefixlen) == 0) {
                    *res_code = ALCS_AUTH_OK;
                    HAL_MutexUnlock(dev_lst->list_mutex);
                    return &node->keyInfo;
                }
            }
            
            svr_group_item* gnode = NULL, *gnext = NULL;
            list_for_each_entry_safe(gnode, gnext, &lst->lst_svr_group, lst, svr_group_item) {
                COAP_DEBUG ("node prefix:%s", gnode->keyInfo.keyprefix);
                if (strlen(gnode->keyInfo.keyprefix) == prefixlen && strncmp (keyprefix, gnode->keyInfo.keyprefix, prefixlen) == 0) {
                    *res_code = ALCS_AUTH_OK;
                    HAL_MutexUnlock(dev_lst->list_mutex);
                    return &gnode->keyInfo;
                }
            }

            *res_code = ALCS_AUTH_UNMATCHPREFIX;
        }

        HAL_MutexUnlock(dev_lst->list_mutex);
    }

    return NULL;
}

void alcs_rec_auth (CoAPContext *ctx, const char *paths, NetworkAddr* from, CoAPMessage* resMsg)
{
    int seqlen = 0, datalen = 0;
    char* seq, *data;
    int res_code = 200;
    char body[200] = {0};
    COAP_INFO ("receive data:%.*s, from:%s", resMsg->payloadlen, resMsg->payload, from->addr);

    do {
        if (!req_payload_parser((const char *)resMsg->payload, resMsg->payloadlen, &seq, &seqlen, &data, &datalen) || !datalen) {
            break;
        }
        char* tmp, *accesskey, *randomkey, *sign;
        int tmplen;
        accesskey = alcs_json_get_value_by_name(data, datalen, "accessKey", &tmplen, NULL);
        COAP_INFO ("accesskey:%.*s", tmplen, accesskey);

        if (!accesskey || tmplen != KEYPREFIX_LEN + 1 + 1 + KEYSEQ_LEN) {
            res_code = ALCS_AUTH_INVALIDPARAM;
            break;
        }

        char* keyprefix = accesskey;
        char* keyseq = accesskey + KEYPREFIX_LEN + 1 + 1;

        svr_key_info* item = is_legal_key(ctx, keyprefix, KEYPREFIX_LEN, keyseq, KEYSEQ_LEN, &res_code);
        if (!item) {
            COAP_INFO ("islegal return null");
            break;
        }

        char accessToken[64];
        int tokenlen = sizeof(accessToken);
        utils_hmac_sha1_base64 (accesskey, tmplen, item->secret, strlen(item->secret), accessToken, &tokenlen);

        //COAP_DEBUG ("accessToken:%.*s", tokenlen, accessToken);

        int randomkeylen;
        randomkey = alcs_json_get_value_by_name(data, datalen, "randomKey", &randomkeylen, NULL);
        if (!randomkey || !randomkeylen) {
            res_code = ALCS_AUTH_INVALIDPARAM;
            break;
        }

        tmp = alcs_json_get_value_by_name(data, datalen, "opt", &tmplen, NULL);
        int support_opt = 0;
        if (tmp) {
            char back;
            backup_json_str_last_char (tmp, tmplen, back);
            support_opt = atoi (tmp);
            restore_json_str_last_char (tmp, tmplen, back);
            COAP_DEBUG ("opt:%d", support_opt);
        }

        /*calc sign, save in buf*/
        char buf[40];
        int calc_sign_len = sizeof(buf);
        utils_hmac_sha1_base64 (randomkey, randomkeylen, accessToken, tokenlen, buf, &calc_sign_len);

        //COAP_DEBUG ("calc randomKey:%.*s,token:%.*s,sign:%.*s", randomkeylen, randomkey, tokenlen,
        //    accessToken, calc_sign_len, buf);

        sign = alcs_json_get_value_by_name(data, datalen, "sign", &tmplen, NULL);
        if (!sign || tmplen != calc_sign_len || strncmp(sign, buf, calc_sign_len)) {
            res_code = ALCS_AUTH_ILLEGALSIGN;
            break;
        }

        int pklen, dnlen;
        char* pk = alcs_json_get_value_by_name(data, datalen, "prodKey",&pklen, NULL);
        char* dn = alcs_json_get_value_by_name(data, datalen, "deviceName",&dnlen, NULL);

        if (!pk || !pklen || !dn || !dnlen) {
            res_code = ALCS_AUTH_INVALIDPARAM;
            break;
        }
        char tmp1 = pk[pklen];
        char tmp2 = dn[dnlen];
        pk[pklen] = 0;
        dn[dnlen] = 0;

        AlcsDeviceKey devKey;
        memset(&devKey, 0x00, sizeof(AlcsDeviceKey));
        memcpy (&devKey.addr, from, sizeof(NetworkAddr));
        devKey.pk = pk;
        devKey.dn = dn;
        session_item* session = get_svr_session (ctx, &devKey);

        if (!session) {
            session = (session_item*)coap_malloc(sizeof(session_item));
            if (!session) {
                res_code = ALCS_AUTH_INTERNALERROR;
                break;
            }
            struct list_head* svr_head = get_svr_session_list (ctx);
            list_add_tail(&session->lst, svr_head);
        }

        gen_random_key((unsigned char *)session->randomKey, RANDOMKEY_LEN);
        session->sessionId = ++sessionid_seed;
        //generate seqStart
        srand((unsigned)time(NULL));
        session->seqStart = rand() % 1000000;

        char path[100] = {0}; 
        HAL_Snprintf (path, sizeof(path), "%s%s", pk, dn);
        CoAPPathMD5_sum (path, strlen(path), session->pk_dn, PK_DN_CHECKSUM_LEN);

        memcpy (&session->addr, from, sizeof(NetworkAddr));
        COAP_INFO ("new session, addr:%s, port:%d", session->addr.addr, session->addr.port);
        
        //restore
        pk[pklen] = tmp1;
        dn[dnlen] = tmp2;

        HAL_Snprintf (buf, sizeof(buf), "%.*s%s", randomkeylen, randomkey, session->randomKey);
        //COAP_DEBUG("source key:%s", buf);
        utils_hmac_sha1_raw (buf,strlen(buf), session->sessionKey, accessToken, tokenlen);

        session->opt = ALCS_OPT_HEART_V1;
        if (support_opt & ALCS_OPT_PAYLOAD_CHECKSUM) {
            session->opt |= ALCS_OPT_PAYLOAD_CHECKSUM;
        }

        if (support_opt & ALCS_OPT_SUPPORT_SEQWINDOWS) {
            session->opt |= ALCS_OPT_SUPPORT_SEQWINDOWS;
            session->seqWindow = (seq_window_item*)coap_malloc(sizeof(seq_window_item));
            if (session->seqWindow) {
                memset (session->seqWindow, 0, sizeof(seq_window_item));
            }
        }

        /*calc sign, save in buf*/
        calc_sign_len = sizeof(buf);
        utils_hmac_sha1_base64 (session->randomKey, RANDOMKEY_LEN, accessToken, tokenlen, buf, &calc_sign_len);
        HAL_Snprintf (body, sizeof(body), "\"sign\":\"%.*s\",\"randomKey\":\"%s\",\"sessionId\":%d,\"opt\":%d,\"seqStart\":%d",
             calc_sign_len, buf, session->randomKey, session->sessionId, session->opt,session->seqStart);

        session->authedTime = HAL_UptimeMs ();
        session->heartRecTime = session->authedTime;

    } while (0);

    CoAPMessage message;
    char payloadbuf[512];
    HAL_Snprintf (payloadbuf, sizeof(payloadbuf), RES_FORMAT, seqlen, seq, res_code, body);
    CoAPLenString payload = {strlen(payloadbuf), (unsigned char*)payloadbuf};

    alcs_msg_init (ctx, &message, COAP_MSG_CODE_205_CONTENT, COAP_MESSAGE_TYPE_CON, 0, &payload, NULL);
    CoAPLenString token = {resMsg->header.tokenlen, resMsg->token};
    alcs_sendrsp (ctx, from, &message, 1, resMsg->header.msgid, &token);
}

int add_svr_key (CoAPContext *ctx, const char* keyprefix, const char* secret, bool isGroup)
{
    COAP_DEBUG("add_svr_key\n");

    svr_key_item *node = NULL, *next = NULL;
    device_auth_list *dev_lst = get_device (ctx);
    auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;

    if (!lst || lst->svr_count >= ALCS_MAX_SERVER_AUTHCODE_COUNT || strlen(keyprefix) != KEYPREFIX_LEN) {
        return COAP_ERROR_INVALID_LENGTH;
    }

    HAL_MutexLock(dev_lst->list_mutex);
    list_for_each_entry_safe(node, next, &lst->lst_svr, lst, svr_key_item) {
        if(strcmp(node->keyInfo.keyprefix, keyprefix) == 0){
            coap_free(node->keyInfo.secret);
            list_del(&node->lst);
            coap_free(node);
            break;
        }
    }
    HAL_MutexUnlock(dev_lst->list_mutex);

    svr_key_item* item = (svr_key_item*) coap_malloc(sizeof(svr_key_item));
    if (!item) {
        return COAP_ERROR_MALLOC;
    }

    item->keyInfo.secret = (char*) coap_malloc(strlen(secret) + 1);
    if (!item->keyInfo.secret) {
        coap_free (item);
        return COAP_ERROR_MALLOC;
    }
    strcpy (item->keyInfo.secret, secret);
    strcpy (item->keyInfo.keyprefix, keyprefix);

    HAL_MutexLock(dev_lst->list_mutex);
    list_add_tail(&item->lst, &lst->lst_svr);
    ++lst->svr_count;
    HAL_MutexUnlock(dev_lst->list_mutex);

    return COAP_SUCCESS;
}

int alcs_add_svr_key (CoAPContext *ctx, const char* keyprefix, const char* secret)
{
    COAP_INFO("alcs_add_svr_key");
    return add_svr_key (ctx, keyprefix, secret, 0);
}


int alcs_remove_svr_key (CoAPContext *ctx, const char* keyprefix)
{
    device_auth_list *dev_lst = get_device (ctx);
    auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;
    if (!lst) {
        return COAP_ERROR_NULL;
    }

    svr_key_item *node = NULL, *next = NULL;
    HAL_MutexLock(dev_lst->list_mutex);

    list_for_each_entry_safe(node, next, &lst->lst_svr, lst, svr_key_item) {
        if(strcmp(node->keyInfo.keyprefix, keyprefix) == 0){
            coap_free(node->keyInfo.secret);
            list_del(&node->lst);
            coap_free(node);
            break;
        }
    }
    HAL_MutexUnlock(dev_lst->list_mutex);

    return COAP_SUCCESS;
}

int alcs_set_revocation (CoAPContext *ctx, const char* seqlist)
{
    device_auth_list *dev_lst = get_device (ctx);
    auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;
    if (!lst) {
        return COAP_ERROR_NULL;
    }

    HAL_MutexLock(dev_lst->list_mutex);

    int len = seqlist? strlen(seqlist) : 0;
    if (lst->revocation) {
        coap_free(lst->revocation);
        lst->revocation = NULL;
    }

    if (len > 0) {
        lst->revocation = (char*)coap_malloc (len + 1);
        strcpy (lst->revocation, seqlist);
    }
    HAL_MutexUnlock(dev_lst->list_mutex);

    return COAP_SUCCESS;
}

//-----------------------------------------

void send_err_rsp (CoAPContext* ctx, NetworkAddr*addr, int code, CoAPMessage* request)
{
    CoAPMessage sendMsg;
    CoAPLenString payload = {0};
    alcs_msg_init (ctx, &sendMsg, code, COAP_MESSAGE_TYPE_ACK, 0, &payload, NULL);
    CoAPLenString token = {request->header.tokenlen,request->token};
    alcs_sendrsp (ctx, addr, &sendMsg, 1, request->header.msgid, &token);
}

static secure_resource_cb_item* get_resource_by_path (const char *path)
{
    secure_resource_cb_item*node, *next;
    char path_calc[MAX_PATH_CHECKSUM_LEN] = {0};
    CoAPPathMD5_sum (path, strlen(path), path_calc, MAX_PATH_CHECKSUM_LEN);

    list_for_each_entry_safe(node, next, &secure_resource_cb_head, lst, secure_resource_cb_item) {
        if (memcmp(node->path, path_calc, MAX_PATH_CHECKSUM_LEN) == 0){
            return node;
        }
    }

    COAP_ERR ("receive unknown request, path:%s", path);
    return NULL;
}

void recv_msg_handler (CoAPContext *context, const char *path, NetworkAddr *remote, CoAPMessage *message)
{
    secure_resource_cb_item* node = get_resource_by_path (path);
    if (!node) {
        return;
    }

    struct list_head* sessions = get_svr_session_list(context);
    session_item* session = get_session_by_checksum(context, sessions, remote, node->pk_dn);
    
    do {
        if (!session) {
            break;
        }

        unsigned int sessionId = 0;
        char checksum[4];
        sessionId = get_message_sessionid (message, session->opt, checksum);
        COAP_DEBUG("recv_msg_handler, sessionID:%d", (int)sessionId);

        if (sessionId != session->sessionId) {
            break;
        }

        session->heartRecTime = HAL_UptimeMs();
        //anti replay
        if (session->opt & ALCS_OPT_SUPPORT_SEQWINDOWS) {
            if (!seqwindow_accept(message, session)) {
                COAP_ERR ("invalid seqid");
                break;
            }
        }

        unsigned int obsVal;
        if (CoAPUintOption_get (message, COAP_OPTION_OBSERVE, &obsVal) == COAP_SUCCESS) {
            if (obsVal == 0) {
                CoAPObsServer_add (context, path, remote, message);
            }
        }

        session->heartRecTime = HAL_UptimeMs();
        char* buf = (char*)coap_malloc(message->payloadlen);
        if (buf) {
            CoAPMessage tmpMsg;
            memcpy (&tmpMsg, message, sizeof(CoAPMessage));

            int len = alcs_decrypt ((const char *)message->payload, message->payloadlen, session->sessionKey, buf);
            if (len > 0) {
                //checksum
                if (session->opt & ALCS_OPT_PAYLOAD_CHECKSUM) {
                    unsigned char md5[16];
                    utils_md5 ((unsigned char*)buf, len, md5);
                    if (memcmp (md5, checksum, 4) != 0) {
                        COAP_ERR ("recv_msg_handler, checksum isn't match");
                        coap_free (buf);
                        break;
                    }
                }

                tmpMsg.payload = (unsigned char *)buf;
                tmpMsg.payloadlen = len;
                node->cb (context, path, remote, &tmpMsg);
                coap_free (buf);
            } else {
                coap_free (buf);
                break;
            }
        }
        return;

    } while (0);
    
    send_err_rsp (context, remote, COAP_MSG_CODE_401_UNAUTHORIZED, message);
    COAP_ERR ("need auth, path:%s, from:%s", path, remote->addr);
}

int alcs_resource_register_secure (CoAPContext *context, const char* pk, const char* dn, const char *path, unsigned short permission,
            unsigned int ctype, unsigned int maxage, CoAPRecvMsgHandler callback)
{
    COAP_INFO("alcs_resource_register_secure");

    secure_resource_cb_item* item = (secure_resource_cb_item*)coap_malloc (sizeof(secure_resource_cb_item));
    item->cb = callback;
    CoAPPathMD5_sum (path, strlen(path), item->path, MAX_PATH_CHECKSUM_LEN);

    char pk_dn[100] = {0};
    HAL_Snprintf (pk_dn, sizeof(pk_dn), "%s%s", pk, dn);
    CoAPPathMD5_sum (pk_dn, strlen(pk_dn), item->pk_dn, PK_DN_CHECKSUM_LEN);
    
    list_add_tail(&item->lst, &secure_resource_cb_head);

    return CoAPResource_register (context, path, permission, ctype, maxage, &recv_msg_handler);
}

int alcs_resource_unregister_secure (CoAPContext *context, const char *path)
{
    secure_resource_cb_item* node = get_resource_by_path (path);
    if (!node) {
        return -1;
    }

    list_del (&node->lst);
    CoAPResource_unregister(context, path);
    coap_free (node);
    return COAP_SUCCESS;
}

void alcs_resource_cb_deinit(void)
{
	secure_resource_cb_item* del_item = NULL;

	list_for_each_entry(del_item,&secure_resource_cb_head,lst,secure_resource_cb_item)
	{
		list_del(&del_item->lst);
		coap_free(del_item);
		del_item = list_entry(&secure_resource_cb_head,secure_resource_cb_item,lst);
	}
}

static void do_rsp_heart (CoAPContext *ctx, NetworkAddr *remote, CoAPMessage *request, struct list_head* ctl_head, char* buf, char* seq, int seqlen)
{
    sprintf (buf, "{\"id\":\"%.*s\",\"code\":200,\"data\":{\"encodetype\":0,\"devices\":\"", seqlen, seq);
    char* p = buf + strlen(buf); 
    session_item *node = NULL, *next = NULL;
    list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {
        if(node->sessionId && is_networkadd_same(&node->addr, remote)) {
            uint32_t outlen;
            utils_base64encode ((const uint8_t *)node->pk_dn, PK_DN_CHECKSUM_LEN, 9, (unsigned char*)p, &outlen);
            p[outlen] = 0;
            p += outlen;
        }
    }

    strcat (buf, "\"}}");
    COAP_DEBUG ("do_rsp_heart, send:%s", buf);

    CoAPLenString payload = {strlen(buf), (unsigned char *)buf};
    CoAPLenString token = {request->header.tokenlen, request->token};
    CoAPMessage msg;
    alcs_msg_init (ctx, &msg, COAP_MSG_CODE_205_CONTENT, COAP_MESSAGE_TYPE_CON, 0, &payload, NULL);
    alcs_sendrsp (ctx, remote, &msg, 1, request->header.msgid, &token);
}

void alcs_rec_heart_beat(CoAPContext *ctx, const char *path, NetworkAddr *remote, CoAPMessage *request)
{
    COAP_DEBUG ("alcs_rec_heart_beat");
    struct list_head* ctl_head = get_svr_session_list (ctx);
    if (!ctl_head || list_empty(ctl_head)) {
        COAP_DEBUG ("ctl_head is NULL");
        return;
    }

    int count = 0;
    session_item *node = NULL, *next = NULL;

    device_auth_list *dev_lst = get_device (ctx);
    HAL_MutexLock(dev_lst->list_mutex);

    list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {
        if(node->sessionId && is_networkadd_same(&node->addr, remote)) {
            node->heartRecTime = HAL_UptimeMs();
            ++ count;
        }
    }
    HAL_MutexUnlock(dev_lst->list_mutex);

    int seqlen;
    char *seq;
    req_payload_parser((const char *)request->payload, request->payloadlen, &seq, &seqlen, NULL, NULL);

    if (count > 0) {
        if (count > 4) {
            char* dbuf = coap_malloc(64 + count * 10);
            if (dbuf) {
                do_rsp_heart (ctx, remote, request, ctl_head, dbuf, seq, seqlen);
                coap_free (dbuf);
            } 
        } else {
            char sbuf[128];
            do_rsp_heart (ctx, remote, request, ctl_head, sbuf, seq, seqlen);
        }
 
    } else {
        char payloadbuf[64];
        CoAPMessage msg;
        CoAPLenString token = {request->header.tokenlen, request->token};
        COAP_DEBUG ("count is zero");

        HAL_Snprintf (payloadbuf, sizeof(payloadbuf), RES_FORMAT, seqlen, seq, ALCS_HEART_FAILAUTH, "");
        CoAPLenString payload = {strlen(payloadbuf), (unsigned char *)payloadbuf};
        alcs_msg_init (ctx, &msg, COAP_MSG_CODE_205_CONTENT, COAP_MESSAGE_TYPE_CON, 0, &payload, NULL);
        alcs_sendrsp (ctx, remote, &msg, 1, request->header.msgid, &token);
    }
}

int observe_data_encrypt(CoAPContext *ctx, const char* path, NetworkAddr* from, CoAPMessage *message, CoAPLenString *src, CoAPLenString *dest)
{
    COAP_DEBUG("observe_data_encrypt, src:%.*s", src->len, src->data);

    secure_resource_cb_item* node = get_resource_by_path (path);
    if (!node) {
        return COAP_ERROR_NOT_FOUND;
    }

    struct list_head* sessions = get_svr_session_list(ctx);
    session_item* session = get_session_by_checksum(ctx, sessions, from, node->pk_dn);

    if (session) {
        dest->len = (src->len & 0xfffffff0) + 16;
        dest->data  = (unsigned char*)coap_malloc(dest->len);
        add_message_sessionid (message, session->sessionId, session->opt, src);
        alcs_encrypt ((const char*)src->data, src->len, session->sessionKey, dest->data);
        return COAP_SUCCESS;
    }

    return COAP_ERROR_NOT_FOUND;
}

void on_svr_auth_timer (CoAPContext* ctx)
{
    struct list_head* head = get_svr_session_list (ctx);
    if (!head || list_empty(head)) {
        return;
    }
    COAP_DEBUG ("on_svr_auth_timer:%d", (int)HAL_UptimeMs());

    //device_auth_list* dev = get_device (ctx);
    int tick = HAL_UptimeMs();

    device_auth_list *dev_lst = get_device (ctx);
    HAL_MutexLock(dev_lst->list_mutex);
    session_item *node = NULL, *next = NULL;
    list_for_each_entry_safe(node, next, head, lst, session_item) {
        if(node->sessionId && node->heartRecTime + default_heart_expire < tick) {
            COAP_ERR ("heart beat timeout");
            remove_session (ctx, node);
        }
    }
    HAL_MutexUnlock(dev_lst->list_mutex);

}
#endif
