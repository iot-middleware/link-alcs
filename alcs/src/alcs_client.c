#include "alcs_api_internal.h"
#include "json_parser.h"
#include "CoAPPlatform.h"
#include "utils_base64.h"
#include "utils_hmac.h"
#include "CoAPResource.h"

#ifndef ALCS_MAX_CLIENT_COUNT
#define ALCS_MAX_CLIENT_COUNT KEY_MAXCOUNT
#endif

#ifdef ALCSCLIENT
static int default_heart_interval = 30000;
char match_key (const char* accesskey, const char* keyprefix)
{
    if (strlen(keyprefix) == KEYPREFIX_LEN && strstr(accesskey, keyprefix) == accesskey) {
        return 1;
    }

    return 0;
}

int do_auth (CoAPContext *ctx, NetworkAddr* addr, ctl_key_item* ctl_item, void *userdata, AuthHandler handler);
bool res_parse (const char* payload, int len, int* seq, ResponseMsg* res_msg, char** data, int* datalen)
{
    if (!payload || !len || !seq || !res_msg || !data) {
        return 0;
    }

    COAP_DEBUG ("payload:%.*s", len, payload);

    int tmplen;
    char* tmp;
    char back;

    tmp = alcs_json_get_value_by_name((char*)payload, len, "id", &tmplen, NULL); 
    if (tmp) {
        backup_json_str_last_char (tmp, tmplen, back);
        *seq = atoi (tmp);
        restore_json_str_last_char (tmp, tmplen, back);
    } else {
        *seq = 0;
    }

    tmp = alcs_json_get_value_by_name((char*)payload, len, "code", &tmplen, NULL);
    if (!tmp) {
        return 0;
    }

    backup_json_str_last_char (tmp, tmplen, back);
    res_msg->code = atoi (tmp);
    restore_json_str_last_char (tmp, tmplen, back);

    tmp = alcs_json_get_value_by_name((char*)payload, len, "msg", &tmplen, NULL);
    if (tmp && tmplen) {
        res_msg->msg = (char*)coap_malloc (tmplen);
        memcpy (res_msg->msg, tmp, tmplen);
    } else {
        res_msg->msg = NULL;
    }

    *data = alcs_json_get_value_by_name((char*)payload, len, "data", datalen, NULL);
    return 1;
}

bool fillAccessKey(CoAPContext*ctx, char* buf)
{
    device_auth_list *dev_lst = get_device (ctx);
    auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;
    if (!lst) {
        return 0;
    }

    HAL_MutexLock(dev_lst->list_mutex);

    if (list_empty(&lst->lst_ctl)) {
        HAL_MutexUnlock(dev_lst->list_mutex);
        return 0;
    }
    strcpy (buf, ",\"accessKeys\":[");
    ctl_key_item *node = NULL, *next = NULL;
    list_for_each_entry_safe(node, next, &lst->lst_ctl, lst, ctl_key_item) {
        char* format;
        if (lst->ctl_group_count || !list_is_last(&node->lst, &lst->lst_ctl)) {
            format = "\"%s\",";
        } else {
            format = "\"%s\"]";
        }
        sprintf (buf + strlen(buf), format, node->accessKey);
    }

    ctl_group_item* gnode = NULL, *gnext = NULL;
    list_for_each_entry_safe(gnode, gnext, &lst->lst_ctl_group, lst, ctl_group_item) {
        char* format;
        if (!list_is_last(&gnode->lst, &lst->lst_ctl_group)) {
            format = "\"%s\",";
        } else {
            format = "\"%s\"]";
        }
        sprintf (buf + strlen(buf), format, gnode->accessKey);
    }

    HAL_MutexUnlock(dev_lst->list_mutex);
    return 1;
}

#define payload_format "{\"version\":\"1.0\",\"method\":\"%s\",\"id\":%d,\"params\":{\"prodKey\":\"%s\", \"deviceName\":\"%s\"%s}}"
void  nego_cb(CoAPContext *ctx, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
    COAP_INFO ("nego_cb, message addr:%p, networkaddr:%p!", message, remote);
    AuthParam* auth_param = (AuthParam*)userdata;

    if(COAP_RECV_RESP_TIMEOUT == result){
        ResponseMsg msg = {-1, "response time!"};
        auth_param->handler (ctx, remote, auth_param->user_data, &msg);
        coap_free (auth_param->productKey);
        coap_free (auth_param->deviceName);
        coap_free (auth_param);

    } else {
        COAP_DEBUG("recv response message");
        int seq, datalen = 0;
        ResponseMsg msg;
        char* data = NULL;

        res_parse ((const char*)message->payload, message->payloadlen, &seq, &msg, &data, &datalen);
        do {
            if (msg.code != 200) {
                break;
            }

            int keylen;
            char* accessKey = alcs_json_get_value_by_name(data, datalen, "accessKey", &keylen, NULL);
            if (!accessKey || !keylen) {
                break;
            }
            //COAP_DEBUG("accesskey:%.*s", keylen, accessKey);

            device_auth_list *dev_lst = get_device (ctx);
            auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;

            ctl_key_item *node = NULL, *next = NULL;
            char *accessTokenFound = NULL;
            HAL_MutexLock(dev_lst->list_mutex);

            list_for_each_entry_safe(node, next, &lst->lst_ctl, lst, ctl_key_item) {
                COAP_DEBUG("node:%s", node->accessKey);
                if (strncmp(node->accessKey, accessKey, keylen) == 0){
                    accessTokenFound = node->accessToken;
                    break;
                }
            }
            
            if (!accessTokenFound) {
                ctl_group_item*gnode = NULL, *gnext = NULL;
                list_for_each_entry_safe(gnode, gnext, &lst->lst_ctl_group, lst, ctl_group_item) {
                    COAP_DEBUG("node:%s", gnode->accessKey);
                    if (strncmp(gnode->accessKey, accessKey, keylen) == 0){
                        accessTokenFound = gnode->accessKey;
                        break;
                    }
                }
            }

            HAL_MutexUnlock(dev_lst->list_mutex);

            if (accessTokenFound) {
                ctl_key_item item;
                item.deviceName = auth_param->deviceName;
                item.productKey = auth_param->productKey;

                item.accessKey = accessKey;
                item.accessToken = accessTokenFound;
                char back;
                backup_json_str_last_char (accessKey, keylen, back);
                do_auth (ctx, remote, &item, auth_param->user_data, auth_param->handler);
                restore_json_str_last_char (accessKey, keylen, back);

                coap_free (auth_param->productKey);
                coap_free (auth_param->deviceName);
                coap_free (auth_param);
                return;
            }
        } while (0);

        //todo
        ResponseMsg tmp = {-1, ""};
        auth_param->handler (ctx, remote, auth_param->user_data, &tmp);
        coap_free (auth_param->productKey);
        coap_free (auth_param->deviceName);
        coap_free (auth_param);

    }
}

static int CoAPServerPath_2_option(char *uri, CoAPMessage *message)
{
    char *ptr     = NULL;
    char *pstr    = NULL;
    char  path[COAP_MSG_MAX_PATH_LEN]  = {0};

    if (NULL == uri || NULL == message) {
        COAP_ERR("Invalid paramter p_path %p, p_message %p", uri, message);
        return ALCS_ERR_INVALID_PARAM;
    }
    if (256 < strlen(uri)) {
        COAP_ERR("The uri length is too loog,len = %d", (int)strlen(uri));
        return ALCS_ERR_INVALID_LENGTH;
    }
    COAP_DEBUG("The uri is %s", uri);
    ptr = pstr = uri;
    while ('\0' != *ptr) {
        if ('/' == *ptr) {
            if (ptr != pstr) {
                memset(path, 0x00, sizeof(path));
                strncpy(path, pstr, ptr - pstr);
                COAP_DEBUG("path: %s,len=%d", path, (int)(ptr - pstr));
                CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                                  (unsigned char *)path, (int)strlen(path));
            }
            pstr = ptr + 1;

        }
        if ('\0' == *(ptr + 1) && '\0' != *pstr) {
            memset(path, 0x00, sizeof(path));
            strncpy(path, pstr, sizeof(path) - 1);
            COAP_DEBUG("path: %s,len=%d", path, (int)strlen(path));
            CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                              (unsigned char *)path, (int)strlen(path));
        }
        ptr ++;
    }
    return ALCS_SUCCESS;
}

void  auth_cb(CoAPContext *ctx, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
    AlcsDeviceKey devKey;
    COAP_DEBUG("recv auth_cb response message");

    AuthParam* auth_param = (AuthParam*)userdata;
    memset(&devKey, 0x00, sizeof(AlcsDeviceKey));
    memcpy (&devKey.addr, remote, sizeof(NetworkAddr));
    devKey.pk = auth_param->productKey;
    devKey.dn = auth_param->deviceName;
    session_item* session = get_ctl_session (ctx, &devKey);

    if (!session) {
        COAP_INFO ("receive unknown auth_cb response, pk:%s, dn:%s", devKey.pk, devKey.dn);
        ResponseMsg msg = {ALCS_ERR_INTERNAL, "no session found!"};
        auth_param->handler (ctx, remote, auth_param->user_data, &msg);
    } else if (COAP_RECV_RESP_TIMEOUT == result){
        COAP_ERR("response time!");
        ResponseMsg msg = {ALCS_AUTH_TIMEOUT, "response time!"};
        auth_param->handler (ctx, remote, auth_param->user_data, &msg);
        remove_session_safe (ctx, session);
    } else {
        int seq, datalen = 0;
        ResponseMsg msg = {0};
        char* data = NULL;

        res_parse ((const char *)message->payload, message->payloadlen, &seq, &msg, &data, &datalen);
        if (msg.code == 200) {
            do {
                int tmplen, signlen;
                char* tmp, *sign;
                char back;

                tmp = alcs_json_get_value_by_name(data, datalen, "opt", &tmplen, NULL);
                if (tmp) {
                    backup_json_str_last_char (tmp, tmplen, back);
                    session->opt = atoi (tmp);
                    restore_json_str_last_char (tmp, tmplen, back);
                    COAP_DEBUG ("opt:%d", session->opt);
                } else {
                    session->opt = 0;
                }

                tmp = alcs_json_get_value_by_name(data, datalen, "seqStart", &tmplen, NULL);
                if (tmp) {
                    backup_json_str_last_char (tmp, tmplen, back);
                    session->seqStart = atoi (tmp);
                    restore_json_str_last_char (tmp, tmplen, back);
                    COAP_DEBUG ("seqstart:%d", session->seqStart);
                } else {
                    session->seqStart = 0;
                }


                tmp = alcs_json_get_value_by_name(data, datalen, "sessionId", &tmplen, NULL);
                if (!tmp) {
                    msg.code = ALCS_ERR_INTERNAL;
                    msg.msg = "sessionid = NULL!";
                    COAP_ERR ("sessionid = NULL!");
                    break;
                }

                backup_json_str_last_char (tmp, tmplen, back);
                session->sessionId = atoi (tmp);
                restore_json_str_last_char (tmp, tmplen, back);
                COAP_INFO ("sessionId:%d", session->sessionId);

                tmp = alcs_json_get_value_by_name(data, datalen, "randomKey", &tmplen, NULL);
                if (!tmp) {
                    msg.code = ALCS_ERR_INTERNAL; 
                    msg.msg = "randomKey = NULL!";
                    COAP_ERR ("randomKey = NULL!");
                    break;
                }

                /*calc sign, save in buf*/
                char buf[40];
                int calc_sign_len = sizeof(buf);

                backup_json_str_last_char (tmp, tmplen, back);
                utils_hmac_sha1_base64 (tmp, tmplen + 1, auth_param->accessToken, strlen(auth_param->accessToken),
                    buf, &calc_sign_len);
                restore_json_str_last_char (tmp, tmplen, back);

                sign = alcs_json_get_value_by_name(data, datalen, "sign", &signlen, NULL);
                if (!sign || signlen != calc_sign_len || strncmp(sign, buf, calc_sign_len)) {
                    msg.code = ALCS_ERR_INTERNAL;
                    msg.msg = "sign isnot match!";
                    COAP_ERR ("msg: %s",msg.msg);
                    auth_param->handler (ctx, remote, auth_param->user_data, &msg);
                    break;
                }

                HAL_Snprintf (buf, sizeof(buf), "%s%.*s", session->randomKey, tmplen, tmp);
                utils_hmac_sha1_raw (buf,strlen(buf), session->sessionKey, auth_param->accessToken, strlen(auth_param->accessToken));
                session->authedTime = HAL_UptimeMs ();
                session->heartSendTime = session->heartRecTime = session->dataRecTime = session->authedTime;
                session->heartInterval = default_heart_interval;
                COAP_INFO("sessionKey is created");

            } while (0);
        } else {
            remove_session_safe (ctx, session);
            COAP_ERR("message code :%d", msg.code);
        }
        auth_param->handler (ctx, remote, auth_param->user_data, &msg);
    }

    coap_free (auth_param->productKey);
    coap_free (auth_param->deviceName);
    coap_free (auth_param->accessToken);
    coap_free (auth_param);
}

#define auth_payload_format "{\"version\":\"1.0\",\"method\":\"core/service/auth\",\"id\":%d,\"params\":{\"prodKey\":\"%s\", \"deviceName\":\"%s\",\"encrypt\":\"payload\",\"randomKey\":\"%s\",\"sign\":\"%s\",\"accessKey\":\"%s\", \"opt\":%d}}"

int do_auth (CoAPContext *ctx, NetworkAddr* addr, ctl_key_item* ctl_item, void *user_data, AuthHandler handler)
{
    int ret = ALCS_SUCCESS;
    AlcsDeviceKey devKey;
    device_auth_list* dev = get_device (ctx);
    if (!dev) {
        return ALCS_ERR_INVALID_PARAM;
    }

    memset(&devKey, 0x00, sizeof(AlcsDeviceKey));
    memcpy (&devKey.addr, addr, sizeof(NetworkAddr));
    devKey.pk = ctl_item->productKey;
    devKey.dn = ctl_item->deviceName; 

    session_item* session = get_ctl_session (ctx, &devKey);
    if (session) {
        if (session->sessionId) {
            COAP_INFO ("no need to reauth!");
            ResponseMsg res = {ALCS_SUCCESS, NULL};
            handler (ctx, addr, user_data, &res);
            return ALCS_SUCCESS;
        } else {
           COAP_INFO ("is authing, no need to reauth!");
           return ALCS_ERR_AUTH_AUTHING;
        }
    }

    //create&save session item
    {
        session = (session_item*)coap_malloc(sizeof(session_item));
        memset (session, 0, sizeof(session_item));
 
        char path[120] = {0};
        strncpy(path, ctl_item->productKey, sizeof(path) - 1);
        strncat(path, ctl_item->deviceName, sizeof(path)-strlen(path)-1);
        CoAPPathMD5_sum (path, strlen(path), session->pk_dn, PK_DN_CHECKSUM_LEN);
        COAP_INFO ("pk:%s, dn:%s", devKey.pk, devKey.dn); 
        memcpy (&session->addr, addr, sizeof(NetworkAddr));
        gen_random_key((unsigned char *)session->randomKey, RANDOMKEY_LEN);

        struct list_head *ctl_head = get_ctl_session_list (ctx);
        HAL_MutexLock(dev->list_mutex);
        list_add_tail(&session->lst, ctl_head);
        HAL_MutexUnlock(dev->list_mutex);
    }

    char sign[64]={0};
    int sign_len = sizeof(sign);
    if (ctl_item->accessToken == NULL) {
        COAP_INFO ("accessToken is null, return err!");
        return ALCS_ERR_AUTH_AUTHING;
    }
    utils_hmac_sha1_base64(session->randomKey, strlen(session->randomKey), ctl_item->accessToken,
        strlen(ctl_item->accessToken), sign, &sign_len);
    COAP_DEBUG ("calc randomKey:%s, sign:%.*s", session->randomKey, sign_len, sign);

    char payloadbuf[512];
    sprintf (payloadbuf, auth_payload_format, ++dev->seq, ctl_item->productKey, ctl_item->deviceName, session->randomKey,
        sign, ctl_item->accessKey, ALCS_OPT_HEART_V1 | ALCS_OPT_SUPPORT_SEQWINDOWS | ALCS_OPT_PAYLOAD_CHECKSUM);
    COAP_DEBUG("payload:%s", payloadbuf);

    CoAPLenString payload;
    payload.data = (unsigned char *)payloadbuf;
    payload.len = strlen(payloadbuf);
    CoAPMessage message;
    alcs_msg_init (ctx, &message, COAP_MSG_CODE_GET, COAP_MESSAGE_TYPE_CON, 0, &payload, NULL);

    char path[120];
    sprintf (path, "/dev/%s/%s/core/service/auth", ctl_item->productKey, ctl_item->deviceName);
    CoAPServerPath_2_option (path, &message);

    AuthParam* authParam = (AuthParam*) coap_malloc (sizeof(AuthParam));
    authParam->handler = handler;
    authParam->user_data = user_data;
    authParam->productKey = (char*) coap_malloc (strlen(ctl_item->productKey) + 1);
    strcpy (authParam->productKey, ctl_item->productKey);
    authParam->deviceName = (char*) coap_malloc (strlen(ctl_item->deviceName) + 1);
    strcpy (authParam->deviceName, ctl_item->deviceName);
    authParam->accessToken = (char*) coap_malloc (strlen(ctl_item->accessToken) + 1);
    strcpy (authParam->accessToken, ctl_item->accessToken);
    message.user = authParam;
    message.handler = auth_cb;

    ret = CoAPMessage_send (ctx, addr, &message);
    CoAPMessage_destory(&message);
    return ret == COAP_SUCCESS? ALCS_SUCCESS : ret;
}

int alcs_auth_has_key (CoAPContext *ctx, NetworkAddr* addr, AuthParam* auth_param)
{
    ctl_key_item item;
    item.accessKey = auth_param->accessKey;
    item.deviceName = auth_param->deviceName;
    item.productKey = auth_param->productKey;
    item.accessToken = auth_param->accessToken;//(char*) coap_malloc (strlen(auth_param->accessToken) + 1);
    //strcpy (item.accessToken, auth_param->accessToken);
    return do_auth (ctx, addr, &item, auth_param->user_data, auth_param->handler);
}

int alcs_auth_nego_key (CoAPContext *ctx, AlcsDeviceKey* devKey, AuthHandler handler)
{
    COAP_DEBUG ("alcs_auth_nego_key");

    device_auth_list* dev = get_device (ctx);
    if (!dev) {
        COAP_INFO ("no device!");
        return ALCS_ERR_INVALID_PARAM;
    }

    char accesskeys[1024] = {0};
    if (!fillAccessKey (ctx, accesskeys)) {
        COAP_INFO ("no ctl key!");
        return ALCS_ERR_AUTH_NOCTLKEY;
    }
    COAP_DEBUG ("accesskeys:%s", accesskeys);

    const char* method = "core/service/auth/select";
    char payloadbuf[1024];
    sprintf (payloadbuf, payload_format, method, ++dev->seq, devKey->pk, devKey->dn, accesskeys);

    CoAPLenString payload;
    payload.data = (unsigned char *)payloadbuf;
    payload.len = strlen(payloadbuf);
    CoAPMessage message;
    alcs_msg_init (ctx, &message, COAP_MSG_CODE_GET, COAP_MESSAGE_TYPE_CON, 0, &payload, NULL);

    char path[120];
    sprintf (path, "/dev/%s/%s/core/service/auth/select", devKey->pk, devKey->dn);
    CoAPServerPath_2_option (path, &message);

    AuthParam* authParam = (AuthParam*) coap_malloc (sizeof(AuthParam));
    memset (authParam, 0, sizeof(AuthParam));

    authParam->handler = handler;
    authParam->productKey = (char*) coap_malloc (strlen(devKey->pk) + 1);
    strcpy (authParam->productKey, devKey->pk);
    authParam->deviceName = (char*) coap_malloc (strlen(devKey->dn) + 1);
    strcpy (authParam->deviceName, devKey->dn);

    message.user = authParam;
    message.handler = nego_cb;
    int ret = CoAPMessage_send (ctx, &devKey->addr, &message);
    CoAPMessage_destory(&message);
    return ret == COAP_SUCCESS? ALCS_SUCCESS : ret;
}

void alcs_auth_disconnect (CoAPContext *ctx, AlcsDeviceKey* devKey)
{
    char path[120] = {0};
    char pk_dn[PK_DN_CHECKSUM_LEN + 1];

    struct list_head* ctl_head = get_ctl_session_list (ctx);
    if (!ctl_head || list_empty(ctl_head)) {
        COAP_INFO ("alcs_auth_disconnect, ctl not found");
        return;
    }

    strncpy(path, devKey->pk, sizeof(path) - 1);
    strncat(path, devKey->dn, sizeof(path)-strlen(path)-1);
    CoAPPathMD5_sum (path, strlen(path), pk_dn, PK_DN_CHECKSUM_LEN);

    session_item *node = NULL, *next = NULL;
    list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {
        if (is_networkadd_same(&node->addr, &devKey->addr) && memcmp (node->pk_dn, pk_dn, PK_DN_CHECKSUM_LEN) == 0) {
            remove_session (ctx, node);
        }
    }
}

int alcs_add_client_key(CoAPContext *ctx, const char* accesskey, const char* accesstoken, const char* productKey, const char* deviceName)
{

    device_auth_list *dev_lst = get_device (ctx);
    auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;

    if (!lst || lst->ctl_count >= ALCS_MAX_CLIENT_COUNT) {
        return ALCS_ERR_INVALID_LENGTH;
    }

    ctl_key_item* item = (ctl_key_item*) coap_malloc(sizeof(ctl_key_item));
    if (!item) {
        return ALCS_ERR_MALLOC;
    }
    item->accessKey = (char*) coap_malloc(strlen(accesskey) + 1);
    item->accessToken = (char*) coap_malloc(strlen(accesstoken) + 1);

    if (!item->accessKey || !item->accessToken) {
        coap_free (item);
        return ALCS_ERR_MALLOC;
    }
    strcpy (item->accessKey, accesskey);
    strcpy (item->accessToken, accesstoken);

    if (deviceName) {
         item->deviceName = (char*) coap_malloc(strlen(deviceName) + 1);
         strcpy (item->deviceName, deviceName);
    }

    HAL_MutexLock(dev_lst->list_mutex);
    list_add_tail(&item->lst, &lst->lst_ctl);
    ++lst->ctl_count;
    HAL_MutexUnlock(dev_lst->list_mutex);

    return ALCS_SUCCESS;
}

int alcs_remove_client_key (CoAPContext *ctx, const char* key, char isfullkey)
{
    device_auth_list *dev_lst = get_device (ctx);
    auth_list *lst = dev_lst ? &dev_lst->lst_auth : NULL;
    if (!lst) {
        return ALCS_ERR_NULL;
    }

    ctl_key_item *node = NULL, *next = NULL;
    HAL_MutexLock(dev_lst->list_mutex);

    list_for_each_entry_safe(node, next, &lst->lst_ctl, lst, ctl_key_item) {
        if(match_key(node->accessKey, key)){
            coap_free(node->accessKey);
            coap_free(node->accessToken);
            list_del(&node->lst);
            coap_free(node);
            break;
        }
    }
    HAL_MutexUnlock(dev_lst->list_mutex);
    return ALCS_SUCCESS;
}

bool alcs_device_online (CoAPContext *ctx, AlcsDeviceKey* devKey)
{
    session_item* session = get_ctl_session (ctx, devKey);
    return session && session->sessionId? 1 : 0;
}

disconnect_notify disconnect_func = NULL;
void alcs_client_disconnect_notify (disconnect_notify func)
{
    disconnect_func = func;
}

void heart_beat_cb(CoAPContext *ctx, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
    COAP_DEBUG ("heart_beat_cb, message addr:%p, networkaddr:%p, result:%d!", message, remote, result);

    struct list_head* ctl_head = get_ctl_session_list (ctx);
    if (!ctl_head || list_empty(ctl_head)) {
        return;
    }

    device_auth_list *dev_lst = get_device (ctx);
    int tick = HAL_UptimeMs();

    if (result == COAP_RECV_RESP_TIMEOUT) {
        COAP_ERR ("heart beat timeout");
        session_item *node = NULL, *next = NULL;
        HAL_MutexLock(dev_lst->list_mutex);
        list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {
            if (node->sessionId && is_networkadd_same(&node->addr, remote) &&
                    node->dataRecTime + node->heartInterval < tick)
            {
                remove_session (ctx, node);
                if (disconnect_func) {
                    disconnect_func (node->pk_dn);
                }
            }
        }
        HAL_MutexUnlock(dev_lst->list_mutex);

    } else {
        int datalen = 0;
        char *data = NULL;
        char* devices = NULL;
        int deviceslen = 0;
        data = alcs_json_get_value_by_name((char*)message->payload, message->payloadlen, "data", &datalen, NULL);
        devices = alcs_json_get_value_by_name(data, datalen, "devices", &deviceslen, NULL);
        
        session_item *node = NULL, *next = NULL;
        HAL_MutexLock(dev_lst->list_mutex);
        list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {

            if(node->sessionId && is_networkadd_same(&node->addr, remote)) {
                if (node->opt & ALCS_OPT_HEART_V1) {
                    COAP_DEBUG ("new heart mode");
                    unsigned int outlen;
                    char calc[9] = {0};
                    if (devices && deviceslen) {
                        utils_base64encode ((const uint8_t *)node->pk_dn, PK_DN_CHECKSUM_LEN, sizeof(calc), (unsigned char*)calc, &outlen);
                        int i;
                        for (i = 0; i < deviceslen / 8; ++i) {
                            COAP_DEBUG ("loop:%d, data:%s", i, devices);
                            if (memcmp (devices + i * 8, calc, 8) == 0) {
                                //find
                                node->heartRecTime= HAL_UptimeMs();
                                COAP_DEBUG ("renew heart time");
                                break;
                            }
                        }
                    }
                } else {
                    node->heartRecTime = HAL_UptimeMs();
                }
            }
        }
        HAL_MutexUnlock(dev_lst->list_mutex);
    }
}

static void do_send_heartdata (CoAPContext* ctx, CoAPLenString* payload, NetworkAddr* addr)
{
    int rt;
    CoAPMessage message;
    alcs_msg_init (ctx, &message, COAP_MSG_CODE_GET, COAP_MESSAGE_TYPE_CON, 0, payload, NULL);
    CoAPServerPath_2_option ("/dev/core/service/heartBeat", &message);
    message.handler = heart_beat_cb;
    rt = CoAPMessage_send_ex (ctx, addr, &message, 7);

    if (rt == ALCS_SUCCESS) {
        COAP_DEBUG ("send heartbeat to :%s", addr->addr);
    } else {
        COAP_INFO ("fail to send heartbeat to :%s", addr->addr);
        heart_beat_cb (ctx, COAP_RECV_RESP_TIMEOUT, NULL, addr, &message);
    }

    CoAPMessage_destory(&message);
}

static void add_tmp_node (struct list_head* head, session_item* new_node)
{
    COAP_DEBUG ("add_tmp_node");

    session_item *node = NULL, *next = NULL;
    list_for_each_entry_safe(node, next, head, tmplst, session_item) {
        if (is_networkadd_same(&node->addr, &new_node->addr)) {
            return;
        }
    }

    list_add (&new_node->tmplst, head);
}

void on_client_auth_timer (CoAPContext* ctx)
{
    device_auth_list* dev = get_device (ctx);
    if (!dev->is_inited) {
        return;
    }

    struct list_head* ctl_head = get_ctl_session_list (ctx);
    if (!ctl_head || list_empty(ctl_head)) {
        return;
    }
    //COAP_DEBUG ("on_client_auth_timer");

    char payloadbuf[64];
    sprintf (payloadbuf, "{\"id\":%d,\"version\":\"1.0\",\"params\":{}}", ++dev->seq);

    CoAPLenString payload;
    payload.data = (unsigned char *)payloadbuf;
    payload.len = strlen(payloadbuf);
    int tick = HAL_UptimeMs();

    struct list_head tmp_head;
    INIT_LIST_HEAD (&tmp_head); 
    session_item *node = NULL, *next = NULL;
    device_auth_list *dev_lst = get_device (ctx);
    HAL_MutexLock(dev_lst->list_mutex);
    list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {
        if (!node->sessionId || node->heartRecTime + node->heartInterval > tick ||
            node->heartSendTime + node->heartInterval > tick)
        {
            continue;
        }

        if (node->opt & ALCS_OPT_HEART_V1) {
            add_tmp_node (&tmp_head, node);
        } else {
            do_send_heartdata (ctx, &payload, &node->addr);
            node->heartSendTime = tick;
        }
    }

    HAL_MutexUnlock(dev_lst->list_mutex);

    list_for_each_entry_safe(node, next, &tmp_head, tmplst, session_item) {
        COAP_DEBUG ("send gateway heartbeat");
        do_send_heartdata (ctx, &payload, &node->addr);
        node->heartSendTime = tick;
    }
}

#endif


