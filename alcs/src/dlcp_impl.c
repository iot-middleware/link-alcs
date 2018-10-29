#include <time.h>
#include "alcs_api.h"
#include "alcs_coap.h"
#include "utils_hmac.h"
#include "alcs_export_st.h"
#include "alcs_export_st_ali.h"
#include "linked_list.h"
#include "CoAPPlatform.h"
#include "json_parser.h"
#include "alcs_export_dlcp.h"
#include "alcs_export.h"
#include "alcs_export_server.h"

const char* KEY_AC = "key_authcode";
const char* KEY_AS = "key_authsecret";
char* DEFAULT_AC = "Xtau@iot";
char* DEFAULT_AS = "Yx3DdsyetbSezlvc";

static dlcp_receiver receiver_func = NULL;
void dlcp_set_receiver (dlcp_receiver receiver)
{
    receiver_func = receiver;
}

void alcs_service_cb_dev (alcs_service_cb_param_pt cb_param)
{
    alcs_rsp_msg_param_t rsp_msg;
    alcs_rsp_msg_param_option_t option;
    char pk[PRODUCT_KEY_MAXLEN];
    char dn[DEVICE_ID_MAXLEN];
    char payload[200];
    char  ip_addr[24];
    char* id;
    int idlen;
    
    COAP_DEBUG ("alcs_service_cb_dev");

    if (!cb_param || !cb_param->payload || !cb_param->payload_len) {
        COAP_ERR ("alcs_service_cb_dev, invalid params");
        HAL_Snprintf (payload, sizeof(payload), "{\"code\":400,\"msg\":\"Payload is empty\"}");
    } else{
        id = alcs_json_get_value_by_name((char*)cb_param->payload, cb_param->payload_len, "id", &idlen, (int*)NULL);
    
        HAL_GetProductModel(pk);
        HAL_GetDeviceID(dn);
        HAL_Wifi_Get_IP (ip_addr, NULL);
        HAL_Snprintf(payload, sizeof(payload), "{\"id\":\"%.*s\",\"version\":\"1.0\", \"code\":200,\"data\":{\"deviceModel\":{\"profile\":{\"pal\":\"dlcp-raw\",\"productKey\":\"%s\",\"deviceName\":\"%s\",\"addr\":\"%s\",\"port\":5683}}}}", idlen, id? id : "", pk, dn, ip_addr);
    }

    option.msg_code = ALCS_MSG_CODE_205_CONTENT;
    option.msg_type = ALCS_MSG_TYPE_CON;
    rsp_msg.payload = (unsigned char*)payload;
    rsp_msg.payload_len = strlen(payload);
    rsp_msg.msg_option = &option;
    iot_alcs_send_rsp(&rsp_msg, cb_param? cb_param->cb_ctx : NULL);
}

void alcs_service_cb_setup (alcs_service_cb_param_pt cb_param)
{
    alcs_rsp_msg_param_t rsp_msg;
    alcs_rsp_msg_param_option_t option;
    char payload[128];
    char* id = NULL, *p;
    int idlen = 0, len, authcodelen, authsecretlen;
    char* authcode = NULL, *authsecret = NULL;
    bool success = 0;
    char* err_msg = NULL;
    char ac[9];
    char configValueBack;
    char *str_pos, *entry;
    int entry_len, type;
    alcs_svr_auth_param_t auth_param;

    COAP_DEBUG ("alcs_service_cb_setup");
    do {
        if (!cb_param || !cb_param->payload || !cb_param->payload_len) {
            err_msg = "invalid package";
            break;
        }
    
        id = alcs_json_get_value_by_name((char*)cb_param->payload, cb_param->payload_len, "id", &idlen, (int*)NULL);
        p = alcs_json_get_value_by_name((char*)cb_param->payload, cb_param->payload_len, "params", &len, (int*)NULL);
        if (!p || !len) {
            err_msg = "params is not found";
            break;
        }

        p = alcs_json_get_value_by_name(p, len, "configValue", &len, (int*)NULL);
        if (!p || !len) {
            err_msg = "configValue is not found";
            break;
        }

        backup_json_str_last_char (p, len, configValueBack);

        json_array_for_each_entry(p, len, str_pos, entry, entry_len, type) {
            COAP_DEBUG ("entry:%.*s", entry_len, entry);
            authcode = alcs_json_get_value_by_name(entry, entry_len, "authCode", &authcodelen, (int*)NULL);
            authsecret = alcs_json_get_value_by_name(entry, entry_len, "authSecret", &authsecretlen, (int*)NULL);
            break;
        } //end json_array_for_each_entry
        restore_json_str_last_char (p, len, configValueBack);
    
        if (!authcode || !authcodelen || !authsecret || !authsecretlen) {
            err_msg = "authinfo is not found";
            break;
        }

        //save
        memset (&auth_param, 0, sizeof(alcs_svr_auth_param_t));

        len = sizeof(ac);
        if (!HAL_Kv_Get (KEY_AC, ac, &len)) {
            auth_param.ac = DEFAULT_AC;
            auth_param.ac_len = strlen(auth_param.ac);
        } else {
            auth_param.ac = ac;
            auth_param.ac_len = len;
        }
        iot_alcs_remove_authkey (&auth_param);

        auth_param.ac = authcode;
        auth_param.as = authsecret;
        auth_param.ac_len = authcodelen;
        auth_param.as_len = authsecretlen;
        iot_alcs_add_and_update_authkey(&auth_param);
        
        COAP_DEBUG ("new ac:%.*s, as:%.*s", auth_param.ac_len, auth_param.ac, auth_param.as_len, auth_param.as);
        HAL_Kv_Set (KEY_AC, auth_param.ac, auth_param.ac_len);
        HAL_Kv_Set (KEY_AS, auth_param.as, auth_param.as_len);

        success = 1;
        
    } while (0);

    if (success) {
        HAL_Snprintf(payload, sizeof(payload), "{\"id\":\"%.*s\",\"code\":200}", idlen, id? id : "");
    } else {
        HAL_Snprintf(payload, sizeof(payload), "{\"id\":\"%.*s\",\"code\":400,\"msg\":\"%s\"}", idlen, id? id : "", err_msg);
        COAP_ERR ("alcs_service_cb_setup, %s", err_msg);
    }

    option.msg_code = ALCS_MSG_CODE_205_CONTENT;
    option.msg_type = ALCS_MSG_TYPE_CON; 
    rsp_msg.payload = (uint8_t*)payload;
    rsp_msg.payload_len = strlen(payload);
    rsp_msg.msg_option = &option;
    iot_alcs_send_rsp(&rsp_msg, cb_param? cb_param->cb_ctx : NULL);
}

void alcs_service_cb_up (alcs_service_cb_param_pt cb_param)
{
    char* id = NULL;
    int idlen = 0;
    alcs_rsp_msg_param_t rsp_msg;
    alcs_rsp_msg_param_option_t option;
    char payload[64];

    if (!cb_param) {
        return;
    }

    if (cb_param->payload && cb_param->payload_len) {
        id = alcs_json_get_value_by_name((char*)cb_param->payload, cb_param->payload_len, "id", &idlen, (int*)NULL);
    }
    HAL_Snprintf(payload, sizeof(payload), "{\"id\":\"%.*s\",\"code\":200}", idlen, id? id : "");

    option.msg_code = ALCS_MSG_CODE_205_CONTENT;
    option.msg_type = ALCS_MSG_TYPE_CON;
    rsp_msg.payload = (uint8_t*)payload;
    rsp_msg.payload_len = strlen(payload);
    rsp_msg.msg_option = &option;
    iot_alcs_send_rsp(&rsp_msg, cb_param->cb_ctx);
}

void alcs_service_cb_down (alcs_service_cb_param_pt cb_param)
{
    if (!cb_param|| !receiver_func) {
        return;
    }

    receiver_func ((char*)cb_param->payload, cb_param->payload_len, cb_param->cb_ctx);
}

int dlcp_init (void)
{
    char pk[PRODUCT_KEY_MAXLEN];
    char dn[DEVICE_ID_MAXLEN];
    char buf1[120];
    char buf2[9];
    int rt, len1, len2;
    alcs_svr_auth_param_t auth_param;
    alcs_service_param_t service;

    if (HAL_GetProductModel(pk) <= 0 || HAL_GetDeviceID(dn) <= 0) {
        return DLCP_PKDNEMPTY;
    }
    if (iot_alcs_init (pk, dn, ALCS_ROLE_SERVER) != ALCS_RESULT_OK) {
        return DLCP_FAIL;
    }
    service.service = "/dev/core/service/dev";
    service.pk = pk;
    service.dn = dn;
    service.perm = ALCS_MSG_PERM_GET;
    service.content_type = ALCS_MSG_CT_APP_JSON;
    service.maxage = 60;
    service.user_data = NULL;
    service.secure = 0;
    rt = iot_alcs_register_service (&service, alcs_service_cb_dev); 

    HAL_Snprintf(buf1, sizeof(buf1), "/dev/%s/%s/core/service/setup", pk, dn);
    service.service = buf1;
    service.perm = ALCS_MSG_PERM_PUT;
    service.secure = 1;
    rt = iot_alcs_register_service (&service, alcs_service_cb_setup);  

    HAL_Snprintf(buf1, sizeof(buf1), "/sys/%s/%s/thing/model/down_raw", pk, dn);
    service.service = buf1;
    service.perm = ALCS_MSG_PERM_PUT | ALCS_MSG_PERM_GET;
    rt = iot_alcs_register_service (&service, alcs_service_cb_down); 

    HAL_Snprintf(buf1, sizeof(buf1), "/sys/%s/%s/thing/model/up_raw", pk, dn);
    service.perm = ALCS_MSG_PERM_GET;
    service.service = buf1;

    rt = iot_alcs_register_service (&service, alcs_service_cb_up);

    memset (&auth_param, 0, sizeof(alcs_svr_auth_param_t));

    len1 = 120;
    len2 = 9;
    if (HAL_Kv_Get (KEY_AC, buf2, &len2) >= 0 && HAL_Kv_Get (KEY_AS, buf1, &len1) >= 0) {
        auth_param.ac = buf2;
        auth_param.ac_len = len2;
        auth_param.as = buf1;
        auth_param.as_len = len1;
    } else {
        auth_param.ac = DEFAULT_AC;
        auth_param.ac_len = strlen(auth_param.ac);
        auth_param.as = DEFAULT_AS;
        auth_param.as_len = strlen(auth_param.as);
    }
    COAP_DEBUG ("use ac:%s, as:%s", auth_param.ac, auth_param.as);
    iot_alcs_add_and_update_authkey(&auth_param);

    return rt;
}

void dlcp_deinit(void)
{
   iot_alcs_deinit (); 
}

int dlcp_sendrsp (const char* data, int len, void* ctx)
{
    alcs_rsp_msg_param_t rsp_msg;
    alcs_rsp_msg_param_option_t option;

    rsp_msg.payload = (uint8_t*)data;
    rsp_msg.payload_len = len;
    option.msg_code = ALCS_MSG_CODE_205_CONTENT;
    option.msg_type = ALCS_MSG_TYPE_CON;
    rsp_msg.msg_option = &option;

    return iot_alcs_send_rsp (&rsp_msg, ctx);
}


void dlcp_start_loop ()
{
    iot_alcs_start_loop (1);
}

void dlcp_stop_loop ()
{
    iot_alcs_stop_loop ();
}

int dlcp_upload (const char* data, int len)
{
    char pk[PRODUCT_KEY_MAXLEN];
    char dn[DEVICE_ID_MAXLEN];
    char method[120];
    alcs_notify_param_t notice;

    if (HAL_GetProductModel(pk) <= 0 || HAL_GetDeviceID(dn) <= 0) {
        return DLCP_PKDNEMPTY;
    }

    HAL_Snprintf(method, sizeof(method), "/sys/%s/%s/thing/model/up_raw", pk, dn);

    notice.payload = (uint8_t*)data;
    notice.payload_len = len;
    notice.option = method;
    
    return iot_alcs_send_notify (&notice);
}
