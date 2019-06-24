#include <time.h>
#include "alcs_api.h"
#include "alcs_api_internal.h"
#include "alcs_coap.h"
#include "utils_hmac.h"
#include "alcs_export.h"
#include "alcs_export_st.h"
#include "alcs_export_st_ali.h"
#include "linked_list.h"
#include "CoAPPlatform.h"
#include "CoAPResource.h"
#include "json_parser.h"
#include "alcs_timer.h"
    
#define MAXPK_LEN 32
#define MAXDN_LEN 64
#define PATH_CK_LEN 4

typedef struct inner_send_msg
{
    void* connection;
    alcs_send_msg_cb cb;
    void* user_data;
    unsigned short msg_id;
} inner_send_msg_t, *inner_send_msg_pt;

typedef struct inner_conn_param
{
    char pk[MAXPK_LEN + 1]; 
    char dn[MAXDN_LEN + 1];
    char ck[PK_DN_CHECKSUM_LEN];
    NetworkAddr addr;
    void* user_data;
    alcs_connect_cb conn_cb;
    bool connected;    
} inner_conn_param_t, *inner_conn_param_pt;

typedef struct inner_probe_param
{
    char pk[MAXPK_LEN + 1];
    char dn[MAXDN_LEN + 1];
    void* user_data;
    alcs_probe_cb probe_cb;
} inner_probe_param_t, *inner_probe_param_pt;

typedef struct inner_resource_cb_save
{
    char path_ck[PATH_CK_LEN];
    char* pk;
    char* dn;
    void* user_data;
    char secure;
    alcs_service_cb cb;
} inner_resource_cb_save_t;

typedef struct inner_subcribe_param
{
    char path_ck[PATH_CK_LEN];
    void* connection;
    alcs_send_msg_cb rsp_cb;
    alcs_sub_cb sub_cb;
    void* user_data;
} inner_subcribe_param_t, *inner_subcribe_param_pt;

typedef struct inner_discovery_param
{
    void* discovery_finish_timer;
    void* discovery_timer;
    void* cb;
    linked_list_t* rec_pkdn;
    void* finish_cb;
    inner_send_msg_pt task_info;
} inner_discovery_param_t, *inner_discovery_param_pt;

typedef struct inner_receive_query
{
    unsigned char token[COAP_MSG_MAX_TOKEN_LEN];
    NetworkAddr addr;
    inner_resource_cb_save_t* resource;
    unsigned char tokenlen;
    unsigned char observe; 
} inner_receive_query_t, *inner_receive_query_pt;

typedef struct inner_userdata_item
{
    int item_id;
    void* user_data;
} inner_userdata_item_t, *inner_userdata_item_pt;

static void * g_alcs_mutex = NULL;
static linked_list_t* alcs_conn_list = NULL;
static linked_list_t* alcs_resource_list = NULL;
static linked_list_t* alcs_userdata_list = NULL;
static linked_list_t* alcs_subcribe_list = NULL;
CoAPContext* g_coap_ctx = NULL;
static int g_discovery_id = 0;
static int g_userdata_maxid = 0;
static alcs_disconnect_cb disconnect_cb = NULL; 
static alcs_discovery_cb new_device_online_cb = NULL;

static void convert2alcsnetworkaddr (alcs_network_addr_t* addr1, NetworkAddr* addr2);
static inner_conn_param_pt get_connection (const char* pk, const char* dn);
//static inner_conn_param_pt get_connection_by_addr (NetworkAddr* addr);
static inner_conn_param_pt find_connection (void* data);
static inner_subcribe_param_pt find_subcribe (void* data);
static void disconnect_notify_cb(const char* pk_dn);
static void do_clear_discovery_task (int task_id);
void alcs_rec_device_online (CoAPContext *context, const char *paths, NetworkAddr *remote, CoAPMessage *request);

int iot_alcs_init(const char* pk, const char* dn, alcs_role_t role)
{
    CoAPInitParam param;

    if (g_alcs_mutex) {
        COAP_INFO ("reinit, return");
        return ALCS_RESULT_FAIL; 
    }

    g_alcs_mutex = HAL_MutexCreate();

    param.appdata = NULL;
    param.group = "224.0.1.187";
    param.notifier = NULL;
    param.obs_maxcount = 16;
    param.res_maxcount = 32;
    if (role & ALCS_ROLE_SERVER) {
        param.port = 5683;
    } else {
        srand((unsigned)time(NULL));
        param.port = 5684 + rand() % 50000; 
    }

    param.send_maxcount = 64;
    param.waittime = 2000;

    alcs_init ();

    if (!g_coap_ctx) {
        g_coap_ctx = alcs_context_create(&param);
    }

    if (!g_coap_ctx) {
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }

    alcs_auth_init (g_coap_ctx, pk, dn, role);

    if (role & ALCS_ROLE_SERVER) {
        alcs_resource_list = linked_list_create("alcs resource list", 1);
        if (alcs_resource_list == NULL) {
            return ALCS_RESULT_INSUFFICIENT_MEM;
        }
    }

    COAP_INFO ("iot_alcs_init role:%d",role);
    if (role & ALCS_ROLE_CLIENT) {
        alcs_conn_list = linked_list_create("alcs connection list", 1);
        if (alcs_conn_list == NULL) {
            return ALCS_RESULT_INSUFFICIENT_MEM;
        }

        alcs_subcribe_list = linked_list_create("alcs subcribe list", 1);
        if (alcs_subcribe_list == NULL) {
            return ALCS_RESULT_INSUFFICIENT_MEM;
        }
        alcs_userdata_list = linked_list_create("alcs userdata list", 1);
        if (alcs_userdata_list == NULL) {
            return ALCS_RESULT_INSUFFICIENT_MEM;
        }

        alcs_resource_register (g_coap_ctx, "", "", "/dev/core/service/dev/notify",
             COAP_PERM_GET|COAP_PERM_POST, COAP_CT_APP_JSON, 60, 0, alcs_rec_device_online);
        alcs_client_disconnect_notify (disconnect_notify_cb);

        alcs_timer_init ();
    }

    return ALCS_RESULT_OK;
}

#define del_timer(timer) \
    { \
        if (timer){ \
            alcs_timer_stop (timer);\
            alcs_timer_delete (timer);\
            timer = NULL; \
        } \
    }

static void free_list_handler (void *data, va_list *params)
{
    coap_free (data);
}

#define destory_list(list) \
    if (list) \
    { \
        linked_list_iterator(list, free_list_handler); \
        linked_list_clear (list); \
        linked_list_destroy (list); \
        list = NULL; \
    }    
        
void iot_alcs_deinit(void)
{
    if (!g_alcs_mutex) {
        return;
    }

    HAL_MutexLock(g_alcs_mutex);
    destory_list (alcs_resource_list);
    destory_list (alcs_conn_list);
    destory_list (alcs_subcribe_list);
    destory_list (alcs_userdata_list);
    do_clear_discovery_task (g_discovery_id);
    HAL_MutexUnlock(g_alcs_mutex);

    alcs_timer_deinit ();
    alcs_context_free(g_coap_ctx);
    g_coap_ctx = NULL;
}

static int connection_iterator_pkdn(void* data, va_list *params)
{
    inner_conn_param_pt conn_param = (inner_conn_param_pt)data;

    char* pk;
    char* dn;

    pk = va_arg(*params, char*);
    dn = va_arg(*params, char*);
    if (!conn_param || !pk || !dn) {
        return 0;
    }
    COAP_DEBUG ("connection_iterator_pkdn, pk:%s, dn:%s, list pk:%s, dn:%s", pk, dn, conn_param->pk, conn_param->dn);

    return (strcmp(pk, conn_param->pk) == 0 && strcmp(dn, conn_param->dn) == 0); 
}

/*static int connection_iterator_addr (void* data, va_list *params)
{
    inner_conn_param_pt conn_param = (inner_conn_param_pt)data;

    NetworkAddr* addr;

    addr = va_arg(*params, NetworkAddr*);
    if (!conn_param || !addr) {
        return 0;
    }

    return (memcmp(&conn_param->addr, addr, sizeof(NetworkAddr)) == 0);
}*/

static int connection_iterator_ck (void* data, va_list *params)
{
    inner_conn_param_pt conn_param = (inner_conn_param_pt)data;

    char* ck;

    ck = va_arg(*params, char*);
    if (!conn_param || !ck) {
        return 0;
    }

    return (memcmp(conn_param->ck, ck, PK_DN_CHECKSUM_LEN) == 0);
}

static int userdata_iterator_id (void* data, va_list *params)
{
    inner_userdata_item_pt item = (inner_userdata_item_pt)data;
    int id;
    id = va_arg(*params, int);
    return item? item->item_id == id : 0;
}

static int userdata_iterator (void* data, va_list *params)
{
    inner_userdata_item_pt item = (inner_userdata_item_pt)data;
    void* user_data;
    user_data = va_arg(*params, void*);
    return item? item->user_data == user_data : 0;
}

static int subcribe_iterator_ck (void* data, va_list *params)
{
    inner_subcribe_param_pt sub_param = (inner_subcribe_param_pt)data;

    char* ck;

    ck = va_arg(*params, char*);
    if (!sub_param || !ck) {
        return 0;
    }

    return (memcmp(sub_param->path_ck, ck, PATH_CK_LEN) == 0);
}

static inner_conn_param_pt get_connection (const char* pk, const char* dn)
{
    list_node_t* node = get_list_node (alcs_conn_list, connection_iterator_pkdn, pk, dn);
    COAP_DEBUG ("get_connection, pk:%s, dn:%s", pk, dn);
    return node? (inner_conn_param_pt)node->data : NULL;
}

/*static inner_conn_param_pt get_connection_by_addr (NetworkAddr* addr)
{
    list_node_t* node = get_list_node (alcs_conn_list, connection_iterator_addr, addr);
    return node? (inner_conn_param_pt)node->data : NULL;
}*/

static inner_conn_param_pt get_connection_by_ck (const char* pk_dn)
{
    list_node_t* node = get_list_node (alcs_conn_list, connection_iterator_ck, pk_dn);
    return node? (inner_conn_param_pt)node->data : NULL;
}

static inner_conn_param_pt find_connection (void* data)
{
    if (linked_list_find(alcs_conn_list, data)) {
        return (inner_conn_param_pt)data;
    }
    return NULL;
}

static inner_subcribe_param_pt find_subcribe (void* data)
{
    if (linked_list_find(alcs_subcribe_list, data)) {
        return (inner_subcribe_param_pt)data;
    }
    return NULL;
}

static inner_subcribe_param_pt get_subcribe_by_ck (const char* ck)
{
    list_node_t* node = get_list_node (alcs_subcribe_list, subcribe_iterator_ck, ck);
    return node? (inner_subcribe_param_pt)node->data : NULL;
}

static int add_user_data (void* user_data)
{
    inner_userdata_item_pt item;
    int item_id;
    if (!user_data) {
        return -1;
    }

    item = (inner_userdata_item_pt)coap_malloc(sizeof(inner_userdata_item_t));
    if (!item) {
        COAP_INFO ("no memory to alloc!");
        return -1;
    }

    item_id = item->item_id = ++g_userdata_maxid;
    item->user_data = user_data;
    linked_list_insert (alcs_userdata_list, item);

    return item_id;
}

static void* get_user_data (int id)
{
    list_node_t* node;
    void* user_data = NULL;
    node = get_list_node (alcs_userdata_list, userdata_iterator_id, id);
    if (node) {
        user_data = ((inner_userdata_item_pt)node->data)->user_data;
    }

    return user_data;
}

static int get_user_data_id (void* data)
{
    list_node_t* node;
    int id = 0;

    node = get_list_node (alcs_userdata_list, userdata_iterator, data);
    if (node) {
        id = ((inner_userdata_item_pt)node->data)->item_id;
    }

    return id;
}

static void remove_user_data (int id, int tofree)
{
    COAP_DEBUG ("remove_user_data, id:%d", id);
    list_node_t* node = get_list_node (alcs_userdata_list, userdata_iterator_id, id);
    if (node) {
        if (tofree) {
            coap_free (((inner_userdata_item_pt)node->data)->user_data);
        }
        coap_free (node->data);
        linked_list_remove (alcs_userdata_list, node->data);
    }
}
 
static void auth_cb (CoAPContext *context, NetworkAddr* addr, void* user_data, ResponseMsg* result)
{
    inner_conn_param_pt connection;
    int id  = (int)(intptr_t)user_data;
    alcs_connect_cb conn_cb = NULL;
    alcs_device_key_t devKey;
    void* connect_user_data = NULL;

    HAL_MutexLock(g_alcs_mutex);
    connection = (inner_conn_param_pt)get_user_data (id);    
    if (connection) {
        connect_user_data = connection->user_data;
        devKey.pk = connection->pk;
        devKey.dn = connection->dn;
        convert2alcsnetworkaddr (&devKey.addr, addr);

        if (ALCS_CONN_OK != result->code) {
            linked_list_remove (alcs_conn_list, connection);
            remove_user_data (get_user_data_id(connection), 0);
        } else {
	    connection->connected = 1;
        }

        conn_cb = connection->conn_cb;
    }
    HAL_MutexUnlock(g_alcs_mutex);

    if (conn_cb) {
        conn_cb (&devKey, connect_user_data, result->code, result->msg);
    }

    if (connection && ALCS_CONN_OK != result->code) {
        coap_free (connection);
    }
}

static void noconnect_notify (inner_conn_param_pt connection, alcs_network_addr_pt addr)
{
    alcs_device_key_t devKey;

    if (connection) {
        devKey.pk = connection->pk;
        devKey.dn = connection->dn;
        memcpy(&devKey.addr, addr, sizeof(alcs_network_addr_t));

        connection->conn_cb (&devKey, connection->user_data,
            connection->connected? ALCS_CONN_OK : ALCS_CONN_CONNECTING, "");
    }
}

int iot_alcs_device_connect (alcs_network_addr_pt paddr, alcs_connect_param_pt conn_param)
{
    char path[MAXPK_LEN + MAXDN_LEN + 1] = {0};
    inner_conn_param_t* connection;
    int id;

    COAP_INFO ("iot_alcs_device_connect");

    if (paddr == NULL || conn_param == NULL || conn_param->pk == NULL || conn_param->dn == NULL) {
        return ALCS_RESULT_INVALIDPARAM;
    }
    if (conn_param->conn_cb == NULL) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    HAL_MutexLock(g_alcs_mutex);    
    connection = get_connection(conn_param->pk, conn_param->dn);
    if (connection != NULL) {
        HAL_MutexUnlock(g_alcs_mutex);
        noconnect_notify (connection, paddr);
        return ALCS_RESULT_DUPLICATE;
    }

    connection = (inner_conn_param_t*)coap_malloc(sizeof(inner_conn_param_t)); 
    if (!connection) {
        HAL_MutexUnlock(g_alcs_mutex);
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }

    strncpy (connection->pk, conn_param->pk, MAXPK_LEN);
    strncpy (connection->dn, conn_param->dn, MAXDN_LEN);
    memcpy (connection->addr.addr, paddr->addr, sizeof(connection->addr.addr));
    strncpy (path, conn_param->pk, MAXPK_LEN);
    strncat (path, conn_param->dn, MAXDN_LEN);
    CoAPPathMD5_sum (path, strlen(path), connection->ck, PK_DN_CHECKSUM_LEN);

    connection->addr.port = paddr->port; 
    connection->user_data = conn_param->user_data;
    connection->conn_cb = conn_param->conn_cb;
    connection->connected = 0;

    linked_list_insert (alcs_conn_list, connection);
    id = add_user_data (connection);
    COAP_DEBUG ("createconn, pk:%s,dn:%s, id:%d", connection->pk, connection->dn, id);

    HAL_MutexUnlock(g_alcs_mutex);

    if (conn_param->auth_info) {
        alcs_auth_param_pt auth_info = (alcs_auth_param_pt)conn_param->auth_info;
        AuthParam auth_param;

        auth_param.productKey = conn_param->pk;
        auth_param.deviceName = conn_param->dn;
        auth_param.accessKey = auth_info->ak;
        auth_param.accessToken = auth_info->at;
        auth_param.user_data = (void*)(intptr_t)id;
        auth_param.handler = auth_cb;
        return alcs_auth_has_key (g_coap_ctx, &connection->addr, &auth_param);
    } else {
        AlcsDeviceKey devKey;
        devKey.pk = conn_param->pk;
        devKey.dn = conn_param->dn;
        strncpy (devKey.addr.addr, paddr->addr, sizeof(devKey.addr.addr) - 1);
        devKey.addr.port = paddr->port;
        return alcs_auth_nego_key (g_coap_ctx, &devKey, auth_cb);
    }
}

int iot_alcs_device_disconnect (const char* pk, const char* dn)
{
    inner_conn_param_pt connection;
    AlcsDeviceKey devKey;

    COAP_INFO ("iot_alcs_device_disconnect");

    HAL_MutexLock(g_alcs_mutex);
    connection = get_connection(pk, dn);
    if (!connection) {
        HAL_MutexUnlock(g_alcs_mutex);
        COAP_INFO ("PK&DN is not found!");
        return ALCS_RESULT_NOTFOUND;
    }

    devKey.pk = (char*)pk;
    devKey.dn = (char*)dn;
    memcpy (&devKey.addr, &connection->addr, sizeof(NetworkAddr));

    linked_list_remove (alcs_conn_list, connection);
    remove_user_data (get_user_data_id(connection), 0);
    HAL_MutexUnlock(g_alcs_mutex);

    alcs_auth_disconnect (g_coap_ctx, &devKey);
    coap_free (connection);    
    
    if (disconnect_cb) {
        disconnect_cb (pk, dn);
    }

    return ALCS_RESULT_OK;
}

bool iot_alcs_device_isonline (const char* pk, const char* dn)
{
    inner_conn_param_pt connection;
    AlcsDeviceKey devKey;

    HAL_MutexLock(g_alcs_mutex);
    connection = get_connection(pk, dn);
    if (!connection) {
        HAL_MutexUnlock(g_alcs_mutex);
        return 0;
    }

    devKey.pk = (char*)pk;
    devKey.dn = (char*)dn;
    memcpy (&devKey.addr, &connection->addr, sizeof(NetworkAddr));    
    HAL_MutexUnlock(g_alcs_mutex);

    return alcs_device_online (g_coap_ctx, &devKey);
}

static void disconnect_notify_cb(const char* pk_dn)
{
    inner_conn_param_pt connection;

    HAL_MutexLock(g_alcs_mutex);
    connection = get_connection_by_ck (pk_dn);
    if (!connection) {
        HAL_MutexUnlock(g_alcs_mutex);
        COAP_INFO ("internal error, can't find connection");
        return;
    }

    linked_list_remove (alcs_conn_list, connection);
    remove_user_data (get_user_data_id(connection), 0);
    HAL_MutexUnlock(g_alcs_mutex);

    if (disconnect_cb) {
        disconnect_cb (connection->pk, connection->dn);
    }
    coap_free (connection);
}

static void device_online_notify (alcs_device_discovery_info_pt device, char* data, int len)
{
    int pklen, dnlen;
    COAP_DEBUG ("device_online_notify data:%.*s", len, data);

    device->pk = alcs_json_get_value_by_name(data, len, "productKey", &pklen, (int*)NULL);
    device->dn = alcs_json_get_value_by_name(data, len, "deviceName", &dnlen, (int*)NULL);

    if (device->pk && pklen && device->dn && dnlen) {
        char pkback, dnback;

        backup_json_str_last_char (device->pk, pklen, pkback);
        backup_json_str_last_char (device->dn, dnlen, dnback);
        if (new_device_online_cb) {
            new_device_online_cb (device);
        }
        restore_json_str_last_char (device->pk, pklen, pkback);
        restore_json_str_last_char (device->dn, dnlen, dnback);
    }

}
void alcs_rec_device_online (CoAPContext *context, const char *paths, NetworkAddr *remote, CoAPMessage *request)
{
    alcs_device_discovery_info_t device;
    int paramslen, deviceslen, profilelen, pallen;
    char *params, *devices, *profile, *pal, palback;

    COAP_DEBUG ("alcs_rec_device_online, len:%d, data:%s", request->payloadlen, request->payload);

    convert2alcsnetworkaddr(&device.from, remote);
    params = alcs_json_get_value_by_name((char*)request->payload, request->payloadlen, "params", &paramslen, (int*)NULL);
    if (!params || !paramslen) {
        COAP_DEBUG ("params is not found");
        return;
    }
    
    devices = alcs_json_get_value_by_name((char*)params, paramslen, "devices", &deviceslen, (int*)NULL);
    
    if (!devices || !deviceslen) {
        COAP_DEBUG ("devices is not found");
        return;
    }

    pal = alcs_json_get_value_by_name(devices, deviceslen, "pal", &pallen, (int*)NULL);
    profile = alcs_json_get_value_by_name(devices, deviceslen, "profile", &profilelen, (int*)NULL);
    
    if (pal && pallen) {
        device.pal = pal;
        backup_json_str_last_char (pal, pallen, palback);
    } else {//default
        device.pal = "linkkit-ica";
    }
    
    if (profile && profilelen) {
        char profileback;
        char *str_pos, *entry;
        int entry_len, type;

        backup_json_str_last_char (profile, profilelen, profileback);
        json_array_for_each_entry(profile, profilelen, str_pos, entry, entry_len, type) {
            device_online_notify (&device, entry, entry_len);
        } //end json_array_for_each_entry
        restore_json_str_last_char (profile, profilelen, profileback);
    } //end if (profile && profilelen)

    if (pal && pallen) {
        restore_json_str_last_char (pal, pallen, palback);
    }
}

void iot_alcs_set_disconnect_listener (alcs_disconnect_cb cb)
{
    disconnect_cb = cb;
}

static void do_send_msg_cb (CoAPContext *context,
                        CoAPReqResult result,
                        void *userdata,
                        NetworkAddr *remote,
                        CoAPMessage *message)
{
    int id = (int)(intptr_t)userdata;
    inner_send_msg_t *send_msg;
    alcs_msg_result_t msg_result = {0};
    inner_conn_param_pt connection;
    alcs_send_msg_cb cb = NULL;
 
    if (userdata == NULL || remote == NULL) {
        COAP_DEBUG ("do_send_msg_cb, param is NULL!");
        return;
    }

    convert2alcsnetworkaddr(&msg_result.addr, remote);
    switch (result) {
        case COAP_REQUEST_SUCCESS: {
            CoAPMessageCode code;
            if (message == NULL) {
                COAP_ERR ("do_send_msg_cb, message is NULL!");
                return;
            }

            if (CoAPMessageCode_get (message, &code) == ALCS_SUCCESS &&
                code >= COAP_MSG_CODE_201_CREATED && code <= COAP_MSG_CODE_231_CONTINUE)
            {
                msg_result.result_code = ALCS_SEND_OK;
            } else {
                msg_result.error_reason = code;
                msg_result.result_code = ALCS_SEND_RSPERROR;
            }
            msg_result.payload_len = message->payloadlen;
            msg_result.payload = message->payload;
        }
        break;
        case COAP_RECV_RESP_TIMEOUT: {
            msg_result.result_code = ALCS_SEND_TIMEOUT;
        }
        break;
    }

    HAL_MutexLock(g_alcs_mutex); 
    send_msg = get_user_data (id);
    if (send_msg) {
        connection = find_connection (send_msg->connection);
        if (connection) {
            COAP_DEBUG ("connection is found, id:%d, pk:%s, dn:%s", id, connection->pk, connection->dn);
            msg_result.pk = connection->pk;
            msg_result.dn = connection->dn;
        }
        msg_result.user_data = send_msg->user_data;
        cb = send_msg->cb;

        if (!send_msg->msg_id) {
            remove_user_data (id, 1);
        }
    } else {
            COAP_ERR ("msg not found");
    }
    HAL_MutexUnlock(g_alcs_mutex);

    if (cb) {
        cb (&msg_result);
    } else {
        COAP_DEBUG ("can't find callack");
    }
}

static inner_send_msg_pt formatMessage (CoAPMessage* msg, alcs_msg_param_pt msg_param, int keep, alcs_send_msg_cb cb)
{
    int id;
    CoAPLenString payload;
    alcs_msg_param_option_pt option = (alcs_msg_param_option_pt)msg_param->msg_option;
    inner_send_msg_pt send_msg = (inner_send_msg_pt)coap_malloc(sizeof(inner_send_msg_t));

    if (send_msg == NULL) {
        COAP_ERR ("formatMessage, fail to malloc");
        return NULL;
    }
    memset (send_msg, 0, sizeof(inner_send_msg_t));
    send_msg->user_data = msg_param->user_data;
    send_msg->cb = cb;

    payload.len = msg_param->payload_len;
    payload.data = msg_param->payload;

    id = add_user_data(send_msg);
    if (id <= 0) {
        coap_free (send_msg);
        return NULL;
    }
    COAP_DEBUG ("formatMessage, id:%d", id);
    alcs_msg_init (g_coap_ctx, msg, option->msg_code, option->msg_type, keep, &payload, (void*)(intptr_t)id);
    alcs_msg_setAddr (msg, option->method, "");
    if (keep) {
        CoAPMessageId_get (msg, &send_msg->msg_id);
    }
    option->msgId = msg->header.msgid;
    return send_msg;
}

static int discovery_iterator_ck (void* data, va_list *params)
{
    char* ck;
    ck = va_arg(*params, char*);
    if (!data || !ck) {
        return 0;
    }

    return (memcmp(data, ck, PK_DN_CHECKSUM_LEN) == 0);
}

static void* get_discovery_pkdn (linked_list_t* list, void* ck)
{
    list_node_t* node;
    void* data;

    node  = get_list_node (list, discovery_iterator_ck, ck);
    data = node? node->data : NULL;

    return data; 
}

static void do_probe_cb (CoAPContext *context,
                        CoAPReqResult result,
                        void *userdata,
                        NetworkAddr *remote,
                        CoAPMessage *message)
{
    alcs_probe_result_t probe_result = {0};
    int id = (int)(intptr_t)userdata;
    inner_probe_param_pt probe_param = get_user_data(id);
    if (!probe_param) {
        return;
    }
    probe_result.pk = probe_param->pk;
    probe_result.dn = probe_param->dn;
    probe_result.user_data = probe_param->user_data;

    switch (result) {
        case COAP_REQUEST_SUCCESS: {
            CoAPMessageCode code;
            if (message == NULL) {
                COAP_ERR ("do_probe_cb, message is NULL!");
                return;
            }
            
            if (CoAPMessageCode_get (message, &code) == ALCS_SUCCESS &&
                code >= COAP_MSG_CODE_201_CREATED && code <= COAP_MSG_CODE_231_CONTINUE)
            {   
                probe_result.result_code = ALCS_SEND_OK;
            } else {
                probe_result.error_reason = code;
                probe_result.result_code = ALCS_SEND_RSPERROR;
            }
        }
        break;
        case COAP_RECV_RESP_TIMEOUT: {
            probe_result.result_code = ALCS_SEND_TIMEOUT;
        }
        break;
    }

    probe_param->probe_cb (&probe_result);
    remove_user_data (id, 1);
}

static int do_probe (alcs_network_addr_pt alcs_addr, inner_probe_param_pt probe_param)
{
    char* method = "/dev/core/service/dev";
    char* payload = "{\"id\":\"1\",\"version\":\"1.0\",\"params\":{},\"method\":\"core.service.dev\"}";
    NetworkAddr addr;
    CoAPMessage msg;
    CoAPLenString obj_payload;

    memcpy (addr.addr, alcs_addr->addr, sizeof(alcs_addr->addr));
    addr.port = alcs_addr->port;
    obj_payload.data = (unsigned char*)payload;
    obj_payload.len = strlen(payload);
    
    int id = add_user_data (probe_param);
    if (id <= 0) {
        coap_free (probe_param);
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }
    COAP_DEBUG ("formatMessage, id:%d", id);
    
    alcs_msg_init (g_coap_ctx, &msg, ALCS_MSG_CODE_GET, ALCS_MSG_TYPE_CON, 0, &obj_payload, (void*)(intptr_t)id);
    alcs_msg_setAddr (&msg, method, "");
    return alcs_sendmsg (g_coap_ctx, &addr, &msg, 2, do_probe_cb);
}

int iot_alcs_device_probe(alcs_prob_param_pt param, alcs_probe_cb cb)
{
    COAP_DEBUG ("iot_alcs_device_probe");
    if (!param || !param->pk || !param->dn || !cb) {
        return ALCS_RESULT_INVALIDPARAM;
    }
    
    inner_probe_param_pt probe_param = coap_malloc(sizeof(inner_probe_param_t));
    if (!probe_param) {
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }
    strncpy (probe_param->pk, param->pk, MAXPK_LEN);
    strncpy (probe_param->dn, param->dn, MAXDN_LEN);
    probe_param->probe_cb = cb;
    probe_param->user_data = param->user_data;

    return do_probe(&param->addr, probe_param);
}

static void discovery_notify (char* data, int len, alcs_network_addr_t addr, void* user_data, char* pal, int pallen)
{
    int pklen, dnlen;
    alcs_device_discovery_info_t device;
    inner_discovery_param_pt task;
    alcs_discovery_cb cb = NULL;
    char path[100];

    COAP_DEBUG ("discovery_notify data:%.*s", len, data);
    memset (&device, 0, sizeof(alcs_device_discovery_info_t));

    device.from = addr;
    device.pk = alcs_json_get_value_by_name(data, len, "productKey", &pklen, (int*)NULL);
    device.dn = alcs_json_get_value_by_name(data, len, "deviceName", &dnlen, (int*)NULL);
    if (!pal || !pallen) {
        device.pal = alcs_json_get_value_by_name(data, len, "pal", &pallen, (int*)NULL);
    } else if (pal && pallen) {
        device.pal = pal;
    } else {//default
        device.pal = "linkkit-ica";
    }

    if (device.pk && pklen && device.dn && dnlen) {
        char pkback, dnback, palback = '\0';
        char ck[PK_DN_CHECKSUM_LEN];

        backup_json_str_last_char (device.pk, pklen, pkback);
        backup_json_str_last_char (device.dn, dnlen, dnback);

        HAL_Snprintf(path, sizeof(path) -1, "%s%s", device.pk, device.dn);
        CoAPPathMD5_sum (path, strlen(path), ck, PK_DN_CHECKSUM_LEN);
 
        COAP_DEBUG ("userdata:%d, discovery_id:%d", (int)(intptr_t)user_data, g_discovery_id);
        
        HAL_MutexLock(g_alcs_mutex);
        if ((int)(intptr_t)user_data == g_discovery_id) {
            task = (inner_discovery_param_pt)get_user_data (g_discovery_id);
            if (task) {
                if (get_discovery_pkdn (task->rec_pkdn, ck)) {
                    COAP_INFO ("device %s,%s is in list", device.pk, device.dn);
                } else {
                    cb = (alcs_discovery_cb)task->cb;
                } 
            }
        }
       
        if (cb) {
            char* p = coap_malloc (PK_DN_CHECKSUM_LEN);
            if (p) {
                memcpy (p, ck, PK_DN_CHECKSUM_LEN);
                linked_list_insert (task->rec_pkdn, p);
            }
            HAL_MutexUnlock(g_alcs_mutex);
            
            COAP_DEBUG ("find new device %s,%s", device.pk, device.dn);
            if (!pal && pallen) {
                backup_json_str_last_char (device.pal, pallen, palback);
            }
            cb (&device);
            if (!pal && pallen) {
                restore_json_str_last_char (device.pal, pallen, palback);
            }            
        } else {
            HAL_MutexUnlock(g_alcs_mutex);
        }

        restore_json_str_last_char (device.pk, pklen, pkback);
        restore_json_str_last_char (device.dn, dnlen, dnback);
    }
}

static void discovery_handler (alcs_msg_result_pt result)
{
    if (!result || !result->user_data) {
        return;
    }

    if (result->result_code == ALCS_SEND_TIMEOUT) {
        COAP_INFO ("discovery_handler, timeout");
    } else if (result->result_code == ALCS_SEND_RSPERROR) {
        COAP_DEBUG("discovery_handler, response error, code:%d", result->error_reason);   
    } else {
        int seq, datalen, modellen, deviceslen;
        ResponseMsg msg;
        char *data, *model, *devices;

        COAP_DEBUG ("discovery_handler, len:%d, data:%s", result->payload_len, result->payload);

        res_parse ((const char *)result->payload, result->payload_len, &seq, &msg, &data, &datalen);
        if (msg.code != 200) {
            COAP_ERR ("msg.code != 200");
            return;
        }

        model = alcs_json_get_value_by_name(data, datalen, "deviceModel", &modellen, (int*)NULL);
        if (model && modellen) {
            int profilelen;
            char* profile;
            COAP_DEBUG ("discovery_handler, model data:%.*s", modellen, model);

            profile = alcs_json_get_value_by_name(model, modellen, "profile", &profilelen, (int*)NULL);
            if (profile && profilelen) {
                discovery_notify (profile, profilelen, result->addr, result->user_data, NULL, 0);
            }
        }

        devices = alcs_json_get_value_by_name(data, datalen, "devices", &deviceslen, (int*)NULL);
        if (devices && deviceslen) {
            int profilelen, pallen;
            char palback = '\0';
            char* profile;
            char* pal = alcs_json_get_value_by_name(devices, deviceslen, "pal", &pallen, (int*)NULL);
            profile = alcs_json_get_value_by_name(devices, deviceslen, "profile", &profilelen, (int*)NULL);
            
            if (pal && pallen) {
                backup_json_str_last_char (pal, pallen, palback);
            }
            
            if (profile && profilelen) {
                char profileback;
                char *str_pos, *entry;
                int entry_len, type;

                backup_json_str_last_char (profile, profilelen, profileback);
                json_array_for_each_entry(profile, profilelen, str_pos, entry, entry_len, type) {
                    discovery_notify (entry, entry_len, result->addr, result->user_data, pal, pallen);
                } //end json_array_for_each_entry
                restore_json_str_last_char (profile, profilelen, profileback);
            } //end if (profile && profilelen)
            
            if (pal && pallen) {
                restore_json_str_last_char (pal, pallen, palback);
            }
        }
    }
}

void iot_alcs_set_new_device_listener (alcs_discovery_cb cb)
{
    new_device_online_cb = cb;
}

static int do_discovery (inner_discovery_param_pt task)
{
    static int seq = 0;
    char* method = "/dev/core/service/dev";
    const char* payload_format = "{\"id\":\"%d\",\"version\":\"1.0\",\"params\":{},\"method\":\"core.service.dev\"}";
    char payload[128];
    alcs_msg_param_option_t option = {0};
    alcs_msg_param_t msg_param;
    NetworkAddr addr;
    CoAPMessage msg;

    snprintf (payload, sizeof(payload), payload_format, ++seq);

    option.method = method;
    option.msg_code = ALCS_MSG_CODE_GET;
    option.msg_type = ALCS_MSG_TYPE_NON;

    memset (&msg_param, 0, sizeof(alcs_msg_param_t));
    msg_param.payload = (unsigned char*)payload;
    msg_param.payload_len = strlen(payload);
    msg_param.msg_option = &option;
    msg_param.user_data = (void*)(intptr_t)g_discovery_id;

    //strcpy (addr.addr, "224.0.1.187");
    HAL_Get_broadcast_ip (addr.addr);
    COAP_DEBUG ("broadcast ip:%s", addr.addr);
    addr.port = 5683;
    task->task_info = formatMessage (&msg, &msg_param, 1, discovery_handler);
    if (!task->task_info) {
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }
    alcs_sendmsg (g_coap_ctx, &addr, &msg, 2, do_send_msg_cb);

    return ALCS_RESULT_OK; 
}

static void do_clear_discovery_task (int task_id)
{
    inner_discovery_param_pt task;

    if (task_id == g_discovery_id) {
        g_discovery_id = 0;
        task = (inner_discovery_param_pt)get_user_data (task_id);
        if (task) {
            del_timer(task->discovery_timer);
            del_timer(task->discovery_finish_timer);
            destory_list (task->rec_pkdn);

            if (task->task_info) {
                inner_send_msg_pt send_msg = (inner_send_msg_pt)task->task_info;
                CoAPMessageId_cancel (g_coap_ctx, send_msg->msg_id);
                remove_user_data (get_user_data_id(send_msg), 1);
            }
            remove_user_data (task_id, 1);
        }
    }
}

typedef void (*discovery_finish_cb)();
void discovery_finish_timer_cb (void* user_data)
{
    int task_id = (int)(intptr_t)user_data;
    void* cb = NULL;
    inner_discovery_param_pt task;    

    COAP_DEBUG ("discovery_finish_timer_cb");

    HAL_MutexLock(g_alcs_mutex); 
    if (g_discovery_id == task_id) {
        task = (inner_discovery_param_pt)get_user_data (task_id);
        if (task) {
            cb = task->finish_cb;
        }
    }
    do_clear_discovery_task (g_discovery_id);
    HAL_MutexUnlock(g_alcs_mutex);

    if (cb) {
        ((discovery_finish_cb)cb) ();
    }
}

const int DISCOVERY_INTERVAL = 10000;
void discovery_timer_cb (void* user_data)
{
    int task_id = (int)(intptr_t)user_data;
    COAP_DEBUG ("discovery_timer_cb\n");
    inner_discovery_param_pt task;

    HAL_MutexLock(g_alcs_mutex);

    task = (inner_discovery_param_pt)get_user_data (task_id);
    if (task && g_discovery_id == task_id) {
        if (task->task_info) {
            inner_send_msg_pt send_msg = (inner_send_msg_pt)task->task_info;
            CoAPMessageId_cancel (g_coap_ctx, send_msg->msg_id);
            remove_user_data (get_user_data_id(send_msg), 1);
            task->task_info = NULL;
        }
        do_discovery (task);
        alcs_timer_start (task->discovery_timer, DISCOVERY_INTERVAL);
    }

    HAL_MutexUnlock(g_alcs_mutex);
}

int iot_alcs_discovery_device (int timeout, alcs_discovery_cb cb, discovery_finish_cb finish_cb)
{
    int rt;
    inner_discovery_param_pt task;
    COAP_DEBUG ("iot_alcs_discovery_device");

    HAL_MutexLock(g_alcs_mutex);
    if (g_discovery_id) {
        COAP_DEBUG ("discovery task is found!");
        HAL_MutexUnlock(g_alcs_mutex);
        return ALCS_RESULT_DUPLICATE;
    }
    HAL_MutexUnlock(g_alcs_mutex);

    task = (inner_discovery_param_pt)coap_malloc (sizeof(inner_discovery_param_t));
    if (!task) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    task->finish_cb = finish_cb;
    task->cb = cb;
    task->rec_pkdn = linked_list_create("discovery received pkdn", 1); 

    HAL_MutexLock(g_alcs_mutex);

    g_discovery_id = add_user_data (task);
    if (g_discovery_id <= 0) {
        coap_free (task);
        rt = ALCS_RESULT_INSUFFICIENT_MEM;
    } else {
        if (timeout > DISCOVERY_INTERVAL) {
            task->discovery_timer = alcs_timer_create ("", discovery_timer_cb, (void*)(intptr_t)g_discovery_id);
            if (task->discovery_timer) {
                alcs_timer_start (task->discovery_timer, DISCOVERY_INTERVAL);
            }
        }
        task->discovery_finish_timer = alcs_timer_create ("", discovery_finish_timer_cb, (void*)(intptr_t)g_discovery_id);
        if (task->discovery_finish_timer) {
            alcs_timer_start (task->discovery_finish_timer, timeout);
        }
        rt = do_discovery(task);
    }

    if (rt != ALCS_RESULT_OK) {
        COAP_ERR ("discovery send error");
        do_clear_discovery_task (g_discovery_id);
    }
    HAL_MutexUnlock(g_alcs_mutex);

    return rt;
}

void iot_alcs_stop_discovery_device ()
{
    COAP_DEBUG ("iot_alcs_stop_discovery_device");
    HAL_MutexLock(g_alcs_mutex);
    do_clear_discovery_task (g_discovery_id);
    HAL_MutexUnlock(g_alcs_mutex);
}

static void convert2alcsnetworkaddr (alcs_network_addr_t* addr1, NetworkAddr* addr2)
{
    strncpy (addr1->addr, addr2->addr, sizeof(addr1->addr) - 1);
    addr1->port = addr2->port;
}

int iot_alcs_send(alcs_msg_param_pt msg_param, alcs_send_msg_cb cb)
{
    inner_conn_param_pt connection;
    CoAPMessage msg;
    AlcsDeviceKey devicekey;
    inner_send_msg_pt send_msg;

    if (!msg_param || !msg_param->msg_option || !cb) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    HAL_MutexLock(g_alcs_mutex);
    connection = get_connection(msg_param->pk, msg_param->dn);
    if (!connection) {
        HAL_MutexUnlock(g_alcs_mutex);
        COAP_INFO ("iot_alcs_send: PK&DN is not found!");
        return ALCS_RESULT_NOTFOUND;
    }
    send_msg = formatMessage (&msg, msg_param, 0, cb);
    if (!send_msg) {
        HAL_MutexUnlock(g_alcs_mutex);
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }
    send_msg->connection = connection;
    HAL_MutexUnlock(g_alcs_mutex);

    memcpy (&devicekey.addr, &connection->addr, sizeof(NetworkAddr));
    devicekey.pk = msg_param->pk;
    devicekey.dn = msg_param->dn;

    return alcs_sendmsg_secure (g_coap_ctx, &devicekey, &msg, 2, do_send_msg_cb) == ALCS_SUCCESS? ALCS_RESULT_OK : ALCS_RESULT_FAIL;
}

static void subcribe_handler (CoAPContext *context,
                        CoAPReqResult result,
                        void *userdata,
                        NetworkAddr *remote,
                        CoAPMessage *message)
{
    int id = (int)(intptr_t)userdata;
    inner_subcribe_param_pt sub_param;
    alcs_msg_result_t msg_result = {0};
    alcs_subcribe_notify_t sub_result = {0};
    inner_conn_param_pt connection;
    alcs_send_msg_cb rsp_cb = NULL;
    alcs_sub_cb sub_cb = NULL;

    if (userdata == NULL || remote == NULL || message == NULL) {
        return;
    }

    HAL_MutexLock(g_alcs_mutex);
    sub_param = (inner_subcribe_param_pt)get_user_data (id);
    if (!find_subcribe (sub_param)) {
        HAL_MutexUnlock(g_alcs_mutex);
        COAP_DEBUG ("subcribe is not found!");
        return;
    }

    connection = find_connection (sub_param->connection);
    if (!connection) {
        HAL_MutexUnlock(g_alcs_mutex);
        COAP_DEBUG ("connection is not found!");
        return;
    }
    
    switch (result) {
        case COAP_REQUEST_SUCCESS: {
            CoAPMessageCode code;
            unsigned int obsVal;
            if (CoAPUintOption_get (message, COAP_OPTION_OBSERVE, &obsVal) != ALCS_SUCCESS) {
                linked_list_remove (alcs_subcribe_list, sub_param);    
            }
            
            if (sub_param->rsp_cb) {
                msg_result.payload_len = message->payloadlen;
                msg_result.payload = message->payload;
                msg_result.user_data = sub_param->user_data;
                msg_result.pk = connection->pk;
                msg_result.dn = connection->dn;
                convert2alcsnetworkaddr(&msg_result.addr, remote);

                if (CoAPMessageCode_get (message, &code) == ALCS_SUCCESS &&
                    code >= COAP_MSG_CODE_201_CREATED && code <= COAP_MSG_CODE_231_CONTINUE)
                {
                    msg_result.result_code = ALCS_SEND_OK;
                } else {
                    msg_result.error_reason = code;
                    msg_result.result_code = ALCS_SEND_RSPERROR;
                }
                rsp_cb = sub_param->rsp_cb;
                sub_param->rsp_cb = NULL;
            } else {
                sub_result.payload_len = message->payloadlen;
                sub_result.payload = message->payload;
                sub_result.user_data = sub_param->user_data;
                sub_result.pk = connection->pk;
                sub_result.dn = connection->dn;
                convert2alcsnetworkaddr(&sub_result.addr, remote);
                sub_cb = sub_param->sub_cb;
            }

            if (CoAPUintOption_get (message, COAP_OPTION_OBSERVE, &obsVal) != ALCS_SUCCESS) {
                coap_free (sub_param);
            }
        }
        break;
        case COAP_RECV_RESP_TIMEOUT: {
            msg_result.result_code = ALCS_SEND_TIMEOUT;
            msg_result.user_data = sub_param->user_data;
            msg_result.pk = connection->pk;
            msg_result.dn = connection->dn;
            convert2alcsnetworkaddr(&msg_result.addr, remote);
            rsp_cb = sub_param->rsp_cb;
            linked_list_remove (alcs_subcribe_list, sub_param);
            coap_free (sub_param);
        }
        break;
    }
    HAL_MutexUnlock(g_alcs_mutex);

    if (rsp_cb) {
        rsp_cb (&msg_result);
    }
    if (sub_cb) {
        sub_cb (&sub_result);
    }
}
                           

int do_subcribe (alcs_sub_param_pt sub_param, int subcribe, alcs_send_msg_cb rsp_cb, alcs_sub_cb sub_cb)
{
    alcs_sub_param_option_pt sub_option;
    inner_subcribe_param_pt sub_save;
    inner_conn_param_pt connection;
    CoAPMessage msg;
    CoAPLenString payload;
    AlcsDeviceKey devicekey;
    char ck[PATH_CK_LEN];
    int id;

    if (!sub_param || !sub_param->sub_option|| !rsp_cb) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    HAL_MutexLock(g_alcs_mutex);
    connection = get_connection(sub_param->pk, sub_param->dn);
    if (!connection) {
        HAL_MutexUnlock(g_alcs_mutex);
        COAP_INFO ("do_subcribe: PK&DN is not found!");
        return ALCS_RESULT_NOTFOUND;
    }

    sub_option = (alcs_sub_param_option_pt)sub_param->sub_option;
    CoAPPathMD5_sum (sub_option->method, strlen(sub_option->method), ck, PATH_CK_LEN);

    sub_save = get_subcribe_by_ck (ck);
    id = get_user_data_id (sub_save);
    if (!sub_save) {
        sub_save = (inner_subcribe_param_pt)coap_malloc (sizeof(inner_subcribe_param_t));
        if (!sub_save) {
            HAL_MutexUnlock(g_alcs_mutex);
            return ALCS_RESULT_INSUFFICIENT_MEM;
        }
        linked_list_insert(alcs_subcribe_list, sub_save);
        id = add_user_data (sub_save);
    }
    HAL_MutexUnlock(g_alcs_mutex);

    if (id <= 0) {
        COAP_INFO ("do_subcribe: item_id is null");
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }

    sub_save->connection = connection;
    sub_save->sub_cb = sub_cb;
    sub_save->rsp_cb = rsp_cb;
    sub_save->user_data = sub_param->user_data;
    memcpy (sub_save->path_ck, ck, PATH_CK_LEN);

    payload.len = sub_param->payload_len;
    payload.data = sub_param->payload;

    alcs_msg_init (g_coap_ctx, &msg, ALCS_MSG_CODE_GET, ALCS_MSG_TYPE_CON, 0, &payload, (void*)(intptr_t)id);
    alcs_msg_setAddr (&msg, sub_option->method, "");

    memcpy (&devicekey.addr, &connection->addr, sizeof(NetworkAddr));
    devicekey.pk = sub_param->pk;
    devicekey.dn = sub_param->dn;

    return alcs_sendmsg_secure (g_coap_ctx, &devicekey, &msg, subcribe? 0 : 1, subcribe_handler) == ALCS_SUCCESS? ALCS_RESULT_OK : ALCS_RESULT_FAIL;
}

int iot_alcs_subcribe (alcs_sub_param_pt sub_param, alcs_send_msg_cb rsp_cb, alcs_sub_cb sub_cb)
{
    return do_subcribe (sub_param, 1, rsp_cb, sub_cb);
}

int iot_alcs_unsubcribe (alcs_sub_param_pt sub_param, alcs_send_msg_cb cb)
{
    alcs_sub_param_option_pt sub_option;
    char ck[PATH_CK_LEN];

    if (!sub_param || !sub_param->sub_option|| !cb) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    sub_option = (alcs_sub_param_option_pt)sub_param->sub_option;
    CoAPPathMD5_sum (sub_option->method, strlen(sub_option->method), ck, PATH_CK_LEN);

    if (!get_subcribe_by_ck (ck)) {
        return ALCS_RESULT_NOTFOUND;
    }
    return do_subcribe (sub_param, 0, cb, NULL);
}

/************************************ Server API  *********************************************/ 

int iot_alcs_add_device (const char* pk, const char* dn)
{
    return alcs_auth_subdev_init (g_coap_ctx, pk, dn) == ALCS_SUCCESS? ALCS_RESULT_OK : ALCS_RESULT_FAIL;
}
    
int iot_alcs_remove_device (const char* pk, const char* dn)
{
    char path[128];
    HAL_Snprintf(path, sizeof(path), "/dev/%s/%s/core/service/auth", pk, dn);
    alcs_resource_unregister (g_coap_ctx, path);

    strcat (path, "/select");
    alcs_resource_unregister (g_coap_ctx, path);
    return ALCS_RESULT_OK;
}   

static void resource_list_handler(void *list_node, va_list *params)
{
    inner_resource_cb_save_t* cb_save = (inner_resource_cb_save_t*)list_node;

    char* path = NULL;
    char ck[PATH_CK_LEN];
    NetworkAddr* addr;
    alcs_service_cb_param_pt cb_param;
    CoAPMessage *message;
    COAP_DEBUG ("resource_list_handler");

    cb_param = va_arg(*params, alcs_service_cb_param_pt);
    path = va_arg(*params, char*);
    addr = va_arg(*params, NetworkAddr*);
    message = va_arg(*params, CoAPMessage*);

    CoAPPathMD5_sum (path, strlen(path), ck, PATH_CK_LEN);

    if (memcmp(ck, cb_save->path_ck, PATH_CK_LEN) == 0) {
        cb_param->user_data = cb_save->user_data;
        cb_param->pk = cb_save->pk;
        cb_param->dn = cb_save->dn;
        inner_receive_query_pt ctx = (inner_receive_query_pt) coap_malloc(sizeof(inner_receive_query_t));
        if (ctx) {
            ctx->tokenlen = sizeof(ctx->token);
            CoAPMessageToken_get(message, ctx->token, &ctx->tokenlen);

            unsigned int obsVal;
            if (CoAPUintOption_get (message, COAP_OPTION_OBSERVE, &obsVal) == ALCS_SUCCESS) {
                ctx->observe = (unsigned char)obsVal;
            } else {
                ctx->observe = 2;
            }
            memcpy (&ctx->addr, addr, sizeof(NetworkAddr)); 
            ctx->resource = cb_save;
        }
        cb_param->cb_ctx = ctx; 
        cb_save->cb (cb_param);
    }
}

static void coap_ack_send(NetworkAddr *remote, unsigned short msgid)
{
    CoAPMessage message;

    CoAPMessage_init(&message);
    CoAPMessageId_set(&message, msgid);
    COAP_DEBUG("Send Ack Response Message: %d", msgid);
    CoAPMessage_send(g_coap_ctx, remote, &message);
    CoAPMessage_destory(&message);
}

static void resource_cb (CoAPContext *context, const char *paths, NetworkAddr *remote, CoAPMessage *message)
{
    alcs_service_cb_param_t cb_param;
    unsigned short msgid;
    unsigned char type; 
    COAP_DEBUG ("resource_cb");
    if (!paths || !remote || !message) {
        return;
    }

    CoAPMessageId_get(message, &msgid);
    CoAPMessageType_get(message, &type);
    if (type == COAP_MESSAGE_TYPE_CON) {
        coap_ack_send (remote, msgid);
    }

    cb_param.service = (char*)paths;
    CoAPMessagePayloadlen_get (message, &cb_param.payload_len);
    cb_param.payload = message->payload;
    convert2alcsnetworkaddr (&cb_param.from, remote);        

    linked_list_iterator(alcs_resource_list,
                            resource_list_handler,
                            &cb_param, paths, remote, message);
}

int iot_alcs_register_service(alcs_service_param_pt svr_param, alcs_service_cb cb)
{   
    if (!svr_param || !cb || !svr_param->service) {
        COAP_INFO ("iot_alcs_register_service, invalid params");
        return ALCS_RESULT_INVALIDPARAM;
    }

    COAP_DEBUG ("iot_alcs_register_service, path:%s", (char*)svr_param->service);

    char* path = (char*)svr_param->service;
    inner_resource_cb_save_t* cb_param = (inner_resource_cb_save_t*)coap_malloc (sizeof(inner_resource_cb_save_t));
    if (!cb_param) {
        COAP_INFO ("iot_alcs_register_service, NO memory");
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }
    memset (cb_param, 0, sizeof(inner_resource_cb_save_t));

    CoAPPathMD5_sum (path, strlen(path), cb_param->path_ck, PATH_CK_LEN);
    cb_param->cb = cb;
    cb_param->user_data = svr_param->user_data;
    cb_param->secure = svr_param->secure;
 
    if (svr_param->pk && svr_param->dn) {
        COAP_DEBUG ("pk:%s, dn:%s", svr_param->pk, svr_param->dn); 
        cb_param->pk = (char*)coap_malloc (strlen(svr_param->pk) + 1); 
        cb_param->dn = (char*)coap_malloc (strlen(svr_param->dn) + 1);
        if (!cb_param->pk || !cb_param->dn) {
            if (cb_param->pk) {
                coap_free (cb_param->pk);
            }
            coap_free (cb_param);
            return ALCS_RESULT_INSUFFICIENT_MEM;
        }

        strcpy (cb_param->pk, svr_param->pk);
        strcpy (cb_param->dn, svr_param->dn);
    }

    int result = alcs_resource_register (g_coap_ctx, svr_param->pk, svr_param->dn, (char*)svr_param->service,
            svr_param->perm, svr_param->content_type, svr_param->maxage, svr_param->secure, resource_cb); 

    if (result == ALCS_SUCCESS) {
        linked_list_insert(alcs_resource_list, cb_param);
        return ALCS_RESULT_OK;
    } else {
        if (cb_param->pk) {
            coap_free (cb_param->pk);
            coap_free (cb_param->dn);
        }
        coap_free (cb_param);     
        return ALCS_RESULT_FAIL;
    }
}       
    
int iot_alcs_unregister_service(void* service)
{   
    if (!service) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    alcs_resource_unregister (g_coap_ctx, (char*)service);
    //linked_list_remove();

    return ALCS_RESULT_OK;
}
    
int iot_alcs_add_and_update_authkey (void* auth_info)
{
    int rt;
    char ac[KEYPREFIX_LEN + 1];
    char buffer[151];
    alcs_svr_auth_param_pt p = (alcs_svr_auth_param_pt)auth_info;

    if (!p || !p->ac || !p->as || p->ac_len != KEYPREFIX_LEN || !p->as_len || p->as_len > AUTHSECRET_MAXLEN) {
        COAP_INFO ("invalid params");
        return ALCS_RESULT_INVALIDPARAM;
    }

    strncpy (ac, p->ac, p->ac_len);
    ac[p->ac_len] = 0;
    strncpy (buffer, p->as, p->as_len);
    buffer[p->as_len] = 0;
    rt = alcs_add_svr_key (g_coap_ctx, ac, buffer);

    if (rt != ALCS_SUCCESS) {
        return ALCS_RESULT_INSUFFICIENT_MEM;
    }

    if (p->blacklist && p->blacklist_len) {
        memset (buffer, 0, sizeof(buffer));
        strncpy (buffer, p->blacklist, sizeof(buffer) - 1);
        rt = alcs_set_revocation (g_coap_ctx, buffer);
    }
    
    return rt != ALCS_SUCCESS? ALCS_RESULT_FAIL : ALCS_RESULT_OK;
}

int iot_alcs_remove_authkey (void* auth_info)
{
    char ac[KEYPREFIX_LEN + 1];
    alcs_svr_auth_param_pt p = (alcs_svr_auth_param_pt)auth_info;
    if (!p || !p->ac || p->ac_len != KEYPREFIX_LEN) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    strncpy (ac, p->ac, sizeof(ac) - 1);
    return alcs_remove_svr_key (g_coap_ctx, ac) == ALCS_SUCCESS? ALCS_RESULT_OK : ALCS_RESULT_FAIL;
}

//
static int use_newThread = 0;
void iot_alcs_start_loop (int newThread)
{
    if (newThread) {
        use_newThread = 1;
        alcs_start_loop (g_coap_ctx, 1); 
    } else {
        
    }
}       

void iot_alcs_stop_loop ()
{
    if (use_newThread) {
        use_newThread = 0;
        alcs_stop_loop (g_coap_ctx);
    }
}

int iot_alcs_send_notify(alcs_notify_param_pt notify)
{
    if (notify == NULL || notify->option == NULL || notify->payload == NULL || !notify->payload_len) {
        return ALCS_RESULT_INVALIDPARAM;
    }

    CoAPLenString lenstr;
    lenstr.len = notify->payload_len;
    lenstr.data = notify->payload;
    return alcs_observe_notify (g_coap_ctx, (char*)notify->option, &lenstr) == ALCS_SUCCESS? ALCS_RESULT_OK : ALCS_RESULT_FAIL;
}

int iot_alcs_send_rsp(alcs_rsp_msg_param_pt rsp_msg, void* cb_ctx)
{
    inner_receive_query_pt query_ctx = (inner_receive_query_pt)cb_ctx;
    AlcsDeviceKey devicekey;
    CoAPLenString token;
    CoAPLenString payload;
    CoAPMessage msg;
    alcs_rsp_msg_param_option_pt option;
    int rt;
    
    COAP_DEBUG ("iot_alcs_send_rsp");
    if (!rsp_msg || !cb_ctx || !rsp_msg->msg_option) {
        COAP_INFO ("iot_alcs_send_rsp, invalid param");
        return ALCS_RESULT_INVALIDPARAM;
    }

    option = (alcs_rsp_msg_param_option_pt)rsp_msg->msg_option;

    memcpy (&devicekey.addr, &query_ctx->addr, sizeof(NetworkAddr));
    devicekey.pk = query_ctx->resource->pk;
    devicekey.dn = query_ctx->resource->dn;

    token.len = query_ctx->tokenlen;
    token.data = query_ctx->token;

    payload.len = rsp_msg->payload_len;
    payload.data = rsp_msg->payload;
    alcs_msg_init (g_coap_ctx, &msg, option->msg_code, option->msg_type, 0, &payload, NULL);

    if (query_ctx->resource->secure) {
        rt = alcs_sendrsp_secure (g_coap_ctx, &devicekey, &msg, query_ctx->observe, 0, &token);
    } else {
        rt = alcs_sendrsp (g_coap_ctx, &query_ctx->addr, &msg, query_ctx->observe, 0, &token);
    }

    coap_free (cb_ctx);
    return rt == ALCS_SUCCESS? ALCS_RESULT_OK : ALCS_RESULT_FAIL;
}

void iot_set_coap_log (int log_level)
{
    //set_coap_log(log_level);
    coap_level = log_level;
}

