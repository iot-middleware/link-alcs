#ifndef _IOT_ALCS_EXPORT_ST_H_
#define _IOT_ALCS_EXPORT_ST_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef bool
#define bool char
#endif

typedef enum {
    ALCS_ROLE_CLIENT = 0x1,
    ALCS_ROLE_SERVER = 0x2,
    ALCS_ROLE_BOTH = 0x3
} alcs_role_t;

typedef enum {
    ALCS_LOG_DUMP = 0,
    ALCS_LOG_TRACE = 1,
    ALCS_LOG_DEBUG = 2,
    ALCS_LOG_INFO = 3,
    ALCS_LOG_WARNGING = 4,
    ALCS_LOG_ERROR = 5
} alcs_log_level;

typedef enum alcs_error_code {
    ALCS_RESULT_OK = 0,
    ALCS_RESULT_DUPLICATE,
    ALCS_RESULT_FAIL = -1,
    ALCS_RESULT_INSUFFICIENT_MEM = -2,
    ALCS_RESULT_NOTFOUND = -3,
    ALCS_RESULT_INVALIDPARAM = -4
} alcs_error_code_t;

typedef enum {
    ALCS_MSG_CT_TEXT_PLAIN                = 0,    /* text/plain (UTF-8) */
    ALCS_MSG_CT_APP_LINK_FORMAT           = 40,   /* application/link-format */
    ALCS_MSG_CT_APP_XML                   = 41,   /* application/xml */
    ALCS_MSG_CT_APP_OCTET_STREAM          = 42,   /* application/octet-stream */
    ALCS_MSG_CT_APP_RDF_XML               = 43,   /* application/rdf+xml */
    ALCS_MSG_CT_APP_EXI                   = 47,   /* application/exi  */
    ALCS_MSG_CT_APP_JSON                  = 50,   /* application/json  */
    ALCS_MSG_CT_APP_CBOR                  = 60   /* application/cbor  */
} alcs_msg_content_type_t;

typedef struct alcs_network_addr
{
    char addr[16];
    unsigned short port;
} alcs_network_addr_t, *alcs_network_addr_pt;

typedef struct alcs_device_key
{
    alcs_network_addr_t addr;
    char* pk;
    char* dn;
} alcs_device_key_t, *alcs_device_key_pt;

typedef void (*alcs_connect_cb) (alcs_device_key_pt device, void* user_data, int code, const char* msg);

typedef struct alcs_connect_param
{
    char* pk;   //productKey
    char* dn;   //deviceName
    char* pal;
    unsigned short auth_info_len;
    void* auth_info; //see alcs_auth_param_t
    void* user_data;
    alcs_connect_cb conn_cb;
} alcs_connect_param_t, *alcs_connect_param_pt;

typedef struct alcs_msg_param {
    char* pk;   //productKey
    char* dn;   //deviceName
    uint32_t payload_len;
    uint8_t *payload;
    void* msg_option;   //see alcs_msg_param_option_t
    void *user_data;
} alcs_msg_param_t, *alcs_msg_param_pt;

typedef struct alcs_rsp_msg_param {
    uint32_t payload_len;
    uint8_t *payload;
    void* msg_option;   //see alcs_rsp_msg_param_option_t 
} alcs_rsp_msg_param_t, *alcs_rsp_msg_param_pt;

typedef struct alcs_notify_param {
    uint32_t payload_len;
    uint8_t *payload;
    void* option;   // for ALCS DEVICE: option=url
} alcs_notify_param_t, *alcs_notify_param_pt;

typedef struct alcs_sub_param {
    char* pk;   //productKey
    char* dn;   //deviceName
    uint32_t payload_len;
    uint8_t *payload;
    void* sub_option; //see alcs_sub_param_option_t
    void *user_data;
} alcs_sub_param_t, *alcs_sub_param_pt;

typedef enum {
    ALCS_SEND_OK,
    ALCS_SEND_TIMEOUT,
    ALCS_SEND_RSPERROR
} alcs_send_code_t;

typedef struct alcs_msg_result {
    int result_code;   //see alcs_send_code_t 
    int error_reason;
    char* pk;   //productKey
    char* dn;   //deviceName
    alcs_network_addr_t addr;
    uint32_t payload_len;
    uint8_t* payload;
    void* user_data;
} alcs_msg_result_t, *alcs_msg_result_pt;

typedef void (*alcs_send_msg_cb)(alcs_msg_result_pt result);

typedef struct alcs_subcribe_notify {
    char* pk;   //productKey
    char* dn;   //deviceName
    alcs_network_addr_t addr;
    uint32_t payload_len;
    uint8_t* payload;
    void* user_data;
} alcs_subcribe_notify_t, *alcs_subcribe_notify_pt;
typedef void (*alcs_sub_cb)(alcs_subcribe_notify_pt sub_data);

typedef struct alcs_device_discovery_info {
    alcs_network_addr_t from;
    char* pk;   //productKey
    char* dn;   //deviceName
    char* pal;
} alcs_device_discovery_info_t, *alcs_device_discovery_info_pt;
typedef void (*alcs_discovery_cb)(alcs_device_discovery_info_pt device);

typedef struct alcs_prob_param {
    alcs_network_addr_t addr;
    char* pk;   //productKey
    char* dn;   //deviceName
    void *user_data;
} alcs_prob_param_t, *alcs_prob_param_pt;

typedef struct alcs_probe_result {
    int result_code;   //see alcs_send_code_t 
    int error_reason;
    char* pk;   //productKey
    char* dn;   //deviceName
    void* user_data;
} alcs_probe_result_t, *alcs_probe_result_pt;

typedef void (*alcs_probe_cb)(alcs_probe_result_pt result);

typedef struct alcs_service_param {
    void* service;
    char* pk;   //productKey
    char* dn;   //deviceName
    int secure; 
    int32_t perm;
    alcs_msg_content_type_t content_type;
    uint32_t maxage;  /*0~60*/
    void* user_data;
} alcs_service_param_t, *alcs_service_param_pt;

typedef struct alcs_service_cb_param {
    void* service;
    alcs_network_addr_t from;
    char* pk;   //productKey
    char* dn;   //deviceName
    uint16_t payload_len;
    uint8_t* payload;
    void* user_data;
    void* cb_ctx;
} alcs_service_cb_param_t, *alcs_service_cb_param_pt;

typedef void (*alcs_service_cb)(alcs_service_cb_param_pt cb_param);

typedef void (*alcs_disconnect_cb)(const char* pk, const char* dn);

#ifdef __cplusplus
}
#endif

#endif
