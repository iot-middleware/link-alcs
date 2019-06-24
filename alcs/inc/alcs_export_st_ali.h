#ifndef _IOT_ALCS_EXPORT_ST_ALI_H_
#define _IOT_ALCS_EXPORT_ST_ALI_H_
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ALCS_CONN_OK       = 200,
    ALCS_CONN_CONNECTING = 300,
    ALCS_CONN_REVOCATE = 501,
    ALCS_CONN_UNMATCHPREFIX = 502,
    ALCS_CONN_INVALIDPARAM = 503,
    ALCS_CONN_AUTHLISTEMPTY = 504,
    ALCS_CONN_VERNOTSUPPORT = 505,
    ALCS_CONN_ILLEGALSIGN = 506,
    ALCS_CONN_TIMEOUT = 507,
    ALCS_CONN_INTERNAL = 510
} alcs_connect_code;

typedef enum alcs_message_type {
    ALCS_MSG_TYPE_CON = 0,
    ALCS_MSG_TYPE_NON = 1,
    ALCS_MSG_TYPE_ACK = 2,
    ALCS_MSG_TYPE_RST = 3
} alcs_msg_type_t;

typedef enum {
    ALCS_MSG_PERM_GET     = 0x0001,
    ALCS_MSG_PERM_POST    = 0x0002,
    ALCS_MSG_PERM_PUT     = 0x0004,
    ALCS_MSG_PERM_DEL     = 0x0008,
    ALCS_MSG_PERM_OBSERVE = 0x0100
} alcs_msg_perm_t;

/*CoAP Message codes*/
#define ALCS_MSG_CODE_DEF(N) (((N)/100 << 5) | (N)%100)
typedef enum {
    /* CoAP Empty Message */
    ALCS_MSG_CODE_EMPTY_MESSAGE                  = ALCS_MSG_CODE_DEF(0),  /* Mapping to CoAP code 0.00 */

    /* CoAP Method Codes */
    ALCS_MSG_CODE_GET                            = ALCS_MSG_CODE_DEF(1),  /* CoAP Get method */
    ALCS_MSG_CODE_POST                           = ALCS_MSG_CODE_DEF(2),  /* CoAP Post method */
    ALCS_MSG_CODE_PUT                            = ALCS_MSG_CODE_DEF(3),  /* CoAP Put method */
    ALCS_MSG_CODE_DELETE                         = ALCS_MSG_CODE_DEF(4),  /* CoAP Delete method */

    /* CoAP Success Response Codes */
    ALCS_MSG_CODE_201_CREATED                    = ALCS_MSG_CODE_DEF(201),  /* Mapping to CoAP code 2.01, Hex:0x41, Created */
    ALCS_MSG_CODE_202_DELETED                    = ALCS_MSG_CODE_DEF(202),  /* Mapping to CoAP code 2.02, Hex:0x42, Deleted*/
    ALCS_MSG_CODE_203_VALID                      = ALCS_MSG_CODE_DEF(203),  /* Mapping to CoAP code 2.03, Hex:0x43, Valid*/
    ALCS_MSG_CODE_204_CHANGED                    = ALCS_MSG_CODE_DEF(204),  /* Mapping to CoAP code 2.04, Hex:0x44, Changed*/
    ALCS_MSG_CODE_205_CONTENT                    = ALCS_MSG_CODE_DEF(205),  /* Mapping to CoAP code 2.05, Hex:0x45, Content*/
    ALCS_MSG_CODE_231_CONTINUE                   = ALCS_MSG_CODE_DEF(231),  /* Mapping to CoAP code 2.31, Hex:0x5F, Continue*/

    /* CoAP Client Error Response Codes */
    ALCS_MSG_CODE_400_BAD_REQUEST                = ALCS_MSG_CODE_DEF(400),  /* Mapping to CoAP code 4.00, Hex:0x80, Bad Request */
    ALCS_MSG_CODE_401_UNAUTHORIZED               = ALCS_MSG_CODE_DEF(401),  /* Mapping to CoAP code 4.01, Hex:0x81, Unauthorized */
    ALCS_MSG_CODE_402_BAD_OPTION                 = ALCS_MSG_CODE_DEF(402),  /* Mapping to CoAP code 4.02, Hex:0x82, Bad Option */
    ALCS_MSG_CODE_403_FORBIDDEN                  = ALCS_MSG_CODE_DEF(403),  /* Mapping to CoAP code 4.03, Hex:0x83, Forbidden */
    ALCS_MSG_CODE_404_NOT_FOUND                  = ALCS_MSG_CODE_DEF(404),  /* Mapping to CoAP code 4.04, Hex:0x84, Not Found */
    ALCS_MSG_CODE_405_METHOD_NOT_ALLOWED         = ALCS_MSG_CODE_DEF(405),  /* Mapping to CoAP code 4.05, Hex:0x85, Method Not Allowed */
    ALCS_MSG_CODE_406_NOT_ACCEPTABLE             = ALCS_MSG_CODE_DEF(406),  /* Mapping to CoAP code 4.06, Hex:0x86, Not Acceptable */
    ALCS_MSG_CODE_408_REQUEST_ENTITY_INCOMPLETE  = ALCS_MSG_CODE_DEF(408),  /* Mapping to CoAP code 4.08, Hex:0x88, Request Entity Incomplete */
    ALCS_MSG_CODE_412_PRECONDITION_FAILED        = ALCS_MSG_CODE_DEF(412),  /* Mapping to CoAP code 4.12, Hex:0x8C, Precondition Failed */
    ALCS_MSG_CODE_413_REQUEST_ENTITY_TOO_LARGE   = ALCS_MSG_CODE_DEF(413),  /* Mapping to CoAP code 4.13, Hex:0x8D, Request Entity Too Large */
    ALCS_MSG_CODE_415_UNSUPPORTED_CONTENT_FORMAT = ALCS_MSG_CODE_DEF(415),  /* Mapping to CoAP code 4.15, Hex:0x8F, Unsupported Content-Format */
    /* CoAP Server Error Response Codes */
    ALCS_MSG_CODE_500_INTERNAL_SERVER_ERROR      = ALCS_MSG_CODE_DEF(500),  /* Mapping to CoAP code 5.00, Hex:0xA0, Internal Server Error */
    ALCS_MSG_CODE_501_NOT_IMPLEMENTED            = ALCS_MSG_CODE_DEF(501),  /* Mapping to CoAP code 5.01, Hex:0xA1, Not Implemented */
    ALCS_MSG_CODE_502_BAD_GATEWAY                = ALCS_MSG_CODE_DEF(502),  /* Mapping to CoAP code 5.02, Hex:0xA2, Bad Gateway */
    ALCS_MSG_CODE_503_SERVICE_UNAVAILABLE        = ALCS_MSG_CODE_DEF(503),  /* Mapping to CoAP code 5.03, Hex:0xA3, Service Unavailable */
    ALCS_MSG_CODE_504_GATEWAY_TIMEOUT            = ALCS_MSG_CODE_DEF(504),  /* Mapping to CoAP code 5.04, Hex:0xA4, Gateway Timeout */
    ALCS_MSG_CODE_505_PROXYING_NOT_SUPPORTED     = ALCS_MSG_CODE_DEF(505)   /* Mapping to CoAP code 5.05, Hex:0xA5, Proxying Not Supported */
} alcs_msg_code_t;


typedef struct alcs_auth_param
{
    char* ak;
    char* at;
} alcs_auth_param_t, *alcs_auth_param_pt;

typedef struct alcs_resource_addr 
{
    alcs_network_addr_t addr;
    char* method;
    char* query;
} alcs_resource_addr_t, *alcs_resource_addr_pt;

typedef struct alcs_msg_param_option {
    uint16_t group_id;              /*multicast group id, used as unicast when 0*/
    char* method;
    alcs_msg_code_t msg_code;
    alcs_msg_type_t msg_type;
    int msgId;// 输出coap msgid
} alcs_msg_param_option_t, *alcs_msg_param_option_pt;

typedef struct alcs_rsp_msg_param_option {
    alcs_msg_code_t msg_code;
    alcs_msg_type_t msg_type;
} alcs_rsp_msg_param_option_t, *alcs_rsp_msg_param_option_pt;

typedef struct alcs_sub_param_option {
    char* method;
} alcs_sub_param_option_t, *alcs_sub_param_option_pt;

typedef struct alcs_svr_auth_param
{
    char* ac;//authcode
    char* as;//authsecret
    char* blacklist;
    int ac_len;
    int as_len;
    int blacklist_len;
} alcs_svr_auth_param_t, *alcs_svr_auth_param_pt;

#ifdef __cplusplus
}
#endif

#endif
