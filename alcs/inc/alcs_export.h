#ifndef _IOT_EXPORT_ALCS_H_
#define _IOT_EXPORT_ALCS_H_
#include "alcs_export_st.h"

#ifdef __cplusplus
extern "C" {
#endif

int iot_alcs_init(const char* pk, const char* dn, alcs_role_t role);
void iot_alcs_deinit(void);
void iot_set_coap_log (int log_level);
/**************** connection api *********************************/
/*  @brief 连接认证  
 *  addr：      待连设备地址
 *  conn_param：包含待连设备的信息和回调接口,
 */
int iot_alcs_device_connect (alcs_network_addr_pt addr, alcs_connect_param_pt conn_param);

/*  @brief 断开连接
 *  @param [in] pk:  product key
 *  @param [in] dn:  device name
 */
int iot_alcs_device_disconnect (const char* pk, const char* dn);

/*  @brief  whether device is online
 *  @param [in] pk:  product key
 *  @param [in] dn:  device name
 *  @return: connect status, true--connected  false--unconnect
 */
bool iot_alcs_device_isonline (const char* pk, const char* dn);

void iot_alcs_set_disconnect_listener (alcs_disconnect_cb cb);

/**************** discovery api ********************/

int iot_alcs_discovery_device (int timeout, alcs_discovery_cb cb, void (*finish_cb)());
int iot_alcs_device_probe(alcs_prob_param_pt prob_param, alcs_probe_cb cb);
void iot_alcs_stop_discovery_device ();

void iot_alcs_set_new_device_listener (alcs_discovery_cb cb);
/**************** sender/receiver api ********************/

/**
 * @brief Send Message To Specific Device
 *
 * @param [in] msg_param: specify the sending parameters.
 * @param [in] cb: specify the callback.
 *
 * @return errorcode.
 * @see None.
 */
int iot_alcs_send(alcs_msg_param_pt msg_param, alcs_send_msg_cb cb);

int iot_alcs_subcribe (alcs_sub_param_pt sub_param, alcs_send_msg_cb rsp_cb, alcs_sub_cb sub_cb);
int iot_alcs_unsubcribe (alcs_sub_param_pt sub_param, alcs_send_msg_cb cb);

//
void iot_alcs_start_loop (int newThread);
void iot_alcs_stop_loop ();
#ifdef __cplusplus
}
#endif

#endif
