#ifndef _IOT_EXPORT_ALCS_SVR_H_
#define _IOT_EXPORT_ALCS_SVR_H_
#include "alcs_export_st.h"

#ifdef __cplusplus
extern "C" {
#endif

int iot_alcs_init(const char* pk, const char* dn, alcs_role_t role);
void iot_alcs_deinit(void);

//server api
int iot_alcs_add_device (const char* pk, const char* dn);
int iot_alcs_remove_device (const char* pk, const char* dn);

int iot_alcs_register_service(alcs_service_param_pt service, alcs_service_cb cb);
int iot_alcs_unregister_service(void* service);

//see alcs_svr_auth_param_t
int iot_alcs_add_and_update_authkey (void* auth_info);
int iot_alcs_remove_authkey (void* auth_info);

/** 
 * @brief Send Response Message To Specific Device
 *  
 * @param [in] msg: specify the sending parameters.
 * @param [in] cb_ctx: 
 *
 * @return status.
 * @see None.
 */ 
int iot_alcs_send_rsp(alcs_rsp_msg_param_pt rsp_msg, void* cb_ctx);
    
int iot_alcs_send_notify(alcs_notify_param_pt notify);
    

void iot_alcs_start_loop (int newThread);
void iot_alcs_stop_loop ();

#ifdef __cplusplus
}
#endif

#endif
