#ifndef _IOT_EXPORT_DLCP_H_
#define _IOT_EXPORT_DLCP_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum dlcp_error_code {
    DLCP_OK,
    DLCP_FAIL,
    DLCP_PKDNEMPTY,
    DLCP_INSUFFICIENT_MEM,
    DLCP_NOTFOUND,
    DLCP_INVALIDPARAM,
    DLCP_DUPLICATE
} dlcp_error_code_t;

/**
 * @brief DLCP初始化
 *
 * @param None.
 * @return
 *    = DLCP_OK: succeeded
 *    = other :  failed 
 */
int dlcp_init(void);

/**
 * @brief DLCP反初始化
 *        调用后DLCP释放资源
 *
 * @param None.
 * @return None. 
 */
void dlcp_deinit(void);

/**
 * @brief 控制器数据的接收回调函数
 *
 * @param[in] data:接收到的数据
 * @param[in] len :接收到的数据长度
 * @param[in] ctx :保存上下文信息指针，调用dlcp_sendrsp回复命令需要传递给DLCP
 *
 * @return None. 
 */
typedef void (*dlcp_receiver) (const char* data, int len, void* ctx);

/**
 * @brief 设置控制器数据接收回调函数指针给DLCP
 *
 * @param[in] receiver:控制器数据的接收回调函数指针
 *
 * @return None. 
 */
void dlcp_set_receiver (dlcp_receiver receiver);


/**
 * @brief 主动向DLCP控制器上传数据或者事件通知
 * @param[in] data 待上传的数据
 * @param[in] len  待上传数据的长度
 * @return
 *    = DLCP_OK: succeeded
 *    = other :  failed 
 */
int dlcp_upload (const char* data, int len);

/**
 * @brief 收到DLCP控制器数据后发送响应
 * @param[in] data 待回复的数据
 * @param[in] len  待回复数据长度
 * @param[in] ctx  上下文信息的指针，dlcp_receiver的第三个参数
 * @see  dlcp_receiver
 * @return
 *    = DLCP_OK: succeeded
 *    = other :  failed 
 */
int dlcp_sendrsp (const char* data, int len, void* ctx);

/**
 * @brief 启动DLCP Device SDK处理线程
 *        初始化和接收处理函数注册完成后，需要启动处理线程
 * @param None.
 * @return None.
 */
void dlcp_start_loop ();

/**
 * @brief 停止DLCP Device SDK处理线程
 *        调用dlcp_deinit前需要先停止DLCP Device SDK处理线程
 * @param None.
 * @return None.
 */
void dlcp_stop_loop ();

#ifdef __cplusplus
}
#endif

#endif
