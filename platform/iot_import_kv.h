/*
 * Copyright (c) 2014-2016 Alibaba Group. All rights reserved.
 * License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __IOT_IMPORT_KV_H__
#define __IOT_IMPORT_KV_H__
#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>

/**
 * @brief ¿¿key-value .
 *
 * @param [in] key: @n Key¿
 * @param [in] value_buf: @n ¿¿value¿¿¿¿
 * @param [in,out] buf_len: @n ¿¿¿¿¿¿¿¿¿¿¿¿value¿¿¿
 *
 * @retval  < 0 : Fail.
 * @retval  = 0 : Success.
 * @see None.
 */
int HAL_Kv_Get (const char* key, void* value_buf, int* buf_len);

/**
 * @brief ¿¿key-value .
 *
 * @param [in] key: @n Key¿
 * @param [in] value_buf: @n ¿¿value¿¿¿
 * @param [in] buf_len: @n value¿¿¿
 *
 * @retval  < 0 : Fail.
 * @retval  = 0 : Success.
 * @see None.
 */
int HAL_Kv_Set (const char* key, const void* value_buf, int value_len);

/**
 * @brief ¿¿¿¿key-value .
 *
 * @param [in] key: @n ¿¿¿¿Key¿
 *
 * @retval  < 0 : Fail.
 * @retval  = 0 : Success.
 * @see None.
 */
int HAL_Kv_Del (const char *key);

#endif  /* SIM7000C_DAM */

#if defined(__cplusplus)
}
#endif
#endif  /* __IOT_IMPORT_KV_H__ */
