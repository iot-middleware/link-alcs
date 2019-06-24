 /* Copyright (c) 2014-2016 Alibaba Group. All rights reserved.
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


#ifndef __COAP_PLATFORM_OS_H__
#define __COAP_PLATFORM_OS_H__
#include <stdio.h>
#ifdef COAP_USE_PLATFORM_MEMORY
#include "lite-utils.h"
#endif
#ifdef COAP_USE_PLATFORM_LOG
#include "lite-log.h"
#endif
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#ifdef COAP_USE_PLATFORM_MEMORY
#define coap_malloc(size) LITE_malloc(size, MEM_MAGIC, "CoAP")
#else
#define coap_malloc malloc
#endif

#ifdef COAP_USE_PLATFORM_MEMORY
#define coap_free LITE_free
#else
#define coap_free free
#endif

#ifdef COAP_USE_PLATFORM_LOG
#define COAP_TRC   log_debug
#define COAP_DUMP  log_debug
#define COAP_DEBUG log_debug
#define COAP_INFO  log_info
#define COAP_WARN  log_warning
#define COAP_ERR   log_err
#define set_coap_log(v) {}
#else
#define COAP_LOG_DUMP 0
#define COAP_LOG_TRACE 1
#define COAP_LOG_DEBUG 2
#define COAP_LOG_INFO 3
#define COAP_LOG_WARING 4
#define COAP_LOG_ERR 5

extern int coap_level;
extern char* coap_level_desc[];
#define set_coap_log(v) \
    {if (v >= COAP_LOG_DUMP && v <= COAP_LOG_ERR) coap_level = v; }

#define coap_log(level, ...) \
    if (level >= coap_level && level <= COAP_LOG_ERR) {\
        fprintf(stderr, "\r\n[%lld][%s][%s LINE #%d]   ", HAL_UptimeMs(), coap_level_desc[level], __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);\
    }

#define coap_dump(...)\
{\
    fprintf(stderr, __VA_ARGS__);\
}

#define COAP_DUMP(...)  coap_log(COAP_LOG_DUMP,__VA_ARGS__)
#define COAP_TRC(...)  coap_log(COAP_LOG_TRACE, __VA_ARGS__)
#define COAP_DEBUG(...)  coap_log(COAP_LOG_DEBUG,__VA_ARGS__)
#define COAP_INFO(...)  coap_log(COAP_LOG_INFO,__VA_ARGS__)
#define COAP_WARN(...)  coap_log(COAP_LOG_WARING,__VA_ARGS__)
#define COAP_ERR(...)  coap_log(COAP_LOG_ERR,__VA_ARGS__)
#endif

int platform_is_multicast(const char *ip_str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
