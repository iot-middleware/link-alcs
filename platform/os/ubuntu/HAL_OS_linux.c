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



#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>
#include <pthread.h>
#include <unistd.h>
//#include <sys/prctl.h>
#include <sys/time.h>
#include <semaphore.h>
#include <errno.h>

#include <net/if.h>       // struct ifreq
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <signal.h>

#include "iot_import.h"
#include "kv.h"

#define HAL_DEBUG
#ifdef HAL_DEBUG
#define hal_printf     printf
#else
#define hal_printf(...)
#endif

void *HAL_MutexCreate(void)
{
    int err_num;
    pthread_mutexattr_t attr;
    pthread_mutex_t *mutex = (pthread_mutex_t *)HAL_Malloc(sizeof(pthread_mutex_t));
    if (NULL == mutex) {
        return NULL;
    }
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    if (0 != (err_num = pthread_mutex_init(mutex, &attr))) {
        perror("create mutex failed");
        HAL_Free(mutex);
        return NULL;
    }

    return mutex;
}

void HAL_MutexDestroy(_IN_ void *mutex)
{
    int err_num;
    if (0 != (err_num = pthread_mutex_destroy((pthread_mutex_t *)mutex))) {
        perror("destroy mutex failed");
    }

    HAL_Free(mutex);
}

void HAL_MutexLock(_IN_ void *mutex)
{
    int err_num;
    if (0 != (err_num = pthread_mutex_lock((pthread_mutex_t *)mutex))) {
        perror("lock mutex failed");
    }
}

void HAL_MutexUnlock(_IN_ void *mutex)
{
    int err_num;
    if (0 != (err_num = pthread_mutex_unlock((pthread_mutex_t *)mutex))) {
        perror("unlock mutex failed");
    }
}

void *HAL_Malloc(_IN_ uint32_t size)
{
    return malloc(size);
}

void HAL_Free(_IN_ void *ptr)
{
    free(ptr);
}

uint64_t HAL_UptimeMs(void)
{
    uint64_t            time_ms;
    struct timespec     ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_ms = (ts.tv_sec * 1000) + (ts.tv_nsec / 1000 / 1000);

    return time_ms;
}

void HAL_SleepMs(_IN_ uint32_t ms)
{
    usleep(1000 * ms);
}

void HAL_Srandom(uint32_t seed)
{
    srandom(seed);
}

uint32_t HAL_Random(uint32_t region)
{
    return (region > 0) ? (random() % region) : 0;
}

int HAL_Snprintf(_IN_ char *str, const int len, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);

    return rc;
}

int HAL_Vsnprintf(_IN_ char *str, _IN_ const int len, _IN_ const char *format, va_list ap)
{
    return vsnprintf(str, len, format, ap);
}

void HAL_Printf(_IN_ const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    fflush(stdout);
}

int HAL_GetModuleID(char mid_str[MID_STRLEN_MAX])
{
    memset(mid_str, 0x0, MID_STRLEN_MAX);
#ifdef __UBUNTU_SDK_DEMO__
    strcpy(mid_str, "example.demo.module-id");
#endif
    return strlen(mid_str);
}

int HAL_ThreadCreate(
            _OU_ void **thread_handle,
            _IN_ void *(*work_routine)(void *),
            _IN_ void *arg,
            _IN_ hal_os_thread_param_t *hal_os_thread_param,
            _OU_ int *stack_used)
{
    int ret = -1;
    *stack_used = 0;

    ret = pthread_create((pthread_t *)thread_handle, NULL, work_routine, arg);

    return ret;
}

void HAL_ThreadDetach(_IN_ void *thread_handle)
{
    pthread_detach((pthread_t)thread_handle);
}

void HAL_ThreadDelete(_IN_ void *thread_handle)
{
    if (NULL == thread_handle) {
        pthread_exit(0);
    } else {
        /*main thread delete child thread*/
        pthread_cancel((pthread_t)thread_handle);
    }
}


void *HAL_SemaphoreCreate(void)
{
    sem_t *sem = (sem_t *)malloc(sizeof(sem_t));
    if (NULL == sem) {
        return NULL;
    }

    if (0 != sem_init(sem, 0, 0)) {
        free(sem);
        return NULL;
    }

    return sem;
}

void HAL_SemaphoreDestroy(_IN_ void *sem)
{
    sem_destroy((sem_t *)sem);
    free(sem);
}

void HAL_SemaphorePost(_IN_ void *sem)
{
    sem_post((sem_t *)sem);
}

int HAL_SemaphoreWait(_IN_ void *sem, _IN_ uint32_t timeout_ms)
{
    if (PLATFORM_WAIT_INFINITE == timeout_ms) {
        sem_wait(sem);
        return 0;
    }

    struct timespec ts;
    int s;
    /* Restart if interrupted by handler */
    do {
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            return -1;
        }

        s = 0;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_nsec -= 1000000000;
            s = 1;
        }

        ts.tv_sec += timeout_ms / 1000 + s;

    } while (((s = sem_timedwait(sem, &ts)) != 0) && errno == EINTR);

    return (s == 0) ? 0 : -1;
}

static kv_file_t *kvfile = NULL;
int HAL_Kv_Set(const char *key, const void *val, int len)
{
    if (!kvfile) {
        kvfile = kv_open("/tmp/kvfile.db");
        if (!kvfile) {
            hal_printf ("can't open kvfile.db");
            return -1;
        }
    }

    return kv_set_blob(kvfile, (char *)key, (char *)val, len);
}

int HAL_Kv_Get(const char *key, void *buffer, int *buffer_len)
{
    if (!kvfile) {
        kvfile = kv_open("/tmp/kvfile.db");
        if (!kvfile) {
            hal_printf ("can't open kvfile.db");
            return -1;
        }
    }

    return kv_get_blob(kvfile, (char *)key, buffer, buffer_len);
}

int HAL_Kv_Del(const char *key)
{
    if (!kvfile) {
        kvfile = kv_open("/tmp/kvfile.db");
        if (!kvfile)
            return -1;
    }

    return kv_del(kvfile, (char *)key);
}
