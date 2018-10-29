#include "iot_import.h"
#include "alcs_timer.h"
#include <sys/select.h>

typedef struct alcs_timer_item
{
    alcs_timer_cb cb;
    void*    user_data;
    int      timeout;
    int      count;
    void*    next;
} alcs_timer_item_t;

static void*    timer_thread = NULL;
static int      g_timer_thread_running = 0;
static void *   timer_thread_routine(void *param);
static void *   g_mutex = NULL;
static alcs_timer_item_t head = {0};
static const int one_tick_value = 30;

int alcs_timer_init ()
{
    int stack_used = 0;
    if (g_timer_thread_running) {
        return -1;
    }

    g_timer_thread_running = 1;
    g_mutex = HAL_MutexCreate();

    if (!g_mutex) {
        return -1;
    }

    HAL_ThreadCreate(&timer_thread, timer_thread_routine, NULL, NULL, &stack_used);
    return 0;
}

void alcs_timer_deinit ()
{
    g_timer_thread_running = 0;
}

static void timer_dispatch ()
{
    alcs_timer_item_t* p, *q;
    alcs_timer_cb cb = NULL;
    void*    user_data = NULL;

    HAL_MutexLock(g_mutex);
    q = &head;
    p = q->next;
    while (p) {
        -- p->count;
        if (!p->count) {
            q->next = p->next;
            cb = p->cb;
            user_data = p->user_data;
            HAL_Free (p);
            break;
        }
	q = q->next;
        p = p->next;
    }
    HAL_MutexUnlock(g_mutex);

    if (cb) {
        cb (user_data);
    }
}

static void timer_insert (alcs_timer_item_t* item)
{
    alcs_timer_item_t* p;
    if (!item) {
        return;
    }

    HAL_MutexLock(g_mutex);
    p = &head;
    while (p) {
        if (!p->next) {
            p->next = item;
            item->next = NULL;
            break;
        }
        p = p->next;
    }
    HAL_MutexUnlock(g_mutex);
}

static int timer_set (alcs_timer_item_t* item, int value)
{
    int ret = -1;
    alcs_timer_item_t* p;

    if (!item) {
        return ret;
    }

    HAL_MutexLock(g_mutex);
    p = &head;
    while (p) {
        if (p == item) {
            if (p->timeout > 0 && value > 0) {
                break;
            } 
            ret = 0;       
            p->timeout = value;
            p->count = (value + one_tick_value -1) /one_tick_value;
            break;
        }
        p = p->next;
    }
    HAL_MutexUnlock(g_mutex);    
    return ret;
}

static int timer_del (alcs_timer_item_t* item)
{
    int rt = -1;
    if (!item) {
        return -1;
    }

    HAL_MutexLock(g_mutex);
    alcs_timer_item_t* p = &head;
    while (p) {
        if (p->next == item) {
            p->next = item->next;
            HAL_Free (item);
            rt = 0;
            break;
        }
        p = p->next;
    }
    HAL_MutexUnlock(g_mutex);

    return rt;
}

static void *timer_thread_routine(void *param)
{
    struct timeval tv;

    while (g_timer_thread_running)  {    
        tv.tv_sec = 0;
        tv.tv_usec = one_tick_value * 1000;
        select(0, NULL, NULL, NULL, &tv);
        timer_dispatch ();
    }

    HAL_MutexDestroy (g_mutex);
    g_mutex = NULL;
    return NULL;
}

void *alcs_timer_create(const char *name, alcs_timer_cb func, void *user_data)
{
    alcs_timer_item_t* p;
    if (!func) {
        return NULL;
    }

    p = HAL_Malloc (sizeof(alcs_timer_item_t));
    if (p) {
        p->cb = func;
        p->user_data = user_data;
        p->timeout = 0;
        p->count = 0;
    }
    timer_insert (p);

    return p;       
}

int alcs_timer_start(void *timer, int ms)
{
    if (!timer || ms <= 0) {
        return -1;
    }

    return timer_set (timer, ms);
}

int alcs_timer_stop(void *timer)
{
    return timer_set (timer, 0);
}

int alcs_timer_delete(void *timer)
{
    return timer_del (timer);
}
