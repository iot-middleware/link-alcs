#include <stdio.h>
#include <string.h>
#include "alcs_coap.h"
#include "iot_import.h"
#include "CoAPPlatform.h"
#include "CoAPResource.h"
#include "alcs_api_internal.h"
#include "lite-list.h"

#ifdef SHARE_COAP_CONTEXT 
#include "CoAPServer.h"
#endif

#define MAX_PATH_CHECKSUM_LEN (5)
typedef struct
{
    char path[MAX_PATH_CHECKSUM_LEN];
    CoAPRecvMsgHandler cb;
    struct list_head   lst;
} resource_cb_item;

static LIST_HEAD(resource_cb_head);
static void *context_mutex = NULL;

static uint32_t tokenSeed = 0;
uint32_t getToken ()
{
    uint32_t token;
    HAL_MutexLock(context_mutex);
    if (tokenSeed == 0) {
        HAL_Srandom ((uint32_t)HAL_UptimeMs());
        token = tokenSeed = HAL_Random (0xffffffff);
    } else {
        token = ++tokenSeed;
    }
    HAL_MutexUnlock(context_mutex);
    
    return token;
}

void alcs_msg_init(CoAPContext *ctx, CoAPMessage *message, int code, unsigned char type,
	int keep, CoAPLenString *payload, void *userdata)
{
    CoAPMessage_init (message);
    message->header.code = code;
    message->header.type = type;
    message->user = userdata;
    message->payload = payload->data;
    message->payloadlen = payload->len;
    if (keep) {
        CoAPMessage_keep (message);
    }

    message->header.msgid = CoAPMessageId_gen (ctx);
    message->header.tokenlen = 4;
    uint32_t token = getToken ();
    memcpy (&message->token, &token, 4);
}

void alcs_msg_deinit(CoAPMessage *message)
{
    CoAPMessage_destory (message);
}

static int do_sendmsg (CoAPContext *context, NetworkAddr* addr, CoAPMessage *message, char observe, unsigned short msgid, CoAPLenString* token)
{
    int ret = ALCS_SUCCESS;
    if (!context || !addr || !message) {
        return ALCS_ERR_NULL;
    }

    if (msgid == 0) {
        message->header.msgid = CoAPMessageId_gen (context);
    } else {
        message->header.msgid = msgid;
    }

    if (observe == 0) {
        CoAPUintOption_add (message, COAP_OPTION_OBSERVE, observe);
    }

    if (token) {
        message->header.tokenlen = token->len;
        memcpy (&message->token, token->data, token->len);
    }

    ret = CoAPMessage_send (context, addr, message);
    alcs_msg_deinit(message);
    return ret;
}

int alcs_sendmsg(CoAPContext *context, NetworkAddr* addr, CoAPMessage *message, char observe, CoAPSendMsgHandler handler)
{
    message->handler = handler;
    return do_sendmsg (context, addr, message, observe, message->header.msgid, NULL);
}

//msgid & token从接收到CoAPMessage获取
//若发送
int alcs_sendrsp(CoAPContext *context, NetworkAddr* addr, CoAPMessage *message, char observe, unsigned short msgid, CoAPLenString* token)
{
    return do_sendmsg (context, addr, message, observe, msgid, token);
}

//observe
int alcs_observe_notify(CoAPContext *context, const char *path, CoAPLenString* payload)
{
    int  needAuth = alcs_resource_need_auth (context, path);
    COAP_DEBUG("alcs_observe_notify, payload: %.*s", payload->len, payload->data);
    return CoAPObsServer_notify (context, path, payload->data, payload->len,
#ifdef USE_ALCS_SECURE
                                 needAuth? &observe_data_encrypt : NULL);

#else
        NULL);
#endif
}

static void send_err_rsp (CoAPContext* ctx, NetworkAddr*addr, int code, CoAPMessage* fromMsg)
{
    CoAPMessage sendMsg;
    CoAPLenString payload = {0};
    alcs_msg_init (ctx, &sendMsg, code, COAP_MESSAGE_TYPE_ACK, 0, &payload, NULL);
    CoAPLenString token = {fromMsg->header.tokenlen, fromMsg->token};
    alcs_sendrsp (ctx, addr, &sendMsg, 1, fromMsg->header.msgid, &token);
}

static void recv_msg_handler (CoAPContext *context, const char *path, NetworkAddr *remote, CoAPMessage *message)
{
    unsigned int obsVal;
    resource_cb_item *node = NULL, *next = NULL;
    char path_calc[MAX_PATH_CHECKSUM_LEN] = {0};
    CoAPPathMD5_sum (path, strlen(path), path_calc, MAX_PATH_CHECKSUM_LEN);

    list_for_each_entry_safe(node, next, &resource_cb_head, lst, resource_cb_item) {
        if (0 == memcmp(path_calc, node->path, MAX_PATH_CHECKSUM_LEN)) {
            if (CoAPUintOption_get (message, COAP_OPTION_OBSERVE, &obsVal) == ALCS_SUCCESS) {
                if (obsVal == 0) {
                    CoAPObsServer_add (context, path, remote, message);
                }
            }
            COAP_INFO("recv_msg_handler call callback");
            node->cb (context, path, remote, message);
            return;
        }
    }

    COAP_ERR ("receive unknown request, path:%s", path);
    send_err_rsp (context, remote, COAP_MSG_CODE_401_UNAUTHORIZED, message);
}

//resource
int alcs_resource_register(CoAPContext *context, const char* pk, const char* dn, const char *path, unsigned short permission,
            unsigned int ctype, unsigned int maxage, char needAuth, CoAPRecvMsgHandler callback)
{
    COAP_INFO("ALCS Resource Register: %s",path);
	
    if (!needAuth) {
        resource_cb_item* item = (resource_cb_item*)coap_malloc (sizeof(resource_cb_item));
        CoAPPathMD5_sum (path, strlen(path), item->path, MAX_PATH_CHECKSUM_LEN);
        item->cb = callback;
        list_add_tail(&item->lst, &resource_cb_head);

        return CoAPResource_register (context, path, permission, ctype, maxage, &recv_msg_handler);
    } else {
#ifdef USE_ALCS_SECURE
        return alcs_resource_register_secure (context, pk, dn, path, permission, ctype, maxage, callback);
#else
        return -1;
#endif
    }
}

resource_cb_item* get_resource_by_path (CoAPContext *context, const char *path)
{
    resource_cb_item *node = NULL, *next = NULL;
    char path_calc[MAX_PATH_CHECKSUM_LEN] = {0};
    CoAPPathMD5_sum (path, strlen(path), path_calc, MAX_PATH_CHECKSUM_LEN);
    
    list_for_each_entry_safe(node, next, &resource_cb_head, lst, resource_cb_item) {
        if (memcmp(path_calc, node->path, MAX_PATH_CHECKSUM_LEN) == 0){
            return node;
        }
    }

    return NULL;
}

int alcs_resource_unregister(CoAPContext *context, const char *path)
{
    resource_cb_item* node = get_resource_by_path (context, path);
    if (!node) {
#ifdef USE_ALCS_SECURE
        return alcs_resource_unregister_secure (context, path);
#else
        return -1;
#endif
    }

    list_del (&node->lst);
    CoAPResource_unregister(context, path); 
    coap_free (node);
    return ALCS_SUCCESS;
}

int alcs_resource_need_auth (CoAPContext *context, const char *path)
{
    return get_resource_by_path (context, path) == NULL;
}

#define RUNNING 0x1
#define TORUN 0x2
typedef struct {
    CoAPContext* ctx;
    char flag;
    int refCount;
} ALCSContext;

ALCSContext g_alcs_ctx = {0};

extern void on_auth_timer (void* arg);

void* thread_routine (void * arg)
{
    COAP_DEBUG("thread_routine");

    ALCSContext*ctx = (ALCSContext*)arg;
    HAL_MutexLock(context_mutex);
    ctx->flag |= RUNNING;
    HAL_MutexUnlock(context_mutex);

    while (ctx->flag & TORUN) {
        CoAPMessage_cycle (ctx->ctx);
#ifdef USE_ALCS_SECURE
        on_auth_timer (ctx->ctx);
#endif
    }

    HAL_MutexLock(context_mutex);
    if (g_alcs_ctx.refCount <= 0) {
        CoAPContext_free (ctx->ctx);
        ctx->ctx = NULL;
    }
    ctx->flag &= ~RUNNING;
    HAL_MutexUnlock(context_mutex);

    COAP_INFO("thread_routine quit");

    return NULL;
}

CoAPContext *alcs_context_create(CoAPInitParam *param)
{
    HAL_MutexLock(context_mutex);
    if (!g_alcs_ctx.refCount) {   
        g_alcs_ctx.ctx = CoAPContext_create (param);
        COAP_INFO("CoAPContext_create return :%p", g_alcs_ctx.ctx);
        g_alcs_ctx.flag = 0;
    }
    ++ g_alcs_ctx.refCount;
    HAL_MutexUnlock(context_mutex);

    return g_alcs_ctx.ctx;
}

void alcs_context_free(CoAPContext *ctx)
{
    HAL_MutexLock(context_mutex);
    if (g_alcs_ctx.refCount > 0) {
        -- g_alcs_ctx.refCount;
        if (g_alcs_ctx.refCount <= 0) {
            if (!(g_alcs_ctx.flag & RUNNING)) {
                CoAPContext_free (g_alcs_ctx.ctx);
                g_alcs_ctx.ctx = NULL;
                g_alcs_ctx.flag = 0;
            }
        }
    }
    HAL_MutexUnlock(context_mutex);

}

#ifdef SHARE_COAP_CONTEXT
CoAPContext* alcs_context_init(CoAPInitParam *param)
{
    HAL_MutexLock(context_mutex);
    if (!g_alcs_ctx.refCount) {
        g_alcs_ctx.ctx = CoAPServer_init();
        g_alcs_ctx.flag = 0;
        COAP_INFO("CoAPServer_init return :%p", g_alcs_ctx.ctx);
    }
    ++ g_alcs_ctx.refCount;
    HAL_MutexUnlock(context_mutex);

    return g_alcs_ctx.ctx;
}

void alcs_context_deinit()
{
    HAL_MutexLock(context_mutex);
    if (g_alcs_ctx.refCount > 0) {
        -- g_alcs_ctx.refCount;
        if (g_alcs_ctx.refCount <= 0) {
            if (!(g_alcs_ctx.flag & RUNNING)) {
                CoAPServer_deinit (g_alcs_ctx.ctx);
                g_alcs_ctx.ctx = NULL;
                g_alcs_ctx.flag = 0;
            }
        }
    }
    HAL_MutexUnlock(context_mutex);
}

CoAPContext * alcs_get_context()
{
    return g_alcs_ctx.ctx;
}

#endif

void alcs_start_loop (CoAPContext *ctx, int newThread)
{
    void * handle = NULL;

    HAL_MutexLock(context_mutex);
    if (!(g_alcs_ctx.flag & TORUN)) {
        g_alcs_ctx.flag |= TORUN;
        HAL_MutexUnlock(context_mutex);

        int stack_used = 0;
        if (!newThread || 0 != HAL_ThreadCreate (&handle, thread_routine, &g_alcs_ctx, NULL, &stack_used)) {
            COAP_INFO ("call routine directly");
            thread_routine (&g_alcs_ctx);
        }
    } else {
        HAL_MutexUnlock(context_mutex);
    }
}

void alcs_stop_loop (CoAPContext *ctx)
{
    HAL_MutexLock(context_mutex);
    g_alcs_ctx.flag &= ~TORUN;
    HAL_MutexUnlock(context_mutex);
}

void alcs_init ()
{
    if (!context_mutex) {
        context_mutex = HAL_MutexCreate();
    }
}

void alcs_deinit()
{
    resource_cb_item* del_item = NULL;

    list_for_each_entry(del_item,&resource_cb_head,lst,resource_cb_item)
    {
        list_del(&del_item->lst);
        coap_free(del_item);
        del_item = list_entry(&resource_cb_head,resource_cb_item,lst);
    }
}

static int path_2_option(const char *uri, CoAPMessage *message)
{
    const char *ptr     = NULL;
    const char *pstr    = NULL;
    char  path[COAP_MSG_MAX_PATH_LEN]  = {0};

    if (256 < strlen(uri)) {
        COAP_ERR("The uri length is too loog,len = %d", (int)strlen(uri));
        return ALCS_ERR_INVALID_LENGTH;
    }
    COAP_DEBUG("The uri is %s", uri);
    ptr = pstr = uri;
    while ('\0' != *ptr) {
        if ('/' == *ptr) {
            if (ptr != pstr) {
                memset(path, 0x00, sizeof(path));
                strncpy(path, pstr, ptr - pstr);
                COAP_DEBUG("path: %s,len=%d", path, (int)(ptr - pstr));
                CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                                  (unsigned char *)path, (int)strlen(path));
            }
            pstr = ptr + 1;

        }
        if ('\0' == *(ptr + 1) && '\0' != *pstr) {
            memset(path, 0x00, sizeof(path));
            strncpy(path, pstr, sizeof(path) - 1);
            COAP_DEBUG("path: %s,len=%d", path, (int)strlen(path));
            CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                              (unsigned char *)path, (int)strlen(path));
        }
        ptr ++;
    }
    return ALCS_SUCCESS;
}

int alcs_msg_setAddr (CoAPMessage *message, const char* path, const char* query)
{
    if (NULL == path || NULL == message) {
        COAP_ERR("Invalid paramter p_path %p, p_message %p", path, message);
        return ALCS_ERR_INVALID_PARAM;
    }

    if (255 < strlen(path)) {
        COAP_ERR("The uri length is too loog,len = %d", (int)strlen(path));
        return ALCS_ERR_INVALID_LENGTH;
    }

    int rt = path_2_option (path, message);
    int len = query? strlen(query) : 0;
    if (len) {
        CoAPStrOption_add (message, COAP_OPTION_URI_QUERY, (unsigned char*)query, len);
    }

    return rt;
}

