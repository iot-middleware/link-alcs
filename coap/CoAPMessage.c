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



#include "stdio.h"
#include "CoAPExport.h"
#include "CoAPSerialize.h"
#include "CoAPDeserialize.h"
#include "CoAPResource.h"
#include "CoAPObserve.h"
#include "iot_import.h"
#include "CoAPPlatform.h"
#include "CoAPInternal.h"
#include "lite-list.h"



#define COAPAckMsg(header) \
    ((header.code == COAP_MSG_CODE_EMPTY_MESSAGE) \
     &&(header.type == COAP_MESSAGE_TYPE_ACK))

#define CoAPRespMsg(header)\
    ((header.code >= 0x40) && (header.code < 0xc0))

#define CoAPPingMsg(header)\
    ((header.code == COAP_MSG_CODE_EMPTY_MESSAGE)\
     && (header.type == COAP_MESSAGE_TYPE_CON))

#define CoAPResetMsg(header)\
    (header.type == COAP_MESSAGE_TYPE_RST)

#define CoAPCONRespMsg(header)\
    ((header.code == COAP_MSG_CODE_205_CONTENT) \
     && (header.type == COAP_MESSAGE_TYPE_CON))

#define CoAPReqMsg(header)\
    ((1 <= header.code) && (32 > header.code))


#define COAP_WAIT_TIME_MS       2000
#define COAP_MAX_MESSAGE_ID     65535
#define COAP_MAX_RETRY_COUNT    4
#define COAP_ACK_TIMEOUT        2
#define COAP_ACK_RANDOM_FACTOR  1
#define COAP_MAX_TRANSMISSION_SPAN   10

int CoAPOption_sort(CoAPMessage *message)
{
    int opt_count = message->optcount;
    CoAPMsgOption *options = message->options;
    CoAPMsgOption temp;
    int i, j;

    if (opt_count <= 1) {
        return COAP_SUCCESS;
    }

    for (i = 1; i < opt_count; i++) {
        if (options[i].num < options[i-1].num) {
            memcpy((void *)&temp, (void *)&options[i], sizeof(CoAPMsgOption));
            for (j = i - 1; j >= 0 && options[j].num > temp.num; j--) {
                memcpy((void *)&options[j + 1], (void *)&options[j], sizeof(CoAPMsgOption));
            }
            memcpy((void *)&options[j + 1], (void *)&temp, sizeof(CoAPMsgOption));
        }
    }

    return COAP_SUCCESS;
}

int CoAPOption_delta(CoAPMessage *message)
{
    int i = 0;
    int opt_count = message->optcount;
    CoAPMsgOption *options = message->options;
    unsigned short opt_num = 0;

    if (opt_count <= 1) {
        return COAP_SUCCESS;
    }

    for (i = 0; i < opt_count - 1; i++) {
        if (options[i].num > options[i+1].num) {
            COAP_ERR("options are not sorted");
            return COAP_ERROR_INVALID_PARAM;
        }
    }

    message->optdelta = 0;
    for (i = 0; i < opt_count; i++) {
        opt_num = options[i].num;
        options[i].num = opt_num - message->optdelta;
        message->optdelta = opt_num;
    }
    return COAP_SUCCESS;
}

int CoAPStrOption_add(CoAPMessage *message, unsigned short optnum, unsigned char *data, unsigned short datalen)
{
    unsigned char *ptr = NULL;
    if (COAP_MSG_MAX_OPTION_NUM <= message->optcount) {
        COAP_ERR("Too much option, max allowed %d, cur hava %d", COAP_MSG_MAX_OPTION_NUM, message->optcount);
        return COAP_ERROR_INVALID_PARAM;
    }

    /* coap options will be sorted in coap send message */
    message->options[message->optcount].num = optnum;
    message->options[message->optcount].len = datalen;
    ptr = (unsigned char *)coap_malloc(datalen);
    if (NULL == ptr) {
        return COAP_ERROR_MALLOC;
    }
    memset(ptr, 0x00, datalen);
    memcpy(ptr, data, datalen);
    message->options[message->optcount].val = ptr;
    message->optcount ++;

    return COAP_SUCCESS;

}

int CoAPStrOption_get(CoAPMessage *message, unsigned short optnum, unsigned char *data, unsigned short *datalen)
{
    unsigned char index = 0;

    for(index=0; index<message->optcount; index++){
        if(message->options[index].num == optnum){
            if(*datalen >= message->options[index].len){
                memcpy(data, message->options[index].val, message->options[index].len);
                *datalen = message->options[index].len;
                return COAP_SUCCESS;
            }else{
                return COAP_ERROR_INVALID_LENGTH;
            }
        }
    }

    return COAP_ERROR_NOT_FOUND;

}


int CoAPUintOption_add(CoAPMessage *message, unsigned short  optnum, unsigned int data)
{
    unsigned char *ptr = NULL;
    if (COAP_MSG_MAX_OPTION_NUM <= message->optcount) {
        return COAP_ERROR_INVALID_PARAM;
    }

    // message->options[message->optcount].num = optnum - message->optdelta;
    message->options[message->optcount].num = optnum;

    if (0 == data) {
        message->options[message->optcount].len = 0;
    } else if (255 >= data) {
        message->options[message->optcount].len = 1;
        ptr = (unsigned char *)coap_malloc(1);
        if (NULL != ptr) {
            *ptr = (unsigned char)data;
        }
    } else if (65535 >= data) {
        message->options[message->optcount].len = 2;
        ptr  = (unsigned char *)coap_malloc(2);
        if (NULL != ptr) {
            *ptr     = (unsigned char)((data & 0xFF00) >> 8);
            *(ptr + 1) = (unsigned char)(data & 0x00FF);
        }
    } else {
        message->options[message->optcount].len = 4;
        ptr   = (unsigned char *)coap_malloc(4);
        if (NULL != ptr) {
            *ptr     = (unsigned char)((data & 0xFF000000) >> 24);
            *(ptr + 1) = (unsigned char)((data & 0x00FF0000) >> 16);
            *(ptr + 2) = (unsigned char)((data & 0x0000FF00) >> 8);
            *(ptr + 3) = (unsigned char)(data & 0x000000FF);
        }
    }
    message->options[message->optcount].val = ptr;
    // message->optdelta = optnum;
    message->optcount += 1;

    return COAP_SUCCESS;
}

int CoAPUintOption_get(CoAPMessage *message,
                              unsigned short  optnum,
                              unsigned int *data)
{

    unsigned char index = 0;

    for(index=0; index<message->optcount; index++){
        if(message->options[index].num == optnum){
            int byte = 0;
            switch(message->options[index].len){
                case 1:
                    *data |= message->options[index].val[byte++];
                    break;
                case 2:
                    *data |= (message->options[index].val[byte++] << 8);
                    *data |= message->options[index].val[byte++];
                    break;
                case 3:
                    *data |= (message->options[index].val[byte++] << 16);
                    *data |= (message->options[index].val[byte++] << 8);
                    *data |= message->options[index].val[byte++];
                    break;
                case 4:
                    *data |= (message->options[index].val[byte++] << 24);
                    *data |= (message->options[index].val[byte++] << 16);
                    *data |= (message->options[index].val[byte++] << 8);
                    *data |= message->options[index].val[byte++];
                    break;
                default:
                    *data = 0;
                    break;
            }
            return COAP_SUCCESS;
        }
    }

    return COAP_ERROR_NOT_FOUND;
}


int CoAPOption_present(CoAPMessage *message, unsigned short option)
{
    unsigned char index = 0;


    for (index = 0; index < message->optcount; index++){
        if(message->options[index].num == option){
            return COAP_SUCCESS;
        }
    }
    return COAP_ERROR_NOT_FOUND;
}

unsigned short CoAPMessageId_gen(CoAPContext *context)
{
    CoAPIntContext *ctx = (CoAPIntContext *)context;
    unsigned short msg_id = 0;
    HAL_MutexLock(ctx->mutex);
    msg_id = ((COAP_MAX_MESSAGE_ID == ctx->message_id)  ? (ctx->message_id = 1) : ctx->message_id++);
    HAL_MutexUnlock(ctx->mutex);
    return msg_id;
}


int CoAPMessageId_set(CoAPMessage *message, unsigned short msgid)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->header.msgid = msgid;
    return COAP_SUCCESS;
}

int CoAPMessageId_get(CoAPMessage *message, unsigned short *msgid)
{
    if(NULL == message || NULL == msgid){
        return COAP_ERROR_NULL;
    }
    *msgid = message->header.msgid;

    return COAP_SUCCESS;
}


int CoAPMessageType_set(CoAPMessage *message, unsigned char type)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    if (COAP_MESSAGE_TYPE_CON != type && COAP_MESSAGE_TYPE_NON != type
        && COAP_MESSAGE_TYPE_ACK != type && COAP_MESSAGE_TYPE_RST != type) {
        return COAP_ERROR_INVALID_PARAM;
    }

    message->header.type = type;
    return COAP_SUCCESS;
}

int CoAPMessageType_get(CoAPMessage *message, unsigned char *type)
{
    if (NULL == message || NULL == type) {
        return COAP_ERROR_NULL;
    }

    *type = message->header.type;
    return COAP_SUCCESS;
}


int CoAPMessageCode_set(CoAPMessage *message, CoAPMessageCode code)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->header.code  = code;
    return COAP_SUCCESS;
}

int CoAPMessageCode_get(CoAPMessage *message, CoAPMessageCode *code)
{
    if (NULL == message || NULL == code) {
        return COAP_ERROR_NULL;
    }
    *code = message->header.code;
    return COAP_SUCCESS;
}

int CoAPMessageToken_set(CoAPMessage *message, unsigned char *token,
                         unsigned char tokenlen)
{
    if (NULL == message || NULL == token) {
        return COAP_ERROR_NULL;
    }
    if (COAP_MSG_MAX_TOKEN_LEN < tokenlen) {
        return COAP_ERROR_INVALID_LENGTH;
    }
    memcpy(message->token, token, tokenlen);
    message->header.tokenlen = tokenlen;

    return COAP_SUCCESS;
}

 int CoAPMessageToken_get(CoAPMessage *message, unsigned char *token,
                          unsigned char *tokenlen)
{
     if (NULL == message || NULL == token || NULL == tokenlen) {
         return COAP_ERROR_NULL;
     }
     if (*tokenlen < message->header.tokenlen) {
         return COAP_ERROR_INVALID_LENGTH;
     }

     memcpy(token, message->token, message->header.tokenlen);
     *tokenlen = message->header.tokenlen;

     return COAP_SUCCESS;
}

int CoAPMessageUserData_set(CoAPMessage *message, void *userdata)
{
    if (NULL == message || NULL == userdata) {
        return COAP_ERROR_NULL;
    }
    message->user = userdata;
    return COAP_SUCCESS;
}

int CoAPMessagePayload_set(CoAPMessage *message, unsigned char *payload,
                           unsigned short payloadlen)
{
    if (NULL == message || (0 < payloadlen && NULL == payload)) {
        return COAP_ERROR_NULL;
    }
    message->payload = payload;
    message->payloadlen = payloadlen;

    return COAP_SUCCESS;
}

int CoAPMessagePayloadlen_get(CoAPMessage *message, unsigned short *len)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }

    *len = message->payloadlen;
    return COAP_SUCCESS;
}

int CoAPMessagePayload_get(CoAPMessage *message,
                            unsigned char *buf, unsigned short buf_len)
{
    if (NULL == message || NULL == message->payload || NULL == buf) {
        return COAP_ERROR_NULL;
    }

    unsigned short payload_len = message->payloadlen;

    if (buf_len < payload_len) {
        return COAP_ERROR_DATA_SIZE;
    }

    memcpy((void *)buf, (void *)message->payload, message->payloadlen);

    return COAP_SUCCESS;
}

int CoAPMessageHandler_set(CoAPMessage *message, CoAPSendMsgHandler handler)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->handler = handler;
    return COAP_SUCCESS;
}

int CoAPMessage_init(CoAPMessage *message)
{
    int count = 0;

    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    memset(message, 0x00, sizeof(CoAPMessage));
    message->header.version    = COAP_CUR_VERSION;
    message->header.type       = COAP_MESSAGE_TYPE_ACK;
    message->header.tokenlen   = 0;
    message->header.code       = COAP_MSG_CODE_EMPTY_MESSAGE;
    message->header.msgid      = 0;
    message->payload           = NULL;
    message->payloadlen        = 0;
    message->optcount          = 0;
    message->optdelta          = 0;
    message->handler           = NULL;
    message->keep              = 0;
    for (count = 0; count < COAP_MSG_MAX_OPTION_NUM; count++) {
        message->options[count].len = 0;
        message->options[count].num = 0;
        message->options[count].val = NULL;
    }

    return COAP_SUCCESS;
}

int CoAPMessage_destory(CoAPMessage *message)
{
    int count = 0;
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }

    for (count = 0; count < COAP_MSG_MAX_OPTION_NUM; count++) {
        if (NULL != message->options[count].val) {
            coap_free(message->options[count].val);
            message->options[count].val = NULL;
        }
    }

    return COAP_SUCCESS;
}

int CoAPMessage_keep(CoAPMessage *message)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->keep = 1;

    return COAP_SUCCESS;
}

static int CoAPMessagePath_calc(CoAPMessage *message, unsigned char path_sum[COAP_PATH_DEFAULT_SUM_LEN])
{
    int index = 0;
    char path[COAP_MSG_MAX_PATH_LEN] = {0};
    char  *tmp = path;

    memset(path_sum ,0x00, COAP_PATH_DEFAULT_SUM_LEN);
    for (index = 0; index < message->optcount; index++){
        if (COAP_OPTION_URI_PATH == message->options[index].num){
            if((COAP_MSG_MAX_PATH_LEN-1) >= (tmp-path+message->options[index].len)){
                *tmp = '/';
                tmp += 1;
                strncpy((char *)tmp, (const char *)message->options[index].val, message->options[index].len);
                tmp += message->options[index].len;
            }
        }
    }
    COAP_DEBUG("Request path is %s", path);
    CoAPPathMD5_sum (path, strlen(path), (char *)path_sum, COAP_PATH_DEFAULT_SUM_LEN);

    return COAP_SUCCESS;
}

static int CoAPMessageList_add(CoAPContext *context, NetworkAddr *remote,
                    CoAPMessage *message, unsigned char *buffer, int len, unsigned char  path[COAP_PATH_DEFAULT_SUM_LEN])
{
    CoAPIntContext *ctx = (CoAPIntContext *)context;
    CoAPSendNode *node = NULL;
    node = coap_malloc(sizeof(CoAPSendNode));

    if (NULL != node) {
        memset(node, 0x00, sizeof(CoAPSendNode));
        node->acked        = 0;
        node->user         = message->user;
        node->header       = message->header;
        node->handler      = message->handler;
        node->msglen       = len;
        node->message      = buffer;
        node->timeout_val   = COAP_ACK_TIMEOUT * COAP_ACK_RANDOM_FACTOR;
        if(COAP_SUCCESS == CoAPOption_present(message, COAP_OPTION_NO_RESPONSE)){
           node->no_response = 1;
        }
        node->no_response = message->no_response;

        memcpy(&node->remote, remote, sizeof(NetworkAddr));
        if(platform_is_multicast((const char *)remote->addr) || 1 == message->keep){
            COAP_DEBUG("The message %d need keep", message->header.msgid);
            node->keep = 1;
        }
        else{
            node->keep = 0;
        }

        uint64_t tick = HAL_UptimeMs () / 1000;

        if (COAP_MESSAGE_TYPE_CON == message->header.type) {
            node->retrans_count = 0;
            node->timeout = node->timeout_val + tick;
        } else {
            node->timeout = COAP_ACK_TIMEOUT * COAP_ACK_RANDOM_FACTOR * 4 + tick;
            node->retrans_count = COAP_MAX_RETRY_COUNT;
        }
        memcpy(node->token, message->token, message->header.tokenlen);
        memcpy(node->path, path, COAP_PATH_DEFAULT_SUM_LEN);

        HAL_MutexLock(ctx->sendlist.list_mutex);
        if (ctx->sendlist.count >= ctx->sendlist.maxcount) {
            HAL_MutexUnlock(ctx->sendlist.list_mutex);
            coap_free(node);
            COAP_INFO("The send list is full");
            return COAP_ERROR_DATA_SIZE;
        } else {
            list_add_tail(&node->sendlist, &ctx->sendlist.list);
            ctx->sendlist.count ++;
            HAL_MutexUnlock(ctx->sendlist.list_mutex);
            return COAP_SUCCESS;
        }
    } else {
        return COAP_ERROR_NULL;
    }
}

void CoAPMessageToken_dump(unsigned char *token, unsigned char tokenlen)
{
    int index = 0, count = 0;
    int total = 2*COAP_MSG_MAX_TOKEN_LEN;
    char   buff[2*COAP_MSG_MAX_TOKEN_LEN+1] = {0}, *ptr = NULL;

    ptr = buff;
    for(index=0; index<tokenlen; index++){
        count = HAL_Snprintf(ptr, total, "%02X", token[index]);
        ptr += count;
        total -= count;
    }

    COAP_DEBUG("Token Len   : %d", tokenlen);
    COAP_DEBUG("Token       : %s", buff);
}

void CoAPMessage_dump(NetworkAddr *remote, CoAPMessage *message)
{
    int ret = COAP_SUCCESS;
    unsigned int ctype;
    unsigned char code, msgclass, detail;

    if(NULL == remote || NULL == message){
        return;
    }
    code = (unsigned char)message->header.code;
    msgclass = code >> 5;
    detail = code & 0x1F;

    COAP_DEBUG("*********Message Info**********");
    COAP_DEBUG("Version     : %d", message->header.version);
    COAP_DEBUG("Code        : %d.%02d(0x%x)", msgclass, detail, code);
    COAP_DEBUG("Type        : 0x%x", message->header.type);
    COAP_DEBUG("Msgid       : %d", message->header.msgid);
    COAP_DEBUG("Option      : %d", message->optcount);
    COAP_DEBUG("Payload Len : %d", message->payloadlen);

    CoAPMessageToken_dump(message->token, message->header.tokenlen);
    COAP_DEBUG("Remote      : %s:%d", remote->addr, remote->port);
    ret = CoAPUintOption_get(message, COAP_OPTION_CONTENT_FORMAT, &ctype);
    if (COAP_SUCCESS == ret && NULL != message->payload
        && (COAP_CT_APP_OCTET_STREAM != ctype && COAP_CT_APP_CBOR != ctype)) {
   //     COAP_DEBUG("Payload     : %s", message->payload);
    }

    COAP_DEBUG("********************************");

}

int CoAPMessage_send(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message)
{
    int   ret              = COAP_SUCCESS;
    unsigned short msglen  = 0;
    unsigned char  *buff   = NULL;
    unsigned short readlen = 0;
    CoAPIntContext *ctx    = NULL;
    unsigned char  path[COAP_PATH_DEFAULT_SUM_LEN]  = {0};

    if (NULL == message || NULL == context) {
        return (COAP_ERROR_INVALID_PARAM);
    }

    ctx = (CoAPIntContext *)context;

    CoAPMessagePath_calc(message, path);

    /* sort coap options */
    CoAPOption_sort(message);
    /* deal with coap option */
    CoAPOption_delta(message);

    msglen = CoAPSerialize_MessageLength(message);
    if (COAP_MSG_MAX_PDU_LEN < msglen) {
        COAP_INFO("The message length %d is too loog", msglen);
        return COAP_ERROR_DATA_SIZE;
    }

    buff = (unsigned char *)coap_malloc(msglen);
    if(NULL == buff){
        COAP_INFO("Malloc memory failed");
        return COAP_ERROR_NULL;
    }
    memset(buff, 0x00, msglen);
    msglen = CoAPSerialize_Message(message, buff, msglen);

#ifndef COAP_OBSERVE_CLIENT_DISABLE
    CoAPObsClient_delete(ctx, message);
#endif

    /* if response need, add to list */
    if (CoAPReqMsg(message->header) || CoAPCONRespMsg(message->header)) {
        COAP_DEBUG("The message id %d is CON msg, add to the list first, cur list num %d", message->header.msgid, ctx->sendlist.count);
        ret = CoAPMessageList_add(ctx, remote, message, buff, msglen, path);
        if(COAP_SUCCESS != ret){
            coap_free(buff);
            COAP_ERR("Add message %d to sendList failed", message->header.msgid);
            return ret;
        }
    } else {
        COAP_DEBUG("The message %d isn't CON msg, needless to be retransmitted",
                   message->header.msgid);
    }

    readlen = CoAPNetwork_write(ctx->p_network, remote,
                        buff, (unsigned int)msglen, ctx->waittime);
    if (msglen == readlen) {    /*Send message success*/
        COAP_DEBUG("CoAP transport write seccess");
        if (!CoAPReqMsg(message->header) && !CoAPCONRespMsg(message->header)) {
            coap_free(buff);
        }
    } else {
        COAP_ERR("CoAP transport write failed, send message %d return %d", message->header.msgid, ret);
        /* delete from send list if it's a CON message */
        if (CoAPReqMsg(message->header) || CoAPCONRespMsg(message->header)) {
            CoAPMessage_cancel(ctx, message);
        }
        else {
            coap_free(buff);
        }
        return COAP_ERROR_WRITE_FAILED;
    }

    COAP_DEBUG("---------Send a Message--------");
    CoAPMessage_dump(remote, message);
    return COAP_SUCCESS;
}

int CoAPMessage_cancel(CoAPContext * context, CoAPMessage *message)
{
    CoAPSendNode *node = NULL, *next = NULL;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (node->header.msgid == message->header.msgid) {
            list_del_init(&node->sendlist);
            ctx->sendlist.count--;
            COAP_INFO("Cancel message %d from list, cur count %d",
                            node->header.msgid, ctx->sendlist.count);
            coap_free(node->message);
            coap_free(node);
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);
    return COAP_SUCCESS;
}

int CoAPMessageId_cancel(CoAPContext * context, unsigned short msgid)
{
    CoAPSendNode *node = NULL, *next = NULL;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

	if(NULL == context || NULL == ctx->sendlist.list_mutex){
		return COAP_ERROR_NULL;
	}

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
		if(NULL != node){
	        if (node->header.msgid == msgid) {
	            list_del_init(&node->sendlist);
	            ctx->sendlist.count--;
				COAP_INFO("Cancel message %d from list, cur count %d",
	                            node->header.msgid, ctx->sendlist.count);
	            coap_free(node->message);
	            coap_free(node);

	        }
		}
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);
    return COAP_SUCCESS;
}

static int CoAPAckMessage_handle(CoAPContext *context, CoAPMessage *message)
{
    CoAPSendNode *node = NULL, *next;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (node->header.msgid == message->header.msgid) {
            node->acked = 1;
            if(CoAPRespMsg(node->header)  //CON response message
                // TODO: Implement The option value is defined as a bit map (Table 2) to achieve granular suppression
                ||(CoAPReqMsg(node->header) && 1 == node->no_response)){
                list_del_init(&node->sendlist);
                ctx->sendlist.count --;
                if(CoAPRespMsg(node->header)){
                    COAP_DEBUG("The CON response message %d receive ACK, remove it", message->header.msgid);
                }
                else{
                    COAP_DEBUG("The CON no response message %d receive ACK, remove it", message->header.msgid);
                }
                coap_free(node->message);
                coap_free(node);
            }
            HAL_MutexUnlock(ctx->sendlist.list_mutex);
            return COAP_SUCCESS;
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);

    return COAP_SUCCESS;
}

static int CoAPAckMessage_send(CoAPContext *context, NetworkAddr *remote, unsigned short msgid)
{   int ret   = COAP_SUCCESS;
    CoAPMessage message;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    CoAPMessage_init(&message);
    CoAPMessageId_set(&message, msgid);
    COAP_DEBUG("Send Ack Response Message");
    ret = CoAPMessage_send(ctx, remote, &message);
    CoAPMessage_destory(&message);
    return ret;
}

static int CoAPRestMessage_send(CoAPContext *context, NetworkAddr *remote, unsigned short msgid)
{
    int ret   = COAP_SUCCESS;
    CoAPMessage message;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    CoAPMessage_init(&message);
    CoAPMessageType_set(&message, COAP_MESSAGE_TYPE_RST);
    CoAPMessageId_set(&message, msgid);
    COAP_DEBUG("Send Rest Pong Message");
    ret = CoAPMessage_send(ctx, remote, &message);
    CoAPMessage_destory(&message);
    return ret;
}

static int CoAPErrRespMessage_send(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message, unsigned char err_code)
{
    CoAPMessage response;
    int ret   = COAP_SUCCESS;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    CoAPMessage_init(&response);
    CoAPMessageCode_set(&response, err_code);
    CoAPMessageId_set(&response, message->header.msgid);
    CoAPMessageToken_set(&response, message->token, message->header.tokenlen);
    if(COAP_MESSAGE_TYPE_CON == message->header.type){
        CoAPMessageType_set(&response, COAP_MESSAGE_TYPE_ACK);
    }
    else{
        CoAPMessageType_set(&response, message->header.type);
    }
    COAP_DEBUG("Send Error Response Message");
    ret = CoAPMessage_send(ctx, remote, &response);
    CoAPMessage_destory(&response);
    return ret;
}

static int CoAPRespMessage_handle(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message)
{
    char found = 0;
    CoAPSendNode *node = NULL, *next = NULL;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    if (COAP_MESSAGE_TYPE_CON == message->header.type) {
        CoAPAckMessage_send(ctx, remote, message->header.msgid);
    }

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (0 != node->header.tokenlen && node->header.tokenlen == message->header.tokenlen
                && 0 == memcmp(node->token, message->token, message->header.tokenlen)){
            if(!node->keep){
		        list_del_init(&node->sendlist);
                ctx->sendlist.count--;
                COAP_DEBUG("Remove the message id %d from list, cur count is %d", node->header.msgid, ctx->sendlist.count);
            }
            else{
                COAP_DEBUG("Find the message id %d, It need keep", node->header.msgid);
            }
            found = 1;

            break;
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);

    if(found && NULL != node){
        message->user  = node->user;
        // TODO: comment it
        /*
        if (COAP_MSG_CODE_400_BAD_REQUEST <= message->header.code) {
            if (NULL != ctx->notifier) {
                ctx->notifier(message->header.code, remote, message);
            }
        }
        */
        if (NULL != node->handler) {
#ifndef COAP_OBSERVE_CLIENT_DISABLE
            CoAPObsClient_add(ctx, message, remote, node);
#endif
            COAP_DEBUG("Call the response message callback %p", node->handler);
            node->handler(ctx, COAP_REQUEST_SUCCESS, node->user, remote, message);
        }

        if(!node->keep){
            if (NULL != node->message) {
                coap_free(node->message);
            }
            coap_free(node);
            node = NULL;
            COAP_DEBUG("The message needless keep, free it");
        }
    }
    else{
#ifndef COAP_OBSERVE_CLIENT_DISABLE
        CoAPObsClient_add(ctx, message, remote, NULL);
#endif
    }
    return COAP_ERROR_NOT_FOUND;
}

static int CoAPRequestMessage_handle(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message)
{
    int             index = 0;
    int             ret   = COAP_SUCCESS;
    CoAPResource   *resource = NULL;
    unsigned char   path[COAP_MSG_MAX_PATH_LEN] = {0};
    unsigned char  *tmp = path;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    /* Option for No Server Response, rfc7967*/
    if(COAP_SUCCESS == CoAPOption_present(message, COAP_OPTION_NO_RESPONSE)){
        // TODO: Implement The option value is defined as a bit map (Table 2) to achieve granular suppression
        if (COAP_MESSAGE_TYPE_CON == message->header.type){
            /* Send the Ack message */
            CoAPAckMessage_send(ctx, remote, message->header.msgid);
        }
        else{
            /*NON message request, Don't send response message*/
        }
        return COAP_SUCCESS;
    }


    // TODO: if need only one callback
    for (index = 0; index < message->optcount; index++){
        if (COAP_OPTION_URI_PATH == message->options[index].num){
            if((COAP_MSG_MAX_PATH_LEN-1) >= (tmp-path+message->options[index].len)){
                *tmp = '/';
                tmp += 1;
                strncpy((char *)tmp, (const char *)message->options[index].val, message->options[index].len);
                tmp += message->options[index].len;
            }
        }
    }
    COAP_DEBUG("Request path is %s", path);

    resource = CoAPResourceByPath_get(ctx, (char *)path);
    if(NULL != resource){
        if(NULL != resource->callback){
            if (((resource->permission) & (1 << ((message->header.code) - 1))) > 0){
                resource->callback(ctx, (char *)path, remote, message);
            }else{
                COAP_INFO("The resource %s isn't allowed", path);
                ret = CoAPErrRespMessage_send(ctx, remote, message, COAP_MSG_CODE_405_METHOD_NOT_ALLOWED);
            }
        }else{
            COAP_INFO("The resource %s handler isn't exist", path);
            ret = CoAPErrRespMessage_send(ctx, remote, message, COAP_MSG_CODE_405_METHOD_NOT_ALLOWED);
        }
    }else{
        COAP_INFO("The resource %s isn't found", path);
        ret = CoAPErrRespMessage_send(ctx, remote, message, COAP_MSG_CODE_404_NOT_FOUND);
    }

    return ret;
}


static void CoAPMessage_handle(CoAPContext *context,
                               NetworkAddr       *remote,
                               unsigned char     *buf,
                               unsigned short     datalen)
{
    int    ret  = COAP_SUCCESS;
    CoAPMessage     message;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    memset(&message, 0x00, sizeof(CoAPMessage));

    ret = CoAPDeserialize_Message(&message, buf, datalen);
    if (COAP_SUCCESS != ret) {
        if (NULL != ctx->notifier) {
            /* TODO: */
            /* context->notifier(context, event); */
        }
        COAP_INFO("Receive Weird packet,drop it");
        return ;
    }

    COAP_DEBUG("--------Dump Received Message------");
    CoAPMessage_dump(remote, &message);

    if (COAPAckMsg(message.header) || CoAPResetMsg(message.header)) {
        // TODO: implement handle client observe

        // TODO: if need call response callback
        CoAPAckMessage_handle(ctx, &message);

    } else if (CoAPRespMsg(message.header)) {
        CoAPRespMessage_handle(ctx, remote, &message);
    }
    else if(CoAPPingMsg(message.header)){
        CoAPRestMessage_send(ctx, remote, message.header.msgid);

    }
    else if(CoAPReqMsg(message.header)){
        CoAPRequestMessage_handle(ctx, remote, &message);
    }
    else{
        COAP_INFO("Weird packet,drop it");
    }

}

void CoAPMessage_process(CoAPContext *context, unsigned int timeout)
{
    int len = 0;
    NetworkAddr remote;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    //while (1) {
        memset(&remote, 0x00, sizeof(NetworkAddr));
        memset(ctx->recvbuf, 0x00, COAP_MSG_MAX_PDU_LEN);
        len = CoAPNetwork_read(ctx->p_network,
                               &remote,
                               ctx->recvbuf,
                               COAP_MSG_MAX_PDU_LEN, timeout);
        if (len > 0) {
            CoAPMessage_handle(ctx, &remote, ctx->recvbuf, len);
        } else {
            return;
        }
    //}
}

int CoAPMessage_cycle(CoAPContext *context)
{
    unsigned int ret = 0;
    CoAPIntContext *ctx =  (CoAPIntContext *)context;

    CoAPMessage_process(ctx, ctx->waittime);
    CoAPSendNode *node = NULL, *next = NULL;

    uint64_t tick = HAL_UptimeMs () / 1000; 
    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (NULL == node || node->timeout > tick ) {
            continue;
        }

        if (node->retrans_count < COAP_MAX_RETRY_COUNT) {
            /*If has received ack message, don't resend the message*/
            if(0 == node->acked){
                COAP_DEBUG("Retansmit the message id %d len %d", node->header.msgid, node->msglen);
                ret = CoAPNetwork_write(ctx->p_network, &node->remote, node->message, node->msglen, ctx->waittime);
                if (ret != COAP_SUCCESS) {
                    if (NULL != ctx->notifier) {
                                /* TODO: */
                                /* context->notifier(context, event); */
                    }
                }
            }
        }

        node->timeout_val <<= 1;
        node->timeout = tick + node->timeout_val;
        node->retrans_count++;

        if ((node->retrans_count >= COAP_MAX_RETRY_COUNT) && !node->keep) {
            if (NULL != ctx->notifier) {
                        /* TODO: */
                        /* context->notifier(context, event); */
            }

            /*Remove the node from the list*/
            list_del_init(&node->sendlist);
            ctx->sendlist.count--;
            COAP_INFO("Retransmit timeout,remove the message id %d count %d",
                              node->header.msgid, ctx->sendlist.count);
            #ifndef COAP_OBSERVE_SERVER_DISABLE
                CoapObsServerAll_delete(ctx, &node->remote);
            #endif
            HAL_MutexUnlock(ctx->sendlist.list_mutex);
            if(NULL != node->handler){
                node->handler(ctx, COAP_RECV_RESP_TIMEOUT, node->user, &node->remote, NULL);
            }
            coap_free(node->message);
            coap_free(node);

            HAL_MutexLock(ctx->sendlist.list_mutex);
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);
    return COAP_SUCCESS;
}

