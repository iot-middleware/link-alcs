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


#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "iot_import.h"
#include "CoAPExport.h"
#include "CoAPPlatform.h"
#ifdef COAP_DTLS_SUPPORT
#include "iot_import_dtls.h"
#endif
#include "CoAPNetwork.h"


typedef struct
{
    CoAPNetworkType       type;
    unsigned short        port;
    intptr_t              fd;
    int                   join;
    char                  group[NETWORK_ADDR_LEN];
}NetworkConf;

int CoAPNetwork_read(NetworkContext         *p_context,
                            NetworkAddr     *p_remote,
                            NetworkAddr     *p_local,
                            unsigned char   *p_data,
                            unsigned int     datalen,
                            unsigned int     timeout_ms)

{
    int          len      = 0;
    NetworkConf  *network = NULL;

    if(NULL == p_context || NULL == p_remote || NULL == p_data){
        return -1; // TODO
    }

    network = (NetworkConf *)p_context;
    if(1 != network->join){
        if(0 == HAL_UDP_joinmulticast(network->fd, network->group)){
            network->join = 1;
        }
    }

#ifdef COAP_DTLS_SUPPORT
    if (COAP_NETWORK_DTLS == network->type) {
    } else {
#endif
        len =  HAL_UDP_recvfrom(network->fd, p_remote, p_data,
                            datalen, timeout_ms);
        
        p_local->port = network->port;
        HAL_Wifi_Get_IP(p_local->addr, "");
        //COAP_DEBUG("Network read return %d", len);
#ifdef COAP_DTLS_SUPPORT
    }
#endif
    return len;
}

int CoAPNetwork_write(NetworkContext          *p_context,
                                NetworkAddr   *p_remote,
                         const unsigned char  *p_data,
                         unsigned int          datalen,
                         unsigned int          timeout_ms)

{

    int          len      = 0;
    NetworkConf  *network = NULL;

    if(NULL == p_context || NULL == p_remote || NULL == p_data){
        return -1; // TODO
    }

    network = (NetworkConf *)p_context;
#ifdef COAP_DTLS_SUPPORT
    // TODO:
    if(COAP_NETWORK_DTLS == network->type){

    }
    else{
#endif
        len = HAL_UDP_sendto(network->fd, p_remote,
                       p_data, datalen, timeout_ms);
#ifdef COAP_DTLS_SUPPORT
    }
#endif
    return len;
}


NetworkContext *CoAPNetwork_init (const NetworkInit   *p_param)
{
    NetworkConf     *network = NULL;

    if (NULL == p_param) {
        return NULL;
    }

    network = coap_malloc(sizeof(NetworkConf));
    if(NULL == network){
        return NULL;
    }

    memset(network, 0x00, sizeof(NetworkConf));
    network->type = p_param->type;

#ifdef COAP_DTLS_SUPPORT
    if (COAP_NETWORK_DTLS == network->type) {
        // TODO:
        return NULL;
    }else{
#endif
        /*Create udp socket*/
        network->port = p_param->port;
        network->fd = HAL_UDP_create(NULL, network->port);
        if ((intptr_t)-1 == network->fd) {
            coap_free(network);
            return NULL;
        }

        memset(network->group, 0x00, NETWORK_ADDR_LEN);
        if(NULL != p_param->group){
            strncpy(network->group, p_param->group, NETWORK_ADDR_LEN - 1);
            if(0 != HAL_UDP_joinmulticast(network->fd, p_param->group))
            {
                network->join = 0;
                COAP_INFO("CoAP join to multicast group failed, will retry it");
            }
            else{
                network->join = 1;
            }
        }
        else{
            network->join = 1;
        }
#ifdef COAP_DTLS_SUPPORT
    }
#endif
    return (NetworkContext *)network;
}


void CoAPNetwork_deinit(NetworkContext *p_context)
{
    NetworkConf     *network = NULL;
    if(NULL == p_context)
        return;

    network = (NetworkConf *)p_context;
#ifdef COAP_DTLS_SUPPORT
    if (COAP_NETWORK_DTLS == network->type) {
        // TODO:
    }else{
#endif
        HAL_UDP_close(network->fd);
        network->join = 0;
        coap_free(p_context);
        p_context = NULL;
#ifdef COAP_DTLS_SUPPORT
    }
#endif
    return;
}

