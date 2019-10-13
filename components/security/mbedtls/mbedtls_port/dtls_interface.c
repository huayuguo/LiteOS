/*----------------------------------------------------------------------------
 * Copyright (c) <2016-2018>, <Huawei Technologies Co., Ltd>
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 * of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific prior written
 * permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------
 * Notice of Export Control Law
 * ===============================================
 * Huawei LiteOS may be subject to applicable export control laws and regulations, which might
 * include those applicable to Huawei LiteOS of U.S. and the country in which you are located.
 * Import, export and usage of Huawei LiteOS in any manner by you shall be in compliance with such
 * applicable export control laws and regulations.
 *---------------------------------------------------------------------------*/

/*
 *  Simple DTLS client demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "dtls_interface.h"
#include "osdepends/atiny_osdep.h"
#include "mbedtls/net_sockets.h"
<<<<<<< HEAD
#include "sal/atiny_socket.h"
=======
#include "atiny_socket.h"
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842

#define MBEDTLS_DEBUG

#ifdef MBEDTLS_DEBUG
#define MBEDTLS_LOG(fmt, ...) \
    do \
    { \
        (void)atiny_printf("[MBEDTLS][%s:%d] " fmt "\r\n", \
        __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#else
#define MBEDTLS_LOG(fmt, ...) ((void)0)
#endif


<<<<<<< HEAD
static void *atiny_calloc(size_t n, size_t size)
{
    void *p = atiny_malloc(n * size);
    if(p)
    {
        memset(p, 0, n * size);
    }

    return p;
}

mbedtls_ssl_context *dtls_ssl_new(dtls_establish_info_s *info, char plat_type)
{
    int ret;
    mbedtls_ssl_context *ssl = NULL;
    mbedtls_ssl_config *conf = NULL;
    mbedtls_entropy_context *entropy = NULL;
    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    mbedtls_timing_delay_context *timer = NULL;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt *cacert;
#endif

    const char *pers = "ssl_client";

    dtls_init();
=======

mbedtls_ssl_context *dtls_ssl_new_with_psk(char *psk, unsigned psk_len, char *psk_identity, char plat_type)
{
    int ret;
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_config *conf;
    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_timing_delay_context * timer;

    const char *pers = "dtls_client";

    dtls_int();
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842

    ssl       = mbedtls_calloc(1, sizeof(mbedtls_ssl_context));
    conf      = mbedtls_calloc(1, sizeof(mbedtls_ssl_config));
    entropy   = mbedtls_calloc(1, sizeof(mbedtls_entropy_context));
    ctr_drbg  = mbedtls_calloc(1, sizeof(mbedtls_ctr_drbg_context));
<<<<<<< HEAD
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    cacert    = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
#endif

    if (NULL == info || NULL == ssl
        || NULL == conf || NULL == entropy
        || NULL == ctr_drbg
#if defined(MBEDTLS_X509_CRT_PARSE_C)
        || NULL == cacert
#endif
        )
=======
    timer     = mbedtls_calloc(1, sizeof(mbedtls_timing_delay_context));

    if (NULL == ssl || NULL == conf || entropy == NULL ||
            NULL == ctr_drbg)
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
    {
        goto exit_fail;
    }

    if (info->udp_or_tcp == MBEDTLS_NET_PROTO_UDP)
    {
        timer = mbedtls_calloc(1, sizeof(mbedtls_timing_delay_context));
        if (NULL == timer) goto exit_fail;
    }

    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (info->psk_or_cert == VERIFY_WITH_CERT)
    {
        mbedtls_x509_crt_init(cacert);
    }
#endif

    if ((ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0)
    {
        MBEDTLS_LOG("mbedtls_ctr_drbg_seed failed: -0x%x", -ret);
        goto exit_fail;
    }

    MBEDTLS_LOG("setting up the SSL structure");

<<<<<<< HEAD
    if (info->udp_or_tcp == MBEDTLS_NET_PROTO_UDP)
    {
        ret = mbedtls_ssl_config_defaults(conf,
                                          plat_type,
                                          MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    }
    else
    {
        ret = mbedtls_ssl_config_defaults(conf,
                                          plat_type,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    }

    if (ret != 0)
=======
    if ((ret = mbedtls_ssl_config_defaults(conf,
                                           plat_type,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
    {
        MBEDTLS_LOG("mbedtls_ssl_config_defaults failed: -0x%x", -ret);
        goto exit_fail;
    }

    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    if (info->udp_or_tcp == MBEDTLS_NET_PROTO_TCP)
    {
        mbedtls_ssl_conf_read_timeout(conf, TLS_SHAKEHAND_TIMEOUT);
    }

<<<<<<< HEAD
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if (info->psk_or_cert == VERIFY_WITH_PSK)
=======
    if ((ret = mbedtls_ssl_conf_psk(conf, (const unsigned char *)psk, psk_len,
                                    (const unsigned char *) psk_identity,
                                    strlen(psk_identity))) != 0)
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
    {
        if ((ret = mbedtls_ssl_conf_psk(conf,
                                        info->v.p.psk,
                                        info->v.p.psk_len,
                                        info->v.p.psk_identity,
                                        strlen((const char *)info->v.p.psk_identity))) != 0)
        {
            MBEDTLS_LOG("mbedtls_ssl_conf_psk failed: -0x%x", -ret);
            goto exit_fail;
        }
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (info->psk_or_cert == VERIFY_WITH_CERT)
    {
        ret = mbedtls_x509_crt_parse(cacert, info->v.c.ca_cert, info->v.c.cert_len);
        if(ret < 0)
        {
            MBEDTLS_LOG("mbedtls_x509_crt_parse failed -0x%x", -ret);
            goto exit_fail;
        }
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);
    }
#endif
    mbedtls_ssl_conf_dtls_cookies( conf, NULL, NULL,NULL );


#ifndef WITH_MQTT
    if (info->udp_or_tcp == MBEDTLS_NET_PROTO_UDP)
    {
        mbedtls_ssl_conf_dtls_cookies(conf, NULL, NULL,NULL);
    }
#endif
    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        MBEDTLS_LOG("mbedtls_ssl_setup failed: -0x%x", -ret);
        goto exit_fail;
    }

<<<<<<< HEAD
    if (info->udp_or_tcp == MBEDTLS_NET_PROTO_UDP)
=======
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !(defined(WITH_CA_UNI) || defined(WITH_CA_BI))

    if ((ret = mbedtls_ssl_set_hostname(ssl, SERVER_NAME)) != 0)
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
    {
        mbedtls_ssl_set_timer_cb(ssl, timer, mbedtls_timing_set_delay,
                                 mbedtls_timing_get_delay);
    }

<<<<<<< HEAD
    MBEDTLS_LOG("set SSL structure succeed");
=======
#endif
#endif

    mbedtls_ssl_set_timer_cb( ssl, timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );

    MBEDTLS_LOG("set DTLS structure succeed");
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842

    return ssl;

exit_fail:

    if (conf)
    {
        mbedtls_ssl_config_free(conf);
        mbedtls_free(conf);
    }

    if (ctr_drbg)
    {
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_free(ctr_drbg);
    }

    if (entropy)
    {
        mbedtls_entropy_free(entropy);
        mbedtls_free(entropy);
    }

    if (timer)
    {
        mbedtls_free(timer);
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (cacert)
    {
        mbedtls_x509_crt_free(cacert);
        mbedtls_free(cacert);
    }
#endif

    if (ssl)
    {
        mbedtls_ssl_free(ssl);
        mbedtls_free(ssl);
    }
    return NULL;
}

static inline uint32_t dtls_gettime()
{
    return (uint32_t)(atiny_gettime_ms() / 1000);
}
<<<<<<< HEAD
=======

int dtls_shakehand(mbedtls_ssl_context *ssl, const dtls_shakehand_info_s *info)
{
    int ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    uint32_t change_value = 0;
    mbedtls_net_context *server_fd = NULL;
    mbedtls_timing_delay_context *timer = NULL;
    uint32_t max_value;

>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842

int dtls_shakehand(mbedtls_ssl_context *ssl, const dtls_shakehand_info_s *info)
{
    int ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    uint32_t change_value = 0;
    mbedtls_net_context *server_fd = NULL;
    uint32_t max_value;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    unsigned int flags;
#endif

    MBEDTLS_LOG("connecting to server");

    if (MBEDTLS_SSL_IS_CLIENT == info->client_or_server)
    {
        server_fd = mbedtls_net_connect(info->u.c.host, info->u.c.port, info->udp_or_tcp);
    }
    else
    {
        server_fd = (mbedtls_net_context*)atiny_net_bind(NULL, info->u.s.local_port, MBEDTLS_NET_PROTO_UDP);
    }

<<<<<<< HEAD
    if (server_fd == NULL)
    {
        MBEDTLS_LOG("connect failed! mode %d", info->client_or_server);
=======
    MBEDTLS_LOG("connecting to udp");


    if (MBEDTLS_SSL_IS_CLIENT == info->client_or_server)
    {
        server_fd = mbedtls_net_connect(info->u.c.host, info->u.c.port, MBEDTLS_NET_PROTO_UDP);
    }
    else
    {
        server_fd = (mbedtls_net_context*)atiny_net_bind(NULL, info->u.s.local_port, MBEDTLS_NET_PROTO_UDP);
    }

    if (server_fd == NULL)
    {
		MBEDTLS_LOG("connect failed! mode %d", info->client_or_server);
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
        goto exit_fail;
    }

    mbedtls_ssl_set_bio(ssl, server_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    MBEDTLS_LOG("performing the SSL/TLS handshake");

    max_value = ((MBEDTLS_SSL_IS_SERVER == info->client_or_server || info->udp_or_tcp == MBEDTLS_NET_PROTO_UDP) ?
                (dtls_gettime() + info->timeout) :  50);

    max_value = ((MBEDTLS_SSL_IS_SERVER == info->client_or_server) ?
                (dtls_gettime() + info->u.s.timeout) : 10);


    do
    {
        ret = mbedtls_ssl_handshake(ssl);
        //MBEDTLS_LOG("mbedtls_ssl_handshake %d %d", change_value, max_value);
        //LOS_TaskDelay(1);
<<<<<<< HEAD
        if (MBEDTLS_SSL_IS_CLIENT == info->client_or_server && info->udp_or_tcp == MBEDTLS_NET_PROTO_TCP)
=======
        if (MBEDTLS_SSL_IS_CLIENT == info->client_or_server)
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
        {
            change_value++;
        }
        else
        {
            change_value = dtls_gettime();
        }

        if (info->step_notify)
        {
            info->step_notify(info->param);
        }
<<<<<<< HEAD
    }
    while ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            (ret == MBEDTLS_ERR_SSL_TIMEOUT &&
            info->udp_or_tcp == MBEDTLS_NET_PROTO_TCP)) &&
            (change_value < max_value));
=======

    }
    while ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) && change_value < max_value);
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842

    if (info->finish_notify)
    {
        info->finish_notify(info->param);
    }

    if (ret != 0)
    {
        MBEDTLS_LOG("mbedtls_ssl_handshake failed: -0x%x", -ret);
        goto exit_fail;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (info->psk_or_cert == VERIFY_WITH_CERT)
    {
        if((flags = mbedtls_ssl_get_verify_result(ssl)) != 0)
        {
            char vrfy_buf[512];
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            MBEDTLS_LOG("cert verify failed: %s", vrfy_buf);
            goto exit_fail;
        }
        else
            MBEDTLS_LOG("cert verify succeed");
    }
#endif

    MBEDTLS_LOG("handshake succeed");

    return 0;

exit_fail:

    if (server_fd)
    {
        mbedtls_net_free(server_fd);
        ssl->p_bio = NULL;
    }

    return ret;

}
void dtls_ssl_destroy(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_config           *conf = NULL;
    mbedtls_ctr_drbg_context     *ctr_drbg = NULL;
    mbedtls_entropy_context      *entropy = NULL;
    mbedtls_net_context          *server_fd = NULL;
    mbedtls_timing_delay_context *timer = NULL;
<<<<<<< HEAD
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt             *cacert = NULL;
=======
#if defined(WITH_CA_UNI)
    mbedtls_x509_crt *cacert = NULL;
#elif defined(WITH_CA_BI)
    mbedtls_x509_crt *cacert = NULL;
    mbedtls_x509_crt *clicert = NULL;
    mbedtls_pk_context *pkey = NULL;
    mbedtls_ssl_key_cert *head = NULL;
    mbedtls_ssl_key_cert *cur = NULL;
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
#endif

    if (ssl == NULL)
    {
        return;
    }

    conf       = ssl->conf;
    server_fd  = (mbedtls_net_context *)ssl->p_bio;
    timer      = (mbedtls_timing_delay_context *)ssl->p_timer;
<<<<<<< HEAD
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    cacert     = (mbedtls_x509_crt *)conf->ca_chain;
=======
#if defined(WITH_CA_UNI)
    cacert     = conf->ca_chain;
#elif defined(WITH_CA_BI)
	head = conf->key_cert;
	cur = head;

    while( cur->next != NULL )
        cur = cur->next;

    cacert     = conf->ca_chain;
    clicert    = cur->cert;
    pkey       = cur->key;
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
#endif

    if (conf)
    {
        ctr_drbg   = conf->p_rng;

        if (ctr_drbg)
        {
            entropy =  ctr_drbg->p_entropy;
        }
    }

#if defined(WITH_CA_UNI)
    if(cacert)
    {
		mbedtls_x509_crt_free(cacert);
        mbedtls_free(cacert);
    }
#elif defined(WITH_CA_BI)
    if(cacert)
    {
        mbedtls_x509_crt_free(cacert);
        mbedtls_free(cacert);
    }
    if(clicert)
    {
        mbedtls_x509_crt_free(clicert);
        mbedtls_free(clicert);
    }
	if(pkey)
    {
        mbedtls_pk_free(pkey);
        mbedtls_free(pkey);
    }
#endif


    if (server_fd)
    {
        mbedtls_net_free(server_fd);
    }

    if (conf)
    {
        mbedtls_ssl_config_free(conf);
        mbedtls_free(conf);
        ssl->conf = NULL; //  need by mbedtls_debug_print_msg(), see mbedtls_ssl_free(ssl)
    }

    if (ctr_drbg)
    {
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_free(ctr_drbg);
    }

    if (entropy)
    {
        mbedtls_entropy_free(entropy);
        mbedtls_free(entropy);
    }

    if (timer)
    {
        mbedtls_free(timer);
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (cacert)
    {
        mbedtls_x509_crt_free(cacert);
        mbedtls_free(cacert);
    }
#endif

    mbedtls_ssl_free(ssl);
    mbedtls_free(ssl);
}

int dtls_write(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len)
{
    int ret = mbedtls_ssl_write(ssl, (unsigned char *) buf, len);

    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        return 0;
    }
    else if (ret < 0)
    {
        return -1;
    }

    return ret;
}

int dtls_read(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len, uint32_t timeout)
{
    int ret;

    mbedtls_ssl_conf_read_timeout(ssl->conf, timeout);

    ret = mbedtls_ssl_read(ssl, buf, len);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ)
    {
        return 0;
    }
    else if (ret == MBEDTLS_ERR_SSL_TIMEOUT)
    {
        return -2;
    }
    else if (ret < 0)
    {
        return -1;
    }

    return ret;
}

<<<<<<< HEAD
void dtls_init(void)
=======
void dtls_int(void)
>>>>>>> 39b93f91c06e3a2e8bb9dcf26ef94d954f00d842
{
    (void)mbedtls_platform_set_calloc_free(atiny_calloc, atiny_free);
    (void)mbedtls_platform_set_snprintf(atiny_snprintf);
    (void)mbedtls_platform_set_printf(atiny_printf);
}

int dtls_accept( mbedtls_net_context *bind_ctx,
                            mbedtls_net_context *client_ctx,
                            void *client_ip, size_t buf_size, size_t *ip_len )
{
    return mbedtls_net_accept(bind_ctx, client_ctx, client_ip, buf_size, ip_len);
}

