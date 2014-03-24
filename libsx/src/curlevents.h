/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef CURLEVENTS_H
#define CURLEVENTS_H

#include <stdlib.h>
#include <time.h>
#include "curlevents-common.h"
#include "sx.h"
#include "hostlist.h"
#include "misc.h"
#include "cluster.h"

typedef void (*finish_cb_t)(curlev_context_t *ctx);
typedef size_t (*head_cb_t)(void *ptr, size_t size, size_t nmemb, curlev_context_t *ctx);

typedef struct {
  curlev_context_t *ctx;
  head_cb_t head;
  finish_cb_t finish;/* called when response is full retrieved */
} reply_headers_t;

typedef struct {
  reply_headers_t headers;
  size_t (*body)(char *ptr, size_t size, size_t nmemb, curlev_context_t *ctx);
} reply_t;

typedef struct {
  const char *field;
  const char *value;
} header_t;

typedef struct {
  const char *host;
  const char *url;
  const header_t *headers;
  size_t n;
} request_headers_t;

typedef struct {
  const void *data;
  size_t size;
} request_data_t;

curl_events_t *sxi_curlev_init(sxi_conns_t *conns);
void sxi_curlev_set_cafile(curl_events_t *ev, const char *cafile);
int sxi_curlev_has_cafile(curl_events_t *ev);
int sxi_curlev_set_save_rootCA(curl_events_t *ev, const char *filename, int quiet);
int sxi_curlev_is_saved(curl_events_t *ev);
void sxi_curlev_set_verbose(curl_events_t *ev, int is_verbose);
void sxi_curlev_done(curl_events_t **c);
int sxi_curlev_add_get(curl_events_t *e, const request_headers_t *headers, const reply_t *reply);
int sxi_curlev_add_head(curl_events_t *e, const request_headers_t *headers,
                        const reply_headers_t *reply_headers);
int sxi_curlev_add_delete(curl_events_t *e, const request_headers_t *headers,
                          const reply_t *reply);
int sxi_curlev_add_put(curl_events_t *e,
                       const request_headers_t *req_headers,
                       const request_data_t *req_data,
                       const reply_t *reply);
int sxi_curlev_poll(curl_events_t *e);
int sxi_curlev_poll_immediate(curl_events_t *e);
int sxi_cbdata_result_fail(curlev_context_t* ctx);

#endif
