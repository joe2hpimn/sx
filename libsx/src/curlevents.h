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
#include "sx.h"
#include "hostlist.h"
#include "misc.h"
#include "cluster.h"
#include "curlevents-common.h"

enum head_result { HEAD_OK, HEAD_FAIL, HEAD_SEEN };

typedef void (*finish_cb_t)(curlev_context_t *ctx, const char *url);
typedef enum head_result (*head_cb_t)(sxi_conns_t *conns, char *ptr, size_t size, size_t nmemb);
typedef void (*error_cb_t)(sxi_conns_t *conns, int reply_code, const char *reason);

typedef struct {
  curlev_context_t *ctx;
  head_cb_t head;
  error_cb_t error;
} reply_headers_t;

typedef struct {
  reply_headers_t headers;
  body_cb_t body;
} reply_t;

typedef struct {
  const char *host;
  const char *url;
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


struct file_upload_ctx;
curlev_context_t* sxi_cbdata_create_upload(sxi_conns_t *conns, finish_cb_t cb, struct file_upload_ctx *ctx);
struct file_upload_ctx *sxi_cbdata_get_upload_ctx(curlev_context_t *ctx);

struct host_upload_ctx;
curlev_context_t* sxi_cbdata_create_host(sxi_conns_t *conns, finish_cb_t cb, struct host_upload_ctx *ctx);
struct host_upload_ctx *sxi_cbdata_get_host_ctx(curlev_context_t *ctx);

struct file_download_ctx;
curlev_context_t* sxi_cbdata_create_download(sxi_conns_t *conns, finish_cb_t cb, struct file_download_ctx *ctx);
struct file_download_ctx *sxi_cbdata_get_download_ctx(curlev_context_t *ctx);

struct job_ctx;
curlev_context_t* sxi_cbdata_create_job(sxi_conns_t *conns, finish_cb_t cb, struct job_ctx *ctx);
struct job_ctx *sxi_cbdata_get_job_ctx(curlev_context_t *ctx);

struct hashop_ctx;
curlev_context_t* sxi_cbdata_create_hashop(sxi_conns_t *conns, finish_cb_t cb, struct hashop_ctx *ctx);
struct hashop_ctx *sxi_cbdata_get_hashop_ctx(curlev_context_t *ctx);

struct generic_ctx;
curlev_context_t* sxi_cbdata_create_generic(sxi_conns_t *conns, finish_cb_t cb, struct generic_ctx *gctx);
struct generic_ctx *sxi_cbdata_get_generic_ctx(curlev_context_t *ctx);

void sxi_cbdata_set_context(curlev_context_t *ctx, void *context);
void* sxi_cbdata_get_context(curlev_context_t *ctx);

typedef int (*retry_cb_t)(curlev_context_t *ctx, sxi_conns_t *conns, const char *host,
                          enum sxi_cluster_verb verb, const char *query,
                          void *content, size_t content_size,
                          ctx_setup_cb_t setup_callback, body_cb_t callback);
int sxi_set_retry_cb(curlev_context_t *ctx, const sxi_hostlist_t *hlist, retry_cb_t cb,
                     enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size,
                     ctx_setup_cb_t setup_callback);

void sxi_cbdata_ref(curlev_context_t *ctx);
void sxi_cbdata_unref(curlev_context_t **ctx);

int sxi_cbdata_wait(curlev_context_t *ctx, curl_events_t *e, int *curlcode);
int sxi_cbdata_result(curlev_context_t *ctx, int *curlcode);
int sxi_cbdata_is_finished(curlev_context_t *ctx);

void sxi_cbdata_reset(curlev_context_t *ctx);
int sxi_cbdata_result_fail(curlev_context_t* ctx);
sxi_conns_t *sxi_cbdata_get_conns(curlev_context_t *ctx);
void sxi_cbdata_set_result(curlev_context_t *ctx, int status);


#endif
