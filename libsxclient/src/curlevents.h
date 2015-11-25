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
#include "fileops.h"

enum head_result { HEAD_OK, HEAD_FAIL, HEAD_SEEN };

typedef void (*finish_cb_t)(curlev_context_t *ctx, const char *url);
typedef enum head_result (*head_cb_t)(curlev_context_t *ctx, long http_status, char *ptr, size_t size, size_t nmemb);
typedef void (*error_cb_t)(curlev_context_t *ctx, int reply_code, const char *reason);

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
  uint16_t port;
} request_headers_t;

typedef struct {
  const void *data;
  size_t size;
} request_data_t;

curl_events_t *sxi_curlev_init(sxi_conns_t *conns);
void sxi_curlev_set_cafile(curl_events_t *ev, const char *cafile);
int sxi_curlev_has_cafile(curl_events_t *ev);
const char* sxi_curlev_get_cafile(curl_events_t *ev);
int sxi_curlev_set_save_rootCA(curl_events_t *ev, const char *filename, int quiet);
int sxi_curlev_is_cert_saved(curl_events_t *ev);
int sxi_curlev_is_cert_rejected(curl_events_t *ev);
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

/* Typedefs for error handling functions */
typedef const char *(*geterrmsg_cb)(void *ctx);
typedef enum sxc_error_t (*geterrnum_cb)(void *ctx);
typedef void (*seterr_cb)(void *ctx, enum sxc_error_t errnum, const char *fmt, ...);
typedef void (*setsyserr_cb)(void *ctx, enum sxc_error_t errnum, const char *fmt, ...);
typedef void (*clearerr_cb)(void *ctx);

typedef enum {
    RCTX_SX, /* Global context, errors will be stored globally */
    RCTX_CBDATA /* cbdata context, errors will be stored inside curlev_context_t */
} retry_ctx_type_t;

curlev_context_t* sxi_cbdata_create_upload(sxi_conns_t *conns, finish_cb_t cb, struct file_upload_ctx *ctx);
struct file_upload_ctx *sxi_cbdata_get_upload_ctx(curlev_context_t *ctx);

curlev_context_t* sxi_cbdata_create_host(sxi_conns_t *conns, finish_cb_t cb, struct host_upload_ctx *ctx);
struct host_upload_ctx *sxi_cbdata_get_host_ctx(curlev_context_t *ctx);

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
void sxi_cbdata_allow_non_sx_responses(struct curlev_context *ctx, int allow);

typedef int (*retry_cb_t)(curlev_context_t *ctx, sxi_conns_t *conns, const char *host,
                          enum sxi_cluster_verb verb, const char *query,
                          void *content, size_t content_size,
                          ctx_setup_cb_t setup_callback, body_cb_t callback);
struct _sxi_jobs_t;
int sxi_set_retry_cb(curlev_context_t *ctx, const sxi_hostlist_t *hlist, retry_cb_t cb,
                     enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size,
                     ctx_setup_cb_t setup_callback,
                     struct _sxi_jobs_t *jobs);

void sxi_cbdata_ref(curlev_context_t *ctx);
void sxi_cbdata_unref(curlev_context_t **ctx);

/* Wait until current request finishes.
 *
 * Return 0 on success, -2 if cannot wait for finishing request (usually critical error),
 * -1 if query failed. When error code is not -2, http status will be assigned.
 */
int sxi_cbdata_wait(curlev_context_t *ctx, curl_events_t *e, long *http_status);
int sxi_cbdata_result(curlev_context_t *ctx, int *curlcode, enum sxc_error_t *errnum, long *http_status);
int sxi_cbdata_is_finished(curlev_context_t *ctx);

void sxi_cbdata_reset(curlev_context_t *ctx);
int sxi_cbdata_result_fail(curlev_context_t* ctx);
sxi_conns_t *sxi_cbdata_get_conns(curlev_context_t *ctx);
void sxi_cbdata_set_result(curlev_context_t *ctx, int status);

void sxi_cbdata_set_etag(curlev_context_t *ctx, const char* etag, unsigned etag_len);
char *sxi_cbdata_get_etag(curlev_context_t *ctx);

/* Store error message and code into curlev context */
void sxi_cbdata_seterr(curlev_context_t *ctx, enum sxc_error_t err, const char *fmt, ...);
void sxi_cbdata_setsyserr(curlev_context_t *ctx, enum sxc_error_t err, const char *fmt, ...);
/* Restore error message and id from global buffer.
 *
 * That data will be copied to local buffer to be able to assign errors to particular query context.
 * It will be needed when multiple queries are performed in parallel. Many libsxclient functions store error only in
 * global buffer, this function is designed to retrieve it. Note that global error will be wiped.
 *
 * Return 1 if restoring fails */
int sxi_cbdata_restore_global_error(sxc_client_t *sx, curlev_context_t *cbdata);

/* Retrieve error message from curlev context */
const char *sxi_cbdata_geterrmsg(const curlev_context_t *ctx);
/* Retrieve error code from curlev context */
enum sxc_error_t sxi_cbdata_geterrnum(const curlev_context_t *ctx);
/* Clear previously stored error message */
void sxi_cbdata_clearerr(curlev_context_t *cbdata);
void sxi_cbdata_clearerr(curlev_context_t *ctx);
void sxi_cbdata_setclusterr(curlev_context_t *ctx, const char *nodeid, const char *reqid, int status, const char *msg, const char *details);
void sxi_cbdata_set_operation(curlev_context_t *ctx, const char *op, const char *host, const char *vol, const char *path);
void sxi_cbdata_clear_operation(curlev_context_t *ctx);

/*
 * Set timeouts (in seconds) which will be used for all requests sent with given curl_events_t reference as context.
 * Soft timing is reset each time request succeeds to transfer any part of data. After hard_timeout request is going to fail.
 * 0 means that no timeout will be considered. If both timouts are set, hard timeout cannot be lower than soft timeout.
 */
int sxi_cbdata_set_timeouts(curlev_context_t *e, unsigned int hard_timeout, unsigned int soft_timeout);

struct sxi_retry;
typedef struct sxi_retry sxi_retry_t;
sxi_retry_t* sxi_retry_init(void *ctx, retry_ctx_type_t ctx_type);
int sxi_retry_check(sxi_retry_t *retry, unsigned current_try);
void sxi_retry_msg(sxc_client_t *sx, sxi_retry_t *retry, const char *host);
int sxi_retry_done(sxi_retry_t **retry);
int sxi_curlev_fetch_certificates(curl_events_t *e, const char *url, int quiet);
char *sxi_curlev_fetch_sxauthd_credentials(curl_events_t *e, const char *url, const char *username, const char *password, const char *label, const char *unique_name, int quiet);

sxi_conns_t *sxi_curlev_get_conns(curlev_t *ev);
void sxi_curlev_set_verified(curlev_t *ev, int value);
int sxi_curlev_verify_peer(curlev_t *ev);

int sxi_curlev_disable_proxy(curl_events_t *ev);

/* 
 * Set bandwidth limit for CURL event. 
 * global_bandwidth_limit - limit shared by all connections
 * host_count - number of hosts sharing bandwidth limit 
 * running - number of transfers running 
 */
int sxi_curlev_set_bandwidth_limit(curl_events_t *e, int64_t global_bandwidth_limit, unsigned int running);
/* Get local bandwidth limit for given connection */
int64_t sxi_curlev_get_bandwidth_limit(const curl_events_t *e);

/* Set limits for number of active connections */
int sxi_curlev_set_conns_limit(curl_events_t *e, unsigned int max_active, unsigned int max_active_per_host);

/* Nullify context for each curlev_t element from active and inactive cURL events */
void sxi_curlev_nullify_upload_context(sxi_conns_t *conns, void *context);

/* Get optimal node according to node preference set via sxc_set_node_preference() */
const char *sxi_hostlist_get_optimal_host(sxi_conns_t * conns, const sxi_hostlist_t *list, sxc_xfer_direction_t direction);
int sxi_get_host_speed_stats(sxi_conns_t *conns, const char *host, double *ul, double *dl);
int sxi_set_host_speed_stats(sxi_conns_t *conns, const char *host, double ul, double dl);
#endif
