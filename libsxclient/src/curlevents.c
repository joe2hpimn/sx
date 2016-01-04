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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "curlevents.h"
#include "libsxclient-int.h"
#include "misc.h"
#include "sxproto.h"
#include "vcrypto.h"
#include "vcryptocurl.h"
#include "jobpoll.h"
#include <curl/curl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include "fileops.h"
#include "jparse.h"

#define ERRBUF_SIZE 512
enum ctx_tag { CTX_UPLOAD, CTX_UPLOAD_HOST, CTX_DOWNLOAD, CTX_JOB, CTX_HASHOP, CTX_GENERIC };

#define MAX_ETAG_SIZE 128

struct recv_context {
    char errbuf[ERRBUF_SIZE+1];
    char etag[MAX_ETAG_SIZE];
    int rc;
    int fail;
    int finished;
    long reply_status;
    char *reason;
    unsigned reasonsz;
    int header_seen;
    enum content_type content_type;
};

struct retry_ctx {
    ctx_setup_cb_t setup_callback;
    enum sxi_cluster_verb verb;
    int hostidx;
    int retries;
    sxi_hostlist_t hosts;
    char *query;
    void *content;
    size_t content_size;
    retry_cb_t cb;
    sxi_retry_t *retry;
    char *op;
    sxi_jobs_t *jobs;
};

struct curlev_context {
    sxi_conns_t *conns;
    int ref;

    /* reset after each retry */
    struct recv_context recv_ctx;
    /* Set to 1 if response should be honoured from non-sx nodes */
    int allow_non_sx_resp;

    /* keep all of the below across retries */
    body_cb_t data_cb;
    finish_cb_t finish_cb;
    struct retry_ctx retry;

    /* Store error messages locally */
    char errbuf[ERRBUF_SIZE+1];
    enum sxc_error_t errnum;
    char *op, *op_host, *op_vol, *op_path;

    enum ctx_tag tag;
    union {
        struct file_upload_ctx *upload_ctx;
        struct host_upload_ctx *host_ctx;
        struct file_download_ctx *download_ctx;
        struct job_ctx *job_ctx;
        struct hashop_ctx *hashop_ctx;
        struct generic_ctx *generic_ctx;
    } u;
    void *context;

    unsigned int hard_timeout; /* Timeout used for requests sent to cluster: total time a single request is allowed to exist */
    unsigned int soft_timeout; /* Timeout for stalled requests: maximum time between successful data parts being transferred */
};

static struct curlev_context *sxi_cbdata_create(sxi_conns_t *conns, finish_cb_t cb)
{
    struct curlev_context *ret;
    sxc_client_t *sx;
    const char *op = NULL, *op_host = NULL, *op_vol = NULL, *op_path = NULL;
    unsigned int hard_timeout = 0, soft_timeout = 0;

    if (!conns)
        return NULL;
    sx = sxi_conns_get_client(conns);
    if (!sx)
        return NULL;
    ret = calloc(1, sizeof(*ret));
    if (!ret) {
        sxi_setsyserr(sx, SXE_EMEM, "OOM allocating cbdata");
        return NULL;
    }
    if(sxi_conns_get_timeouts(conns, &hard_timeout, &soft_timeout) ||
       sxi_cbdata_set_timeouts(ret, hard_timeout, soft_timeout)) {
        sxi_seterr(sx, SXE_EARG, "Failed to set connection timeouts");
        free(ret);
        return NULL;
    }
    ret->conns = conns;
    ret->finish_cb = cb;
    ret->ref = 1;
    sxi_cbdata_clearerr(ret);
    sxi_operation_info(sx, &op, &op_host, &op_vol, &op_path);
    sxi_cbdata_set_operation(ret, op, op_host, op_vol, op_path);
    sxi_hostlist_init(&ret->retry.hosts);
    return ret;
}

static int sxi_cbdata_is_tag(struct curlev_context *ctx, enum ctx_tag expected)
{
    if (ctx) {
        if (ctx->tag == expected)
            return 1;
        sxi_cbdata_seterr(ctx, SXE_EARG, "context tag mismatch: %d != %d", ctx->tag, expected);
    }
    return 0;
}

struct curlev_context* sxi_cbdata_create_upload(sxi_conns_t *conns, finish_cb_t cb, struct file_upload_ctx *ctx)
{
    struct curlev_context *ret = sxi_cbdata_create(conns, cb);
    if (ret) {
        ret->tag = CTX_UPLOAD;
        ret->u.upload_ctx = ctx;
    }
    return ret;
}

struct file_upload_ctx *sxi_cbdata_get_upload_ctx(struct curlev_context *ctx)
{
    if (ctx && sxi_cbdata_is_tag(ctx, CTX_UPLOAD))
        return ctx->u.upload_ctx;
    return NULL;
}

struct curlev_context* sxi_cbdata_create_host(sxi_conns_t *conns, finish_cb_t cb, struct host_upload_ctx *ctx)
{
    struct curlev_context *ret = sxi_cbdata_create(conns, cb);
    if (ret) {
        ret->tag = CTX_UPLOAD_HOST;
        ret->u.host_ctx = ctx;
    }
    return ret;
}

struct host_upload_ctx *sxi_cbdata_get_host_ctx(struct curlev_context *ctx)
{
    if (ctx && sxi_cbdata_is_tag(ctx, CTX_UPLOAD_HOST))
        return ctx->u.host_ctx;
    return NULL;
}

struct curlev_context* sxi_cbdata_create_download(sxi_conns_t *conns, finish_cb_t cb, struct file_download_ctx *ctx)
{
    struct curlev_context *ret = sxi_cbdata_create(conns, cb);
    if (ret) {
        ret->tag = CTX_DOWNLOAD;
        ret->u.download_ctx = ctx;
    }
    return ret;
}

struct file_download_ctx *sxi_cbdata_get_download_ctx(struct curlev_context *ctx)
{
    if (ctx && sxi_cbdata_is_tag(ctx, CTX_DOWNLOAD))
        return ctx->u.download_ctx;
    return NULL;
}

struct curlev_context* sxi_cbdata_create_job(sxi_conns_t *conns, finish_cb_t cb, struct job_ctx *ctx)
{
    struct curlev_context *ret = sxi_cbdata_create(conns, cb);
    if (ret) {
        ret->tag = CTX_JOB;
        ret->u.job_ctx = ctx;
    }
    return ret;
}

struct job_ctx *sxi_cbdata_get_job_ctx(struct curlev_context *ctx)
{
    if (ctx && sxi_cbdata_is_tag(ctx, CTX_JOB))
        return ctx->u.job_ctx;
    return NULL;
}

struct curlev_context* sxi_cbdata_create_hashop(sxi_conns_t *conns, finish_cb_t cb, struct hashop_ctx *ctx)
{
    struct curlev_context *ret = sxi_cbdata_create(conns, cb);
    if (ret) {
        ret->tag = CTX_HASHOP;
        ret->u.hashop_ctx = ctx;
    }
    return ret;
}

struct hashop_ctx *sxi_cbdata_get_hashop_ctx(struct curlev_context *ctx)
{
    if (ctx && sxi_cbdata_is_tag(ctx, CTX_HASHOP))
        return ctx->u.hashop_ctx;
    return NULL;
}

struct curlev_context* sxi_cbdata_create_generic(sxi_conns_t *conns, finish_cb_t cb, struct generic_ctx *gctx)
{
    struct curlev_context *ret = sxi_cbdata_create(conns, cb);
    if (ret) {
        ret->tag = CTX_GENERIC;
        ret->u.generic_ctx = gctx;
    }
    return ret;
}

struct generic_ctx *sxi_cbdata_get_generic_ctx(struct curlev_context *ctx)
{
    if (ctx && sxi_cbdata_is_tag(ctx, CTX_GENERIC))
        return ctx->u.generic_ctx;
    return NULL;
}

void sxi_cbdata_set_context(struct curlev_context *ctx, void *context)
{
    if (ctx)
        ctx->context = context;
}

void* sxi_cbdata_get_context(struct curlev_context *ctx)
{
    return ctx ? ctx->context : NULL;
}

void sxi_cbdata_allow_non_sx_responses(struct curlev_context *ctx, int allow) {
    if(ctx)
        ctx->allow_non_sx_resp = allow;
}

int sxi_set_retry_cb(curlev_context_t *ctx, const sxi_hostlist_t *hlist, retry_cb_t cb,
                     enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size,
                     ctx_setup_cb_t setup_callback, sxi_jobs_t *jobs)
{
    if (ctx) {
        sxc_client_t *sx = sxi_conns_get_client(ctx->conns);
        ctx->retry.cb = cb;
        ctx->retry.setup_callback = setup_callback;
        ctx->retry.verb = verb;
        ctx->retry.query = strdup(query);
        if (!ctx->retry.query) {
            sxi_cbdata_setsyserr(ctx, SXE_EMEM, "Out of memory allocating retry query");
            return -1;
        }
        ctx->retry.content = content;
        ctx->retry.content_size = content_size;
        if (sxi_hostlist_add_list(sx, &ctx->retry.hosts, hlist)) {
            sxi_cbdata_restore_global_error(sx, ctx);
            return -1;
        }
        if (!(ctx->retry.retry = sxi_retry_init(ctx, RCTX_CBDATA))) {
            sxi_cbdata_seterr(ctx, SXE_EMEM, "Out of memory allocating retry");
            return -1;
        }
        ctx->retry.jobs = jobs;
        return 0;
    }
    return -1;
}

void sxi_cbdata_ref(curlev_context_t *ctx)
{
    if (ctx) {
        sxc_client_t *sx = sxi_conns_get_client(ctx->conns);
        ctx->ref++;
        SXDEBUG("cbdata reference count for %p: %d", (void*)ctx, ctx->ref);
    }
}

void sxi_cbdata_unref(curlev_context_t **ctx_ptr)
{
    if (ctx_ptr) {
        char *oldop;
        curlev_context_t *ctx = *ctx_ptr;
        sxc_client_t *sx;
        if (!ctx) {
            /* it is already freed */
            return;
        }
        sx = sxi_conns_get_client(ctx->conns);
        oldop = ctx->retry.op;
        /* op might be equal to ctx->retry.op, so don't free it yet
         * before strdup-ing it */
        ctx->retry.op = ctx->op ? strdup(ctx->op) : NULL;
        free(oldop);
        sxi_cbdata_clear_operation(ctx);
        ctx->ref--;
        *ctx_ptr = NULL;
        if (ctx->ref < 0) {
            /* Store message globally, otherwise it wouldn't ever be shown */
            sxi_seterr(sx, SXE_EARG, "cbdata: Reference count wrong: %d", ctx->ref);
            /* don't free, the reference count is corrupt */
            return;
        }
        SXDEBUG("cbdata reference count for %p: %d", (void*)ctx, ctx->ref);
        if (!ctx->ref) {
            SXDEBUG("freeing cbdata %p", (void*)ctx);
            /* Store local error message in global error buffer, otherwise it would be lost */
            if(ctx->errnum != SXE_NOERROR) {
                sxi_seterr(sx, ctx->errnum, "%s", ctx->errbuf);
                SXDEBUG("Clearing cbdata, global error message set [%d]: %s", sxc_geterrnum(sx), sxc_geterrmsg(sx));
            }
            /* Restore operation globally */
            sxi_set_operation(sx, ctx->op, ctx->op_host, ctx->op_vol, ctx->op_path);
            sxi_cbdata_reset(ctx);
            sxi_hostlist_empty(&ctx->retry.hosts);
            sxi_retry_done(&ctx->retry.retry);
            free(ctx->retry.query);
            free(ctx->retry.op);
            free(ctx);
            /* we freed it */
            return;
        }
        /* we didn't free it, but no errors */
        sxi_cbdata_set_operation(ctx, ctx->retry.op, NULL, NULL, NULL);
        return;
    }
    /* error */
}

void sxi_cbdata_reset(curlev_context_t *ctx)
{
    if (ctx) {
        struct recv_context *rctx = &ctx->recv_ctx;
        free(rctx->reason);
        memset(rctx, 0, sizeof(*rctx));
        sxi_cbdata_clearerr(ctx);
    }
}

int sxi_cbdata_is_finished(curlev_context_t *ctx)
{
    return ctx && ctx->recv_ctx.finished;
}

void sxi_cbdata_set_result(curlev_context_t *ctx, int status)
{
    if (!ctx)
        return;
    ctx->recv_ctx.rc = CURLE_OK;
    ctx->recv_ctx.reply_status = status;
}

int sxi_cbdata_result(curlev_context_t *ctx, int *curlcode, enum sxc_error_t *errnum, long *http_status)
{
    struct recv_context *rctx = ctx ?  &ctx->recv_ctx : NULL;
    if (!rctx)
        return -1;

    if(http_status && (rctx->rc == CURLE_OK || rctx->rc == CURLE_WRITE_ERROR))
        *http_status = rctx->reply_status;
    if(errnum)
        *errnum = sxi_cbdata_geterrnum(ctx);
    if (curlcode)
        *curlcode = rctx->rc;

    if (rctx->rc == CURLE_OUT_OF_MEMORY) {
        sxi_cbdata_seterr(ctx, SXE_ECURL, "Cluster query failed: Out of memory in library routine");
        return -1;
    }

    return 0;
}

void sxi_cbdata_clear_operation(curlev_context_t *ctx) {
    if(!ctx)
        return;
    free(ctx->op);
    free(ctx->op_host);
    free(ctx->op_vol);
    free(ctx->op_path);
    ctx->op = NULL;
    ctx->op_host = NULL;
    ctx->op_vol = NULL;
    ctx->op_path = NULL;
}

void sxi_cbdata_set_operation(curlev_context_t *ctx, const char *op, const char *host, const char *vol, const char *path) {
    if (!ctx)
        return;
    sxi_cbdata_clear_operation(ctx);
    if(op)
        ctx->op = strdup(op);
    if (host)
        ctx->op_host = strdup(host);
    if (vol)
        ctx->op_vol = strdup(vol);
    if (path)
        ctx->op_path = strdup(path);
}

void sxi_cbdata_seterr(curlev_context_t *ctx, enum sxc_error_t err, const char *fmt, ...) {
    va_list ap;

    if(!ctx)
        return;
    ctx->errnum = err;
    va_start(ap, fmt);
    vsnprintf(ctx->errbuf, sizeof(ctx->errbuf) - 1, fmt, ap);
    va_end(ap);
    ctx->errbuf[sizeof(ctx->errbuf)-1] = '\0';
}

void sxi_cbdata_set_content_type(curlev_context_t *cbdata, enum content_type type)
{
    if(cbdata)
        cbdata->recv_ctx.content_type = type;
}

void sxi_cbdata_set_etag(curlev_context_t *cbdata, const char* etag, unsigned etag_len)
{
    if (cbdata) {
        struct recv_context *rctx = &cbdata->recv_ctx;
        if (etag_len < sizeof(rctx->etag)) {
            if(etag)
                memcpy(rctx->etag, etag, etag_len);
            rctx->etag[etag_len] = '\0';
        }
    }
}

char* sxi_cbdata_get_etag(curlev_context_t *ctx)
{
    char *etag = NULL;
    if (ctx) {
        etag = strdup(ctx->recv_ctx.etag);
        if (!etag)
            sxi_cbdata_setsyserr(ctx, SXE_EMEM, "failed to duplicate etag");
    }
    return etag;
}

void sxi_cbdata_setsyserr(curlev_context_t *ctx, enum sxc_error_t err, const char *fmt, ...) {
    struct sxi_fmt f;
    va_list ap;

    if(!ctx)
        return;
    sxi_fmt_start(&f);
    va_start(ap, fmt);
    sxi_vfmt_syserr(&f, fmt, ap);
    va_end(ap);

    sxi_cbdata_seterr(ctx, err, "%s", f.buf);
}

void sxi_cbdata_setclusterr(curlev_context_t *ctx, const char *nodeid, const char *reqid, int status,
                     const char *msg, const char *details)
{
    char httpcode[16];
    struct sxi_fmt f;
    sxc_client_t *sx;
    if (!ctx)
        return;
    sx = sxi_conns_get_client(sxi_cbdata_get_conns(ctx));
    if(!sx)
        return;
    if (!*msg) {
        snprintf(httpcode, sizeof(httpcode), "HTTP code %d", status);
        msg = httpcode;
    }
    sxi_fmt_start(&f);
    sxi_fmt_msg(&f, "Failed to %s: %s", ctx->op ? ctx->op : "query cluster", msg);
    if (ctx->op_host) {
        sxi_fmt_msg(&f, ": sx://%s", ctx->op_host);
        if (ctx->op_vol) {
            sxi_fmt_msg(&f, "/%s", ctx->op_vol);
            if (ctx->op_path) {
                sxi_fmt_msg(&f, "/%s", ctx->op_path);
            }
        }
    }
    if(status == 500 || status == 503) {
        sxi_fmt_msg(&f," (on");
        if (nodeid)
            sxi_fmt_msg(&f, " node:%s", nodeid);
        if (reqid)
            sxi_fmt_msg(&f, " reqid:%s", reqid);
        sxi_fmt_msg(&f, ")");
        if (sxc_is_verbose(sx) && details && *details)
            sxi_fmt_msg(&f, "\nHTTP %d: %s", status, details);
    }
    sxi_cbdata_seterr(ctx, (status == 403 || status == 401) ? SXE_EAUTH : status == 429 ? SXE_EAGAIN : SXE_ECOMM, "%s", f.buf);
    sxi_cbdata_clear_operation(ctx);
    SXDEBUG("Cluster query failed (HTTP %d): %s", status, f.buf);
    if (details && *details)
        SXDEBUG("Cluster error: %s", details);
}


void sxi_cbdata_clearerr(curlev_context_t *cbdata) {
    if(!cbdata)
        return;
    if(cbdata->errnum != SXE_NOERROR)
        CBDATADEBUG("Clearing error stored in cbdata [%d]: %s", cbdata->errnum, cbdata->errbuf);
    cbdata->errnum = SXE_NOERROR;
    strcpy(cbdata->errbuf, "No error");
}

const char *sxi_cbdata_geterrmsg(const curlev_context_t *ctx) {
    if(!ctx)
        return NULL;

    if(ctx->errnum != SXE_NOERROR)
        return ctx->errbuf;
    else
        return "No error";
}

enum sxc_error_t sxi_cbdata_geterrnum(const curlev_context_t *ctx) {
    if(!ctx)
        return SXE_NOERROR;

    return ctx->errnum;
}

int sxi_cbdata_restore_global_error(sxc_client_t *sx, curlev_context_t *cbdata) {
    if(!sx || !cbdata)
        return 1;

    if(sxc_geterrnum(sx) != SXE_NOERROR) {
        sxi_cbdata_seterr(cbdata, sxc_geterrnum(sx), "%s", sxc_geterrmsg(sx));
        sxc_clearerr(sx);
    }
    return 0;
}

sxi_conns_t *sxi_cbdata_get_conns(curlev_context_t *ctx)
{
    return ctx ? ctx->conns : NULL;
}

int sxi_cbdata_wait(curlev_context_t *ctx, curl_events_t *e, long *http_status)
{
    if (ctx) {
        struct recv_context *rctx = &ctx->recv_ctx;
        while (!rctx->finished) {
            if (sxi_curlev_poll(e))
                return -2;
        }
        return sxi_cbdata_result(ctx, NULL, NULL, http_status);
    }
    return -2;
}

static void sxi_cbdata_finish(curl_events_t *e, curlev_context_t **ctxptr, const char *url, error_cb_t err)
{
    struct recv_context *rctx;
    curlev_context_t *ctx;
    sxc_client_t *sx;
    if (!ctxptr)
        return;
    ctx = *ctxptr;
    rctx = &ctx->recv_ctx;
    sx = sxi_conns_get_client(ctx->conns);
    ctx->recv_ctx.finished = 1;

    if (rctx->rc != CURLE_OK) {
        const char *strerr = curl_easy_strerror(rctx->rc);
        SXDEBUG("curl perform failed: %s, %s",
                strerr, rctx->errbuf);
        if (rctx->rc != CURLE_WRITE_ERROR) {
            const char *msg = *rctx->errbuf ? rctx->errbuf : strerr;
            if (rctx->rc == CURLE_SSL_CACERT && sxi_curlev_has_cafile(e))
                sxi_cbdata_seterr(ctx, SXE_ECURL, "%s: Possible MITM attack, see http://www.skylable.com/docs/faq#Possible_MITM_attack",
                           strerr);
            else {
                SXDEBUG("%s: %s", url ? url : "", msg);
                if(rctx->rc != CURLE_ABORTED_BY_CALLBACK || !ctx->soft_timeout) {
                    if(ctx->hard_timeout && rctx->rc == CURLE_OPERATION_TIMEDOUT)
                        sxi_cbdata_seterr(ctx, SXE_ECURL, "Failed to %s: Request timeout", ctx->op ? ctx->op : "query cluster");
                    else
                        sxi_cbdata_seterr(ctx, SXE_ECURL, "Failed to %s: %s", ctx->op ? ctx->op : "query cluster", msg);
                }
            }
        }
    } else if (rctx->reply_status > 0 && rctx->reason && rctx->reasonsz > 0) {
        rctx->reason[rctx->reasonsz] = '\0';
        if (err)
            err(ctx, rctx->reply_status, rctx->reason);
    }

    do {
    if (ctx->retry.cb && (rctx->rc != CURLE_OK || rctx->reply_status / 100 != 2) && rctx->reply_status != 413) {
        int n = sxi_hostlist_get_count(&ctx->retry.hosts);
        if (++ctx->retry.hostidx >= n) {
            if (ctx->retry.retries < 2 || ctx->recv_ctx.reply_status == 429) {
                ctx->retry.retries++;
                ctx->retry.hostidx = 0;
                if (ctx->recv_ctx.reply_status == 429 && ctx->retry.jobs) {
                    if (sxi_job_wait(ctx->conns, ctx->retry.jobs)) {
                        SXDEBUG("job wait failed");
                    }
                }
                sxi_retry_throttle(sx, ctx->retry.retries);
            }
        }
        const char *host = sxi_hostlist_get_host(&ctx->retry.hosts, ctx->retry.hostidx);
        if (sxi_retry_check(ctx->retry.retry, ctx->retry.retries * n + ctx->retry.hostidx))
            break;
        sxi_cbdata_set_operation(ctx, ctx->retry.op, NULL, NULL, NULL);
        sxi_retry_msg(sx, ctx->retry.retry, host);
        sxi_cbdata_reset(ctx);
        if (host) {
            if (!ctx->retry.cb(ctx, ctx->conns, host,
                               ctx->retry.verb, ctx->retry.query, ctx->retry.content, ctx->retry.content_size,
                               ctx->retry.setup_callback,
                               ctx->data_cb)) {
                sxi_cbdata_unref(ctxptr);
                return; /* not finished yet, context reused */
            }
        }
        else {
            sxi_cbdata_seterr(ctx, SXE_EAGAIN, "All %d hosts returned failure, retried %d times",
                    sxi_hostlist_get_count(&ctx->retry.hosts),
                    ctx->retry.retries);
            sxi_retry_done(&ctx->retry.retry);
        }
    }
    } while(0);
    if (ctx->finish_cb)
        ctx->finish_cb(ctx, url);
    sxi_cbdata_unref(ctxptr);
}

enum cert_status { CERT_UNKNOWN=0, CERT_ACCEPTED, CERT_REJECTED };

struct curlev {
    curlev_context_t *ctx;
    char *host;
    sxi_ht *hosts; /* Hold information about active connections for each host */
    char *cluster;
    char *url;
    struct curl_slist *slist;
    CURL *curl;
    head_cb_t head;
    error_cb_t error;
    request_data_t body;
    enum sxi_cluster_verb verb;
    reply_t reply;
    struct curl_slist *resolve;
    int ssl_verified;/* 1 = OK; -1 = FAILED; 0 = not verified yet */
    int ssl_ctx_called;
    int is_http;
    int verify_peer;
    int quiet;
    enum cert_status cert_status;
    uint16_t port;

    struct timeval last_progress_time; /* Start or last xfer progress timestamp on this multi handle */
    int64_t total_xfer; /* Total number of bytes transferred so far */
};

static void ev_free(curlev_t *ev)
{
    if (!ev)
        return;
    if (ev->slist) {
        curl_slist_free_all(ev->slist);
        ev->slist = NULL;
    }
    if (ev->resolve) {
        curl_slist_free_all(ev->resolve);
        ev->resolve = NULL;
    }
    if (ev->curl)
        curl_easy_cleanup(ev->curl);
    free(ev->host);
    memset(ev, 0, sizeof(*ev));
}

static const struct curl_certinfo *get_certinfo(curlev_t *ctx);
static int print_certificate_info(sxc_client_t *sx, const struct curl_certinfo *info);

static void cert_ask_question(sxc_client_t *sx, curlev_t *ev, const struct curl_certinfo *info)
{
    const struct curl_certinfo *certinfo = get_certinfo(ev);
    if (ev->verify_peer || ev->cert_status != CERT_UNKNOWN)
        return;
    if (ev->quiet) {
        ev->cert_status = CERT_ACCEPTED;
    } else if (ev->cert_status == CERT_UNKNOWN){
        char ans;
        int inp;
        SXDEBUG("cert_status: %d", ev->cert_status);
        if (print_certificate_info(sx, certinfo)) {
            SXDEBUG("certificate chain info not available yet");
            ev->ssl_ctx_called = 0;
            return;
        }
        inp = sxi_get_input(sx, SXC_INPUT_YN, "Do you trust this SSL certificate?", "n", &ans, 1);
        if(inp != 1 && ans != 'y') {
            ev->cert_status = CERT_REJECTED;
        } else {
            ev->cert_status = CERT_ACCEPTED;
        }
    }
}

static int check_ssl_cert(curlev_t *ev)
{
    const struct curl_tlssessioninfo *info;
    sxi_conns_t *conns = ev->ctx ? ev->ctx->conns : NULL;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if (ev->is_http)
        return 0;
    if (!ev->ssl_ctx_called) {
        SXDEBUG("querying TLS_SESSION");
        const struct curl_slist *to_info = NULL;
        CURLcode res = curl_easy_getinfo(ev->curl, CURLINFO_TLS_SESSION, &to_info);
        memcpy(&info, &to_info, sizeof(to_info));
        if (!res) {
            int rc;
            if (info->backend == CURLSSLBACKEND_NONE)
                return 0;/* no SSL connection yet */
            rc = sxi_sslctxfun(sx, ev, info);
            if (rc == -EAGAIN)
                return 0;
            SXDEBUG("ctx function called");
            ev->ssl_ctx_called = 1;
            if (rc)
                return 1;
            if (1 == ev->ssl_verified) {
                SXDEBUG("certificate verified (verify_peer=%d)", ev->verify_peer);
                const struct curl_certinfo *certinfo = get_certinfo(ev);
                cert_ask_question(sx, ev, certinfo);
                if (ev->cert_status == CERT_REJECTED) {
                    sxi_seterr(sx, SXE_ECOMM, "User rejected the certificate");
                    return 1;
                }
                if (ev->cert_status == CERT_ACCEPTED) {
                    rc = sxi_ssl_usertrusted(sx, ev, info);
                    if (rc) {
                        SXDEBUG("failed to set user trust");
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

static size_t headfn(void *ptr, size_t size, size_t nmemb, curlev_t *ev)
{
    curlev_context_t *ctx = ev ? ev->ctx : NULL;
    struct recv_context *rctx = ctx ? &ctx->recv_ctx : NULL;
    if (!rctx)
        return 0;
    if (rctx->reply_status == -1 || !rctx->reply_status)
        curl_easy_getinfo(ev->curl, CURLINFO_RESPONSE_CODE, &rctx->reply_status);

    if (!rctx->fail && rctx->reply_status >= 400)
        rctx->fail = 1;
    if (!ev || check_ssl_cert(ev))
        return 0;/* fail */
    if (ev->ssl_verified < 0 && !ev->is_http) {
        sxi_cbdata_seterr(ctx, SXE_ECURL, "SSL certificate not verified");
        return 0;
    }
    if (!ev->head)
        return size * nmemb;
    switch (ev->head(ctx, rctx->reply_status, ptr, size, nmemb)) {
        case HEAD_SEEN:
            rctx->header_seen = 1;
            /* fall-through */
        case HEAD_OK:
            return size * nmemb;
        default:
            return 0;/* fail */
    }
}

static size_t writefn(void *ptr, size_t size, size_t nmemb, void *ctxptr) {
    curlev_context_t *ctx = ctxptr;
    struct recv_context *wd = ctx ? &ctx->recv_ctx : NULL;
    sxi_conns_t *conns;
    sxc_client_t *sx;

    if(!wd)
	return 0;

    conns = ctx->conns;
    sx = sxi_conns_get_client(conns);
    size *= nmemb;

    if(!wd->header_seen) {
	if(wd->reply_status == 502 || wd->reply_status == 504) {
	    /* Reply is very likely to come from a busy cluster */
	    sxi_cbdata_seterr(ctx, SXE_ECOMM, "Bad cluster reply(%ld): The cluster may be under maintenance or overloaded, please try again later", wd->reply_status);
            wd->fail = 1;
	} else if(wd->reply_status == 414) {
	    sxi_cbdata_seterr(ctx, SXE_ECOMM, "URI too long: Path to the requested resource is too long");
	    wd->fail = 1;
        } else if(!ctx->allow_non_sx_resp) {
            /* Reply is certainly not from sx */
            sxi_cbdata_seterr(ctx, SXE_ECOMM, "The server contacted is not an SX Cluster node (http status: %ld)", wd->reply_status);
            wd->fail = 1;
        }
    }

    if (!wd->fail && wd->reply_status >= 400)
	wd->fail = 1;
    if(wd->fail) {
	SXDEBUG("error reply: %.*s\n", (int)size, (char *)ptr);
	if(conns && wd->content_type == CONTENT_TYPE_JSON) {
	    wd->reason = sxi_realloc(sx, wd->reason, size + wd->reasonsz + 1);
	    if(!wd->reason)
		return 0;
	    memcpy(wd->reason + wd->reasonsz, ptr, size);
	    wd->reasonsz += size;
	    return nmemb;
	} else return 0;
    }

    if(!ctx->data_cb)
	return nmemb;

    if(ctx->data_cb(ctx, ptr, size) == 0)
	return nmemb;

    SXDEBUG("failing due to callback failure");
    return 0;
}

/* Hold information needed to control transfer bandwidth */
typedef struct {
    int64_t local_limit; /* Bandwidth limit [bytes per second] */
    int64_t global_limit; /* Bandwidth limit for whole transfer [bytes per second] */
} bandwidth_t;

/* Maximal number of connections to be done in parallel */
#define MAX_EVENTS                              64
#define MAX_ACTIVE_CONNECTIONS                  5
#define MAX_ACTIVE_PER_HOST                     2
#define HOST_STATS_WINDOW_SIZE                  256
#define MIN_XFER_THRESHOLD                      4096.0
#define MIN_EVENTS_THRESHOLD                    4

/* Hold information about active connections for each host */
struct host_info {
    char *host; /* Host address */
    unsigned int active; /* Number of active connections to host */
    double dl_speed[HOST_STATS_WINDOW_SIZE];
    unsigned int dl_index; /* Current position in dl_speed window */
    unsigned int dl_counter; /* Number of dl measures (max is HOST_STATS_WINDOW_SIZE) */
    double ul_speed[HOST_STATS_WINDOW_SIZE];
    unsigned int ul_index; /* Current position in ul_speed window */
    unsigned int ul_counter; /* Number of ul measures (max is HOST_STATS_WINDOW_SIZE) */
};

static struct host_info *host_info_new(const char *host) {
    struct host_info *info = malloc(sizeof(struct host_info));
    unsigned int i;

    if(!info)
        return NULL;

    info->host = strdup(host);
    if(!info->host) {
        free(info);
        return NULL;
    }

    for(i = 0; i < HOST_STATS_WINDOW_SIZE; i++) {
        info->ul_speed[i] = 0.0;
        info->dl_speed[i] = 0.0;
    }
    info->ul_index = 0;
    info->ul_counter = 0;
    info->dl_index = 0;
    info->dl_counter = 0;
    info->active = 0;
    return info;
}

static void host_info_free(struct host_info* info) {
    if(info) {
        free(info->host);
    }
    free(info);
}

/* Forward declaration */
struct ev_queue;

/* Connections pool */
typedef struct {
    sxc_client_t *sx;
    struct ev_queue *queue; /* Queued connections */
    unsigned int max_active_total; /* Total number of active connections */
    unsigned int max_active_per_host; /* Number of active connections that each node can connect */
    curlev_t *active; /* Connections that are currently used */
    unsigned int active_count; /* Number of active connections */
    sxi_ht *hosts; /* Hold struct host_active_info structures */
} connection_pool_t;

struct ev_queue_node {
    curlev_t *element;
    struct ev_queue_node *next;
};

/* 
 * Ivoked for each element in the list during ev_queue_get() until first matching has been found. 
 * Element will be removed only if rm_check() returns 1. 
 */
typedef int (*rm_check)(const connection_pool_t *pool, const curlev_t *element);

struct ev_queue {
    struct ev_queue_node *head; /* First list element */
    struct ev_queue_node *tail; /* Last element */
    unsigned int length; /* Number of elements */
    rm_check checker; /* Function used to check if element should be removed */
    connection_pool_t *pool; /* Parent */
};

typedef struct ev_queue ev_queue_t;

static struct host_info *connection_pool_get_host_info(const connection_pool_t *pool, const char *host) {
    struct host_info *ret = NULL;

    if(!pool || !host)
        return NULL;

    /* Get active host information reference */
    if(sxi_ht_get(pool->hosts, host, strlen(host), (void**)&ret)) {
        sxi_seterr(pool->sx, SXE_EARG, "Host %s is not stored in active hosts hashtable", host);
        return NULL;
    }

    if(!ret) {
        sxi_seterr(pool->sx, SXE_EARG, "NULL active host information reference");
        return NULL;
    }
    return ret;
}

/* Update connection information for host */
static int update_active_host(connection_pool_t *pool, const curlev_t *ev) {
    double dl_speed = 0, ul_speed = 0;
    double dl_size = 0, ul_size = 0;
    struct host_info *hi;

    if(!ev)
        return 1;

    if(!pool) {
        sxi_cbdata_seterr(ev->ctx, SXE_EARG, "NULL argument");
        return 1;
    }

    /* Get download speed from curl handle */
    if(curl_easy_getinfo(ev->curl, CURLINFO_SPEED_DOWNLOAD, &dl_speed)) {
        sxi_cbdata_seterr(ev->ctx, SXE_ECURL, "Failed to get download speed");
        return 1;
    }

    /* Get download size from curl handle */
    if(curl_easy_getinfo(ev->curl, CURLINFO_SIZE_DOWNLOAD, &dl_size)) {
        sxi_cbdata_seterr(ev->ctx, SXE_ECURL, "Failed to get download size");
        return 1;
    }

    /* Get upload speed from curl handle */
    if(curl_easy_getinfo(ev->curl, CURLINFO_SPEED_UPLOAD, &ul_speed)) {
        sxi_cbdata_seterr(ev->ctx, SXE_ECURL, "Failed to get upload speed");
        return 1;
    }

    /* Get upload size from curl handle */
    if(curl_easy_getinfo(ev->curl, CURLINFO_SIZE_UPLOAD, &ul_size)) {
        sxi_cbdata_seterr(ev->ctx, SXE_ECURL, "Failed to get upload size");
        return 1;
    }

    /* Get active host information reference */
    if(sxi_ht_get(pool->hosts, ev->host, strlen(ev->host), (void**)&hi)) {
        sxi_cbdata_seterr(ev->ctx, SXE_EARG, "Host %s is not stored in active hosts hashtable", ev->host);
        return 1;
    }

    if(!hi) {
        sxi_cbdata_seterr(ev->ctx, SXE_EARG, "NULL active host information reference");
        return 1;
    }

    /* Insert current upload measures into window if needed */
    if(ul_size > MIN_XFER_THRESHOLD) {
        hi->ul_speed[hi->ul_index] = ul_speed;
        hi->ul_index = (hi->ul_index + 1) & (HOST_STATS_WINDOW_SIZE-1);
        if(hi->ul_counter < HOST_STATS_WINDOW_SIZE)
            hi->ul_counter++;
    }

    /* Insert current download measures into window if needed */
    if(dl_size > MIN_XFER_THRESHOLD) {
        hi->dl_speed[hi->dl_index] = dl_speed;
        hi->dl_index = (hi->dl_index + 1) & (HOST_STATS_WINDOW_SIZE-1);
        if(hi->dl_counter < HOST_STATS_WINDOW_SIZE)
            hi->dl_counter++;
    }

    /* Decrease number of active connections for given host */
    hi->active--;
    return 0;
}

static int get_host_info_speed(const struct host_info *hi, double *ul, double *dl) {
    double dl_speed = 0.0, ul_speed = 0.0;
    unsigned int i;

    if(!hi)
        return 1;

    if(hi->ul_counter >= MIN_EVENTS_THRESHOLD) {
        for(i = 0; i < hi->ul_counter; i++)
            ul_speed += hi->ul_speed[i];
    }
    if(hi->dl_counter >= MIN_EVENTS_THRESHOLD) {
        for(i = 0; i < hi->dl_counter; i++)
            dl_speed += hi->dl_speed[i];
    }

    ul_speed = hi->ul_counter >= MIN_EVENTS_THRESHOLD ? ul_speed / (double)hi->ul_counter : 0.0;
    dl_speed = hi->dl_counter >= MIN_EVENTS_THRESHOLD ? dl_speed / (double)hi->dl_counter : 0.0;

    if(ul)
        *ul = ul_speed;
    if(dl)
        *dl = dl_speed;
    return 0;
}

static ev_queue_t *ev_queue_new(connection_pool_t *pool, rm_check checker) {
    ev_queue_t *q = NULL;
    sxc_client_t *sx = NULL;

    if(!pool) {
        return NULL;
    }
    sx = pool->sx;

    q = calloc(1, sizeof(*q));
    if(!q) {
        SXDEBUG("OOM Allocating cURL events queue");
        return NULL;
    }
    q->checker = checker;
    q->pool = pool;
    return q;
}

/* Free events queue */
static void ev_queue_free(ev_queue_t *q) {
    unsigned int i;
    struct ev_queue_node *n = NULL;
    sxc_client_t *sx = NULL;

    if(!q) 
        return;
        
    sx = q->pool->sx;
    n = q->head;

    /* iterate over all elements */
    for(i = 0; i < q->length; i++) {
        struct ev_queue_node *next;

        if(!n) {
            /* Number of elements should be exactly the same as number of not NULL pointers */
            SXDEBUG("Error freeing cURL events queue: invalid number of elements");
            break;
        }
        next = n->next;

        ev_free(n->element);
        free(n);
        n = next;
    }

    free(q);
}

/* Add element to events queue */
static int ev_queue_add(ev_queue_t *q, curlev_t *element) {
    struct ev_queue_node *n = NULL;
    sxc_client_t *sx = NULL;

    if(!q || !element) {
        SXDEBUG("NULL argument");
        return 1;
    }
    sx = q->pool->sx;

    if(q->length >= MAX_EVENTS) {
        SXDEBUG("Reachecd maximal number of events");
        return 1;
    }

    n = calloc(1, sizeof(*n));
    if(!n) {
        SXDEBUG("OOM Allocating new ev_queue_node");
        return 1;
    }

    n->element = element;
    if(q->tail) {
        q->tail->next = n;
    } else {
        /* First element in the queue */
        q->head = n;
    }
    q->tail = n;
    q->length++;
    return 0;
}

/* Get and remove element from queue */
static curlev_t *ev_queue_get(ev_queue_t *q) {
    struct ev_queue_node *n = NULL; /* Current element */
    struct ev_queue_node *p = NULL; /* Previous element */
    unsigned int i;
    sxc_client_t *sx = NULL;

    if(!q) {
        return NULL;
    }
    sx = q->pool->sx;

    n = q->head;
    for(i = 0; i < q->length; i++) {
        if(!n) {
            SXDEBUG("Error getting cURL events from queue: invalid number of elements");
            return NULL;
        }

        if(!q->checker || q->checker(q->pool, n->element) == 1) {
            curlev_t *element = n->element;

            /* Remove node */
            q->length--;
            if(!p) {
                /* Previous element is NULL, we are removing first element */
                q->head = n->next;
            } else {
                /* Previous element is not NULL, we are removing middle or last element */
                p->next = n->next;
            }

            if(n == q->tail) {
                q->tail = p;
            }
            free(n);
            return element;
        } 

        p = n;
        n = n->next;
    }

    /* Element not found */
    return NULL;
}

static int ev_queue_length(ev_queue_t *q) {
    if(!q) {
        return 0;
    }

    return q->length;
}

/* Return 1 if cURL event destination host hold less than pool->max_active_per_host */
static int check_host_active_count(const connection_pool_t *pool,  const curlev_t *ev) {
    struct host_info *host = NULL;

    if(!ev) {
        return 0;
    }

    if(sxi_ht_get(ev->hosts, (void*)ev->host, strlen(ev->host), (void **)&host) || !host) {
        /* Could not get host info, this is an error, return -1 */
        return -1;
    }

    return host->active < pool->max_active_per_host ? 1 : 0;
}

/* Get new connection pool instance */
static connection_pool_t *connection_pool_new(sxc_client_t *sx) {
    connection_pool_t *pool = NULL;

    if(!sx) {
        return NULL;
    }

    pool = calloc(1, sizeof(*pool));
    if(!pool) {
        return NULL;
    }

    pool->sx = sx;
    pool->max_active_total = MAX_ACTIVE_CONNECTIONS;
    pool->max_active_per_host = MAX_ACTIVE_PER_HOST;

    pool->active = calloc(MAX_EVENTS, sizeof(*pool->active));
    if(!pool->active) {
        SXDEBUG("OOM Could not allocate array of events");
        free(pool);
        return NULL;
    }

    pool->queue = ev_queue_new(pool, check_host_active_count);
    if(!pool->queue) {
        SXDEBUG("OOM Could not allocate queue");
        free(pool->active);
        free(pool);
        return NULL;
    }

    pool->hosts = sxi_ht_new(sx, 64);
    if(!pool->hosts) {
        SXDEBUG("OOM Could not allocate hosts hash table");
        ev_queue_free(pool->queue);
        free(pool->active);
        free(pool);
        return NULL;
    }

    return pool;
}

/* Free connections pool */
static void connection_pool_free(connection_pool_t *pool) {
    unsigned int i = 0;
    struct host_info *info = NULL;
    if(!pool)
        return;

    for(i = 0; i < MAX_EVENTS; i++) {
        ev_free(&pool->active[i]);
    }

    ev_queue_free(pool->queue);

    sxi_ht_enum_reset(pool->hosts);
    while(!sxi_ht_enum_getnext(pool->hosts, NULL, NULL, (const void **)&info))
        host_info_free(info);
    sxi_ht_free(pool->hosts);
    free(pool->active);
    free(pool);
}

/* to avoid using too much memory */
struct curl_events {
    CURLM *multi;
    CURLSH *share;
    sxi_conns_t *conns;
    int running;
    int verbose;
    int used;
    int depth;
    int added_notpolled;
    const char *cafile;
    char *savefile;
    int cert_saved, quiet, cert_rejected;
    int disable_proxy;

    /* Connections pool handle connections shared between hosts */
    connection_pool_t *conn_pool;

    /* Used for bandwidth throttling */
    bandwidth_t bandwidth;
};

/* Classify hosts by connection speed */
static double *classify_hosts(sxi_conns_t *conns, const sxi_hostlist_t *hosts, float distribution, sxc_xfer_direction_t direction) {
    unsigned int i;
    double speed_sum = 0.0, dnhosts, speed_counter = 0.0;
    double *speed_ratings;
    curl_events_t *e = sxi_conns_get_curlev(conns);
    struct host_info *hi = NULL;

    if(!hosts)
        return NULL;

    if(!e) {
        sxi_seterr(sxi_conns_get_client(conns), SXE_EARG, "NULL argument");
        return NULL;
    }

    dnhosts = (double)hosts->nhosts;
    speed_ratings = malloc(sizeof(double) * hosts->nhosts);
    if(!speed_ratings) {
        sxi_seterr(sxi_conns_get_client(conns), SXE_EMEM, "Failed to allocate ratings array");
        return NULL;
    }

    /* Trivial list needs trivial assignment */
    if(hosts->nhosts<2) {
        if(hosts->nhosts)
            speed_ratings[0] = 1.0;
        return speed_ratings;
    }

    for(i = 0; i < hosts->nhosts; i++) {
        if(sxi_ht_get(e->conn_pool->hosts, hosts->hosts[i], strlen(hosts->hosts[i]), (void**)&hi) || !hi) {
            speed_ratings[i] = 0.0;
        } else {
            if(get_host_info_speed(hi, direction == SXC_XFER_DIRECTION_UPLOAD ? &speed_ratings[i] : NULL, direction == SXC_XFER_DIRECTION_UPLOAD ? NULL : &speed_ratings[i])) {
                sxi_seterr(sxi_conns_get_client(conns), SXE_EARG, "Failed to get average speed for host %s", hi->host);
                free(speed_ratings);
                return NULL;
            }
            if(speed_ratings[i] > 0.0) {
                /* Square speed to get higher variance */
                speed_ratings[i] *= speed_ratings[i];
                speed_sum += speed_ratings[i];
                speed_counter++;
            }
        }
    }

    /* Normalize ratings */
    for(i = 0; i < hosts->nhosts; i++) {
        if(speed_ratings[i] > 0.0)
            speed_ratings[i] = ((speed_ratings[i] / speed_sum) * speed_counter) / dnhosts;
        else
            speed_ratings[i] = 1.0 / dnhosts;
    }

    return speed_ratings;
}

const char *sxi_hostlist_get_optimal_host(sxi_conns_t * conns, const sxi_hostlist_t *list, sxc_xfer_direction_t direction) {
    unsigned int i;
    double *ratings;
    unsigned int r = sxi_rand();
    float rd = (float)r / UINT_MAX;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    float distribution = sxi_get_node_preference(sx);

    if(!conns || !list || !list->nhosts)
        return NULL;

    if(distribution < 0.0 || distribution > 1.0) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument: %.2f", distribution);
        return NULL;
    }
    if(distribution < 1.0 && rd > distribution)
        return list->hosts[0];

    ratings = classify_hosts(conns, list, distribution, direction);
    if(!ratings)
        return NULL;

    if(distribution < 1.0) {
        r = sxi_rand();
        rd = (float)r / UINT_MAX;
        double sum = 0.0;

        for(i = 0; i < list->nhosts; i++) {
            sum += ratings[i];
            if(rd < sum) {
                free(ratings);
                return list->hosts[i];
            }
        }
    } else {
        unsigned int max = 0;

        /* Choose the fastest node */
        for(i = 1; i < list->nhosts; i++) {
            if(ratings[i] > ratings[max])
                max = i;
        }

        free(ratings);
        return list->hosts[max];
    }

    free(ratings);
    if(list->nhosts)
        return list->hosts[list->nhosts-1];
    return NULL;
}

int sxi_set_host_speed_stats(sxi_conns_t *conns, const char *host, double ul, double dl) {
    struct host_info *hi;
    connection_pool_t *pool;
    curl_events_t *e;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    unsigned int i;

    if(!conns)
        return 1;
    if(!host) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    e = sxi_conns_get_curlev(conns);
    if(!e || !e->conn_pool) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }
    pool = e->conn_pool;

    hi = connection_pool_get_host_info(pool, host);

    /* Get active host information reference */
    if(sxi_ht_get(pool->hosts, host, strlen(host), (void**)&hi)) {
        /* Host could not be found, add given host */
        hi = host_info_new(host);
        if(!hi) {
            SXDEBUG("OOM Could not allocate memory for host");
            return 1;
        }
        if(sxi_ht_add(pool->hosts, host, strlen(host), (void*)hi)) {
            SXDEBUG("OOM Could not allocate memory for host");
            host_info_free(hi);
            return 1;
        }
    }

    if(!hi) {
        sxi_seterr(sx, SXE_EARG, "NULL active host information reference");
        return 1;
    }

    /* Fill the table at minimum threshold to make speed to be taken into account for speed averages */
    for(i = 0; i < MIN_EVENTS_THRESHOLD; i++) {
        hi->dl_speed[i] = dl;
        hi->ul_speed[i] = ul;
    }
    hi->ul_counter = i;
    hi->ul_index = i;
    hi->dl_counter = i;
    hi->dl_index = i;

    return 0;
}

int sxi_get_host_speed_stats(sxi_conns_t *conns, const char *host, double *ul, double *dl) {
    struct host_info *hi;
    curl_events_t *e;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(!conns)
        return 1;
    if(!host) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    e = sxi_conns_get_curlev(conns);
    if(!e || !e->conn_pool) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    hi = connection_pool_get_host_info(e->conn_pool, host);
    if(!hi) /* Error should already be set */
        return 1;

    if(get_host_info_speed(hi, ul, dl)) {
        sxi_seterr(sxi_conns_get_client(conns), SXE_EARG, "Failed to get host %s speed", host);
        return 1;
    }

    return 0;
}

/* Nullify context for each curlev_t element from active and inactive cURL events */
void sxi_curlev_nullify_upload_context(sxi_conns_t *conns, void *ctx) {
    unsigned int i;
    connection_pool_t *pool;
    struct ev_queue_node *n;
    curl_events_t *e;
    if(!ctx || !conns)
        return;
    e = sxi_conns_get_curlev(conns);
    if(!e)
        return;
    pool = e->conn_pool;
    if(!pool || !pool->queue)
        return;

    for(i = 0; i < MAX_EVENTS; i++) {
        curlev_context_t *c = pool->active[i].ctx;
        if(!c)
            continue;
        switch(c->tag) {
            case CTX_UPLOAD_HOST:
                if(c->u.host_ctx == ctx)
                    c->u.host_ctx = NULL;
                break;
            case CTX_DOWNLOAD:
                if(c->u.download_ctx == ctx)
                    c->u.download_ctx = NULL;
                break;
            default: 
                break;
        }
    }

    n = pool->queue->head;

    /* iterate over all elements and nullify context */
    while(n) {
        if(n->element && n->element->ctx) {
            curlev_context_t *c = n->element->ctx;
            switch(c->tag) {
                case CTX_UPLOAD_HOST:
                    if(c->u.host_ctx == ctx)
                        c->u.host_ctx = NULL;
                    break;
                case CTX_DOWNLOAD:
                    if(c->u.download_ctx == ctx)
                        c->u.download_ctx = NULL;
                    break;
                default: 
                    break;
            }
        }
        n = n->next;
    }
}

static void ctx_err(curlev_context_t *ctx, CURLcode rc, const char *msg)
{
    if (!ctx)
        return;
    ctx->recv_ctx.rc = rc;
    sxi_strlcpy(ctx->recv_ctx.errbuf, msg, sizeof(ctx->recv_ctx.errbuf));
    sxi_cbdata_seterr(ctx, SXE_EARG, "ev_add: bad argument");
}

#define EVENTSDEBUG(e, ...) do {\
    if (e && e->conns) {\
        sxc_client_t *_sx = sxi_conns_get_client(e->conns); \
	sxi_debug(_sx, __func__, __VA_ARGS__);\
    }} while (0)

#define EVDEBUG(ev, ...) do {\
    if (ev && ev->ctx && ev->ctx->conns) {\
        sxc_client_t *_sx = sxi_conns_get_client(ev->ctx->conns); \
	sxi_debug(_sx, __func__, __VA_ARGS__);\
    }} while (0)

int sxi_curlev_set_bandwidth_limit(curl_events_t *e, int64_t global_bandwidth_limit, unsigned int running) {
    if(!e) {
        EVENTSDEBUG(e, "Could not set bandwidth limit, NULL argument");
        return 1;
    }

    /* Bandwidth limitation for whole process */
    e->bandwidth.global_limit = global_bandwidth_limit;

    /* Divide global bandwidth limit by up to that it can be set for each transfer */
    if(running && running < e->conn_pool->max_active_total)
        e->bandwidth.local_limit = global_bandwidth_limit / running; 
    else if(running)
        e->bandwidth.local_limit = global_bandwidth_limit / e->conn_pool->max_active_total;
    else
        e->bandwidth.local_limit = global_bandwidth_limit;

    return 0;
}

int64_t sxi_curlev_get_bandwidth_limit(const curl_events_t *e) {
    if(!e) {
        EVENTSDEBUG(e, "Could not get bandwidth limit, NULL argument");
        return -1;
    }

    return e->bandwidth.local_limit;
}

static int queue_next_inactive(curl_events_t *e);
int sxi_curlev_set_conns_limit(curl_events_t *e, unsigned int max_active, unsigned int max_active_per_host) {
    if(!e)
        return 1;

    /* Check and fallback to defaults if necessary */
    if(!max_active) max_active = MAX_ACTIVE_CONNECTIONS;
    if(!max_active_per_host) max_active_per_host = MAX_ACTIVE_PER_HOST;

    e->conn_pool->max_active_per_host = max_active_per_host;
    /* 
     * If maximal number of running connections is not increased, simply wait for current
     * connections to finish. 
     */
    if(max_active > e->conn_pool->max_active_total) {
        int ret = 0;
        /*
         * Maximal number of running connections has been increased, we have to dequeue existing
         * but not running connections.
         */
        e->conn_pool->max_active_total = max_active;
        while(e->conn_pool->active_count < e->conn_pool->max_active_total) {
            ret = queue_next_inactive(e);
            if(!ret) /* This happens if no events are queued or all events reached per-host limit */
                break;
        }
    } else {
        e->conn_pool->max_active_total = max_active;
    }
    return 0;
}

static int curl_check(curlev_t *e, CURLcode code, const char *msg)
{
    if (code != CURLE_OK) {
        e->ctx->recv_ctx.errbuf[ERRBUF_SIZE] = 0;
        EVDEBUG(e, "curl failed to %s: %s\n", msg, curl_easy_strerror(code));
        return -1;
    }
    return 0;
}

static int curlm_check(curlev_t *ev, CURLMcode code, const char *msg)
{
    if (code != CURLM_OK && code != CURLM_CALL_MULTI_PERFORM) {
        EVDEBUG(ev, "WARNING: curl multi %s: %s\n", msg,
                curl_multi_strerror(code));
        if (ev && ev->ctx)
            sxi_cbdata_seterr(ev->ctx, SXE_ECURL, "curl multi failed: %s, %s",
                       curl_multi_strerror(code), ev->ctx->recv_ctx.errbuf);
        return -1;
    }
    return 0;
}

static int curlsh_check(curl_events_t *e, CURLSHcode code)
{
    if (code != CURLSHE_OK) {
        EVENTSDEBUG(e, "WARNING: curl share: %s\n",
                curl_share_strerror(code));
        return -1;
    }
    return 0;
}

void sxi_curlev_done(curl_events_t **c)
{
    curl_events_t *e = c ? *c : NULL;
    if (!e)
        return;
    if (e->used) {
        EVENTSDEBUG(e, "Leaked %d curl events!!", e->used);
    }
    connection_pool_free(e->conn_pool);
    if (e->multi) {
        CURL *dummy;
        /* curl 7.29.0 bug: NULL dereference if multi handle has never seen an
         * easy handle */
        dummy = curl_easy_init();
        if (dummy) {
            curl_multi_add_handle(e->multi, dummy);
            curl_multi_remove_handle(e->multi, dummy);
            curl_easy_cleanup(dummy);
        }
        curlm_check(NULL, curl_multi_cleanup(e->multi), "cleanup");
        e->multi = NULL;
    }
    if (e->share) {
        curlsh_check(e, curl_share_cleanup(e->share));
        e->share = NULL;
    }
    free(e->savefile);
    free(e);
    *c = NULL;
}

curl_events_t *sxi_curlev_init(sxi_conns_t *conns)
{
    curl_events_t *x = calloc(1, sizeof(*x));
    if (!x)
        return NULL;

    x->conns = conns;
    do {
        x->cafile = "";/* verify with default root CAs */
        if (!(x->share = curl_share_init()))
            break;
        if (!(x->multi = curl_multi_init()))
            break;
        /* When pipelining is enabled curl starts counting CONNECT_TIMEOUT
         * as soon as an easy handle is added to a multi handle.
         * This causes timeouts if a lot of data is transferred for each query,
         * or if server is slow to reply to some queries.
         *
         * To avoid this either turn off pipelining, or avoid sending more than
         * 1 concurrent request to same host.
         * Turning off pipelining causes EADDRNOTAVAIL due to the repeat
         * open/close of the connection.
         *
         * A third solution would be to keep pipelining off, and reuse
         * the easy handle instead of creating a new handle */
#if LIBCURL_VERSION_NUM >= 0x071000
        CURLMcode rc2 = curl_multi_setopt(x->multi, CURLMOPT_PIPELINING, 0L);
        if (curlm_check(NULL, rc2, "set pipelining") == -1)
            break;
        rc2 = curl_multi_setopt(x->multi, CURLMOPT_MAXCONNECTS, 64);
        if (curlm_check(NULL, rc2, "set maxconnects") == -1)
            break;
#endif

        x->conn_pool = connection_pool_new(sxi_conns_get_client(conns));
        if(!x->conn_pool) {
            break;
        }
        /* Initialize bandwidth limit information */
        x->bandwidth.global_limit = 0;
        x->bandwidth.local_limit = 0;

        return x;
    } while(0);
    sxi_curlev_done(&x);
    return NULL;
}

void sxi_curlev_set_cafile(curl_events_t *ev, const char *cafile)
{
    if (ev)
        ev->cafile = cafile;
}

int sxi_curlev_has_cafile(curl_events_t *ev)
{
    return ev && ev->cafile && *ev->cafile;
}

const char* sxi_curlev_get_cafile(curl_events_t *ev)
{
    return ev && ev->cafile && *ev->cafile ? ev->cafile : NULL;
}

int sxi_curlev_set_save_rootCA(curl_events_t *ev, const char *filename, int quiet)
{
    if (!ev)
        return -1;
    free(ev->savefile);
    ev->savefile = strdup(filename);
    ev->cert_saved = 0;
    ev->cert_rejected = 0;
    ev->quiet = quiet;
    return ev->savefile ? 0 : -1;
}

int sxi_curlev_is_cert_saved(curl_events_t *ev)
{
    return ev && ev->cert_saved;
}

int sxi_curlev_is_cert_rejected(curl_events_t *ev)
{
    return ev && ev->cert_rejected;
}

void sxi_curlev_set_verbose(curl_events_t *ev, int is_verbose)
{
    if (ev)
        ev->verbose = is_verbose;
}

#if LIBCURL_VERSION_NUM < 0x071c00
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct curl_waitfd {
    curl_socket_t fd;
    short events;
    short revents;
    int running;
};

/* function introduced in 7.28.0, emulate using select on older libs */
static CURLMcode curl_multi_wait(CURLM *multi_handle,
                                 struct curl_waitfd extra_fds[],
                                 unsigned int extra_nfds,
                                 int timeout_ms, int *numfds)
{
    struct timeval *timeoutptr = NULL;
    struct timeval timeout;
    fd_set read_fd_set;
    fd_set write_fd_set;
    fd_set exc_fd_set;
    CURLMcode rc;
    int maxfd;
    int rc2;

    if (extra_nfds != 0)
        return CURLM_BAD_SOCKET;/* we could emulate this but we don't actually use it */

    FD_ZERO(&read_fd_set);
    FD_ZERO(&write_fd_set);
    FD_ZERO(&exc_fd_set);
    maxfd = -1;
    rc = curl_multi_fdset(multi_handle,
                          &read_fd_set, &write_fd_set, &exc_fd_set,
                          &maxfd);
    if (rc != CURLM_OK)
        return rc;
    do {
        struct timeval tv0, tv1;
        if (timeout_ms < 0) timeout_ms = 2000;
        if (timeout_ms >= 0) {
            timeout.tv_sec = timeout_ms / 1000;
            timeout.tv_usec = (timeout_ms % 1000) * 1000;
            timeoutptr = &timeout;
            gettimeofday(&tv0, NULL);
        }
        rc2 = select(maxfd+1, &read_fd_set, &write_fd_set, &exc_fd_set, timeoutptr);
        if (rc2 == -1 && errno != EINTR)
            return CURLM_CALL_MULTI_PERFORM;
        if (rc2 == -1) {
            gettimeofday(&tv1, NULL);
            long d = (tv1.tv_sec - tv0.tv_sec) * 1000 - (tv1.tv_usec - tv0.tv_usec)/1000;
            timeout_ms -= d;
            if (timeout_ms <= 0)
                break;
        }
    } while (rc2 == -1);
    if (numfds) {
        if (rc2 == -1)
            *numfds = 0;
        else
            *numfds = rc2;
    }
    return CURLM_OK;
}
#endif

typedef struct {
  const char *field;
  const char *value;
} header_t;

static int set_headers(curl_events_t *e, curlev_t *ev, const header_t *headers, unsigned n)
{
    char header[512];
    unsigned i;

    for (i=0;i<n;i++) {
        struct curl_slist *slist_next;

        const header_t *h = &headers[i];
        if (!h->field)
            continue;
        snprintf(header,sizeof(header),"%s: %s",h->field,h->value ? h->value : "");
        slist_next = curl_slist_append(ev->slist, header);
        if (!slist_next) {
            curl_slist_free_all(ev->slist);
            ctx_err(ev->ctx, CURLE_OUT_OF_MEMORY, "curl_slist_append: Out of memory");
            ev->slist = NULL;
            return -1;
        }
        ev->slist = slist_next;
    }
    return 0;
}

#if LIBCURL_VERSION_NUM >= 0x071000
static int sockoptfn(void *clientp, curl_socket_t curlfd, curlsocktype purpose)
{
    int reuse = 1;
    if (setsockopt(curlfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
        return 1;
    return 0;
}
#endif

#if ERRBUF_SIZE < CURL_ERROR_SIZE
#error "errbuf too small: ERRBUF_SIZE < CURL_ERROR_SIZE"
#endif

static int curlev_update_bandwidth_limit(curlev_t *ev) {
    curl_events_t *e;
    int rc;
    if(!ev || !ev->ctx)
        return 1;

    e = sxi_conns_get_curlev(ev->ctx->conns);
    if(!e)
        return 1;

    if(e->bandwidth.global_limit) {
        rc = curl_easy_setopt(ev->curl, CURLOPT_MAX_SEND_SPEED_LARGE, e->bandwidth.local_limit);
        if (curl_check(ev,rc, "set CURLOPT_MAX_SEND_SPEED_LARGE") == -1) {
            EVDEBUG(ev, "Could not set CURL max send seed");
            return 1;
        }

        rc = curl_easy_setopt(ev->curl, CURLOPT_MAX_RECV_SPEED_LARGE, e->bandwidth.local_limit);
        if (curl_check(ev,rc, "set CURLOPT_MAX_RECV_SPEED_LARGE") == -1) {
            EVDEBUG(ev, "Could not set CURL max recv seed");
            return 1;
        }
    }

    return 0;
}

static int xferinfo(void *p, curl_off_t dltotal, curl_off_t dlnow,
                    curl_off_t ultotal, curl_off_t ulnow)
{
    curlev_t *ev = p;
    int err = SXE_ABORT;
    sxc_client_t *sx;
    double dl_speed = 0;
    double ul_speed = 0;
    curl_events_t *e;

    if (!ev || check_ssl_cert(ev))
        return -1;

    if(!ev || !ev->ctx) /* Not an error, context could be disabled */
        return 0;

    e = sxi_conns_get_curlev(ev->ctx->conns);
    sx = sxi_conns_get_client(ev->ctx->conns);

    /* If we want to abort transfers, other cURL transfers will be killed now */
    if(sxc_geterrnum(sx) == SXE_ABORT)
        return 1;

    if(ulnow + dlnow != ev->total_xfer) {
        /* Total number of bytes transferred has changed, update timing */
        gettimeofday(&ev->last_progress_time, NULL);
        ev->total_xfer = ulnow + dlnow;
    } else if(ev->ctx->soft_timeout) {
        struct timeval now;
        double diff;

        gettimeofday(&now, NULL);
        diff = sxi_timediff(&now, &ev->last_progress_time);

        /* Check if xfer is not stalled for too long */
        if(diff > ev->ctx->soft_timeout) {
            sxi_cbdata_seterr(ev->ctx, SXE_ETIME, "Failed to %s: Request timeout", ev->ctx->op ? ev->ctx->op : "query cluster");
            return 1;
        }
    }

    switch(ev->ctx->tag) {
        case CTX_DOWNLOAD: {
            if(!e || (e->bandwidth.global_limit && curl_easy_getinfo(ev->curl, CURLINFO_SPEED_DOWNLOAD, &dl_speed) != CURLE_OK)) {
                err = SXE_ECURL;
            } else {
                err = sxi_file_download_set_xfer_stat(ev->ctx->u.download_ctx, dlnow, dltotal);
                if(e->bandwidth.global_limit && dl_speed * e->running > e->bandwidth.global_limit * 1.2)
                    curlev_update_bandwidth_limit(ev);
            }
        } break;

        case CTX_UPLOAD_HOST: {
            if(!e || (e->bandwidth.global_limit && curl_easy_getinfo(ev->curl, CURLINFO_SPEED_UPLOAD, &ul_speed) != CURLE_OK)) {
                err = SXE_ECURL;
            } else {
                err = sxi_host_upload_set_xfer_stat(ev->ctx->u.host_ctx, ulnow, ultotal);
                if(e->bandwidth.global_limit && ul_speed * e->running > e->bandwidth.global_limit * 1.2)
                    curlev_update_bandwidth_limit(ev);
            }
        } break;

        case CTX_GENERIC: {
            if(!e || (e->bandwidth.global_limit && (curl_easy_getinfo(ev->curl, CURLINFO_SPEED_DOWNLOAD, &dl_speed) != CURLE_OK ||
               curl_easy_getinfo(ev->curl, CURLINFO_SPEED_UPLOAD, &ul_speed) != CURLE_OK))) {
                err = SXE_ECURL;
            } else {
                err = sxi_generic_set_xfer_stat(ev->ctx->u.generic_ctx, dlnow, dltotal, ulnow, ultotal);
                if(e->bandwidth.global_limit && (dl_speed * e->running > e->bandwidth.global_limit * 1.2 ||
                   ul_speed * e->running > e->bandwidth.global_limit * 1.2))
                    curlev_update_bandwidth_limit(ev);
            }
        } break;

        case CTX_HASHOP:
        case CTX_JOB:
        case CTX_UPLOAD: {
            /* Do nothing simply assign error value as no error */
            err = SXE_NOERROR;
        }
    }

    if(err != SXE_NOERROR) {
        /* Set error message */
        if(err == SXE_ABORT)
            sxi_cbdata_seterr(ev->ctx, err, "Transfer aborted");
        else
            sxi_cbdata_seterr(ev->ctx, err, "Could not update progress information");

        /* This stops transfer and causes libcurl to fail */
        return 1;
    }
    return 0;
}

static int easy_set_default_opt(curl_events_t *e, curlev_t *ev)
{
    CURLcode rc;
    CURL *curl = ev->curl;
    memset(ev->ctx->recv_ctx.errbuf, 0, sizeof(ev->ctx->recv_ctx.errbuf));
    rc = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, ev->ctx->recv_ctx.errbuf);
    if (curl_check(ev,rc, "set CURLOPT_ERRORBUFFER") == -1)
        return -1;

    rc = curl_easy_setopt(curl, CURLOPT_VERBOSE, e->verbose);
    if (curl_check(ev,rc,"set CURLOPT_VERBOSE") == -1)
        return -1;

    rc = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    if (curl_check(ev,rc, "set CURLOPT_NOSIGNAL") == -1)
        return -1;

    /* network */
#if LIBCURL_VERSION_NUM >= 0x071304
    long protos = CURLPROTO_HTTP | CURLPROTO_HTTPS;
    rc = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, protos);
    if (curl_check(ev,rc,"set CURLOPT_PROTOCOLS") == -1)
        return -1;
    rc = curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, protos);
    if (curl_check(ev,rc,"set CURLOPT_PROTOCOLS") == -1)
        return -1;
#endif

#if LIBCURL_VERSION_NUM < 0x071506
    rc = curl_easy_setopt(curl, CURLOPT_ENCODING,"");
#else
    rc = curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING,"");
#endif
    if (curl_check(ev,rc,"set CURLOPT_(ACCEPT)_ENCODING") == -1)
        return -1;

    rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0);
    if (curl_check(ev,rc,"disable global timeout") == -1)
        return -1;

    /* otherwise it tries SSLv2 on < 7.18.1 and fails to connect to
     * SSLv3/TLSv1 */
    rc = curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
    if (curl_check(ev,rc,"set SSL version") == -1)
        return -1;
    /* cafile = NULL => accept any root CA, still do hostname verification
     *        = ""   => verify with default root CAs
     *        = "<path>" => verify with just that root CA */
    rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (curl_check(ev,rc,"set SSL_VERIFYPEER") == -1)
        return -1;
    /* we'll verify hostname ourselves */
    rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    if (curl_check(ev,rc,"set SSL_VERIFYHOST") == -1)
        return -1;

    /* used for SSL hostname validation with NSS (since we turned off VERIFY_HOST),
        * and (in the future) for transfer timeouts */
    curl_easy_setopt(ev->curl, CURLOPT_XFERINFOFUNCTION, xferinfo);
    curl_easy_setopt(ev->curl, CURLOPT_XFERINFODATA, ev);
    curl_easy_setopt(ev->curl, CURLOPT_NOPROGRESS, 0L);

    if (e->cafile && *e->cafile) {
        rc = curl_easy_setopt(curl, CURLOPT_CAINFO, e->cafile);
        if (curl_check(ev, rc, "set CURLOPT_CAINFO") == -1)
            return -1;
        rc = curl_easy_setopt(curl, CURLOPT_CAPATH, NULL);
        if (curl_check(ev, rc, "set CURLOPT_CAPATH") == -1)
            return -1;
    }

    if (e->disable_proxy) {
        rc = curl_easy_setopt(curl, CURLOPT_PROXY, "");
        if (curl_check(ev, rc, "set CURLOPT_PROXY") == -1)
            return -1;
    }

#if LIBCURL_VERSION_NUM >= 0x071000
    rc = curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockoptfn);
    if (curl_check(ev,rc,"set sockoptfn") == -1)
        return -1;
#endif
    ev->verify_peer = 1;
    return 0;
}

typedef size_t (*write_cb_t)(char *ptr, size_t size, size_t nmemb, void *ctx);

static void resolve(curlev_t *ev, const char *host, uint16_t port)
{
#if LIBCURL_VERSION_NUM >= 0x071503
    if (!ev || !host)
        return;
    struct curl_slist *slist;
    unsigned len = strlen(host) * 2 + sizeof(":65535:");
    char *res = malloc(len);
    if (!res)
        return;
    /* avoid getaddrinfo */
    snprintf(res, len, "%s:%u:%s", host, port, host);
    slist = curl_slist_append(NULL, res);
    free(res);
    if (!slist)
        return;

    ev->resolve = slist;
    curl_easy_setopt(ev->curl, CURLOPT_RESOLVE, ev->resolve);
#endif
}

static int compute_headers_url(curl_events_t *e, curlev_t *ev, curlev_t *src);

static int curlev_apply(curl_events_t *e, curlev_t *ev, curlev_t *src)
{
    CURLcode rc;
    CURL *handle;
    int ret = -1;
    /* Apply curl easy handle settings.
     * The purpose is to preserve any opened connections in the destination
     * handle and avoid TIME_WAIT issues.
     */
    handle = ev->curl;
    if (ev->slist)
        curl_slist_free_all(ev->slist);
    if (ev->resolve)
        curl_slist_free_all(ev->resolve);
    free(ev->host);
    memcpy(ev, src, sizeof(*src));
    ev->url = NULL;
    if (!handle) {
        handle = curl_easy_init();
        if (!handle) {
            ctx_err(ev->ctx, CURLE_OUT_OF_MEMORY, "curl_easy_init failed");
            return -1;
        }
        rc = curl_easy_setopt(handle, CURLOPT_SHARE, e->share);
        if (curl_check(ev,rc,"set share") == -1) {
            curl_easy_cleanup(handle);
            return -1;
        }
    }

    ev->curl = handle;
    do {
	unsigned int contimeout;
        resolve(ev, src->host, src->port);
        if (compute_headers_url(e, ev, src) == -1) {
            EVDEBUG(ev, "compute_headers_url failed");
            break;
        }
        rc = curl_easy_setopt(ev->curl, CURLOPT_URL, src->url);
        if (curl_check(ev,rc, "set CURLOPT_URL") == -1)
            break;
        if (easy_set_default_opt(e, ev) == -1)
            break;

	contimeout = sxi_conns_get_timeout(e->conns, src->host);
#if LIBCURL_VERSION_NUM >= 0x071002
	rc = curl_easy_setopt(ev->curl, CURLOPT_CONNECTTIMEOUT_MS, contimeout);
	if (curl_check(ev, rc, "set CURLOPT_CONNECTTIMEOUT_MS") == -1)
	    break;
#else
	rc = curl_easy_setopt(ev->curl, CURLOPT_CONNECTTIMEOUT, (contimeout+999) / 1000);
	if (curl_check(ev, rc, "set CURLOPT_CONNECTTIMEOUT") == -1)
	    break;
#endif

        rc = curl_easy_setopt(ev->curl, CURLOPT_PRIVATE, ev);
        if (curl_check(ev,rc,"set PRIVATE") == -1)
            break;
        /* reset previously set verbs */
        rc = curl_easy_setopt(ev->curl, CURLOPT_CUSTOMREQUEST, NULL);
        if (rc == CURLE_OK)
            rc = curl_easy_setopt(ev->curl, CURLOPT_NOBODY, 0);
        if (rc == CURLE_OK)
            rc = curl_easy_setopt(ev->curl, CURLOPT_HTTPGET, 1);
        if (rc == CURLE_OK) {
            /* set verb */
            switch (ev->verb) {
            case REQ_GET:
                /* nothing needs to be set */
                break;
            case REQ_HEAD:
                rc = curl_easy_setopt(ev->curl, CURLOPT_NOBODY, 1);
                break;
            case REQ_PUT:
                rc = curl_easy_setopt(ev->curl, CURLOPT_POST, 1);
                if (rc == CURLE_OK)
                    rc = curl_easy_setopt(ev->curl, CURLOPT_CUSTOMREQUEST, "PUT");
                if (rc == CURLE_OK)
                    rc = curl_easy_setopt(ev->curl, CURLOPT_POSTFIELDSIZE, ev->body.size);
                if (rc == CURLE_OK)
                    rc = curl_easy_setopt(ev->curl, CURLOPT_POSTFIELDS, ev->body.data);
                break;
            case REQ_DELETE:
                rc = curl_easy_setopt(ev->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
                break;
            }
        }
        if (curl_check(ev,rc,"set verb") == -1)
            break;
        rc = curl_easy_setopt(ev->curl, CURLOPT_WRITEFUNCTION, writefn);
        if (curl_check(ev,rc, "set CURLOPT_WRITEFUNCTION") == -1)
            break;
        rc = curl_easy_setopt(ev->curl, CURLOPT_WRITEDATA, ev->ctx);
        if (curl_check(ev,rc, "set CURLOPT_WRITEDATA") == -1)
            break;
        rc = curl_easy_setopt(ev->curl, CURLOPT_HEADERFUNCTION, (write_cb_t)headfn);
        if (curl_check(ev,rc, "set CURLOPT_HEADERFUNCTION") == -1)
            break;
        rc = curl_easy_setopt(ev->curl, CURLOPT_HEADERDATA, ev);
        if (curl_check(ev,rc, "set CURLOPT_HEADERFUNCTION") == -1)
            break;
        rc = curl_easy_setopt(ev->curl, CURLOPT_HTTPHEADER, ev->slist);
        if (curl_check(ev, rc, "set headers"))
            break;
        ev->ssl_verified = ev->ssl_ctx_called = 0;

        if(e->bandwidth.global_limit) {
            rc = curl_easy_setopt(ev->curl, CURLOPT_MAX_SEND_SPEED_LARGE, e->bandwidth.local_limit);
            if (curl_check(ev,rc, "set CURLOPT_MAX_SEND_SPEED_LARGE") == -1) {
                EVDEBUG(ev, "Could not set CURL max send seed");
                break;
            }

            rc = curl_easy_setopt(ev->curl, CURLOPT_MAX_RECV_SPEED_LARGE, e->bandwidth.local_limit);
            if (curl_check(ev,rc, "set CURLOPT_MAX_RECV_SPEED_LARGE") == -1) {
                EVDEBUG(ev, "Could not set CURL max send seed");
                break;
            }
        }

        /* If set, apply hard limit for request */
        if(ev->ctx && ev->ctx->hard_timeout) {
            rc = curl_easy_setopt(ev->curl, CURLOPT_TIMEOUT, ev->ctx->hard_timeout);
            if (curl_check(ev, rc, "set request timeout"))
                break;
        }
        ret = 0;
    } while(0);
    free(src->url);
    memset(src, 0, sizeof(*src));
    free(src);
    return ret;
}

static int compute_date(curlev_context_t *cbdata, char buf[32], time_t diff, sxi_hmac_sha1_ctx *hmac_ctx) {
    const char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const char *wkday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    time_t t = time(NULL) + diff;
    struct tm ts;

    if(!gmtime_r(&t, &ts)) {
	CBDATADEBUG("failed to get time");
	sxi_cbdata_seterr(cbdata, SXE_EARG, "Cannot get current time: Invalid argument");
	return -1;
    }
    sprintf(buf, "%s, %02u %s %04u %02u:%02u:%02u GMT", wkday[ts.tm_wday], ts.tm_mday, month[ts.tm_mon], ts.tm_year + 1900, ts.tm_hour, ts.tm_min, ts.tm_sec);

    if(!sxi_hmac_sha1_update_str(hmac_ctx, buf))
	return -1;
    return 0;
}

static const char *verbstr(int verb)
{
    switch (verb) {
        case REQ_GET:
            return "GET";
        case REQ_HEAD:
            return "HEAD";
        case REQ_PUT:
            return "PUT";
        case REQ_DELETE:
            return "DELETE";
        default:
            return "??";
    }
}

#define conns_err(...) do { if(conns) sxi_seterr(sx, __VA_ARGS__); } while(0)
static int compute_headers_url(curl_events_t *e, curlev_t *ev, curlev_t *src)
{
    char auth[lenof("SKY ") + AUTHTOK_ASCII_LEN + 1], *sendtok = NULL;
    unsigned char bintoken[AUTHTOK_BIN_LEN];
    const unsigned char *content;
    char datebuf[32];
    unsigned content_size;
    unsigned int keylen;
    sxi_hmac_sha1_ctx *hmac_ctx = NULL;
    sxi_conns_t *conns;
    sxc_client_t *sx;
    int rc;
    const char *content_type_field = ev->verb == REQ_PUT ? "Content-Type" : NULL;
    const char *content_type_value = content_type_field ? "application/octet-stream" : NULL;

    header_t headers[] = {
        {"User-Agent", sxi_get_useragent()},
        {"Expect", NULL},
        {"Date", datebuf },
        {"Authorization", auth },
        {"SX-Cluster-Name", sxi_conns_get_sslname(e->conns) ? sxi_conns_get_sslname(e->conns) : sxi_conns_get_dnsname(e->conns)},
        {"If-None-Match", ev->ctx->recv_ctx.etag},
        { content_type_field, content_type_value }
    };

    memset(bintoken, 0, sizeof(bintoken));
    conns = e->conns;
    sx = sxi_conns_get_client(conns);
    /* we sign request as late as possible to avoid
     * clock drift errors from the server */
    do {
        const char *verb = verbstr(src->verb);
        const char *token = sxi_conns_get_auth(e->conns);
        const char *query;
        char *url;
	rc = -1;
        hmac_ctx = sxi_hmac_sha1_init();
        if (!hmac_ctx)
            break;

        content_size = src->body.size;
        content = src->body.data;

        keylen = AUTHTOK_BIN_LEN;
        if (!token) {
            rc = 0;
            break;
        }
        rc = curl_easy_setopt(ev->curl, CURLOPT_URL, src->url);
        if (curl_check(ev, rc, "set URL"))
            break;
        rc = curl_easy_getinfo(ev->curl, CURLINFO_EFFECTIVE_URL, &url);
        if (curl_check(ev, rc, "get URL"))
            break;

        rc = -1;
        if (!strncmp(url, "http://", 7)) {
            query = url + 7;
            ev->is_http = 1;
        } else if(!strncmp(url, "https://", 8)) {
            query = url + 8;
        } else {
            sxi_cbdata_seterr(ev->ctx, SXE_EARG, "Invalid URL: %s", url);
            break;
        }
        query = strchr(query, '/');
        if (!query) {
            sxi_cbdata_seterr(ev->ctx, SXE_EARG, "Cluster query failed: Bad URL");
            break;
        }
        query++;
        if(sxi_b64_dec(sx, token, bintoken, &keylen) || keylen != AUTHTOK_BIN_LEN) {
            EVDEBUG(ev, "failed to decode the auth token");
            sxi_cbdata_restore_global_error(sx, ev->ctx);
            break;
        }

        if(!sxi_hmac_sha1_init_ex(hmac_ctx, bintoken + AUTH_UID_LEN, AUTH_KEY_LEN)) {
	    EVDEBUG(ev, "failed to init hmac context");
	    sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cluster query failed: HMAC calculation failed");
	    break;
	}

	if(!sxi_hmac_sha1_update_str(hmac_ctx, verb) || !sxi_hmac_sha1_update_str(hmac_ctx, query)) {
            sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cluster query failed: HMAC calculation failed");
	    break;
        }

	if (compute_date(ev->ctx, datebuf, sxi_conns_get_timediff(e->conns), hmac_ctx) == -1) {
            sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cluster query failed: Failed to compute date");
	    break;
        }

	if(content_size) {
	    char content_hash[41];
	    unsigned char d[20];
            sxi_md_ctx *ch_ctx = sxi_md_init();

            if (!sxi_sha1_init(ch_ctx)) {
		EVDEBUG(ev, "failed to init content digest");
                sxi_md_cleanup(&ch_ctx);
		sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cannot compute hash: Unable to initialize crypto library");
		break;
	    }
            if (!sxi_sha1_update(ch_ctx, content, content_size) || !sxi_sha1_final(ch_ctx, d, NULL)) {
		EVDEBUG(ev, "failed to update content digest");
		sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cannot compute hash: Crypto library failure");
                sxi_md_cleanup(&ch_ctx);
		break;
	    }
            sxi_md_cleanup(&ch_ctx);

	    sxi_bin2hex(d, sizeof(d), content_hash);
	    content_hash[sizeof(content_hash)-1] = '\0';

	    if(!sxi_hmac_sha1_update_str(hmac_ctx, content_hash)) {
                sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cluster query failed: HMAC calculation failed");
		break;
            }
	} else if(!sxi_hmac_sha1_update_str(hmac_ctx, "da39a3ee5e6b4b0d3255bfef95601890afd80709")) {
            sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cluster query failed: HMAC calculation failed");
	    break;
        }

	keylen = AUTH_KEY_LEN;
	if(!sxi_hmac_sha1_final(hmac_ctx, bintoken + AUTH_UID_LEN, &keylen) || keylen != AUTH_KEY_LEN) {
	    EVDEBUG(ev, "failed to finalize hmac calculation");
	    sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "Cluster query failed: HMAC finalization failed");
	    break;
	}
        if(!(sendtok = sxi_b64_enc(sx, bintoken, AUTHTOK_BIN_LEN))) {
            EVDEBUG(ev, "failed to encode computed auth token");
            sxi_cbdata_seterr(ev->ctx, SXE_ECRYPT, "failed to encode computed auth token");
            break;
        }

        snprintf(auth, sizeof(auth), "SKY %s", sendtok);

        rc = set_headers(e, ev, headers, sizeof(headers)/sizeof(headers[0]));
        if (curl_check(ev,rc,"set headers") == -1)
            break;

	rc = 0;
    } while(0);
    free(sendtok);
    sxi_hmac_sha1_cleanup(&hmac_ctx);
    return rc;
}

static int enqueue_request(curl_events_t *e, curlev_t *ev, int re)
{
    struct host_info *host = NULL;
    sxc_client_t *sx = NULL;

    if(!e || !ev) {
        return -1;
    }

    sx = e->conn_pool->sx;

    /* Store hosts list to be able to get information from single event */
    ev->hosts = e->conn_pool->hosts;

    /* Get information about active connections for each host */
    if(sxi_ht_get(e->conn_pool->hosts, (void*)ev->host, strlen(ev->host), (void**)&host) || !host) {
        /* Host could not be found, add given host */
        host = host_info_new(ev->host);
        if(!host) {
            SXDEBUG("OOM Could not allocate memory for host");
            return -1;
        }
        if(sxi_ht_add(e->conn_pool->hosts, (void*)ev->host, strlen(ev->host), (void*)host)) {
            SXDEBUG("Could not add host to hashtable");
            host_info_free(host);
            return -1;
        }
    }

    if (e->conn_pool->active_count < e->conn_pool->max_active_total && host->active < e->conn_pool->max_active_per_host) {
        unsigned i;
        /* reuse previous easy handle to reuse the connection and prevent
         * TIME_WAIT issues */

        /* find free slot */
        for (i=0;i<e->conn_pool->max_active_total;i++) {
            curlev_t *o; 
            o = &e->conn_pool->active[i];
            if (!o->ctx) {
                /* free slot */
                if (curlev_apply(e, o, ev) == -1) {
                    EVDEBUG(o,"curlev_apply failed");
                    return -1;
                }

                ev = o;

                /* Update per-host active connections counters */
                host->active++;
                /* Reset last successful xfer update */
                gettimeofday(&ev->last_progress_time, NULL);
                break;
            }
        }
        if (i == e->conn_pool->max_active_total) {
            EVDEBUG(ev,"no free hosts?");
            return -1;
        }

        if(e->bandwidth.global_limit) {
            /* Enqueuing new request needs to update bandwidth */
            if(sxi_curlev_set_bandwidth_limit(e, e->bandwidth.global_limit, e->running+1)) {
                EVDEBUG(ev, "sxi_curlev_set_bandwidth_limit failed");
                return -1;
            }
        }

        /* less than 2 active requests: launch requests now */
        CURLMcode rcm = curl_multi_add_handle(e->multi, ev->curl);
        if (curlm_check(ev,rcm,"add_handle") == -1) {
            EVDEBUG(ev,"add_handle failed: %s", sxi_cbdata_geterrmsg(ev->ctx));
            return -1;
        }
        e->conn_pool->active_count++;
        EVDEBUG(ev, "::add_handle %p, active now: %d", ev->curl, e->conn_pool->active_count);

        if (re)
            EVDEBUG(ev, "Started next waiting request for host %s (%d active)", ev->host, e->conn_pool->active_count);
        else
            EVDEBUG(ev, "Started new request to host %s (%d active)", ev->host, e->conn_pool->active_count);
    } else {
        /* has pending request for this host, chain request to avoid
         * pipelining timeout.
         * Note: this list is actually reversed, but we only request
         * hashes so it doesn't matter. */
        if(ev_queue_add(e->conn_pool->queue, ev)) {
           EVDEBUG(ev, "Could not add event to a queue");
           return -1;
        }
        EVDEBUG(ev, "queued now: %d", ev_queue_length(e->conn_pool->queue));
        EVDEBUG(ev, "Enqueued request to existing host %s", ev->host);
    }

    return 0;
}

/* Return 1 if event was dequeued, else 0 */
static int queue_next_inactive(curl_events_t *e)
{
    curlev_t *ev = NULL;

    if(!e) {
        return -1;
    }

    /*
     * If total connections limit is not higher than current active connections number,
     * then do not dequeue event. Ohterwise it would be put here again.
     */
    if(e->conn_pool->active_count >= e->conn_pool->max_active_total) {
        return 0;
    }

    ev = ev_queue_get(e->conn_pool->queue);
    if (!ev) {
        EVDEBUG(ev,"finished %s", ev->host);
        EVDEBUG(ev, "finished queued requests for host %s", ev->host);
        /* TODO: remove the host after a timeout of a few mins */
        return 0;
    }
    
    if (enqueue_request(e, ev, 1) == -1) {
        EVENTSDEBUG(e, "enqueue_request failed");
        return 0;
    }

    return 1;
}

static int ev_add(curl_events_t *e,
                  const request_headers_t *headers,
                  const request_data_t *body, enum sxi_cluster_verb verb,
                  const reply_t *reply)
{
    curlev_t *ev = NULL;
    curlev_context_t *ctx = reply ? reply->headers.ctx : NULL;

    if (!e || !headers || !reply || !ctx || !reply->headers.error) {
        ctx_err(ctx, CURLE_ABORTED_BY_CALLBACK, "ev_add: NULL argument");
        /* body is allowed to be NULL */
        return SXE_EARG;
    }

    sxi_cbdata_ref(reply->headers.ctx);
    memset(ctx->recv_ctx.errbuf, 0, sizeof(ctx->recv_ctx.errbuf));

    do {
        while (e->used >= MAX_EVENTS) {
            /* we got too many handles in use already,
             * wait for some to finish to reduce memory usage */
            if (sxi_curlev_poll(e) < 0) {
                ctx_err(ctx, CURLE_ABORTED_BY_CALLBACK, "curlev polling failed");
                break;
            }
        }
        if (e->used >= MAX_EVENTS) {
            sxi_cbdata_seterr(ctx, SXE_EARG, "Events queue is overloaded");
            break;
        }
        ev = calloc(1, sizeof(*ev));
        if (!ev) {
            ctx_err(ctx, CURLE_OUT_OF_MEMORY, "failed to allocate event");
            break;
        }
        ev->error = reply->headers.error;
        ev->ctx = reply->headers.ctx;
        ev->head = reply->headers.head;
        if (ev->ctx)
            ev->ctx->data_cb = reply->body;
        /* URL */
        if (!headers->url) {
            ctx_err(ctx, CURLE_URL_MALFORMAT, "URL is NULL");
            break;
        }
        ev->reply = *reply;
        if (body)
            ev->body = *body;

        /* reply callbacks */
        if (!reply->headers.head) {
            ctx_err(ctx, CURLE_BAD_FUNCTION_ARGUMENT, "head callback not set\n");
            break;
        }
        ev->host = strdup(headers->host);
        if (!ev->host) {
            ctx_err(ctx, CURLE_OUT_OF_MEMORY, "cannot dup hostname");
            break;
        }
	ev->port = headers->port;
        ev->url = strdup(headers->url);
        if (!ev->url) {
            ctx_err(ctx, CURLE_OUT_OF_MEMORY, "cannot dup URL");
            break;
        }
        ev->verb = verb;
        if (enqueue_request(e, ev, 0) == -1) {
            /* TODO: remove all reuse[] handles if this fails */
            EVENTSDEBUG(e, "enqueue_request failed");
            sxi_cbdata_seterr(ctx, SXE_EARG, "Failed to queue request");
            ev = NULL;
            break;
        }
        e->used++;
        if (!e->depth)
            sxi_curlev_poll_immediate(e);
        else
            e->added_notpolled = 1;
        return 0;
    } while(0);
    EVENTSDEBUG(e, "ev_add failed");
    sxi_cbdata_finish(e, &ctx, headers->url, reply->headers.error);
    if (ev) {
        if (ev->slist) {
            curl_slist_free_all(ev->slist);
            ev->slist = NULL;
        }
        free(ev->host);
        memset(ev, 0, sizeof(*ev));
        free(ev);
    }
    return -1;
}

int sxi_curlev_add_get(curl_events_t *e, const request_headers_t *headers, const reply_t *reply)
{
    return ev_add(e, headers, NULL, REQ_GET, reply);
}

static int nobody(curlev_context_t *ctx, const unsigned char *data, size_t size)
{
    sxi_cbdata_seterr(ctx, SXE_EARG, "Body received on HEAD?\n");
    return 0;
}

int sxi_curlev_add_head(curl_events_t *e, const request_headers_t *headers,
                        const reply_headers_t *reply_headers)
{
    if (!reply_headers) {
        EVENTSDEBUG(e, "curlev_add_head: NULL argument\n");
        return -1;
    }
    reply_t reply = { *reply_headers, nobody };
    return ev_add(e, headers, NULL, REQ_HEAD, &reply);
}

int sxi_curlev_add_delete(curl_events_t *e, const request_headers_t *headers,
                          const reply_t *reply)
{
    return ev_add(e, headers, NULL, REQ_DELETE, reply);
}

int sxi_curlev_add_put(curl_events_t *e,
                       const request_headers_t *req_headers,
                       const request_data_t *req_data,
                       const reply_t *reply)
{
    return ev_add(e, req_headers, req_data, REQ_PUT, reply);
}

#define MAX_POLL_SEEP_TIME      100 /* 100ms */
int sxi_curlev_poll(curl_events_t *e)
{
    CURLMcode rc;
    int callbacks = 0;
    long timeout = -1;
    int immediately_returned = 0;
    double usleep_timeout = 0; 
    sxc_client_t *sx;
    if (!e) {
        EVENTSDEBUG(e, "NULL argument");
        return -1;
    }

    do {
        int numfds = 0;

        callbacks = 0;
        if (e->added_notpolled) {
            /* If we added new queries that haven't been launched yet,
             * poll now to avoid needlessly sleeping until timeout in multi_wait().
             * But do not poll without a timeout if the queries have already been launched.
             * */
            if ((callbacks += sxi_curlev_poll_immediate(e)) == -1)
                return -1;
        } 
        rc = curl_multi_timeout(e->multi, &timeout);

        if (curlm_check(NULL,rc,"set timeout") == -1)
            return -1;

        if (timeout < 0)
            timeout = 2000;
        rc = curl_multi_wait(e->multi, NULL, 0, timeout, &numfds);

        if (curlm_check(NULL,rc,"wait") == -1)
            return -1;

        if(e->bandwidth.global_limit) {
            if(!numfds && timeout > 0) {
                immediately_returned++; 

                /* 
                 * Check if curl_multi_wait() returns too quickly more than 2 times in a row.
                 * If true, usleep() and increase timeout.
                 */
                if(immediately_returned > 2) {
                    usleep_timeout += 10; /* Add 10 ms */
                    if(usleep_timeout > MAX_POLL_SEEP_TIME) 
                        usleep_timeout = MAX_POLL_SEEP_TIME;

                    usleep(usleep_timeout * 1000);
                }
            } else {
                /* curl_multi_wait() did not return immediately, reset timeout */
                usleep_timeout = 0;
                immediately_returned = 0;
            }
        }

        if ((callbacks += sxi_curlev_poll_immediate(e)) == -1)
            return -1;
    } while (e->running && !callbacks && !e->depth);
    sx = sxi_conns_get_client(e->conns);
    SXDEBUG("running: %d, callbacks executed: %d", e->running, callbacks);
    if (!e->running && !callbacks) {
        EVENTSDEBUG(e,"Deadlock avoided: no more running handles");
        if (sxc_geterrnum(sx) == SXE_NOERROR) /* do not overwrite previous error */
            sxi_seterr(sx, SXE_ECOMM, "sxi_curlev_poll called but nothing to poll");
        return -2;
    }
    return 0;
}

int sxi_curlev_poll_immediate(curl_events_t *e)
{
    CURLMcode rc;
    CURLMsg *msg;
    int msgs;
    int callbacks = 0;
    int last_running = e->running;
    do {
        rc = curl_multi_perform(e->multi, &e->running);
    } while (rc == CURLM_CALL_MULTI_PERFORM);

    /* If number of running transfers has changed, recalculate bandwidth */
    if(e->bandwidth.global_limit && last_running != e->running) {
        if(sxi_curlev_set_bandwidth_limit(e, e->bandwidth.global_limit, e->running)) {
            EVENTSDEBUG(e, "Could not set bandwidth limit");
            return -1;
        }
    }
    
    if (curlm_check(NULL,rc,"perform") == -1)
        return -1;
    e->added_notpolled = 0;
    e->depth++;
    while ((msg = curl_multi_info_read(e->multi, &msgs))) {
            char *priv = NULL;
            callbacks++;
            if (msg->msg != CURLMSG_DONE) {
                continue;
            }

            /* TODO: invoke callbacks */
            curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &priv);
            if (priv) {
                const char *url;
                char *urldup;
                curlev_t *ev = (curlev_t*)priv;
                struct recv_context *rctx = &ev->ctx->recv_ctx;
                int xfer_err = SXE_NOERROR;
                curlev_context_t *ctx;

                curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &rctx->reply_status);
                rctx->errbuf[sizeof(rctx->errbuf)-1] = 0;
                rctx->rc = msg->data.result;
		if(rctx->rc == CURLE_OK)
		    sxi_conns_set_timeout(e->conns, ev->host, 1);
		else
		    sxi_conns_set_timeout(e->conns, ev->host, -1);

                /* get url, it will get freed by curl_easy_cleanup */
                curl_easy_getinfo(msg->easy_handle, CURLINFO_EFFECTIVE_URL, &url);

                /* Update information about connection with given host */
                if(update_active_host(e->conn_pool, ev)) {
                    EVDEBUG(ev, "Failed to update host %s speed: %s", ev->host, sxi_cbdata_geterrmsg(ev->ctx));
                    e->depth--;
                    return -1;
                }

                /* finish might add more queries, let it know
                 * there is room */
                rc = curl_multi_remove_handle(e->multi, ev->curl);
                if (curlm_check(ev, rc,"remove_handle") == -1) {
                    e->depth--;
                    return -1;
                }
                EVDEBUG(ev, "::remove_handle %p", ev->curl);
                e->used--;
                ctx = ev->ctx;
                ev->ctx = NULL;

                /* 
                 * For some transfers xferinfo() function can be not called when all bytes were 
                 * transferred. But in this place we are sure that transfer has finished, so following
                 * updates transfer information to satisfy progress information 
                 */
                switch(ctx->tag) {
                    case CTX_DOWNLOAD: {
                        /* Update file download to be finished */
                        int64_t to_dl = sxi_file_download_get_xfer_to_send(ctx->u.download_ctx);
                        if(to_dl)
                            xfer_err = sxi_file_download_set_xfer_stat(ctx->u.download_ctx, to_dl, to_dl);
                    } break;

                    case CTX_UPLOAD_HOST: {
                        /* Update file upload */
                        int64_t to_ul = sxi_host_upload_get_xfer_to_send(ctx->u.host_ctx);
                        if(to_ul)
                            xfer_err = sxi_host_upload_set_xfer_stat(ctx->u.host_ctx, to_ul, to_ul);
                    } break;

                    case CTX_GENERIC: {
                        switch(ev->verb) {
                            case REQ_GET: {
                                int64_t to_dl = sxi_generic_get_xfer_to_dl(ctx->u.generic_ctx);
                                if(to_dl)
                                    xfer_err = sxi_generic_set_xfer_stat(ctx->u.generic_ctx, to_dl, to_dl, 0, 0);
                            } break;

                            case REQ_PUT: {
                                int64_t to_ul = sxi_generic_get_xfer_to_ul(ctx->u.generic_ctx);
                                if(to_ul)
                                    xfer_err = sxi_generic_set_xfer_stat(ctx->u.generic_ctx, 0, 0, to_ul, to_ul);
                            } break;

                            default:
                                break;
                        }
                    } break;

                    default: {
                        /* Generic transfer updates */
                    }
                }

                /* Check if user transfer callbacks did not return error message */
                if(xfer_err != SXE_NOERROR) {
                    if(xfer_err == SXE_ABORT)
                        sxi_cbdata_seterr(ctx, xfer_err, "Transfer aborted");
                    else
                        sxi_cbdata_seterr(ctx, xfer_err, "Could not update progress information");
                    e->depth--;
                    return -1;
                }

                /* Update global active connections counter */
                e->conn_pool->active_count--;

                urldup = strdup(url);
                queue_next_inactive(e);
                sxi_cbdata_finish(e, &ctx, urldup, ev->error);
                free(urldup);
            } else {
                EVENTSDEBUG(e,"WARNING: failed to find curl handle\n");
                e->depth--;
                return -1;
            }
    }
    e->depth--;
    return callbacks;
}

/* message to display to user, in order of increasing priority */
enum msg_prio {
    MSG_PRIO_NOERROR,
    MSG_PRIO_SERVER_EAGAIN,
    MSG_PRIO_CURL,
    MSG_PRIO_SERVER,
    MSG_PRIO_AUTH,
    MSG_PRIO_LOCAL_FATAL,
};

struct sxi_retry {
    void *ctx;
    int last_try;
    int last_printed;
    int errnum;
    char errmsg[65536];
    enum msg_prio prio;

    /* Error handling callbacks */
    geterrmsg_cb geterrmsg;
    geterrnum_cb geterrnum;
    seterr_cb seterr;
    setsyserr_cb setsyserr;
    clearerr_cb clrerr;
};

static void retry_init_err_callbacks(sxi_retry_t *retry, retry_ctx_type_t ctx_type) {
    switch(ctx_type) {
        case RCTX_SX: {
            retry->geterrmsg = (geterrmsg_cb)sxc_geterrmsg;
            retry->geterrnum = (geterrnum_cb)sxc_geterrnum;
            retry->seterr = (seterr_cb)sxi_seterr;
            retry->setsyserr = (seterr_cb)sxi_setsyserr;
            retry->clrerr = (clearerr_cb)sxc_clearerr;
        } break;

        case RCTX_CBDATA: {
            retry->geterrmsg = (geterrmsg_cb)sxi_cbdata_geterrmsg;
            retry->geterrnum = (geterrnum_cb)sxi_cbdata_geterrnum;
            retry->seterr = (seterr_cb)sxi_cbdata_seterr;
            retry->setsyserr = (seterr_cb)sxi_cbdata_setsyserr;
            retry->clrerr = (clearerr_cb)sxi_cbdata_clearerr;
        } break;
    }
}

sxi_retry_t* sxi_retry_init(void *ctx, retry_ctx_type_t ctx_type) {
    sxi_retry_t *ret;
    if (!ctx)
        return NULL;

    ret = calloc(1, sizeof(*ret));
    if (!ret)
        return NULL;

    retry_init_err_callbacks(ret, ctx_type);
    ret->ctx = ctx;
    ret->last_printed = -1;
    return ret;
}

static enum msg_prio classify_error(int errnum)
{
    switch (errnum) {
        case SXE_NOERROR:
            return MSG_PRIO_NOERROR;
        case SXE_ECURL:
            return MSG_PRIO_CURL;
        case SXE_ECOMM:
            return MSG_PRIO_SERVER;
        case SXE_EAGAIN:
            return MSG_PRIO_SERVER_EAGAIN;
        case SXE_EAUTH:
            return MSG_PRIO_AUTH;
        default:
            return MSG_PRIO_LOCAL_FATAL;
    }
}

int sxi_retry_check(sxi_retry_t *retry, unsigned current_try)
{
    const char *errmsg;
    int errnum;
    enum msg_prio prio;

    if (!retry || !retry->ctx || !retry->geterrmsg || !retry->geterrnum)
        return -1;
    errmsg = retry->geterrmsg(retry->ctx);
    errnum = retry->geterrnum(retry->ctx);
    if (!errmsg)
        return -1;
    prio = classify_error(errnum);
    /* noerror can be overridden by anything, and in turn it can override
     * anything */
    if (prio > retry->prio || prio == MSG_PRIO_NOERROR) {
        /* this is a better error message than the previous retry's */
        retry->prio = prio;
        retry->errnum = errnum;
        /* do not malloc/strdup so that we can store OOM messages too */
        sxi_strlcpy(retry->errmsg, errmsg, sizeof(retry->errmsg));
    }
    if (prio == MSG_PRIO_LOCAL_FATAL || prio == MSG_PRIO_AUTH) {
        return -1;/* do not retry */
    }
    if ((int)current_try != retry->last_try) {
        retry->clrerr(retry->ctx);
        retry->last_try = current_try;
    }
    return 0;
}

void sxi_retry_msg(sxc_client_t *sx, sxi_retry_t *retry, const char *host)
{
    const char *op;
    if (!sx || !retry || !retry->ctx)
        return;
    op = sxi_get_operation(sx);
    SXDEBUG("op: %s", op ? op : "N/A");
    if (op && retry->errnum && retry->last_try != retry->last_printed) {
        sxi_info(sx, "%s, retrying %s%s%s ...", retry->errmsg, op,
                 host ? " on " : "",
                 host ? host : "");
        retry->last_printed = retry->last_try;
    }
}

int sxi_retry_done(sxi_retry_t **retryptr)
{
    sxi_retry_t *retry = retryptr ? *retryptr : NULL;
    int ret;
    if (!retry)
        return -1;
    sxi_retry_check(retry, retry->last_try+1);
    if (retry->errnum != SXE_NOERROR)
        retry->seterr(retry->ctx, retry->errnum, "%s", retry->errmsg);
    ret = retry->geterrnum(retry->ctx) != SXE_NOERROR;
    free(retry);
    *retryptr = NULL;
    return ret;
}

static const struct curl_certinfo *get_certinfo(curlev_t *ctx)
{
    const struct curl_slist *to_info = NULL;
    int res = curl_easy_getinfo(ctx->curl, CURLINFO_CERTINFO, &to_info);
    if (!res) {
        const struct curl_certinfo *to_certinfo;
        memcpy(&to_certinfo, &to_info, sizeof(to_info));
        if (to_certinfo->num_of_certs > 0)
            return to_certinfo;
    }
    return NULL;
}

static const char *get_certinfo_field(const struct curl_certinfo *cert, int i, const char *key)
{
    const struct curl_slist *slist;
    unsigned keylen = strlen(key);
    if (i < 0 || i >= cert->num_of_certs)
        return NULL;
    for (slist = cert->certinfo[i]; slist; slist = slist->next) {
        const char *data = slist->data;
        if (data && !strncmp(data, key, keylen) && data[keylen] == ':')
            return data + keylen + 1;
    }
    return NULL;
}

static int print_certificate_info(sxc_client_t *sx, const struct curl_certinfo *info)
{
    if (!info) {
	SXDEBUG("no certificate info present");
        return -1;
    }
    int ca = info->num_of_certs - 1;
    if (ca < 0) {
        sxi_seterr(sx, SXE_ECOMM, "Received 0 certificates");
        return -1;
    }

    struct sxi_fmt fmt;
    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "Server certificate:\n");
    sxi_fmt_msg(&fmt, "\tSubject: %s\n", get_certinfo_field(info, 0, "Subject"));
    sxi_fmt_msg(&fmt, "\tIssuer: %s\n", get_certinfo_field(info, 0, "Issuer"));
    if (ca > 0) {
        sxi_fmt_msg(&fmt, "Certificate Authority:\n");
        sxi_fmt_msg(&fmt, "\tSubject: %s\n", get_certinfo_field(info, ca, "Subject"));
        sxi_fmt_msg(&fmt, "\tIssuer: %s\n", get_certinfo_field(info, ca, "Issuer"));
    }
    const char *rootcert = get_certinfo_field(info, ca, "Cert");
    rootcert = strchr(rootcert, '\n');
    if (rootcert) {
        int ok = 0;
        rootcert++;
        unsigned i = 0;
        unsigned rawbuf_len = 3 * strlen(rootcert) / 4;
        unsigned char *rawbuf = calloc(1, rawbuf_len);
        if (!rawbuf) {
            sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate memory");
            return -1;
        }
        char *b64 = calloc(1, strlen(rootcert));
        if (!b64) {
            sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate memory");
            free(rawbuf);
            return -1;
        }
        for (;*rootcert;rootcert++) {
            unsigned char c = *rootcert;
            if (c == ' ' || c == '\n' || c == '\r')
                continue;
            if (c == '-')
                break;
            b64[i++] = c;
        }
        b64[i] = '\0';
        if (!sxi_b64_dec(sx, b64, rawbuf, &rawbuf_len)) {
            char hash[SXI_SHA1_TEXT_LEN + 1];
            if (!sxi_conns_hashcalc_core(sx, NULL, 0, rawbuf, rawbuf_len, hash)) {
                sxi_fmt_msg(&fmt, "\tSHA1 fingerprint: %s\n", hash);
                sxi_notice(sx, "%s", fmt.buf);
                ok = 1;
            }
        }
        free(b64);
        free(rawbuf);
        if (ok)
            return 0;
    }

    sxi_seterr(sx, SXE_ECOMM, "Invalid certificate: %s", rootcert);
    return -1;
}

static int save_ca(curl_events_t *e, const struct curl_certinfo *certinfo)
{
    sxc_client_t *sx = sxi_conns_get_client(e->conns);
    if (!certinfo)
        return -1;
    int ca = certinfo->num_of_certs - 1;
    const char *subj = get_certinfo_field(certinfo, ca, "Subject");
    const char *cert = get_certinfo_field(certinfo, ca, "Cert");
    FILE *out;
    int rc = 0;

    if (!cert) {
        sxi_seterr(sx, SXE_ECOMM, "Received 0 certificates");
        return -1;
    }
    out = fopen(e->savefile, "w");
    if (!out) {
        sxi_setsyserr(sx, SXE_EWRITE, "Cannot open '%s' for writing", e->savefile);
        return -1;
    }
    if (fputs(cert, out) < 0) {
        sxi_setsyserr(sx, SXE_EWRITE, "Cannot save '%s'", e->savefile);
        rc = -1;
    }
    if (fclose(out)) {
        sxi_setsyserr(sx, SXE_EWRITE, "Cannot save(close) '%s'", e->savefile);
        rc = -1;
    }
    if (!rc) {
        e->cert_saved = 1;
        if (subj)
            SXDEBUG("Saved root CA '%s' to '%s'", subj, e->savefile);
    }
    return rc;
}

int sxi_curlev_fetch_certificates(curl_events_t *e, const char *url, int quiet)
{
    int ok = 0;
    CURLcode rc;
    sxc_client_t *sx = sxi_conns_get_client(e->conns);
    curlev_t ev;
    curlev_context_t ctx;

    memset(&ev, 0, sizeof(ev));
    memset(&ctx, 0, sizeof(ctx));
    ev.curl = curl_easy_init();
    ev.ctx = &ctx;
    ctx.conns = e->conns;
    if (!ev.curl) {
        sxi_seterr(sx, SXE_EMEM, "curl_easy_init failed");
        return -1;
    }
    do {
        sxi_curlev_set_cafile(e, NULL);
        if (easy_set_default_opt(e, &ev))
            break;
        rc = curl_easy_setopt(ev.curl, CURLOPT_URL, url);
        if (curl_check(&ev,rc, "set CURLOPT_URL") == -1)
            break;
        long contimeout = sxi_conns_get_timeout(e->conns, url);
       rc = curl_easy_setopt(ev.curl, CURLOPT_CONNECTTIMEOUT_MS, contimeout);
       if (curl_check(&ev, rc, "set CURLOPT_CONNECTTIMEOUT_MS") == -1)
           break;
        rc = curl_easy_setopt(ev.curl, CURLOPT_CERTINFO, 1L);
        if (curl_check(&ev, rc, "set CURLOPT_CERTINFO") == -1)
            break;
        rc = curl_easy_setopt(ev.curl, CURLOPT_NOBODY, 1L);
        if (curl_check(&ev, rc, "set CURLOPT_NOBODY") == -1)
            break;
        /* this is a test connection, do not reuse */
        rc = curl_easy_setopt(ev.curl, CURLOPT_FORBID_REUSE, 1L);
        if (curl_check(&ev, rc, "set CURLOPT_FORBID_REUSE") == -1)
            break;
        rc = curl_easy_setopt(ev.curl, CURLOPT_HEADERFUNCTION, (write_cb_t)headfn);
        if (curl_check(&ev,rc, "set CURLOPT_HEADERFUNCTION") == -1)
            break;
        rc = curl_easy_setopt(ev.curl, CURLOPT_HEADERDATA, &ev);
        if (curl_check(&ev,rc, "set CURLOPT_HEADERFUNCTION") == -1)
            break;

        ev.quiet = quiet;
        ev.ssl_verified = 0;
        /* Do a first connection with peer verification turned on,
         * no questions asked if this succeeds.
         * This is needed to find root CA certs in the system cert store.
         * */
        ev.verify_peer = 2;
        rc = curl_easy_perform(ev.curl);
        SXDEBUG("1st perform result: %d", rc);
        if (rc == CURLE_OK) {
            if (ev.ssl_verified != 1) {
                sxi_seterr(sx, SXE_ECURL, "SSL certificate not verified");
                break;
            }
            if (save_ca(e, get_certinfo(&ev)))
                break;
        } else if (rc == CURLE_SSL_CACERT) {
            sxc_clearerr(sx);
            /* Do a second try with verification turned off, and ask a question.
             * this won't find root CA certs stored in system cert store */
            ev.verify_peer = 0;
            rc = curl_easy_setopt(ev.curl, CURLOPT_SSL_VERIFYPEER, 0L);
            if (curl_check(&ev,rc,"set SSL_VERIFYPEER") == -1)
                break;
            ev.ssl_verified = ev.ssl_ctx_called = 0;
            rc = curl_easy_perform(ev.curl);
            SXDEBUG("2nd perform result: %d", rc);
            if (rc == CURLE_OK || rc == CURLE_SSL_CACERT) {
                if (ev.ssl_verified < 0) {
                    sxi_seterr(sx, SXE_ECURL, "SSL certificate not verified");
                    break;
                }
                const struct curl_certinfo *info = get_certinfo(&ev);
                cert_ask_question(sx, &ev, info);
                if (ev.cert_status != CERT_ACCEPTED) {
                    sxi_seterr(sx, SXE_ECOMM, "User rejected the certificate");
                    break;
                }
                if (save_ca(e, info))
                    break;
            }
        } else {
            sxi_seterr(sx, SXE_ECOMM,"Cannot connect to %s: %s", url, curl_easy_strerror(rc));
        }
        /* try again, with newly saved CA and hostname verification on */
        e->cafile = e->savefile;
        if (easy_set_default_opt(e, &ev))
            break;
        rc = curl_easy_setopt(ev.curl, CURLOPT_SSL_VERIFYPEER, 1L);
        if (curl_check(&ev,rc,"set SSL_VERIFYPEER") == -1)
            break;
        ev.ssl_verified = ev.ssl_ctx_called = 0;
        rc = curl_easy_perform(ev.curl);
        if (rc) {
            sxi_seterr(sx, SXE_ECOMM,"Cannot connect to %s: %s", url, curl_easy_strerror(rc));
            break;
        }
        ok = 1;
    } while(0);
    e->cert_rejected = ev.cert_status == CERT_REJECTED;
    curl_easy_cleanup(ev.curl);
    e->cafile = NULL;
    return !ok;
}

/* Passed to cURL as a header write context */
struct sxauthd_hdr_ctx {
    curlev_t *ev;
    char *link; /* Will store configuration link generated by sxauthd */
    int is_sxauthd_host; /* Will be used to propagate error message */
};

static size_t sxauthd_headfn(void *ptr, size_t size, size_t nmemb, struct sxauthd_hdr_ctx *ctx)
{
    char *q;
    struct recv_context *rctx;
    curlev_context_t *cbdata;
    if (!ptr || !ctx || !ctx->ev || !ctx->ev->ctx)
        return 0;
    cbdata = ctx->ev->ctx;
    rctx = &cbdata->recv_ctx;
    curl_easy_getinfo(ctx->ev->curl, CURLINFO_RESPONSE_CODE, &rctx->reply_status);
    if (check_ssl_cert(ctx->ev))
        return 0;
    if (ctx->ev->ssl_verified < 0 && !ctx->ev->is_http) {
        sxi_cbdata_seterr(cbdata, SXE_ECURL, "SSL certificate not verified");
        return 0;
    }

    q = ptr;
    /* Header is parsed */
    rctx->header_seen = 1;
    /* We expect 302 response from the server */
    if(rctx->reply_status != 302) {
        if(size * nmemb > lenof("Content-Type: ") && !strncmp("Content-Type: ", q, lenof("Content-Type: ")) && strncmp("application/json", q + lenof("Content-Type: "), lenof("application/json"))) {
            sxi_cbdata_seterr(cbdata, SXE_ECOMM, "This is not an sxauthd host");
            ctx->is_sxauthd_host = 0;
        }
        /* Avoid overriding error message when node is not and sxauthd host */
        if(ctx->is_sxauthd_host) {
            if(rctx->reply_status == 401)
                sxi_cbdata_seterr(cbdata, SXE_ECOMM, "Invalid credentials");
            else
                sxi_cbdata_seterr(cbdata, SXE_ECOMM, "Failed to get configuration link from sxauthd server");
        }
        return size*nmemb;
    }

    if(!ctx->link && size * nmemb > lenof("Location: ") && !strncasecmp("Location: ", q, lenof("Location: "))) {
        unsigned int len;
        q += lenof("Location: ");
        ctx->link = strdup(q);
        if(!ctx->link)
            return 0;
        len = strlen(ctx->link);
        /* Trim carriage return and line feed chars */
        if(len >= 2 && ctx->link[len-2] == '\r' && ctx->link[len-1] == '\n')
            ctx->link[len-2] = '\0';
    }
    return size * nmemb;
}

struct cb_sxauthd_ctx {
    char message[1024];
    char node[64];
};

static void cb_sxauthd_errmsg(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_sxauthd_ctx *c = (struct cb_sxauthd_ctx *)ctx;
    sxi_strlcpy(c->message, string, MIN(sizeof(c->message), length + 1));
}

static void cb_sxauthd_errnode(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_sxauthd_ctx *c = (struct cb_sxauthd_ctx *)ctx;
    sxi_strlcpy(c->node, string, MIN(sizeof(c->node), length + 1));
}

static void sxauthd_errfn(curlev_context_t *ctx, int reply_code, const char *reason) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_sxauthd_errmsg, JPKEY("ErrorMessage")),
		      JPACT(cb_sxauthd_errnode, JPKEY("NodeId"))
		      )
    };
    struct cb_sxauthd_ctx yctx;
    jparse_t *J = sxi_jparse_create(&acts, &yctx, 0);

    yctx.message[0] = '\0';
    yctx.node[0] = '\0';

    if(!J) {
	sxi_cbdata_seterr(ctx, SXE_EMEM, "Cluster query failed: Out of memory");
	return;
    }

    if(sxi_jparse_digest(J, reason, strlen(reason)) || sxi_jparse_done(J))
	sxi_cbdata_seterr(ctx, SXE_ECOMM, sxi_jparse_geterr(J));
    else if(strcmp("SXAUTHD", yctx.node))
	sxi_cbdata_seterr(ctx, SXE_ECOMM, "This is not an sxauthd host");
    else if(yctx.message[0])
	sxi_cbdata_setclusterr(ctx, NULL, NULL, reply_code, yctx.message, NULL);
    else
	sxi_cbdata_seterr(ctx, SXE_ECOMM, "Cluster query failed: No reason provided");

    sxi_jparse_destroy(J);
}

char *sxi_curlev_fetch_sxauthd_credentials(curl_events_t *e, const char *url, const char *username, const char *password, const char *display, const char *unique, int quiet)
{
    char* ret = NULL;
    CURLcode rc;
    sxc_client_t *sx = sxi_conns_get_client(e->conns);
    curlev_t *ev;
    curlev_context_t *cbdata;
    char *display_enc = NULL, *unique_enc = NULL, *data = NULL;
    unsigned int data_len;
    /* This headers context will store configuration link (aka 'location') from sxauthd response */
    struct sxauthd_hdr_ctx header_ctx = { NULL, NULL, 1 };
    long contimeout;

    header_t headers[] = {
        {"User-Agent", sxi_get_useragent()},
        {"SX-Cluster-Name", sxi_conns_get_sslname(e->conns) ? sxi_conns_get_sslname(e->conns) : sxi_conns_get_dnsname(e->conns)},
    };

    ev = calloc(1, sizeof(*ev));
    if(!ev) {
        sxi_seterr(sx, SXE_EMEM, "curl_easy_init failed");
        return NULL;
    }
    header_ctx.ev = ev;
    memset(&cbdata, 0, sizeof(cbdata));
    ev->curl = curl_easy_init();
    /* cbdata will store and handle error messages */
    cbdata = sxi_cbdata_create(e->conns, NULL);
    if(!cbdata) {
        free(ev);
        return NULL;
    }
    ev->ctx = cbdata;
    if (!ev->curl) {
        sxi_seterr(sx, SXE_EMEM, "curl_easy_init failed");
        sxi_cbdata_unref(&cbdata);
        free(ev);
        return NULL;
    }

    if(set_headers(e, ev, headers, sizeof(headers) / sizeof(headers[0]))) {
        sxi_cbdata_unref(&cbdata);
        free(ev);
        return NULL;
    }

    /* Set common query options */
    if(easy_set_default_opt(e, ev))
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    rc = curl_easy_setopt(ev->curl, CURLOPT_VERBOSE, sxc_is_verbose(sx));
    if(curl_check(ev,rc, "set CURLOPT_VERBOSE") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    rc = curl_easy_setopt(ev->curl, CURLOPT_URL, url);
    if (curl_check(ev,rc, "set CURLOPT_URL") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    contimeout = sxi_conns_get_timeout(e->conns, url);
    rc = curl_easy_setopt(ev->curl, CURLOPT_CONNECTTIMEOUT_MS, contimeout);
    if (curl_check(ev, rc, "set CURLOPT_CONNECTTIMEOUT_MS") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;

    /* This call should be done once, do not reuse this handle */
    rc = curl_easy_setopt(ev->curl, CURLOPT_FORBID_REUSE, 1L);
    if (curl_check(ev, rc, "set CURLOPT_FORBID_REUSE") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;

    /* Set header function which will handle configuration link parsing */
    rc = curl_easy_setopt(ev->curl, CURLOPT_HEADERFUNCTION, (write_cb_t)sxauthd_headfn);
    if (curl_check(ev,rc, "set CURLOPT_HEADERFUNCTION") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    rc = curl_easy_setopt(ev->curl, CURLOPT_HEADERDATA, &header_ctx);
    if (curl_check(ev,rc, "set CURLOPT_HEADERFUNCTION") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    rc = curl_easy_setopt(ev->curl, CURLOPT_HTTPHEADER, ev->slist);
    if (curl_check(ev, rc, "set headers"))
        goto sxi_curlev_fetch_sxauthd_credentials_err;

    /* This will suppress printing contents of a body and assign failure in case of http error code returned */
    rc = curl_easy_setopt(ev->curl, CURLOPT_WRITEFUNCTION, writefn);
    if (curl_check(ev,rc, "set CURLOPT_WRITEFUNCTION") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    rc = curl_easy_setopt(ev->curl, CURLOPT_WRITEDATA, ev->ctx);
    if (curl_check(ev,rc, "set CURLOPT_WRITEDATA") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;

    /* Set basic authentication method */
    rc = curl_easy_setopt(ev->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    if (curl_check(ev, rc, "set CURLOPT_HTTPAUTH") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    rc = curl_easy_setopt(ev->curl, CURLOPT_USERNAME, username);
    if (curl_check(ev, rc, "set CURLOPT_USERNAME") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    rc = curl_easy_setopt(ev->curl, CURLOPT_PASSWORD, password);
    if (curl_check(ev, rc, "set CURLOPT_PASSWORD") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;

    /* Prepare query data - urlencode inputs */
    display_enc = sxi_urlencode(sx, display, 1);
    if(!display_enc) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    }
    unique_enc = sxi_urlencode(sx, unique, 1);
    if(!unique_enc) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    }
    data_len = strlen(display_enc) + strlen(unique_enc) + lenof("display=") + lenof("&unique=") + 1;
    data = malloc(data_len);
    if(!data) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    }
    snprintf(data, data_len, "display=%s&unique=%s", display_enc, unique_enc); /* 'data' stores url-encoded body required by sxauthd */

    /* set verb and POST data */
    rc = curl_easy_setopt(ev->curl, CURLOPT_POST, 1);
    if(rc == CURLE_OK)
        rc = curl_easy_setopt(ev->curl, CURLOPT_POSTFIELDSIZE, data_len);
    if(rc == CURLE_OK)
        rc = curl_easy_setopt(ev->curl, CURLOPT_POSTFIELDS, data);
    if(curl_check(ev,rc,"set verb") == -1)
        goto sxi_curlev_fetch_sxauthd_credentials_err;

    /* Send the query */
    rc = curl_easy_perform(ev->curl);
    if (rc != CURLE_OK) {
        /* location_headfn() stores error messages, get them if they are set */
        if(sxi_cbdata_geterrnum(cbdata) != SXE_NOERROR)
            sxi_seterr(sx, sxi_cbdata_geterrnum(cbdata), "%s", sxi_cbdata_geterrmsg(cbdata));
        else
            sxi_seterr(sx, SXE_ECOMM,"Cannot connect to %s: %s", url, curl_easy_strerror(rc));
        free(header_ctx.link);
        goto sxi_curlev_fetch_sxauthd_credentials_err;
    }

    /* Check if error was stored in cbdata error buffer */
    if(cbdata->recv_ctx.reply_status != 302 || cbdata->recv_ctx.reasonsz || !header_ctx.is_sxauthd_host)
        goto sxi_curlev_fetch_sxauthd_credentials_err;

    ret = header_ctx.link;
sxi_curlev_fetch_sxauthd_credentials_err:
    curl_easy_cleanup(ev->curl);
    free(display_enc);
    free(unique_enc);
    free(data);
    free(ev);
    sxi_cbdata_finish(e, &cbdata, url, sxauthd_errfn);
    return ret;
}

sxi_conns_t *sxi_curlev_get_conns(curlev_t *ev)
{
    return ev && ev->ctx ? ev->ctx->conns : NULL;
}

void sxi_curlev_set_verified(curlev_t *ev, int value)
{
    ev->ssl_verified = value;
}

int sxi_curlev_verify_peer(curlev_t *ev)
{
    return ev->verify_peer;
}

int sxi_curlev_disable_proxy(curl_events_t *ev)
{
    if (!ev)
        return -1;
    ev->disable_proxy = 1;
    return 0;
}

int sxi_cbdata_set_timeouts(curlev_context_t *e, unsigned int hard_timeout, unsigned int soft_timeout) {
    if(!e)
        return 1;
    if(hard_timeout && soft_timeout && soft_timeout > hard_timeout) {
        sxi_cbdata_seterr(e, SXE_EARG, "Invalid argument: hard timeout cannot be lower than soft timeout");
        return 1;
    }
    e->hard_timeout = hard_timeout;
    e->soft_timeout = soft_timeout;
    return 0;
}
