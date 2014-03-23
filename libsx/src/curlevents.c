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
#include "libsx-int.h"
#include "misc.h"
#include "cert.h"
#include "sxproto.h"
#include <curl/curl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <unistd.h>

#define ERRBUF_SIZE 512
enum ctx_tag { CTX_UPLOAD, CTX_UPLOAD_HOST, CTX_DOWNLOAD, CTX_JOB, CTX_HASHOP, CTX_GENERIC };

struct recv_context {
    char errbuf[ERRBUF_SIZE+1];
    int rc;
    int fail;
    int finished;
    long reply_status;
    char *reason;
    unsigned reasonsz;
    int header_seen;
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
};

struct curlev_context {
    sxi_conns_t *conns;
    int ref;

    /* reset after each retry */
    struct recv_context recv_ctx;

    /* keep all of the below across retries */

    body_cb_t data_cb;
    finish_cb_t finish_cb;
    struct retry_ctx retry;

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
};

static struct curlev_context *sxi_cbdata_create(sxi_conns_t *conns, finish_cb_t cb)
{
    struct curlev_context *ret;
    sxc_client_t *sx;
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
    ret->conns = conns;
    ret->finish_cb = cb;
    ret->ref = 1;
    sxi_hostlist_init(&ret->retry.hosts);
    return ret;
}

static int sxi_cbdata_is_tag(struct curlev_context *ctx, enum ctx_tag expected)
{
    if (ctx) {
        sxc_client_t *sx = sxi_conns_get_client(ctx->conns);
        if (ctx->tag == expected)
            return 1;
        sxi_seterr(sx, SXE_EARG, "context tag mismatch: %d != %d", ctx->tag, expected);
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

int sxi_set_retry_cb(curlev_context_t *ctx, const sxi_hostlist_t *hlist, retry_cb_t cb,
                     enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size,
                     ctx_setup_cb_t setup_callback)
{
    if (ctx) {
        sxc_client_t *sx = sxi_conns_get_client(ctx->conns);
        ctx->retry.cb = cb;
        ctx->retry.setup_callback = setup_callback;
        ctx->retry.verb = verb;
        ctx->retry.query = strdup(query);
        if (!ctx->retry.query) {
            sxi_setsyserr(sx, SXE_EMEM, "Out of memory allocating retry query");
            return -1;
        }
        ctx->retry.content = content;
        ctx->retry.content_size = content_size;
        if (sxi_hostlist_add_list(sx, &ctx->retry.hosts, hlist))
            return -1;
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

static int sxi_cbdata_decref(curlev_context_t **ctx_ptr, int *freed)
{
    if (ctx_ptr) {
        curlev_context_t *ctx = *ctx_ptr;
        sxc_client_t *sx;
        if (!ctx)
            return -1;
        sx = sxi_conns_get_client(ctx->conns);
        ctx->ref--;
        *ctx_ptr = NULL;
        if (ctx->ref < 0) {
            sxi_seterr(sx, SXE_EARG, "cbdata: reference count wrong: %d", ctx->ref);
            /* don't free, the reference count is corrupt */
            return -1;
        }
        SXDEBUG("cbdata reference count for %p: %d", (void*)ctx, ctx->ref);
        if (!ctx->ref) {
            SXDEBUG("freeing cbdata %p", (void*)ctx);
            sxi_cbdata_reset(ctx);
            sxi_hostlist_empty(&ctx->retry.hosts);
            free(ctx->retry.query);
            free(ctx);
            if (freed)
                *freed = 1;
        }
        return 0;
    }
    return -1;
}

int sxi_cbdata_unref(curlev_context_t **ctx_ptr)
{
    return sxi_cbdata_decref(ctx_ptr, NULL);
}

int sxi_cbdata_free(curlev_context_t **ctxptr)
{
    sxc_client_t *sx = ctxptr && (*ctxptr) ? sxi_conns_get_client((*ctxptr)->conns) : NULL;
    int freed = 0;
    if (sxi_cbdata_decref(ctxptr, &freed))
        return -1;
    if (!freed) {
        sxi_notice(sx, "expected cbdata to be freed here");
        return -1;
    }
    return 0;
}

void sxi_cbdata_reset(curlev_context_t *ctx)
{
    if (ctx) {
        struct recv_context *rctx = &ctx->recv_ctx;
        free(rctx->reason);
        memset(rctx, 0, sizeof(*rctx));
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

int sxi_cbdata_result(curlev_context_t *ctx, int *curlcode)
{
    struct recv_context *rctx = ctx ?  &ctx->recv_ctx : NULL;
    if (!rctx)
        return -1;
    if (curlcode)
        *curlcode = rctx->rc;
    if (rctx->rc == CURLE_OK || rctx->rc == CURLE_WRITE_ERROR)
        return rctx->reply_status;
    if (rctx->rc == CURLE_OUT_OF_MEMORY) {
        sxi_seterr(sxi_conns_get_client(ctx->conns), SXE_ECURL,
                   "Cluster query failed: out of memory in library routine");
        return -1;
    }
    return 0;
}

sxi_conns_t *sxi_cbdata_get_conns(curlev_context_t *ctx)
{
    return ctx ? ctx->conns : NULL;
}

int sxi_cbdata_wait(curlev_context_t *ctx, curl_events_t *e, int *curlcode)
{
    if (ctx) {
        struct recv_context *rctx = &ctx->recv_ctx;
        while (!rctx->finished) {
            if (sxi_curlev_poll(e)) {
                *curlcode = rctx->rc;
                return -1;
            }
        }
        return sxi_cbdata_result(ctx, curlcode);
    }
    return -1;
}

void sxi_cbdata_finish(curl_events_t *e, curlev_context_t **ctxptr, const char *url, error_cb_t err)
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
                sxi_seterr(sx, SXE_ECURL, "%s: possible MITM attack: run sxinit again!",
                           strerr);
            else
                sxi_seterr(sx, SXE_ECURL, "%s: %s", url ? url : "", msg);
        }
    } else if (rctx->reply_status > 0 && rctx->reason && rctx->reasonsz > 0) {
        rctx->reason[rctx->reasonsz] = '\0';
        if (err)
            err(ctx->conns, rctx->reply_status, rctx->reason);
    }

    sxi_clear_operation(sx);
    if (ctx->retry.cb && (rctx->rc != CURLE_OK || rctx->reply_status / 100 != 2)) {
        if (++ctx->retry.hostidx >= sxi_hostlist_get_count(&ctx->retry.hosts)) {
            if (ctx->retry.retries < 2 || ctx->recv_ctx.reply_status == 429) {
                ctx->retry.retries++;
                ctx->retry.hostidx = 0;
                sxi_retry_throttle(sx, ctx->retry.retries);
            }
        }
        const char *host = sxi_hostlist_get_host(&ctx->retry.hosts, ctx->retry.hostidx);
        sxi_cbdata_reset(ctx);
        if (host) {
            if (!ctx->retry.cb(ctx, ctx->conns, host,
                               ctx->retry.verb, ctx->retry.query, ctx->retry.content, ctx->retry.content_size,
                               ctx->retry.setup_callback,
                               ctx->data_cb))
                return; /* not finished yet, context reused */
        }
        else {
            SXDEBUG("All %d hosts returned failure, retried %d times",
                    sxi_hostlist_get_count(&ctx->retry.hosts),
                    ctx->retry.retries);
        }
    }
    if (ctx->finish_cb)
        ctx->finish_cb(ctx, url);
    sxi_cbdata_unref(ctxptr);
}

typedef struct curlev {
    curlev_context_t *ctx;
    char *host;
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
} curlev_t;

#define MAX_EVENTS 64
typedef struct {
    curlev_t *queue[MAX_EVENTS];
    unsigned read;
    unsigned write;
} curlev_fifo_t;

static int fifo_is_full(const curlev_fifo_t *fifo)
{
    return (fifo->write + 1) % MAX_EVENTS == fifo->read;
}

static int fifo_count(const curlev_fifo_t *fifo)
{
    return (fifo->write - fifo->read) % MAX_EVENTS;
}

static int fifo_put(curlev_fifo_t *fifo, curlev_t *ev)
{
    if (fifo_is_full(fifo))
        return -1;
    fifo->queue[fifo->write] = ev;
    fifo->write = (fifo->write + 1) % MAX_EVENTS;
    return 0;
}

static curlev_t *fifo_get(curlev_fifo_t *fifo)
{
    curlev_t *ev;
    if (fifo->read == fifo->write)
        return NULL;/* empty */
    ev = fifo->queue[fifo->read];
    fifo->queue[fifo->read] = NULL;
    fifo->read = (fifo->read + 1) % MAX_EVENTS;
    return ev;
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
    switch (ev->head(ctx->conns, ptr, size, nmemb)) {
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
	    sxi_seterr(sx, SXE_ECOMM, "Bad cluster reply(%ld): the cluster may be under maintenance or overloaded, please try again later", wd->reply_status);
	} else if(wd->reply_status == 414) {
	    sxi_seterr(sx, SXE_ECOMM, "URI too long: the path to the requested resource is too long");
	} else {
	    /* Reply is certainly not from sx */
	    sxi_seterr(sx, SXE_ECOMM, "The server contacted is not an SX Cluster node (http status: %ld)", wd->reply_status);
	}
	wd->fail = 1;
    }

    if (!wd->fail && wd->reply_status >= 400)
	wd->fail = 1;
    if(wd->fail) {
	SXDEBUG("error reply: %.*s\n", (int)size, (char *)ptr);
	if(conns) {
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


/* to avoid using too much memory */
struct curl_events {
    CURLM *multi;
    CURLSH *share;
    sxi_ht *hosts_map;
    sxi_conns_t *conns;
    int running;
    int verbose;
    int used;
    int depth;
    int added_notpolled;
    const char *cafile;
    const char *defaultcafile;
    char *savefile;
    int saved, quiet;
    X509 *servercert;
};

#define MAX_ACTIVE_PER_HOST 2
struct host_info {
    int active;
    curlev_fifo_t fifo;
    curlev_t reuse[MAX_ACTIVE_PER_HOST];
};

static void ctx_err(curlev_context_t *ctx, CURLcode rc, const char *msg)
{
    if (!ctx)
        return;
    ctx->recv_ctx.rc = rc;
    strncpy(ctx->recv_ctx.errbuf, msg, sizeof(ctx->recv_ctx.errbuf)-1);
    if (ctx->conns) {
        sxc_client_t *sx = sxi_conns_get_client(ctx->conns);
        if (sx) {
            SXDEBUG("ev_add: %s", msg);
            sxi_seterr(sx, SXE_EARG, "ev_add: bad argument");
        }
    }
}


#define EVENTSDEBUG(e, ...) do {\
    if (e && e->conns) {\
        sxc_client_t *sx = sxi_conns_get_client(e->conns); \
        SXDEBUG(__VA_ARGS__);\
    }} while (0)

#define EVDEBUG(ev, ...) do {\
    if (ev && ev->ctx && ev->ctx->conns) {\
        sxc_client_t *sx = sxi_conns_get_client(ev->ctx->conns); \
        SXDEBUG(__VA_ARGS__);\
    }} while (0)

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
        if (ev && ev->ctx && ev->ctx->conns)
            sxi_seterr(sxi_conns_get_client(ev->ctx->conns), SXE_ECURL, "curl multi failed: %s, %s",
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

static int info_free(curl_events_t *e, struct host_info *info)
{
    unsigned i;

    if (!info) {
        return 0;
    }
    for (i=0;i<MAX_ACTIVE_PER_HOST;i++) {
        ev_free(&info->reuse[i]);
    }
    for (i=0;i<MAX_EVENTS;i++)
        ev_free(info->fifo.queue[i]);
    free(info);
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
    if (e->hosts_map) {
        struct host_info *info;
        const void *host;
        unsigned host_len;
        /* TODO: iterate */
        while (!sxi_ht_enum_getnext(e->hosts_map, &host, &host_len, (const void**)&info)) {
            info_free(e, info);
        }
        sxi_ht_free(e->hosts_map);
        e->hosts_map = NULL;
    }
    if (e->share) {
        curlsh_check(e, curl_share_cleanup(e->share));
        e->share = NULL;
    }
    free(e->servercert);
    free(e->savefile);
    free(e);
    *c = NULL;
}

static const char *get_default_cafile(sxc_client_t *sx)
{
    /* curl determines this at configure time, but if we ship
     * a single binary we have to detect at runtime */
    unsigned i;
    const char *default_ca_files[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/usr/share/ssl/certs/ca-bundle.crt"
    };
    for (i=0; i<sizeof(default_ca_files)/sizeof(default_ca_files[0]);i++) {
        const char *path = default_ca_files[i];
        if (access(path, R_OK) == 0) {
            SXDEBUG("Default CA file: %s", path);
            return path;
        }
    }
    return "";
}

curl_events_t *sxi_curlev_init(sxi_conns_t *conns)
{
    curl_events_t *x = calloc(1, sizeof(*x));
    if (!x)
        return NULL;

    x->conns = conns;
    do {
        x->defaultcafile = get_default_cafile(sxi_conns_get_client(conns));
        x->cafile = "";/* verify with default root CAs */
        if (!(x->share = curl_share_init()))
            break;
        if (!(x->hosts_map = sxi_ht_new(sxi_conns_get_client(conns), 64)))
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

int sxi_curlev_set_save_rootCA(curl_events_t *ev, const char *filename, int quiet)
{
    if (!ev)
        return -1;
    free(ev->savefile);
    ev->savefile = strdup(filename);
    ev->saved = 0;
    ev->quiet = quiet;
    return ev->savefile ? 0 : -1;
}

int sxi_curlev_is_saved(curl_events_t *ev)
{
    return ev && ev->saved;
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
            ctx_err(ev->ctx, CURLE_OUT_OF_MEMORY, "curl_slist_append: out of memory");
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

    if (e->cafile && !*e->cafile)
        e->cafile = e->defaultcafile;
    if (e->cafile && *e->cafile) {
        rc = curl_easy_setopt(curl, CURLOPT_CAINFO, e->cafile);
        if (curl_check(ev, rc, "set CURLOPT_CAINFO") == -1)
            return -1;
        rc = curl_easy_setopt(curl, CURLOPT_CAPATH, "/");
        if (curl_check(ev, rc, "set CURLOPT_CAPATH") == -1)
            return -1;
    }

#if LIBCURL_VERSION_NUM >= 0x071000
    rc = curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockoptfn);
    if (curl_check(ev,rc,"set sockoptfn") == -1)
        return -1;
#endif
    return 0;
}

typedef size_t (*write_cb_t)(char *ptr, size_t size, size_t nmemb, void *ctx);

static struct host_info *get_host(curl_events_t *e, const char *host)
{
    struct host_info *info = NULL;
    if (sxi_ht_get(e->hosts_map, host, strlen(host)+1, (void**)&info) || !info) {
        info = calloc(1, sizeof(*info));
        if (sxi_ht_add(e->hosts_map, host, strlen(host)+1, info)) {
            /* it failed */
            free(info);
            return NULL;
        }
    }
    return info;
}

static int ask_trust(sxc_client_t *sx, const char *cafile, X509 *x)
{
    if (cafile && *cafile) {
        sxi_print_old_certificate_info(sx, cafile);
        sxi_notice(sx, "The new CA certificate is:");
    } else
        sxi_notice(sx, "Warning: self-signed certificate:\n");
    sxi_print_certificate_info(sx, x);

    return sxi_confirm(sx, "Do you trust this SSL certificate?", 0) ? 0 : -1;
}

static const char *ssl_err(void)
{
    const char *s = ERR_reason_error_string(ERR_get_error());
    return s ? s : "";
}

static int ssl_get_CA_cert(X509_STORE_CTX *ctx, void *arg)
{
    STACK_OF(X509) *sk;
    int err, last_cert, ok;
    BIO *out;
    X509 *x;
    curl_events_t *e = arg;
    sxc_client_t *sx = sxi_conns_get_client(e->conns);
    const char *name;
    struct stat sb;

    ok = X509_verify_cert(ctx);
    sk = X509_STORE_CTX_get_chain(ctx);
    if (!ok) {
        err = X509_STORE_CTX_get_error(ctx);
        if (e->savefile && (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN || err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)) {
	    if(!e->quiet) {
		if (ask_trust(sx, e->cafile, sk_X509_value(sk, 0)) == -1) {
		    sxi_notice(sx, "Not trusting certificate");
		    return 0;
		}
		sxi_notice(sx, "Trusting self-signed certificate");
	    }
            X509_STORE_CTX_set_error(ctx,X509_V_OK);
        } else {
            SXDEBUG("Failed to verify SSL certificate: %s\n", X509_verify_cert_error_string(err));
            return 0;
        }
    }
    if (!sk) {
        sxi_seterr(sx, SXE_ECOMM, "No certificate chain?");
        return 0;
    }
    x = sk_X509_value(sk, 0);
    name = sxi_conns_get_sslname(e->conns) ? sxi_conns_get_sslname(e->conns) : sxi_conns_get_dnsname(e->conns);
    if (sxi_verifyhost(sx, name, x) != CURLE_OK) {
        if (!e->cafile) {
            sxi_notice(sx, "Ignoring %s!", sxc_geterrmsg(sx));
            return 1;
        }
        sxi_seterr(sx, SXE_ECOMM, "Hostname mismatch in certificate, expected: \"%s\"", name);
        X509_STORE_CTX_set_error(ctx,X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    if (!e->savefile)
        return 1;
    last_cert = sk_X509_num(sk) - 1;
    if (last_cert < 0 || !(x = sk_X509_value(sk, last_cert))) {
        sxi_seterr(sx, SXE_ECOMM, "Cannot retrieve root cert");
        return 0;
    }
    ERR_clear_error();
    if (!(out = BIO_new_file(e->savefile,"w"))) {
        sxi_seterr(sx, SXE_EWRITE, "Cannot open file '%s' for writing: %s", e->savefile, ssl_err());
        return 0;
    }
    if (!PEM_write_bio_X509(out, x)) {
        sxi_seterr(sx, SXE_EWRITE, "Cannot write certificate to '%s': %s", e->savefile, ssl_err());
        return 0;
    }
    if (!BIO_free(out)) {
        sxi_seterr(sx, SXE_EWRITE, "Cannot close file '%s': %s", e->savefile, ssl_err());
        return 0;
    }
    if (stat(e->savefile, &sb) == -1 || !sb.st_size) {
        sxi_seterr(sx, SXE_EWRITE, "Cannot save certificate to file: %s", e->savefile);
        return 0;
    }
    e->saved = 1;
    SXDEBUG("root CA saved to %s", e->savefile);
    return 1;/* ok */
}

static CURLcode sslctxfun_save_rootCA(CURL *curl, void *sslctx, void *parm)
{
    SSL_CTX *ctx = (SSL_CTX*)sslctx;
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_cert_verify_callback(ctx, ssl_get_CA_cert, parm);
    return CURLE_OK;
}

static void resolve(curlev_t *ev, const char *host)
{
#if LIBCURL_VERSION_NUM >= 0x071503
    if (!ev || !host)
        return;
    struct curl_slist *slist = NULL, *slist2 = NULL;
    unsigned len = strlen(host) * 2 + 6;
    char *res = malloc(len);
    if (!res)
        return;
    /* avoid getaddrinfo */
    snprintf(res, len, "%s:80:%s", host, host);
    slist = curl_slist_append(slist, res);
    if (!slist) {
        free(res);
        return;
    }
    snprintf(res, len, "%s:443:%s", host, host);
    slist2 = curl_slist_append(slist, res);
    free(res);
    if (!slist2) {
        curl_slist_free_all(slist);
        return;
    }
    ev->resolve = slist2;
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
        resolve(ev, src->host);
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

        /* TODO: only if we're in ssl mode */
        rc = curl_easy_setopt(ev->curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun_save_rootCA);
        if (curl_check(ev, rc, "set CURLOPT_SSL_CTX_FUNCTION") == -1)
            break;
        rc = curl_easy_setopt(ev->curl, CURLOPT_SSL_CTX_DATA, e);
        if (curl_check(ev, rc, "set CURLOPT_SSL_CTX_DATA") == -1)
            break;
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
        ret = 0;
    } while(0);
    free(src->url);
    memset(src, 0, sizeof(*src));
    free(src);
    return ret;
}

static int hmac_update_str(sxc_client_t *sx, HMAC_CTX *ctx, const char *str) {
    int r = sxi_hmac_update(ctx, (unsigned char *)str, strlen(str));
    if(r)
	r = sxi_hmac_update(ctx, (unsigned char *)"\n", 1);
    if(!r) {
	SXDEBUG("hmac_update failed for '%s'", str);
	sxi_seterr(sx, SXE_ECRYPT, "Cluster query failed: HMAC calculation failed");
    }
    return r;
}

static int compute_date(sxc_client_t *sx, char buf[32], time_t diff, HMAC_CTX *hmac_ctx) {
    const char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const char *wkday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    time_t t = time(NULL) + diff;
    struct tm ts;

    if(!gmtime_r(&t, &ts)) {
	SXDEBUG("failed to get time");
	sxi_seterr(sx, SXE_EARG, "Cannot get current time: invalid argument");
	return -1;
    }
    sprintf(buf, "%s, %02u %s %04u %02u:%02u:%02u GMT", wkday[ts.tm_wday], ts.tm_mday, month[ts.tm_mon], ts.tm_year + 1900, ts.tm_hour, ts.tm_min, ts.tm_sec);

    if(!hmac_update_str(sx, hmac_ctx, buf))
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
    HMAC_CTX hmac_ctx;
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
        { content_type_field, content_type_value }
    };

    memset(bintoken, 0, sizeof(bintoken));
    conns = e->conns;
    sx = sxi_conns_get_client(conns);
    /* we sign request as late as possible to avoid
     * clock drift errors from the server */
    HMAC_CTX_init(&hmac_ctx);
    do {
        const char *verb = verbstr(src->verb);
        const char *token = sxi_conns_get_auth(e->conns);
        const char *query;
        char *url;
	rc = -1;

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

        if (!strncmp(url, "http://", 7))
            query = url + 7;
        else if(!strncmp(url, "https://", 8))
            query = url + 8;
        else {
            conns_err(SXE_EARG, "Invalid URL: %s", url);
            break;
        }
        query = strchr(query, '/');
        if (!query) {
            conns_err(SXE_EARG, "Cluster query failed: Bad URL");
            break;
        }
        query++;
        if(sxi_b64_dec(sx, token, bintoken, &keylen) || keylen != AUTHTOK_BIN_LEN) {
            EVDEBUG(ev, "failed to decode the auth token");
            conns_err(SXE_EAUTH, "Cluster query failed: invalid authentication token");
            break;
        }

        if(!sxi_hmac_init_ex(&hmac_ctx, bintoken + AUTH_UID_LEN, AUTH_KEY_LEN, EVP_sha1(), NULL)) {
	    EVDEBUG(ev, "failed to init hmac context");
	    conns_err(SXE_ECRYPT, "Cluster query failed: HMAC calculation failed");
	    break;
	}

	if(!hmac_update_str(sx, &hmac_ctx, verb) || !hmac_update_str(sx, &hmac_ctx, query))
	    break;

	if (compute_date(sx, datebuf, sxi_conns_get_timediff(e->conns), &hmac_ctx) == -1)
	    break;
	if(content_size) {
	    char content_hash[41];
	    unsigned char d[20];
	    EVP_MD_CTX ch_ctx;

	    if(!EVP_DigestInit(&ch_ctx, EVP_sha1())) {
		EVDEBUG(ev, "failed to init content digest");
		conns_err(SXE_ECRYPT, "Cannot compute hash: unable to initialize crypto library");
		break;
	    }
	    if(!EVP_DigestUpdate(&ch_ctx, content, content_size) || !EVP_DigestFinal(&ch_ctx, d, NULL)) {
		EVDEBUG(ev, "failed to update content digest");
		conns_err(SXE_ECRYPT, "Cannot compute hash: crypto library failure");
		EVP_MD_CTX_cleanup(&ch_ctx);
		break;
	    }
	    EVP_MD_CTX_cleanup(&ch_ctx);

	    sxi_bin2hex(d, sizeof(d), content_hash);
	    content_hash[sizeof(content_hash)-1] = '\0';

	    if(!hmac_update_str(sx, &hmac_ctx, content_hash))
		break;
	} else if(!hmac_update_str(sx, &hmac_ctx, "da39a3ee5e6b4b0d3255bfef95601890afd80709"))
	    break;

	keylen = AUTH_KEY_LEN;
	if(!sxi_hmac_final(&hmac_ctx, bintoken + AUTH_UID_LEN, &keylen) || keylen != AUTH_KEY_LEN) {
	    EVDEBUG(ev, "failed to finalize hmac calculation");
	    conns_err(SXE_ECRYPT, "Cluster query failed: HMAC finalization failed");
	    break;
	}
        if(!(sendtok = sxi_b64_enc(sx, bintoken, AUTHTOK_BIN_LEN))) {
            EVDEBUG(ev, "failed to encode computed auth token");
            break;
        }

        snprintf(auth, sizeof(auth), "SKY %s", sendtok);

        rc = set_headers(e, ev, headers, sizeof(headers)/sizeof(headers[0]));
        if (curl_check(ev,rc,"set headers") == -1)
            break;

	rc = 0;
    } while(0);
    free(sendtok);
    HMAC_CTX_cleanup(&hmac_ctx);
    return rc;
}

static int enqueue_request(curl_events_t *e, curlev_t *ev, int re)
{
    struct host_info *info;
    info = get_host(e, ev->host);
    if (!info) {
        ctx_err(ev->ctx, SXE_EMEM, "out of mem allocing host info");
        return -1;
    }

    if (info->active < MAX_ACTIVE_PER_HOST) {
        unsigned i;
        /* reuse previous easy handle to reuse the connection and prevent
         * TIME_WAIT issues */

        /* find free slot */
        for (i=0;i<MAX_ACTIVE_PER_HOST;i++) {
            curlev_t *o;
            o = &info->reuse[i];
            if (!o->ctx) {
                /* free slot */
                if (curlev_apply(e, o, ev) == -1) {
                    EVDEBUG(ev,"curlev_apply failed");
                    return -1;
                }
                ev = o;
                break;
            }
        }
        if (i == MAX_ACTIVE_PER_HOST) {
            EVDEBUG(ev,"no free hosts?");
            return -1;
        }
        /* less than 2 active requests: launch requests now */
        CURLMcode rcm = curl_multi_add_handle(e->multi, ev->curl);
        if (curlm_check(ev,rcm,"add_handle") == -1) {
            EVDEBUG(ev,"add_handle failed: %s", sxc_geterrmsg(sxi_conns_get_client(ev->ctx->conns)));
            return -1;
        }
        info->active++;
        EVDEBUG(ev, "::add_handle %p, active now: %d", ev->curl, info->active);

        if (re)
            EVDEBUG(ev, "Started next waiting request for host %s (%d active)", ev->host, info->active);
        else
            EVDEBUG(ev, "Started new request to host %s (%d active)", ev->host, info->active);
    } else {
        /* has pending request for this host, chain request to avoid
         * pipelining timeout.
         * Note: this list is actually reversed, but we only request
         * hashes so it doesn't matter. */
        fifo_put(&info->fifo, ev);
        EVDEBUG(ev, "queued now: %d", fifo_count(&info->fifo));
        EVDEBUG(ev, "Enqueued request to existing host %s", ev->host);
    }
    return 0;
}

static int queue_next(curl_events_t *e, curlev_t *ev)
{
    struct host_info *info;
    info = get_host(e, ev->host);
    if (!info) {
        ctx_err(ev->ctx, SXE_EMEM, "out of mem allocing host info");
        return -1;
    }
    info->active--;
    EVDEBUG(ev, "%s active: %d, queued: %d", ev->host, info->active, fifo_count(&info->fifo));
    ev = fifo_get(&info->fifo);
    if (!ev) {
        EVDEBUG(ev,"finished %s", ev->host);
        EVDEBUG(ev, "finished queued requests for host %s", ev->host);
        /* TODO: remove the host after a timeout of a few mins */
        return 0;
    }
    return enqueue_request(e, ev, 1);
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
        if (e->used >= MAX_EVENTS)
            break;
        ev = calloc(1, sizeof(*ev));
        if (!ev) {
            ctx_err(ctx, CURLE_OUT_OF_MEMORY, "failed to allocate event");
            break;
        }
        ev->error = reply->headers.error;
        ev->ctx = reply->headers.ctx;
        sxi_cbdata_ref(ev->ctx);
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
        ev->url = strdup(headers->url);
        if (!ev->url) {
            ctx_err(ctx, CURLE_OUT_OF_MEMORY, "cannot dup URL");
            break;
        }
        ev->verb = verb;
        if (enqueue_request(e, ev, 0) == -1) {
            /* TODO: remove all reuse[] handles if this fails */
            EVDEBUG(ev, "enqueue_request failed");
            return -1;
        }
        e->used++;
        if (!e->depth)
            sxi_curlev_poll_immediate(e);
        else
            e->added_notpolled = 1;
        return 0;
    } while(0);
    EVDEBUG(ev, "ev_add failed");
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
    sxc_client_t *sx = ctx ? sxi_conns_get_client(ctx->conns) : NULL;
    sxi_seterr(sx, SXE_EARG, "Body received on HEAD?\n");
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

int sxi_curlev_poll(curl_events_t *e)
{
    CURLMcode rc;
    int callbacks = 0;
    long timeout = -1;
    sxc_client_t *sx;
    if (!e) {
        return -1;
    }
    do {
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

        rc = curl_multi_wait(e->multi, NULL, 0, timeout, NULL);
        if (curlm_check(NULL,rc,"wait") == -1)
            return -1;

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

    do {
        rc = curl_multi_perform(e->multi, &e->running);
    } while (rc == CURLM_CALL_MULTI_PERFORM);
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
                curlev_t *ev = (curlev_t*)priv;
                struct recv_context *rctx = &ev->ctx->recv_ctx;

                curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &rctx->reply_status);
                rctx->errbuf[sizeof(rctx->errbuf)-1] = 0;
                rctx->rc = msg->data.result;
		if(rctx->rc == CURLE_OK)
		    sxi_conns_set_timeout(e->conns, ev->host, 1);
		else
		    sxi_conns_set_timeout(e->conns, ev->host, -1);

                /* get url, it will get freed by curl_easy_cleanup */
                curl_easy_getinfo(msg->easy_handle, CURLINFO_EFFECTIVE_URL, &url);
                /* finish might add more queries, let it know
                 * there is room */
                rc = curl_multi_remove_handle(e->multi, ev->curl);
                if (curlm_check(ev, rc,"remove_handle") == -1) {
                    e->depth--;
                    return -1;
                }
                EVDEBUG(ev, "::remove_handle %p", ev->curl);
                e->used--;
                curlev_context_t *ctx = ev->ctx;
                ev->ctx = NULL;
                queue_next(e, ev);/* modifies ev */
                sxi_cbdata_finish(e, &ctx, url, ev->error);
            } else {
                EVENTSDEBUG(e,"WARNING: failed to find curl handle\n");
                e->depth--;
                return -1;
            }
    }
    e->depth--;
    return callbacks;
}

int sxi_cbdata_result_fail(curlev_context_t* ctx)
{
    return !ctx || ctx->recv_ctx.rc != CURLE_OK;
}
