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

#include "default.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <curl/curl.h>
#include <unistd.h>

#include "libsxclient-int.h"
#include "cluster.h"
#include "curlevents.h"
#include "misc.h"
#include "vcrypto.h"
#include "version.h"
#include "jparse.h"

#define CLSTDEBUG(...) do{ sxc_client_t *_sx; if(conns && (_sx = conns->sx)) sxi_debug(_sx, __func__, __VA_ARGS__); } while(0)
#define conns_err(...) do { if(conns) sxi_seterr(conns->sx, __VA_ARGS__); } while(0)

struct _sxi_conns_t {
    sxc_client_t *sx;
    char *uuid;
    char *dnsname;
    char *sslname;
    sxi_hostlist_t hlist;
    sxi_ht *timeouts;
    char *auth_token;
    curl_events_t *curlev;
    time_t timediff;
    int insecure, internal_security;
    int clock_drifted;
    int vcheckwarn;
    int no_blacklisting;
    int no_clock_adjust;
    uint16_t port;

    /* Transfer progress stats */
    sxc_xfer_stat_t *xfer_stat;

    /* Connection timeouts */
    unsigned int hard_timeout; /* Timeout used for requests sent to cluster: total time a single request is allowed to exist */
    unsigned int soft_timeout; /* Timeout for stalled requests: maximum time between successful data parts being transferred */
};

sxi_conns_t *sxi_conns_new(sxc_client_t *sx) {
    sxi_conns_t *conns = calloc(1, sizeof(*conns));
    if(!conns) {
	SXDEBUG("OOM allocating conns");
	sxi_seterr(sx, SXE_EMEM, "Failed to create conns: Out of memory");
	return NULL;
    }
    conns->sx = sx;
    conns->curlev = sxi_curlev_init(conns);
    if(!conns->curlev) {
        SXDEBUG("OOM allocating curl events");
        sxi_seterr(sx, SXE_EMEM, "Failed to initialize curl events");
        free(conns);
        return NULL;
    }
    sxi_conns_set_cafile(conns, NULL);
    return conns;
}

void sxi_conns_free(sxi_conns_t *conns) {
    void *value;

    if(!conns)
	return;
    sxi_curlev_done(&conns->curlev);
    free(conns->uuid);
    free(conns->dnsname);
    sxi_hostlist_empty(&conns->hlist);
    free(conns->auth_token);
    free(conns->sslname);
    free(conns->xfer_stat);

    if(conns->timeouts) {
	while(!sxi_ht_enum_getnext(conns->timeouts, NULL, NULL, (const void **)&value))
	    free(value);
	sxi_ht_free(conns->timeouts);
    }

    free(conns);
}

int sxi_conns_set_dnsname(sxi_conns_t *conns, const char *dnsname) {
    char *name;
    if(dnsname && *dnsname) {
	if(!(name = strdup(dnsname))) {
	    CLSTDEBUG("failed to duplicate %s", dnsname);
	    conns_err(SXE_EMEM, "Cannot set cluster dnsname: Out of memory");
	    return 1;
	}
    } else
	name = NULL;
    free(conns->dnsname);
    conns->dnsname = name;
    return 0;
}

int sxi_conns_set_sslname(sxi_conns_t *conns, const char *sslname) {
    char *name;
    if(sslname && *sslname) {
	if(!(name = strdup(sslname))) {
	    CLSTDEBUG("failed to duplicate %s", sslname);
	    conns_err(SXE_EMEM, "Cannot set cluster sslname: Out of memory");
	    return 1;
	}
    } else
        return 0;
    free(conns->sslname);
    conns->sslname = name;
    return 0;
}

const char *sxi_conns_get_dnsname(const sxi_conns_t *conns) {
    return conns ? conns->dnsname : NULL;
}

const char *sxi_conns_get_sslname(const sxi_conns_t *conns) {
    return conns ? conns->sslname : NULL;
}

sxc_client_t *sxi_conns_get_client(sxi_conns_t *conns) {
    return conns ? conns->sx : NULL;
}

curl_events_t *sxi_conns_get_curlev(sxi_conns_t *conns) {
    return conns ? conns->curlev : NULL;
}

time_t sxi_conns_get_timediff(const sxi_conns_t *conns) {
    return conns ? conns->timediff : 0;
}
void sxi_conns_set_timediff(sxi_conns_t *conns, time_t timediff) {
    if(conns && !conns->no_clock_adjust)
	conns->timediff = timediff;
}

void sxi_conns_set_cafile(sxi_conns_t *conns, const char *cafile) {
    if(!conns)
	return;
    if(cafile) {
	conns->insecure = 0;
	sxi_curlev_set_cafile(conns->curlev, cafile);
    } else {
	conns->insecure = 1;
	sxi_curlev_set_cafile(conns->curlev, NULL);
    }
}

const char *sxi_conns_get_cafile(sxi_conns_t *conns) {
    return sxi_curlev_get_cafile(conns->curlev);
}

int sxi_conns_is_secure(sxi_conns_t *conns) {
    return conns && !conns->insecure;
}

int sxi_conns_set_uuid(sxi_conns_t *conns, const char *uuid) {
    char *id;

    if(!uuid || !*uuid) { /* FIXME: check for valid guid */
	CLSTDEBUG("called with NULL/empty uuid");
	conns_err(SXE_EARG, "Cannot set cluster uuid: Invalid argument");
	return 1;
    }
    if(!(id = strdup(uuid))) {
	CLSTDEBUG("failed to duplicate %s", uuid);
	conns_err(SXE_EMEM, "Cannot set cluster uuid: Out of memory");
	return 1;
    }
    free(conns->uuid);
    conns->uuid = id;
    return 0;
}

const char *sxi_conns_get_uuid(const sxi_conns_t *conns) {
    return conns ? conns->uuid : NULL;
}

void sxi_conns_remove_uuid(sxi_conns_t *conns)
{
    free(conns->uuid);
    conns->uuid = NULL;
}

int sxi_conns_set_auth(sxi_conns_t *conns, const char *token) {
    char *tok;
    if(!sxi_is_valid_authtoken(conns->sx, token)) {
	CLSTDEBUG("failed to set auth to %s", token ? token : "(null token)");
	conns_err(SXE_EARG, "Cannot setup cluster authentication: Invalid authentication token");
	return 1;
    }
    if(!(tok = strdup(token))) {
	CLSTDEBUG("failed to duplicate %s", tok);
	conns_err(SXE_EMEM, "Cannot setup cluster authentication: Out of memory");
	return 1;
    }
    free(conns->auth_token);
    conns->auth_token = tok;
    return 0;
}

const char *sxi_conns_get_auth(const sxi_conns_t *conns) {
    return conns ? conns->auth_token : NULL;
}

int sxi_conns_set_hostlist(sxi_conns_t *conns, const sxi_hostlist_t *hlist) {
    if(!hlist) {
	CLSTDEBUG("called with NULL list");
	conns_err(SXE_EARG, "Cannot set cluster nodes: Invalid argument");
	return 1;
    }
    sxi_hostlist_empty(&conns->hlist);
    return sxi_hostlist_add_list(conns->sx, &conns->hlist, hlist);
}

sxi_hostlist_t *sxi_conns_get_hostlist(sxi_conns_t *conns) {
    return &conns->hlist;
}

#define ERRFNBUFLEN 1024
static void cb_errfn(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    sxi_strlcpy(ctx, string, MIN(ERRFNBUFLEN, length+1));
}

static void errfn(curlev_context_t *ctx, int reply_code, const char *reason) {
    const struct jparse_actions acts = {
	JPACTS_STRING(JPACT(cb_errfn, JPKEY("ErrorMessage")))
    };
    char errbuf[ERRFNBUFLEN];
    jparse_t *J = sxi_jparse_create(&acts, errbuf, 0);

    errbuf[0] = '\0';

    if(!J) {
	sxi_cbdata_seterr(ctx, SXE_EMEM, "Cluster query failed: Out of memory");
	return;
    }

    if(sxi_jparse_digest(J, reason, strlen(reason)) || sxi_jparse_done(J))
	sxi_cbdata_seterr(ctx, SXE_ECOMM, sxi_jparse_geterr(J));
    else if(*errbuf)
	sxi_cbdata_setclusterr(ctx, NULL, NULL, reply_code, errbuf, NULL);
    else
	sxi_cbdata_seterr(ctx, SXE_ECOMM, "Cluster query failed: No reason provided");

    sxi_jparse_destroy(J);
}

static enum head_result head_cb(curlev_context_t *ctx, long http_status, char *ptr, size_t size, size_t nmemb) {
    size_t vlen = size * nmemb, klen;
    const char *v;
    sxi_conns_t *conns = sxi_cbdata_get_conns(ctx);
    char nstr[16], *eon;
    int nlen;
    long num;

    if(!(v = memchr(ptr, ':', vlen)))
	return HEAD_OK;

    v++;
    klen = v - ((char *)ptr);
    vlen -= klen;
    for(;vlen;v++,vlen--)
	if(!strchr(" \t\r\n", *v))
	    break;
    if(!vlen)
	return HEAD_OK;

    for(;vlen;vlen--)
	if(!strchr(" \t\r\n", v[vlen-1]))
	    break;
    if(!vlen)
	return HEAD_OK;

    if(klen == lenof("Content-Type:") && !strncasecmp(ptr, "Content-Type:", lenof("Content-Type:"))) {
        if(vlen == lenof("application/json") && !strncasecmp(v, "application/json", lenof("application/json")))
            sxi_cbdata_set_content_type(ctx, CONTENT_TYPE_JSON);
    }

    if(klen == lenof("SX-Cluster:") && !strncasecmp(ptr, "SX-Cluster:", lenof("SX-Cluster:"))) {
	char uuid[UUID_LEN+1];
	const char *suuid, *vv;

        vv = memchr(v,' ',vlen);
        if(!vv) {
            sxi_cbdata_seterr(ctx, SXE_ECOMM,"Invalid cluster header (no uuid)");
            return HEAD_FAIL;
        }
	if(!conns->vcheckwarn && !sxi_getenv("SX_DEBUG_NOVERSIONCHECK")) {
	    int badver = 0;
	    nlen = MIN(vv-v, sizeof(nstr) - 1);
	    memcpy(nstr, v, nlen);
	    nstr[nlen] = '\0';
	    num = strtol(nstr, &eon, 10);
	    if(eon == nstr || *eon != '.' || num > SRC_MAJOR_VERSION)
		badver = 1;
	    else if(num == SRC_MAJOR_VERSION) {
		num = strtol(eon+1, &eon, 10);
		if((*eon != '\0' && *eon != '.' && *eon != '-') || num > SRC_MINOR_VERSION + 1)
		    badver = 1;
	    }
	    if(badver) {
		fprintf(stderr, "WARNING: cluster version is much newer; please upgrade your client software (client version %s, server version %.*s)\n", sxc_get_version(), nlen, v);
		conns->vcheckwarn = 1;
	    }
	}
	vlen -= vv -v;
        v = vv + 2;
	if(vlen < UUID_LEN + 1 || v[UUID_LEN] != ')') {
	    sxi_cbdata_seterr(ctx, SXE_ECOMM, "Invalid server UUID");
	    return HEAD_FAIL;
	}

	memcpy(uuid, v, UUID_LEN);
	uuid[UUID_LEN] = '\0';

	v += UUID_LEN + 1;
	vlen -= UUID_LEN + 1;
	if(vlen >= 4 && !strncmp(v, " ssl", 4)) {
	    CLSTDEBUG("Server reports internal communication is secure");
	    conns->internal_security = 1;
	} else {
	    CLSTDEBUG("Server reports internal communication is insecure");
	    conns->internal_security = 0;
	}

	suuid = sxi_conns_get_uuid(conns);
	if(!suuid) {
	    if(sxi_conns_set_uuid(conns, uuid)) {
		CLSTDEBUG("failed to set server name");
		return HEAD_FAIL;
	    }
            return HEAD_SEEN;
	}
	if(strcmp(uuid, suuid)) {
	    CLSTDEBUG("server uuid mismatch (got %s, expected %s)", uuid, suuid);
	    sxi_cbdata_seterr(ctx, SXE_ECOMM, "Server UUID mismatch: Found %s, expected %s", uuid, suuid);
	    return HEAD_FAIL;
	}

        return HEAD_SEEN;
    }

    if(klen == lenof("SX-API-Version:") &&
       !strncasecmp(ptr, "SX-API-Version:", lenof("SX-API-Version:")) &&
       !sxi_getenv("SX_DEBUG_NOVERSIONCHECK")) {
	nlen = MIN(vlen, sizeof(nstr) - 1);
	memcpy(nstr, v, nlen);
	nstr[nlen] = '\0';
	num = strtol(nstr, &eon, 10);
	if(eon == nstr || *eon != '\0' || num > SRC_API_VERSION) {
	    sxi_cbdata_seterr(ctx, SXE_ECOMM, "Unsupported protocol version (client version %u, server version %.*s)", SRC_API_VERSION, nlen, v);
	    return HEAD_FAIL;
	}
    }

    if(klen == lenof("ETag:") &&
       !strncasecmp(ptr, "ETag:", lenof("ETag:"))) {
        sxi_cbdata_set_etag(ctx, v, vlen);
    }

    if(http_status == 401) {
	if(klen == lenof("date:") && !strncasecmp(ptr, "date:", lenof("date:"))) {
	    char datestr[32];
	    time_t mine, their;

	    if(vlen >= sizeof(datestr)) {
		CLSTDEBUG("got bogus date from server");
		sxi_cbdata_seterr(ctx, SXE_ECOMM, "Bad Date from server");
		return HEAD_FAIL;
	    }

	    memcpy(datestr, v, vlen);
	    datestr[vlen] = '\0';

	    mine = time(NULL);
	    if(mine == (time_t) -1) {
		CLSTDEBUG("time query failed");
		sxi_cbdata_seterr(ctx, SXE_ETIME, "Cannot retrieve current time");
		return HEAD_FAIL;
	    }

	    their = curl_getdate(datestr, NULL);
	    if(their == (time_t) -1) {
		CLSTDEBUG("got bogus date from server");
		sxi_cbdata_seterr(ctx, SXE_ECOMM, "Bad Date from server");
		return HEAD_FAIL;
	    }

	    sxi_conns_set_timediff(conns, their - mine);
	    return HEAD_OK;
	}

	if(klen == lenof("WWW-Authenticate:") && !strncasecmp(ptr, "WWW-Authenticate:", lenof("WWW-Authenticate:")) &&
	   vlen == lenof("SKY realm=\"SXCLOCK\"") && !strncasecmp(v, "SKY realm=\"SXCLOCK\"", lenof("SKY realm=\"SXCLOCK\""))) {
	    conns->clock_drifted = 1;
	    return HEAD_OK;
	}
    }

    return HEAD_OK;
}

/*
  FIXME: review possibly useful options like these...

    CURLOPT_INTERFACE;
*/

int sxi_reject_dots(const char *str)
{
    const char *lastslash;
    if (strstr(str, "/../") || strstr(str, "/./"))
        return 1;
    lastslash = strrchr(str, '/');
    if (lastslash)
        lastslash++;
    else
        lastslash = str;
    if (!strcmp(lastslash, "..") || !strcmp(lastslash, "."))
        return 1;
    return 0;
}

int sxi_cluster_query_ev(curlev_context_t *cbdata,
			 sxi_conns_t *conns, const char *host,
			 enum sxi_cluster_verb verb, const char *query,
			 void *content, size_t content_size,
                         ctx_setup_cb_t setup_callback,
			 body_cb_t callback)
{
    sxc_client_t *sx = conns->sx;
    int rc;
    const char *bracket_open, *bracket_close, *qprefix;
    unsigned n;

    if (!cbdata) {
        conns_err(SXE_EARG, "Null cbdata");
        return -1;
    }
    if (!host) {
        sxi_cbdata_seterr(cbdata, SXE_EARG, "Null host");
        return -1;
    }
    if (sxi_is_debug_enabled(conns->sx))
	sxi_curlev_set_verbose(conns->curlev, 1);


    if(!query || !*query || (content_size && !content) || verb < REQ_GET || verb > REQ_DELETE) {
	CLSTDEBUG("called with unexpected NULL or empty arguments");
	sxi_cbdata_seterr(cbdata, SXE_EARG, "Cluster query failed: Invalid argument");
	return -1;
    }
    if (sxi_reject_dots(query)) {
        sxi_cbdata_seterr(cbdata, SXE_EARG, "URL with '.' or '..' is not accepted");
        return -1;
    }

    if(!conns->auth_token) {
	CLSTDEBUG("cluster is not authed");
	sxi_cbdata_seterr(cbdata, SXE_EAUTH, "Cluster query failed: Not authorised");
	return -1;
    }

    qprefix = sxi_get_query_prefix(sx);
    if(!qprefix)
	qprefix = "";

    n = lenof("https://[]:65535") + strlen(host) + 1 + strlen(qprefix) + strlen(query) + 1;
    char *url = malloc(n);
    request_headers_t request = { host, url, conns->port ? conns->port : (conns->insecure ? 80 : 443) };
    reply_t reply = {{ cbdata, head_cb, errfn}, callback};

    if(!url) {
	CLSTDEBUG("OOM allocating request url: %s / %s", host, query);
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cluster query failed: Out of memory");
	return -1;
    }
    bracket_open = strchr(host, ':') ? "[" : "";
    bracket_close = strchr(host, ':') ? "]" : "";
    /* caveats: we loose SNI support when connecting directly to IP */

    if(conns->port)
	snprintf(url, n, "http%s://%s%s%s:%u/%s%s", conns->insecure ? "" : "s", bracket_open, host, bracket_close, conns->port, qprefix, query);
    else
	snprintf(url, n, "http%s://%s%s%s/%s%s", conns->insecure ? "" : "s", bracket_open, host, bracket_close, qprefix, query);
    sxi_cbdata_reset(cbdata);

    if(setup_callback && setup_callback(cbdata, host)) {
        free(url);
        sxi_clear_operation(sx);
        CLSTDEBUG("setup_callback failed");
	return -1;
    }

    switch (verb) {
	case REQ_GET:
	    rc = sxi_curlev_add_get(conns->curlev, &request, &reply);
	    break;
	case REQ_HEAD:
	    rc = sxi_curlev_add_head(conns->curlev, &request, &reply.headers);
	    break;
	case REQ_PUT:
	    {
		request_data_t data = { content, content_size };
		rc = sxi_curlev_add_put(conns->curlev, &request, &data, &reply);
		break;
	    }
	case REQ_DELETE:
	    rc = sxi_curlev_add_delete(conns->curlev, &request, &reply);
	    break;
	default:
	    sxi_cbdata_seterr(cbdata, SXE_EARG, "Unknown verb");
            return -1;
    }

    free(url);
    CLSTDEBUG("returning code %d", rc);
    return rc;
}

void sxi_retry_throttle(sxc_client_t *sx, unsigned retry)
{
    unsigned delays[] = { 10, 22, 70, 262, 1030 }; /* 4*n + 6 */
    unsigned n = sizeof(delays)/sizeof(delays[0]);
    unsigned delay = retry < n ? delays[retry] : delays[n-1];
    SXDEBUG("Retry #%d: sleeping for %dms", retry, delay);
    usleep(delay*1000);
}

struct generic_ctx {
    cluster_setupcb setup_callback;
    cluster_datacb callback;
    void *context;

    /* Hold information about transfer progress */
    sxc_xfer_stat_t *xfer_stat;
    int64_t to_ul;
    int64_t to_dl;
    int64_t ul;
    int64_t dl;
};

static int wrap_setup_callback(curlev_context_t *cbdata, const char *host)
{
    struct generic_ctx *gctx = sxi_cbdata_get_generic_ctx(cbdata);
    if (!gctx || !gctx->setup_callback)
        return 0;
    return gctx->setup_callback(cbdata, gctx->context, host);
}

static int wrap_data_callback(curlev_context_t *cbdata, const unsigned char *data, size_t size)
{
    struct generic_ctx *gctx = sxi_cbdata_get_generic_ctx(cbdata);
    if (!gctx || !gctx->callback)
        return 0;
    return gctx->callback(cbdata, gctx->context, (void*)data, size);
}

/* Set information about current generic transfer */
int sxi_generic_set_xfer_stat(struct generic_ctx *ctx, int64_t downloaded, int64_t to_download, int64_t uploaded, int64_t to_upload) {
    int64_t ul_diff = 0;
    int64_t dl_diff = 0;
    double timediff = 0;
    struct timeval now;

    /* This is not considered as error, ctx or ctx->xfer_stat is NULL if we do not want to check progress */
    if(!ctx || !ctx->xfer_stat)
        return SXE_NOERROR;

    gettimeofday(&now, NULL);
    timediff = sxi_timediff(&now, &ctx->xfer_stat->interval_timer);

    ctx->to_dl = to_download;
    dl_diff = downloaded - ctx->dl;
    ctx->dl = downloaded;

    ctx->to_ul = to_upload;
    ul_diff = uploaded - ctx->ul;
    ctx->ul = uploaded;

    if(dl_diff > 0 || ul_diff > 0 || timediff >= XFER_PROGRESS_INTERVAL)
        return sxi_set_xfer_stat(ctx->xfer_stat, dl_diff, ul_diff, timediff);
    else
        return SXE_NOERROR;
}

/* Get number of bytes to be downloaded for generic transfer context */
int64_t sxi_generic_get_xfer_to_dl(const struct generic_ctx *ctx) {
    return ctx && ctx->xfer_stat ? ctx->to_dl : 0;
}

/* Get number of bytes to be uploaded for generic transfer context */
int64_t sxi_generic_get_xfer_to_ul(const struct generic_ctx *ctx) {
    return ctx && ctx->xfer_stat ? ctx->to_ul : 0;
}

int sxi_cluster_query_track(sxi_conns_t *conns, const sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query,
                            void *content, size_t content_size, cluster_setupcb setup_callback, cluster_datacb callback,
                            void *context, int track_xfer)
{
    unsigned int i, clock_fixed = 0;
    long status = -1;
    unsigned hostcount;
    struct generic_ctx gctx;
    sxi_retry_t *retry;

    if(!hlist)
	    hlist = &conns->hlist;
    hostcount = sxi_hostlist_get_count(hlist);

    if (!hostcount) {
	CLSTDEBUG("called with unexpected NULL or empty arguments");
	conns_err(SXE_EARG, "Cluster query failed: Invalid argument");
	return -1;
    }

    gctx.setup_callback = setup_callback;
    gctx.callback = callback;
    gctx.context = context;
    if(track_xfer)
        gctx.xfer_stat = sxi_conns_get_xfer_stat(conns);
    else
        gctx.xfer_stat = NULL;
    curlev_context_t *cbdata = sxi_cbdata_create_generic(conns, NULL, &gctx);

    if (!cbdata) {
	conns_err(SXE_EMEM, "Cluster query failed: Out of memory allocating context");
	return -1;
    }
    retry = sxi_retry_init(cbdata, RCTX_CBDATA);
    if (!retry) {
        sxi_cbdata_seterr(cbdata, SXE_EMEM, "Could not allocate retry");
        sxi_cbdata_unref(&cbdata);
        return -1;
    }
    for(i=0; i<hostcount; i++) {
	int rc;
	sxi_cbdata_reset(cbdata);

	/* clear errors: we're retrying on next host */
	if (sxi_retry_check(retry, i))
	    break;

	const char *host = sxi_hostlist_get_host(hlist, i);
	sxi_retry_msg(sxi_conns_get_client(conns), retry, host);

	conns->clock_drifted = 0;
	rc = sxi_cluster_query_ev(cbdata, conns, host, verb, query, content, content_size,
				  wrap_setup_callback, wrap_data_callback);
	if (rc == -1)
	    break;

	if (sxi_cbdata_wait(cbdata, conns->curlev, &status))
	    break;

	if(status == 401 && !clock_fixed && conns->clock_drifted) {
	    clock_fixed = 1; /* Only try to fix the clock once per request */
	    i--;
	    sxi_cbdata_clearerr(cbdata);
	    continue;
	}

	/* Break out on success or if the failure is non retriable */
	if((status == 200) || (status == 304) ||
	   (status / 100 == 4 && status != 404 && status != 408 && status != 410 && status != 429))
	    break;
    }

    if(i==hostcount && status != 200)
        CLSTDEBUG("All %d hosts returned failure", sxi_hostlist_get_count(hlist));

    if (sxi_retry_done(&retry) && status == 200) {
        /* error encountered in retry_done, even though status was successful
         * do not change status in other cases, we want to return an actual
         * http status code if we have it on an error */
        status = -1;
    }
    sxi_cbdata_unref(&cbdata);
    return status;
}

int sxi_cluster_query(sxi_conns_t *conns, const sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size, cluster_setupcb setup_callback, cluster_datacb callback, void *context) {
    return sxi_cluster_query_track(conns, hlist, verb, query, content, content_size, setup_callback, callback, context, 0);
}

int sxi_cluster_query_ev_retry(curlev_context_t *cbdata,
                               sxi_conns_t *conns, const sxi_hostlist_t *hlist,
                               enum sxi_cluster_verb verb, const char *query,
                               void *content, size_t content_size,
                               ctx_setup_cb_t setup_callback, body_cb_t callback,
                               struct _sxi_jobs_t *jobs)
{
    if (!cbdata || !conns)
        return -1;
    if(sxi_set_retry_cb(cbdata, hlist, sxi_cluster_query_ev,
                     verb, query, content, content_size, setup_callback, jobs)) {
        sxi_seterr(sxi_conns_get_client(conns), SXE_EARG, "Cannot set retry callback");
        return -1;
    }
    return sxi_cluster_query_ev(cbdata, conns, sxi_hostlist_get_host(hlist, 0), verb, query, content, content_size,
                                setup_callback, callback);
}

int sxi_sha1_calc(const void *salt, unsigned salt_len, const void *buffer, unsigned int len, unsigned char *md)
{
    sxi_md_ctx *ctx = sxi_md_init();
    if (!ctx)
        return -1;
    if (!sxi_sha1_init(ctx)) {
        sxi_md_cleanup(&ctx);
        return 1;
    }

    if(salt && !sxi_sha1_update(ctx, salt, salt_len)) {
        sxi_md_cleanup(&ctx);
	return 1;
    }
    if(!sxi_sha1_update(ctx, buffer, len) || !sxi_sha1_final(ctx, md, NULL)) {
        sxi_md_cleanup(&ctx);
	return 1;
    }
    sxi_md_cleanup(&ctx);
    return 0;
}

int sxi_conns_hashcalc_core(sxc_client_t *sx, const void *salt, unsigned salt_len, const void *buffer, unsigned int len, char *hash)
{
    unsigned char md[SXI_SHA1_BIN_LEN];
    if (sxi_sha1_calc(salt, salt_len, buffer, len, md)) {
        sxi_seterr(sx, SXE_ECRYPT, "Failed to calculate hash");
        return 1;
    }
    sxi_bin2hex(md, sizeof(md), hash);
    return 0;
}

int sxi_conns_hashcalc(sxi_conns_t *conns, const void *buffer, unsigned int len, char *hash) {
    const char *uuid = sxi_conns_get_uuid(conns);
    if(!uuid) {
	CLSTDEBUG("cluster has got no uuid");
	conns_err(SXE_EARG, "Cannot compute hash: No cluster uuid is set");
	return 1;
    }

    return sxi_conns_hashcalc_core(sxi_conns_get_client(conns), uuid, strlen(uuid), buffer, len, hash);
}

static const int timeouts[] = { 3000, 6800, 9000, 10000, 11600, 14800, 20000 };
#define MAX_TIMEOUT_IDX (sizeof(timeouts)/sizeof(*timeouts))
#define INITIAL_TIMEOUT_IDX 3
#define INITIAL_BLACKLIST_INTERVAL 23

struct timeout_data {
    time_t blacklist_expires;
    unsigned int idx;
    unsigned int blacklist_interval, was_blacklisted;
    int last_action;
};


static struct timeout_data *get_timeout_data(sxi_conns_t *conns, const char *host) {
    struct timeout_data *t;

    if(!conns || !conns->timeouts || !host || sxi_ht_get(conns->timeouts, host, strlen(host), (void **)&t))
	return NULL;

    return t;
}

unsigned int sxi_conns_get_timeout(sxi_conns_t *conns, const char *host) {
    struct timeout_data *t = get_timeout_data(conns, host);
    const char *mulstr;
    unsigned int ret;

    if(!t) {
	ret = timeouts[INITIAL_TIMEOUT_IDX];
	CLSTDEBUG("No timeout data for %s, using %u", host, ret);
    } else {
	if(conns->no_blacklisting)
	    return MAX(timeouts[t->idx], timeouts[INITIAL_TIMEOUT_IDX]);
	if(t->blacklist_expires > time(NULL)) {
	    CLSTDEBUG("Host %s is blacklisted", host);
	    t->was_blacklisted = 1;
	    return 1;
	}
	t->was_blacklisted = 0;
	ret = timeouts[t->idx];
	CLSTDEBUG("Timeout for host %s is %u", host, ret);
    }
    if((mulstr = sxi_getenv("SX_DEBUG_TIMEOUT_MULTIPLIER"))) {
	char *eom;
	double mul = strtod(mulstr, &eom);
	if(!mul || *eom)
	    CLSTDEBUG("Ignoring bad SX_DEBUG_TIMEOUT_MULTIPLIER (%s)", mulstr);
	else {
	    ret = mul * (double)ret;
	    CLSTDEBUG("After applying debug multiplier timeout for %s is set at %u", host, ret);
	}
    }
    return ret;
}

int sxi_conns_set_timeout(sxi_conns_t *conns, const char *host, int timeout_action) {
    struct timeout_data *t = get_timeout_data(conns, host);

    if(!conns || !host) {
	CLSTDEBUG("Called with null data");
	return -1;
    }

    if(t) {
	if(timeout_action >= 0) {
	    if(t->idx < MAX_TIMEOUT_IDX - 1) {
		CLSTDEBUG("Increasing timeout for host %s", host);
		t->idx++;
	    } else
		CLSTDEBUG("Not increasing timeout for host %s (already at max)", host);
	    t->blacklist_expires = 0;
	    t->blacklist_interval = INITIAL_BLACKLIST_INTERVAL;
	} else if(!t->was_blacklisted) {
	    if(t->idx > 0) {
		CLSTDEBUG("Decreasing timeout for host %s", host);
		t->idx--;
	    } else
		CLSTDEBUG("Not decreasing timeout for host %s (already at min)", host);
	    if(t->last_action < 0) {
		t->blacklist_expires = time(NULL) + t->blacklist_interval;
		CLSTDEBUG("Already failed host %s is now blacklisted for %u seconds", host, t->blacklist_interval);
		t->blacklist_interval *= 2;
		if(t->blacklist_interval > 10 * 60)
		    t->blacklist_interval = 10 * 60;
	    }
	}

	t->last_action = timeout_action;
	return 0;
    }

    if(!conns->timeouts && !(conns->timeouts = sxi_ht_new(conns->sx, 0)))
	return -1;

    t = malloc(sizeof(*t));
    if(!t)
	return -1;

    t->blacklist_expires = 0;
    t->blacklist_interval = INITIAL_BLACKLIST_INTERVAL;
    if(timeout_action >= 0)
	t->idx = INITIAL_TIMEOUT_IDX + 1;
    else
	t->idx = INITIAL_TIMEOUT_IDX - 1;
    t->last_action = timeout_action;
    t->was_blacklisted = 0;

    if(sxi_ht_add(conns->timeouts, host, strlen(host), t)) {
	free(t);
	return -1;
    }

    CLSTDEBUG("Timeout for host %s initialized to %u", host, timeouts[t->idx]);

    return 0;
}

void sxi_conns_disable_blacklisting(sxi_conns_t *conns) {
    if(conns)
	conns->no_blacklisting = 1;
}

void sxi_conns_disable_clock_adjust(sxi_conns_t *conns) {
    if(conns)
	conns->no_clock_adjust = 1;
}

char *sxi_conns_fetch_sxauthd_credentials(sxi_conns_t *conns, const char *username, const char *pass, const char *unique_name, const char *display_name, int port, int quiet) {
    unsigned int len;
    sxc_client_t *sx;
    char *url, *ret;
    const char *host;
    if(!conns)
        return NULL;
    sx = sxi_conns_get_client(conns);

    if(!username || port < 0 || !pass) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }

    host = sxi_hostlist_get_host(sxi_conns_get_hostlist(conns), 0); /* Fetch only one host for now */
    if(!host) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to fetch sxauthd credentials: NULL host");
        return NULL;
    }
    len = lenof("https://:65535/.auth/api/v1/create") + strlen(host) + 1;
    url = malloc(len);
    if(!url) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    if(port)
        snprintf(url, len, "https://%s:%u/.auth/api/v1/create", host, port);
    else
        snprintf(url, len, "https://%s/.auth/api/v1/create", host);

    ret = sxi_curlev_fetch_sxauthd_credentials(sxi_conns_get_curlev(conns), url, username, pass, unique_name, display_name, quiet);
    free(url);
    return ret;
}

int sxi_conns_root_noauth(sxi_conns_t *conns, const char *tmpcafile, int quiet)
{
    unsigned i, hostcount, n;
    int rc;
    const char *bracket_open, *bracket_close;
    const char *query = "";
    char *url;
    if (sxi_is_debug_enabled(conns->sx))
	sxi_curlev_set_verbose(conns->curlev, 1);
    hostcount = sxi_hostlist_get_count(&conns->hlist);
    if (!hostcount) {
        conns_err(SXE_EARG, "Cannot fetch cluster CA certificate: No node found%s in local cache",
                    sxi_conns_get_dnsname(conns) ? " via dns resolution nor" : "");
	CLSTDEBUG("called with empty hostlist");
	return -1;
    }
    if (tmpcafile && sxi_curlev_set_save_rootCA(sxi_conns_get_curlev(conns), tmpcafile, quiet)) {
        conns_err(SXE_EMEM, "Cannot store CA filename");
        return 1;
    }

    for(i=0; i<hostcount; i++) {
        const char *host = sxi_hostlist_get_host(&conns->hlist, i);
        bracket_open = strchr(host, ':') ? "[" : "";
        bracket_close = strchr(host, ':') ? "]" : "";
        n = lenof("https://[]:65535") + strlen(host) + 1 + strlen(query) + 1;

        sxc_clearerr(conns->sx);/* clear errors: we're retrying on next host */
        url = malloc(n);
        if(!url) {
            conns_err(SXE_EMEM, "OOM allocating URL");
            return -1;
        }
	if(!quiet)
	    sxi_notice(sxi_conns_get_client(conns), "Connecting to %s", host);
	if(conns->port)
	    snprintf(url, n, "https://%s%s%s:%u/%s", bracket_open, host, bracket_close, conns->port, query);
	else
	    snprintf(url, n, "https://%s%s%s/%s", bracket_open, host, bracket_close, query);
        rc = sxi_curlev_fetch_certificates(conns->curlev, url, quiet);
        free(url);
        if (rc == CURLE_SSL_CACERT || sxi_curlev_is_cert_rejected(conns->curlev))
            return 1;
        if (sxi_curlev_is_cert_saved(conns->curlev))
            return 0;
        if (hostcount > 1 && sxc_geterrnum(conns->sx) != SXE_NOERROR)
            sxi_notice(conns->sx, "%s", sxc_geterrmsg(conns->sx));
    }
    return 1;
}

int sxi_conns_disable_proxy(sxi_conns_t *conns)
{
    if (!conns)
        return -1;
    return sxi_curlev_disable_proxy(conns->curlev);
}

int sxi_conns_set_port(sxi_conns_t *conns, unsigned int port) {
    if(!conns || (port & 0xffff0000))
	return -1;

    conns->port = port;
    return 0;
}

unsigned int sxi_conns_get_port(const sxi_conns_t *conns) {
    if(!conns)
	return 0;

    return conns->port;
}

int sxi_conns_set_bandwidth_limit(sxi_conns_t *conns, int64_t bandwidth_limit) {
    if(!conns || !conns->curlev) {
        CLSTDEBUG("Could not set bandwidth limit to %ld, NULL argument: %s", bandwidth_limit, 
            (conns != NULL ? "conns" : "conns->curlev"));
        return 1;
    }

    return sxi_curlev_set_bandwidth_limit(conns->curlev, bandwidth_limit, 0);
}

int64_t sxi_conns_get_bandwidth_limit(const sxi_conns_t *conns) {
    if(!conns || !conns->curlev) {
        CLSTDEBUG("Could not bandwidth limit, NULL argument: %s", (conns != NULL ? "conns->curlev" : "conns"));
        return -1;
    }

    return sxi_curlev_get_bandwidth_limit(conns->curlev);
}

int sxi_conns_set_connections_limit(sxi_conns_t *conns, unsigned int max_active, unsigned int max_active_per_host) {
    if(!conns) 
        return 1;

    if(max_active < max_active_per_host) {
        sxi_seterr(conns->sx, SXE_EARG, "Global connections limit must be higher or equal to limit for host");
        return 1;
    }

    return sxi_curlev_set_conns_limit(conns->curlev, max_active, max_active_per_host);
}

/* Set progress statistics information */
int sxi_conns_set_xfer_stat(sxi_conns_t *conns, sxc_xfer_stat_t *xfer_stat) {
    if(!conns)
        return 1;

    conns->xfer_stat = xfer_stat;
    return 0;
}

/* Retrieve progress statistics information */
sxc_xfer_stat_t *sxi_conns_get_xfer_stat(const sxi_conns_t *conns) {
    return conns ? conns->xfer_stat : NULL;
}

int sxi_conns_internally_secure(sxi_conns_t *conns) {
    if(!conns)
	return -1;
    return conns->internal_security != 0;
}

int sxi_conns_set_timeouts(sxi_conns_t *conns, unsigned int hard_timeout, unsigned int soft_timeout) {
    if(!conns)
        return -1;
    if(hard_timeout && soft_timeout && soft_timeout > hard_timeout) {
        sxi_seterr(sxi_conns_get_client(conns), SXE_EARG, "Invalid argument: hard timeout cannot be lower than soft timeout");
        return 1;
    }
    conns->hard_timeout = hard_timeout;
    conns->soft_timeout = soft_timeout;
    return 0;
}

int sxi_conns_get_timeouts(sxi_conns_t *conns, unsigned int *hard_timeout, unsigned int *soft_timeout) {
    if(!conns)
        return -1;
    if(hard_timeout)
        *hard_timeout = conns->hard_timeout;
    if(soft_timeout)
        *soft_timeout = conns->soft_timeout;
    return 0;
}
