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
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "libsx-int.h"
#include "yajlwrap.h"
#include "cluster.h"
#include "curlevents.h"
#include "curlevents-detail.h"
#include "misc.h"

#define CLSTDEBUG(...) do{ sxc_client_t *sx; if(conns && (sx = conns->sx)) SXDEBUG(__VA_ARGS__); } while(0)
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
    int insecure;
};

sxi_conns_t *sxi_conns_new(sxc_client_t *sx) {
    sxi_conns_t *conns = calloc(1, sizeof(*conns));
    if(!conns) {
	SXDEBUG("OOM allocating conns");
	sxi_seterr(sx, SXE_EMEM, "Failed to create conns: out of memory");
	return NULL;
    }
    conns->sx = sx;
    conns->curlev = sxi_curlev_init(conns);
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
	    conns_err(SXE_EMEM, "Cannot set cluster dnsname: out of memory");
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
	    conns_err(SXE_EMEM, "Cannot set cluster sslname: out of memory");
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
    if(conns)
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

int sxi_conns_is_secure(sxi_conns_t *conns) {
    return conns && !conns->insecure;
}

int sxi_conns_set_uuid(sxi_conns_t *conns, const char *uuid) {
    char *id;

    if(!uuid || !*uuid) { /* FIXME: check for valid guid */
	CLSTDEBUG("called with NULL/empty uuid");
	conns_err(SXE_EARG, "Cannot set cluster uuid: invalid argument");
	return 1;
    }
    if(!(id = strdup(uuid))) {
	CLSTDEBUG("failed to duplicate %s", uuid);
	conns_err(SXE_EMEM, "Cannot set cluster uuid: out of memory");
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
	conns_err(SXE_EARG, "Cannot setup cluster authentication: invalid authentication token");
	return 1;
    }
    if(!(tok = strdup(token))) {
	CLSTDEBUG("failed to duplicate %s", tok);
	conns_err(SXE_EMEM, "Cannot setup cluster authentication: out of memory");
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
	conns_err(SXE_EARG, "Cannot set cluster nodes: invalid argument");
	return 1;
    }
    sxi_hostlist_empty(&conns->hlist);
    return sxi_hostlist_add_list(conns->sx, &conns->hlist, hlist);
}

sxi_hostlist_t *sxi_conns_get_hostlist(sxi_conns_t *conns) {
    return &conns->hlist;
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



#define real_str(x) #x
#define str(x) real_str(x)
#define set_copt(opt, val)						\
    do {								\
	int cerr;								\
	if((cerr = curl_easy_setopt(conns->C, opt, val)) != CURLE_OK) { \
	    CLSTDEBUG("failed to set curl opt %s: %s\n", str(opt), curl_easy_strerror(cerr)); \
	    conns_err(SXE_ECURL, "Failed to set cluster query parameter: refused by library"); \
	    goto cluster_query_fail; \
	} \
    } while(0)


static void finishfn(curlev_context_t *cbdata)
{
    sxi_conns_t *conns = cbdata->conns;
    cbdata->finished = 1;

    if (cbdata->rc != CURLE_OK) {
	CLSTDEBUG("curl perform failed: %s, %s", curl_easy_strerror(cbdata->rc), cbdata->errbuf);
	if(cbdata->rc != CURLE_WRITE_ERROR) {
           const char *msg = *cbdata->errbuf ? cbdata->errbuf : curl_easy_strerror(cbdata->rc);
           if (cbdata->rc == CURLE_SSL_CACERT && sxi_curlev_has_cafile(conns->curlev)) {
               conns_err(SXE_ECURL, "%s: possible MITM attack: run sxinit again!",
                         curl_easy_strerror(cbdata->rc));
           }
           else
               conns_err(SXE_ECURL, "%s: %s",
                         cbdata->url ? cbdata->url : "", msg);
        }
    }
    if(cbdata->rc == CURLE_OK && cbdata->reply_status / 100 != 2) {
        if(cbdata->reply_status == 429) {
            CLSTDEBUG("throttle 429 received");
            /* we are throttled, poll for pending jobs now... */
            if (cbdata->jobs && cbdata->jobs->jobs && cbdata->jobs->n) {
                CLSTDEBUG("server has throttled us ... polling for jobs");
                int ret = sxi_job_wait(cbdata->conns, cbdata->jobs, NULL);
                /* TODO: handle ret, but we probably want to just continue and
                 * upload/download what we can */
                CLSTDEBUG("throttle wait finished");
                /* TODO: retry on next replica, and then once more on first */
            }
            conns_err(SXE_ECOMM, "Throttled by cluster: too many requests");
        } else if(cbdata->reply_status > 0 && cbdata->reason) {
	    struct cb_error_ctx yctx;
            yajl_callbacks yacb;
            ya_error_parser(&yacb);
	    yajl_handle yh = yajl_alloc(&yacb, NULL, &yctx);
	    if(yh) {
		memset(&yctx, 0, sizeof(yctx));
                yctx.status = cbdata->reply_status;
                yctx.sx = conns->sx;
		if(yajl_parse(yh, (uint8_t *)cbdata->reason, cbdata->reasonsz) != yajl_status_ok || yajl_complete_parse(yh) != yajl_status_ok)
		    conns_err(SXE_ECOMM, "Cluster query failed with status %ld", cbdata->reply_status);
                /* else: the parser already set the error in sx */
		yajl_free(yh);
	    } else
		conns_err(SXE_EMEM, "Cluster query failed: out of memory");
	} else if(cbdata->reply_status > 0)
	    conns_err(SXE_ECOMM, "Cluster query failed with status %ld", cbdata->reply_status);
    }
    sxi_clear_operation(conns->sx);
    if (cbdata->finish_callback)
	cbdata->finish_callback(cbdata);
}

static size_t headfn(void *ptr, size_t size, size_t nmemb, curlev_context_t *hd) {
    sxi_conns_t *conns = hd->conns;
    size_t vlen = size * nmemb, klen;
    const char *v;

    if(!(v = memchr(ptr, ':', vlen)))
	return nmemb;
    if (!hd->fail && hd->reply_status >= 400)
	hd->fail = 1;

    v++;
    klen = v - ((char *)ptr);
    vlen -= klen;
    for(;vlen;v++,vlen--)
	if(!strchr(" \t\r\n", *v))
	    break;
    if(!vlen)
	return nmemb;

    for(;vlen;vlen--)
	if(!strchr(" \t\r\n", v[vlen-1]))
	    break;
    if(!vlen)
	return nmemb;

    if(klen == lenof("SX-Cluster:") && !strncasecmp(ptr, "SX-Cluster:", lenof("SX-Cluster:"))) {
	char uuid[UUID_LEN+1];
	const char *suuid, *vv;

        vv = memchr(v,' ',vlen);
        if(!vv) {
            conns_err(SXE_ECOMM,"Invalid cluster header (no uuid)");
            return 0;
        }
	if(!getenv("SX_DEBUG_NOVERSIONCHECK")) {
            if (!sxc_compatible_with(conns->sx, v)) {
		conns_err(SXE_ECOMM, "Invalid cluster version (client version %s, server version %.*s)", sxc_get_version(), (int)(vv - v), v);
		return 0;
	    }
	}
	vlen -= vv -v;
        v = vv + 2;
	if(vlen < UUID_LEN + 1 || v[UUID_LEN] != ')') {
	    conns_err(SXE_ECOMM, "Invalid server UUID");
	    return 0;
	}

	memcpy(uuid, v, UUID_LEN);
	uuid[UUID_LEN] = '\0';

	suuid = sxi_conns_get_uuid(conns);
	if(!suuid) {
	    if(sxi_conns_set_uuid(conns, uuid)) {
		CLSTDEBUG("failed to set server name");
		return 0;
	    }
	    hd->cluster_uuid_ok = 1;
	    return nmemb;
	}
	if(strcmp(uuid, suuid)) {
	    CLSTDEBUG("server uuid mismatch (got %s, expected %s)", uuid, suuid);
	    conns_err(SXE_ECOMM, "Server UUID mismatch: found %s, expected %s", uuid, suuid);
	    return 0;
	}
	hd->cluster_uuid_ok = 1;
	return nmemb;
    }

    if(klen == lenof("date:") && !strncasecmp(ptr, "date:", lenof("date:"))) {
	time_t mine = time(NULL), their = curl_getdate(v, NULL);
	if(their == (time_t) -1) {
	    CLSTDEBUG("time query failed");
	    conns_err(SXE_ETIME, "Cannot retrieve current time");
	    return 0;
	}
	sxi_conns_set_timediff(conns, their - mine);
	return nmemb;
    }

    return nmemb;
}

static size_t writefn(char *ptr, size_t size, size_t nmemb, curlev_context_t *wd) {
    sxi_conns_t *conns;

    if(!wd)
	return 0;

    conns = wd->conns;
    size *= nmemb;

    if(!wd->cluster_uuid_ok) {
	if(wd->reply_status == 502 || wd->reply_status == 504) {
	    /* Reply is very likely to come from a busy cluster */
	    conns_err(SXE_ECOMM, "Bad cluster reply(%ld): the cluster may be under maintenance or overloaded, please try again later", wd->reply_status);
	} else if(wd->reply_status == 414) {
	    conns_err(SXE_ECOMM, "URI too long: the path to the requested resource is too long");
	} else {
	    /* Reply is certainly not from sx */
	    conns_err(SXE_ECOMM, "The server contacted is not an SX Cluster node (http status: %ld)", wd->reply_status);
	}
	wd->fail = 1;
    }

    if (!wd->fail && wd->reply_status >= 400)
	wd->fail = 1;
    if(wd->fail) {
	CLSTDEBUG("error reply: %.*s\n", (int)size, (char *)ptr);
	if(conns) {
	    wd->reason = sxi_realloc(conns->sx, wd->reason, size + wd->reasonsz);
	    if(!wd->reason)
		return 0;
	    memcpy(wd->reason + wd->reasonsz, ptr, size);
	    wd->reasonsz += size;
	    return nmemb;
	} else return 0;
    }

    if(!wd->cb)
	return nmemb;

    if(wd->cb(conns, wd->context, ptr, size) == 0)
	return nmemb;

    CLSTDEBUG("failing due to callback failure");
    return 0;
}

/*
  FIXME: review possibly useful options like these...

    CURLOPT_INTERFACE;
    CURLOPT_FOLLOWLOCATION;
    CURLOPT_MAXFILESIZE;
    CURLOPT_MAX_SEND_SPEED_LARGE;
    CURLOPT_MAX_RECV_SPEED_LARGE;
*/


int sxi_cluster_query_ev(curlev_context_t *cbdata,
			 sxi_conns_t *conns, const char *host,
			 enum sxi_cluster_verb verb, const char *query,
			 void *content, size_t content_size,
			 cluster_setupcb setup_callback, cluster_datacb callback,
			 void *context)
{
    sxc_client_t *sx = conns->sx;
    unsigned int keylen;
    const char *verbstr[] = {"GET", "PUT", "HEAD", "DELETE"};
    unsigned char bintoken[AUTHTOK_BIN_LEN];
    char auth[lenof("SKY ") + AUTHTOK_ASCII_LEN + 1], *sendtok;
    HMAC_CTX hmac_ctx;
    int rc;
    const char *bracket_open, *bracket_close;
    char datebuf[32];
    unsigned n;
    header_t headers [] = {
	{"User-Agent", sxi_get_useragent()},
	{"Expect", NULL},
	{"Date", datebuf},
	{"Authorization",auth}
    };

    if (sxi_is_debug_enabled(conns->sx))
	sxi_curlev_set_verbose(conns->curlev, 1);


    memset(auth, 0, sizeof(auth));
    memset(datebuf, 0, sizeof(datebuf));
    if(!query || !*query || (content_size && !content) || verb < REQ_GET || verb > REQ_DELETE) {
	CLSTDEBUG("called with unexpected NULL or empty arguments");
	conns_err(SXE_EARG, "Cluster query failed: invalid argument");
	return -1;
    }

    if(!conns->auth_token) {
	CLSTDEBUG("cluster is not authed");
	conns_err(SXE_EAUTH, "Cluster query failed: not authorised");
	return -1;
    }

    keylen = AUTHTOK_BIN_LEN;
    if(sxi_b64_dec(sx, conns->auth_token, bintoken, &keylen) || keylen != AUTHTOK_BIN_LEN) {
	CLSTDEBUG("failed to decode the auth token");
	conns_err(SXE_EAUTH, "Cluster query failed: invalid authentication token");
	return -1;
    }

    HMAC_CTX_init(&hmac_ctx);
    do {
	rc = -1;

	if(!sxi_hmac_init_ex(&hmac_ctx, bintoken + AUTH_UID_LEN, AUTH_KEY_LEN, EVP_sha1(), NULL)) {
	    CLSTDEBUG("failed to init hmac context");
	    conns_err(SXE_ECRYPT, "Cluster query failed: HMAC calculation failed");
	    break;
	}

	if(!hmac_update_str(sx, &hmac_ctx, verbstr[verb]) || !hmac_update_str(sx, &hmac_ctx, query))
	    break;

	if (compute_date(sx, datebuf, sxi_conns_get_timediff(conns), &hmac_ctx) == -1)
	    break;
	if(content_size) {
	    char content_hash[41];
	    unsigned char d[20];
	    EVP_MD_CTX ch_ctx;

	    if(!EVP_DigestInit(&ch_ctx, EVP_sha1())) {
		CLSTDEBUG("failed to init content digest");
		conns_err(SXE_ECRYPT, "Cannot compute hash: unable to initialize crypto library");
		break;
	    }
	    if(!EVP_DigestUpdate(&ch_ctx, content, content_size) || !EVP_DigestFinal(&ch_ctx, d, NULL)) {
		CLSTDEBUG("failed to update content digest");
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
	    CLSTDEBUG("failed to finalize hmac calculation");
	    conns_err(SXE_ECRYPT, "Cluster query failed: HMAC finalization failed");
	    break;
	}
	rc = 0;
    } while(0);
    HMAC_CTX_cleanup(&hmac_ctx);
    if (rc == -1) {
        sxi_clear_operation(sx);
	return -1;
    }

    if(!(sendtok = sxi_b64_enc(sx, bintoken, AUTHTOK_BIN_LEN))) {
	CLSTDEBUG("failed to encode computed auth token");
        sxi_clear_operation(sx);
	return -1;
    }
    sprintf(auth, "SKY %s", sendtok);
    free(sendtok);

    cbdata->conns = conns;
    cbdata->context = context;
    cbdata->cb = callback;
    cbdata->cluster_uuid_ok = 0;

    n = lenof("https://[]") + strlen(host) + 1 + strlen(query) + 1;
    char *url = malloc(n);
    request_headers_t request = { host, url, headers, sizeof(headers)/sizeof(headers[0]) };
    reply_t reply = {{ cbdata, headfn, finishfn}, writefn};

    if(!url) {
	CLSTDEBUG("OOM allocating request url: %s / %s", host, query);
	conns_err(SXE_EMEM, "Cluster query failed: out of memory");
	return -1;
    }
    bracket_open = strchr(host, ':') ? "[" : "";
    bracket_close = strchr(host, ':') ? "]" : "";
    /* caveats: we loose SNI support when connecting directly to IP */
    snprintf(url, n, "http%s://%s%s%s/%s", conns->insecure ? "" : "s", bracket_open, host, bracket_close, query);
    cbdata->reply_status = -1;

    if(setup_callback && setup_callback(conns, context, host)) {
        free(url);
        sxi_clear_operation(sx);
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
	    conns_err(SXE_EARG, "Unknown verb");
            return -1;
    }

    free(url);
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

int sxi_cluster_query(sxi_conns_t *conns, const sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size, cluster_setupcb setup_callback, cluster_datacb callback, void *context)
{
    unsigned i, ok = 0;
    int rc;
    long status;
    unsigned hostcount;

    if(!hlist)
	    hlist = &conns->hlist;
    hostcount = sxi_hostlist_get_count(hlist);

    if (!hostcount) {
	CLSTDEBUG("called with unexpected NULL or empty arguments");
	conns_err(SXE_EARG, "Cluster query failed: invalid argument");
	return -1;
    }

    curlev_context_t *cbdata = malloc(sizeof(*cbdata));

    if (!cbdata) {
	conns_err(SXE_EMEM, "Cluster query failed: out of memory allocating context");
	return -1;
    }
    rc = 0;
    cbdata->reason = NULL;
    for(i=0; i<hostcount && rc != -1 && !ok; i++) {
            free(cbdata->reason);
            memset(cbdata, 0, sizeof(*cbdata));

            sxc_clearerr(conns->sx);/* clear errors: we're retrying on next host */
            const char *host = sxi_hostlist_get_host(hlist, i);
            rc = sxi_cluster_query_ev(cbdata, conns, host, verb, query, content, content_size,
                                      setup_callback, callback, context);
            while (!cbdata->finished && rc != -1)
                rc = sxi_curlev_poll(conns->curlev);
            if (rc != -1 && cbdata->rc != CURLE_OK) {
                if(cbdata->rc == CURLE_OUT_OF_MEMORY) {
                    conns_err(SXE_ECURL, "Cluster query failed: out of memory in library routine");
                    rc = -1;
                    break;
                }
                continue;
            }
            if(cbdata->reply_status == 404 || cbdata->reply_status == 408
               || cbdata->reply_status == 429
               /*|| cbdata->reply_status == 400 this is not retriable */
               || (cbdata->reply_status / 100 == 5 && cbdata->reply_status != 500))
                continue; /* transient, retriable */
            ok = 1;
    }
    if (!ok && !rc)
        CLSTDEBUG("All %d hosts returned failure",
                  sxi_hostlist_get_count(hlist));
    status = cbdata->rc == CURLE_OK ? cbdata->reply_status : -1;
    free(cbdata->reason);
    free(cbdata);
    return status;
}

static void sxi_retry_callback(curlev_context_t *cbdata)
{
    int ret = -1;
    if (cbdata->rc != CURLE_OK || cbdata->reply_status / 100 != 2) {
        if (++cbdata->hostidx >= sxi_hostlist_get_count(cbdata->hlist)) {
            if (cbdata->retries < 2 || cbdata->reply_status == 429) {
                cbdata->retries++;
                cbdata->hostidx = 0;
                sxi_retry_throttle(cbdata->conns->sx, cbdata->retries);
            }
        }
        const char *host = sxi_hostlist_get_host(cbdata->hlist, cbdata->hostidx);
        free(cbdata->reason);
        cbdata->reason = NULL;
        cbdata->reasonsz = 0;
        cbdata->fail = 0;
        if (host) {
            cbdata->reply_status = -1;
            ret = sxi_cluster_query_ev(cbdata, cbdata->conns, host,
                                       cbdata->verb, cbdata->query, cbdata->content, cbdata->content_size,
                                       cbdata->setup_callback, cbdata->data_callback, cbdata->ctxretry);
        }
        else {
            sxc_client_t *sx = cbdata->conns->sx;
            SXDEBUG("All %d hosts returned failure, retried %d times",
                    sxi_hostlist_get_count(cbdata->hlist),
                    cbdata->retries);
        }
    }
    if (ret == -1) {
        free(cbdata->query);
        if (cbdata->finish_callback_last)
            cbdata->finish_callback_last(cbdata);
    }
}

int sxi_cluster_query_ev_retry(curlev_context_t *cbdata,
                               sxi_conns_t *conns, const sxi_hostlist_t *hlist,
                               enum sxi_cluster_verb verb, const char *query,
                               void *content, size_t content_size,
                               cluster_setupcb setup_callback, cluster_datacb callback,
                               void *context)
{
    if (!cbdata || !conns)
        return -1;
    cbdata->finish_callback_last = cbdata->finish_callback;
    cbdata->finish_callback = sxi_retry_callback;
    cbdata->conns = conns;
    cbdata->hlist = hlist;
    cbdata->verb = verb;
    cbdata->query = strdup(query);
    cbdata->content = content;
    cbdata->content_size = content_size;
    cbdata->setup_callback = setup_callback;
    cbdata->data_callback = callback;
    cbdata->hostidx = 0;
    cbdata->retries = 0;
    cbdata->reasonsz = 0;
    cbdata->ctxretry = context;
    return sxi_cluster_query_ev(cbdata, conns, sxi_hostlist_get_host(hlist, cbdata->hostidx), verb, query, content, content_size,
                                setup_callback, callback, context);
}

int sxi_conns_hashcalc(const sxi_conns_t *conns, const void *buffer, unsigned int len, char *hash) {
    const char *uuid = sxi_conns_get_uuid(conns);
    unsigned char d[20];
    EVP_MD_CTX ctx;

    if(!uuid) {
	CLSTDEBUG("cluster has got no uuid");
	conns_err(SXE_EARG, "Cannot compute hash: no cluster uuid is set");
	return 1;
    }

    if(!EVP_DigestInit(&ctx, EVP_sha1())) {
	CLSTDEBUG("failed to init digest");
	conns_err(SXE_ECRYPT, "Cannot compute hash: unable to initialize crypto library");
	return 1;
    }
    if(!EVP_DigestUpdate(&ctx, uuid, strlen(uuid)) || !EVP_DigestUpdate(&ctx, buffer, len) || !EVP_DigestFinal(&ctx, d, NULL)) {
	CLSTDEBUG("failed to update digest");
	conns_err(SXE_ECRYPT, "Cannot compute hash: crypto library failure");
	EVP_MD_CTX_cleanup(&ctx);
	return 1;
    }
    EVP_MD_CTX_cleanup(&ctx);

    sxi_bin2hex(d, sizeof(d), hash);
    return 0;
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

    if(!t)
	return timeouts[INITIAL_TIMEOUT_IDX];

    if(t->blacklist_expires > time(NULL)) {
	t->was_blacklisted = 1;
	return 1;
    }

    t->was_blacklisted = 0;
    return timeouts[t->idx];
}

int sxi_conns_set_timeout(sxi_conns_t *conns, const char *host, int timeout_action) {
    struct timeout_data *t = get_timeout_data(conns, host);

    if(!conns || !host)
	return -1;

    if(t) {
	if(timeout_action >= 0) {
	    if(t->idx < MAX_TIMEOUT_IDX - 1)
		t->idx++;
	    t->blacklist_expires = 0;
	    t->blacklist_interval = INITIAL_BLACKLIST_INTERVAL;
	} else if(!t->was_blacklisted) {
	    if(t->idx > 0)
		t->idx--;
	    if(t->last_action < 0) {
		t->blacklist_expires = time(NULL) + t->blacklist_interval;
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
    t->idx = INITIAL_TIMEOUT_IDX;
    t->last_action = 1;
    t->was_blacklisted = 0;

    if(sxi_ht_add(conns->timeouts, host, strlen(host), t)) {
	free(t);
	return -1;
    }

    return 0;
}

static size_t noauth_headfn(void *ptr, size_t size, size_t nmemb, curlev_context_t *hd) {
    return nmemb;
}

int sxi_conns_root_noauth(sxi_conns_t *conns, const char *tmpcafile, int quiet)
{
    curlev_context_t cbdata;
    unsigned i, hostcount, n;
    int rc;
    const char *bracket_open, *bracket_close;
    const char *query = "";
    char *url;

    memset(&cbdata, 0, sizeof(cbdata));
    if (sxi_is_debug_enabled(conns->sx))
	sxi_curlev_set_verbose(conns->curlev, 1);
    hostcount = sxi_hostlist_get_count(&conns->hlist);
    if (!hostcount) {
        conns_err(SXE_EARG, "Cannot fetch cluster CA certificate: no node found%s in local cache",
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
        n = lenof("https://[]") + strlen(host) + 1 + strlen(query) + 1;
        url = malloc(n);
        snprintf(url, n, "https://%s%s%s/%s", bracket_open, host, bracket_close, query);
        header_t headers [] = { {"User-Agent", sxi_get_useragent() } };
        request_headers_t request = { host, url, headers, sizeof(headers)/sizeof(headers[0]) };
        reply_t reply = {{ &cbdata, noauth_headfn, finishfn}, NULL};

        free(cbdata.reason);
        memset(&cbdata, 0, sizeof(cbdata));
        cbdata.conns = conns;
        sxc_clearerr(conns->sx);/* clear errors: we're retrying on next host */
        rc = sxi_curlev_add_head(conns->curlev, &request, &reply.headers);
        while (!cbdata.finished && !rc)
            rc = sxi_curlev_poll(conns->curlev);
        free(url);

        if (cbdata.rc == CURLE_SSL_CACERT)
            return 1;
        if (!rc)
            rc = cbdata.rc == CURLE_OK || cbdata.rc == CURLE_WRITE_ERROR ? cbdata.reply_status : -1;
        /* all we wanted is to save the cert, ignore any errors after that */
        if (rc == 200 || sxi_curlev_is_saved(conns->curlev))
            return 0;
    }
    return 1;
}
