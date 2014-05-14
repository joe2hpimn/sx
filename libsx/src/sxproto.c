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
#include <string.h>
#include <stdlib.h>

#include "libsx-int.h"
#include "sxproto.h"
#include "misc.h"

void sxi_query_free(sxi_query_t *query)
{
    if (query) {
        free(query->path);
        free(query->content);
        free(query);
    }
}

static int sxi_query_realloc(sxc_client_t *sx, sxi_query_t *query, unsigned len)
{
    if (len > query->content_allocated) {
        query->content_allocated = (len + 4095) & ~4095;
        query->content = sxi_realloc(sx, query->content, query->content_allocated);
        if (!query->content) {
            query->content_len = query->content_allocated = 0;
            return -1;
        }
    }
    return 0;
}

static FMT_PRINTF(4, 5) sxi_query_t* sxi_query_append_fmt(sxc_client_t *sx, sxi_query_t *query, unsigned n, const char *fmt, ...)
{
    int rc;
    va_list ap;
    if (!query) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_query_append");
        return NULL;
    }
    if (sxi_query_realloc(sx, query, query->content_len + n + 1) == -1) {
        sxi_query_free(query);
        return NULL;
    }
    va_start(ap, fmt);
    rc = vsnprintf((char*)query->content + query->content_len, n + 1, fmt, ap);
    va_end(ap);
    if (rc < 0 || rc > n) {
        sxi_seterr(sx, SXE_EARG, "Failed to allocate query: format string overflow (%d -> %d) %s", n, rc, fmt);
        sxi_query_free(query);
        return NULL;
    }
    query->content_len += rc;
    return query;
}

static sxi_query_t *sxi_query_create(sxc_client_t *sx, const char *path, enum sxi_cluster_verb verb)
{
    sxi_query_t *ret = calloc(1, sizeof(*ret));
    if (ret) {
        ret->verb = verb;
        ret->path = strdup(path);
        if (ret->path)
            return ret;
    }
    sxi_setsyserr(sx, SXE_EMEM, "Failed to allocate query");
    sxi_query_free(ret);
    return NULL;
}

/* also closes outer json object */
static int sxi_query_add_meta(sxc_client_t *sx, sxi_query_t *query, const char *field, sxc_meta_t *metadata)
{
    unsigned int i, nmeta;
    const char *key;
    const void *value;
    unsigned int value_len;

    nmeta = sxc_meta_count(metadata);

    if (!query) {
        sxi_seterr(sx, SXE_EARG, "Null arg passed to sxi_add_meta");
        return -1;
    }
    if (nmeta) {
        if (!(query = sxi_query_append_fmt(sx, query, strlen(field)+5, ",\"%s\":{", field)))
            return -1;
    }

    for(i=0; i<nmeta; i++) {
        char *quoted, *hex;
	if(sxc_meta_getkeyval(metadata, i, &key, &value, &value_len))
	    return -1;
        if(sxi_utf8_validate(key)) {
            SXDEBUG("key is not valid utf8");
            sxi_seterr(sx, SXE_EARG, "Invalid metadata");
            return -1;
        }
        quoted = sxi_json_quote_string(key);
        if (!quoted)
            return -1;
        query = sxi_query_append_fmt(sx, query, strlen(quoted)+2, "%s:\"", quoted);
        free(quoted);
        if (!query)
            return -1;
        hex = malloc(2 * value_len + 1);
        if (!hex) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory allocating meta value hex");
            return -1;
        }
        sxi_bin2hex(value, value_len, hex);
        query = sxi_query_append_fmt(sx, query, 2*value_len + 2,
                                    "%s\"%s", hex, i < nmeta-1 ? "," : "");

        free(hex);
        if (!query)
            return -1;
    }
    if (!(query = sxi_query_append_fmt(sx, query, 2, nmeta ? "}}" : "}")))
        return -1;
    query->content_len = strlen(query->content);
    return 0;
}

sxi_query_t *sxi_useradd_proto(sxc_client_t *sx, const char *username, const uint8_t *key, int admin) {
    char *qname, hexkey[AUTH_KEY_LEN*2+1];
    sxi_query_t *ret;
    unsigned n;

    qname = sxi_json_quote_string(username);
    if(!qname)
	return NULL;

    n = sizeof("{\"userName\":,\"userType\":\"normal\",\"userKey\":\"\"}") + /* the json body with terminator */
	strlen(qname) + /* the json encoded username with quotes */
	AUTH_KEY_LEN * 2 /* the hex encoded key without quotes */;
    sxi_bin2hex(key, AUTH_KEY_LEN, hexkey);
    ret = sxi_query_create(sx, ".users", REQ_PUT);
    if (ret)
        ret = sxi_query_append_fmt(sx, ret, n, "{\"userName\":%s,\"userType\":\"%s\",\"userKey\":\"%s\"}", qname, admin ? "admin" : "normal", hexkey);

    free(qname);
    return ret;
}

sxi_query_t *sxi_volumeadd_proto(sxc_client_t *sx, const char *volname, const char *owner, int64_t size, unsigned int replica, sxc_meta_t *metadata) {
    unsigned int tlen;
    char *url, *qowner;
    sxi_query_t *ret;

    url = sxi_urlencode(sx, volname, 0);
    if(!url)
	return NULL;

    qowner = sxi_json_quote_string(owner);
    if(!qowner) {
	sxi_seterr(sx, SXE_EMEM, "Failed to quote username: out of memory");
	free(url);
	return NULL;
    }

    ret = sxi_query_create(sx, url, REQ_PUT);
    free(url);
    if (ret) {
        tlen = lenof("{\"volumeSize\":,\"replicaCount\":,\"owner\":,\"volumeMeta\":{}}") + strlen(qowner) + 128; /* content */
        ret = sxi_query_append_fmt(sx, ret, tlen, "{\"volumeSize\":%lld,\"owner\":%s,\"replicaCount\":%u",
                                   (long long)size, qowner, replica);
    }
    free(qowner);
    if (sxi_query_add_meta(sx, ret, "volumeMeta", metadata) == -1) {
        sxi_query_free(ret);
        return NULL;
    }
    return ret;
}

sxi_query_t *sxi_flushfile_proto(sxc_client_t *sx, const char *token) {
    char *url = malloc(sizeof(".upload/") + strlen(token));
    sxi_query_t *ret;

    if(!url) {
	sxi_seterr(sx, SXE_EMEM, "Failed to generate query: out of memory");
	return NULL;
    }

    sprintf(url, ".upload/%s", token);
    ret = sxi_query_create(sx, url, REQ_PUT);
    free(url);
    return ret;
}

sxi_query_t *sxi_fileadd_proto_begin(sxc_client_t *sx, const char *volname, const char *path, const char *revision, int64_t pos, int64_t blocksize, int64_t size) {
    char *enc_vol = NULL, *enc_path = NULL, *enc_rev = NULL, *url = NULL;
    sxi_query_t *ret;

    enc_vol = sxi_urlencode(sx, volname, 0);
    enc_path = sxi_urlencode(sx, path, 0);
    enc_rev = revision ? sxi_urlencode(sx, revision, 1) : "";
    if(enc_vol && enc_path && enc_rev && 
       (url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + lenof("?rev=") + strlen(enc_rev) + 1))) {
	if(revision)
	    sprintf(url, "%s/%s?rev=%s", enc_vol, enc_path, enc_rev);
	else
	    sprintf(url, "%s/%s", enc_vol, enc_path);
    }
    free(enc_vol);
    free(enc_path);
    if(revision)
	free(enc_rev);
    if(!url) {
	sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate URL");
        return NULL;
    }

    ret = sxi_query_create(sx, url, REQ_PUT);
    free(url);
    if (!ret)
        return NULL;

    if (pos > 0)
        ret = sxi_query_append_fmt(sx, ret, 34, "{\"extendSeq\":%llu,", (unsigned long long)pos / blocksize);
    else
        ret = sxi_query_append_fmt(sx, ret, 34, "{\"fileSize\":%llu,", (unsigned long long)size);

    if (!ret)
        return NULL;

    return sxi_query_append_fmt(sx, ret, lenof("\"fileData\":["), "\"fileData\":[");
}

sxi_query_t *sxi_fileadd_proto_addhash(sxc_client_t *sx, sxi_query_t *query, const char *hexhash)
{
    if (!query) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_file_proto_end");
        return NULL;
    }
    query = sxi_query_append_fmt(sx, query, strlen(hexhash) + 3, "%s\"%s\"",
                             query->comma ? "," : "", hexhash);
    if (!query)
        return NULL;
    query->comma = 1;
    return query;
}

sxi_query_t *sxi_fileadd_proto_end(sxc_client_t *sx, sxi_query_t *query, sxc_meta_t *metadata)
{
    if (!query) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_file_proto_end");
        return NULL;
    }
    query = sxi_query_append_fmt(sx, query, 1, "]");
    if (!query)
        return NULL;
    if (sxi_query_add_meta(sx, query, "fileMeta", metadata) == -1) {
        sxi_query_free(query);
        return NULL;
    }
    return query;
}


sxi_query_t *sxi_filedel_proto(sxc_client_t *sx, const char *volname, const char *path, const char *revision) {
    char *enc_vol = NULL, *enc_path = NULL, *enc_rev = NULL, *url = NULL;
    sxi_query_t *ret;

    enc_vol = sxi_urlencode(sx, volname, 0);
    enc_path = sxi_urlencode(sx, path, 0);

    if(!enc_vol || !enc_path) {
	free(enc_vol);
	free(enc_path);
	sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: out of memory");
	return NULL;
    }

    if(revision) {
	enc_rev = sxi_urlencode(sx, revision, 1);
	if(enc_rev && (url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + lenof("?rev=") + strlen(enc_rev) + 1)))
	    sprintf(url, "%s/%s?rev=%s", enc_vol, enc_path, enc_rev);
    } else if((url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + 1)))
	sprintf(url, "%s/%s", enc_vol, enc_path);

    if(!url) {
	sxi_setsyserr(sx, SXE_EMEM, "Failed to generate query: out of memory");
	ret = NULL;
    } else
	ret = sxi_query_create(sx, url, REQ_DELETE);
    free(enc_vol);
    free(enc_path);
    free(enc_rev);
    free(url);
    return ret;
}

sxi_query_t *sxi_hashop_proto(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len, enum sxi_hashop_kind kind, const char *id)
{
    char url[DOWNLOAD_MAX_BLOCKS * (EXPIRE_TEXT_LEN + SXI_SHA1_TEXT_LEN) + sizeof(".data/1048576/?o=reserve&id=") + 64];
    enum sxi_cluster_verb verb;
    int rc;

    if (!sx)
        return NULL;

    if (!hashes) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_hashop_proto");
        return NULL;
    }
    switch (kind) {
        case HASHOP_INUSE:
            verb = REQ_PUT;
            if (!id) {
                sxi_seterr(sx, SXE_EARG, "Null id");
                return NULL;
            }
            rc = snprintf(url, sizeof(url), ".data/%u/%.*s?o=inuse&id=%s", blocksize, hashes_len, hashes, id);
            break;
        case HASHOP_RESERVE:
            verb = REQ_PUT;
            if (!id) {
                sxi_seterr(sx, SXE_EARG, "Null id");
                return NULL;
            }
            rc = snprintf(url, sizeof(url), ".data/%u/%.*s?o=reserve&id=%s", blocksize, hashes_len, hashes, id);
            break;
        case HASHOP_CHECK:
            verb = REQ_PUT;
            rc = snprintf(url, sizeof(url), ".data/%u/%.*s?o=check", blocksize, hashes_len, hashes);
            break;
        case HASHOP_DELETE:
            verb = REQ_DELETE;
            if (!id) {
                sxi_seterr(sx, SXE_EARG, "Null id");
                return NULL;
            }
            rc = snprintf(url, sizeof(url), ".data/%u/%.*s?id=%s", blocksize, hashes_len, hashes, id);
            break;
        default:
            sxi_seterr(sx, SXE_EARG, "Unknown hashop");
            return NULL;
    }

    if (rc < 0 || rc >= sizeof(url)) {
        sxi_seterr(sx, SXE_EARG, "Failed to build hashop url: URL too long");
        return NULL;
    }

    return sxi_query_create(sx, url, verb);
}


sxi_query_t *sxi_nodeinit_proto(sxc_client_t *sx, const char *cluster_name, const char *node_uuid, uint16_t http_port, int ssl_flag, const char *ssl_file) {
    char *ca_data = NULL, *name = NULL, *node = NULL;
    sxi_query_t *ret;
    unsigned int n;

    if(ssl_flag && ssl_file && *ssl_file) {
	FILE *f = fopen(ssl_file, "r");
	unsigned int ca_alloc_sz = 0, ca_data_len = 0;
	char *ca_tmp_data = NULL;

	if(!f) {
	    sxi_seterr(sx, SXE_EARG, "Failed to open ssl file");
	    return NULL;
	}
	while(!feof(f)) {
	    if(ca_data_len + 1024 > ca_alloc_sz) {
		ca_alloc_sz += 1024;
		ca_tmp_data = sxi_realloc(sx, ca_tmp_data, ca_alloc_sz + 1);
		if(!ca_tmp_data) {
		    fclose(f);
		    return NULL;
		}
	    }
	    ca_data_len += fread(ca_tmp_data + ca_data_len, 1, ca_alloc_sz - ca_data_len, f);
	    if(ferror(f)) {
		free(ca_tmp_data);
		sxi_setsyserr(sx, SXE_EREAD, "Failed to read ssl file");
		return NULL;
	    }
	}
	if(!ca_tmp_data) /* shut up clang */
	    return NULL;
        ca_tmp_data[ca_data_len] = '\0';
	ca_data = sxi_json_quote_string(ca_tmp_data);
	free(ca_tmp_data);
	if(!ca_data) {
	    sxi_seterr(sx, SXE_EARG, "Failed to encode ssl file");
	    return NULL;
	}
    }

    name = sxi_json_quote_string(cluster_name);
    node = sxi_json_quote_string(node_uuid);
    if(!name || !node) {
	free(ca_data);
	free(name);
	free(node);
	return NULL;
    }

    n = sizeof("{\"clusterName\":,\"nodeUUID\":,\"httpPort\":65535,\"secureProtocol\":false,\"caCertData\":\"\"}") +
	strlen(name) +
	strlen(node);
    if(ca_data)
	n += strlen(ca_data);
    ret = sxi_query_create(sx, ".node", REQ_PUT);
    if(ret) {
	if(http_port)
	    ret = sxi_query_append_fmt(sx, ret, n, "{\"clusterName\":%s,\"nodeUUID\":%s,\"httpPort\":%u,\"secureProtocol\":%s,\"caCertData\":%s}", name, node, http_port, ssl_flag ? "true" : "false", ca_data ? ca_data : "\"\"");
	else
	    ret = sxi_query_append_fmt(sx, ret, n, "{\"clusterName\":%s,\"nodeUUID\":%s,\"secureProtocol\":%s,\"caCertData\":%s}", name, node, ssl_flag ? "true" : "false", ca_data ? ca_data : "\"\"");
    }

    free(ca_data);
    free(name);
    free(node);

    return ret;
}

sxi_query_t *sxi_distribution_proto(sxc_client_t *sx, const void *cfg, unsigned int cfg_len) {
    char *hexcfg = NULL;
    sxi_query_t *ret;
    unsigned int n;

    if(!sx || !cfg || !cfg_len)
	return 0;

    hexcfg = malloc(cfg_len * 2 + 1);
    if(!hexcfg)
	return NULL;

    sxi_bin2hex(cfg, cfg_len, hexcfg);

    n = sizeof("{\"newDistribution\":\"\"}") + cfg_len * 2;
    ret = sxi_query_create(sx, ".dist", REQ_PUT);
    if(ret)
	ret = sxi_query_append_fmt(sx, ret, n, "{\"newDistribution\":\"%s\"}", hexcfg);

    free(hexcfg);
    return ret;
}

static sxi_query_t *sxi_volumeacl_loop(sxc_client_t *sx, sxi_query_t *query,
                                       const char *key, acl_cb_t cb, void *ctx)
{
    const char *user;
    sxi_query_append_fmt(sx, query, strlen(key)+5,"%s\"%s\":[",
                         query->comma ? "," : "",
                         key);
    query->comma=0;
    while ((user = cb(ctx))) {
        char *qname = sxi_json_quote_string(user);
        query = sxi_query_append_fmt(sx, query, strlen(qname)+1,"%s%s",
                                     query->comma ? "," : "",
                                     qname);
        free(qname);
        query->comma = 1;
    }
    sxi_query_append_fmt(sx, query, 1, "]");
    query->comma=1;
    return query;
}

sxi_query_t *sxi_volumeacl_proto(sxc_client_t *sx, const char *volname,
                                 acl_cb_t grant_read, acl_cb_t grant_write,
                                 acl_cb_t revoke_read, acl_cb_t revoke_write,
                                 void *ctx)
{
    sxi_query_t *ret;
    unsigned n = strlen(volname) + sizeof("?o=acl");
    char *enc_vol;
    char *url = malloc(n);

    if (!url) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate url");
        return NULL;
    }

    enc_vol = sxi_urlencode(sx, volname, 0);
    if (!enc_vol) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate encoded url");
        free(url);
        return NULL;
    }
    snprintf(url, n, "%s?o=acl", enc_vol);
    free(enc_vol);
    ret = sxi_query_create(sx, url, REQ_PUT);
    ret = sxi_query_append_fmt(sx, ret, 1, "{");
    ret = sxi_volumeacl_loop(sx, ret, "grant-read", grant_read, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "grant-write", grant_write, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "revoke-read", revoke_read, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "revoke-write", revoke_write, ctx);
    ret = sxi_query_append_fmt(sx, ret, 1, "}");
    SXDEBUG("acl query: '%.*s'", ret->content_len, (const char*)ret->content);
    free(url);
    return ret;
}

