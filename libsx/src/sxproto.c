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
#include "vcrypto.h"

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
    if (rc < 0 || rc > (int) n) {
        sxi_seterr(sx, SXE_EARG, "Failed to allocate query: Format string overflow (%d -> %d) %s", n, rc, fmt);
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
static sxi_query_t* sxi_query_add_meta(sxc_client_t *sx, sxi_query_t *query, const char *field, sxc_meta_t *metadata)
{
    unsigned int i, nmeta;
    const char *key;
    const void *value;
    unsigned int value_len;

    nmeta = sxc_meta_count(metadata);

    if (!query) {
        sxi_seterr(sx, SXE_EARG, "Null arg passed to sxi_add_meta");
        sxi_query_free(query);
        return NULL;
    }
    if (nmeta) {
        if (!(query = sxi_query_append_fmt(sx, query, strlen(field)+5, ",\"%s\":{", field)))
            return NULL;
    }

    for(i=0; i<nmeta; i++) {
        char *quoted, *hex;
	if(sxc_meta_getkeyval(metadata, i, &key, &value, &value_len))
            break;
        if(sxi_utf8_validate(key)) {
            SXDEBUG("key is not valid utf8");
            sxi_seterr(sx, SXE_EARG, "Invalid metadata");
            break;
        }
        quoted = sxi_json_quote_string(key);
        if (!quoted)
            break;
        query = sxi_query_append_fmt(sx, query, strlen(quoted)+2, "%s:\"", quoted);
        free(quoted);
        if (!query)
            return NULL;
        hex = malloc(2 * value_len + 1);
        if (!hex) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory allocating meta value hex");
            break;
        }
        sxi_bin2hex(value, value_len, hex);
        query = sxi_query_append_fmt(sx, query, 2*value_len + 2,
                                    "%s\"%s", hex, i < nmeta-1 ? "," : "");

        free(hex);
        if (!query)
            return NULL;
    }
    if (i != nmeta) {
        sxi_query_free(query);
        return NULL;
    }
    if (!(query = sxi_query_append_fmt(sx, query, 2, nmeta ? "}}" : "}")))
        return NULL;
    query->content_len = strlen(query->content);
    return query;
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

sxi_query_t *sxi_usernewkey_proto(sxc_client_t *sx, const char *username, const uint8_t *key) {
    char *qname = NULL, hexkey[AUTH_KEY_LEN*2+1], *query = NULL;
    sxi_query_t *ret = NULL;
    unsigned n;

    do {
        qname = sxi_urlencode(sx, username, 0);
        if(!qname)
            break;
        n = sizeof(".users/") + strlen(qname);
        query = malloc(n);
        if (!query)
            break;
        snprintf(query, n, ".users/%s", qname);
        n = sizeof("{\"userKey\":\"\"}") + /* the json body with terminator */
            AUTH_KEY_LEN * 2 /* the hex encoded key without quotes */;
        sxi_bin2hex(key, AUTH_KEY_LEN, hexkey);
        ret = sxi_query_create(sx, query, REQ_PUT);
        if (ret)
            ret = sxi_query_append_fmt(sx, ret, n, "{\"userKey\":\"%s\"}", hexkey);
    } while(0);
    free(qname);
    free(query);
    return ret;
}

sxi_query_t *sxi_useronoff_proto(sxc_client_t *sx, const char *username, int enable) {
    sxi_query_t *ret = NULL;
    unsigned n;
    char *path = NULL;
    char *query = NULL;

    do {
        path = sxi_urlencode(sx, username, 0);
        if(!path) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory encoding user query");
            break;
        }
        n = lenof(".users/?o=disable") + strlen(path) + 1;
        query = malloc(n);
        if(!query) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory allocating user query");
            break;
        }
        snprintf(query, n, ".users/%s?o=%s", path, enable ? "enable" : "disable");
        ret = sxi_query_create(sx, query, REQ_PUT);
    } while(0);
    free(path);
    free(query);
    return ret;
}

sxi_query_t *sxi_userdel_proto(sxc_client_t *sx, const char *username, const char *newowner) {
    sxi_query_t *ret = NULL;
    unsigned n;
    char *oldusr = sxi_urlencode(sx, username, 0);
    char *newusr = sxi_urlencode(sx, newowner, 0);
    char *query = NULL;

    do {
        if(!oldusr || !newusr) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory encoding user query");
            break;
        }
        n = lenof(".users/?chgto=") + strlen(oldusr) + strlen(newusr) + 1;
        query = malloc(n);
        if(!query) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory allocating user query");
            break;
        }
        snprintf(query, n, ".users/%s?chgto=%s", oldusr, newusr);
        ret = sxi_query_create(sx, query, REQ_DELETE);
    } while(0);
    free(oldusr);
    free(newusr);
    free(query);
    return ret;
}

sxi_query_t *sxi_volumeadd_proto(sxc_client_t *sx, const char *volname, const char *owner, int64_t size, unsigned int replica, unsigned int revisions, sxc_meta_t *metadata) {
    unsigned int tlen;
    char *url, *qowner;
    sxi_query_t *ret;

    url = sxi_urlencode(sx, volname, 0);
    if(!url)
	return NULL;

    qowner = sxi_json_quote_string(owner);
    if(!qowner) {
	sxi_seterr(sx, SXE_EMEM, "Failed to quote username: Out of memory");
	free(url);
	return NULL;
    }

    ret = sxi_query_create(sx, url, REQ_PUT);
    free(url);
    if (ret) {
        tlen = lenof("{\"volumeSize\":,\"replicaCount\":,\"maxRevisions\":,\"owner\":,\"volumeMeta\":{}}") + strlen(qowner) + 128; /* content */
        ret = sxi_query_append_fmt(sx, ret, tlen, "{\"volumeSize\":%lld,\"owner\":%s,\"replicaCount\":%u,\"maxRevisions\":%u",
                                   (long long)size, qowner, replica, revisions);
    }
    free(qowner);
    return sxi_query_add_meta(sx, ret, "volumeMeta", metadata);
}

sxi_query_t *sxi_flushfile_proto(sxc_client_t *sx, const char *token) {
    char *url = malloc(sizeof(".upload/") + strlen(token));
    sxi_query_t *ret;

    if(!url) {
	sxi_seterr(sx, SXE_EMEM, "Failed to generate query: Out of memory");
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
    if(!enc_vol || !enc_path) {
	free(enc_vol);
	free(enc_path);
	sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: Out of memory");
	return NULL;
    }
    if(revision) {
	enc_rev = sxi_urlencode(sx, revision, 1);
	if(!enc_rev) {
	    sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: Out of memory");
	    free(enc_vol);
	    free(enc_path);
	    return NULL;
	}
    }

    if((url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + lenof("?rev=") + strlen(enc_rev ? enc_rev : "") + 1))) {
	if(enc_rev)
	    sprintf(url, "%s/%s?rev=%s", enc_vol, enc_path, enc_rev);
	else
	    sprintf(url, "%s/%s", enc_vol, enc_path);
    }
    free(enc_vol);
    free(enc_path);
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
    return sxi_query_add_meta(sx, query, "fileMeta", metadata);
}


sxi_query_t *sxi_filedel_proto(sxc_client_t *sx, const char *volname, const char *path, const char *revision) {
    char *enc_vol = NULL, *enc_path = NULL, *enc_rev = NULL, *url = NULL;
    sxi_query_t *ret;

    enc_vol = sxi_urlencode(sx, volname, 0);
    enc_path = sxi_urlencode(sx, path, 0);

    if(!enc_vol || !enc_path) {
	free(enc_vol);
	free(enc_path);
	sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: Out of memory");
	return NULL;
    }

    if(revision) {
	enc_rev = sxi_urlencode(sx, revision, 1);
	if(!enc_rev) {
	    sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: Out of memory");
	    free(enc_vol);
	    free(enc_path);
	    return NULL;
	}
    }

    if((url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + lenof("?rev=") + strlen(enc_rev ? enc_rev : "") + 1))) {
	if(enc_rev)
	    sprintf(url, "%s/%s?rev=%s", enc_vol, enc_path, enc_rev);
	else
	    sprintf(url, "%s/%s", enc_vol, enc_path);
    }

    if(!url) {
	sxi_setsyserr(sx, SXE_EMEM, "Failed to generate query: Out of memory");
	ret = NULL;
    } else
	ret = sxi_query_create(sx, url, REQ_DELETE);
    free(enc_vol);
    free(enc_path);
    free(enc_rev);
    free(url);
    return ret;
}

static sxi_query_t *sxi_hashop_proto_list(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len, enum sxi_cluster_verb verb, const char *op, const char *id, uint64_t op_expires_at)
{
    char url[DOWNLOAD_MAX_BLOCKS * (EXPIRE_TEXT_LEN + SXI_SHA1_TEXT_LEN) + sizeof(".data/1048576/?o=reserve&id=") + 64];
    char expires_str[24];
    int rc;

    snprintf(expires_str, sizeof(expires_str), "%llu", (long long)op_expires_at);
    rc = snprintf(url, sizeof(url), ".data/%u/%.*s?%s%s%s%s%s%s", blocksize, hashes_len, hashes,
                  op ? "o=" : "", op ? op : "",
                  id ? op ? "&id=" : "id=" : "", id ? id : "",
                  op_expires_at ? "&op_expires_at=" : "", op_expires_at ? expires_str : "");
    if (rc < 0 || rc >= sizeof(url)) {
        sxi_seterr(sx, SXE_EARG, "Failed to build hashop url: URL too long");
        return NULL;
    }
    return sxi_query_create(sx, url, verb);
}

sxi_query_t *sxi_hashop_proto_check(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len)
{
    return sxi_hashop_proto_list(sx, blocksize, hashes, hashes_len, REQ_GET, "check", NULL, 0);
}

sxi_query_t *sxi_hashop_proto_reserve(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len, const char *id, uint64_t op_expires_at)
{
    if (!id) {
        sxi_seterr(sx, SXE_EARG, "Null id");
        return NULL;
    }
    if (!op_expires_at) {
        sxi_seterr(sx, SXE_EARG, "Missing expires");
        return NULL;
    }
    return sxi_hashop_proto_list(sx, blocksize, hashes, hashes_len, REQ_PUT, "reserve", id, op_expires_at);
}

int sxi_hashop_generate_id(sxc_client_t *sx, hashop_kind_t kind,
                           const void *global, unsigned global_size,
                           const void *local, unsigned local_size, sx_hash_t *id)
{
    sxi_md_ctx *hash_ctx;

    if (!sx)
        return 1;
    if (!id) {
        sxi_seterr(sx, SXE_EARG, "null arg");
        return 1;
    }
    if (!global && !local) {
        sxi_seterr(sx, SXE_EARG, "must be one of: local, global or both");
        return 1;
    }

    hash_ctx = sxi_md_init();
    if (!hash_ctx)
        return 1;
    if (!sxi_sha1_init(hash_ctx))
        return 1;

    if (!sxi_sha1_update(hash_ctx, &kind, sizeof(kind)) ||
        (global && !sxi_sha1_update(hash_ctx, global, global_size)) ||
        (local && !sxi_sha1_update(hash_ctx, local, local_size)) ||
        !sxi_sha1_final(hash_ctx, id->b, NULL)) {
        return 1;
    }

    sxi_md_cleanup(&hash_ctx);
    return 0;
}

sxi_query_t *sxi_hashop_proto_inuse_begin_bin(sxc_client_t *sx, hashop_kind_t kind, const void *id, unsigned id_size, uint64_t op_expires_at)
{
    char idhex[SXI_SHA1_TEXT_LEN+1];
    sx_hash_t hash;
    sxi_hashop_generate_id(sx, kind, id, id_size, NULL, 0, &hash);

    sxi_bin2hex(hash.b, sizeof(hash.b), idhex);
    return sxi_hashop_proto_inuse_begin(sx, kind, idhex, op_expires_at);
}

sxi_query_t *sxi_hashop_proto_inuse_begin(sxc_client_t *sx, hashop_kind_t kind, const char *id, uint64_t op_expires_at)
{
    char url[128];
    sxi_query_t *ret;

    if (!id) {
        sxi_seterr(sx, SXE_EARG, "Null id");
        return NULL;
    }
    snprintf(url, sizeof(url), ".data/?id=%s&op_expires_at=%llu", id, (long long)op_expires_at);
    ret = sxi_query_create(sx, url, REQ_PUT);
    ret = sxi_query_append_fmt(sx, ret, 1, "{");
    return ret;
}

static sxi_query_t *sxi_hashop_proto_inuse_hash_helper(sxc_client_t *sx, sxi_query_t *query, const block_meta_t *blockmeta, int invert)
{
    unsigned i;
    char hexhash[SXI_SHA1_TEXT_LEN + 1];
    if (!blockmeta || !blockmeta->entries) {
        sxi_seterr(sx, SXE_EARG, "Null/empty blockmeta");
        return NULL;
    }
    if (!query)
        return NULL;
    if (query->comma)
        query = sxi_query_append_fmt(sx, query, 1, ",");
    else
        query->comma = 1;
    sxi_bin2hex(blockmeta->hash.b, sizeof(blockmeta->hash.b), hexhash);
    query = sxi_query_append_fmt(sx, query, sizeof(hexhash) + 8 + 7, "\"%s\":{\"b\":%u", hexhash, blockmeta->blocksize);
    for (i=0;i<blockmeta->count;i++) {
        int count = blockmeta->entries[i].count;
        query = sxi_query_append_fmt(sx, query, 1, ",");
        if (invert)
            count = -count;
        query = sxi_query_append_fmt(sx, query, 32, "\"%u\":%d", blockmeta->entries[i].replica, count);
    }
    return sxi_query_append_fmt(sx, query, 1, "}");
}

sxi_query_t *sxi_hashop_proto_inuse_hash(sxc_client_t *sx, sxi_query_t *query, const block_meta_t *blockmeta)
{
    return sxi_hashop_proto_inuse_hash_helper(sx, query, blockmeta, 0);
}

sxi_query_t *sxi_hashop_proto_decuse_hash(sxc_client_t *sx, sxi_query_t *query, const block_meta_t *blockmeta)
{
    return sxi_hashop_proto_inuse_hash_helper(sx, query, blockmeta, 1);
}

sxi_query_t *sxi_hashop_proto_inuse_end(sxc_client_t *sx, sxi_query_t *query)
{
    sxi_query_t *ret = sxi_query_append_fmt(sx, query, 1, "}");
    if (ret && ret->content)
        SXDEBUG("hashop proto: %.*s", query->content_len, (const char*)query->content);
    return ret;
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
		fclose(f);
		sxi_setsyserr(sx, SXE_EREAD, "Failed to read ssl file");
		return NULL;
	    }
	}
	fclose(f);
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

sxi_query_t *sxi_distribution_proto_begin(sxc_client_t *sx, const void *cfg, unsigned int cfg_len) {
    char *hexcfg = NULL;
    sxi_query_t *ret;
    unsigned int n;

    if(!sx || !cfg || !cfg_len)
	return 0;

    hexcfg = malloc(cfg_len * 2 + 1);
    if(!hexcfg)
	return NULL;

    sxi_bin2hex(cfg, cfg_len, hexcfg);

    n = sizeof("{\"newDistribution\":\"\",\"faultyNodes\":[") + cfg_len * 2;
    ret = sxi_query_create(sx, ".dist", REQ_PUT);
    if(ret) {
	ret->comma = 0;
	ret = sxi_query_append_fmt(sx, ret, n, "{\"newDistribution\":\"%s\",\"faultyNodes\":[", hexcfg);
    }

    free(hexcfg);
    return ret;
}

sxi_query_t *sxi_distribution_proto_add_faulty(sxc_client_t *sx, sxi_query_t *query, const char *node_uuid) {
    if(!sx || !query || !node_uuid) {
        SXDEBUG("Called with NULL argument");
        return NULL;
    }

    if(!query->comma) {
	query->comma = 1;
	return sxi_query_append_fmt(sx, query, strlen(node_uuid)+2,"\"%s\"", node_uuid);
    } else
	return sxi_query_append_fmt(sx, query, strlen(node_uuid)+3,",\"%s\"", node_uuid);
}

sxi_query_t *sxi_distribution_proto_end(sxc_client_t *sx, sxi_query_t *query) {
    if(!sx || !query) {
        SXDEBUG("Called with NULL argument");
        return NULL;
    }

    return sxi_query_append_fmt(sx, query, 3, "]}");
}

static sxi_query_t *sxi_volumeacl_loop(sxc_client_t *sx, sxi_query_t *query,
                                       const char *key, acl_cb_t cb, void *ctx)
{
    const char *user;
    query = sxi_query_append_fmt(sx, query, strlen(key)+5,"%s\"%s\":[",
                         query->comma ? "," : "",
                         key);
    if (!query)
        return NULL;
    query->comma=0;
    while ((user = cb(ctx))) {
        char *qname = sxi_json_quote_string(user);
        if (!qname) {
            sxi_query_free(query);
            return NULL;
        }
        query = sxi_query_append_fmt(sx, query, strlen(qname)+1,"%s%s",
                                     query->comma ? "," : "",
                                     qname);
        free(qname);
        if (!query)
            return NULL;
        query->comma = 1;
    }
    query = sxi_query_append_fmt(sx, query, 1, "]");
    if (!query)
        return NULL;
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

sxi_query_t *sxi_volsizes_proto_begin(sxc_client_t *sx) {
    sxi_query_t *query;

    if(!sx) {
        SXDEBUG("Called with NULL argument");
        return NULL;
    }

    query = sxi_query_create(sx, ".volsizes", REQ_PUT);
    if(!query) {
        SXDEBUG("Failed to create query");
        return NULL;
    }

    query = sxi_query_append_fmt(sx, query, 2, "{");
    if(!query) {
        SXDEBUG("Failed to append opening bracket to query");
        return NULL;
    }

    return query;
}

sxi_query_t *sxi_volsizes_proto_add_volume(sxc_client_t *sx, sxi_query_t *query, const char *volname, int64_t size) {
    char *enc_vol;

    if(!sx || !query || !volname) {
        SXDEBUG("Called with NULL argument");
        return NULL;
    }

    enc_vol = sxi_json_quote_string(volname);
    if(!enc_vol) {
        SXDEBUG("Failed to encode volume name");
        return NULL;
    }

    if(query->comma) {
        query = sxi_query_append_fmt(sx, query, strlen(",:") + 20 + strlen(enc_vol) + 1,
            ",%s:%lld", enc_vol, (long long)size);
    } else {
        query = sxi_query_append_fmt(sx, query, strlen(":") + 20 + strlen(enc_vol) + 1,
            "%s:%lld", enc_vol, (long long)size);
    }

    if(!query) {
        SXDEBUG("Failed to append volume to a query");
        free(enc_vol);
        return NULL;
    }

    query->comma = 1;
    free(enc_vol);
    return query;
}

sxi_query_t *sxi_volsizes_proto_end(sxc_client_t *sx, sxi_query_t *query) {
    if(!sx || !query) {
        SXDEBUG("Called with NULL argument");
        return NULL;
    }

    return sxi_query_append_fmt(sx, query, 2, "}");
}

sxi_query_t *sxi_volume_mod_proto(sxc_client_t *sx, const char *volume, const char *newowner, int64_t newsize) {
    sxi_query_t *query = NULL, *ret = NULL;
    char *enc_vol = NULL, *enc_owner = NULL, *path = NULL;
    unsigned int len;
    int comma = 0;

    if(!volume || (!newowner && newsize < 0)) {
        SXDEBUG("Called with NULL argument");
        return NULL;
    }

    enc_vol = sxi_urlencode(sx, volume, 0);
    if(!enc_vol) {
        SXDEBUG("Failed to encode volume name");
        goto sxi_volume_mod_proto_err;
    }
    len = strlen("?o=mod") + strlen(enc_vol) + 1;

    path = malloc(len);
    if(!path) {
        SXDEBUG("Failed to allocate query path");
        goto sxi_volume_mod_proto_err;
    }
    snprintf(path, len, "%s?o=mod", enc_vol);
    query = sxi_query_create(sx, path, REQ_PUT);
    if(!query) {
        SXDEBUG("Failed to allocate query");
        goto sxi_volume_mod_proto_err;
    }

    query = sxi_query_append_fmt(sx, query, 2, "{");
    if(!query) {
        SXDEBUG("Failed to close query JSON");
        goto sxi_volume_mod_proto_err;
    }

    if(newowner) {
        enc_owner = sxi_json_quote_string(newowner);
        if(!enc_owner) {
            SXDEBUG("Failed to encode new volume owner name");
            goto sxi_volume_mod_proto_err;
        }

        query = sxi_query_append_fmt(sx, query, strlen("\"owner\":\"\"") + strlen(enc_owner) + 1, "\"owner\":%s", enc_owner);
        if(!query) {
            SXDEBUG("Failed to append owner field to query JSON");
            goto sxi_volume_mod_proto_err;
        }
        comma = 1;
    }

    if(newsize > 0) {
        query = sxi_query_append_fmt(sx, query, strlen("\"size\":") + 21 + comma, "%s\"size\":%lld", (comma ? "," : ""), (long long)newsize);
        if(!query) {
            SXDEBUG("Failed to append owner field to query JSON");
            goto sxi_volume_mod_proto_err;
        }
    }

    query = sxi_query_append_fmt(sx, query, 2, "}");
    if(!query) {
        SXDEBUG("Failed to close query JSON");
        goto sxi_volume_mod_proto_err;
    }

    ret = query;
sxi_volume_mod_proto_err:
    free(enc_vol);
    free(enc_owner);
    free(path);
    if(!ret) /* If failed, do not return incomplete query */
        sxi_query_free(query);
    return ret;
}
