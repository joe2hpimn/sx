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

#include "libsxclient-int.h"
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

sxi_query_t *sxi_query_create(sxc_client_t *sx, const char *path, enum sxi_cluster_verb verb)
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
static sxi_query_t* sxi_query_add_meta(sxc_client_t *sx, sxi_query_t *query, const char *field, sxc_meta_t *metadata, int comma, int allow_empty)
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
    if (nmeta || allow_empty) {
        if (!(query = sxi_query_append_fmt(sx, query, strlen(field)+6, "%s\"%s\":{", comma ? "," : "", field)))
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
    if (!(query = sxi_query_append_fmt(sx, query, 2, (nmeta || allow_empty) ? "}}" : "}")))
        return NULL;
    query->content_len = strlen(query->content);
    return query;
}

sxi_query_t *sxi_useradd_proto(sxc_client_t *sx, const char *username, const uint8_t *uid, const uint8_t *key, int admin, const char *desc, int64_t quota, sxc_meta_t *meta) {
    char *qname, *dname = NULL, hexkey[AUTH_KEY_LEN*2+1];
    sxi_query_t *ret;
    unsigned n;

    qname = sxi_json_quote_string(username);
    if(!qname)
	return NULL;
    if(quota < -1) {
        free(qname);
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }
    if (desc) {
        dname = sxi_json_quote_string(desc);
        if (!dname) {
            free(qname);
            return NULL;
        }
    }

    n = sizeof("{\"userName\":,\"userType\":\"normal\",\"userKey\":\"\"") + /* the json body without terminator */
	strlen(qname) + /* the json encoded username with quotes */
	AUTH_KEY_LEN * 2/* the hex encoded key without quotes */;
    sxi_bin2hex(key, AUTH_KEY_LEN, hexkey);
    ret = sxi_query_create(sx, ".users", REQ_PUT);
    if (ret)
        ret = sxi_query_append_fmt(sx, ret, n, "{\"userName\":%s,\"userType\":\"%s\",\"userKey\":\"%s\"",
                                   qname, admin ? "admin" : "normal", hexkey);
    if (ret && dname)
        ret = sxi_query_append_fmt(sx, ret, sizeof(",\"userDesc\":") + strlen(dname), ",\"userDesc\":%s", dname);
    if (ret && quota != -1)
        ret = sxi_query_append_fmt(sx, ret, sizeof(",\"userQuota\":") + 20, ",\"userQuota\":%lld", (long long)quota);
    if(ret && uid) { /* If UID has been added, then append its hex representation also */
        char hexuid[AUTH_UID_LEN*2+1];
        sxi_bin2hex(uid, AUTH_UID_LEN, hexuid);
        ret = sxi_query_append_fmt(sx, ret, AUTH_UID_LEN * 2 + strlen(",\"userID\":\"\""), ",\"userID\":\"%s\"", hexuid);
    }
    if(ret) {
        if(meta)
            ret = sxi_query_add_meta(sx, ret, "userMeta", meta, 1, 1);
        else
            ret = sxi_query_append_fmt(sx, ret, 2, "}");
    }
    free(qname);
    free(dname);
    return ret;
}

/* username - new username, the clone name
 * exsitingname - the cloned username
 * desc - human readable decription of the user
 * There is also no need to send admin flag like for useradd proto, clone has the same role as existing user */
sxi_query_t *sxi_userclone_proto(sxc_client_t *sx, const char *existingname, const char *username, const uint8_t *uid, const uint8_t *key, const char *desc, sxc_meta_t *meta) {
    char *ename, *uname, *dname, hexkey[AUTH_KEY_LEN*2+1];
    sxi_query_t *ret;
    unsigned n;

    ename = sxi_json_quote_string(existingname);
    if(!ename)
        return NULL;
    uname = sxi_json_quote_string(username);
    if(!uname) {
        free(ename);
        return NULL;
    }
    dname = sxi_json_quote_string(desc);
    if (!dname) {
        free(ename);
        free(uname);
        return NULL;
    }

    n = sizeof("{\"userName\":,\"existingName\":,\"userKey\":\"\",\"userDesc\":") + /* the json body with terminator */
        strlen(ename) + /* the json encoded exsitingname with quotes */
        strlen(uname) + /* the json encoded username with quotes */
        strlen(dname) +
        AUTH_KEY_LEN * 2/* the hex encoded key without quotes */;
    sxi_bin2hex(key, AUTH_KEY_LEN, hexkey);
    ret = sxi_query_create(sx, ".users", REQ_PUT);
    if (ret)
        ret = sxi_query_append_fmt(sx, ret, n, "{\"userName\":%s,\"existingName\":%s,\"userKey\":\"%s\",\"userDesc\":%s",
                                   uname, ename, hexkey, dname);
    if(ret && uid) {
        char hexuid[AUTH_UID_LEN*2+1];
        sxi_bin2hex(uid, AUTH_UID_LEN, hexuid);
        ret = sxi_query_append_fmt(sx, ret, strlen(",\"userID\":\"\"") + AUTH_UID_LEN * 2, ",\"userID\":\"%s\"", hexuid);
    }
    if(ret) {
        if(meta)
            ret = sxi_query_add_meta(sx, ret, "userMeta", meta, 1, 1);
        else
            ret = sxi_query_append_fmt(sx, ret, 2, "}");
    }
    free(ename);
    free(uname);
    free(dname);
    return ret;
}

sxi_query_t *sxi_usermod_proto(sxc_client_t *sx, const char *username, const uint8_t *key, int64_t quota, const char *description, sxc_meta_t *custom_meta) {
    char *qname = NULL, *query = NULL;
    sxi_query_t *ret = NULL;
    unsigned n;

    if((!key && quota == -1 && !description) || quota < -1) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }

    do {
        int comma = 0;

        qname = sxi_urlencode(sx, username, 0);
        if(!qname)
            break;
        n = sizeof(".users/") + strlen(qname);
        query = malloc(n);
        if (!query) {
            sxi_seterr(sx, SXE_EMEM, "Out of memory");
            break;
        }
        snprintf(query, n, ".users/%s", qname);
        ret = sxi_query_create(sx, query, REQ_PUT);
        if(ret)
            ret = sxi_query_append_fmt(sx, ret, 1, "{");
        if(key && ret) {
            char hexkey[AUTH_KEY_LEN*2+1];
            n = sizeof("\"userKey\":\"\"") + /* the json key with quotes */
                AUTH_KEY_LEN * 2 /* the hex encoded key without quotes */;
            sxi_bin2hex(key, AUTH_KEY_LEN, hexkey);
            ret = sxi_query_append_fmt(sx, ret, n, "\"userKey\":\"%s\"", hexkey);
            comma = 1;
        }

        if(quota != -1 && ret) {
            n = sizeof(",\"quota\":") + /* the json key with quotes */
                20 /* 20 bytes for a number */;
            ret = sxi_query_append_fmt(sx, ret, n, "%s\"quota\":%lld", comma ? "," : "", (long long)quota);
            comma = 1;
        }

        if(description && ret) {
            char *desc_enc = sxi_json_quote_string(description);

            if(!desc_enc) {
                sxi_seterr(sx, SXE_EMEM, "Failed to quote description: Out of memory");
                break;
            }
            n = sizeof(",\"desc\":") + strlen(desc_enc);
            ret = sxi_query_append_fmt(sx, ret, n, "%s\"desc\":%s", comma ? "," : "", desc_enc);
            free(desc_enc);
        }

        if(ret) {
            if(custom_meta)
                ret = sxi_query_add_meta(sx, ret, "customUserMeta", custom_meta, 1, 1);
            else
                ret = sxi_query_append_fmt(sx, ret, 1, "}");
        }
    } while(0);
    free(qname);
    free(query);
    return ret;
}

sxi_query_t *sxi_useronoff_proto(sxc_client_t *sx, const char *username, int enable, int all_clones) {
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
        if(all_clones)
            n += strlen("&all");
        query = malloc(n);
        if(!query) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory allocating user query");
            break;
        }
        snprintf(query, n, ".users/%s?o=%s%s", path, enable ? "enable" : "disable", all_clones ? "&all" : "");
        ret = sxi_query_create(sx, query, REQ_PUT);
    } while(0);
    free(path);
    free(query);
    return ret;
}

sxi_query_t *sxi_userdel_proto(sxc_client_t *sx, const char *username, const char *newowner, int all_clones) {
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
        if(all_clones)
            n += strlen("&all");
        query = malloc(n);
        if(!query) {
            sxi_setsyserr(sx, SXE_EMEM, "out of memory allocating user query");
            break;
        }
        snprintf(query, n, ".users/%s?chgto=%s%s", oldusr, newusr, (all_clones ? "&all" : ""));
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
    return sxi_query_add_meta(sx, ret, "volumeMeta", metadata, 1, 0);
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

sxi_query_t *sxi_fileadd_proto_begin(sxc_client_t *sx, const char *volname, const char *path, const char *revision, const char *revision_id, int64_t pos, int64_t blocksize, int64_t size) {
    char *enc_vol = NULL, *enc_path = NULL, *enc_rev = NULL, *url = NULL;
    sxi_query_t *ret;
    unsigned int len;

    if(revision_id) {
        /* Revision ID should be hex-encoded, and must be provided when revision is provided. */
        if(strlen(revision_id) != SXI_SHA1_TEXT_LEN || !revision) {
            sxi_seterr(sx, SXE_EMEM, "Invalid argument: revision_id");
            return NULL;
        }
    }

    enc_vol = sxi_urlencode(sx, volname, 0);
    enc_path = sxi_urlencode(sx, path, 0);
    if(!enc_vol || !enc_path) {
	free(enc_vol);
	free(enc_path);
	sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: Out of memory");
	return NULL;
    }
    len = strlen(enc_vol) + 1 + strlen(enc_path) + 1;
    if(revision) {
	enc_rev = sxi_urlencode(sx, revision, 1);
	if(!enc_rev) {
	    sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: Out of memory");
	    free(enc_vol);
	    free(enc_path);
	    return NULL;
	}
        len += strlen(enc_rev) + lenof("?rev=");
        if(revision_id)
            len += strlen(revision_id) + lenof("&revid=");
    }

    url = malloc(len);
    if(url)
        sprintf(url, "%s/%s%s%s%s%s", enc_vol, enc_path, enc_rev ? "?rev=" : "", enc_rev ? enc_rev : "", revision_id ? "&revid=" : "", revision_id ? revision_id : "");
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
    return sxi_query_add_meta(sx, query, "fileMeta", metadata, 1, 0);
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

sxi_query_t *sxi_massdel_proto(sxc_client_t *sx, const char *volname, const char *pattern, int recursive) {
    char *enc_vol, *enc_pattern, *url;
    sxi_query_t *ret;
    unsigned int len;

    enc_vol = sxi_urlencode(sx, volname, 0);
    enc_pattern = sxi_urlencode(sx, pattern, 0);

    if(!enc_vol || !enc_pattern) {
        free(enc_vol);
        free(enc_pattern);
        sxi_setsyserr(sx, SXE_EMEM, "Failed to quote url: Out of memory");
        return NULL;
    }

    len = strlen(enc_vol) + lenof("?filter=") + strlen(enc_pattern) + 1;
    if(recursive)
        len += lenof("&recursive");
    url = malloc(len);
    if(!url) {
        sxi_setsyserr(sx, SXE_EMEM, "Failed to generate query: Out of memory");
        free(enc_vol);
        free(enc_pattern);
        return NULL;
    }

    sprintf(url, "%s?filter=%s%s", enc_vol, enc_pattern, recursive ? "&recursive" : "");
    ret = sxi_query_create(sx, url, REQ_DELETE);
    free(enc_vol);
    free(enc_pattern);
    free(url);
    return ret;
}

static sxi_query_t *sxi_hashop_proto_list(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len, enum sxi_cluster_verb verb, const char *op, const char *global_vol_id, const char *reserve_id, const char *revision_id, unsigned replica, uint64_t op_expires_at)
{
    char url[DOWNLOAD_MAX_BLOCKS * (EXPIRE_TEXT_LEN + SXI_SHA1_TEXT_LEN) + sizeof(".data/1048576/?o=reserve&reserve_id=&revision_id=&global_vol_id=") + 144];
    char expires_str[24];
    char replica_str[24];
    int rc;

    if (!op)
        return NULL;
    snprintf(expires_str, sizeof(expires_str), "%llu", (long long)op_expires_at);
    snprintf(replica_str, sizeof(replica_str), "%u", replica);
    rc = snprintf(url, sizeof(url), ".data/%u/%.*s?o=%s%s%s%s%s%s%s%s%s%s%s", blocksize, hashes_len, hashes,
                  op,
                  reserve_id ? "&reserve_id=" : "", reserve_id ? reserve_id : "",
                  revision_id ? "&revision_id=" : "", revision_id ? revision_id : "",
                  global_vol_id ? "&global_vol_id=" : "", global_vol_id ? global_vol_id : "",
                  op_expires_at ? "&op_expires_at=" : "", op_expires_at ? expires_str : "",
                  replica ? "&replica=" : "", replica ? replica_str : "");
    if (rc < 0 || rc >= sizeof(url)) {
        sxi_seterr(sx, SXE_EARG, "Failed to build hashop url: URL too long");
        return NULL;
    }
    return sxi_query_create(sx, url, verb);
}

sxi_query_t *sxi_hashop_proto_check(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len)
{
    return sxi_hashop_proto_list(sx, blocksize, hashes, hashes_len, REQ_GET, "check", NULL, NULL, NULL, 0, 0);
}

sxi_query_t *sxi_hashop_proto_reserve(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len, const sx_hash_t *global_vol_id, const sx_hash_t *reserve_id, const sx_hash_t *revision_id, unsigned replica, uint64_t op_expires_at)
{
    char reserve_idhex[SXI_SHA1_TEXT_LEN + 1];
    char revision_idhex[SXI_SHA1_TEXT_LEN + 1];
    char vidhex[SXI_SHA1_TEXT_LEN + 1];
    if (!reserve_id || !revision_id || !global_vol_id) {
        sxi_seterr(sx, SXE_EARG, "Null id");
        return NULL;
    }
    if (!replica) {
        sxi_seterr(sx, SXE_EARG, "Replica cannot be zero");
        return NULL;
    }
    if (!op_expires_at) {
        sxi_seterr(sx, SXE_EARG, "Missing expires");
        return NULL;
    }
    sxi_bin2hex(reserve_id->b, sizeof(reserve_id->b), reserve_idhex);
    sxi_bin2hex(revision_id->b, sizeof(revision_id->b), revision_idhex);
    sxi_bin2hex(global_vol_id->b, sizeof(global_vol_id->b), vidhex);
    return sxi_hashop_proto_list(sx, blocksize, hashes, hashes_len, REQ_PUT, "reserve", vidhex, reserve_idhex, revision_idhex, replica, op_expires_at);
}

sxi_query_t *sxi_hashop_proto_inuse_begin(sxc_client_t *sx, const sx_hash_t *reserve_hash)
{
    char url[128];
    char reserve_idhex[SXI_SHA1_TEXT_LEN+1];
    sxi_query_t *ret;

    if (reserve_hash) {
        sxi_bin2hex(reserve_hash->b, sizeof(reserve_hash->b), reserve_idhex);
        snprintf(url, sizeof(url), ".data/?reserve_id=%s", reserve_idhex);
    } else {
        snprintf(url, sizeof(url), ".data/");
    }

    ret = sxi_query_create(sx, url, REQ_PUT);
    /* tokenid should be a wrapper here, and parser should accept tokenid at any
     * level and set it for all descendants... */
    ret = sxi_query_append_fmt(sx, ret, 1, "{");
    return ret;
}

sxi_query_t *sxi_hashop_proto_inuse_hash(sxc_client_t *sx, sxi_query_t *query, const block_meta_t *blockmeta)
{
    unsigned i;
    char hexhash[SXI_SHA1_TEXT_LEN + 1];
    char hexrevid[SXI_SHA1_TEXT_LEN + 1];
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
    query = sxi_query_append_fmt(sx, query, sizeof(hexhash) + 8 + 8, "\"%s\":{\"%u\":[", hexhash, blockmeta->blocksize);
    for (i=0;i<blockmeta->count;i++) {
        const block_meta_entry_t *e = &blockmeta->entries[i];
        if (i > 0)
            query = sxi_query_append_fmt(sx, query, 1, ",");
        sxi_bin2hex(e->revision_id.b, sizeof(e->revision_id.b), hexrevid);
        SXDEBUG("sending replica %d", e->replica);
        if(e->has_vol_id) {
            char hexvolid[SXI_SHA1_TEXT_LEN + 1];

            sxi_bin2hex(e->global_vol_id.b, sizeof(e->global_vol_id.b), hexvolid);
            query = sxi_query_append_fmt(sx, query, lenof("{\"\":{\"volid\":\"\",\"replica\":}}") + 2 * SXI_SHA1_TEXT_LEN + 21, "{\"%s\":{\"volid\":\"%s\",\"replica\":%u}}", hexrevid, hexvolid, e->replica);
        } else
            query = sxi_query_append_fmt(sx, query, lenof("{\"\":{\"replica\":}}") + SXI_SHA1_TEXT_LEN + 21, "{\"%s\":{\"replica\":%u}}", hexrevid, e->replica);
    }
    return sxi_query_append_fmt(sx, query, 2, "]}");
}

sxi_query_t *sxi_hashop_proto_inuse_end(sxc_client_t *sx, sxi_query_t *query)
{
    sxi_query_t *ret = sxi_query_append_fmt(sx, query, 1, "}");
    if (ret && ret->content && query)
        SXDEBUG("hashop proto: %.*s", query->content_len, (const char*)query->content);
    return ret;
}

sxi_query_t *sxi_hashop_proto_revision(sxc_client_t *sx, unsigned blocksize, const sx_hash_t *revision_id, int op)
{
    char url[sizeof(".data/1048576/?o=revmod&revision_id=") + SXI_SHA1_TEXT_LEN + 1];
    char idhex[SXI_SHA1_TEXT_LEN + 1];

    if (!revision_id) {
        sxi_seterr(sx, SXE_EARG, "Null revisionid");
        return NULL;
    }

    sxi_bin2hex(revision_id->b, sizeof(revision_id->b), idhex);
    snprintf(url, sizeof(url), ".data/%u/?o=revmod&revision_id=%s", blocksize, idhex);
    switch (op) {
        case 1:
            return sxi_query_create(sx, url, REQ_PUT);
        case -1:
            return sxi_query_create(sx, url, REQ_DELETE);
        default:
            sxi_seterr(sx, SXE_EARG, "Bad revision op: %d", op);
            return NULL;
    }
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

sxi_query_t *sxi_distribution_proto_begin(sxc_client_t *sx, const void *cfg, unsigned int cfg_len, const char *swver) {
    char *hexcfg = NULL, *enc_ver = NULL;
    sxi_query_t *ret;
    unsigned int n;

    if(!sx || !cfg || !cfg_len || !swver)
	return NULL;

    hexcfg = malloc(cfg_len * 2 + 1);
    if(!hexcfg)
	return NULL;
    sxi_bin2hex(cfg, cfg_len, hexcfg);

    enc_ver = sxi_json_quote_string(swver);
    if(!enc_ver) {
	free(hexcfg);
	return NULL;
    }

    n = sizeof("{\"newDistribution\":\"\",\"softwareVersion\":,\"faultyNodes\":[") + cfg_len * 2  + strlen(enc_ver);
    ret = sxi_query_create(sx, ".dist", REQ_PUT);
    if(ret) {
	ret->comma = 0;
	ret = sxi_query_append_fmt(sx, ret, n, "{\"newDistribution\":\"%s\",\"softwareVersion\":%s,\"faultyNodes\":[", hexcfg, enc_ver);
    }

    free(enc_ver);
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
                                 acl_cb_t grant_read, acl_cb_t grant_write, acl_cb_t grant_manager,
                                 acl_cb_t revoke_read, acl_cb_t revoke_write, acl_cb_t revoke_manager,
                                 void *ctx)
{
    sxi_query_t *ret;
    unsigned n;
    char *enc_vol;
    char *url;

    enc_vol = sxi_urlencode(sx, volname, 0);
    if (!enc_vol) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate encoded url");
        return NULL;
    }
    n = strlen(enc_vol) + sizeof("?o=acl");
    url = malloc(n);
    if (!url) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate url");
        free(enc_vol);
        return NULL;
    }
    snprintf(url, n, "%s?o=acl&manager", enc_vol);
    free(enc_vol);

    ret = sxi_query_create(sx, url, REQ_PUT);
    ret = sxi_query_append_fmt(sx, ret, 1, "{");
    ret = sxi_volumeacl_loop(sx, ret, "grant-read", grant_read, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "grant-write", grant_write, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "grant-manager", grant_manager, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "revoke-read", revoke_read, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "revoke-write", revoke_write, ctx);
    ret = sxi_volumeacl_loop(sx, ret, "revoke-manager", revoke_manager, ctx);
    ret = sxi_query_append_fmt(sx, ret, 1, "}");
    if (ret)
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

sxi_query_t *sxi_volsizes_proto_add_volume(sxc_client_t *sx, sxi_query_t *query, const char *volname, int64_t size, int64_t fsize, int64_t nfiles) {
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

    query = sxi_query_append_fmt(sx, query, strlen(",:{\"usedSize\":,\"filesSize\":,\"filesCount\":}") + 60 + strlen(enc_vol) + 1,
        "%s%s:{\"usedSize\":%lld,\"filesSize\":%lld,\"filesCount\":%lld}", query->comma ? "," : "", enc_vol, (long long)size, (long long)fsize, (long long)nfiles);

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

sxi_query_t *sxi_volume_mod_proto(sxc_client_t *sx, const char *volume, const char *newowner, int64_t newsize, int max_revs, sxc_meta_t *meta) {
    sxi_query_t *query = NULL, *ret = NULL;
    char *enc_vol = NULL, *enc_owner = NULL, *path = NULL;
    unsigned int len;
    int comma = 0;

    if(!volume || (!newowner && newsize < 0 && max_revs < 0 && !meta)) {
        SXDEBUG("Invalid argument");
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
            SXDEBUG("Failed to append size field to query JSON");
            goto sxi_volume_mod_proto_err;
        }
        comma = 1;
    }

    if(max_revs > 0) {
        query = sxi_query_append_fmt(sx, query, strlen("\"maxRevisions\":") + 21 + comma, "%s\"maxRevisions\":%d", (comma ? "," : ""), max_revs);
        if(!query) {
            SXDEBUG("Failed to append revs field to query JSON");
            goto sxi_volume_mod_proto_err;
        }
    }

    if(meta) {
        /* This call encloses the JSON too */
        query = sxi_query_add_meta(sx, query, "customVolumeMeta", meta, (max_revs > 0 || newsize > 0 || newowner) ? 1 : 0, 1);
        if(!query) {
            SXDEBUG("Failed to append volume metadata to query JSON");
            goto sxi_volume_mod_proto_err;
        }
    } else {
        /* JSON should be enclosed when meta is not given */
        query = sxi_query_append_fmt(sx, query, 2, "}");
        if(!query) {
            SXDEBUG("Failed to close query JSON");
            goto sxi_volume_mod_proto_err;
        }
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

sxi_query_t *sxi_distlock_proto(sxc_client_t *sx, int lock, const char *lockid) {
    sxi_query_t *query = NULL;

    query = sxi_query_create(sx, ".distlock", REQ_PUT);
    if(!query) {
        SXDEBUG("Failed to create query");
        sxi_seterr(sx, SXE_EMEM, "Failed to create .distlock query");
        return NULL;
    }

    query = sxi_query_append_fmt(sx, query, strlen("{\"op\":\"unlock\""), "{\"op\":\"%s\"", lock ? "lock" : "unlock");
    if(!query) {
        SXDEBUG("Failed to append JSON content");
        sxi_seterr(sx, SXE_EMEM, "Failed to create .distlock query");
        return NULL;
    }

    if(lockid) {
        query = sxi_query_append_fmt(sx, query, strlen(",\"lockID\":\"\"") + strlen(lockid), ",\"lockID\":\"%s\"", lockid);
        if(!query) {
            SXDEBUG("Failed to append JSON content");
            sxi_seterr(sx, SXE_EMEM, "Failed to create .distlock query");
            return NULL;
        }
    }

    query = sxi_query_append_fmt(sx, query, 1, "}");
    if(!query) {
        SXDEBUG("Failed to append JSON content");
        sxi_seterr(sx, SXE_EMEM, "Failed to create .distlock query");
        return NULL;
    }

    return query;
}

sxi_query_t *sxi_cluster_mode_proto(sxc_client_t *sx, int readonly) {
    sxi_query_t *query;

    query = sxi_query_create(sx, ".mode", REQ_PUT);
    if(!query) {
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate query");
        return NULL;
    }

    query = sxi_query_append_fmt(sx, query, strlen("{\"mode\":\"ro\"}"), "{\"mode\":\"%s\"}", readonly ? "ro" : "rw");
    if(!query) {
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate query");
        return NULL;
    }
    return query;
}

sxi_query_t *sxi_cluster_upgrade_proto(sxc_client_t *sx) {
    return sxi_query_create(sx, ".upgrade", REQ_PUT);
}

static sxi_query_t *cluster_setmeta_proto_common(sxc_client_t *sx, int timestamp, sxc_meta_t *meta, int is_cluster_meta) {
    sxi_query_t *query;

    query = sxi_query_create(sx, is_cluster_meta ? ".clusterMeta" : ".clusterSettings", REQ_PUT);
    if(query)
        query = sxi_query_append_fmt(sx, query, 1, "{");

    /* Timestamp won't be included if it is -1 */
    if(timestamp != -1 && query)
        query = sxi_query_append_fmt(sx, query, lenof("\"timestamp\":") + 21, "\"timestamp\":%d", timestamp);

    /* This should also enclose the JSON */
    if(query)
        query = sxi_query_add_meta(sx, query, is_cluster_meta ? "clusterMeta" : "clusterSettings", meta, timestamp != -1 ? 1 : 0, 1);

    if(!query)
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate query");

    return query;
}

sxi_query_t *sxi_cluster_setmeta_proto(sxc_client_t *sx, int timestamp, sxc_meta_t *meta) {
    return cluster_setmeta_proto_common(sx, timestamp, meta, 1);
}

sxi_query_t *sxi_cluster_settings_proto(sxc_client_t *sx, int timestamp, sxc_meta_t *meta) {
    return cluster_setmeta_proto_common(sx, timestamp, meta, 0);
}

sxi_query_t *sxi_raft_request_vote(sxc_client_t *sx, int64_t term, int64_t hdist_version, const char *hashfs_version, const char *candidate_uuid, int64_t last_log_index, int64_t last_log_term) {
    sxi_query_t *query = sxi_query_create(sx, ".requestVote", REQ_PUT);

    /* Length: lenof(str) + 3 times long long (20) + UUID_STRING_SIZE */
    if(query)
        query = sxi_query_append_fmt(sx, query, lenof("{\"term\":,\"distributionVersion\":,\"hashFSVersion\":\"\",\"libsxclientVersion\":\"\",\"candidateID\":\"\",\"lastLogIndex\":,\"lastLogTerm\":}") + 60 + 36,
                "{\"term\":%lld,\"distributionVersion\":%lld,\"hashFSVersion\":\"%s\",\"libsxclientVersion\":\"%s\",\"candidateID\":\"%s\",\"lastLogIndex\":%lld,\"lastLogTerm\":%lld}",
                (long long)term, (long long)hdist_version, hashfs_version, sxc_get_version(), candidate_uuid, (long long)last_log_index, (long long)last_log_term);

    if(!query)
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate query");

    return query;
}

sxi_query_t *sxi_raft_append_entries_begin(sxc_client_t *sx, int64_t term, int64_t hdist_version, const char *hashfs_version, const char *leader_uuid, int64_t prev_log_index, int64_t prev_log_term, int64_t leader_commit) {
    sxi_query_t *query = sxi_query_create(sx, ".appendEntries", REQ_PUT);

    /* Length: lenof(str) + 4 times long long (20) + UUID_STRING_SIZE */
    if(query)
        query = sxi_query_append_fmt(sx, query, lenof("{\"term\":,\"distributionVersion\":,\"hashFSVersion\":\"\",\"libsxclientVersion\":\"\",\"leaderID\":\"\",\"prevLogIndex\":,\"prevLogTerm\":,\"leaderCommit\":,\"entries\":[") + 80 + 36,
                "{\"term\":%lld,\"distributionVersion\":%lld,\"hashFSVersion\":\"%s\",\"libsxclientVersion\":\"%s\",\"leaderID\":\"%s\",\"prevLogIndex\":%lld,\"prevLogTerm\":%lld,\"leaderCommit\":%lld,\"entries\":[",
                (long long)term, (long long)hdist_version, hashfs_version, sxc_get_version(), leader_uuid, (long long)prev_log_index, (long long)prev_log_term, (long long)leader_commit);

    if(!query)
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate query");

    return query;
}

sxi_query_t *sxi_raft_append_entries_add(sxc_client_t *sx, sxi_query_t *query, int64_t index, const void *entry, unsigned int entry_len, int comma) {
    char *hex;

    if(!query)
        sxi_seterr(sx, SXE_EARG, "NULL argument");

    hex = malloc(entry_len * 2 + 1);
    if(!hex) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory encoding entry");
        sxi_query_free(query);
        return NULL;
    }
    sxi_bin2hex(entry, entry_len, hex);

    query = sxi_query_append_fmt(sx, query, lenof(",{\"index\":,\"entry\":\"\"}") + 20 + entry_len * 2 + 1, "%s{\"index\":%lld,\"entry\":\"%s\"}",
        comma ? "," : "", (long long)index, hex);

    if(!query)
        sxi_seterr(sx, SXE_EMEM, "Failed to add log entry");

    free(hex);
    return query;
}

sxi_query_t *sxi_raft_append_entries_finish(sxc_client_t *sx, sxi_query_t *query) {
    if(!query)
        sxi_seterr(sx, SXE_EARG, "NULL argument");

    query = sxi_query_append_fmt(sx, query, 3, "]}");

    if(!query)
        sxi_seterr(sx, SXE_EMEM, "Failed to add log entry");

    return query;
}

sxi_query_t *sxi_mass_job_proto(sxc_client_t *sx, unsigned int job_type, time_t job_timeout, const char *job_lockname, const void *job_data, unsigned int job_data_len) {
    sxi_query_t *ret;
    char *enc_lockname = NULL;

    ret = sxi_query_create(sx, ".jobspawn", REQ_PUT);
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    if(job_lockname) {
        enc_lockname = sxi_json_quote_string(job_lockname);
        if(!enc_lockname) {
            sxi_query_free(ret);
            sxi_seterr(sx, SXE_EMEM, "Failed to json-encode job lockname");
            return NULL;
        }
    }

    ret = sxi_query_append_fmt(sx, ret, lenof("{\"job_type\":,\"job_timeout\":,\"job_lockname\":") + 40 + (enc_lockname ? strlen(enc_lockname) : 0) + 1,
        "{\"job_type\":%u,\"job_timeout\":%lld,\"job_lockname\":%s", job_type, (long long)job_timeout, enc_lockname);
    free(enc_lockname);
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Failed to prepare query");
        return NULL;
    }

    if(job_data && job_data_len) {
        char *hex;

        hex = malloc(job_data_len * 2 + 1);
        if(!hex) {
            sxi_seterr(sx, SXE_EMEM, "Failed to allocate memory");
            sxi_query_free(ret);
            return NULL;
        }

        sxi_bin2hex(job_data, job_data_len, hex);
        ret = sxi_query_append_fmt(sx, ret, lenof(",\"job_data\":\"\"") + job_data_len*2, ",\"job_data\":\"%s\"", hex);
        free(hex);
        if(!ret) {
            sxi_seterr(sx, SXE_EMEM, "Failed to prepare query");
            return NULL;
        }
    }

    ret = sxi_query_append_fmt(sx, ret, 1, "}");
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Failed to prepare query");
        return NULL;
    }

    return ret;
}

sxi_query_t *sxi_mass_job_commit_proto(sxc_client_t *sx, const char *job_id) {
    char url[128];
    sxi_query_t *ret;

    if(!job_id) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }

    snprintf(url, sizeof(url), ".jobspawn/%s", job_id);

    ret = sxi_query_create(sx, url, REQ_PUT);
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    return ret;
}

/* startfile and startrev are optional */
sxi_query_t *sxi_2_1_4_upgrade_proto(sxc_client_t *sx, const char *volume, const char *maxrev, const char *startfile, const char *startrev) {
    char *enc_vol = NULL, *enc_file = NULL, *enc_rev = NULL, *enc_maxrev = NULL, *url = NULL;
    sxi_query_t *proto = NULL;
    unsigned int len;

    if(!volume || !maxrev) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }

    enc_vol = sxi_urlencode(sx, volume, 0);
    if(!enc_vol) {
        sxi_seterr(sx, SXE_EMEM, "Failed to encode the volume name");
        goto sxi_replica_change_files_proto_err;
    }
    enc_maxrev = sxi_urlencode(sx, maxrev, 0);
    if(!enc_vol) {
        sxi_seterr(sx, SXE_EMEM, "Failed to encode the maximum revision");
        goto sxi_replica_change_files_proto_err;
    }

    if(startfile && startrev) {
        enc_file = sxi_urlencode(sx, startfile, 0);
        if(!enc_vol) {
            sxi_seterr(sx, SXE_EMEM, "Failed to encode the start file");
            goto sxi_replica_change_files_proto_err;
        }
        enc_rev = sxi_urlencode(sx, startrev, 0);
        if(!enc_vol) {
            sxi_seterr(sx, SXE_EMEM, "Failed to encode the start revision");
            goto sxi_replica_change_files_proto_err;
        }
    } else if(startfile || startrev) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        goto sxi_replica_change_files_proto_err;
    }

    len = lenof(".upgrade_2_1_4/") + strlen(enc_vol) + lenof("?maxrev=") + strlen(enc_maxrev) + 1;
    if(enc_file && enc_rev) {
        len += lenof("/") + strlen(enc_file)  + lenof("&startrev=") + strlen(enc_rev);
    }

    url = malloc(len);
    if(!url) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory allocating the request URL");
        goto sxi_replica_change_files_proto_err;
    }

    if(enc_rev && enc_file)
        sprintf(url, ".upgrade_2_1_4/%s/%s?maxrev=%s&startrev=%s", enc_vol, enc_file, enc_maxrev, enc_rev);
    else
        sprintf(url, ".upgrade_2_1_4/%s?maxrev=%s", enc_vol, enc_maxrev);

    proto = sxi_query_create(sx, url, REQ_GET);
    if(!proto)
        sxi_seterr(sx, SXE_EMEM, "Failed to prepare request");

sxi_replica_change_files_proto_err:
    free(enc_vol);
    free(enc_file);
    free(enc_rev);
    free(enc_maxrev);
    free(url);
    return proto;
}

sxi_query_t *sxi_replica_change_proto(sxc_client_t *sx, const char *volume, unsigned int prev_replica, unsigned int next_replica) {
    sxi_query_t *ret;
    char *url;
    char *enc_vol;
    unsigned int len;

    if(!sx)
        return NULL;
    if(!volume || !prev_replica || !next_replica) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }

    enc_vol = sxi_urlencode(sx, volume, 1);
    if(!enc_vol) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    len = strlen(enc_vol) + lenof("?o=replica&phase=&commit=") + 1;
    url = malloc(len);
    if(!url) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        free(enc_vol);
        return NULL;
    }
    /* assuming phase does not need urlencoding */
    snprintf(url, len, "%s?o=replica", enc_vol);
    free(enc_vol);
    ret = sxi_query_create(sx, url, REQ_PUT);
    free(url);
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    ret = sxi_query_append_fmt(sx, ret, lenof("{\"prev_replica\":,\"next_replica\":}") + 21, "{\"prev_replica\":%u,\"next_replica\":%u}", prev_replica, next_replica);
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Failed to prepare query");
        return NULL;
    }

    return ret;
}
