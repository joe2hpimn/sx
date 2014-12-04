/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *  Special exception for linking this software with OpenSSL:
 *
 *  In addition, as a special exception, Skylable Ltd. gives permission to
 *  link the code of this program with the OpenSSL library and distribute
 *  linked combinations including the two. You must obey the GNU General
 *  Public License in all respects for all of the code used other than
 *  OpenSSL. You may extend this exception to your version of the program,
 *  but you are not obligated to do so. If you do not wish to do so, delete
 *  this exception statement from your version.
 */

#include "hashfs.h"
#include "../libsx/src/clustcfg.h"
#include "../libsx/src/curlevents.h"
#include "../libsx/src/yajlwrap.h"
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "log.h"
#include "utils.h"
#include <yajl/yajl_parse.h>

void sxi_hashop_begin(sxi_hashop_t *hashop, sxi_conns_t *conns, hash_presence_cb_t cb, enum sxi_hashop_kind kind, unsigned replica, const sx_hash_t *reservehash, const sx_hash_t *idhash, void *context, uint64_t op_expires_at)
{
    memset(hashop, 0, sizeof(*hashop));
    hashop->conns = conns;
    hashop->cb = cb;
    hashop->context = context;
    hashop->kind = kind;
    hashop->replica = replica;
    hashop->op_expires_at = op_expires_at;
    if (reservehash && bin2hex(reservehash->b, sizeof(reservehash->b), hashop->id, sizeof(hashop->id)/2 + 1))
        WARN("bin2hex failed");
    if (idhash) {
        if (bin2hex(idhash->b, sizeof(idhash->b), hashop->id + sizeof(hashop->id)/2, sizeof(hashop->id)/2 + 1))
            WARN("bin2hex failed");
        if (!reservehash)
            memcpy(hashop->id, hashop->id + sizeof(hashop->id)/2, sizeof(hashop->id)/2);
    }
    if (!idhash && !reservehash && kind != HASHOP_CHECK)
        WARN("empty id");
    hashop->id[sizeof(hashop->id)-1] = '\0';
    DEBUG("id: %s", hashop->id);
    sxc_clearerr(sxi_conns_get_client(conns));
}

struct hashop_ctx {
    yajl_handle yh;
    char *hexhashes;
    sxi_query_t *query;
    enum { MISS_ERROR, MISS_BEGIN, MISS_MAP, MISS_PRESENCE, MISS_ARRAY, MISS_COMPLETE } state;
    unsigned idx;
    int idxs[DOWNLOAD_MAX_BLOCKS];
    sxi_hashop_t *hashop;
    curlev_context_t *cbdata;
    struct cb_error_ctx errctx;
};

static int cb_presence_start_map(void *ctx) {
    struct hashop_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    if (yactx->state != MISS_BEGIN) {
	WARN("bad state %d", yactx->state);
	return 0;
    }
    yactx->state = MISS_MAP;
    return 1;
}

static int cb_presence_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct hashop_ctx *yactx = ctx;
    if (!yactx)
        return 0;
/*    if (yactx->state == MISS_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);*/
    if (yactx->state == MISS_MAP) {
/*        if (ya_check_error(yactx->sx, &yactx->errctx, s, l)) {
            yactx->state = MISS_ERROR;
            return 1;
        }*/
	if(l == lenof("presence") && !memcmp(s, "presence", lenof("presence"))) {
            yactx->state = MISS_PRESENCE;
            return 1;
        }
        WARN("unknown key %.*s", (int)l, s);
        return 0;
    }

    WARN("bad state %d", yactx->state);
    return 0;
}

static int cb_presence_string(void *ctx, const unsigned char *s, size_t l) {
    struct hashop_ctx *yactx = ctx;
    if (!yactx)
        return 0;
/*    if (yactx->state == MISS_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);*/
    WARN("unexpected string");
    return 0;
}

static int cb_presence_boolean(void *ctx, int boolean) {
    struct hashop_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    sxi_hashop_t *hashop = yactx->hashop;
    if (!hashop) {
        WARN("NULL hashop");
        return 0;
    }
    if (yactx->state == MISS_ARRAY) {
        unsigned maxidx, mapped_idx;
        const char *q = yactx->hexhashes;

        if (!q) {
            WARN("NULL hexhashes");
            return 0;
        }
        maxidx = strlen(q) / SXI_SHA1_TEXT_LEN;
        if (yactx->idx >= maxidx || yactx->idx >= DOWNLOAD_MAX_BLOCKS) {
            WARN("index out of bounds: %d out of [0,%d)", yactx->idx, maxidx);
            return 0;
        }
        q += yactx->idx * SXI_SHA1_TEXT_LEN;
        mapped_idx = yactx->idxs[yactx->idx];
        DEBUG("Hash index %d (%d) status: %d", mapped_idx, yactx->idx, boolean);
        if (boolean) {
            if (hashop->cb && hashop->cb(q, mapped_idx, 200, hashop->context) == -1)
                hashop->cb_fail++;
            hashop->ok++;
        } else {
            if (hashop->cb && hashop->cb(q, mapped_idx, 404, hashop->context) == -1)
                hashop->cb_fail++;
            hashop->enoent++;
        }
        yactx->idx++;
        hashop->finished++;
	return 1;
    }

    WARN("bad state %d", yactx->state);
    return 0;
}

static int cb_presence_start_array(void *ctx) {
    struct hashop_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    if(yactx->state != MISS_PRESENCE) {
	WARN("bad state %d", yactx->state);
	return 0;
    }

    yactx->state = MISS_ARRAY;
    return 1;
}

static int cb_presence_end_array(void *ctx) {
    struct hashop_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    if(yactx->state != MISS_ARRAY)
	return 0;
    yactx->state = MISS_MAP;
    return 1;
}

static int cb_presence_end_map(void *ctx) {
    struct hashop_ctx *yactx = ctx;
    if(!ctx)
	return 0;

/*    if (yactx->state == MISS_ERROR)
        return yacb_error_end_map(&yactx->errctx);*/
    if(yactx->state == MISS_MAP) {
	yactx->state = MISS_COMPLETE;
        return 1;
    }
    WARN("bad state %d", yactx->state);
    return 0;
}

static const yajl_callbacks presence_parser = {
    cb_fail_null,
    cb_presence_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_presence_string,
    cb_presence_start_map,
    cb_presence_map_key,
    cb_presence_end_map,
    cb_presence_start_array,
    cb_presence_end_array
};

static int presence_setup_cb(curlev_context_t *cbdata, const char *host) {
    struct hashop_ctx *yactx = sxi_cbdata_get_hashop_ctx(cbdata);

    if(yactx->yh)
	yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh  = yajl_alloc(&presence_parser, NULL, yactx))) {
	CBDEBUG("OOM allocating yajl context");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Failed to setup hashop: out of memory");
	return 1;
    }

    yactx->idx = 0;
    yactx->state = MISS_BEGIN;
    return 0;
}

static void batch_finish(curlev_context_t *ctx, const char *url)
{
    struct hashop_ctx *yactx = sxi_cbdata_get_hashop_ctx(ctx);
    long status = 0;
    int rc = sxi_cbdata_result(ctx, NULL, NULL, &status);
    if (!yactx) {
        WARN("NULL context");
        return;
    }
    sxi_query_free(yactx->query);

    sxi_hashop_t *hashop = yactx->hashop;
    if (!hashop) {
        WARN("NULL hashop");
        return;
    }

    char *q;
    q = yactx->hexhashes;
    if (!q) {
        WARN("NULL hexhashes");
        return;
    }
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(ctx));
    yajl_handle yh = yactx->yh;

    SXDEBUG("batch_finish for %s (%p) : %ld", yactx->hexhashes, yactx->hexhashes, status);
    if (rc != -1 && status == 200) {
        /* some hashes (maybe all) are present,
         * the server reports us the presence ones */
        if (!yh) {
            sxi_cbdata_seterr(ctx, SXE_EARG, "null yajl handle");
            hashop->cb_fail++;
        } else if(yajl_complete_parse(yh) != yajl_status_ok || yactx->state != MISS_COMPLETE) {
            sxi_cbdata_seterr(ctx, SXE_ECOMM, "hashop failed: failed to parse cluster response");
            hashop->cb_fail++;
        }
    } else {
        unsigned i, n = strlen(q) / SXI_SHA1_TEXT_LEN;
        DEBUG("hexhashes missing all: %s (%p)", q, q);
        /* error: report all hashes as missing */
        if (hashop->cb) {
            for (i=0;i<n;i++) {
                int mapped_idx = yactx->idxs[i];
                if (mapped_idx < 0 ) {
                    WARN("uninitialized mapped_idx");
                    continue;
                }
                DEBUG("Hash index %d (%d) status: missing", mapped_idx, i);
                hashop->cb(q + i * SXI_SHA1_TEXT_LEN, mapped_idx, 404, hashop->context);
            }
        }
    }
    if (yh)
        yajl_free(yh);
    free(yactx->hexhashes);
    free(yactx);
}

static int presence_cb(curlev_context_t *ctx, const unsigned char *data, size_t size) {
    struct hashop_ctx *yactx = sxi_cbdata_get_hashop_ctx(ctx);
    if (!yactx) {
        WARN("NULL parser context");
        return 1;
    }
    yajl_handle yh = yactx->yh;
    if (!yh) {
        WARN("NULL yajl handle");
        return 1;
    }
    if(yajl_parse(yh, data, size) != yajl_status_ok) {
	WARN("failed to parse JSON data");
	return 1;
    }

    return 0;
}

static int sxi_hashop_batch(sxi_hashop_t *hashop)
{
    const char *host, *hexhashes;
    unsigned int blocksize, i, n;
    sxi_query_t *query;
    int rc;
    if (!hashop || !hashop->conns)
	return -1;
    host = hashop->current_host;
    hexhashes = hashop->hexhashes;
    if (!host || !hexhashes)
        return -1;
    blocksize = hashop->current_blocksize;
    hashop->hashes[hashop->hashes_pos] = '\0';
    hashop->hexhashes[hashop->hashes_count*SXI_SHA1_TEXT_LEN] = '\0';
    sxc_client_t *sx;

    sx = sxi_conns_get_client(hashop->conns);
    if (hashop->finished > hashop->ok + hashop->enoent) {
	sxi_seterr(sx, SXE_ECOMM, "%d failed HEAD requests",
		   hashop->finished - hashop->ok - hashop->enoent);
	return -1;
    }
    struct hashop_ctx *pp = calloc(1, sizeof(*pp));
    if (!pp) {
        sxi_seterr(sx, SXE_EMEM, "failed to allocate presence parser");
        return -1;
    }
    memcpy(pp->idxs, hashop->idxs_tmp, sizeof(hashop->idxs_tmp));
    curlev_context_t *cbdata = sxi_cbdata_create_hashop(hashop->conns, batch_finish, pp);
    if (!cbdata) {
	sxi_seterr(sx, SXE_EMEM, "failed to allocate callback");
        free(pp);
	return -1;
    }
    pp->hexhashes = strdup(hexhashes);
    if (!pp->hexhashes) {
	sxi_seterr(sx, SXE_EMEM, "failed to allocate hashbatch");
        free(pp);
	free(cbdata);
	return -1;
    }
    pp->hashop = hashop;
    SXDEBUG("a->queries: %d", hashop->queries);
    hashop->queries += strlen(hexhashes) / 40;

    SXDEBUG("hashop %d, on %s, hexhashes: %s (%p)", hashop->hashes_count, hashop->hashes, hashop->hexhashes,
            hashop->hexhashes);
    n = strlen(hexhashes) / SXI_SHA1_TEXT_LEN;
    switch (hashop->kind) {
        case HASHOP_CHECK:
            query = sxi_hashop_proto_check(sxi_conns_get_client(hashop->conns), blocksize, hashop->hashes, hashop->hashes_pos);
            break;
        case HASHOP_RESERVE:
            query = sxi_hashop_proto_reserve(sxi_conns_get_client(hashop->conns), blocksize, hashop->hashes, hashop->hashes_pos, hashop->id, hashop->op_expires_at);
            break;
        case HASHOP_DELETE:/* fall-through */
        case HASHOP_INUSE:
            DEBUG("inuse id: %s", hashop->id);
            query = sxi_hashop_proto_inuse_begin(sxi_conns_get_client(hashop->conns), SX_ID_TOKEN, hashop->id, hashop->op_expires_at);
            for (i=0;i < n;i++) {
                block_meta_entry_t entry;
                block_meta_t meta;
                if (hex2bin(hexhashes + i * SXI_SHA1_TEXT_LEN, SXI_SHA1_TEXT_LEN, meta.hash.b, sizeof(meta.hash.b))) {
                    sxi_query_free(query);
                    query = NULL;
                    break;
                }
                entry.replica = hashop->replica;
                entry.count = hashop->kind == HASHOP_INUSE ? 1 : -1;
                meta.entries = &entry;
                meta.count = 1;
                meta.blocksize = hashop->current_blocksize;
                query = sxi_hashop_proto_inuse_hash(sx, query, &meta);
            }
            query = sxi_hashop_proto_inuse_end(sx, query);
            break;
        default:
            query = NULL;
            break;
    }
    pp->query = query;
    if (query) {
        DEBUG("Sending query to %s", query->path);
        rc = sxi_cluster_query_ev(cbdata, hashop->conns, host, query->verb, query->path, query->content, query->content_len, presence_setup_cb, presence_cb);
    } else {
        free(pp->hexhashes);
        sxi_query_free(pp->query);
        free(pp);
        rc = -1;
    }
    sxi_cbdata_unref(&cbdata);
    return rc;
}

int sxi_hashop_batch_flush(sxi_hashop_t *hashop)
{
    int rc = 0;
    if (hashop->hashes_count > 0)
        rc = sxi_hashop_batch(hashop);
    memset(hashop->idxs_tmp, -1, sizeof(hashop->idxs_tmp));
    hashop->hashes_count = hashop->hashes_pos = 0;
    return rc;
}

int sxi_hashop_batch_add(sxi_hashop_t *hashop, const char *host, unsigned idx, const unsigned char *binhash, unsigned int blocksize)
{
    unsigned hidx;
    int rc = 0;
    sxc_client_t *sx;
    if (!hashop)
        return -1;
    sx = sxi_conns_get_client(hashop->conns);
    if (!host || !binhash) {
        sxi_seterr(sx, SXE_EARG, "Null arg to hashop_batch_add");
        return -1;
    }
    if ((hashop->current_host && strcmp(host, hashop->current_host)) || blocksize != hashop->current_blocksize || hashop->hashes_count >= DOWNLOAD_MAX_BLOCKS) {
        rc = sxi_hashop_batch_flush(hashop);
    }
    hashop->current_host = host;
    hashop->current_blocksize = blocksize;
    hidx = hashop->hashes_count * SXI_SHA1_TEXT_LEN;
    if (hashop->hashes_pos + SXI_SHA1_TEXT_LEN + 1 >= sizeof(hashop->hashes) ||
        hidx + SXI_SHA1_TEXT_LEN >= sizeof(hashop->hexhashes)) {
        sxi_seterr(sx, SXE_EARG, "Out of bounds hashes_pos: %u (limit %lu), hidx: %u (limit %lu)",
                   hashop->hashes_pos, (long)sizeof(hashop->hashes),
                   hidx, (long)sizeof(hashop->hexhashes));
        return -1;
    }
    sxi_bin2hex(binhash, SXI_SHA1_BIN_LEN, hashop->hashes + hashop->hashes_pos);
    memcpy(hashop->hexhashes + hidx, hashop->hashes + hashop->hashes_pos, SXI_SHA1_TEXT_LEN);
    SXDEBUG("hash @%d (%d): %.*s", idx, hashop->hashes_count, SXI_SHA1_TEXT_LEN, hashop->hashes + hashop->hashes_pos);
    hashop->hashes_pos += SXI_SHA1_TEXT_LEN;
    hashop->hashes[hashop->hashes_pos++] = ',';
    hashop->idxs_tmp[hashop->hashes_count] = idx;
    hashop->hashes_count++;
    SXDEBUG("returning: %d", rc);
    return rc;
}

int sxi_hashop_end(sxi_hashop_t *hashop)
{
    int rc = 0;
    if (!hashop || !hashop->conns)
	return -1;
    rc = sxi_hashop_batch_flush(hashop);
    while (hashop->finished != hashop->queries && !sxi_curlev_poll(sxi_conns_get_curlev(hashop->conns))) {
/*        syslog(LOG_INFO,"finished: %d, queries: %d", hashop->finished,
 *        hashop->queries);*/
    }
    if (hashop->finished > hashop->ok + hashop->enoent) {
	/* TODO: overwrite error msg or not? */
	sxi_seterr(sxi_conns_get_client(hashop->conns), SXE_ECOMM, "%d failed HEAD requests",
		   hashop->finished - hashop->ok - hashop->enoent);
	return -1;
    } else if (hashop->finished != hashop->queries) {
	sxi_seterr(sxi_conns_get_client(hashop->conns), SXE_ECOMM, "%d unfinished HEAD requests",
		   hashop->queries - hashop->finished);
	return -1;
    }
    if (hashop->cb_fail) {
	sxi_seterr(sxi_conns_get_client(hashop->conns), SXE_ECOMM, "%d callback failures",
		   hashop->cb_fail);
	return -1;
    }
    if (hashop->enoent) {
        sxc_client_t *sx = sxi_conns_get_client(hashop->conns);
        SXDEBUG("enoent: %d", hashop->enoent);
	return ENOENT;
    }
    if (!rc)
        sxc_clearerr(sxi_conns_get_client(hashop->conns));
    return rc;
}
