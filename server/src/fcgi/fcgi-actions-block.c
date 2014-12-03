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

#include "default.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <yajl/yajl_parse.h>

#include "fcgi-utils.h"
#include "utils.h"
#include "blob.h"
#include "fcgi-actions-block.h"

void fcgi_send_blocks(void) {
    unsigned int blocksize;
    const uint8_t *data;
    sx_hash_t reqhash;
    const char *hpath;
    const char *cond;
    int i, urlen;
    rc_ty s;

    blocksize = strtol(path, (char **)&hpath, 10);
    if(sx_hashfs_check_blocksize(blocksize))
	quit_errmsg(404, "The requested block size does not exist");

    if(*hpath != '/') {
        msg_set_reason("Path must begin with / after blocksize: %s", path);
        quit_errmsg(404, msg_get_reason());
    }
    while(*hpath == '/')
	hpath++;
    urlen = strlen(hpath);
    if(!urlen || urlen % SXI_SHA1_TEXT_LEN)
	quit_errmsg(400, "Invalid url length: not multiple of hash length");
    if(urlen > DOWNLOAD_MAX_BLOCKS * SXI_SHA1_TEXT_LEN)
	quit_errmsg(414, "Too many blocks requested in batch download");

    urlen /= SXI_SHA1_TEXT_LEN;
    for(i=0; i<urlen; i++) {
	if(hex2bin(hpath + SXI_SHA1_TEXT_LEN*i, SXI_SHA1_TEXT_LEN, reqhash.b, SXI_SHA1_BIN_LEN)) {
            msg_set_reason("Invalid hash %*.s", SXI_SHA1_TEXT_LEN, hpath + SXI_SHA1_TEXT_LEN * i);
            quit_errmsg(400,"invalid hash");
        }
	s = sx_hashfs_block_get(hashfs, blocksize, &reqhash, NULL);
	if(s == ENOENT || s == FAIL_BADBLOCKSIZE)
	    quit_errmsg(404, "Block not found");
        else if(s != OK) {
            msg_set_reason("Failed to read block with hash %.*s", SXI_SHA1_TEXT_LEN, hpath + SXI_SHA1_TEXT_LEN*i);
	    quit_errmsg(500, msg_get_reason());
        }
    }

    /* Marking the block resources as freely shareable by caches without revalidation
     * Rationale is that if you can sniff/guess the hashes then all bets are off anyway
     * Authentication on block retrieval is essentially in place for accounting reasons
     * and abuse prevention, none of which applies if the content is served by a cache */
    CGI_PUTS("Cache-control: public\r\nLast-Modified: ");
    send_httpdate(0);
    CGI_PUTS("\r\nExpires: ");
    send_httpdate(time(NULL) + 60*60*24*365); /* as per rfc2616 */
    if((cond = FCGX_GetParam("HTTP_IF_MODIFIED_SINCE", envp))) {
	time_t modsince;
	if(!httpdate_to_time_t(cond, &modsince) && modsince >= 0) {
	    CGI_PUTS("\r\nStatus: 304\r\n\r\n");
	    return;
	}
    }

    CGI_PRINTF("\r\nContent-type: application/octet-stream\r\nContent-Length: %u\r\n\r\n", blocksize*urlen);

    if(verb == VERB_HEAD)
	return;

    for(i=0; i<urlen; i++) {
	if(hex2bin(hpath + SXI_SHA1_TEXT_LEN*i, SXI_SHA1_TEXT_LEN, reqhash.b, SXI_SHA1_BIN_LEN))
	    break;
	if(sx_hashfs_block_get(hashfs, blocksize, &reqhash, &data) != OK)
	    break;
	CGI_PUTD(data, blocksize);
    }
}

#define DEBUGHASH(MSG, X) do {				\
    char _debughash[sizeof(sx_hash_t)*2+1];		\
    if (UNLIKELY(sxi_log_is_debug(&logger))) {          \
        bin2hex((X)->b, sizeof(*X), _debughash, sizeof(_debughash));	\
        DEBUG("%s: #%s#", MSG, _debughash); \
    }\
    } while(0)
void fcgi_hashop_blocks(enum sxi_hashop_kind kind) {
    unsigned blocksize, n=0;
    const char *hpath;
    sx_hash_t reqhash;
    rc_ty rc = OK;
    unsigned missing = 0;
    const char *id, *expires;
    char *end = NULL;
    int comma = 0;
    unsigned idx = 0;
    uint64_t op_expires_at;

    auth_complete();
    quit_unless_authed();

    id = get_arg("id");
    expires = get_arg("op_expires_at");
    if (kind != HASHOP_CHECK) {
        if (!id || !expires)
            quit_errmsg(400, "Missing id/expires");
        op_expires_at = strtoll(expires, &end, 10);
        if (!end || *end)
            quit_errmsg(400, "Invalid number for op_expires_at");
    } else
        op_expires_at = 0;

    blocksize = strtol(path, (char **)&hpath, 10);
    if(*hpath != '/') {
        msg_set_reason("Path must begin with / after blocksize: %s", path);
        quit_errmsg(404, msg_get_reason());
    }
    while(*hpath == '/')
	hpath++;
    CGI_PUTS("Content-type: application/json\r\n\r\n{\"presence\":[");
    while (*hpath) {
	int present;
        if(hex2bin(hpath, SXI_SHA1_TEXT_LEN, reqhash.b, SXI_SHA1_BIN_LEN)) {
            msg_set_reason("Invalid hash %*.s", SXI_SHA1_TEXT_LEN, hpath);
            rc = EINVAL;
            break;
        }
        hpath += SXI_SHA1_TEXT_LEN;
        if (*hpath++ != ',') {
            CGI_PUTC(']');
            quit_itererr("bad URL format for hashop", EINVAL);
        }
        n++;
        rc = sx_hashfs_hashop_perform(hashfs, blocksize, 0, kind, &reqhash, id, op_expires_at, &present);
        if (comma)
            CGI_PUTC(',');
        /* the presence callback wants an index not the actual hash...
         * */
        CGI_PUTS(present ? "true" : "false");
        DEBUGHASH("Status sent for ", &reqhash);
	DEBUG("Hash index %d, present: %d", idx, present);
        comma = 1;
        if (rc != OK)
                break;
        idx++;
    }
    if (rc != OK) {
        WARN("hashop: %s", rc2str(rc));
        CGI_PUTC(']');
        quit_itererr(msg_get_reason(), rc);
    }
    CGI_PUTS("]}");
    DEBUG("hashop: missing %d, n: %d", missing, n);
}

static int meta_add(block_meta_t *meta, unsigned replica, int64_t count)
{
    block_meta_entry_t *e;
    if (!meta)
        return -1;
    meta->entries = wrap_realloc_or_free(meta->entries, ++meta->count * sizeof(*meta->entries));
    if (!meta->entries)
        return -1;
    e = &meta->entries[meta->count - 1];
    e->replica = replica;
    e->count = count;
    return 0;
}

static int all_add(blocks_t *all, const block_meta_t *m)
{
    if (!all)
        return -1;
    all->all = wrap_realloc_or_free(all->all, ++all->n * sizeof(*all->all));
    if (!all->all)
        return -1;
    memcpy(&all->all[all->n - 1], m, sizeof(*m));
    return 0;
}

struct inuse_ctx {
    rc_ty error;
    block_meta_t meta;
    blocks_t all;
    unsigned replica;
    unsigned blocksize;
    enum inuse_state { CB_IU_START, CB_IU_MAP, CB_IU_HASH, CB_IU_VALUES, CB_IU_BLOCKSIZE, CB_IU_REPLICA, CB_IU_COMPLETE  } state;
};

static int cb_inuse_number(void *ctx, const char *s, size_t l)
{
    char numb[24], *enumb;
    int64_t nnumb;
    struct inuse_ctx *yactx = (struct inuse_ctx*)ctx;
    if (!yactx)
        return 0;
    if(l > 20) {
	DEBUG("number too long (%u bytes)", (unsigned)l);
	return 0;
    }
    if (yactx->state != CB_IU_REPLICA && yactx->state != CB_IU_BLOCKSIZE) {
        DEBUG("bad number state %d", yactx->state);
        return 0;
    }
    memcpy(numb, s, l);
    numb[l] = '\0';
    nnumb = strtoll(numb, &enumb, 10);
    if(*enumb) {
	DEBUG("failed to parse number %.*s", (int)l, s);
	return 0;
    }

    if (yactx->state == CB_IU_BLOCKSIZE) {
        DEBUG("blocksize: %lld", (long long)nnumb);
        yactx->meta.blocksize = nnumb;
        yactx->replica = 0;
        yactx->state = CB_IU_VALUES;
        return 1;
    }

    if (!yactx->replica) {
        DEBUG("zero replica");
        return 0;
    }

    if (meta_add(&yactx->meta, yactx->replica, nnumb)) {
        DEBUG("meta_add failed");
        return 0;
    }
    yactx->replica = 0;
    yactx->state = CB_IU_VALUES;
    return 1;
}

static int cb_inuse_start_map(void *ctx) {
    struct inuse_ctx *yactx = (struct inuse_ctx*)ctx;
    if (!yactx) {
        DEBUG("null yactx");
        return 0;
    }
    switch (yactx->state) {
        case CB_IU_START:
            yactx->state = CB_IU_MAP;
            break;
        case CB_IU_HASH:
            yactx->state = CB_IU_VALUES;
            break;
        default:
            DEBUG("bad map state: %d", yactx->state);
            return 0;
    }
    DEBUG("start_map OK");
    return 1;
}

static int cb_inuse_end_map(void *ctx) {
    struct inuse_ctx *yactx = (struct inuse_ctx*)ctx;
    if (!yactx)
        return 0;
    switch (yactx->state) {
        case CB_IU_MAP:
            yactx->state = CB_IU_COMPLETE;
            break;
        case CB_IU_VALUES:
            if (all_add(&yactx->all, &yactx->meta)) {
                free(yactx->meta.entries);
                return 0;
            }
            memset(&yactx->meta, 0, sizeof(yactx->meta));
            yactx->state = CB_IU_MAP;
            break;
        default:
            DEBUG("bad map state: %d", yactx->state);
            return 0;
    }
    return 1;
}

static int cb_inuse_map_key(void *ctx, const unsigned char *s, size_t l) {
    char numb[24], *enumb;
    int64_t nnumb;
    struct inuse_ctx *yactx = (struct inuse_ctx*)ctx;
    if (!yactx)
        return 0;
    switch (yactx->state) {
        case CB_IU_MAP:
            yactx->state = CB_IU_HASH;
            memset(&yactx->meta, 0, sizeof(yactx->meta));
            if(hex2bin(s, l, (uint8_t *)&yactx->meta.hash, sizeof(yactx->meta.hash)))
                return 0;
            break;
        case CB_IU_VALUES:
            if (!strncmp("b", s , l)) {
                yactx->state = CB_IU_BLOCKSIZE;
            } else {
                yactx->state = CB_IU_REPLICA;
                memcpy(numb, s, l);
                numb[l] = '\0';
                nnumb = strtoll(numb, &enumb, 10);
                if(*enumb) {
                    DEBUG("failed to parse number %.*s", (int)l, s);
                    return 0;
                }
                yactx->replica = nnumb;
            }
            break;
        default:
            DEBUG("bad map key state: %d", yactx->state);
            return 0;
    }
    return 1;
}

static void blocks_free(blocks_t *blocks)
{
    unsigned i;
    for (i=0;i<blocks->n;i++)
        free(blocks->all[i].entries);
    free(blocks->all);
    blocks->all = NULL;
}

static const yajl_callbacks inuse_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_inuse_number,
    cb_fail_string,
    cb_inuse_start_map,
    cb_inuse_map_key,
    cb_inuse_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

void fcgi_hashop_inuse(void) {
    unsigned i, j;
    rc_ty rc = FAIL_EINTERNAL;
    unsigned missing = 0;
    const char *id, *expires;
    int comma = 0;
    unsigned idx = 0;
    int64_t op_expires_at;
    char *end;

    struct inuse_ctx yctx;
    memset(&yctx, 0, sizeof(yctx));

    id = get_arg("id");
    expires = get_arg("op_expires_at");
    if (!id || !expires)
        quit_errmsg(400, "Missing id/expires");
    op_expires_at = strtoll(expires, &end, 10);
    if (!end || *end)
        quit_errmsg(400, "Invalid number for op_expires_at");

    yajl_handle yh = yajl_alloc(&inuse_parser, NULL, &yctx);
    if (!yh) {
        quit_errmsg(500, "Cannot allocate json parser");
    }
    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0) {
        DEBUG("parsing: %.*s", len, hashbuf);
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) {
            DEBUG("yajl_parse failed on chunk: %.*s", len, hashbuf);
            break;
        }
    }

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_IU_COMPLETE) {
        free(yctx.meta.entries);
        blocks_free(&yctx.all);
        DEBUG("yajl parse failed, state: %d (%d)", yctx.state, CB_IU_COMPLETE);
	yajl_free(yh);
	quit_errmsg(rc2http(yctx.error), (yctx.error == ENOMEM) ? "Out of memory processing the request" : "Invalid request content");
    }
    free(yctx.meta.entries);
    yctx.meta.entries = NULL;
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
        blocks_free(&yctx.all);
	send_authreq();
	return;
    }

    CGI_PUTS("Content-type: application/json\r\n\r\n{\"presence\":[");

    for (i=0;i<yctx.all.n;i++) {
        int present;
        const block_meta_t *m = &yctx.all.all[i];
        rc = FAIL_EINTERNAL;
        for (j=0;j<m->count;j++) {
            const block_meta_entry_t *e = &m->entries[j];
            rc = sx_hashfs_hashop_mod(hashfs, &m->hash, id, m->blocksize, e->replica, e->count, op_expires_at);
            if (rc && rc != ENOENT)
                break;
        }
        present = rc == OK;
        if (comma)
            CGI_PUTC(',');
        /* the presence callback wants an index not the actual hash...
         * */
        CGI_PUTS(present ? "true" : "false");
        DEBUG("Hash index %d, present: %d", idx, present);
        comma = 1;
        if (rc != OK) {
            if (rc == ENOENT)
                rc = OK;
            else
                break;
        }
        idx++;
    }
    blocks_free(&yctx.all);
    if (rc != OK) {
        WARN("hashop: %s", rc2str(rc));
        CGI_PUTC(']');
        quit_itererr(msg_get_reason(), rc);
    }
    CGI_PUTS("]}");
    DEBUG("hashop: missing %d, n: %ld", missing, yctx.all.n);
}

void fcgi_save_blocks(void) {
    unsigned int replica_count;
    unsigned int blocksize;
    int len = content_len();
    const char *token;

    blocksize = strtol(path, (char **)&token, 10);
    if(*token != '/' || sx_hashfs_check_blocksize(blocksize) != OK)
        quit_errnum(404);
    token++;

    if(has_priv(PRIV_CLUSTER)) {  /* FIXME: use a cluster token to avoid arbitrary replays to over-replica nodes */
	/* MODHDIST: WTF?! */
	replica_count = sx_nodelist_count(sx_hashfs_nodelist(hashfs, NL_NEXT));
    } else {
        if(sx_hashfs_token_get(hashfs, user, token, &replica_count, NULL))
            quit_errmsg(400, "Invalid token");
    }

    if(len & (blocksize-1))
	quit_errmsg(400, "Wrong content length");

    if(len > sizeof(hashbuf))
	quit_errnum(413);

    if(get_body_chunk(hashbuf, len) != len)
	quit_errmsg(400, "Block with wrong size");

    auth_complete();
    if(!is_authed())
	quit_errmsg(403, "Bad signature");

    const uint8_t *end = hashbuf + len;
    for(const uint8_t *src = hashbuf;src < end; src += blocksize) {
        rc_ty rc;
        if ((rc = sx_hashfs_block_put(hashfs, src, blocksize, replica_count, !has_priv(PRIV_CLUSTER)))) {
            WARN("Cannot store block: %s", rc2str(rc));
	    quit_errmsg(500, "Cannot store block");
        }
    }
    if(replica_count > 1 && !has_priv(PRIV_CLUSTER))
	sx_hashfs_xfer_trigger(hashfs);

    CGI_PUTS("\r\n");
}

struct pushblox_ctx {
    sx_blob_t *stash;
    rc_ty error;
    enum pushblox_state { CB_PB_START, CB_PB_HASH, CB_PB_TARGETS, CB_PB_TARGET, CB_PB_COMPLETE } state;
};

static int cb_pushblox_start_map(void *ctx) {
    struct pushblox_ctx *c = ctx;
    if(c->state == CB_PB_START)
	c->state = CB_PB_HASH;
    else
	return 0;
    return 1;
}

static int cb_pushblox_end_map(void *ctx) {
    struct pushblox_ctx *c = ctx;
    if(c->state != CB_PB_HASH)
	return 0;

    if(sx_blob_add_blob(c->stash, "", 1)) {
	c->error = ENOMEM;
	return 0;
    }

    c->state = CB_PB_COMPLETE;
    return 1;
}

static int cb_pushblox_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct pushblox_ctx *c = ctx;
    sx_hash_t block;

    if(c->state != CB_PB_HASH)
	return 0;

    c->state = CB_PB_TARGETS;
    if(hex2bin(s, l, (uint8_t *)&block, sizeof(block)))
	return 0;

    if(sx_blob_add_blob(c->stash, &block, sizeof(block))) {
	c->error = ENOMEM;
	return 0;
    }

    return 1;
}

static int cb_pushblox_start_array(void *ctx) {
    struct pushblox_ctx *c = ctx;
    if(c->state == CB_PB_TARGETS)
	c->state = CB_PB_TARGET;
    else
	return 0;
    return 1;
}

static int cb_pushblox_end_array(void *ctx) {
    struct pushblox_ctx *c = ctx;
    if(c->state == CB_PB_TARGET)
	c->state = CB_PB_HASH;
    else
	return 0;
    return 1;
}

static int cb_pushblox_string(void *ctx, const unsigned char *s, size_t l) {
    struct pushblox_ctx *c = ctx;
    char uuidstr[UUID_STRING_SIZE+1];
    sx_uuid_t uuid;

    if(c->state != CB_PB_TARGET)
	return 0;

    if(l != UUID_STRING_SIZE)
	return 0;

    memcpy(uuidstr, s, UUID_STRING_SIZE);
    uuidstr[UUID_STRING_SIZE] = '\0';

    if(uuid_from_string(&uuid, uuidstr))
	return 0;

    if(sx_blob_add_blob(c->stash, uuid.binary, sizeof(uuid.binary))) {
	c->error = ENOMEM;
	return 0;
    }

    return 1;
}

static const yajl_callbacks pushblx_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_pushblox_string,
    cb_pushblox_start_map,
    cb_pushblox_map_key,
    cb_pushblox_end_map,
    cb_pushblox_start_array,
    cb_pushblox_end_array
};


void fcgi_push_blocks(void) {
    struct pushblox_ctx yctx;
    unsigned int blocksize;
    const char *eop;

    blocksize = strtol(path, (char **)&eop, 10);
    if(*eop || sx_hashfs_check_blocksize(blocksize) != OK)
	quit_errmsg(404, "Invalid blocksize");

    yctx.stash = sx_blob_new();
    if(!yctx.stash)
	quit_errmsg(500, "Cannot allocate temporary storage");
    yctx.state = CB_PB_START;
    yctx.error = EINVAL;

    yajl_handle yh = yajl_alloc(&pushblx_parser, NULL, &yctx);
    if(!yh) {
	sx_blob_free(yctx.stash);
	quit_errmsg(500, "Cannot allocate json parser");
    }

    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_PB_COMPLETE) {
	yajl_free(yh);
	sx_blob_free(yctx.stash);
	quit_errmsg(rc2http(yctx.error), (yctx.error == ENOMEM) ? "Out of memory processing the request" : "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
	sx_blob_free(yctx.stash);
	send_authreq();
	return;
    }

    sx_blob_loadpos(yctx.stash); /* Reset blob */

    sx_hash_t block;
    /* MODHDIST: propagate to _next set */
    const sx_nodelist_t *nodes = sx_hashfs_nodelist(hashfs, NL_NEXT);
    sx_nodelist_t *targets = sx_nodelist_new();
    if(!nodes || !targets) {
	sx_nodelist_delete(targets);
	sx_blob_free(yctx.stash);
	quit_errmsg(500, "Cannot allocate node lists");
    }

    while(1) {
	const sx_node_t *target;
	unsigned int ptr_len;
	const void *ptr;
	sx_uuid_t uuid;

	if(sx_blob_get_blob(yctx.stash, &ptr, &ptr_len))
	    ptr_len = 0;

	switch(ptr_len) {
	case sizeof(block):
	case 1:
	    if(sx_nodelist_count(targets)) {
		rc_ty ret = sx_hashfs_xfer_tonodes(hashfs, &block, blocksize, targets);
		if(ret != OK) {
		    sx_nodelist_delete(targets);
		    sx_blob_free(yctx.stash);
		    quit_errmsg(rc2http(ret), msg_get_reason());
		}
		sx_nodelist_empty(targets);
	    }
	    memcpy(&block, ptr, ptr_len);
	    break;

	case sizeof(uuid.binary):
	    uuid_from_binary(&uuid, ptr);
	    target = sx_nodelist_lookup(nodes, &uuid);
	    if(target) {
		if(sx_nodelist_add(targets, sx_node_dup(target)) != OK) {
		    sx_nodelist_delete(targets);
		    sx_blob_free(yctx.stash);
		    quit_errmsg(500, "Out of memory adding target to target list");
		}
	    } else
		WARN("Ignoring request to unknown target node %s", uuid.string);
	    break;

	default:
	    sx_nodelist_delete(targets);
	    sx_blob_free(yctx.stash);
	    quit_errmsg(500, "Internal error detected");
	}

	if(ptr_len == 1)
	    break;
    }

    sx_nodelist_delete(targets);
    sx_blob_free(yctx.stash);
    CGI_PUTS("\r\n");
}

void fcgi_send_replacement_blocks(void) {
    sx_block_meta_index_t bmidx, *bmidxptr = NULL;
    unsigned int version = 0, bytes_sent = 0;
    sx_uuid_t target;
    sx_blob_t *b;

    if(uuid_from_string(&target, get_arg("target")))
	quit_errmsg(400, "Parameter target is not valid");

    if(has_arg("dist")) {
	char *eon;
	version = strtol(get_arg("dist"), &eon, 10);
	if(*eon)
	    version = 0;
    }
    if(version == 0)
	quit_errmsg(400, "Parameter dist missing or invalid");

    if(has_arg("idx")) {
	if(strlen(get_arg("idx")) != sizeof(bmidx) * 2 ||
	   hex2bin(get_arg("idx"), sizeof(bmidx) * 2, (uint8_t *)&bmidx, sizeof(bmidx)))
	    quit_errmsg(400, "Parameter idx is not valid");
	bmidxptr = &bmidx;
    }

    b = sx_blob_new();
    if(!b)
	quit_errmsg(503, "Out of memory");

    CGI_PUTS("\r\n");
    while(bytes_sent < REPLACEMENT_BATCH_SIZE) {
	const uint8_t *blockdata;
	unsigned int header_len, hlenton;
	block_meta_t *bmeta;
	const void *header;
	rc_ty r;

	sx_blob_reset(b);
	r = sx_hashfs_br_find(hashfs, bmidxptr, version, &target, &bmeta);

	if(r == ITER_NO_MORE) {
	    if(sx_blob_add_string(b, "$THEEND$"))
		break;
	} else if(r != OK) {
	    break;
	} else {
	    unsigned int i;
	    if(sx_blob_add_string(b, "$BLOCK$") ||
	       sx_blob_add_int32(b, bmeta->blocksize) ||
	       sx_blob_add_blob(b, &bmeta->hash, sizeof(bmeta->hash)) ||
	       sx_blob_add_blob(b, &bmeta->cursor, sizeof(bmeta->cursor)) ||
	       sx_blob_add_int32(b, bmeta->count)) {
		sx_hashfs_blockmeta_free(&bmeta);
		break;
	    }
	    for(i=0; i<bmeta->count; i++)
		if(sx_blob_add_int32(b, bmeta->entries[i].replica)||
		   sx_blob_add_int32(b, bmeta->entries[i].count))
		    break;
	    if(i < bmeta->count ||
	       sx_hashfs_block_get(hashfs, bmeta->blocksize, &bmeta->hash, &blockdata) != OK) {
		sx_hashfs_blockmeta_free(&bmeta);
		break;
	    }
	}
	sx_blob_to_data(b, &header, &header_len);
	hlenton = htonl(header_len);
	CGI_PUTD(&hlenton, sizeof(hlenton));
	CGI_PUTD(header, header_len);
	bytes_sent += sizeof(hlenton) + header_len;
	if(r == ITER_NO_MORE)
	    break;

	CGI_PUTD(blockdata, bmeta->blocksize);
	bytes_sent += bmeta->blocksize;
	memcpy(&bmidx, &bmeta->cursor, sizeof(bmidx));
	bmidxptr = &bmidx;
	sx_hashfs_blockmeta_free(&bmeta);
    }
    sx_blob_free(b);
}
