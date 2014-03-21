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
#include <yajl/yajl_parse.h>

#include "fcgi-utils.h"
#include "utils.h"
#include "blob.h"

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

    if(*hpath != '/')
	quit_errmsg(404, "Path must begin with /");
    while(*hpath == '/')
	hpath++;
    urlen = strlen(hpath);
    if(!urlen || urlen % HASH_TEXT_LEN)
	quit_errmsg(400, "Invalid url length: not multiple of hash length");
    if(urlen > DOWNLOAD_MAX_BLOCKS * HASH_TEXT_LEN)
	quit_errmsg(414, "Too many blocks requested in batch download");

    urlen /= HASH_TEXT_LEN;
    for(i=0; i<urlen; i++) {
	if(hex2bin(hpath + HASH_TEXT_LEN*i, HASH_TEXT_LEN, reqhash.b, HASH_BIN_LEN)) {
            msg_set_reason("Invalid hash %*.s", HASH_TEXT_LEN, hpath + HASH_TEXT_LEN * i);
            quit_errmsg(400,"invalid hash");
        }
	s = sx_hashfs_block_get(hashfs, blocksize, &reqhash, NULL);
	if(s == ENOENT || s == FAIL_BADBLOCKSIZE)
	    quit_errmsg(404, "Block not found");
        else if(s != OK) {
            msg_set_reason("Failed to read block with hash %.*s", HASH_TEXT_LEN, hpath + HASH_TEXT_LEN*i);
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
	if(hex2bin(hpath + HASH_TEXT_LEN*i, HASH_TEXT_LEN, reqhash.b, HASH_BIN_LEN))
	    break;
	if(sx_hashfs_block_get(hashfs, blocksize, &reqhash, &data) != OK)
	    break;
	CGI_PUTD(data, blocksize);
    }
}

#define GC_HASHOP_PERIOD 60

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
    rc_ty rc;
    unsigned missing = 0;
    const char *id;
    int comma = 0;
    unsigned idx = 0;

    auth_complete();
    quit_unless_authed();

    id = get_arg("id");

    blocksize = strtol(path, (char **)&hpath, 10);
    if(*hpath != '/')
	quit_errmsg(404, "Path must begin with /");
    while(*hpath == '/')
	hpath++;
    rc = sx_hashfs_hashop_begin(hashfs, blocksize);
    if (rc) {
        msg_set_reason("Failed to reserve hashes: %s", rc2str(rc));
        quit_errmsg(500, msg_get_reason());
    }
    CGI_PUTS("Content-type: application/json\r\n\r\n{\"presence\":[");
    while (*hpath) {
        int present;
        if(hex2bin(hpath, HASH_TEXT_LEN, reqhash.b, HASH_BIN_LEN)) {
            msg_set_reason("Invalid hash %*.s", HASH_TEXT_LEN, hpath);
            rc = EINVAL;
            break;
        }
        hpath += HASH_TEXT_LEN;
        if (*hpath++ != ',') {
            CGI_PUTC(']');
            quit_itererr("bad URL format for hashop", 400);
        }
        n++;
        rc = sx_hashfs_hashop_perform(hashfs, kind, &reqhash, id);
        present = rc == OK;
        if (comma)
            CGI_PUTC(',');
        /* the presence callback wants an index not the actual hash...
         * */
        CGI_PUTS(present ? "true" : "false");
        DEBUGHASH("Status sent for ", &reqhash);
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
    rc = sx_hashfs_hashop_finish(hashfs, rc);
    if (rc != OK) {
        WARN("hashop: %s", rc2str(rc));
        CGI_PUTC(']');
        quit_itererr(msg_get_reason(), rc2http(rc));
    }
    CGI_PUTS("]}");
    DEBUG("hashop: missing %d, n: %d", missing, n);
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
