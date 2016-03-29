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

#include "fcgi-utils.h"
#include "utils.h"
#include "blob.h"
#include "fcgi-actions-block.h"
#include "job_common.h"
#include "libsxclient/src/jparse.h"

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
    const char *reserve_id, *revision_id, *expires, *global_vol_id;
    char *end = NULL;
    int comma = 0;
    unsigned idx = 0;
    uint64_t op_expires_at;
    unsigned replica;

    auth_complete();
    quit_unless_authed();

    reserve_id = get_arg("reserve_id");
    revision_id = get_arg("revision_id");
    global_vol_id = get_arg("global_vol_id");
    expires = get_arg("op_expires_at");
    replica = get_arg_uint("replica");
    if (replica == -1) replica = 0;
    if (kind != HASHOP_CHECK) {
        if (!reserve_id || !revision_id || !expires || !global_vol_id)
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
        sx_hash_t reserve_hash, revision_hash, volume_hash;
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
        switch (kind) {
            case HASHOP_RESERVE:
                if (hex2bin(reserve_id, strlen(reserve_id), reserve_hash.b, sizeof(reserve_hash.b)) ||
                    hex2bin(revision_id, strlen(revision_id), revision_hash.b, sizeof(revision_hash.b)) ||
                    hex2bin(global_vol_id, strlen(global_vol_id), volume_hash.b, sizeof(volume_hash.b))) {
                    msg_set_reason("Invalid hash(es): %s, %s, %s", reserve_id, revision_id, global_vol_id);
                    rc = EINVAL;
                    break;
                }
                rc = sx_hashfs_hashop_perform(hashfs, blocksize, replica, HASHOP_RESERVE, &reqhash, &volume_hash, &reserve_hash, &revision_hash, op_expires_at, &present);
                break;
            case HASHOP_CHECK:
                rc = sx_hashfs_hashop_perform(hashfs, blocksize, 0, HASHOP_CHECK, &reqhash, NULL, NULL, NULL, 0, &present);
                break;
            default:
                WARN("unexpected kind: %d", kind);
                rc = EINVAL;
                break;
        }
        if (comma)
            CGI_PUTC(',');
        if (rc != OK)
                break;
        /* the presence callback wants an index not the actual hash...
         * */
        CGI_PUTS(present ? "true" : "false");
        DEBUGHASH("Status sent for ", &reqhash);
	DEBUG("Hash index %d, present: %d", idx, present);
        comma = 1;
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

static int meta_add(block_meta_t *meta, unsigned replica, const sx_hash_t *global_vol_id, const sx_hash_t *revision_id)
{
    block_meta_entry_t *e;
    if (!meta || !revision_id)
        return -1;
    meta->entries = wrap_realloc_or_free(meta->entries, ++meta->count * sizeof(*meta->entries));
    if (!meta->entries)
        return -1;
    e = &meta->entries[meta->count - 1];
    memcpy(&e->global_vol_id, global_vol_id, sizeof(e->global_vol_id));
    memcpy(&e->revision_id, revision_id, sizeof(e->revision_id));
    e->replica = replica;
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
};

/*
 * BOB: Maybe we could skip the replica argument if we provide the volume ID, since replica seems to
 *      depend on the volume replica.
 */

/* Example:
   {"BLOCKHASH":{"BLOCKSIZE":[ {"GLOBAL_VOL_ID|REVISION_HASH": REPLICA_COUNT, ...}, ...]}, ...}
{
  "10c91e6b2aecaa5e731fbd7ac26fa3d847dd4ac2": {
    "16384": [
      {
        "b6972d2ecbfd2e41f3b207310b5fa4708d6fcee92ca3d1a4d2d70d03d301c173ce70fca11d29bfbf": 3
      }
    ]
  },
  "69ad191523992b70d85fdd50072933bf3b6d8624": {
    "16384": [
      {
        "b6972d2ecbfd2e41f3b207310b5fa4708d6fcee92ca3d1a4d2d70d03d301c173ce70fca11d29bfbf": 3
      }
    ]
  },
  "9259e1f7daaa152241db155478a027e096dad979": {
    "16384": [
      {
        "b6972d2ecbfd2e41f3b207310b5fa4708d6fcee92ca3d1a4d2d70d03d301c173ce70fca11d29bfbf": 3
      }
    ]
  }
}
*/


static void cb_inuse_rpl(jparse_t *J, void *ctx, int64_t num) {
    const char *blockstr = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    const char *bsstr = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    const char *revstr = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
    struct inuse_ctx *yactx = (struct inuse_ctx*)ctx;
    sx_hash_t revision_id, global_vol_id;
    const char *eon;
    int64_t bs;

    if(strlen(blockstr) != sizeof(yactx->meta.hash) * 2 ||
       hex2bin(blockstr, sizeof(yactx->meta.hash) * 2, (uint8_t *)&yactx->meta.hash, sizeof(yactx->meta.hash))) {
	sxi_jparse_cancel(J, "Invalid block %s", blockstr);
	yactx->error = EINVAL;
	return;
    }

    bs = strtoll(bsstr, (char **)&eon, 10);
    if(*eon || bs < 0 || bs > 0xffffffff) {
	sxi_jparse_cancel(J, "Invalid block size %s for block %s", bsstr, blockstr);
	yactx->error = EINVAL;
	return;
    }
    yactx->meta.blocksize = bs;

    if(strlen(revstr) != 2 * (sizeof(revision_id.b) + sizeof(global_vol_id.b)) ||
       hex2bin(revstr, sizeof(global_vol_id.b) * 2, global_vol_id.b, sizeof(global_vol_id.b)) ||
       hex2bin(revstr + SXI_SHA1_TEXT_LEN, sizeof(revision_id.b) * 2, revision_id.b, sizeof(revision_id.b))) {
	sxi_jparse_cancel(J, "Invalid revision id %s for block %s", revstr, blockstr);
	yactx->error = EINVAL;
	return;
    }

    if(num < 0 || num > 0xffffffff) {
	sxi_jparse_cancel(J, "Invalid replica count %lld for block %s", (long long)num, blockstr);
	yactx->error = EINVAL;
	return;
    }

    if (meta_add(&yactx->meta, num, &global_vol_id, &revision_id)) {
	sxi_jparse_cancel(J, "meta_add failed");
	yactx->error = ENOMEM;
	return;
    }
}

static void cb_inuse_bsend(jparse_t *J, void *ctx) {
    struct inuse_ctx *yactx = (struct inuse_ctx*)ctx;

    if (all_add(&yactx->all, &yactx->meta)) {
	free(yactx->meta.entries);
	sxi_jparse_cancel(J, "add_all failed");
	yactx->error = ENOMEM;
	return;
    }
    memset(&yactx->meta, 0, sizeof(yactx->meta));
}

static void blocks_free(blocks_t *blocks)
{
    unsigned i;
    for (i=0;i<blocks->n;i++)
        free(blocks->all[i].entries);
    free(blocks->all);
    blocks->all = NULL;
}

void fcgi_hashop_inuse(void) {
    const struct jparse_actions acts = {
	JPACTS_INT64(
		     JPACT(cb_inuse_rpl,
			   JPANYKEY /* block */,
			   JPANYKEY /* block size */,
			   JPANYITM,
			   JPANYKEY /* global volume id and revision */
			   )
		     ),
	JPACTS_MAP_END(
		       JPACT(cb_inuse_bsend, JPANYKEY)
		       ),
    };
    unsigned i, j;
    rc_ty rc = FAIL_EINTERNAL;
    unsigned missing = 0;
    const char *reserve_id;
    int comma = 0;
    unsigned idx = 0;
    sx_hash_t reserve_hash;
    jparse_t *J;

    struct inuse_ctx yctx;
    memset(&yctx, 0, sizeof(yctx));

    reserve_id = get_arg("reserve_id");
    if (reserve_id &&
        hex2bin(reserve_id, strlen(reserve_id), reserve_hash.b, sizeof(reserve_hash.b))) {
        msg_set_reason("bad reserve id: %s", reserve_id);
        quit_errmsg(400, "Bad reserve id");
    }

    if(!(J = sxi_jparse_create(&acts, &yctx, 0)))
        quit_errmsg(500, "Cannot allocate json parser");

    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0) {
        DEBUG("parsing: %.*s", len, hashbuf);
	if(sxi_jparse_digest(J, hashbuf, len)) {
            DEBUG("Failed to parse JSON: %s", sxi_jparse_geterr(J));
            break;
        }
    }

    if(len || sxi_jparse_done(J)) {
	WARN("Parsing failed: %s", sxi_jparse_geterr(J));
        free(yctx.meta.entries);
        blocks_free(&yctx.all);
	send_error(rc2http(yctx.error), sxi_jparse_geterr(J));
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);
    free(yctx.meta.entries);
    yctx.meta.entries = NULL;

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
            rc = sx_hashfs_hashop_mod(hashfs, &m->hash, &e->global_vol_id, reserve_id ? &reserve_hash : NULL, &e->revision_id, m->blocksize, e->replica, 1, 0);
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
	replica_count = 0; /* convention to mean just take the f** block and stfu - see sx_hashfs_block_put */
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
	/* Maximum replica used here;
	 * block_put internally skips ignored nodes and only propagates to effective nodes */
        if ((rc = sx_hashfs_block_put(hashfs, src, blocksize, replica_count, uid))) {
            WARN("Cannot store block: %s", rc2str(rc));
	    quit_errmsg(500, "Cannot store block");
        }
    }
    if(replica_count > 1)
	sx_hashfs_xfer_trigger(hashfs);

    CGI_PUTS("\r\n");
}

/* {"hash1":["uuid1", "uuid2"], "hash2":["uuid3", "uuid1"], ...} */
struct pushblox_ctx {
    sx_blob_t *stash;
    rc_ty error;
};

void cb_pushblox_target(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    jploc_t *lkey = sxi_jparse_whereami(J), *lhost = sxi_jpath_down(lkey);
    struct pushblox_ctx *c = ctx;

    if(!sxi_jpath_arraypos(lhost)) { /* First target of a block */
	const char *key = sxi_jpath_mapkey(lkey);
	sx_hash_t block;
	if(strlen(key) != sizeof(block) * 2 ||
	   hex2bin(key, sizeof(block) * 2, (uint8_t *)&block, sizeof(block))) {
	    c->error = EINVAL;
	    sxi_jparse_cancel(J, "Invalid block name '%s'", key);
	    return;
	}
	if(sx_blob_add_blob(c->stash, &block, sizeof(block))) {
	    c->error = ENOMEM;
	    sxi_jparse_cancel(J, "Out of memory");
	    return;
	}
    }

    if(length == UUID_STRING_SIZE) {
	char uuidstr[UUID_STRING_SIZE+1];
	sx_uuid_t uuid;

	memcpy(uuidstr, string, UUID_STRING_SIZE);
	uuidstr[UUID_STRING_SIZE] = '\0';
	if(!uuid_from_string(&uuid, uuidstr)) {
	    if(sx_blob_add_blob(c->stash, uuid.binary, sizeof(uuid.binary))) {
		c->error = ENOMEM;
		sxi_jparse_cancel(J, "Out of memory");
	    }
	    return; /* Target added */
	}
    }
    sxi_jparse_cancel(J, "Invalid target uuid '%.*s'", length, string);
    c->error = EINVAL;
}


void fcgi_push_blocks(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(JPACT(cb_pushblox_target, JPANYKEY, JPANYITM))
    };
    struct pushblox_ctx yctx;
    unsigned int blocksize;
    int64_t flowuid = FLOW_DEFAULT_UID;
    const char *eop;
    jparse_t *J;
    int len;

    blocksize = strtol(path, (char **)&eop, 10);
    if(*eop == '/') {
	eop++;
	len = strlen(eop);
	if(len == AUTH_UID_LEN * 2) {
	    uint8_t pushuser[AUTH_UID_LEN];
	    if(!hex2bin(eop, AUTH_UID_LEN * 2, pushuser, sizeof(pushuser)))
		sx_hashfs_get_user_info(hashfs, pushuser, &flowuid, NULL, NULL, NULL, NULL);
	}
    } else if(*eop)
	quit_errmsg(404, "Invalid blocksize");
    if(sx_hashfs_check_blocksize(blocksize) != OK)
	quit_errmsg(404, "Invalid blocksize value");

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    yctx.stash = sx_blob_new();
    if(!yctx.stash) {
	sxi_jparse_destroy(J);
	quit_errmsg(503, "Cannot allocate temporary storage");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(rc2http(yctx.error), sxi_jparse_geterr(J));
	sx_blob_free(yctx.stash);
	sxi_jparse_destroy(J);
	return;
    }

    sxi_jparse_destroy(J);
    auth_complete();
    if(!is_authed()) {
	sx_blob_free(yctx.stash);
	send_authreq();
	return;
    }

    if(sx_blob_add_blob(yctx.stash, "", 1)) {
	sx_blob_free(yctx.stash);
	quit_errmsg(503, "Out of memory building propagation list");
    }
    sx_blob_loadpos(yctx.stash); /* Reset blob */

    sx_hash_t block;
    /* MODHDIST: propagate to _next set */
    const sx_nodelist_t *nodes = sx_hashfs_all_nodes(hashfs, NL_NEXT);
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
		rc_ty ret = sx_hashfs_xfer_tonodes(hashfs, &block, blocksize, targets, flowuid);
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
            /* TODO: token id */
	    for(i=0; i<bmeta->count; i++)
		if(sx_blob_add_blob(b, bmeta->entries[i].revision_id.b, sizeof(bmeta->entries[i].revision_id.b)) ||
                   sx_blob_add_blob(b, bmeta->entries[i].global_vol_id.b, sizeof(bmeta->entries[i].global_vol_id.b)) ||
                   sx_blob_add_int32(b, bmeta->entries[i].replica))
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

void fcgi_send_volrep_blocks(void) {
    sx_block_meta_index_t bmidx, *bmidxptr = NULL;

    unsigned int bytes_sent = 0;
    sx_uuid_t target;
    sx_blob_t *b;
    const char *volname = get_arg("volume");
    const sx_hashfs_volume_t *vol = NULL;

    if(!volname || sx_hashfs_volume_by_name(hashfs, volname, &vol))
        quit_errmsg(400, "Volume does not exist");

    if(uuid_from_string(&target, get_arg("target")))
        quit_errmsg(400, "Parameter target is not valid");

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
        r = sx_hashfs_volrep_find(hashfs, vol, bmidxptr, &target, has_arg("undo"), &bmeta);
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
                if(sx_blob_add_blob(b, bmeta->entries[i].revision_id.b, sizeof(bmeta->entries[i].revision_id.b)) ||
                   sx_blob_add_blob(b, bmeta->entries[i].global_vol_id.b, sizeof(bmeta->entries[i].global_vol_id.b)) ||
                   sx_blob_add_int32(b, bmeta->entries[i].replica))
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

void fcgi_revision_op(void) {
    sx_revision_op_t op;
    const char *revision_id_hex;
    char *hpath;

    revision_id_hex = get_arg("revision_id");
    if (!revision_id_hex || strlen(revision_id_hex) != SXI_SHA1_TEXT_LEN ||
        hex2bin(revision_id_hex, SXI_SHA1_TEXT_LEN, op.revision_id.b, sizeof(op.revision_id.b)))
    {
        msg_set_reason("Cannot parse revision in request");
        quit_errmsg(400, msg_get_reason());
    }
    op.blocksize = strtol(path, &hpath, 10);
    if (*hpath != '\0') {
        msg_set_reason("Path must consist of just the blocksize and /: %s", path);
        quit_errmsg(404, msg_get_reason());
    }
    if(sx_hashfs_check_blocksize(op.blocksize)) {
	msg_set_reason("The requested block size does not exist");
        quit_errmsg(400, msg_get_reason());
    }
    switch (verb) {
        case VERB_PUT:
            op.op = 1;
            break;
        case VERB_DELETE:
            op.op = -1;
            break;
        default:
            quit_errmsg(405,"Bad verb");
    }
    op.lock = revision_id_hex;
    job_2pc_handle_request(sx_hashfs_client(hashfs), &revision_spec, &op);
}


struct blockrevs_ctx {
    rc_ty error;
    int op;
};

void cb_blockrev(jparse_t *J, void *ctx, int32_t bs) {
    const char *revhex = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct blockrevs_ctx *c = (struct blockrevs_ctx *)ctx;
    sx_hash_t revid;
    rc_ty s;

    if(strlen(revhex) != sizeof(revid) * 2 ||
       hex2bin(revhex, sizeof(revid) * 2, revid.b, sizeof(revid))) {
	c->error = EINVAL;
	sxi_jparse_cancel(J, "Invalid revision id %s", revhex);
    } else if(sx_hashfs_check_blocksize(bs)) {
	c->error = EINVAL;
	sxi_jparse_cancel(J, "Invalid block size %u on revision id %s", bs, revhex);
    } else if((s = sx_hashfs_revision_op(hashfs, bs, &revid, c->op)) != OK) {
	c->error = s;
	sxi_jparse_cancel(J, "Revision op failed: %s", msg_get_reason());
    }
}

void fcgi_blockrevs(void) {
    const struct jparse_actions acts = {
	JPACTS_INT32(JPACT(cb_blockrev, JPANYKEY))
    };
    struct blockrevs_ctx ctx;
    jparse_t *J;
    int len;

    memset(&ctx, 0, sizeof(ctx));

    if(!strcmp(path, "remove"))
	ctx.op = -1;
    else if(!strcmp(path, "add"))
	ctx.op = +1; /* Not currently used */
    else
	quit_errmsg(400, "Invalid blockrev operation");

    J = sxi_jparse_create(&acts, &ctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    if(sx_hashfs_revision_op_begin(hashfs)) {
	sxi_jparse_destroy(J);
	quit_errmsg(503, "Cannot create JSON parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	sx_hashfs_revision_op_rollback(hashfs);
	send_error(rc2http(ctx.error), sxi_jparse_geterr(J));
	sxi_jparse_destroy(J);
	return;
    }

    sxi_jparse_destroy(J);
    auth_complete();
    if(!is_authed()) {
	sx_hashfs_revision_op_rollback(hashfs);
	send_authreq();
	return;
    }
    if((ctx.error = sx_hashfs_revision_op_commit(hashfs)) != OK) {
	sx_hashfs_revision_op_rollback(hashfs);
	quit_errmsg(rc2http(ctx.error), msg_get_reason());
    }

    CGI_PUTS("\r\n");
}
