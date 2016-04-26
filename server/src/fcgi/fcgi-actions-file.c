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

#include "fcgi-actions-file.h"
#include "fcgi-utils.h"
#include "utils.h"
#include "blob.h"

#include "libsxclient/src/jparse.h"

void fcgi_send_file_meta(void) {
    const char *metakey;
    const void *metavalue;
    unsigned int created_at;
    sx_hash_t etag;
    int metasize;
    int comma = 0;
    rc_ty s;

    s = sx_hashfs_getfilemeta_begin(hashfs, volume, path, get_arg("rev"), &created_at, &etag);
    if(s != OK)
	quit_errnum(s == ENOENT ? 404 : 500);

    if(is_object_fresh(&etag, 'M', created_at))
	return;

    CGI_PUTS("Content-type: application/json\r\n\r\n{\"fileMeta\":{");
    while((s = sx_hashfs_getfilemeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK) {
	char hexval[SXLIMIT_META_MAX_VALUE_LEN*2+1];
	if(comma)
	    CGI_PUTC(',');
	else
	    comma |= 1;
	json_send_qstring(metakey);
	CGI_PUTS(":\"");
	bin2hex(metavalue, metasize, hexval, sizeof(hexval));
	CGI_PUTS(hexval);
	CGI_PUTC('"');
    }
    CGI_PUTS("}");
    if (s != ITER_NO_MORE)
	quit_itererr("Failed to get file metadata", s);
    CGI_PUTS("}");
}

void fcgi_send_file_revisions(void) {
    const sx_hashfs_volume_t *vol;
    const sx_hashfs_file_t *file;
    int comma = 0;
    rc_ty s;

    s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    s = sx_hashfs_revision_first(hashfs, vol, path, &file, 0);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("Content-type: application/json\r\n\r\n{\"fileRevisions\":{");
    do {
	CGI_PRINTF("%s\"%s\":{\"blockSize\":%d,\"fileSize\":", comma ? "," : "", file->revision, file->block_size);
	CGI_PUTLL(file->file_size);
	CGI_PRINTF(",\"createdAt\":%u}", file->created_at);
	comma = 1;
	s = sx_hashfs_revision_next(hashfs, 0);
    } while(s == OK);
    if(s == ITER_NO_MORE)
	CGI_PUTS("}}");
}

void fcgi_send_file(void) {
    sx_hashfs_file_t filedata;
    const sx_hash_t *hash;
    sx_nodelist_t *nodes;
    sx_hash_t etag;
    int comma = 0;
    rc_ty s = sx_hashfs_getfile_begin(hashfs, volume, path, get_arg("rev"), &filedata, &etag);

    if(s != OK)
	quit_errnum(s == ENOENT ? 404 : 500);

    if(is_object_fresh(&etag, 'F', filedata.created_at)) {
	sx_hashfs_getfile_end(hashfs);
	return;
    }

    CGI_PRINTF("Content-type: application/json\r\n\r\n{\"blockSize\":%d,\"fileSize\":", filedata.block_size);
    CGI_PUTLL(filedata.file_size);
    CGI_PRINTF(",\"createdAt\":%u,\"fileRevision\":\"%s\",\"fileData\":[", filedata.created_at, filedata.revision);

    while((s = sx_hashfs_getfile_block(hashfs, &hash, &nodes)) == OK) {
	if(comma)
	    CGI_PUTC(',');
	else
	    comma |= 1;
	CGI_PUTC('{');
	send_qstring_hash(hash);
	CGI_PUTC(':');
	/* Nodes are in NL_PREVNEXT order and MUST NOT be randomized
	 * (see comments in sx_hashfs_getfile_block) */
	send_nodes(nodes);
	CGI_PUTC('}');

	sx_nodelist_delete(nodes);
    }

    sx_hashfs_getfile_end(hashfs);
    CGI_PUTS("]");
    if(s != ITER_NO_MORE)
	quit_itererr("Failed to list file blocks", s);

    CGI_PUTS("}");
}


typedef struct {
    sx_hashfs_t *h;
    int comma;
} hash_presence_ctx_t;

static int hash_presence_callback(const char *hexhash, unsigned int index, int code, void *context)
{
    hash_presence_ctx_t *ctx = (hash_presence_ctx_t*)context;
    sx_hashfs_t *h = ctx->h;
    sx_nodelist_t *nodes;
    sx_hash_t hash;
    if (code != 200) {
	if (code < 0)
	    WARN("Failed to query hash %.*s: %s", 40, hexhash, sx_hashfs_geterrmsg(h));
	if (hex2bin(hexhash, SXI_SHA1_TEXT_LEN, hash.b, sizeof(hash.b))) {
	    WARN("hex2bin failed on %.*s", 40, hexhash);
	    return -1;
	}
	nodes = sx_hashfs_putfile_hashnodes(h, &hash);
	if (!nodes) {
	    WARN("hashnodes failed");
	    return -1;
	}
	if(ctx->comma)
	    CGI_PUTC(',');
	else
	    ctx->comma |= 1;
        DEBUG("Requesting from user: #%.*s#", 40, hexhash);
	send_qstring_hash(&hash);
	CGI_PUTC(':');
	/* Although there is no danger in doing so, nodes SHOULD NOT be randomized:
	 * hdist already does a pretty good job here */
	send_nodes(nodes);
	sx_nodelist_delete(nodes);
    }
    send_keepalive();
    return 0;
}

/* create: {"fileSize":1234,"fileData":["hash1","hash2"],"fileMeta":{"key":"value","key2":"value2"}} */
/* extend: {"extendSeq":1234,"fileData":["hash1","hash2"],"fileMeta":{"key":"value","key2":"value2"}} */
struct cb_newfile_ctx {
    int64_t filesize;
    int64_t seq;
    rc_ty rc;
    char metakey[SXLIMIT_META_MAX_KEY_LEN+1];
};

static void cb_newfile_size(jparse_t *J, void *ctx, int64_t size) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;
    c->filesize = size;
}

static void cb_newfile_seq(jparse_t *J, void *ctx, int64_t seq) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;
    c->seq = seq;
}

static void cb_newfile_block(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;
    sx_hash_t hash;

    if(length != SXI_SHA1_TEXT_LEN || hex2bin(string, SXI_SHA1_TEXT_LEN, hash.b, sizeof(hash.b))) {
	c->rc = EINVAL;
	sxi_jparse_cancel(J, "Invalid block '%.*s'", length, string);
	return;
    }

    c->rc = sx_hashfs_putfile_putblock(hashfs, &hash);
    if(c->rc != OK) {
	const char *reason = msg_get_reason();
	sxi_jparse_cancel(J, "Failed to add block '%.*s': %s", length, string, reason ? reason : " (reason unknown)");
	return;
    }
}

static void cb_newfile_addmeta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *metakey = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    uint8_t metavalue[SXLIMIT_META_MAX_VALUE_LEN];
    struct cb_newfile_ctx *c = ctx;

    if(hex2bin(string, length, metavalue, sizeof(metavalue))) {
	c->rc = EINVAL;
	sxi_jparse_cancel(J, "Invalid volume metadata value for key '%s'", metakey);
	return;
    }

    c->rc = sx_hashfs_putfile_putmeta(hashfs, metakey, metavalue, length / 2);
    if(c->rc) {
	const char *reason = msg_get_reason();
	sxi_jparse_cancel(J, "'%s'", reason ? reason : "Invalid file metadata");
	return;
    }
}

static void cb_newfile_delmeta(jparse_t *J, void *ctx) {
    const char *metakey = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_newfile_ctx *c = ctx;

    c->rc = sx_hashfs_putfile_putmeta(hashfs, metakey, NULL, 0);
    if(c->rc != OK) {
	const char *reason = msg_get_reason();
	sxi_jparse_cancel(J, "'%s'", reason ? reason : "Invalid file metadata");
	return;
    }
}

void fcgi_create_file(void) {
    const struct jparse_actions acts = {
	JPACTS_INT64(
		     JPACT(cb_newfile_size, JPKEY("fileSize"))
		     ),
	JPACTS_STRING(
		      JPACT(cb_newfile_block, JPKEY("fileData"), JPANYITM),
		      JPACT(cb_newfile_addmeta, JPKEY("fileMeta"), JPANYKEY)
		      ),
	JPACTS_NULL(
		    JPACT(cb_newfile_delmeta, JPKEY("fileMeta"), JPANYKEY)
		    )
    };
    struct cb_newfile_ctx yctx;
    jparse_t *J;
    int len;
    rc_ty s;
    sx_hash_t revid;
    sx_hash_t global_vol_id;
    const sx_hashfs_volume_t *vol = NULL;

    quit_unless_has(PRIV_CLUSTER); /* Just in case */

    if(!has_arg("rev") || !has_arg("revid") || strlen(get_arg("revid")) != SXI_SHA1_TEXT_LEN)
	quit_errmsg(500, "File revision missing");
    if(hex2bin(get_arg("revid"), SXI_SHA1_TEXT_LEN, revid.b, sizeof(revid.b)))
        quit_errmsg(400, "Failed to parse revision ID");

    /*
     * 'volume' variable stores the global volume ID because this is an s2s query.
     */
    if(strlen(volume) != SXI_SHA1_TEXT_LEN || hex2bin(volume, SXI_SHA1_TEXT_LEN, global_vol_id.b, sizeof(global_vol_id.b)))
        quit_errmsg(400, "Invalid global volume ID");

    s = sx_hashfs_createfile_begin(hashfs);
    switch (s) {
    case OK:
	break;
    case ENOENT:
	quit_errnum(404);
    case EINVAL:
	quit_errnum(400);
    default:
	WARN("sx_hashfs_createfile_begin failed: %d", s);
	quit_errmsg(rc2http(s), "Cannot initialize file upload");
    }

    yctx.filesize = -1;
    yctx.rc = EINVAL;

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J) {
	sx_hashfs_createfile_end(hashfs);
	quit_errmsg(503, "Cannot create JSON parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(rc2http(yctx.rc), sxi_jparse_geterr(J));
	sx_hashfs_createfile_end(hashfs);
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    quit_unless_authed();

    if((s = sx_hashfs_volume_by_global_id(hashfs, &global_vol_id, &vol)) != OK) {
        sx_hashfs_createfile_end(hashfs);
        quit_errmsg(rc2http(s), rc2str(s));
    }

    s = sx_hashfs_createfile_commit(hashfs, vol, path, get_arg("rev"), &revid, yctx.filesize, 0);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

static void create_or_extend_tempfile(const sx_hashfs_volume_t *vol, const char *filename, int extending) {
    const struct jparse_actions acts = {
	JPACTS_INT64(
		     JPACT(cb_newfile_size, JPKEY("fileSize")),
		     JPACT(cb_newfile_seq, JPKEY("extendSeq"))
		     ),
	JPACTS_STRING(
		      JPACT(cb_newfile_block, JPKEY("fileData"), JPANYITM),
		      JPACT(cb_newfile_addmeta, JPKEY("fileMeta"), JPANYKEY)
		      ),
	JPACTS_NULL(
		    JPACT(cb_newfile_delmeta, JPKEY("fileMeta"), JPANYKEY)
		    )
    };
    struct cb_newfile_ctx yctx;
    hash_presence_ctx_t ctx;
    const char *token;
    jparse_t *J;
    int len;
    rc_ty s;

    yctx.filesize = -1;
    yctx.seq = -1;
    yctx.rc = EINVAL;

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J) {
	sx_hashfs_putfile_end(hashfs);
	quit_errmsg(503, "Cannot create JSON parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(rc2http(yctx.rc), sxi_jparse_geterr(J));
	sx_hashfs_putfile_end(hashfs);
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    quit_unless_authed();

    s = sx_hashfs_putfile_gettoken(hashfs, user, yctx.filesize, yctx.seq, &token, hash_presence_callback, &ctx);
    if (s != OK) {
	sx_hashfs_putfile_end(hashfs);
	if(!*msg_get_reason())
	    msg_set_reason("Cannot obtain upload token: %s", rc2str(s));
	quit_errmsg((s == ENOSPC) ? 413 : rc2http(s), msg_get_reason());
    }

    CGI_PRINTF("Content-type: application/json\r\n\r\n{\"uploadToken\":");
    json_send_qstring(extending ? path : token);
    CGI_PUTS(",\"uploadData\":{");
    ctx.h = hashfs;
    ctx.comma = 0;
    while((s = sx_hashfs_putfile_getblock(hashfs)) == OK) {
	/* Nothing to do here, API does a little bit of work at a time by design
	 * We can stick keepalives in here if we ever need to */
    }
    sx_hashfs_putfile_end(hashfs);
    CGI_PUTS("}");
    if(s != ITER_NO_MORE) {
	quit_itererr("Failed to send file blocks", s);
    }

    CGI_PUTS("}");
}

void fcgi_create_tempfile(void) {
    const sx_hashfs_volume_t *vol;
    rc_ty s = sx_hashfs_putfile_begin(hashfs, uid, volume, path, &vol);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());
    create_or_extend_tempfile(vol, path, 0);
}

void fcgi_extend_tempfile(void) {
    rc_ty s = sx_hashfs_putfile_extend_begin(hashfs, uid, user, path);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());
    create_or_extend_tempfile(NULL, NULL, 1);
}

void fcgi_flush_tempfile(void) {
    job_t job;
    rc_ty s;

    auth_complete();
    quit_unless_authed();

    s = sx_hashfs_putfile_commitjob(hashfs, user, uid, path, &job);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());
    send_job_info(job);
    return;
}

void fcgi_delete_file(void) {
    const char *rev = get_arg("rev");
    const sx_hashfs_volume_t *vol;
    rc_ty s;

    if(has_priv(PRIV_CLUSTER)) {
        sx_hash_t global_vol_id;

        if(strlen(volume) != SXI_SHA1_TEXT_LEN || hex2bin(volume, SXI_SHA1_TEXT_LEN, global_vol_id.b, sizeof(global_vol_id.b)))
            quit_errmsg(400, "Invalid global volume ID");
        s = sx_hashfs_volume_by_global_id(hashfs, &global_vol_id, &vol);
    } else
        s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol, 0))
	quit_errnum(404);

    if(has_priv(PRIV_CLUSTER)) {
	/* Request comes in from the cluster: apply locally */
	s = sx_hashfs_file_delete(hashfs, vol, path, rev);
	if(s != OK)
	    quit_errmsg(rc2http(s), msg_get_reason());
	CGI_PUTS("\r\n");
    } else {
	/* Request comes in from the user: create job */
	job_t job;
	s = sx_hashfs_filedelete_job(hashfs, uid, vol, path, rev, &job);
	if(s != OK)
	    quit_errmsg(rc2http(s), msg_get_reason());
	send_job_info(job);
    }
}

struct rplfiles {
    sx_blob_t *b;
    sx_hashfs_file_t lastfile;
    unsigned int bytes_sent;
};

static void send_rplfiles_header(struct rplfiles *ctx) {
    unsigned int header_len, hlenton;
    const void *header;

    sx_blob_to_data(ctx->b, &header, &header_len);
    hlenton = htonl(header_len);
    if(!ctx->bytes_sent)
	CGI_PUTS("\r\n");
    CGI_PUTD(&hlenton, sizeof(hlenton));
    CGI_PUTD(header, header_len);
    ctx->bytes_sent += sizeof(hlenton) + header_len;
}

static int rplfiles_cb(const sx_hashfs_volume_t *volume, const sx_hashfs_file_t *file, const sx_hash_t *contents, unsigned int nblocks, void *ctx) {
    unsigned int bodylen = sizeof(*contents) * nblocks, mval_len;
    struct rplfiles *c = (struct rplfiles *)ctx;
    const char *mkey;
    const void *mval;
    rc_ty s;

    if(c->bytes_sent >= REPLACEMENT_BATCH_SIZE)
	return 0;
    sx_blob_reset(c->b);
    if(sx_blob_add_string(c->b, "$FILE$") ||
       sx_blob_add_int32(c->b, nblocks) ||
       sx_blob_add_string(c->b, file->name) ||
       sx_blob_add_string(c->b, file->revision) ||
       sx_blob_add_blob(c->b, file->revision_id.b, sizeof(file->revision_id.b)) ||
       sx_blob_add_int64(c->b, file->file_size))
	return 0;
    if(sx_hashfs_getfilemeta_begin(hashfs, volume->name, file->name, file->revision, NULL, NULL))
	return 0;
    while((s = sx_hashfs_getfilemeta_next(hashfs, &mkey, &mval, &mval_len)) == OK) {
	if(sx_blob_add_string(c->b, "$META$") ||
	   sx_blob_add_string(c->b, mkey) ||
	   sx_blob_add_blob(c->b, mval, mval_len))
	    break;
    }
    if(s != ITER_NO_MORE)
	return 0;
    if(sx_blob_add_string(c->b, "$ENDMETA$"))
	return 0;

    send_rplfiles_header(c);
    CGI_PUTD(contents, bodylen);
    c->bytes_sent += bodylen;
    return 1;
}

void fcgi_send_replacement_files(void) {
    const char *startname, *startrev = NULL;
    const sx_hashfs_volume_t *vol;
    struct rplfiles ctx;
    rc_ty s;

    if(!has_arg("maxrev"))
	quit_errmsg(400, "Parameter maxrev is required");

    startname = strchr(path, '/');
    if(!startname) {
	s = sx_hashfs_volume_by_name(hashfs, path, &vol);
    } else {
	unsigned int vnamelen = startname - path;
	char *vname = malloc(vnamelen + 1);
	if(!vname)
	    quit_errmsg(503, "Out of memory");
	memcpy(vname, path, vnamelen);
	vname[vnamelen] = '\0';
	s = sx_hashfs_volume_by_name(hashfs, vname, &vol);
	free(vname);
	startname++;
	if(strlen(startname))
	    startrev = get_arg("startrev");
	else
	    startname = NULL;
    }
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol, 0))
	quit_errnum(404);

    ctx.bytes_sent = 0;
    ctx.b = sx_blob_new();
    if(!ctx.b)
	quit_errmsg(503, "Out of memory");

    s = sx_hashfs_file_find(hashfs, vol, startname, startrev, get_arg("maxrev"), rplfiles_cb, &ctx);
    if(s == ITER_NO_MORE) {
	sx_blob_reset(ctx.b);
	if(!sx_blob_add_string(ctx.b, "$THEEND$"))
	    send_rplfiles_header(&ctx);
	sx_blob_free(ctx.b);
	return;
    }

    sx_blob_free(ctx.b);
    if(s != FAIL_ETOOMANY && !ctx.bytes_sent)
	quit_errmsg(rc2http(s), msg_get_reason());
}

static int upgrade_2_1_4_cb(const sx_hashfs_volume_t *vol, const sx_hashfs_file_t *file, const sx_hash_t *contents, unsigned int nblocks, void *ctx) {
    struct rplfiles *c = (struct rplfiles *)ctx;

    if(c->bytes_sent >= REPLACEMENT_BATCH_SIZE)
        return 0;
    sx_blob_reset(c->b);

    if(sx_blob_add_string(c->b, "$REVID$") ||
       sx_blob_add_blob(c->b, file->revision_id.b, sizeof(file->revision_id.b)))
        return 0;
    memcpy(c->lastfile.name, file->name, sizeof(c->lastfile.name));
    memcpy(c->lastfile.revision, file->revision, sizeof(c->lastfile.revision));

    send_rplfiles_header(c);
    return 1;
}

void fcgi_upgrade_2_1_4(void) {
    rc_ty s;
    const sx_hashfs_volume_t *vol = NULL;
    const char *startname, *startrev = NULL;
    struct rplfiles ctx;

    if(!has_arg("maxrev"))
        quit_errmsg(400, "Parameter maxrev is required");

    startname = strchr(path, '/');
    if(!startname) {
        s = sx_hashfs_volume_by_name(hashfs, path, &vol);
    } else {
        unsigned int vnamelen = startname - path;
        char *vname = malloc(vnamelen + 1);
        if(!vname)
            quit_errmsg(503, "Out of memory");
        memcpy(vname, path, vnamelen);
        vname[vnamelen] = '\0';
        s = sx_hashfs_volume_by_name(hashfs, vname, &vol);
        free(vname);
        startname++;
        if(strlen(startname))
            startrev = get_arg("startrev");
        else
            startname = NULL;
    }
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol, 0))
        quit_errnum(404);

    ctx.bytes_sent = 0;
    ctx.b = sx_blob_new();
    if(!ctx.b)
        quit_errmsg(503, "Out of memory");

    s = sx_hashfs_file_find(hashfs, vol, startname, startrev, get_arg("maxrev"), upgrade_2_1_4_cb, &ctx);
    if(s == FAIL_ETOOMANY || s == ITER_NO_MORE) {
        sx_blob_reset(ctx.b);
        if(!sx_blob_add_string(ctx.b, "$FILE$") && !sx_blob_add_string(ctx.b, ctx.lastfile.name) &&
           !sx_blob_add_string(ctx.b, ctx.lastfile.revision))
            send_rplfiles_header(&ctx);
    }
    if(s == ITER_NO_MORE) {
        sx_blob_reset(ctx.b);
        if(!sx_blob_add_string(ctx.b, "$THEEND$"))
            send_rplfiles_header(&ctx);
        sx_blob_free(ctx.b);
        return;
    }

    sx_blob_free(ctx.b);
    if(s != FAIL_ETOOMANY && !ctx.bytes_sent)
        quit_errmsg(rc2http(s), msg_get_reason());
}
