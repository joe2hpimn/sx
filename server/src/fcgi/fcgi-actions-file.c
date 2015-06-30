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

#include "fcgi-actions-file.h"
#include "fcgi-utils.h"
#include "utils.h"
#include "blob.h"

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
    enum cb_newfile_state { CB_NEWFILE_START, CB_NEWFILE_KEY, CB_NEWFILE_CONTENT, CB_NEWFILE_HASH, CB_NEWFILE_SIZE, CB_NEWFILE_META, CB_NEWFILE_METAKEY, CB_NEWFILE_METAVALUE, CB_NEWFILE_COMPLETE } state;
    int64_t filesize; /* file size if creating, extend seq if extending */
    unsigned nhashes;
    int extending;
    char metakey[SXLIMIT_META_MAX_KEY_LEN+1];
};

static int cb_newfile_start_map(void *ctx) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;
    if(c->state == CB_NEWFILE_START)
	c->state = CB_NEWFILE_KEY;
    else if(c->state == CB_NEWFILE_META)
	c->state = CB_NEWFILE_METAKEY;
    else
	return 0;
    return 1;
}

static int cb_newfile_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;

    if(c->state == CB_NEWFILE_KEY) {
	if(l == lenof("fileData") && !strncmp("fileData", s, lenof("fileData"))) {
	    c->state = CB_NEWFILE_CONTENT;
	    return 1;
	}

	if(l == lenof("fileMeta") && !strncmp("fileMeta", s, lenof("fileMeta"))) {
	    c->state = CB_NEWFILE_META;
	    return 1;
	}

	if((!c->extending && l == lenof("fileSize") && !strncmp("fileSize", s, lenof("fileSize"))) ||
	   (c->extending && l == lenof("extendSeq") && !strncmp("extendSeq", s, lenof("extendSeq")))) {
	    c->state = CB_NEWFILE_SIZE;
	    return 1;
	}

	return 0;
    }

    if(c->state == CB_NEWFILE_METAKEY) {
	if(l >= sizeof(c->metakey))
	    return 0;
	memcpy(c->metakey, s, l);
	c->metakey[l] = '\0';
	c->state = CB_NEWFILE_METAVALUE;
	return 1;
    }

    return 0;
}

static int cb_newfile_number(void *ctx, const char *s, size_t l) {
    char number[32], *eon;
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;

    if(c->state != CB_NEWFILE_SIZE || c->filesize != -1 || l<1 || l>20)
	return 0;
    memcpy(number, s, l);
    number[l] = '\0';
    c->filesize = strtoll(number, &eon, 10);
    if(*eon || c->filesize < 0)
	return 0;
    c->state = CB_NEWFILE_KEY;
    return 1;
}

static int cb_newfile_start_array(void *ctx) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;
    return (c->nhashes == 0 && c->state++ == CB_NEWFILE_CONTENT);
}

static int cb_newfile_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;

    if(c->state == CB_NEWFILE_HASH) {
	sx_hash_t hash;
	if(l != SXI_SHA1_TEXT_LEN)
	    return 0;

	if(hex2bin(s, SXI_SHA1_TEXT_LEN, hash.b, sizeof(hash.b)))
	    return 0;

	rc_ty rc = sx_hashfs_putfile_putblock(hashfs, &hash);
	if (rc != OK) {
	    WARN("filehash_add failed: %d", rc);
	    return 0;
	}

	c->nhashes++;
	return 1;
    }

    if(c->state == CB_NEWFILE_METAVALUE) {
	uint8_t metavalue[SXLIMIT_META_MAX_VALUE_LEN];
	if(hex2bin(s, l, metavalue, sizeof(metavalue)))
	    return 0;
	if(sx_hashfs_putfile_putmeta(hashfs, c->metakey, metavalue, l/2))
	    return 0;
	c->state = CB_NEWFILE_METAKEY;
	return 1;
    }
    return 0;
}

static int cb_newfile_null(void *ctx) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;

    if(c->state != CB_NEWFILE_METAVALUE)
	return 0;

    if(sx_hashfs_putfile_putmeta(hashfs, c->metakey, NULL, 0))
	return 0;
    c->state = CB_NEWFILE_METAKEY;
    return 1;
}

static int cb_newfile_end_array(void *ctx) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;
    if(c->state != CB_NEWFILE_HASH)
	return 0;
    c->state = CB_NEWFILE_KEY;
    return 1;
}

static int cb_newfile_end_map(void *ctx) {
    struct cb_newfile_ctx *c = (struct cb_newfile_ctx *)ctx;
    if(c->state == CB_NEWFILE_METAKEY)
	c->state = CB_NEWFILE_KEY;
    else if(c->state == CB_NEWFILE_KEY)
	c->state = CB_NEWFILE_COMPLETE;
    else
	return 0;
    return 1;
}


static const yajl_callbacks newfile_parser = {
    cb_newfile_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_newfile_number,
    cb_newfile_string,
    cb_newfile_start_map,
    cb_newfile_map_key,
    cb_newfile_end_map,
    cb_newfile_start_array,
    cb_newfile_end_array
};


void fcgi_create_file(void) {
    int len;
    rc_ty s;

    quit_unless_has(PRIV_CLUSTER); /* Just in case */

    if(!has_arg("rev"))
	quit_errmsg(500, "File revision missing");

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

    struct cb_newfile_ctx yctx;
    yctx.state = CB_NEWFILE_START;
    yctx.filesize = -1;
    yctx.nhashes = 0;
    yctx.extending = 0;

    yajl_handle yh = yajl_alloc(&newfile_parser, NULL, &yctx);
    if(!yh) {
	sx_hashfs_createfile_end(hashfs);
	quit_errmsg(500, "Cannot allocate json parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_NEWFILE_COMPLETE) {
	yajl_free(yh);
	sx_hashfs_createfile_end(hashfs);
	quit_errmsg(400, "Invalid request content");
    }

    yajl_free(yh);
    auth_complete();
    quit_unless_authed();

    s = sx_hashfs_createfile_commit(hashfs, volume, path, get_arg("rev"), yctx.filesize);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

static void create_or_extend_tempfile(const sx_hashfs_volume_t *vol, const char *filename, int extending) {
    hash_presence_ctx_t ctx;
    const char *token;
    int len;
    rc_ty s;

    struct cb_newfile_ctx yctx;
    yctx.state = CB_NEWFILE_START;
    yctx.filesize = -1;
    yctx.nhashes = 0;
    yctx.extending = extending;
    yajl_handle yh = yajl_alloc(&newfile_parser, NULL, &yctx);
    if(!yh) {
	sx_hashfs_putfile_end(hashfs);
	quit_errmsg(500, "Cannot allocate json parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_NEWFILE_COMPLETE) {
	yajl_free(yh);
	sx_hashfs_putfile_end(hashfs);
	quit_errmsg(400, "Invalid request content");
    }

    yajl_free(yh);
    auth_complete();
    quit_unless_authed();

    s = sx_hashfs_putfile_gettoken(hashfs, user, yctx.filesize, &token, hash_presence_callback, &ctx);
    if (s != OK) {
	sx_hashfs_putfile_end(hashfs);
	if(s == ENOSPC)
	    quit_errmsg(413, msg_get_reason());
	WARN("store_filehash_end failed: %d", s);
	if(!*msg_get_reason())
	    msg_set_reason("Cannot obtain upload token: %s", rc2str(s));
	quit_errmsg(500, msg_get_reason());
    }

    CGI_PRINTF("Content-type: application/json\r\n\r\n{\"uploadToken\":");
    json_send_qstring(extending ? path : token);
    CGI_PUTS(",\"uploadData\":{");
    ctx.h = hashfs;
    ctx.comma = 0;
    while((s = sx_hashfs_putfile_getblock(hashfs)) == OK) {
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

    s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol))
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

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol))
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
