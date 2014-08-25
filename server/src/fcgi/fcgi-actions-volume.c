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
#include "fcgi-actions-volume.h"
#include "../libsx/src/misc.h"
#include "blob.h"
#include "utils.h"
#include "job_common.h"

void fcgi_locate_volume(const sx_hashfs_volume_t *vol) {
    const char *size = get_arg("size"), *eon;
    sx_nodelist_t *nodes;
    unsigned int blocksize;
    int64_t fsize;
    rc_ty s;

    if(size) {
	fsize = strtoll(size, (char **)&eon, 10);
	if(*eon || fsize < 0) {
	    msg_set_reason("Invalid size parameter: '%s'", size);
	    quit_errmsg(400, msg_get_reason());
	}
    } else
	fsize = 0;

    /* The locate_volume query is shared between different ops.
     * Although most of them (file creation, file deletion, etc) can be
     * safely target to PREV and NEXT volumes, listing files is only 
     * guaranteed to be accurate when performed against a PREV volnode */
    s = sx_hashfs_volnodes(hashfs, NL_PREV, vol, fsize, &nodes, &blocksize);
    switch(s) {
	case OK:
	    break;
	case EINVAL:
	    quit_errmsg(400, msg_get_reason());
	default:
	    quit_errmsg(500, "Cannot locate the requested volume");
    }

    if(has_arg("volumeMeta") && sx_hashfs_volumemeta_begin(hashfs, vol))
	quit_errmsg(500, "Cannot lookup volume metadata");

    CGI_PUTS("Content-type: application/json\r\n\r\n{\"nodeList\":");
    send_nodes_randomised(nodes);
    sx_nodelist_delete(nodes);
    if(size)
	CGI_PRINTF(",\"blockSize\":%d", blocksize);
    if(has_arg("volumeMeta")) {
	const char *metakey;
	const void *metavalue;
	int metasize, comma = 0;

	CGI_PUTS(",\"volumeMeta\":{");
	while((s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK) {
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
	CGI_PUTC('}');
	if(s != ITER_NO_MORE) {
	    quit_itererr("Failed to list volume metadata", s);
	}
    }
    CGI_PUTC('}');

}


void fcgi_list_volume(const sx_hashfs_volume_t *vol) {
    const sx_hashfs_file_t *file;
    char *reply, *cur;
    unsigned int comma = 0, rplavail, len;
    sx_hash_t etag;
    rc_ty s;

    s = sx_hashfs_list_first(hashfs, vol, get_arg("filter"), &file, has_arg("recursive"));
    switch(s) {
    case OK:
    case ITER_NO_MORE:
	break;
    case ENOENT:
	quit_errmsg(404, "The list for the volume is not available here");
    case EINVAL:
	quit_errnum(400);
    default:
	quit_errnum(500);
    }

    reply = malloc(8192); /* Have room for the volume info, the json closure and the string terminator */
    if(!reply)
	quit_errnum(503);

    sprintf(reply, "Content-type: application/json\r\n\r\n{\"volumeSize\":%lld,\"replicaCount\":%u,\"fileList\":{",
	    (long long)vol->size, vol->replica_count);
    len = strlen(reply);
    cur = reply + len;
    rplavail = 8192 - len;

    for(; s == OK; s = sx_hashfs_list_next(hashfs)) {
	/* Make room for the comma,
	 * the worst case encoded filename,
	 * the whole file data,
	 * the json closure
	 * and the string terminator */

	/* "filename":{"fileSize":123,"blockSize":4096,"createdAt":456,"fileRev":"REVISON_STRING"} */
	if(rplavail < strlen(file->name) * 6 + 256 + REV_LEN) {
	    char *nureply = realloc(reply, (cur - reply) + rplavail + 8192);
	    if(!nureply) {
		free(reply);
		quit_errnum(503);
	    }
	    cur = nureply + (cur - reply);
	    reply = nureply;
	    rplavail += 8192;
	}
	if(comma) {
	    *cur = ','; /* Bound checked above */
	    cur++;
	    rplavail--;
	} else
	    comma |= 1;

	json_qstring(cur, rplavail, file->name);
	len = strlen(cur);
	cur += len;
	rplavail -= len;
	if(file->revision[0]) {
	    /* A File */
	    snprintf(cur, rplavail, ":{\"fileSize\":%lld,\"blockSize\":%u,\"createdAt\":%lld,\"fileRevision\":\"%s\"}",
		     (long long)file->file_size,
		     file->block_size,
		     (long long)file->created_at,
		     file->revision);
	} else {
	    /* A Fakedir */
	    snprintf(cur, rplavail, ":{}");
	}
	len = strlen(cur);
	cur += len;
	rplavail -= len;
    }

    strcpy(cur, "}}"); /* Bound checked above */

    if(s != ITER_NO_MORE)  {
	free(reply);
	quit_errmsg(rc2http(s), "Failed to list files");
    }

    if(!sx_hashfs_hash_buf(NULL, 0, reply, strlen(reply), &etag)) {
	if(is_object_fresh(&etag, 'L', NO_LAST_MODIFIED)) {
	    free(reply);
	    return;
	}
    } else
	WARN("Failed to compute ETag");

    CGI_PUTS(reply);
    free(reply);
}


/* {"volumeSize":123, "replicaCount":2, "volumeMeta":{"metaKey":"hex(value)"}, "user":"jack", "maxRevisions":5} */
struct cb_vol_ctx {
    enum cb_vol_state { CB_VOL_START, CB_VOL_KEY, CB_VOL_VOLSIZE, CB_VOL_REPLICACNT, CB_VOL_OWNER, CB_VOL_NREVS, CB_VOL_META, CB_VOL_METAKEY, CB_VOL_METAVALUE, CB_VOL_COMPLETE } state;
    int64_t volsize;
    int replica;
    unsigned int nmeta, revisions;
    char owner[SXLIMIT_MAX_USERNAME_LEN+1];
    char metakey[SXLIMIT_META_MAX_KEY_LEN+1];
    sx_blob_t *metablb;
};

static int cb_vol_number(void *ctx, const char *s, size_t l) {
    struct cb_vol_ctx *c = (struct cb_vol_ctx *)ctx;
    char number[24], *eon;
    if(c->state == CB_VOL_VOLSIZE) {
	if(c->volsize != -1 || l<1 || l>20)
	    return 0;

	memcpy(number, s, l);
	number[l] = '\0';
	c->volsize = strtoll(number, &eon, 10);
	if(*eon || c->volsize < 0)
	    return 0;
    } else if(c->state == CB_VOL_REPLICACNT) {
	if(c->replica || l<1 || l>10)
	    return 0;

	memcpy(number, s, l);
	number[l] = '\0';
	c->replica = strtol(number, &eon, 10);
	if(*eon || c->replica < 1)
	    return 0;
    } else if(c->state == CB_VOL_NREVS) {
	if(c->revisions || l<1 || l>10)
	    return 0;
	memcpy(number, s, l);
	number[l] = '\0';
	c->revisions = strtol(number, &eon, 10);
	if(*eon || c->revisions < 1)
	    return 0;
    } else
	return 0;

    c->state = CB_VOL_KEY;
    return 1;
}

static int cb_vol_start_map(void *ctx) {
    struct cb_vol_ctx *c = (struct cb_vol_ctx *)ctx;
    if(c->state == CB_VOL_START)
	c->state = CB_VOL_KEY;
    else if(c->state == CB_VOL_META)
	c->state = CB_VOL_METAKEY;
    else
	return 0;
    return 1;
}

static int cb_vol_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_vol_ctx *c = (struct cb_vol_ctx *)ctx;
    if(c->state == CB_VOL_KEY) {
	if(l == lenof("volumeSize") && !strncmp("volumeSize", s, lenof("volumeSize"))) {
	    c->state = CB_VOL_VOLSIZE;
	    return 1;
	}
	if(l == lenof("replicaCount") && !strncmp("replicaCount", s, lenof("replicaCount"))) {
	    c->state = CB_VOL_REPLICACNT;
	    return 1;
	}
	if(l == lenof("volumeMeta") && !strncmp("volumeMeta", s, lenof("volumeMeta"))) {
	    c->state = CB_VOL_META;
	    return 1;
	}
	if(l == lenof("owner") && !strncmp("owner", s, l)) {
	    c->state = CB_VOL_OWNER;
	    return 1;
	}
	if(l == lenof("maxRevisions") && !strncmp("maxRevisions", s, l)) {
	    c->state = CB_VOL_NREVS;
	    return 1;
	}
    } else if(c->state == CB_VOL_METAKEY) {
	if(c->nmeta >= SXLIMIT_META_MAX_ITEMS || l < SXLIMIT_META_MIN_KEY_LEN || l > SXLIMIT_META_MAX_KEY_LEN)
	    return 0;
	c->nmeta++;
	memcpy(c->metakey, s, l);
	c->metakey[l] = '\0';
	c->state = CB_VOL_METAVALUE;
	return 1;
    }
    return 0;
}

static int cb_vol_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_vol_ctx *c = (struct cb_vol_ctx *)ctx;
    uint8_t metavalue[SXLIMIT_META_MAX_VALUE_LEN];

    if(c->state == CB_VOL_OWNER) {
	if(c->owner[0])
	    return 0;
	if(l >= sizeof(c->owner))
	    return 0;
	memcpy(c->owner, s, l);
	c->owner[l] = '\0';
	if(sx_hashfs_check_username(c->owner))
	    return 0;
	c->state = CB_VOL_KEY;
	return 1;
    } else if(c->state != CB_VOL_METAVALUE)
	return 0;

    if(hex2bin(s, l, metavalue, sizeof(metavalue)))
	return 0;
    l/=2;
    if(sx_hashfs_check_meta(c->metakey, metavalue, l) ||
       sx_blob_add_string(c->metablb, c->metakey) ||
       sx_blob_add_blob(c->metablb, metavalue, l))
	return 0;

    c->state = CB_VOL_METAKEY;
    return 1;
}

static int cb_vol_end_map(void *ctx) {
    struct cb_vol_ctx *c = (struct cb_vol_ctx *)ctx;
    if(c->state == CB_VOL_KEY) {
	c->state = CB_VOL_COMPLETE;
	if(!c->replica)
	    c->replica = 1; /* FIXME: document the replicaCount param on the api page, document its default value */
    } else if(c->state == CB_VOL_METAKEY)
	c->state = CB_VOL_KEY;
    else
	return 0;
    return 1;
}

enum acl_state { CB_ACL_START=0, CB_ACL_KEY, CB_ACL_KEYARRAY, CB_ACL_GRANT_READ, CB_ACL_GRANT_WRITE, CB_ACL_REVOKE_READ, CB_ACL_REVOKE_WRITE, CB_ACL_COMPLETE };
struct acl_op {
    char *name;
    int priv;
};

struct acl_ctx {
    struct acl_op *ops;
    unsigned n;
    enum acl_state state;
};

static int cb_acl_string(void *ctx, const unsigned char *s, size_t l) {
    struct acl_ctx *c = ctx;
    int priv;
    switch (c->state) {
	case CB_ACL_GRANT_READ:
	    priv = PRIV_READ;
	    break;
	case CB_ACL_GRANT_WRITE:
	    priv = PRIV_WRITE;
	    break;
	case CB_ACL_REVOKE_READ:
	    priv = ~PRIV_READ;
	    break;
	case CB_ACL_REVOKE_WRITE:
	    priv = ~PRIV_WRITE;
	    break;
	default:
	    WARN("acl bad string state: %d", c->state);
	    return 0;
    }
    struct acl_op *newops = realloc(c->ops, sizeof(*newops) * (++c->n));
    if (!newops) {
	WARN("Cannot realloc acl ops");
	return 0;
    }
    c->ops = newops;

    char *name = malloc(l + 1);
    if (!name) {
	WARN("Cannot malloc name");
	return 0;
    }
    memcpy(name, s, l);
    name[l] = 0;
    c->ops[c->n-1].name = name;
    c->ops[c->n-1].priv = priv;
    return 1;
}

static int cb_acl_start_map(void *ctx) {
    struct acl_ctx *c = ctx;
    if (c->state == CB_ACL_START) {
	c->state = CB_ACL_KEY;
	return 1;
    }
    WARN("bad map state");
    return 0;
}

static int cb_acl_start_array(void *ctx) {
    struct acl_ctx *c = ctx;
    if (c->state == CB_ACL_KEY || c->state == CB_ACL_START) {
	WARN("bad array state");
	return 0;
    }
    return 1;
}

static int cb_acl_end_array(void *ctx) {
    struct acl_ctx *c = ctx;
    if (c->state == CB_ACL_START) {
	WARN("bad array end state");
	return 0;
    }
    c->state = CB_ACL_KEY;
    return 1;
}

static int cb_acl_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct acl_ctx *c = ctx;
    if (c->state != CB_ACL_KEY) {
	WARN("bad map key state ");
	return 0;
    }
    if (l == lenof("grant-read") && !strncmp("grant-read", s, l)) {
	c->state = CB_ACL_GRANT_READ;
	return 1;
    }
    if (l == lenof("grant-write") && !strncmp("grant-write", s, l)) {
	c->state = CB_ACL_GRANT_WRITE;
	return 1;
    }
    if (l == lenof("revoke-read") && !strncmp("revoke-read", s, l)) {
	c->state = CB_ACL_REVOKE_READ;
	return 1;
    }
    if (l == lenof("revoke-write") && !strncmp("revoke-write", s, l)) {
	c->state = CB_ACL_REVOKE_WRITE;
	return 1;
    }
    WARN("bad map key word: %.*s", (int)l, s);
    return 0;
}

static int cb_acl_end_map(void *ctx) {
    struct acl_ctx *c = ctx;
    if(c->state == CB_ACL_KEY)
	c->state = CB_ACL_COMPLETE;
    else {
	WARN("bad array end state");
	return 0;
    }
    return 1;
}

static const yajl_callbacks acl_ops_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_acl_string,
    cb_acl_start_map,
    cb_acl_map_key,
    cb_acl_end_map,
    cb_acl_start_array,
    cb_acl_end_array
};

static int print_acl(const char *username, int priv, void *ctx)
{
    int *first = ctx;
    if (*first)
	CGI_PUTS("Content-type: application/json\r\n\r\n{");
    else
        CGI_PUTS(",");
    json_send_qstring(username);
    CGI_PUTS(":[");
    int comma = 0;
    if (priv & PRIV_READ) {
	CGI_PUTS("\"read\"");
	comma = 1;
    }
    if (priv & PRIV_WRITE) {
	CGI_PRINTF("%s\"write\"", comma ? "," : "");
	comma = 1;
    }
    if (priv & PRIV_ADMIN) {
        CGI_PRINTF("%s\"admin\"", comma ? ",":"");
        comma = 1;
    } else if (priv & PRIV_OWNER) {
	CGI_PRINTF("%s\"owner\"", comma ? ",":"");
	comma = 1;
    }
    CGI_PUTS("]");
    *first = 0;
    return 0;
}

void fcgi_list_acl(const sx_hashfs_volume_t *vol) {
    int first = 1;
    rc_ty rc = sx_hashfs_list_acl(hashfs, vol, uid, get_priv(1), print_acl, &first);
    if (rc != OK) {
	if (rc == ENOENT)
	    quit_errmsg(404, "Volume not found");
        if (rc == EPERM)
            quit_errmsg(403, "Not enough privileges to list volume ACL");
	if (first) {
	    msg_set_reason("Failed to list volume acl: %s", rc2str(rc));
	    quit_errmsg(500, msg_get_reason());
	}
	else
	    quit_itererr("Failed to list volume acl", rc);
    }
    CGI_PUTS("}");
}

static int acl_parse_complete(void *yctx)
{
    struct acl_ctx *actx = yctx;
    return actx && actx->state == CB_ACL_COMPLETE;
}

static int acl_to_blob(sxc_client_t *sx, void *yctx, sx_blob_t *blob)
{
    struct acl_ctx *actx = yctx;
    int i;
    if (sx_blob_add_string(blob, volume) ||
        sx_blob_add_int32(blob, actx->n))
        return -1;
    for (i=0;i<actx->n;i++) {
        int64_t uid;
        rc_ty rc;
        int undo_priv, new_priv;
        sx_priv_t old_priv;/* TODO: get_access should return int not sx_priv_t, as its a bitmask not an enum */

        int priv  = actx->ops[i].priv;
        const char *name = actx->ops[i].name;
        rc = sx_hashfs_get_uid(hashfs, name, &uid);
        if (rc) {
            msg_set_reason("Cannot retrieve user id for '%s'", name);
            return -1;
        }
        rc = sx_hashfs_get_access(hashfs, uid, volume, &old_priv);
        if (rc) {
            msg_set_reason("Cannot retrieve acl for volume '%s' and user '%s'", volume, name);
            return -1;
        }
        if (priv > 0)
            new_priv = old_priv | priv;
        else
            new_priv = old_priv & (~priv);
        /* undo_priv should be -priv, or 0 */
        undo_priv = old_priv - new_priv;
        if (sx_blob_add_string(blob, name) ||
            sx_blob_add_int32(blob, priv) ||
            sx_blob_add_int32(blob, undo_priv))
            return -1;
    }
    return 0;
}

static rc_ty acl_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase)
{
    const char *volume;
    rc_ty rc = OK;
    int32_t n, i;
    if (!hashfs || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (phase == JOBPHASE_COMMIT)
        return OK;
    if (sx_blob_get_string(b, &volume)) {
        msg_set_reason("Corrupt blob: volume");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_int32(b, &n)) {
        msg_set_reason("Corrupt blob: count");
        return FAIL_EINTERNAL;
    }
    for (i=0;i<n && rc == OK;i++) {
        const char *name;
        int priv, undo_priv, role;
        if (sx_blob_get_string(b, &name) ||
            sx_blob_get_int32(b, &priv) ||
            sx_blob_get_int32(b, &undo_priv)) {
            msg_set_reason("Corrupt blob entry %d/%d", i, n);
            return FAIL_EINTERNAL;
        }
        int64_t uid;
        if (phase != JOBPHASE_REQUEST)
            priv = undo_priv;
        rc = sx_hashfs_get_uid_role(hashfs, name, &uid, &role);
        if (rc == OK) {
            if (role > ROLE_USER) {
                msg_set_reason("Cannot grant/revoke privileges for admin user");
                rc = EINVAL;
                break;
            }
            if (priv > 0) {
                rc = sx_hashfs_grant(hashfs, uid, volume, priv);
                if (rc != OK)
                    msg_set_reason("Cannot grant privileges: %s", rc2str(rc));
            } else {
                rc = sx_hashfs_revoke(hashfs, uid, volume, priv);
                if (rc != OK)
                    msg_set_reason("Cannot revoke privileges: %s", rc2str(rc));
            }
        } else {
            msg_set_reason("Cannot get uid for %s: %s", name, rc2str(rc));
        }
    }
    return rc;
}

struct blob_iter {
    sx_blob_t *b;
    int i;
    int n;
};

static const char *blob_iter_cb(void *ctx, int priv_state, int priv_mask)
{
    struct blob_iter *iter = ctx;
    sx_blob_t *b = iter->b;
    DEBUG("blob_iter entered with i=%d, n=%d", iter->i, iter->n);
    while (iter->i++ < iter->n) {
        const char *name;
        int priv, undo_priv;
        if (sx_blob_get_string(b, &name) ||
            sx_blob_get_int32(b, &priv) ||
            sx_blob_get_int32(b, &undo_priv)) {
            sx_blob_loadpos(b);
            iter->i = 0;
            return NULL;
        }
        DEBUG("blob_iter on %s: %d,%d; %d,%d", name, priv,undo_priv, priv_state,priv_mask);
        if (priv_state > 0) {
            if (priv > 0 && priv & priv_mask)
                return name;
        } else {
            if (priv < 0 && (~priv) & priv_mask)
                return name;
        }
    }
    iter->i = 0;
    sx_blob_loadpos(b);
    return NULL;
}

static const char *grant_read_cb(void *ctx)
{
    return blob_iter_cb(ctx, 1, PRIV_READ);
}

static const char *grant_write_cb(void *ctx)
{
    return blob_iter_cb(ctx, 1, PRIV_WRITE);
}

static const char *revoke_read_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_READ);
}

static const char *revoke_write_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_WRITE);
}

static sxi_query_t* acl_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    const char *volume = NULL;
    struct blob_iter iter;
    memset(&iter, 0, sizeof(iter));

    if (sx_blob_get_string(b, &volume) ||
        sx_blob_get_int32(b, &iter.n)) {
        WARN("Corrupt acl blob");
        return NULL;
    }
    sx_blob_savepos(b);
    iter.b = b;
    return sxi_volumeacl_proto(sx, volume,
                               grant_read_cb, grant_write_cb,
                               revoke_read_cb, revoke_write_cb,
                               &iter);
}

const char *acl_get_lock(sx_blob_t *b)
{
    const char *name = NULL;
    return !sx_blob_get_string(b, &name) ? name : NULL;
}

static rc_ty acl_nodes(sxc_client_t *sx, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    *nodes = sx_nodelist_dup(sx_hashfs_nodelist(hashfs, NL_NEXTPREV));
    if (!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

const job_2pc_t acl_spec = {
    &acl_ops_parser,
    JOBTYPE_VOLUME_ACL,
    acl_parse_complete,
    acl_get_lock,
    acl_to_blob,
    acl_execute_blob,
    acl_proto_from_blob,
    acl_nodes
};

void fcgi_acl_volume(void) {
    int i;
    if (is_reserved())
	quit_errmsg(403, "Invalid volume name: must not start with a '.'");
    struct acl_ctx actx;
    memset(&actx, 0, sizeof(actx));

    job_2pc_handle_request(sx_hashfs_client(hashfs), &acl_spec, &actx);

    for (i=0;i<actx.n;i++) {
        free(actx.ops[i].name);
    }
    free(actx.ops);
}

static const yajl_callbacks vol_ops_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_vol_number,
    cb_vol_string,
    cb_vol_start_map,
    cb_vol_map_key,
    cb_vol_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

void fcgi_create_volume(void) {
    struct cb_vol_ctx yctx;
    rc_ty s;

    if(sx_hashfs_check_volume_name(volume))
	quit_errmsg(400, "Bad volume name");

    yctx.state = CB_VOL_START;
    yctx.volsize = -1LL;
    yctx.replica = 0;
    yctx.revisions = 0;
    yctx.owner[0] = '\0';
    yctx.nmeta = 0;
    yctx.metablb = sx_blob_new();
    if(!yctx.metablb)
	quit_errmsg(500, "Cannot allocate meta storage");
    sx_blob_savepos(yctx.metablb);

    yajl_handle yh = yajl_alloc(&vol_ops_parser, NULL, &yctx);
    if(!yh) {
	sx_blob_free(yctx.metablb);
	quit_errmsg(500, "Cannot allocate json parser");
    }

    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || !yctx.owner[0] || yctx.state != CB_VOL_COMPLETE) {
	yajl_free(yh);
	sx_blob_free(yctx.metablb);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
	sx_blob_free(yctx.metablb);
	send_authreq();
	return;
    }

    if(yctx.volsize < SXLIMIT_MIN_VOLUME_SIZE || yctx.volsize > SXLIMIT_MAX_VOLUME_SIZE) {
	sx_blob_free(yctx.metablb);
	quit_errmsg(400, "Bad volume size");
    }
    int64_t owner_uid;
    if(sx_hashfs_get_uid(hashfs, yctx.owner, &owner_uid)) {
	sx_blob_free(yctx.metablb);
	quit_errmsg(400, "Invalid owner");
    }

    if(yctx.revisions == 0)
	yctx.revisions = 1;

    if(has_priv(PRIV_CLUSTER)) {
	/* Request comes in from the cluster: apply locally */
	sx_hashfs_volume_new_begin(hashfs);
	sx_blob_loadpos(yctx.metablb);
	while(yctx.nmeta--) {
	    const char *mkey;
	    const void *mval;
	    unsigned int mval_len;
	    if(sx_blob_get_string(yctx.metablb, &mkey) ||
	       sx_blob_get_blob(yctx.metablb, &mval, &mval_len)) {
		sx_blob_free(yctx.metablb);
		quit_errmsg(500, "Cannot get metadata from blob");
	    }
	    s = sx_hashfs_volume_new_addmeta(hashfs, mkey, mval, mval_len);
	    if(s != OK) {
		sx_blob_free(yctx.metablb);
		if(s == EOVERFLOW)
		    quit_errmsg(400, "Too many metadata items");
		else
		    quit_errmsg(400, "Bad metadata");
	    }
	}

	s = sx_hashfs_volume_new_finish(hashfs, volume, yctx.volsize, yctx.replica, yctx.revisions, owner_uid);
	sx_blob_free(yctx.metablb);

	switch (s) {
	case OK:
	    break;
	case FAIL_VOLUME_EEXIST:
	    quit_errmsg(409, "Volume already exists");
	case ENAMETOOLONG: /* FIXME: currently not returned */
	    quit_errmsg(414, "Volume name too long");
	case EINVAL:
	    quit_errmsg(400, msg_get_reason());
	default:
	    if (msg_was_busy())
		quit_errmsg(503, "The requested volume could not be created: try again later");
	    else
		quit_errmsg(500, "The requested volume could not be created");
	}
	CGI_PUTS("\r\n");
	return;
    } else {
	/* Request comes in from the user: broadcst to all nodes */
	sx_blob_t *joblb = sx_blob_new();
	const void *job_data;
	unsigned int job_datalen;
	const sx_nodelist_t *allnodes = sx_hashfs_nodelist(hashfs, NL_NEXTPREV);
	int extra_job_timeout = 50 * (sx_nodelist_count(allnodes)-1);
	job_t job;
	rc_ty res;

	if(!joblb) {
	    sx_blob_free(yctx.metablb);
	    quit_errmsg(500, "Cannot allocate job blob");
	}
	if(sx_blob_add_string(joblb, volume) ||
	   sx_blob_add_string(joblb, yctx.owner) ||
	   sx_blob_add_int64(joblb, yctx.volsize) ||
	   sx_blob_add_int32(joblb, yctx.replica) ||
	   sx_blob_add_int32(joblb, yctx.revisions) ||
	   sx_blob_add_int32(joblb, yctx.nmeta) ||
	   sx_blob_add_int32(joblb, extra_job_timeout) ||
	   sx_blob_cat(joblb, yctx.metablb)) {
	    sx_blob_free(yctx.metablb);
	    sx_blob_free(joblb);
	    quit_errmsg(500, "Cannot create job blob");
	}
	sx_blob_free(yctx.metablb);

	sx_blob_to_data(joblb, &job_data, &job_datalen);
	/* Volumes are created globally, in no particluar order (PREVNEXT would be fine too) */
	res = sx_hashfs_job_new(hashfs, uid, &job, JOBTYPE_CREATE_VOLUME, 20, volume, job_data, job_datalen, allnodes);
	sx_blob_free(joblb);
	if(res != OK)
	    quit_errmsg(rc2http(res), msg_get_reason());

	send_job_info(job);
	return;
    }
}

void fcgi_volume_onoff(int enable) {
    rc_ty s;
    if(is_reserved())
	quit_errmsg(403, "Invalid volume name: must not start with a '.'");

    if(enable)
	s = sx_hashfs_volume_enable(hashfs, volume);
    else
	s = sx_hashfs_volume_disable(hashfs, volume);

    if(s != OK)
	quit_errnum(400);

    CGI_PUTS("\r\n");
}

void fcgi_delete_volume(void) {
    rc_ty s;
    if(is_reserved())
	quit_errmsg(403, "Invalid volume name: must not start with a '.'");

    s = sx_hashfs_volume_delete(hashfs, volume);
    if(s != OK)
	quit_errnum(rc2http(s));

    CGI_PUTS("\r\n");
}

void fcgi_trigger_gc(void)
{
    auth_complete();
    quit_unless_authed();
    sx_hashfs_gc_trigger(hashfs);
    CGI_PUTS("\r\n");
}
