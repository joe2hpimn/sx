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

static rc_ty int64_arg(const char* arg, int64_t *v, int64_t defaultv)
{
    const char *s = get_arg(arg);
    char *eon;
    *v = defaultv;
    if (s) {
        *v = strtoll(s, &eon, 10);
        if (*eon || *v < 0) {
            msg_set_reason("Invalid '%s' parameter: '%s'", arg, s);
            return EINVAL;
        }
    }
    return OK;
}

void fcgi_locate_volume(const sx_hashfs_volume_t *vol) {
    sx_nodelist_t *allnodes, *goodnodes;
    unsigned int blocksize, nnode, nnodes;
    int64_t fsize;
    rc_ty s;

    if (int64_arg("size", &fsize, 0))
        quit_errmsg(400, msg_get_reason());

    /* The locate_volume query is shared between different ops.
     * Although most of them (file creation, file deletion, etc) can be
     * safely target to PREV and NEXT volumes, listing files is only 
     * guaranteed to be accurate when performed against a PREV volnode */
    s = sx_hashfs_volnodes(hashfs, NL_PREV, vol, fsize, &allnodes, &blocksize);
    switch(s) {
	case OK:
	    break;
	case EINVAL:
	    quit_errmsg(400, msg_get_reason());
	default:
	    quit_errmsg(500, "Cannot locate the requested volume");
    }

    goodnodes = sx_nodelist_new();
    if(!goodnodes) {
	sx_nodelist_delete(allnodes);
	quit_errmsg(503, "Out of memeory");
    }
    nnodes = sx_nodelist_count(allnodes);
    for(nnode=0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(allnodes, nnode);
	if(sx_hashfs_is_node_faulty(hashfs, sx_node_uuid(node)))
	    continue;
	if(sx_nodelist_add(goodnodes, sx_node_dup(node)))
	    break;
    }
    sx_nodelist_delete(allnodes);
    if(nnode < nnodes) {
	sx_nodelist_delete(goodnodes);
	quit_errmsg(503, "Out of memeory");
    }
    if(!sx_nodelist_count(goodnodes)) {
	sx_nodelist_delete(goodnodes);
	quit_errmsg(503, "All nodes for the volume have failed");
    }

    if(has_arg("volumeMeta") && sx_hashfs_volumemeta_begin(hashfs, vol)) {
	sx_nodelist_delete(goodnodes);
	quit_errmsg(500, "Cannot lookup volume metadata");
    }

    CGI_PUTS("Content-type: application/json\r\n\r\n{\"nodeList\":");
    send_nodes_randomised(goodnodes);
    sx_nodelist_delete(goodnodes);
    if(has_arg("size"))
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
    unsigned int comma = 0;
    sx_hash_t etag;
    rc_ty s;
    const char *pattern;
    int recursive, size_only;
    int64_t i, nmax;

    if (int64_arg("limit", &nmax, ~0u))
        quit_errmsg(400, msg_get_reason());

    CGI_PUTS("Content-type: application/json\r\n");

    /* If we have sizeOnly parameter given, no listing will be performed */
    size_only = has_arg("sizeOnly");
    if (!size_only) {
        pattern = get_arg("filter");
        recursive = has_arg("recursive");
        if(!pattern)
            pattern = "/";
        if (sx_hashfs_list_etag(hashfs, vol, pattern, recursive, &etag)) {
            quit_errmsg(500, "failed to calculate etag");
        }
        if(is_object_fresh(&etag, 'L', NO_LAST_MODIFIED)) {
            return;
        }
    }
    CGI_PUTS("\r\n");
    if (verb == VERB_HEAD)
        return;
    CGI_PUTS("{\"volumeSize\":");
    CGI_PUTLL(vol->size);
    CGI_PRINTF(",\"replicaCount\":%u,\"volumeUsedSize\":", vol->replica_count);
    CGI_PUTLL(vol->cursize);
    if (size_only) {
        CGI_PUTS("}");
        return;
    }

    s = sx_hashfs_list_first(hashfs, vol, get_arg("filter"), &file, has_arg("recursive"), get_arg("after"));
    switch(s) {
    case OK:
    case ITER_NO_MORE:
	break;
    case ENOENT: {
	quit_itererr("The list for the volume is not available here", ENOENT);
    }
    case EINVAL: {
	quit_itererr("Invalid argument", EINVAL);
    }
    default: {
	quit_itererr("Internal error", FAIL_EINTERNAL);
    }
    }

    CGI_PUTS(",\"fileList\":{");

    for(i=0; s == OK && i < nmax; i++, s = sx_hashfs_list_next(hashfs)) {
	/* Make room for the comma,
	 * the worst case encoded filename,
	 * the whole file data,
	 * the json closure
	 * and the string terminator */

	/* "filename":{"fileSize":123,"blockSize":4096,"createdAt":456,"fileRev":"REVISON_STRING"} */
	if(comma) {
            CGI_PUTC(',');
	} else
	    comma |= 1;

	json_send_qstring(file->name);
	if(file->revision[0]) {
	    /* A File */
            CGI_PUTS(":{\"fileSize\":");
            CGI_PUTLL(file->file_size);
            CGI_PRINTF(",\"blockSize\":%u,\"createdAt\":", file->block_size);
            CGI_PUTT(file->created_at);
            CGI_PRINTF(",\"fileRevision\":\"%s\"}", file->revision);
	} else {
	    /* A Fakedir */
            CGI_PUTS(":{}");
	}
    }

    CGI_PUTS("}");
    if (i == nmax) {
        DEBUG("listing truncated after %lld filenames", (long long)i);
        s = ITER_NO_MORE;
    }

    if(s != ITER_NO_MORE)  {
	quit_itererr("Failed to list files", s);
        WARN("failed to list: %s", rc2str(s));
    }
    CGI_PUTS("}");
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
	    c->replica = 1;
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

static int print_acl(const char *username, int priv, int is_owner, void *ctx)
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
    if (is_owner) {
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

static rc_ty acl_parse_complete(void *yctx)
{
    struct acl_ctx *actx = yctx;
    return actx && actx->state == CB_ACL_COMPLETE ? OK : EINVAL;
}

static int acl_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *blob)
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

static rc_ty acl_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase, int remote)
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

static unsigned acl_timeout(sxc_client_t *sx, int nodes)
{
    return 12 * nodes;
}

const job_2pc_t acl_spec = {
    &acl_ops_parser,
    JOBTYPE_VOLUME_ACL,
    acl_parse_complete,
    acl_get_lock,
    acl_to_blob,
    acl_execute_blob,
    acl_proto_from_blob,
    acl_nodes,
    acl_timeout
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
	sx_blob_t *joblb;
	const void *job_data;
	unsigned int job_datalen;
	const sx_nodelist_t *allnodes = sx_hashfs_nodelist(hashfs, NL_NEXTPREV);
	int extra_job_timeout = 50 * (sx_nodelist_count(allnodes)-1);
	job_t job;
	rc_ty res;

        res = sx_hashfs_check_volume_settings(hashfs, volume, yctx.volsize, yctx.replica, yctx.revisions);
        if(res != OK) {
            sx_blob_free(yctx.metablb);
            if(res == EINVAL)
                quit_errmsg(400, msg_get_reason());
            else
                quit_errmsg(500, "The requested volume could not be created");
        }

	if(!(joblb = sx_blob_new())) {
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

    if(has_priv(PRIV_CLUSTER)) {
	/* Coming in from cluster */
	s = sx_hashfs_volume_delete(hashfs, volume, has_arg("force"));
	if(s != OK)
	    quit_errnum(rc2http(s));

	CGI_PUTS("\r\n");

    } else {
	/* Coming in from (admin) user */
	const sx_hashfs_volume_t *vol;
	const sx_nodelist_t *allnodes;
	unsigned int timeout;
	const void *job_data;
	unsigned int job_datalen;
	sx_blob_t *joblb;
	int emptyvol = 0;
	job_t job;

	if((s = sx_hashfs_volume_by_name(hashfs, volume, &vol)))
	    quit_errmsg(rc2http(s), msg_get_reason());

	if(!sx_hashfs_is_or_was_my_volume(hashfs, vol))
	    quit_errmsg(404, "This volume does not belong here");

	if(!vol->cursize) {
	    s = sx_hashfs_list_first(hashfs, vol, NULL, NULL, 1, NULL);
	    if(s == ITER_NO_MORE)
		emptyvol = 1;
	    else if(s != OK)
		quit_errmsg(rc2http(s), msg_get_reason());
	}

	if(!emptyvol)
	    quit_errmsg(409, "Cannot delete non-empty volume");

	allnodes = sx_hashfs_nodelist(hashfs, NL_NEXTPREV);
	timeout = 5 * 60 * sx_nodelist_count(allnodes);
	joblb = sx_blob_new();
	if(!joblb)
	    quit_errmsg(500, "Cannot allocate job blob");

	if(sx_blob_add_string(joblb, volume)) {
	    sx_blob_free(joblb);
	    quit_errmsg(500, "Cannot create job blob");
	}

	sx_blob_to_data(joblb, &job_data, &job_datalen);
	s = sx_hashfs_job_new(hashfs, 0, &job, JOBTYPE_DELETE_VOLUME, timeout, path, job_data, job_datalen, allnodes);
	sx_blob_free(joblb);

	if(s != OK)
	    quit_errmsg(rc2http(s), msg_get_reason());

	send_job_info(job);

    }
}

void fcgi_trigger_gc(void)
{
    auth_complete();
    quit_unless_authed();
    sx_hashfs_gc_trigger(hashfs);
    CGI_PUTS("\r\n");
}

/* {"vol1":123,"vol2":122} */
struct cb_volsizes_ctx {
    enum cb_volsizes_state { CB_VOLSIZES_START, CB_VOLSIZES_KEY, CB_VOLSIZES_SIZE, CB_VOLSIZES_COMPLETE } state;
    sx_hashfs_volume_t *vols;
    unsigned int nvols;
};

static int cb_volsizes_number(void *ctx, const char *s, size_t l) {
    struct cb_volsizes_ctx *c = (struct cb_volsizes_ctx *)ctx;
    char number[21], *eon;
    if(c->state == CB_VOLSIZES_SIZE) {
        sx_hashfs_volume_t *vol = &c->vols[c->nvols-1];

        if(vol->cursize >= 0 || l<1 || l>20) {
            WARN("Failed to parse volume size");
            return 0;
        }

        memcpy(number, s, l);
        number[l] = '\0';
        vol->cursize = strtoll(number, &eon, 10);
        if(*eon)
            return 0;
        if(vol->cursize < 0) {
            WARN("Volume size is negative, falling back to 0");
            vol->cursize = 0;
        }
    }
    c->state = CB_VOLSIZES_KEY;
    return 1;
}

static int cb_volsizes_start_map(void *ctx) {
    struct cb_volsizes_ctx *c = (struct cb_volsizes_ctx *)ctx;
    if(c->state == CB_VOLSIZES_START)
        c->state = CB_VOLSIZES_KEY;
    else
        return 0;
    return 1;
}

static int cb_volsizes_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_volsizes_ctx *c = (struct cb_volsizes_ctx *)ctx;
    if(c->state == CB_VOLSIZES_KEY) {
        char name[SXLIMIT_MAX_VOLNAME_LEN+1];
        const sx_hashfs_volume_t *vol;
        sx_hashfs_volume_t *oldptr;

        if(l > SXLIMIT_MAX_VOLNAME_LEN) {
            WARN("Failed to parse volume: name is too long");
            return 0;
        }

        /* Copy to local buffer to support nulbyte termination */
        memcpy(name, s, l);
        name[l] = '\0';

        /* Get volume instance */
        if(sx_hashfs_volume_by_name(hashfs, name, &vol) != OK) {
            WARN("Failed to get volume %s instance: %s", name, msg_get_reason());
            return 0;
        }

        /* Check if volume was mine on PREV */
        if(sx_hashfs_is_node_volume_owner(hashfs, NL_PREV, sx_hashfs_self(hashfs), vol)) {
            WARN("Request was sent to node that is a volnode of %s", vol->name);
            msg_set_reason(".volsizes request sent to a volnode of %s", vol->name);
            return 0;
        }

        /* Get memory for new volume */
        oldptr = c->vols;
        c->vols = realloc(c->vols, (++c->nvols) * sizeof(*vol));
        if(!c->vols) {
            WARN("Failed to realloc volumes array");
            free(oldptr);
            return 0;
        }

        /* Copy current volume to the array */
        memcpy(&c->vols[c->nvols-1], vol, sizeof(*vol));

        /* Reset cursize */
        c->vols[c->nvols-1].cursize = -1LL;

        c->state = CB_VOLSIZES_SIZE;
        return 1;
    }
    return 0;
}

static int cb_volsizes_end_map(void *ctx) {
    struct cb_volsizes_ctx *c = (struct cb_volsizes_ctx *)ctx;
    if(c->state == CB_VOLSIZES_KEY)
        c->state = CB_VOLSIZES_COMPLETE;
    else
        return 0;
    return 1;
}

static const yajl_callbacks volsizes_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_volsizes_number,
    NULL,
    cb_volsizes_start_map,
    cb_volsizes_map_key,
    cb_volsizes_end_map,
    NULL,
    NULL
};

void fcgi_volsizes(void) {
    struct cb_volsizes_ctx yctx;
    yajl_handle yh;
    int len;
    unsigned int i;

    /* Assign begin state */
    yctx.state = CB_VOLSIZES_START;
    yctx.nvols = 0;
    yctx.vols = NULL;

    yh = yajl_alloc(&volsizes_parser, NULL, &yctx);
    if(!yh)
        quit_errmsg(500, "Cannot allocate json parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
        if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_VOLSIZES_COMPLETE) {
        free(yctx.vols);
        yajl_free(yh);
        WARN("Failed to parse JSON");
        quit_errmsg(400, "Invalid request content");
    }

    /* JSON parsing completed */
    auth_complete();
    if(!is_authed()) {
        free(yctx.vols);
        yajl_free(yh);
        send_authreq();
        return;
    }

    for(i = 0; i < yctx.nvols; i++) {
        const sx_hashfs_volume_t *vol = &yctx.vols[i];
        rc_ty rc;

        /* Set volume size */
        if((rc = sx_hashfs_reset_volume_cursize(hashfs, vol->id, vol->cursize)) != OK) {
            WARN("Failed to set volume %s size to %lld", vol->name, (long long)vol->cursize);
            free(yctx.vols);
            yajl_free(yh);
            quit_errmsg(rc2http(rc), rc2str(rc));
        }
    }

    CGI_PUTS("\r\n");
    free(yctx.vols);
    yajl_free(yh);
}

/* {"owner":"alice","size":1000000000} */
struct volmod_ctx {
    enum cb_volmod_state { CB_VOLMOD_START, CB_VOLMOD_KEY, CB_VOLMOD_OWNER, CB_VOLMOD_SIZE, CB_VOLMOD_COMPLETE } state;
    const char *volume;
    char oldowner[SXLIMIT_MAX_FILENAME_LEN+1];
    char newowner[SXLIMIT_MAX_FILENAME_LEN+1];
    int64_t oldsize;
    int64_t newsize;
};

static const char *volmod_get_lock(sx_blob_t *b)
{
    const char *vol = NULL;
    return !sx_blob_get_string(b, &vol) ? vol : NULL;
}

static rc_ty volmod_nodes(sxc_client_t *sx, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    /* All nodes have to receive modification request since owners and sizes are set globally */
    *nodes = sx_nodelist_dup(sx_hashfs_nodelist(hashfs, NL_NEXTPREV));
    if (!*nodes)
        return FAIL_EINTERNAL;

    return OK;
}

static int blob_to_volmod(sx_blob_t *b, struct volmod_ctx *ctx) {
    const char *oldowner = NULL, *newowner = NULL;

    if(!b || !ctx)
        return 1;

    if(sx_blob_get_string(b, &ctx->volume) || sx_blob_get_string(b, &oldowner)
       || sx_blob_get_string(b, &newowner) || sx_blob_get_int64(b, &ctx->oldsize)
       || sx_blob_get_int64(b, &ctx->newsize)) {
        WARN("Corrupted volume mod blob");
        return 1;
    }

    if(oldowner && *oldowner)
        snprintf(ctx->oldowner, SXLIMIT_MAX_USERNAME_LEN+1, "%s", oldowner);
    else
        ctx->oldowner[0] = '\0';

    if(newowner && *newowner)
        snprintf(ctx->newowner, SXLIMIT_MAX_USERNAME_LEN+1, "%s", newowner);
    else
        ctx->newowner[0] = '\0';

    return 0;
}

static int volmod_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct volmod_ctx *ctx = yctx;
    if (!joblb) {
        msg_set_reason("Cannot allocate job storage");
        return -1;
    }

    if(sx_blob_add_string(joblb, ctx->volume) || sx_blob_add_string(joblb, ctx->oldowner)
        || sx_blob_add_string(joblb, ctx->newowner) || sx_blob_add_int64(joblb, ctx->oldsize)
        || sx_blob_add_int64(joblb, ctx->newsize)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }
    return 0;
}

static unsigned volmod_timeout(sxc_client_t *sx, int nodes)
{
    return 20 * nodes;
}

static sxi_query_t* volmod_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    struct volmod_ctx ctx;

    if(blob_to_volmod(b, &ctx)) {
        WARN("Failed to read job blob");
        return NULL;
    }

    switch (phase) {
        case JOBPHASE_COMMIT:
            return sxi_volume_mod_proto(sx, ctx.volume, ctx.newowner, ctx.newsize);
        case JOBPHASE_ABORT:
            return sxi_volume_mod_proto(sx, ctx.volume, ctx.oldowner, ctx.oldsize);
        case JOBPHASE_UNDO:
            return sxi_volume_mod_proto(sx, ctx.volume, ctx.oldowner, ctx.oldsize);
        default:
            return NULL;
    }
}

static rc_ty volmod_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    struct volmod_ctx ctx;
    rc_ty rc = OK;
    if (!h || !b) {
        WARN("NULL arguments");
        return FAIL_EINTERNAL;
    }

    if(blob_to_volmod(b, &ctx)) {
        WARN("Corrupted volume mod blob");
        return FAIL_EINTERNAL;
    }

    if (remote && phase == JOBPHASE_REQUEST)
        phase = JOBPHASE_COMMIT;

    switch (phase) {
        case JOBPHASE_COMMIT:
            rc = sx_hashfs_volume_mod(h, ctx.volume, ctx.newowner, ctx.newsize);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.volume, msg_get_reason());
            return rc;
        case JOBPHASE_ABORT:
            rc = sx_hashfs_volume_mod(h, ctx.volume, ctx.oldowner, ctx.oldsize);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.volume, msg_get_reason());
            return rc;
        case JOBPHASE_UNDO:
            CRIT("volume '%s' may have been left in an inconsistent state after a failed modification attempt", ctx.volume);
            rc = sx_hashfs_volume_mod(h, ctx.volume, ctx.oldowner, ctx.oldsize);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.volume, msg_get_reason());
            return rc;
        default:
            WARN("Impossible job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

static rc_ty volmod_parse_complete(void *yctx)
{
    rc_ty s;
    struct volmod_ctx *ctx = yctx;
    const sx_hashfs_volume_t *vol = NULL;
    if (!ctx || ctx->state != CB_VOLMOD_COMPLETE)
        return EINVAL;

    /* Check if volume exists */
    if(sx_hashfs_volume_by_name(hashfs, volume, &vol) != OK) {
        WARN("Volume does not exist");
        msg_set_reason("Volume does not exist");
        return ENOENT;
    }

    /* Preliminary checks for ownership change */
    if(*ctx->newowner) {
        /* Do that check only for local node */
        if(sx_hashfs_uid_get_name(hashfs, vol->owner, ctx->oldowner, SXLIMIT_MAX_USERNAME_LEN) != OK) {
            WARN("Could not get current volume owner");
            msg_set_reason("Volume owner does not exist");
            return ENOENT;
        }

        if(sx_hashfs_check_username(ctx->newowner)) {
            msg_set_reason("Bad user name");
            return EINVAL;
        }

        /* Check if new volume owner exists */
        if((s = sx_hashfs_get_user_by_name(hashfs, ctx->newowner, NULL)) != OK) {
            msg_set_reason("User not found");
            return s;
        }

        /* Check if old owner is not the same as new one */
        if(!has_priv(PRIV_CLUSTER) && !strncmp(ctx->oldowner, ctx->newowner, SXLIMIT_MAX_USERNAME_LEN)) {
            WARN("New owner is the same as old owner");
            msg_set_reason("User is already a volume owner");
            return EINVAL;
        }
    }

    /* Preliminary checks for size change */
    if(ctx->newsize != -1) {
        /* Do that check only for local node */
        if(!has_priv(PRIV_CLUSTER) && ctx->newsize == vol->size) {
            WARN("Invalid volume size: same as current value");
            msg_set_reason("New volume size is the same as the current value");
            return EINVAL;
        }
        ctx->oldsize = vol->size;

        /* Check if new volume size is ok */
        if((s = sx_hashfs_check_volume_settings(hashfs, volume, ctx->newsize, vol->replica_count, vol->revisions)) != OK)
            return s; /* Message is set by sx_hashfs_check_volume_settings() */
    }

    return OK;
}


static int cb_volmod_string(void *ctx, const unsigned char *s, size_t l) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->state == CB_VOLMOD_OWNER) {
        if(l > SXLIMIT_MAX_USERNAME_LEN) {
            WARN("Failed to parse volume: name is too long");
            return 0;
        }
        memcpy(c->newowner, s, l);
        c->newowner[l] = '\0';

        c->state = CB_VOLMOD_KEY;
        return 1;
    }
    return 0;
}

static int cb_volmod_number(void *ctx, const char *s, size_t l) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    char number[21], *eon;
    if(c->state == CB_VOLMOD_SIZE) {
        if(c->newsize >= 0 || l<1 || l>20) {
            WARN("Failed to parse new volume size");
            return 0;
        }

        memcpy(number, s, l);
        number[l] = '\0';
        c->newsize = strtoll(number, &eon, 10);
        if(*eon)
            return 0;

        c->state = CB_VOLMOD_KEY;
        return 1;
    }
    return 0;
}

static int cb_volmod_start_map(void *ctx) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->state == CB_VOLMOD_START)
        c->state = CB_VOLMOD_KEY;
    else
        return 0;
    return 1;
}

static int cb_volmod_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->state == CB_VOLMOD_KEY) {
        if(l == lenof("owner") && !strncmp("owner", (const char*)s, l)) {
            c->state = CB_VOLMOD_OWNER;
            return 1;
        }
        if(l == lenof("size") && !strncmp("size", (const char*)s, l)) {
            c->state = CB_VOLMOD_SIZE;
            return 1;
        }
    }
    return 0;
}

static int cb_volmod_end_map(void *ctx) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->state == CB_VOLMOD_KEY)
        c->state = CB_VOLMOD_COMPLETE;
    else
        return 0;
    return 1;
}

static const yajl_callbacks volmod_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_volmod_number,
    cb_volmod_string,
    cb_volmod_start_map,
    cb_volmod_map_key,
    cb_volmod_end_map,
    NULL,
    NULL
};

const job_2pc_t volmod_spec = {
    &volmod_parser,
    JOBTYPE_MODIFY_VOLUME,
    volmod_parse_complete,
    volmod_get_lock,
    volmod_to_blob,
    volmod_execute_blob,
    volmod_proto_from_blob,
    volmod_nodes,
    volmod_timeout
};

void fcgi_volume_mod(void) {
    struct volmod_ctx ctx;

    /* Assign begin state */
    ctx.state = CB_VOLMOD_START;
    ctx.oldowner[0] = '\0';
    ctx.newowner[0] = '\0';
    ctx.newsize = -1;
    ctx.oldsize = -1;
    ctx.volume = volume;

    job_2pc_handle_request(sx_hashfs_client(hashfs), &volmod_spec, &ctx);
}
