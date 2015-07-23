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
#include <arpa/inet.h>
#include "fcgi-utils.h"
#include "fcgi-actions-volume.h"
#include "../libsxclient/src/misc.h"
#include "blob.h"
#include "utils.h"
#include "job_common.h"
#include "version.h"

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
    unsigned int blocksize, nnode, nnodes, i;
    int64_t fsize;
    rc_ty s;
    struct {
        char key[SXLIMIT_META_MAX_KEY_LEN+1];
        uint8_t value[SXLIMIT_META_MAX_VALUE_LEN];
        int value_len;
    } custom_meta[SXLIMIT_META_MAX_ITEMS], meta[SXLIMIT_META_MAX_ITEMS];
    unsigned int nmeta = 0, ncustommeta = 0;

    if (int64_arg("size", &fsize, 0))
        quit_errmsg(400, msg_get_reason());

    /* The locate_volume query is shared between different ops.
     * Although most of them (file creation, file deletion, etc) can be
     * safely target to PREV and NEXT volumes, listing files is only 
     * guaranteed to be accurate when performed against a PREV volnode */
    s = sx_hashfs_effective_volnodes(hashfs, NL_PREV, vol, fsize, &allnodes, &blocksize);
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

    if(has_arg("volumeMeta") || has_arg("customVolumeMeta")) {
        const char *metakey;
        const void *metavalue;
        unsigned int metasize;
        if(sx_hashfs_volumemeta_begin(hashfs, vol)) {
            sx_nodelist_delete(goodnodes);
            quit_errmsg(500, "Cannot lookup volume metadata");
        }

        while((s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK) {
            if(!strncmp(SX_CUSTOM_META_PREFIX, metakey, lenof(SX_CUSTOM_META_PREFIX))) {
                if(has_arg("customVolumeMeta")) {
                    /* Append custom meta value */
                    sxi_strlcpy(custom_meta[ncustommeta].key, metakey + lenof(SX_CUSTOM_META_PREFIX), sizeof(custom_meta[ncustommeta].key) - lenof(SX_CUSTOM_META_PREFIX));
                    memcpy(custom_meta[ncustommeta].value, metavalue, metasize);
                    custom_meta[ncustommeta].value_len = metasize;
                    ncustommeta++;
                }
            } else {
                if(has_arg("volumeMeta")) {
                    /* Append regular meta value */
                    sxi_strlcpy(meta[nmeta].key, metakey, sizeof(meta[nmeta].key));
                    memcpy(meta[nmeta].value, metavalue, metasize);
                    meta[nmeta].value_len = metasize;
                    nmeta++;
                }
            }
        }

        if(s != ITER_NO_MORE) {
            sx_nodelist_delete(goodnodes);
            quit_errmsg(rc2http(s), rc2str(s));
        }
    }
    CGI_PUTS("Content-type: application/json\r\n\r\n{\"nodeList\":");
    send_nodes_randomised(goodnodes);
    sx_nodelist_delete(goodnodes);
    if(has_arg("size"))
	CGI_PRINTF(",\"blockSize\":%d", blocksize);
    if(has_arg("volumeMeta")) {
        CGI_PUTS(",\"volumeMeta\":{");
        for(i = 0; i < nmeta; i++) {
            char hexval[SXLIMIT_META_MAX_VALUE_LEN*2+1];
            if(i)
                CGI_PUTC(',');
            json_send_qstring(meta[i].key);
            CGI_PUTS(":\"");
            bin2hex(meta[i].value, meta[i].value_len, hexval, sizeof(hexval));
            CGI_PUTS(hexval);
            CGI_PUTC('"');
        }
        CGI_PUTC('}');
    }
    if(has_arg("customVolumeMeta")) {
        CGI_PUTS(",\"customVolumeMeta\":{");
        for(i = 0; i < ncustommeta; i++) {
            char hexval[SXLIMIT_META_MAX_VALUE_LEN*2+1];
            if(i)
                CGI_PUTC(',');
            json_send_qstring(custom_meta[i].key);
            CGI_PUTS(":\"");
            bin2hex(custom_meta[i].value, custom_meta[i].value_len, hexval, sizeof(hexval));
            CGI_PUTS(hexval);
            CGI_PUTC('"');
        }
        CGI_PUTC('}');
    }
    CGI_PUTC('}');

}


void fcgi_list_volume(const sx_hashfs_volume_t *vol) {
    const sx_hashfs_file_t *file;
    unsigned int comma = 0;
    sx_hash_t etag;
    rc_ty s;
    const char *pattern;
    int recursive;
    int64_t i, nmax;

    if (int64_arg("limit", &nmax, ~0u))
        quit_errmsg(400, msg_get_reason());

    CGI_PUTS("Content-type: application/json\r\n");

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
    CGI_PUTS("\r\n");
    if (verb == VERB_HEAD)
        return;
    CGI_PUTS("{\"volumeSize\":");
    CGI_PUTLL(vol->size);
    CGI_PRINTF(",\"replicaCount\":%u,\"volumeUsedSize\":", vol->max_replica);
    CGI_PUTLL(vol->cursize);

    s = sx_hashfs_list_first(hashfs, vol, get_arg("filter"), &file, has_arg("recursive"), get_arg("after"), 0);
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
    if(sx_hashfs_check_volume_meta(c->metakey, metavalue, l) ||
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

enum acl_state { CB_ACL_START=0, CB_ACL_KEY, CB_ACL_KEYARRAY, CB_ACL_GRANT_READ, CB_ACL_GRANT_WRITE, CB_ACL_GRANT_MANAGER, CB_ACL_REVOKE_READ, CB_ACL_REVOKE_WRITE, CB_ACL_REVOKE_MANAGER, CB_ACL_COMPLETE };
struct acl_op {
    char *name;
    int priv;
    int require_owner;
};

struct acl_ctx {
    struct acl_op *ops;
    unsigned n;
    int require_owner;
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
        case CB_ACL_GRANT_MANAGER:
            priv = PRIV_MANAGER;
            c->require_owner = 1;
            break;
        case CB_ACL_REVOKE_READ:
	    priv = ~PRIV_READ;
	    break;
	case CB_ACL_REVOKE_WRITE:
	    priv = ~PRIV_WRITE;
	    break;
        case CB_ACL_REVOKE_MANAGER:
            priv = ~PRIV_MANAGER;
            c->require_owner = 1;
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
    if (l == lenof("grant-manager") && !strncmp("grant-manager", s, l)) {
	c->state = CB_ACL_GRANT_MANAGER;
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
    if (l == lenof("revoke-manager") && !strncmp("revoke-manager", s, l)) {
	c->state = CB_ACL_REVOKE_MANAGER;
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

struct acl_print_ctx {
    int first;
    int is_1_1;
};

static int print_acl(const char *username, int priv, int is_owner, void *ctx)
{
    struct acl_print_ctx *actx = ctx;
    /* FIXME: should set api_version for send_server_info, however send_server_info is called before handle_request */
    if (actx->first)
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
    if (!actx->is_1_1 && (is_owner || (priv & PRIV_MANAGER))) {
	CGI_PRINTF("%s\"manager\"", comma ? "," : "");
	comma = 1;
    }
    if (is_owner) {
	CGI_PRINTF("%s\"owner\"", comma ? ",":"");
	comma = 1;
    }
    CGI_PUTS("]");
    actx->first = 0;
    return 0;
}

void fcgi_list_acl(const sx_hashfs_volume_t *vol) {
    struct acl_print_ctx actx;
    actx.first = 1;
    actx.is_1_1 = !has_arg("manager");
    rc_ty rc = sx_hashfs_list_acl(hashfs, vol, uid, get_priv(1), print_acl, &actx);
    if (rc != OK) {
	if (rc == ENOENT)
	    quit_errmsg(404, "Volume not found");
        if (rc == EPERM)
            quit_errmsg(403, "Not enough privileges to list volume ACL");
	if (actx.first) {
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
    if (!actx || actx->state != CB_ACL_COMPLETE)
        return EINVAL;
    if (actx->require_owner && !has_priv(PRIV_OWNER)) {
        msg_set_reason("Permission denied: granting/revoking the manager privilege requires owner or admin privilege");
        return EPERM;
    }
    return OK;
}

static int acl_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *blob)
{
    struct acl_ctx *actx = yctx;
    int i;
    if (sx_blob_add_string(blob, volume) ||
        sx_blob_add_int32(blob, actx->n))
        return -1;
    for (i=0;i<actx->n;i++) {
        uint8_t user_uid[AUTH_UID_LEN];
        rc_ty rc;
        int undo_priv, new_priv;
        sx_priv_t old_priv;/* TODO: get_access should return int not sx_priv_t, as its a bitmask not an enum */

        int priv  = actx->ops[i].priv;
        const char *name = actx->ops[i].name;
        rc = sx_hashfs_get_user_by_name(hashfs, name, user_uid, 0);
        if (rc) {
            msg_set_reason("Cannot retrieve user id for '%s'", name);
            return -1;
        }
        rc = sx_hashfs_get_access(hashfs, user_uid, volume, &old_priv);
        if (rc) {
            msg_set_reason("Cannot retrieve acl for volume '%s' and user '%s'", volume, name);
            return -1;
        }
        if (priv >= 0)
            new_priv = old_priv | priv;
        else
            new_priv = old_priv & priv;
        int undo_revoke = new_priv & ~old_priv;
        int undo_grant = old_priv & ~new_priv;
        if (undo_grant > 0)
            undo_priv = undo_grant;
        else
            undo_priv = ~undo_revoke;
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
            if (priv >= 0) {
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
    int phase;
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
        if (iter->phase != JOBPHASE_REQUEST && iter->phase != JOBPHASE_COMMIT)
            priv = undo_priv;
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

static const char *grant_manager_cb(void *ctx)
{
    return blob_iter_cb(ctx, 1, PRIV_MANAGER);
}

static const char *revoke_read_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_READ);
}

static const char *revoke_write_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_WRITE);
}

static const char *revoke_manager_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_MANAGER);
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
    iter.phase = phase;
    return sxi_volumeacl_proto(sx, volume,
                               grant_read_cb, grant_write_cb, grant_manager_cb,
                               revoke_read_cb, revoke_write_cb, revoke_manager_cb,
                               &iter);
}

const char *acl_get_lock(sx_blob_t *b)
{
    const char *name = NULL;
    return !sx_blob_get_string(b, &name) ? name : NULL;
}

static rc_ty acl_nodes(sx_hashfs_t *hashfs, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV));
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

	s = sx_hashfs_volume_new_finish(hashfs, volume, yctx.volsize, yctx.replica, yctx.revisions, owner_uid, 1);
	sx_blob_free(yctx.metablb);

	switch (s) {
	case OK:
	    break;
	case EEXIST:
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
	const sx_nodelist_t *allnodes = sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV);
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
	    s = sx_hashfs_list_first(hashfs, vol, NULL, NULL, 1, NULL, 0);
	    if(s == ITER_NO_MORE)
		emptyvol = 1;
	    else if(s != OK)
		quit_errmsg(rc2http(s), msg_get_reason());
	}

	if(!emptyvol)
	    quit_errmsg(409, "Cannot delete non-empty volume");

	allnodes = sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV);
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

/* {"owner":"alice","size":1000000000,"maxRevisions":10,"customVolumeMeta":{"customMeta1":"aabbcc"}} */
struct volmod_ctx {
    enum cb_volmod_state { CB_VOLMOD_START, CB_VOLMOD_KEY, CB_VOLMOD_OWNER, CB_VOLMOD_SIZE, CB_VOLMOD_REVS, CB_VOLMOD_META, CB_VOLMOD_METAKEY, CB_VOLMOD_METAVAL, CB_VOLMOD_COMPLETE } state;
    const char *volume;
    char oldowner[SXLIMIT_MAX_FILENAME_LEN+1];
    char newowner[SXLIMIT_MAX_FILENAME_LEN+1];
    int64_t oldsize;
    int64_t newsize;
    int oldrevs;
    int newrevs;
    char metakey[SXLIMIT_META_MAX_KEY_LEN+1];
    int nmeta;
    sx_blob_t *meta;
    int noldmeta;
    sx_blob_t *oldmeta;
};

static void volmod_ctx_init(struct volmod_ctx *ctx) {
    ctx->state = CB_VOLMOD_START;
    ctx->oldowner[0] = '\0';
    ctx->newowner[0] = '\0';
    ctx->newsize = -1;
    ctx->oldsize = -1;
    ctx->newrevs = -1;
    ctx->oldrevs = -1;
    ctx->volume = volume;
    ctx->meta = NULL;
    ctx->nmeta = -1;
    ctx->oldmeta = NULL;
    ctx->noldmeta = -1;
}

static const char *volmod_get_lock(sx_blob_t *b)
{
    const char *vol = NULL;
    return !sx_blob_get_string(b, &vol) ? vol : NULL;
}

static rc_ty volmod_nodes(sx_hashfs_t *h, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    /* All nodes have to receive modification request since owners and sizes are set globally */
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(h, NL_NEXTPREV));
    if (!*nodes)
        return FAIL_EINTERNAL;

    return OK;
}

static int blob_to_sxc_meta(sxc_client_t *sx, sx_blob_t *b, sxc_meta_t **meta, int skip) {
    int nmeta, i, ret = -1;
    if(!b || !meta)
        return 1;

    if(sx_blob_get_int32(b, &nmeta)) {
        WARN("Corrupted volume mod blob");
        return 1;
    }

    *meta = NULL;

    /* If nmeta is -1, then no metadata is stored in blob */
    if(nmeta == -1)
        return 0;

    if(!skip) {
        *meta = sxc_meta_new(sx);
        if(!*meta) {
            WARN("Failed to allocate metadata");
            return 1;
        }
    }

    for(i = 0; i < nmeta; i++) {
        const char *metakey;
        const void *metaval;
        unsigned int l;

        if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &l)) {
            WARN("Failed to get meta key-value pair from blob");
            goto blob_to_sxc_meta_err;
        }

        if(sx_hashfs_check_meta(metakey, metaval, l)) {
            WARN("Invalid meta");
            goto blob_to_sxc_meta_err;
        }

        if(!skip && sxc_meta_setval(*meta, metakey, metaval, l)) {
            WARN("Failed to add meta key-value pair to context blob");
            goto blob_to_sxc_meta_err;
        }
    }

    ret = 0;
blob_to_sxc_meta_err:
    if(ret)
        sxc_meta_free(*meta);

    return ret;
}

static int blob_to_volmod(sxc_client_t *sx, sx_blob_t *b, struct volmod_ctx *ctx) {
    const char *oldowner = NULL, *newowner = NULL;

    if(!b || !ctx)
        return 1;
    volmod_ctx_init(ctx);

    if(sx_blob_get_string(b, &ctx->volume) || sx_blob_get_string(b, &oldowner)
       || sx_blob_get_string(b, &newowner) || sx_blob_get_int64(b, &ctx->oldsize)
       || sx_blob_get_int64(b, &ctx->newsize) || sx_blob_get_int32(b, &ctx->oldrevs)
       || sx_blob_get_int32(b, &ctx->newrevs)) {
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
        || sx_blob_add_int64(joblb, ctx->newsize) || sx_blob_add_int32(joblb, ctx->oldrevs)
        || sx_blob_add_int32(joblb, ctx->newrevs) || sx_blob_add_int32(joblb, ctx->nmeta)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }

    if(ctx->nmeta != -1 && sx_blob_cat(joblb, ctx->meta)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }

    /* Backup also old meta */
    if(sx_blob_add_int32(joblb, ctx->noldmeta)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }

    if(ctx->noldmeta != -1 && sx_blob_cat(joblb, ctx->oldmeta)) {
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
    sxi_query_t *ret;
    sxc_meta_t *meta = NULL;

    if(blob_to_volmod(sx, b, &ctx)) {
        WARN("Failed to read job blob");
        return NULL;
    }

    /* If job is in abort phase, then skip setting metadata */
    if(blob_to_sxc_meta(sx, b, &meta, phase != JOBPHASE_COMMIT)) {
        WARN("Failed to read job blob");
        return NULL;
    }

    /* Pick up old metadata */
    if(phase != JOBPHASE_COMMIT && blob_to_sxc_meta(sx, b, &meta, 0)) {
        WARN("Failed to read job blob");
        return NULL;
    }

    /* In COMMIT phase meta contains new metadata, in ABORT or UNDO it contains old, backed up metadata */
    switch (phase) {
        case JOBPHASE_COMMIT:
            ret = sxi_volume_mod_proto(sx, ctx.volume, ctx.newowner, ctx.newsize, ctx.newrevs, meta);
            break;
        case JOBPHASE_ABORT:
        case JOBPHASE_UNDO:
            ret = sxi_volume_mod_proto(sx, ctx.volume, ctx.oldowner, ctx.oldsize, ctx.oldrevs, meta);
            break;
        default:
            ret = NULL;
    }

    sxc_meta_free(meta);
    return ret;
}

static rc_ty volmod_create_revsclean_job(sx_hashfs_t *h, const char *v) {
    const sx_hashfs_volume_t *vol = NULL;
    rc_ty s;
    job_t job;
    sx_nodelist_t *curnode_list = NULL;
    sx_blob_t *joblb;
    const void *job_data;
    unsigned int job_datalen;
    int job_timeout = 20;
    const sx_node_t *me;

    if((s = sx_hashfs_volume_by_name(h, v, &vol)) != OK) {
        WARN("Failed to get volume %s reference", v);
        return s;
    }

    me = sx_hashfs_self(h);
    if(!me) {
        WARN("Failed to get self node reference");
        return FAIL_EINTERNAL;
    }

    /* Schedule to PREVNEXT. On old volnodes all files will eventually be dropped,
     * but we should avoid listing old revs and it is done on PREV */
    if(!sx_hashfs_is_node_volume_owner(h, NL_PREVNEXT, me, vol)) {
        /* Do not schedule this job if local node is not a volnode */
        DEBUG("Skipped scheduling revsclean job: not a volnode");
        return OK;
    }

    curnode_list = sx_nodelist_new();
    if(!curnode_list) {
        WARN("Failed to allocate nodeslist");
        return FAIL_EINTERNAL;
    }
    if(sx_nodelist_add(curnode_list, sx_node_dup(me))) {
        WARN("Failed to add myself to nodelist");
        sx_nodelist_delete(curnode_list);
        return FAIL_EINTERNAL;
    }

    if(!(joblb = sx_blob_new())) {
        WARN("Cannot allocate job blob");
        sx_nodelist_delete(curnode_list);
        return FAIL_EINTERNAL;
    }

    if(sx_blob_add_string(joblb, vol->name) || sx_blob_add_string(joblb, "")) {
        sx_blob_free(joblb);
        sx_nodelist_delete(curnode_list);
        WARN("Cannot create job blob");
        return FAIL_EINTERNAL;
    }

    sx_blob_to_data(joblb, &job_data, &job_datalen);
    s = sx_hashfs_job_new(h, 0, &job, JOBTYPE_REVSCLEAN, job_timeout, vol->name, job_data, job_datalen, curnode_list);
    sx_blob_free(joblb);
    sx_nodelist_delete(curnode_list);
    return s;
}

static rc_ty volmod_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    struct volmod_ctx ctx;
    rc_ty rc = OK, s;
    int i, nmeta, change_meta = 0;

    if (!h || !b) {
        WARN("NULL arguments");
        return FAIL_EINTERNAL;
    }

    if(blob_to_volmod(sx_hashfs_client(h), b, &ctx)) {
        WARN("Corrupted volume mod blob");
        return FAIL_EINTERNAL;
    }

    if (remote && phase == JOBPHASE_REQUEST)
        phase = JOBPHASE_COMMIT;

    if(sx_blob_get_int32(b, &nmeta)) {
        WARN("Corrupted volume mod blob");
        return 1;
    }

    if(nmeta != -1) {
        const sx_hashfs_volume_t *vol = NULL;
        if(sx_hashfs_volume_by_name(h, ctx.volume, &vol))
            return 1;
        if(sx_hashfs_volume_mod_begin(h, vol))
            return 1;
        change_meta = 1;
    }

    for(i = 0; i < nmeta; i++) {
        const char *metakey;
        const void *metaval;
        unsigned int l;

        if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &l)) {
            WARN("Failed to get meta key-value pair from blob");
            return FAIL_EINTERNAL;
        }

        if(phase == JOBPHASE_COMMIT && (s = sx_hashfs_volume_mod_addmeta(h, metakey, metaval, l)) != OK) {
            WARN("Failed to add meta key-value pair to context blob");
            return s;
        }
    }

    /* When meta change is intended and job phase is abort or undo, then pick backed up meta from blob */
    if(phase != JOBPHASE_COMMIT && change_meta) {
        if(sx_blob_get_int32(b, &nmeta)) {
            WARN("Corrupted volume mod blob");
            return 1;
        }

        for(i = 0; i < nmeta; i++) {
            const char *metakey;
            const void *metaval;
            unsigned int l;

            if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &l)) {
                WARN("Failed to get meta key-value pair from blob");
                return FAIL_EINTERNAL;
            }

            if(sx_hashfs_volume_mod_addmeta(h, metakey, metaval, l)) {
                WARN("Failed to add meta key-value pair to context blob");
                return FAIL_EINTERNAL;
            }
        }
    }

    switch (phase) {
        case JOBPHASE_COMMIT:
            rc = sx_hashfs_volume_mod(h, ctx.volume, ctx.newowner, ctx.newsize, ctx.newrevs, change_meta);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.volume, msg_get_reason());
            if(rc == OK && ctx.newrevs < ctx.oldrevs) {
                rc = volmod_create_revsclean_job(h, ctx.volume);
                if(rc != OK)
                    WARN("Failed to create revsclean job");
                /* Do not fail here, its background job */
                return OK;
            }
            return rc;
        case JOBPHASE_ABORT:
            rc = sx_hashfs_volume_mod(h, ctx.volume, ctx.oldowner, ctx.oldsize, ctx.oldrevs, change_meta);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.volume, msg_get_reason());
            return rc;
        case JOBPHASE_UNDO:
            CRIT("volume '%s' may have been left in an inconsistent state after a failed modification attempt", ctx.volume);
            rc = sx_hashfs_volume_mod(h, ctx.volume, ctx.oldowner, ctx.oldsize, ctx.oldrevs, change_meta);
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

    if((*ctx->newowner || ctx->newsize != -1) && !has_priv(PRIV_ADMIN)) {
        msg_set_reason("Permission denied: Not enough privileges");
        return EPERM;
    } else if(ctx->newrevs != -1 && !has_priv(PRIV_OWNER)) {
        msg_set_reason("Permission denied: Not enough privileges");
        return EPERM;
    } else if(!has_priv(PRIV_MANAGER)) {
        msg_set_reason("Permission denied: Not enough privileges");
        return EPERM;
    }

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
        if((s = sx_hashfs_get_user_by_name(hashfs, ctx->newowner, NULL, 0)) != OK) {
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
    }

    if(ctx->newrevs != -1) {
        /* Check if revisions number is higher than current limit */
        if(!has_priv(PRIV_CLUSTER) && (unsigned int)ctx->newrevs == vol->revisions) {
            msg_set_reason("New revisions limit is the same as current value");
            return EINVAL;
        }
        ctx->oldrevs = vol->revisions;
    }

    if(ctx->newrevs != -1 || ctx->newsize != -1) {
        /* Check if new volume configuration is ok */
        if((s = sx_hashfs_check_volume_settings(hashfs, volume, ctx->newsize != -1 ? ctx->newsize : vol->size, vol->max_replica, ctx->newrevs != -1 ? ctx->newrevs : vol->revisions)) != OK)
            return s; /* Message is set by sx_hashfs_check_volume_settings() */
    }

    if(ctx->nmeta != -1) {
        const char *metakey;
        const void *metaval;
        unsigned int l;

        if(!ctx->meta) {
            WARN("Corrupt volume modification context");
            return FAIL_EINTERNAL;
        }

        /* New meta has been given, we need to backup old meta in order to properly handle abort/undo phases */
        if((s = sx_hashfs_volumemeta_begin(hashfs, vol)) != OK)
            return s;
        ctx->oldmeta = sx_blob_new();
        if(!ctx->oldmeta) {
            msg_set_reason("Out of memory");
            return FAIL_EINTERNAL;
        }
        ctx->noldmeta = 0;

        s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metaval, &l);
        while(s == OK) {
            if(!strncmp(SX_CUSTOM_META_PREFIX, metakey, lenof(SX_CUSTOM_META_PREFIX))) {
                if(sx_blob_add_string(ctx->oldmeta, metakey + lenof(SX_CUSTOM_META_PREFIX)) || sx_blob_add_blob(ctx->oldmeta, metaval, l)) {
                    msg_set_reason("Out of memory");
                    sx_blob_free(ctx->oldmeta);
                    ctx->oldmeta = NULL;
                    ctx->noldmeta = -1;
                    return FAIL_EINTERNAL;
                }
                ctx->noldmeta++;
            }
            s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metaval, &l);
        }

        if(s != ITER_NO_MORE) {
            WARN("Failed to iterate through volume meta");
            sx_blob_free(ctx->oldmeta);
            ctx->oldmeta = NULL;
            ctx->noldmeta = -1;
            return s;
        }
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
    } else if(c->state == CB_VOLMOD_METAVAL) {
        uint8_t metaval[SXLIMIT_META_MAX_VALUE_LEN];

        if(sxi_hex2bin((const char*)s, l, metaval, sizeof(metaval))) {
            INFO("Invalid meta value");
            return 0;
        }
        l /= 2;

        if(sx_hashfs_check_meta(c->metakey, metaval, l)) {
            INFO("Invalid meta key-value pair");
            return 0;
        }

        if(sx_blob_add_string(c->meta, c->metakey) || sx_blob_add_blob(c->meta, metaval, l)) {
            WARN("Failed to add data to meta blob");
            return 0;
        }
        c->nmeta++;
        c->state = CB_VOLMOD_METAKEY;
        return 1;
    }
    return 0;
}

static int cb_volmod_number(void *ctx, const char *s, size_t l) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    char number[21], *eon;
    int64_t n;
    if(l<1 || l>20) {
        WARN("Failed to parse number: invalid length: %ld", l);
        return 0;
    }

    memcpy(number, s, l);
    number[l] = '\0';
    n = strtoll(number, &eon, 10);
    if(*eon) {
        WARN("Failed to parse number");
        return 0;
    }

    if(c->state == CB_VOLMOD_SIZE) {
        if(c->newsize >= 0) {
            WARN("Failed to parse new volume size: already assigned");
            return 0;
        }
        c->newsize = n;
        c->state = CB_VOLMOD_KEY;
        return 1;
    } else if(c->state == CB_VOLMOD_REVS) {
        if(c->newrevs >= 0) {
            WARN("Failed to parse new volume revisions limit: already assigned");
            return 0;
        }
        c->newrevs = n;
        c->state = CB_VOLMOD_KEY;
        return 1;
    }
    return 0;
}

static int cb_volmod_start_map(void *ctx) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->state == CB_VOLMOD_START)
        c->state = CB_VOLMOD_KEY;
    else if(c->state == CB_VOLMOD_META)
        c->state = CB_VOLMOD_METAKEY;
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
        if(l == lenof("maxRevisions") && !strncmp("maxRevisions", (const char*)s, l)) {
            c->state = CB_VOLMOD_REVS;
            return 1;
        }
        if(l == lenof("customVolumeMeta") && !strncmp("customVolumeMeta", (const char*)s, l)) {
            if(c->nmeta != -1) {
                DEBUG("customVolumeMeta has already been parsed");
                return 0;
            }
            c->meta = sx_blob_new();
            if(!c->meta) {
                WARN("Failed to allocate metadata");
                return 0;
            }
            c->nmeta = 0;
            c->state = CB_VOLMOD_META;
            return 1;
        }
    } else if(c->state == CB_VOLMOD_METAKEY) {
        if(c->nmeta >= SXLIMIT_META_MAX_ITEMS || l > SXLIMIT_META_MAX_KEY_LEN - lenof(SX_CUSTOM_META_PREFIX) || l < SXLIMIT_META_MIN_KEY_LEN)
            return 0;
        memcpy(c->metakey, s, l);
        c->metakey[l] = '\0';
        c->state = CB_VOLMOD_METAVAL;
        return 1;
    }
    return 0;
}

static int cb_volmod_end_map(void *ctx) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->state == CB_VOLMOD_KEY)
        c->state = CB_VOLMOD_COMPLETE;
    else if(c->state == CB_VOLMOD_METAKEY)
        c->state = CB_VOLMOD_KEY;
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
    volmod_ctx_init(&ctx);
    job_2pc_handle_request(sx_hashfs_client(hashfs), &volmod_spec, &ctx);
    sx_blob_free(ctx.meta);
    sx_blob_free(ctx.oldmeta);
}

void fcgi_node_status(void) {
    sxi_node_status_t status;
    rc_ty s;

    s = sx_hashfs_node_status(hashfs, &status);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());
    CGI_PUTS("Content-type: application/json\r\n\r\n{");
    CGI_PRINTF("\"osType\":\"%s\",\"osArch\":\"%s\",\"osRelease\":\"%s\",\"osVersion\":\"%s\",\"cores\":%d",
        status.os_name, status.os_arch, status.os_release, status.os_version, status.cores);
    CGI_PRINTF(",\"osEndianness\":\"%s\",\"localTime\":\"%s\",\"utcTime\":\"%s\"", status.endianness, status.localtime, status.utctime);
    CGI_PRINTF(",\"hashFSVersion\":\"%s\",\"libsxclientVersion\":\"%s\"", status.hashfs_version, status.libsxclient_version);
    if(!status.is_bare)
        CGI_PRINTF(",\"address\":\"%s\",\"internalAddress\":\"%s\",\"UUID\":\"%s\"", status.addr, status.internal_addr, status.uuid);
    CGI_PRINTF(",\"nodeDir\":\"%s\"", status.storage_dir);
    CGI_PRINTF(",\"storageAllocated\":");
    CGI_PUTLL(status.storage_allocated);
    CGI_PRINTF(",\"storageUsed\":");
    CGI_PUTLL(status.storage_commited);
    CGI_PUTS(",\"fsBlockSize\":");
    CGI_PUTLL(status.block_size);
    CGI_PUTS(",\"fsTotalBlocks\":");
    CGI_PUTLL(status.total_blocks);
    CGI_PUTS(",\"fsAvailBlocks\":");
    CGI_PUTLL(status.avail_blocks);
    CGI_PUTS(",\"memTotal\":");
    CGI_PUTLL(status.mem_total);
    CGI_PRINTF(",\"heal\":\"%s\"", status.heal_status);
    CGI_PUTC('}');
}

struct cluster_mode_ctx {
    int mode; /* 1: readonly, 0: read-write (default) */
    enum cluster_mode_state { CB_CM_START=0, CB_CM_KEY, CB_CM_MODE, CB_CM_COMPLETE } state;
};

static int cb_cluster_mode_string(void *ctx, const unsigned char *s, size_t l) {
    struct cluster_mode_ctx *c = ctx;
    if(c->state == CB_CM_MODE) {
        if(l != lenof("ro")) {
            msg_set_reason("Invalid cluster mode length");
            return 0;
        }
        if(!strncmp((const char*)s, "ro", 2))
            c->mode = 1;
        else if(!strncmp((const char*)s, "rw", 2))
            c->mode = 0;
        else {
            msg_set_reason("Invalid cluster mode");
            return 1;
        }
        c->state = CB_CM_KEY;
        return 1;
    }
    DEBUG("Invalid state %d: expected %d", c->state, CB_CM_MODE);
    return 0;
}

static int cb_cluster_mode_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cluster_mode_ctx *c = ctx;
    if(c->state == CB_CM_KEY) {
        if(l == lenof("mode") && !strncmp("mode", (const char*)s, l)) {
            c->state = CB_CM_MODE;
            return 1;
        }
        DEBUG("Unknown key: %.*s", (int)l, s);
    }
    return 0;
}

static int cb_cluster_mode_start_map(void *ctx) {
    struct cluster_mode_ctx *c = ctx;
    if(c->state == CB_CM_START)
        c->state = CB_CM_KEY;
    else
        return 0;
    return 1;
}

static int cb_cluster_mode_end_map(void *ctx) {
    struct cluster_mode_ctx *c = ctx;
    if(c->state == CB_CM_KEY)
        c->state = CB_CM_COMPLETE;
    else
        return 0;
    return 1;
}

static const yajl_callbacks cluster_mode_ops_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_cluster_mode_string,
    cb_cluster_mode_start_map,
    cb_cluster_mode_map_key,
    cb_cluster_mode_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

static rc_ty cluster_mode_parse_complete(void *yctx)
{
    struct cluster_mode_ctx *c = yctx;
    if(!c || c->state != CB_CM_COMPLETE)
        return EINVAL;
    if(c->mode != 0 && c->mode != 1) {
        msg_set_reason("Invalid cluster mode");
        return EINVAL;
    }
    return OK;
}

static int cluster_mode_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct cluster_mode_ctx *c = yctx;
    if(!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }

    if(sx_blob_add_int32(joblb, c->mode)) {
        msg_set_reason("Cannot create job blob");
        return -1;
    }
    return 0;
}

static unsigned cluster_mode_timeout(sxc_client_t *sx, int nodes)
{
    return nodes > 1 ? 50 * (nodes - 1) : 20;
}

static sxi_query_t* cluster_mode_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    int32_t mode = 0;

    if(sx_blob_get_int32(b, &mode)) {
        WARN("Corrupt user blob");
        return NULL;
    }

    switch(phase) {
        case JOBPHASE_REQUEST:
            return sxi_cluster_mode_proto(sx, mode);
        case JOBPHASE_ABORT:/* fall-through */
            INFO("Aborting cluster mode switch operation: '%s'", mode ? "read-only" : "read-write");
            return sxi_cluster_mode_proto(sx, !mode);
        default:
            WARN("Invalid job phase");
            return NULL;
    }
}

static rc_ty cluster_mode_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    rc_ty rc = FAIL_EINTERNAL;
    int32_t mode = 0;
    int cluster_readonly = 0;

    if(!h || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if(sx_blob_get_int32(b, &mode)) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    if(sx_hashfs_cluster_get_mode(h, &cluster_readonly)) {
        WARN("Failed to get cluster oparting mode");
        msg_set_reason("Failed to check cluster operating mode");
        return FAIL_EINTERNAL;
    }

    if(!remote && phase == JOBPHASE_REQUEST && cluster_readonly == mode) {
        msg_set_reason("Cluster is already in '%s' mode", cluster_readonly ? "read-only" : "read-write");
        return EINVAL;
    }

    switch(phase) {
        case JOBPHASE_REQUEST:
            DEBUG("Cluster mode switch request: '%s'", mode ? "read-only" : "read-write");
            rc = sx_hashfs_cluster_set_mode(h, mode);
            if(rc != OK)
                msg_set_reason("Unable to switch cluster to '%s' mode", mode ? "read-only" : "read-write");
            return rc;
        case JOBPHASE_ABORT:
            DEBUG("Cluster mode switch abort: '%s'", mode ? "read-only" : "read-write");
            rc = sx_hashfs_cluster_set_mode(h, !mode);
            if(rc != OK)
                msg_set_reason("Unable to switch cluster to '%s' mode", mode ? "read-write" : "read-only");
            return rc;
        default:
            WARN("Invalid job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

static const char *cluster_mode_get_lock(sx_blob_t *b)
{
    return "CLUSTER_MODE";
}

static rc_ty cluster_mode_nodes(sx_hashfs_t *h, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if(!nodes)
        return FAIL_EINTERNAL;
    /* Spawn cluster mode job to all nodes */
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV));
    if(!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

const job_2pc_t cluster_mode_spec = {
    &cluster_mode_ops_parser,
    JOBTYPE_CLUSTER_MODE,
    cluster_mode_parse_complete,
    cluster_mode_get_lock,
    cluster_mode_to_blob,
    cluster_mode_execute_blob,
    cluster_mode_proto_from_blob,
    cluster_mode_nodes,
    cluster_mode_timeout
};

void fcgi_cluster_mode(void) {
    struct cluster_mode_ctx c = { -1, CB_CM_START };

    job_2pc_handle_request(sx_hashfs_client(hashfs), &cluster_mode_spec, &c);
}

static void blob_send(const sx_blob_t *b)
{
    const void *data;
    uint32_t len, len_net;
    sx_blob_to_data(b, &data, &len);
    len_net = htonl(len);
    CGI_PUTD(&len_net, sizeof(len_net));
    CGI_PUTD(data, len);
}

static void blob_send_eof(void)
{
    sx_blob_t *b = sx_blob_new();
    if (!b)
        quit_errmsg(500, "OOM");
    if (sx_blob_add_string(b, "EOF$")) {
        sx_blob_free(b);
        quit_errmsg(500, "blob_add failed");
    }
    blob_send(b);
    sx_blob_free(b);
}

static int list_rev_cb(const sx_hashfs_volume_t *vol, const sx_uuid_t *target, const sx_hash_t *revision_id, const sx_hash_t *contents, int64_t nblocks, unsigned block_size)
{
    int64_t i=-1;
    sx_blob_t *b = sx_blob_new();
    if (!b)
        return -1;
    DEBUG("IN");
    do {
        if (sx_blob_add_string(b, "[REV]") ||
            sx_blob_add_blob(b, revision_id->b, sizeof(revision_id->b)) ||
            sx_blob_add_int32(b, block_size))
            break;
        for (i=0;i<nblocks;i++) {
            const sx_hash_t *hash = &contents[i];
            sx_nodelist_t *nl = sx_hashfs_all_hashnodes(hashfs, NL_NEXT, hash, vol->max_replica);
            if (!nl)
                break;
            const sx_node_t *found = sx_nodelist_lookup(nl, target);
            sx_nodelist_delete(nl);
            if (found && sx_blob_add_blob(b, hash->b, sizeof(hash->b)))
                break;
        }
        if (sx_blob_add_blob(b, "", 0)) {
            i = -1;
            break;
        }
        blob_send(b);
    } while(0);
    sx_blob_free(b);
    return i == nblocks ? 0 : -1;
}

static int list_count_cb(int64_t count)
{
    sx_blob_t *b = sx_blob_new();
    if (!b)
        return -1;
    DEBUG("IN");
    do {
        if (sx_blob_add_string(b,"[COUNT]") ||
            sx_blob_add_int64(b, count))
            break;
        blob_send(b);
    } while(0);
    sx_blob_free(b);
    return 0;
}

void fcgi_list_revision_blocks(const sx_hashfs_volume_t *vol) {
    int max_age = get_arg_uint("max-age");
    const char *min_rev  = get_arg("min-rev");
    const char *node_uuid = get_arg("for-node-uuid");
    int metadb = get_arg_uint("metadb");
    sx_hash_t min_revision;
    sx_uuid_t uuid;
    if (max_age < 0)
        quit_errmsg(400, "Invalid max-age: cannot be negative");
    if (!node_uuid || uuid_from_string(&uuid, node_uuid))
        quit_errmsg(400, "target node uuid missing or invalid");
    if (min_rev && *min_rev &&
        hex2bin(min_rev, strlen(min_rev), min_revision.b, sizeof(min_revision.b)))
        quit_errmsg(400, "failed to convert revision from hex");
    rc_ty rc;
    CGI_PUTS("\r\n");
    DEBUG("max-age: %d", max_age);
    if ((rc = sx_hashfs_list_revision_blocks(hashfs, vol, &uuid, (min_rev && *min_rev) ? &min_revision : NULL, max_age, metadb, list_rev_cb, list_count_cb)))
        quit_errmsg(rc2http(rc), msg_get_reason());
    blob_send_eof();
}

static int parse_timeval(const char *str, struct timeval *tv) {
    char *enumb = NULL;

    if(!str || !tv) {
        WARN("NULL argument");
        return -1;
    }
    
    tv->tv_sec = strtoll(str, &enumb, 10);
    if(enumb) {
        if(*enumb != '.')
            return -1;
        str = enumb + 1;
        enumb = NULL;
        tv->tv_usec = strtoll(str, &enumb, 10);
        if(enumb && *enumb)
            return -1;
    } else
        tv->tv_usec = 0;
    return 0;
}

void fcgi_mass_delete(void) {
    const sx_hashfs_volume_t *vol;
    rc_ty s;
    const char *input_pattern = get_arg("filter");

    s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol))
        quit_errnum(404);

    if(!input_pattern)
        input_pattern = "*";

    if(has_priv(PRIV_CLUSTER)) {
        /* Schedule a batch job slave, will schedule the job on local node only */
        sx_blob_t *b;
        const void *job_data = NULL;
        unsigned int job_data_len = 0;
        sx_nodelist_t *nodelist;
        struct timeval timestamp;
        job_t job_id;

        if(!has_arg("timestamp"))
            quit_errmsg(400, "Missing timestamp parameter");
        if(parse_timeval(get_arg("timestamp"), &timestamp))
            quit_errmsg(400, "Invalid timestamp parameter");

        nodelist = sx_nodelist_new();
        if(!nodelist)
            quit_errmsg(500, "Failed to create a nodelist");

        if(sx_nodelist_add(nodelist, sx_node_dup(sx_hashfs_self(hashfs)))) {
            sx_nodelist_delete(nodelist);
            quit_errmsg(500, "Failed to add node to nodelist");
        }

        b = sx_blob_new();
        if(!b) {
            sx_nodelist_delete(nodelist);
            quit_errmsg(500, "Failed to allocate blob");
        }

        if(sx_blob_add_string(b, vol->name) || sx_blob_add_int32(b, has_arg("recursive")) ||
           sx_blob_add_string(b, input_pattern) || sx_blob_add_datetime(b, &timestamp)) {
            sx_nodelist_delete(nodelist);
            sx_blob_free(b);
            quit_errmsg(500, "Failed to add data to blob");
        }

        sx_blob_to_data(b, &job_data, &job_data_len);
        /* Schedule the job locally */
        s = sx_hashfs_job_new(hashfs, uid, &job_id, JOBTYPE_MASSDELETE, 3600, NULL, job_data, job_data_len, nodelist);
        sx_blob_free(b);
        sx_nodelist_delete(nodelist);
        if(s)
            quit_errmsg(rc2http(s), rc2str(s));
        send_job_info(job_id);
    } else {
        /* Request comes in from the user: create jobs on each volnode */
        job_t job;
        s = sx_hashfs_files_processing_job(hashfs, uid, vol, has_arg("recursive"), input_pattern, NULL, &job);

        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
        send_job_info(job);
    }
}

void fcgi_mass_rename(void) {
    const sx_hashfs_volume_t *vol;
    rc_ty s;
    const char *dest = get_arg("dest");
    const char *source = get_arg("source");
    unsigned int slen, dlen;
    const sx_hashfs_file_t *file = NULL;

    s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol))
        quit_errnum(404);

    if(!source || !dest)
        quit_errmsg(400, "Invalid argument");
    slen = strlen(source);
    dlen = strlen(dest);
    if(!dlen || !slen)
        quit_errmsg(400, "Invalid argument");

    /* Check if dest is a directory when source is a directory too */
    if((source[slen-1] == '/' && dest[dlen-1] != '/'))
        quit_errmsg(400, "Not a directory");
    if(dlen == 1 && dest[0] == '/') /* Volume root cannot be the target, because it always exists */
        quit_errmsg(400, "Target cannot be a volume root");

    if(has_priv(PRIV_CLUSTER)) {
        /* Schedule a batch job slave, will schedule the job on local node only */
        sx_blob_t *b;
        const void *job_data = NULL;
        unsigned int job_data_len = 0;
        sx_nodelist_t *nodelist;
        struct timeval timestamp;
        job_t job_id;

        if(!has_arg("timestamp"))
            quit_errmsg(400, "Missing timestamp parameter");
        if(parse_timeval(get_arg("timestamp"), &timestamp))
            quit_errmsg(400, "Invalid timestamp parameter");

        nodelist = sx_nodelist_new();
        if(!nodelist)
            quit_errmsg(500, "Failed to create a nodelist");

        if(sx_nodelist_add(nodelist, sx_node_dup(sx_hashfs_self(hashfs)))) {
            sx_nodelist_delete(nodelist);
            quit_errmsg(500, "Failed to add node to nodelist");
        }

        b = sx_blob_new();
        if(!b) {
            sx_nodelist_delete(nodelist);
            quit_errmsg(500, "Failed to allocate blob");
        }

        if(sx_blob_add_string(b, vol->name) || sx_blob_add_int32(b, 0) ||
           sx_blob_add_string(b, source) || sx_blob_add_datetime(b, &timestamp) ||
           sx_blob_add_string(b, dest)) {
            sx_nodelist_delete(nodelist);
            sx_blob_free(b);
            quit_errmsg(500, "Failed to add data to blob");
        }

        sx_blob_to_data(b, &job_data, &job_data_len);
        /* Schedule the job locally */
        s = sx_hashfs_job_new(hashfs, uid, &job_id, JOBTYPE_MASSRENAME, 3600, NULL, job_data, job_data_len, nodelist);
        sx_blob_free(b);
        sx_nodelist_delete(nodelist);
        if(s)
            quit_errmsg(rc2http(s), rc2str(s));
        send_job_info(job_id);
    } else {
        /* Request comes in from the user: create jobs on each volnode */
        job_t job;

        /* Check if dest exists and if so, reject it */
        s = sx_hashfs_list_first(hashfs, vol, dest, &file, 0, NULL, 1);
        if(s == OK && ((dest[dlen-1] != '/' && !strcmp(dest, file->name + 1)) || (dest[dlen-1] == '/' && !strncmp(dest, file->name + 1, dlen))))
            quit_errmsg(rc2http(EEXIST), "Target already exists");
        else if(s != ITER_NO_MORE && s != OK)
            quit_errmsg(rc2http(s), rc2str(s));

        /* Check source file existence */
        s = sx_hashfs_list_first(hashfs, vol, source, &file, 0, NULL, 1);
        if(s == ITER_NO_MORE || (s == OK && slen && source[slen-1] != '/' && strcmp(source, file->name + 1)))
            quit_errmsg(rc2http(ENOENT), "Not Found");
        else if(s != OK && s != ITER_NO_MORE)
            quit_errmsg(rc2http(s), rc2str(s));

        s = sx_hashfs_files_processing_job(hashfs, uid, vol, 0, source, dest, &job);

        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
        send_job_info(job);
    }
}
